//! The session's one private storage codec: an [`Event`] as a slot's fixed
//! words and back. It checks storage form only (known tags and codes, every
//! word a tag does not use zero); whether an observation is a legal
//! transition is the refinement checker's to decide.
//!
//! Layout, by tag (word 0), the rest of the [`WORDS`] words zero:
//!
//! | tag | event        | words 1..                                                        |
//! |-----|--------------|------------------------------------------------------------------|
//! | 1   | call         | kind (1 work, 2 allocate, 3 reclaim), values, bytes, answer, a, b |
//! | 2   | admit        | values, bytes, obligation (0 none), held values, held bytes, id(2), acquisition(2) |
//! | 3   | spend        | obligation, values, bytes, id(2), acquisition(2), permit(2)       |
//! | 4   | forfeit      | as spend, then rule                                               |
//! | 5   | effect       | kind (1 reserved, 2 failed), permit(2), acquisition(2)            |
//! | 6   | split        | parent(2), child(2), bytes                                        |
//! | 7   | merge        | survivor(2), retired(2), bytes                                    |
//! | 8   | released     | permit(2)                                                         |
//! | 9   | owner        | owner(2)                                                          |
//! | 10  | bound        | acquisition(2), owner(2)                                          |
//! | 11  | end          | acquisition(2), owner(2)                                          |
//! | 12  | custody      | permit(2), owner(2), stage (1 granted, 2 handle, 3 queued, 4 active, 5 reclaimed) |
//!
//! An identity is two words, family then sequence. A call's answer is 1
//! admitted, 2 granted (a and b the permit), or 3 plus a refusal's code (a
//! its argument, b 1 when the fault schedule injected it, else 0). An
//! absent permit is the unobserved identity.

use super::super::super::{
    Call, Credit, Effect, Forfeit, Hold, Identity, Obligation, Settled, WriteWork,
};
use super::super::{Answer, Event, LimitRefusal, RecordStage};

/// The words one slot holds: a tag and up to eleven fields (a forfeit's).
pub(super) const WORDS: usize = 12;

const CALL: u64 = 1;
const ADMIT: u64 = 2;
const SPEND: u64 = 3;
const FORFEIT: u64 = 4;
const EFFECT: u64 = 5;
const SPLIT: u64 = 6;
const MERGE: u64 = 7;
const RELEASED: u64 = 8;
const OWNER: u64 = 9;
const BOUND: u64 = 10;
const END: u64 = 11;
const CUSTODY: u64 = 12;

fn stage_code(stage: RecordStage) -> u64 {
    match stage {
        RecordStage::Granted => 1,
        RecordStage::Handle => 2,
        RecordStage::Queued => 3,
        RecordStage::Active => 4,
        RecordStage::Reclaimed => 5,
    }
}

fn stage_of(code: u64) -> Option<RecordStage> {
    match code {
        1 => Some(RecordStage::Granted),
        2 => Some(RecordStage::Handle),
        3 => Some(RecordStage::Queued),
        4 => Some(RecordStage::Active),
        5 => Some(RecordStage::Reclaimed),
        _ => None,
    }
}

fn obligation_code(obligation: Obligation) -> u64 {
    match obligation {
        Obligation::Release => 1,
        Obligation::Grant => 2,
        Obligation::BucketWindow => 3,
    }
}

fn obligation_of(code: u64) -> Option<Obligation> {
    match code {
        1 => Some(Obligation::Release),
        2 => Some(Obligation::Grant),
        3 => Some(Obligation::BucketWindow),
        _ => None,
    }
}

fn forfeit_code(rule: Forfeit) -> u64 {
    match rule {
        Forfeit::AcquisitionRefused => 1,
        Forfeit::AcquisitionFailed => 2,
        Forfeit::Cancelled => 3,
        Forfeit::EnumerationComplete => 4,
    }
}

fn forfeit_of(code: u64) -> Option<Forfeit> {
    match code {
        1 => Some(Forfeit::AcquisitionRefused),
        2 => Some(Forfeit::AcquisitionFailed),
        3 => Some(Forfeit::Cancelled),
        4 => Some(Forfeit::EnumerationComplete),
        _ => None,
    }
}

/// A refusal's code and argument; none when a scheduled index does not fit
/// a word.
fn refusal_code(refusal: LimitRefusal) -> Option<(u64, u64)> {
    Some(match refusal {
        LimitRefusal::Work => (1, 0),
        LimitRefusal::Storage => (2, 0),
        LimitRefusal::Deadline => (3, 0),
        LimitRefusal::Scheduled(index) => (4, u64::try_from(index).ok()?),
        LimitRefusal::Unrecorded => (5, 0),
        LimitRefusal::Turn => (6, 0),
        LimitRefusal::QuantumTooSmall => (7, 0),
        LimitRefusal::Requested => (8, 0),
        LimitRefusal::TooLarge => (9, 0),
        LimitRefusal::Contended => (10, 0),
        LimitRefusal::Cancelled => (11, 0),
    })
}

fn refusal_of(code: u64, argument: u64) -> Option<LimitRefusal> {
    match (code, argument) {
        (1, 0) => Some(LimitRefusal::Work),
        (2, 0) => Some(LimitRefusal::Storage),
        (3, 0) => Some(LimitRefusal::Deadline),
        (4, index) => usize::try_from(index).ok().map(LimitRefusal::Scheduled),
        (5, 0) => Some(LimitRefusal::Unrecorded),
        (6, 0) => Some(LimitRefusal::Turn),
        (7, 0) => Some(LimitRefusal::QuantumTooSmall),
        (8, 0) => Some(LimitRefusal::Requested),
        (9, 0) => Some(LimitRefusal::TooLarge),
        (10, 0) => Some(LimitRefusal::Contended),
        (11, 0) => Some(LimitRefusal::Cancelled),
        _ => None,
    }
}

/// `fields` after `tag`, the rest zero.
fn words(tag: u64, fields: &[u64]) -> [u64; WORDS] {
    let mut words = [0; WORDS];
    words[0] = tag;
    words[1..=fields.len()].copy_from_slice(fields);
    words
}

fn settled_fields(settled: Settled) -> [u64; 9] {
    let permit = settled.permit.unwrap_or(Identity::UNOBSERVED);
    [
        obligation_code(settled.obligation),
        settled.work.values,
        settled.work.bytes,
        settled.id.family(),
        settled.id.sequence(),
        settled.acquisition.family(),
        settled.acquisition.sequence(),
        permit.family(),
        permit.sequence(),
    ]
}

/// `event`'s words; none when it holds a quantity no word holds.
pub(super) fn encode(event: Event) -> Option<[u64; WORDS]> {
    Some(match event {
        Event::Call(call, answer) => {
            let (kind, values, bytes) = match call {
                Call::Work { values, bytes } => (1, values, bytes),
                Call::Allocate(bytes) => (2, 0, bytes),
                Call::Reclaim { values, bytes } => (3, values, bytes),
            };
            let (outcome, a, b) = match answer {
                Answer::Admitted => (1, 0, 0),
                Answer::Granted(permit) => (2, permit.family(), permit.sequence()),
                Answer::Refused { refusal, injected } => {
                    let (code, argument) = refusal_code(refusal)?;
                    (3 + code, argument, u64::from(injected))
                }
            };
            words(CALL, &[kind, values, bytes, outcome, a, b])
        }
        Event::Credit(Credit::Admit { work, held: None }) => {
            words(ADMIT, &[work.values, work.bytes, 0])
        }
        Event::Credit(Credit::Admit {
            work,
            held: Some(hold),
        }) => words(
            ADMIT,
            &[
                work.values,
                work.bytes,
                obligation_code(hold.obligation),
                hold.work.values,
                hold.work.bytes,
                hold.id.family(),
                hold.id.sequence(),
                hold.acquisition.family(),
                hold.acquisition.sequence(),
            ],
        ),
        Event::Credit(Credit::Spend(spent)) => words(SPEND, &settled_fields(spent)),
        Event::Credit(Credit::Forfeit(forfeited, rule)) => {
            let mut fields = [0; 10];
            fields[..9].copy_from_slice(&settled_fields(forfeited));
            fields[9] = forfeit_code(rule);
            words(FORFEIT, &fields)
        }
        Event::Effect(effect) => {
            let (kind, permit, acquisition) = match effect {
                Effect::Reserved {
                    permit,
                    acquisition,
                } => (1, permit, acquisition),
                Effect::Failed {
                    permit,
                    acquisition,
                } => (2, permit, acquisition),
            };
            words(
                EFFECT,
                &[
                    kind,
                    permit.family(),
                    permit.sequence(),
                    acquisition.family(),
                    acquisition.sequence(),
                ],
            )
        }
        Event::Split {
            parent,
            child,
            bytes,
        } => words(
            SPLIT,
            &[
                parent.family(),
                parent.sequence(),
                child.family(),
                child.sequence(),
                bytes,
            ],
        ),
        Event::Merge {
            survivor,
            retired,
            bytes,
        } => words(
            MERGE,
            &[
                survivor.family(),
                survivor.sequence(),
                retired.family(),
                retired.sequence(),
                bytes,
            ],
        ),
        Event::Released(permit) => words(RELEASED, &[permit.family(), permit.sequence()]),
        Event::Owner(owner) => words(OWNER, &[owner.family(), owner.sequence()]),
        Event::Bound { acquisition, owner } => words(
            BOUND,
            &[
                acquisition.family(),
                acquisition.sequence(),
                owner.family(),
                owner.sequence(),
            ],
        ),
        Event::End { acquisition, owner } => words(
            END,
            &[
                acquisition.family(),
                acquisition.sequence(),
                owner.family(),
                owner.sequence(),
            ],
        ),
        Event::Custody {
            permit,
            owner,
            stage,
        } => words(
            CUSTODY,
            &[
                permit.family(),
                permit.sequence(),
                owner.family(),
                owner.sequence(),
                stage_code(stage),
            ],
        ),
    })
}

/// The event `words` store, when they are one's storage form: a known tag,
/// known codes, and zero in every word its tag does not use.
pub(super) fn decode(words: &[u64; WORDS]) -> Option<Event> {
    let id = |at: usize| Identity::new(words[at], words[at + 1]);
    let used = |count: usize| words[count + 1..].iter().all(|word| *word == 0);
    let settled = || {
        let permit = id(8);
        Some(Settled {
            obligation: obligation_of(words[1])?,
            work: WriteWork::new(words[2], words[3]),
            id: id(4),
            acquisition: id(6),
            permit: (permit != Identity::UNOBSERVED).then_some(permit),
        })
    };
    let (event, count) = match words[0] {
        CALL => {
            let call = match words[1] {
                1 => Call::Work {
                    values: words[2],
                    bytes: words[3],
                },
                2 if words[2] == 0 => Call::Allocate(words[3]),
                3 => Call::Reclaim {
                    values: words[2],
                    bytes: words[3],
                },
                _ => return None,
            };
            let answer = match words[4] {
                1 if words[5] == 0 && words[6] == 0 => Answer::Admitted,
                2 => Answer::Granted(id(5)),
                code if words[6] <= 1 => Answer::Refused {
                    refusal: refusal_of(code.checked_sub(3)?, words[5])?,
                    injected: words[6] == 1,
                },
                _ => return None,
            };
            (Event::Call(call, answer), 6)
        }
        ADMIT => match words[3] {
            0 => (
                Event::Credit(Credit::Admit {
                    work: WriteWork::new(words[1], words[2]),
                    held: None,
                }),
                3,
            ),
            code => (
                Event::Credit(Credit::Admit {
                    work: WriteWork::new(words[1], words[2]),
                    held: Some(Hold {
                        obligation: obligation_of(code)?,
                        work: WriteWork::new(words[4], words[5]),
                        id: id(6),
                        acquisition: id(8),
                    }),
                }),
                9,
            ),
        },
        SPEND => (Event::Credit(Credit::Spend(settled()?)), 9),
        FORFEIT => (
            Event::Credit(Credit::Forfeit(settled()?, forfeit_of(words[10])?)),
            10,
        ),
        EFFECT => {
            let (permit, acquisition) = (id(2), id(4));
            let effect = match words[1] {
                1 => Effect::Reserved {
                    permit,
                    acquisition,
                },
                2 => Effect::Failed {
                    permit,
                    acquisition,
                },
                _ => return None,
            };
            (Event::Effect(effect), 5)
        }
        SPLIT => (
            Event::Split {
                parent: id(1),
                child: id(3),
                bytes: words[5],
            },
            5,
        ),
        MERGE => (
            Event::Merge {
                survivor: id(1),
                retired: id(3),
                bytes: words[5],
            },
            5,
        ),
        RELEASED => (Event::Released(id(1)), 2),
        OWNER => (Event::Owner(id(1)), 2),
        BOUND => (
            Event::Bound {
                acquisition: id(1),
                owner: id(3),
            },
            4,
        ),
        END => (
            Event::End {
                acquisition: id(1),
                owner: id(3),
            },
            4,
        ),
        CUSTODY => (
            Event::Custody {
                permit: id(1),
                owner: id(3),
                stage: stage_of(words[5])?,
            },
            5,
        ),
        _ => return None,
    };
    used(count).then_some(event)
}

#[cfg(test)]
mod tests;
