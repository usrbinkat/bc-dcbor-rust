extern crate alloc;
use super::*;
use alloc::vec;
use alloc::vec::Vec;

fn id(family: u64, sequence: u64) -> Identity {
    Identity::new(family, sequence)
}

fn settled(permit: Option<Identity>) -> Settled {
    Settled {
        obligation: Obligation::Grant,
        work: WriteWork::new(1, 32),
        id: id(1, 4),
        acquisition: id(2, 3),
        permit,
    }
}

/// One of every event shape: every call answer and refusal, both admissions,
/// every obligation, every forfeiture rule, both effects, and the transfer,
/// release, owner and binding observations.
fn every_event() -> Vec<Event> {
    let mut events = vec![
        Event::Call(
            Call::Work {
                values: 3,
                bytes: 64,
            },
            Answer::Admitted,
        ),
        Event::Call(
            Call::Allocate(u64::MAX),
            Answer::Granted(id(1, u64::MAX - 1)),
        ),
        Event::Credit(Credit::Admit {
            work: WriteWork::new(2, 16),
            held: None,
        }),
        Event::Effect(Effect::Reserved {
            permit: id(1, 9),
            acquisition: id(2, 3),
        }),
        Event::Effect(Effect::Failed {
            permit: id(1, 9),
            acquisition: id(2, 3),
        }),
        Event::Split {
            parent: id(1, 9),
            child: id(1, 10),
            bytes: 0,
        },
        Event::Merge {
            survivor: id(1, 9),
            retired: id(1, 10),
            bytes: u64::MAX,
        },
        Event::Released(id(3, 1)),
        Event::Owner(id(4, 1)),
        Event::Bound {
            acquisition: id(4, 2),
            owner: id(4, 1),
        },
        Event::End {
            acquisition: id(4, 2),
            owner: id(4, 1),
        },
        Event::Credit(Credit::Spend(settled(None))),
        Event::Credit(Credit::Spend(settled(Some(id(1, 9))))),
    ];
    for stage in [
        RecordStage::Granted,
        RecordStage::Handle,
        RecordStage::Queued,
        RecordStage::Active,
        RecordStage::Reclaimed,
    ] {
        events.push(Event::Custody {
            permit: id(1, 9),
            owner: id(4, 1),
            stage,
        });
    }
    for refusal in [
        LimitRefusal::Work,
        LimitRefusal::Storage,
        LimitRefusal::Deadline,
        LimitRefusal::Scheduled(0),
        LimitRefusal::Scheduled(usize::MAX),
        LimitRefusal::Unrecorded,
    ] {
        for injected in [false, true] {
            events.push(Event::Call(
                Call::Allocate(8),
                Answer::Refused { refusal, injected },
            ));
        }
    }
    for obligation in [
        Obligation::Release,
        Obligation::Grant,
        Obligation::BucketWindow,
    ] {
        events.push(Event::Credit(Credit::Admit {
            work: WriteWork::new(1, 8),
            held: Some(Hold {
                obligation,
                work: WriteWork::new(1, 8),
                id: id(1, 2),
                acquisition: id(1, 1),
            }),
        }));
    }
    for rule in [
        Forfeit::AcquisitionRefused,
        Forfeit::AcquisitionFailed,
        Forfeit::Cancelled,
        Forfeit::EnumerationComplete,
    ] {
        events.push(Event::Credit(Credit::Forfeit(
            settled(Some(id(1, 9))),
            rule,
        )));
    }
    events
}

/// Every event shape reads back from its words exactly.
#[test]
fn every_event_round_trips_through_its_words() {
    for event in every_event() {
        let words = encode(event).expect("every event in the fixture fits its words");
        assert_eq!(decode(&words), Some(event), "{event:?} as {words:?}");
    }
}

/// Planted controls: words naming no observation are refused, each by its
/// own defect: an unknown tag, an unknown obligation code, an unknown
/// refusal code, an unknown forfeiture rule, an unknown effect kind, an
/// allocation answered as admitted work stored with a stray word, and a
/// nonzero word past a tag's fields.
#[test]
fn words_naming_no_observation_are_refused() {
    let admit = encode(Event::Credit(Credit::Admit {
        work: WriteWork::new(1, 8),
        held: Some(Hold {
            obligation: Obligation::Grant,
            work: WriteWork::new(1, 8),
            id: id(1, 2),
            acquisition: id(1, 1),
        }),
    }))
    .expect("an admission fits");
    let refused = encode(Event::Call(
        Call::Allocate(8),
        Answer::Refused {
            refusal: LimitRefusal::Work,
            injected: false,
        },
    ))
    .expect("a refusal fits");
    let forfeit = encode(Event::Credit(Credit::Forfeit(
        settled(None),
        Forfeit::Cancelled,
    )))
    .expect("a forfeit fits");
    let effect = encode(Event::Effect(Effect::Reserved {
        permit: id(1, 9),
        acquisition: id(2, 3),
    }))
    .expect("an effect fits");
    let released = encode(Event::Released(id(1, 9))).expect("a release fits");
    let custody = encode(Event::Custody {
        permit: id(1, 9),
        owner: id(4, 1),
        stage: RecordStage::Handle,
    })
    .expect("a custody transition fits");
    let mut cases: Vec<(&str, [u64; WORDS])> = Vec::new();
    let mut unknown_tag = released;
    unknown_tag[0] = 13;
    cases.push(("unknown tag", unknown_tag));
    let mut unknown_stage = custody;
    unknown_stage[5] = 6;
    cases.push(("unknown record stage", unknown_stage));
    let mut zero_stage = custody;
    zero_stage[5] = 0;
    cases.push(("zero record stage", zero_stage));
    let mut zero_tag = released;
    zero_tag[0] = 0;
    cases.push(("zero tag", zero_tag));
    let mut unknown_obligation = admit;
    unknown_obligation[3] = 4;
    cases.push(("unknown obligation", unknown_obligation));
    let mut unknown_refusal = refused;
    unknown_refusal[4] = 3 + 6;
    cases.push(("unknown refusal", unknown_refusal));
    let mut refusal_argument = refused;
    refusal_argument[5] = 1;
    cases.push(("argument of a refusal that takes none", refusal_argument));
    let mut injection = refused;
    injection[6] = 2;
    cases.push(("injection flag neither 0 nor 1", injection));
    let mut unknown_rule = forfeit;
    unknown_rule[10] = 5;
    cases.push(("unknown forfeiture rule", unknown_rule));
    let mut unknown_effect = effect;
    unknown_effect[1] = 3;
    cases.push(("unknown effect kind", unknown_effect));
    let mut stray = released;
    stray[3] = 1;
    cases.push(("nonzero word past the tag's fields", stray));
    let mut stray_last = forfeit;
    stray_last[WORDS - 1] = 1;
    cases.push(("nonzero last word", stray_last));
    for (defect, words) in cases {
        assert_eq!(decode(&words), None, "{defect}: {words:?} decoded");
    }
}
