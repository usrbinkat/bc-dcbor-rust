//! A run's one text: each observation's and each mark's canonical rendering
//! and its inverse, and the one canonical numbering of a run's identities.
//!
//! An identity is `FAMILY.SEQUENCE`. An observation is its publishing
//! family, its performer (a policy's number, or `-` for none) and its event:
//!
//! - `work V B ANSWER`, `reclaim V B ANSWER` (a cleanup unit), `allocate N
//!   ANSWER`; an answer is `admitted`,
//!   `granted ID` or `refused REASON`, then `injected` when injected; a
//!   reason is `turn`, `quantum-too-small`, `work`, `requested`, `storage`,
//!   `too-large`, `contended`, `deadline`, `cancelled`, `scheduled N` or
//!   `unrecorded`;
//! - `admit V B`, or `admit V B hold HOLD`; a hold is `KIND V B ID ACQ`;
//! - `spend KIND V B ID ACQ PERMIT`, `forfeit KIND V B ID ACQ PERMIT RULE`,
//!   `PERMIT` an identity or `-`;
//! - `reserved PERMIT ACQ`, `failed PERMIT ACQ`;
//! - `split PARENT CHILD N`, `merge SURVIVOR RETIRED N`, `released ID`;
//! - `owner ID`, `bound ACQ OWNER`, `end ACQ OWNER`;
//! - `custody PERMIT OWNER STAGE`, a stage `granted`, `handle`, `queued`,
//!   `active` or `reclaimed`.
//!
//! A mark is `@B` and: `checkpoint K` and its `K` custodies, each `owner ID
//! bound N` and its `N` acquisitions, `held N` and its `N` holds, then
//! `permits M` and its `M` permits, each an identity and its record stage
//! (`-` for a permit that is no record block);
//! `cleaning CAUSE` (`cancel`, or a class); `published M` and its `M`
//! identities. A class is `invalid`, `allocation`, `defect` or `refused
//! REASON`; an end `published`, `cancelled` or a class.
//!
//! Identities are numbered canonically ([`canonical`]): families, and within
//! each family its identities, by first appearance across the whole run,
//! performers likewise, so equal runs render equally and every relation the
//! machine reads (equality, distinction, family) is kept.

use std::collections::BTreeMap;

use crate::{
    Answer, Call, Cause, Checkpoint, Class, Credit, Custody, Effect, End, Event, Forfeit, Hold,
    Identity, LimitRefusal, Obligation, Observed, Performer, Publication, RecordStage, Reported,
    Run, Settled, WriteWork,
};

const STAGES: [RecordStage; 5] = [
    RecordStage::Granted,
    RecordStage::Handle,
    RecordStage::Queued,
    RecordStage::Active,
    RecordStage::Reclaimed,
];

pub(crate) const fn stage_name(stage: RecordStage) -> &'static str {
    match stage {
        RecordStage::Granted => "granted",
        RecordStage::Handle => "handle",
        RecordStage::Queued => "queued",
        RecordStage::Active => "active",
        RecordStage::Reclaimed => "reclaimed",
    }
}

fn record_text(record: Option<RecordStage>) -> &'static str {
    record.map_or("-", stage_name)
}

const OBLIGATIONS: [Obligation; 3] = [
    Obligation::Release,
    Obligation::Grant,
    Obligation::BucketWindow,
];

const FORFEITS: [Forfeit; 4] = [
    Forfeit::AcquisitionRefused,
    Forfeit::AcquisitionFailed,
    Forfeit::Cancelled,
    Forfeit::EnumerationComplete,
];

pub(crate) const fn obligation_name(obligation: Obligation) -> &'static str {
    match obligation {
        Obligation::Release => "release",
        Obligation::Grant => "grant",
        Obligation::BucketWindow => "bucket-window",
    }
}

pub(crate) const fn forfeit_name(rule: Forfeit) -> &'static str {
    match rule {
        Forfeit::AcquisitionRefused => "acquisition-refused",
        Forfeit::AcquisitionFailed => "acquisition-failed",
        Forfeit::Cancelled => "cancelled",
        Forfeit::EnumerationComplete => "enumeration-complete",
    }
}

pub(crate) fn refusal_name(refusal: LimitRefusal) -> String {
    match refusal {
        LimitRefusal::Work => "work".into(),
        LimitRefusal::Storage => "storage".into(),
        LimitRefusal::Deadline => "deadline".into(),
        LimitRefusal::Scheduled(index) => format!("scheduled {index}"),
        LimitRefusal::Unrecorded => "unrecorded".into(),
        LimitRefusal::Turn => "turn".into(),
        LimitRefusal::QuantumTooSmall => "quantum-too-small".into(),
        LimitRefusal::Requested => "requested".into(),
        LimitRefusal::TooLarge => "too-large".into(),
        LimitRefusal::Contended => "contended".into(),
        LimitRefusal::Cancelled => "cancelled".into(),
    }
}

pub(crate) fn work_text(work: WriteWork) -> String {
    format!("{} {}", work.values, work.bytes)
}

pub(crate) fn identity_text(identity: Identity) -> String {
    format!("{}.{}", identity.family(), identity.sequence())
}

fn permit_text(permit: Option<Identity>) -> String {
    permit.map_or_else(|| "-".to_string(), identity_text)
}

fn class_text(class: Class<LimitRefusal>) -> String {
    match class {
        Class::Invalid => "invalid".into(),
        Class::Allocation => "allocation".into(),
        Class::Defect => "defect".into(),
        Class::Refused(refusal) => format!("refused {}", refusal_name(refusal)),
    }
}

pub(crate) fn cause_text(cause: Cause) -> String {
    match cause {
        Cause::Cancel => "cancel".into(),
        Cause::Error(class) => class_text(class),
    }
}

pub(crate) fn end_text(end: End) -> String {
    match end {
        End::Published => "published".into(),
        End::Cancelled => "cancelled".into(),
        End::Failed(class) => class_text(class),
    }
}

fn hold_text(hold: &Hold) -> String {
    format!(
        "{} {} {} {}",
        obligation_name(hold.obligation),
        work_text(hold.work),
        identity_text(hold.id),
        identity_text(hold.acquisition)
    )
}

fn settled_text(settled: &Settled) -> String {
    format!(
        "{} {} {} {} {}",
        obligation_name(settled.obligation),
        work_text(settled.work),
        identity_text(settled.id),
        identity_text(settled.acquisition),
        permit_text(settled.permit)
    )
}

fn call_text(call: Call) -> String {
    match call {
        Call::Work { values, bytes } => format!("work {values} {bytes}"),
        Call::Reclaim { values, bytes } => format!("reclaim {values} {bytes}"),
        Call::Allocate(bytes) => format!("allocate {bytes}"),
    }
}

fn answer_text(answer: Answer) -> String {
    match answer {
        Answer::Admitted => "admitted".into(),
        Answer::Granted(permit) => format!("granted {}", identity_text(permit)),
        Answer::Refused { refusal, injected } => {
            let refused = format!("refused {}", refusal_name(refusal));
            if injected {
                format!("{refused} injected")
            } else {
                refused
            }
        }
    }
}

fn event_text(event: &Event) -> String {
    match event {
        Event::Call(call, answer) => format!("{} {}", call_text(*call), answer_text(*answer)),
        Event::Credit(Credit::Admit { work, held: None }) => format!("admit {}", work_text(*work)),
        Event::Credit(Credit::Admit {
            work,
            held: Some(hold),
        }) => format!("admit {} hold {}", work_text(*work), hold_text(hold)),
        Event::Credit(Credit::Spend(settled)) => format!("spend {}", settled_text(settled)),
        Event::Credit(Credit::Forfeit(settled, rule)) => {
            format!("forfeit {} {}", settled_text(settled), forfeit_name(*rule))
        }
        Event::Effect(Effect::Reserved {
            permit,
            acquisition,
        }) => format!(
            "reserved {} {}",
            identity_text(*permit),
            identity_text(*acquisition)
        ),
        Event::Effect(Effect::Failed {
            permit,
            acquisition,
        }) => format!(
            "failed {} {}",
            identity_text(*permit),
            identity_text(*acquisition)
        ),
        Event::Split {
            parent,
            child,
            bytes,
        } => format!(
            "split {} {} {bytes}",
            identity_text(*parent),
            identity_text(*child)
        ),
        Event::Merge {
            survivor,
            retired,
            bytes,
        } => format!(
            "merge {} {} {bytes}",
            identity_text(*survivor),
            identity_text(*retired)
        ),
        Event::Released(permit) => format!("released {}", identity_text(*permit)),
        Event::Owner(owner) => format!("owner {}", identity_text(*owner)),
        Event::Bound { acquisition, owner } => format!(
            "bound {} {}",
            identity_text(*acquisition),
            identity_text(*owner)
        ),
        Event::End { acquisition, owner } => format!(
            "end {} {}",
            identity_text(*acquisition),
            identity_text(*owner)
        ),
        Event::Custody {
            permit,
            owner,
            stage,
        } => format!(
            "custody {} {} {}",
            identity_text(*permit),
            identity_text(*owner),
            stage_name(*stage)
        ),
    }
}

/// One observation's text.
pub fn render_observed(observed: &Observed) -> String {
    let by = match observed.by {
        Performer::Policy(policy) => policy.to_string(),
        Performer::None => "-".into(),
    };
    format!("{} {by} {}", observed.family, event_text(&observed.event))
}

fn custody_text(custody: &Custody) -> String {
    let mut text = format!(
        "owner {} bound {}",
        identity_text(custody.owner),
        custody.bound.len()
    );
    for acquisition in &custody.bound {
        text.push(' ');
        text.push_str(&identity_text(*acquisition));
    }
    text.push_str(&format!(" held {}", custody.held.len()));
    for hold in &custody.held {
        text.push(' ');
        text.push_str(&hold_text(hold));
    }
    text.push_str(&format!(" permits {}", custody.permits.len()));
    for reported in &custody.permits {
        text.push(' ');
        text.push_str(&identity_text(reported.permit));
        text.push(' ');
        text.push_str(record_text(reported.record));
    }
    text
}

/// A run's three recorded columns, each canonical (`canonical`): its
/// observations, separated by `; `; its marks in boundary order, separated
/// by `; `; its end.
pub fn render_run(run: &Run) -> (String, String, String) {
    let run = canonical(run);
    let observed = run
        .observed
        .iter()
        .map(render_observed)
        .collect::<Vec<_>>()
        .join("; ");
    let mut marks: Vec<(usize, String)> = run
        .checkpoints
        .iter()
        .map(|checkpoint| {
            let mut text = format!(
                "@{} checkpoint {}",
                checkpoint.boundary,
                checkpoint.custody.len()
            );
            for custody in &checkpoint.custody {
                text.push(' ');
                text.push_str(&custody_text(custody));
            }
            (checkpoint.boundary, text)
        })
        .collect();
    if let Some((boundary, cause)) = run.cleaning {
        marks.push((
            boundary,
            format!("@{boundary} cleaning {}", cause_text(cause)),
        ));
    }
    if let Some(publication) = &run.published {
        let mut text = format!(
            "@{} published {}",
            publication.boundary,
            publication.permits.len()
        );
        for permit in &publication.permits {
            text.push(' ');
            text.push_str(&identity_text(*permit));
        }
        marks.push((publication.boundary, text));
    }
    marks.sort_by_key(|&(boundary, _)| boundary);
    let marks = marks
        .into_iter()
        .map(|(_, text)| text)
        .collect::<Vec<_>>()
        .join("; ");
    (observed, marks, end_text(run.end))
}

/// The words of one observation or mark, read in order, each refusal naming
/// what it expected.
struct Words<'t> {
    words: std::str::SplitWhitespace<'t>,
}

impl<'t> Words<'t> {
    fn new(text: &'t str) -> Self {
        Self {
            words: text.split_whitespace(),
        }
    }

    fn word(&mut self, what: &str) -> Result<&'t str, String> {
        self.words.next().ok_or_else(|| format!("missing {what}"))
    }

    fn exact(&mut self, expected: &str) -> Result<(), String> {
        let word = self.word(expected)?;
        if word == expected {
            Ok(())
        } else {
            Err(format!("{word:?} where {expected:?} was expected"))
        }
    }

    fn number(&mut self, what: &str) -> Result<u64, String> {
        let word = self.word(what)?;
        word.parse::<u64>()
            .map_err(|error| format!("{what} {word:?}: {error}"))
    }

    fn count(&mut self, what: &str) -> Result<usize, String> {
        let word = self.word(what)?;
        word.parse::<usize>()
            .map_err(|error| format!("{what} {word:?}: {error}"))
    }

    fn work(&mut self) -> Result<WriteWork, String> {
        Ok(WriteWork::new(
            self.number("values")?,
            self.number("bytes")?,
        ))
    }

    fn identity(&mut self, what: &str) -> Result<Identity, String> {
        let word = self.word(what)?;
        let (family, sequence) = word
            .split_once('.')
            .ok_or_else(|| format!("{what} {word:?} is not FAMILY.SEQUENCE"))?;
        let part = |digits: &str| {
            digits
                .parse::<u64>()
                .map_err(|error| format!("{what} {word:?}: {error}"))
        };
        Ok(Identity::new(part(family)?, part(sequence)?))
    }

    fn permit(&mut self) -> Result<Option<Identity>, String> {
        let word = self.word("permit")?;
        if word == "-" {
            return Ok(None);
        }
        Words::new(word).identity("permit").map(Some)
    }

    fn obligation(&mut self) -> Result<Obligation, String> {
        let word = self.word("obligation")?;
        OBLIGATIONS
            .into_iter()
            .find(|obligation| obligation_name(*obligation) == word)
            .ok_or_else(|| format!("{word:?} is not an obligation"))
    }

    fn forfeit(&mut self) -> Result<Forfeit, String> {
        let word = self.word("forfeiture rule")?;
        FORFEITS
            .into_iter()
            .find(|rule| forfeit_name(*rule) == word)
            .ok_or_else(|| format!("{word:?} is not a forfeiture rule"))
    }

    fn refusal(&mut self) -> Result<LimitRefusal, String> {
        match self.word("refusal")? {
            "work" => Ok(LimitRefusal::Work),
            "storage" => Ok(LimitRefusal::Storage),
            "deadline" => Ok(LimitRefusal::Deadline),
            "unrecorded" => Ok(LimitRefusal::Unrecorded),
            "turn" => Ok(LimitRefusal::Turn),
            "quantum-too-small" => Ok(LimitRefusal::QuantumTooSmall),
            "requested" => Ok(LimitRefusal::Requested),
            "too-large" => Ok(LimitRefusal::TooLarge),
            "contended" => Ok(LimitRefusal::Contended),
            "cancelled" => Ok(LimitRefusal::Cancelled),
            "scheduled" => {
                let index = self.count("scheduled call")?;
                Ok(LimitRefusal::Scheduled(index))
            }
            word => Err(format!("{word:?} is not a refusal")),
        }
    }

    fn class(&mut self) -> Result<Class<LimitRefusal>, String> {
        match self.word("class")? {
            "invalid" => Ok(Class::Invalid),
            "allocation" => Ok(Class::Allocation),
            "defect" => Ok(Class::Defect),
            "refused" => Ok(Class::Refused(self.refusal()?)),
            word => Err(format!("{word:?} is not a class")),
        }
    }

    fn hold(&mut self) -> Result<Hold, String> {
        Ok(Hold {
            obligation: self.obligation()?,
            work: self.work()?,
            id: self.identity("obligation identity")?,
            acquisition: self.identity("acquisition")?,
        })
    }

    fn settled(&mut self) -> Result<Settled, String> {
        Ok(Settled {
            obligation: self.obligation()?,
            work: self.work()?,
            id: self.identity("obligation identity")?,
            acquisition: self.identity("acquisition")?,
            permit: self.permit()?,
        })
    }

    fn answer(&mut self) -> Result<Answer, String> {
        match self.word("answer")? {
            "admitted" => Ok(Answer::Admitted),
            "granted" => Ok(Answer::Granted(self.identity("permit")?)),
            "refused" => {
                let refusal = self.refusal()?;
                let injected = match self.words.clone().next() {
                    Some("injected") => {
                        self.words.next();
                        true
                    }
                    _ => false,
                };
                Ok(Answer::Refused { refusal, injected })
            }
            word => Err(format!("{word:?} is not an answer")),
        }
    }

    fn event(&mut self) -> Result<Event, String> {
        Ok(match self.word("event")? {
            "work" => {
                let (values, bytes) = (self.number("values")?, self.number("bytes")?);
                Event::Call(Call::Work { values, bytes }, self.answer()?)
            }
            "reclaim" => {
                let (values, bytes) = (self.number("values")?, self.number("bytes")?);
                Event::Call(Call::Reclaim { values, bytes }, self.answer()?)
            }
            "allocate" => {
                let bytes = self.number("bytes")?;
                Event::Call(Call::Allocate(bytes), self.answer()?)
            }
            "admit" => {
                let work = self.work()?;
                let held = match self.words.clone().next() {
                    Some("hold") => {
                        self.words.next();
                        Some(self.hold()?)
                    }
                    _ => None,
                };
                Event::Credit(Credit::Admit { work, held })
            }
            "spend" => Event::Credit(Credit::Spend(self.settled()?)),
            "forfeit" => {
                let settled = self.settled()?;
                Event::Credit(Credit::Forfeit(settled, self.forfeit()?))
            }
            "reserved" => Event::Effect(Effect::Reserved {
                permit: self.identity("permit")?,
                acquisition: self.identity("acquisition")?,
            }),
            "failed" => Event::Effect(Effect::Failed {
                permit: self.identity("permit")?,
                acquisition: self.identity("acquisition")?,
            }),
            "split" => Event::Split {
                parent: self.identity("parent")?,
                child: self.identity("child")?,
                bytes: self.number("bytes")?,
            },
            "merge" => Event::Merge {
                survivor: self.identity("survivor")?,
                retired: self.identity("retired")?,
                bytes: self.number("bytes")?,
            },
            "released" => Event::Released(self.identity("permit")?),
            "owner" => Event::Owner(self.identity("owner")?),
            "bound" => Event::Bound {
                acquisition: self.identity("acquisition")?,
                owner: self.identity("owner")?,
            },
            "end" => Event::End {
                acquisition: self.identity("acquisition")?,
                owner: self.identity("owner")?,
            },
            "custody" => Event::Custody {
                permit: self.identity("permit")?,
                owner: self.identity("owner")?,
                stage: self.stage()?,
            },
            word => return Err(format!("{word:?} is not an event")),
        })
    }

    fn stage(&mut self) -> Result<RecordStage, String> {
        let word = self.word("record stage")?;
        STAGES
            .into_iter()
            .find(|stage| stage_name(*stage) == word)
            .ok_or_else(|| format!("{word:?} is not a record stage"))
    }

    /// A reported permit: its identity, then its record stage or `-`.
    fn reported(&mut self) -> Result<Reported, String> {
        let permit = self.identity("permit")?;
        let record = match self.words.clone().next() {
            Some("-") => {
                self.word("record stage")?;
                None
            }
            _ => Some(self.stage()?),
        };
        Ok(Reported { permit, record })
    }

    /// Refused unless every word was read.
    fn done(mut self) -> Result<(), String> {
        match self.words.next() {
            None => Ok(()),
            Some(word) => Err(format!("{word:?} after the end")),
        }
    }
}

/// One observation from its text, the inverse of [`render_observed`]: text
/// that is not its canonical rendering is refused.
pub fn parse_observed(text: &str) -> Result<Observed, String> {
    let mut words = Words::new(text);
    let family = words.number("family")?;
    let by = match words.word("performer")? {
        "-" => Performer::None,
        policy => Performer::Policy(
            policy
                .parse::<u64>()
                .map_err(|error| format!("performer {policy:?}: {error}"))?,
        ),
    };
    let event = words.event()?;
    words.done()?;
    let observed = Observed { family, by, event };
    if render_observed(&observed) != text {
        return Err(format!(
            "{text:?} is not the canonical text of its observation"
        ));
    }
    Ok(observed)
}

/// A run from its three recorded columns, the inverse of [`render_run`]:
/// every observation and mark in canonical text, the marks in boundary
/// order, at most one cleaning and one publication, and the run's
/// identities canonically numbered.
pub(crate) fn parse_run(observed: &str, marks: &str, end: &str) -> Result<Run, String> {
    let split = |column: &str| -> Vec<String> {
        if column.is_empty() {
            Vec::new()
        } else {
            column.split("; ").map(str::to_string).collect()
        }
    };
    let column = observed;
    let observed = split(column)
        .iter()
        .map(|text| parse_observed(text))
        .collect::<Result<Vec<_>, _>>()?;
    let mut run = Run {
        observed,
        checkpoints: Vec::new(),
        cleaning: None,
        published: None,
        end: parse_end(end)?,
    };
    for text in split(marks) {
        let mut words = Words::new(&text);
        let at = words.word("mark")?;
        let boundary = at
            .strip_prefix('@')
            .ok_or_else(|| format!("{text:?} is not a mark"))?
            .parse::<usize>()
            .map_err(|error| format!("{text:?}: boundary: {error}"))?;
        match words.word("mark kind")? {
            "checkpoint" => {
                let owners = words.count("custodies")?;
                let mut custody = Vec::new();
                for _ in 0..owners {
                    words.exact("owner")?;
                    let owner = words.identity("owner")?;
                    words.exact("bound")?;
                    let bound = (0..words.count("bindings")?)
                        .map(|_| words.identity("acquisition"))
                        .collect::<Result<Vec<_>, _>>()?;
                    words.exact("held")?;
                    let held = (0..words.count("holds")?)
                        .map(|_| words.hold())
                        .collect::<Result<Vec<_>, _>>()?;
                    words.exact("permits")?;
                    let permits = (0..words.count("permits")?)
                        .map(|_| words.reported())
                        .collect::<Result<Vec<_>, _>>()?;
                    custody.push(Custody {
                        owner,
                        bound,
                        held,
                        permits,
                    });
                }
                run.checkpoints.push(Checkpoint { boundary, custody });
            }
            "cleaning" => {
                if run.cleaning.is_some() {
                    return Err(format!("{text:?}: a second cleaning"));
                }
                let cause = match words.words.clone().next() {
                    Some("cancel") => {
                        words.words.next();
                        Cause::Cancel
                    }
                    _ => Cause::Error(words.class()?),
                };
                run.cleaning = Some((boundary, cause));
            }
            "published" => {
                if run.published.is_some() {
                    return Err(format!("{text:?}: a second publication"));
                }
                let permits = (0..words.count("permits")?)
                    .map(|_| words.identity("permit"))
                    .collect::<Result<Vec<_>, _>>()?;
                run.published = Some(Publication { boundary, permits });
            }
            kind => return Err(format!("{text:?}: {kind:?} is not a mark")),
        }
        words.done().map_err(|error| format!("{text:?}: {error}"))?;
    }
    // The columns read must be exactly the run's canonical rendering: its
    // identities canonically numbered and its marks in boundary order.
    let (rendered_observed, rendered_marks, rendered_end) = render_run(&run);
    if (
        rendered_observed.as_str(),
        rendered_marks.as_str(),
        rendered_end.as_str(),
    ) != (column, marks, end)
    {
        return Err("the run is not in its canonical text".into());
    }
    Ok(run)
}

fn parse_end(text: &str) -> Result<End, String> {
    let mut words = Words::new(text);
    let end = match words.words.clone().next() {
        Some("published") => {
            words.words.next();
            End::Published
        }
        Some("cancelled") => {
            words.words.next();
            End::Cancelled
        }
        _ => End::Failed(words.class()?),
    };
    words.done()?;
    Ok(end)
}

/// The one canonical numbering of a run's identities: families by first
/// appearance across the run (observations in order, each field in its
/// rendering's order, then the marks in boundary order), from 1; within each
/// family its identities by first appearance, from 1; performers likewise.
/// The numbering is a bijection on what the run names, so equality,
/// distinction and family membership are kept; family 0 and
/// [`Identity::UNOBSERVED`] stay as they are, for the machine to refuse.
pub(crate) fn canonical(run: &Run) -> Run {
    let mut canon = Canon::default();
    let observed = run
        .observed
        .iter()
        .map(|observed| canon.observed(observed))
        .collect();
    let mut marks: Vec<(usize, u8, usize)> = run
        .checkpoints
        .iter()
        .enumerate()
        .map(|(index, checkpoint)| (checkpoint.boundary, 0, index))
        .collect();
    if let Some((boundary, _)) = run.cleaning {
        marks.push((boundary, 1, 0));
    }
    if let Some(publication) = &run.published {
        marks.push((publication.boundary, 2, 0));
    }
    marks.sort_by_key(|&(boundary, _, _)| boundary);
    let mut checkpoints = vec![None; run.checkpoints.len()];
    let mut published = None;
    for (_, kind, index) in marks {
        match kind {
            0 => {
                let checkpoint = &run.checkpoints[index];
                checkpoints[index] = Some(Checkpoint {
                    boundary: checkpoint.boundary,
                    custody: checkpoint
                        .custody
                        .iter()
                        .map(|custody| Custody {
                            owner: canon.identity(custody.owner),
                            bound: custody
                                .bound
                                .iter()
                                .map(|acquisition| canon.identity(*acquisition))
                                .collect(),
                            held: custody.held.iter().map(|hold| canon.hold(hold)).collect(),
                            permits: custody
                                .permits
                                .iter()
                                .map(|reported| Reported {
                                    permit: canon.identity(reported.permit),
                                    record: reported.record,
                                })
                                .collect(),
                        })
                        .collect(),
                });
            }
            2 => {
                if let Some(publication) = &run.published {
                    published = Some(Publication {
                        boundary: publication.boundary,
                        permits: publication
                            .permits
                            .iter()
                            .map(|permit| canon.identity(*permit))
                            .collect(),
                    });
                }
            }
            _ => {}
        }
    }
    Run {
        observed,
        checkpoints: checkpoints.into_iter().flatten().collect(),
        cleaning: run.cleaning,
        published,
        end: run.end,
    }
}

/// The numbering [`canonical`] builds as it reads.
#[derive(Default)]
struct Canon {
    families: BTreeMap<u64, u64>,
    sequences: BTreeMap<u64, u64>,
    identities: BTreeMap<Identity, Identity>,
    performers: BTreeMap<u64, u64>,
}

impl Canon {
    fn family(&mut self, family: u64) -> u64 {
        if family == 0 {
            return 0;
        }
        let next = self.families.len() as u64 + 1;
        *self.families.entry(family).or_insert(next)
    }

    fn identity(&mut self, identity: Identity) -> Identity {
        if identity == Identity::UNOBSERVED || identity.family() == 0 {
            return identity;
        }
        if let Some(&mapped) = self.identities.get(&identity) {
            return mapped;
        }
        let family = self.family(identity.family());
        let sequence = self.sequences.entry(family).or_insert(0);
        *sequence += 1;
        let mapped = Identity::new(family, *sequence);
        self.identities.insert(identity, mapped);
        mapped
    }

    fn performer(&mut self, by: Performer) -> Performer {
        match by {
            Performer::None => Performer::None,
            Performer::Policy(policy) => {
                let next = self.performers.len() as u64 + 1;
                Performer::Policy(*self.performers.entry(policy).or_insert(next))
            }
        }
    }

    fn hold(&mut self, hold: &Hold) -> Hold {
        Hold {
            obligation: hold.obligation,
            work: hold.work,
            id: self.identity(hold.id),
            acquisition: self.identity(hold.acquisition),
        }
    }

    fn settled(&mut self, settled: &Settled) -> Settled {
        Settled {
            obligation: settled.obligation,
            work: settled.work,
            id: self.identity(settled.id),
            acquisition: self.identity(settled.acquisition),
            permit: settled.permit.map(|permit| self.identity(permit)),
        }
    }

    fn observed(&mut self, observed: &Observed) -> Observed {
        let family = self.family(observed.family);
        let by = self.performer(observed.by);
        let event = match observed.event {
            Event::Call(call, Answer::Granted(permit)) => {
                Event::Call(call, Answer::Granted(self.identity(permit)))
            }
            Event::Call(call, answer) => Event::Call(call, answer),
            Event::Credit(Credit::Admit { work, held }) => Event::Credit(Credit::Admit {
                work,
                held: held.map(|hold| self.hold(&hold)),
            }),
            Event::Credit(Credit::Spend(settled)) => {
                Event::Credit(Credit::Spend(self.settled(&settled)))
            }
            Event::Credit(Credit::Forfeit(settled, rule)) => {
                Event::Credit(Credit::Forfeit(self.settled(&settled), rule))
            }
            Event::Effect(Effect::Reserved {
                permit,
                acquisition,
            }) => Event::Effect(Effect::Reserved {
                permit: self.identity(permit),
                acquisition: self.identity(acquisition),
            }),
            Event::Effect(Effect::Failed {
                permit,
                acquisition,
            }) => Event::Effect(Effect::Failed {
                permit: self.identity(permit),
                acquisition: self.identity(acquisition),
            }),
            Event::Split {
                parent,
                child,
                bytes,
            } => Event::Split {
                parent: self.identity(parent),
                child: self.identity(child),
                bytes,
            },
            Event::Merge {
                survivor,
                retired,
                bytes,
            } => Event::Merge {
                survivor: self.identity(survivor),
                retired: self.identity(retired),
                bytes,
            },
            Event::Released(permit) => Event::Released(self.identity(permit)),
            Event::Owner(owner) => Event::Owner(self.identity(owner)),
            Event::Bound { acquisition, owner } => Event::Bound {
                acquisition: self.identity(acquisition),
                owner: self.identity(owner),
            },
            Event::End { acquisition, owner } => Event::End {
                acquisition: self.identity(acquisition),
                owner: self.identity(owner),
            },
            Event::Custody {
                permit,
                owner,
                stage,
            } => Event::Custody {
                permit: self.identity(permit),
                owner: self.identity(owner),
                stage,
            },
        };
        Observed { family, by, event }
    }
}
