//! The machine's state, keyed by the identities a session minted, and the
//! rules it refuses an observation by.

use crate::text::{cause_text, identity_text, refusal_name, work_text};
use crate::{
    Answer, Call, Cause, End, Forfeit, Identity, LimitRefusal, Obligation, RecordStage, WriteWork,
};

/// A held obligation, keyed by its identity, whose family is its origin's.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Held {
    pub obligation: Obligation,
    pub acquisition: Identity,
    pub remaining: WriteWork,
}

/// Where a permit is in its life. Its physical outcome is kept apart
/// ([`Outcome`]); no credit event moves either.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Life {
    /// Held: it may be split, merged, given its outcome and released.
    Live,
    /// Merged into another: its drop releases nothing.
    Retired,
    /// Released by its drop.
    Released,
}

/// A permit's observed physical outcome (`Event::Effect`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Reserved,
    Failed,
}

/// How a permit came to be.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    /// A granted allocation, whose reservation's outcome is observed.
    Granted,
    /// A split's child: part of a reservation that already exists.
    Split,
}

/// A permit, keyed by its identity: its bytes, how it was made, the
/// acquisition its release was spent for (a split's child inherits its
/// parent's), its observed outcome, its life, and, for a record block's,
/// its record's lifecycle ([`RecordState`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Permit {
    pub bytes: u64,
    pub source: Source,
    pub acquisition: Option<Identity>,
    pub outcome: Option<Outcome>,
    pub life: Life,
    pub record: Option<RecordState>,
}

/// A record block's lifecycle (`Event::Custody`): the owner whose
/// acquisition granted it, fixed at its classification, and the stage its
/// holder holds it under.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecordState {
    pub owner: Identity,
    pub stage: RecordStage,
}

/// An acquisition, keyed by its identity: the owner that bound it
/// (`Event::Bound`), kept after its end for attribution. Whether it is
/// still active (bound and not yet ended, `Event::End`) is the machine's
/// set of unended acquisitions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AcquisitionState {
    pub owner: Identity,
}

/// One family's ledgers, from the events it published.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Ledger {
    pub admitted: WriteWork,
    pub consumed: WriteWork,
    pub forfeited: WriteWork,
}

/// Where the machine refused: an observation, by its index in the session's
/// stream; a checkpoint, by its index among the run's; or one of the run's
/// own marks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum At {
    Observation(usize),
    Checkpoint(usize),
    Cleaning,
    Published,
    End,
}

/// Why the machine refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rule {
    /// A mark placed past the session's stream.
    BoundaryPastEnd {
        boundary: usize,
        len: usize,
    },
    /// A mark placed before an earlier one.
    BoundaryDecreasing {
        boundary: usize,
        previous: usize,
    },
    /// An identity no recorded family mints.
    Unobserved,
    /// An identity minted twice.
    Reissued(Identity),
    /// An observation published by a family other than the one that owns
    /// the identity it names.
    WrongFamily {
        identity: Identity,
        publisher: u64,
    },
    UnknownOwner(Identity),
    UnknownAcquisition(Identity),
    UnknownObligation(Identity),
    UnknownPermit(Identity),
    /// A call answered as no call of its kind is.
    UnexpectedAnswer(Call, Answer),
    /// An admitted work call whose performer called again, or the run
    /// ended, before admitting it.
    MissingAdmission(WriteWork),
    /// An admission no admitted work call of its performer made.
    UnauthorizedAdmission(WriteWork),
    /// An admission of other work than its call admitted.
    AdmissionMismatch {
        call: WriteWork,
        admitted: WriteWork,
    },
    /// An admission no policy performed.
    AdmissionWithoutPolicy,
    /// An admission holding more than it admitted.
    Overheld,
    /// A settlement naming another acquisition than its obligation's.
    AcquisitionMismatch {
        obligation: Identity,
        held: Identity,
        named: Identity,
    },
    /// A settlement naming another kind than its obligation's.
    KindMismatch {
        obligation: Identity,
        held: Obligation,
        named: Obligation,
    },
    /// A settlement of more than its obligation holds.
    Overdrawn {
        obligation: Identity,
        remaining: WriteWork,
        settled: WriteWork,
    },
    /// A release or grant settled in part, or a forfeit of part.
    Partial(Identity),
    /// A forfeit under a rule that does not name its obligation's kind.
    UnnamedForfeit(Obligation, Forfeit),
    /// A release spent with no permit, or a window settled at one.
    PermitLink(Identity),
    /// A release forfeited at a permit: once granted, its release is spent.
    ReleaseForfeitedAfterGrant(Identity),
    /// A release spent at a permit already carrying one.
    PermitBound(Identity),
    /// A permit named for another acquisition than its release was spent for.
    PermitAcquisition {
        permit: Identity,
        bound: Option<Identity>,
        named: Identity,
    },
    /// A grant spent at a permit whose reservation was not observed made,
    /// or forfeited as failed at one not observed failed.
    MissingEffect {
        permit: Identity,
        required: Outcome,
    },
    /// A second outcome for one permit, or one for a split's child.
    EffectInvalid(Identity),
    /// A transition its permit's life forbids.
    PermitLife {
        permit: Identity,
        life: Life,
    },
    /// A merge of a permit into itself.
    SelfMerge(Identity),
    /// A split taking more than its parent holds.
    SplitOverdrawn {
        permit: Identity,
        held: u64,
        taken: u64,
    },
    /// A merge passing other than every byte of its input.
    MergeMismatch {
        permit: Identity,
        held: u64,
        passed: u64,
    },
    /// A split or merge across families.
    ForeignTransfer {
        left: Identity,
        right: Identity,
    },
    /// A held admission once cleanup began.
    HoldInCleanup,
    /// An allocation requested once cleanup began.
    AllocateInCleanup,
    /// Cleanup begun for a refusal other than the outstanding one.
    RefusalUnmatched {
        cause: Cause,
        outstanding: Option<LimitRefusal>,
    },
    /// Cleanup begun for a physical failure no permit suffered.
    NoFailedPermit,
    /// Publication while a refusal is outstanding.
    PublishedRefused(LimitRefusal),
    /// Publication once cleanup began.
    PublishedAfterCleaning,
    /// A published permit not live.
    PublishedPermit(Identity),
    /// A checkpoint while an admission, a permit's acquisition or a failed
    /// permit's release is between its steps.
    MidStep,
    /// One identity twice in one checkpoint.
    Duplicate(Identity),
    /// An acquisition reported bound under an owner other than the one that
    /// bound it (`Event::Bound`).
    BindingElsewhere {
        owner: Identity,
        acquisition: Identity,
        bound: Identity,
    },
    /// An obligation the owner holds that its custody did not report.
    MissingHeld {
        owner: Identity,
        obligation: Identity,
    },
    /// An obligation reported that the owner does not hold.
    ExtraHeld {
        owner: Identity,
        obligation: Identity,
    },
    /// An obligation reported other than the machine holds it.
    HeldMismatch {
        obligation: Identity,
        remaining: WriteWork,
        reported: WriteWork,
    },
    /// A permit the owner holds that its custody did not report.
    MissingPermit {
        owner: Identity,
        permit: Identity,
    },
    /// A permit reported that the owner does not hold.
    ExtraPermit {
        owner: Identity,
        permit: Identity,
    },
    /// A permit still live once the run is over.
    Leaked(Identity),
    /// An obligation still holding work once the run is over.
    Outstanding(Identity),
    /// A granted permit whose release was never spent for an acquisition.
    Unpaid(Identity),
    /// A granted permit whose reservation's outcome was never observed.
    NoEffect(Identity),
    /// The end disagrees with what the run reached.
    EndMismatch {
        end: End,
        reached: Option<End>,
    },
    /// A quantity does not fit in `u64`.
    Overflow,
    /// An acquisition already ended, ended again or admitted for.
    AcquisitionEnded(Identity),
    /// An acquisition ended while an obligation admitted for it still holds
    /// work.
    EndOutstanding {
        acquisition: Identity,
        obligation: Identity,
    },
    /// An acquisition ended for another owner than the one that bound it.
    EndOwner {
        acquisition: Identity,
        bound: Identity,
        named: Identity,
    },
    /// An acquisition still active once the run is over.
    Unended(Identity),
    /// An active acquisition the owner's custody did not report bound.
    MissingBinding {
        owner: Identity,
        acquisition: Identity,
    },
    /// A binding reported for an acquisition that has ended.
    StaleBinding {
        owner: Identity,
        acquisition: Identity,
    },
    /// A record transition its permit's record stage forbids: the stage it
    /// held (none, an ordinary or unclassified permit) and the one named.
    RecordTransition {
        permit: Identity,
        from: Option<RecordStage>,
        to: RecordStage,
    },
    /// A record transition naming another owner than its record's, or one
    /// other than the owner that bound the acquisition granting the permit.
    RecordOwner {
        permit: Identity,
        owner: Identity,
        named: Identity,
    },
    /// A record block released before its cleanup completed.
    PrematureRecordRelease {
        permit: Identity,
        stage: RecordStage,
    },
    /// A permit reported under another record stage than its record holds
    /// (none for a permit that is no record block).
    HolderMismatch {
        permit: Identity,
        expected: Option<RecordStage>,
        reported: Option<RecordStage>,
    },
}

impl core::fmt::Display for Rule {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let id = |identity: &Identity| identity_text(*identity);
        match self {
            Self::BoundaryPastEnd { boundary, len } => {
                write!(
                    f,
                    "boundary {boundary} past the stream's {len} observations"
                )
            }
            Self::BoundaryDecreasing { boundary, previous } => {
                write!(f, "boundary {boundary} before the earlier {previous}")
            }
            Self::Unobserved => f.write_str("an identity no recorded family mints"),
            Self::Reissued(identity) => write!(f, "{} minted twice", id(identity)),
            Self::WrongFamily {
                identity,
                publisher,
            } => write!(f, "{} published by family {publisher}", id(identity)),
            Self::UnknownOwner(identity) => write!(f, "owner {} was never made", id(identity)),
            Self::UnknownAcquisition(identity) => {
                write!(f, "acquisition {} was never bound", id(identity))
            }
            Self::UnknownObligation(identity) => {
                write!(f, "obligation {} was never admitted", id(identity))
            }
            Self::UnknownPermit(identity) => {
                write!(f, "permit {} was never given", id(identity))
            }
            Self::UnexpectedAnswer(call, answer) => {
                write!(f, "{call:?} answered {answer:?}")
            }
            Self::MissingAdmission(work) => write!(
                f,
                "a work call of {} admitted without its admission",
                work_text(*work)
            ),
            Self::UnauthorizedAdmission(work) => write!(
                f,
                "an admission of {} no admitted work call made",
                work_text(*work)
            ),
            Self::AdmissionMismatch { call, admitted } => write!(
                f,
                "an admission of {} for a work call of {}",
                work_text(*admitted),
                work_text(*call)
            ),
            Self::AdmissionWithoutPolicy => f.write_str("an admission no policy performed"),
            Self::Overheld => f.write_str("an admission holding more than it admitted"),
            Self::AcquisitionMismatch {
                obligation,
                held,
                named,
            } => write!(
                f,
                "obligation {} of acquisition {} settled for {}",
                id(obligation),
                id(held),
                id(named)
            ),
            Self::KindMismatch {
                obligation,
                held,
                named,
            } => write!(
                f,
                "obligation {} held as {held:?} settled as {named:?}",
                id(obligation)
            ),
            Self::Overdrawn {
                obligation,
                remaining,
                settled,
            } => write!(
                f,
                "obligation {} settled {} where {} remains",
                id(obligation),
                work_text(*settled),
                work_text(*remaining)
            ),
            Self::Partial(obligation) => {
                write!(f, "obligation {} settled in part", id(obligation))
            }
            Self::UnnamedForfeit(obligation, rule) => {
                write!(
                    f,
                    "{obligation:?} forfeited under {rule:?}, a rule that does not name it"
                )
            }
            Self::PermitLink(obligation) => write!(
                f,
                "obligation {} settled with a permit link its kind does not take",
                id(obligation)
            ),
            Self::ReleaseForfeitedAfterGrant(obligation) => write!(
                f,
                "release {} forfeited at a granted permit",
                id(obligation)
            ),
            Self::PermitBound(permit) => {
                write!(f, "permit {} already carries a release", id(permit))
            }
            Self::PermitAcquisition {
                permit,
                bound,
                named,
            } => write!(
                f,
                "permit {} of acquisition {} named for {}",
                id(permit),
                bound.as_ref().map_or_else(|| "none".to_string(), id),
                id(named)
            ),
            Self::MissingEffect { permit, required } => write!(
                f,
                "permit {}'s reservation was not observed {required:?}",
                id(permit)
            ),
            Self::EffectInvalid(permit) => {
                write!(f, "an outcome permit {} cannot have", id(permit))
            }
            Self::PermitLife { permit, life } => write!(
                f,
                "permit {} is {life:?}, which forbids this transition",
                id(permit)
            ),
            Self::SelfMerge(permit) => write!(f, "permit {} merged into itself", id(permit)),
            Self::SplitOverdrawn {
                permit,
                held,
                taken,
            } => write!(
                f,
                "a split takes {taken} bytes from permit {}, which holds {held}",
                id(permit)
            ),
            Self::MergeMismatch {
                permit,
                held,
                passed,
            } => write!(
                f,
                "a merge passes {passed} bytes of permit {}, which holds {held}",
                id(permit)
            ),
            Self::ForeignTransfer { left, right } => write!(
                f,
                "a transfer between {} and {} of different families",
                id(left),
                id(right)
            ),
            Self::HoldInCleanup => f.write_str("a held admission in cleanup"),
            Self::AllocateInCleanup => f.write_str("an allocation requested in cleanup"),
            Self::RefusalUnmatched { cause, outstanding } => write!(
                f,
                "cleanup for {} with {} outstanding",
                cause_text(*cause),
                outstanding.map_or_else(|| "no refusal".to_string(), refusal_name)
            ),
            Self::NoFailedPermit => {
                f.write_str("cleanup for a physical failure no permit suffered")
            }
            Self::PublishedRefused(refusal) => write!(
                f,
                "published with refusal {} outstanding",
                refusal_name(*refusal)
            ),
            Self::PublishedAfterCleaning => f.write_str("published once cleanup began"),
            Self::PublishedPermit(permit) => {
                write!(f, "published permit {} is not live", id(permit))
            }
            Self::MidStep => f.write_str("a checkpoint inside a step"),
            Self::Duplicate(identity) => {
                write!(f, "{} twice in one checkpoint", id(identity))
            }
            Self::BindingElsewhere {
                owner,
                acquisition,
                bound,
            } => write!(
                f,
                "owner {}'s custody reports acquisition {} bound, which owner {} bound",
                id(owner),
                id(acquisition),
                id(bound)
            ),
            Self::MissingHeld { owner, obligation } => write!(
                f,
                "owner {} holds obligation {}, which its custody did not report",
                id(owner),
                id(obligation)
            ),
            Self::ExtraHeld { owner, obligation } => write!(
                f,
                "owner {}'s custody reports obligation {}, which it does not hold",
                id(owner),
                id(obligation)
            ),
            Self::HeldMismatch {
                obligation,
                remaining,
                reported,
            } => write!(
                f,
                "obligation {} holds {} where its custody reports {}",
                id(obligation),
                work_text(*remaining),
                work_text(*reported)
            ),
            Self::MissingPermit { owner, permit } => write!(
                f,
                "owner {} holds permit {}, which its custody did not report",
                id(owner),
                id(permit)
            ),
            Self::ExtraPermit { owner, permit } => write!(
                f,
                "owner {}'s custody reports permit {}, which it does not hold",
                id(owner),
                id(permit)
            ),
            Self::Leaked(permit) => write!(f, "permit {} is still live", id(permit)),
            Self::Outstanding(obligation) => {
                write!(f, "obligation {} still holds work", id(obligation))
            }
            Self::Unpaid(permit) => {
                write!(f, "permit {}'s release was never spent", id(permit))
            }
            Self::NoEffect(permit) => write!(
                f,
                "permit {}'s reservation outcome was never observed",
                id(permit)
            ),
            Self::EndMismatch { end, reached } => {
                write!(f, "end {end:?} where the run reached {reached:?}")
            }
            Self::Overflow => f.write_str("a quantity does not fit in u64"),
            Self::AcquisitionEnded(acquisition) => {
                write!(f, "acquisition {} has already ended", id(acquisition))
            }
            Self::EndOutstanding {
                acquisition,
                obligation,
            } => write!(
                f,
                "acquisition {} ended while obligation {} still holds work",
                id(acquisition),
                id(obligation)
            ),
            Self::EndOwner {
                acquisition,
                bound,
                named,
            } => write!(
                f,
                "acquisition {} bound by owner {} ended for owner {}",
                id(acquisition),
                id(bound),
                id(named)
            ),
            Self::Unended(acquisition) => {
                write!(f, "acquisition {} never ended", id(acquisition))
            }
            Self::MissingBinding { owner, acquisition } => write!(
                f,
                "owner {} holds active acquisition {}, which its custody did not report",
                id(owner),
                id(acquisition)
            ),
            Self::StaleBinding { owner, acquisition } => write!(
                f,
                "owner {}'s custody reports acquisition {} bound, which has ended",
                id(owner),
                id(acquisition)
            ),
            Self::RecordTransition { permit, from, to } => write!(
                f,
                "permit {} at record stage {from:?} cannot enter {to:?}",
                id(permit)
            ),
            Self::RecordOwner {
                permit,
                owner,
                named,
            } => write!(
                f,
                "record {} of owner {} named under owner {}",
                id(permit),
                id(owner),
                id(named)
            ),
            Self::PrematureRecordRelease { permit, stage } => write!(
                f,
                "record {} released at stage {stage:?}, before its cleanup completed",
                id(permit)
            ),
            Self::HolderMismatch {
                permit,
                expected,
                reported,
            } => write!(
                f,
                "permit {} held at record stage {expected:?} reported at {reported:?}",
                id(permit)
            ),
        }
    }
}

/// The machine's refusal: where, and the rule broken.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Divergence {
    pub at: At,
    pub rule: Rule,
}

impl core::fmt::Display for Divergence {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.at {
            At::Observation(index) => write!(f, "observation {index}: {}", self.rule),
            At::Checkpoint(index) => write!(f, "checkpoint {index}: {}", self.rule),
            At::Cleaning => write!(f, "cleaning: {}", self.rule),
            At::Published => write!(f, "publication: {}", self.rule),
            At::End => write!(f, "end: {}", self.rule),
        }
    }
}
