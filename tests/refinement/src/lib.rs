//! The refinement machine: an executable model of the admission, credit and
//! permit protocol every recorded run must refine, and the admission-trace
//! record's one row format, which the trace recorder
//! (`tests/resumable/native_traces.rs`) writes and the gate (`tests/gate`)
//! reads back and validates.
//!
//! A recorded run ([`Run`]) is a recording session's whole stream
//! (`dcbor::bounded::Session::finish`, every [`Observed`] in the session's
//! one order, each with the family that published it and the policy that
//! performed it), and the driver's observations placed in that stream at
//! session boundaries (`dcbor::bounded::Session::boundary`): the custody its
//! owners held ([`Checkpoint`], each owner's held obligations and permits by
//! identity), when cleanup began and why, what it published ([`Publication`],
//! the output's permits by identity), and how it ended ([`End`]). A boundary
//! `b` means the observations `[0, b)` happened before the driver's
//! observation; a policy's call count is no boundary.
//!
//! The machine ([`check`]) keeps one state, keyed by the identities the
//! session minted ([`model`]): each owner; each acquisition and the owner
//! that bound it; each held obligation, its kind, acquisition and remaining
//! work, whose family is its identity's; each permit, its bytes, the
//! acquisition its release was spent for, its physical outcome and its
//! life; and each family's admitted, consumed and forfeited work. Every
//! observation advances that state once, through the production transition
//! it records:
//!
//! - admission (`bounded.rs` `admit_at`, `admit_held_at`): an admitted work
//!   call is followed by its performer's admission of exactly that work
//!   before that performer's next call; a held part names a fresh
//!   obligation identity of the admitting family and an acquisition bound
//!   to a known owner;
//! - settlement (`Retained::consume`, `spend`, `forfeit`, published by the
//!   obligation's origin family whoever performs it): the named obligation,
//!   with its own kind and acquisition, by at most what it holds; a release
//!   or grant settled whole, a window consumed in parts; a forfeit under a
//!   rule naming its kind; a release spent once, at the permit granted for
//!   its acquisition, which binds that permit to the acquisition; a grant
//!   spent only at its acquisition's permit whose reservation was observed
//!   made, forfeited `AcquisitionFailed` only at one observed failed;
//! - permits (`policy.rs` `Reservation`, `Allocator for Limits`): a grant
//!   makes a fresh permit of its family; a physical outcome
//!   (`Event::Effect`) names a permit bound to that acquisition, once; a
//!   split takes at most what its live parent holds into a fresh child of
//!   the same family; a merge passes every byte of a live input to a live
//!   permit of the same family and retires the input; a release is a live
//!   permit's drop, once. No credit event moves a permit's physical state
//!   and no permit event moves credit.
//!
//! At each checkpoint the observed custody, grouped by the owner each
//! production component stores, equals the machine's owner by owner: the
//! same obligations by identity, acquisition, kind and remaining work, and
//! the same live permits, a published one still its acquiring owner's until
//! released; every identity reported once, and no owner holding custody left
//! unreported; no admission, permit acquisition or failed permit is between
//! its steps. Cleanup's cause is what the run
//! reached (the outstanding refusal, or an observed failed reservation);
//! publication names live permits and follows no outstanding refusal; the
//! end is the phase the run reached, every permit released, every
//! obligation settled and every admission made.
//!
//! The same transitions and rules, through the same replay, serve a whole
//! recording session and the custody checkpoints its runner took
//! ([`settled`]); a recorded trace run adds only its own marks, cleanup and
//! publication, and its end ([`check`]). A mark adds checks; its absence
//! relaxes none. A fixture inside a recorded session follows the production
//! protocol: it admits through the route and allocates through an
//! acquisition, or its stream is refused.
//!
//! The machine is a refusal check: a row it refuses is never recorded and a
//! record holding one is a fault, but acceptance upgrades no evidence. A row
//! stays [`Evidence::Observed`] until every correspondence obligation of the
//! refinement register and each rule's planted divergence are verified.
//!
//! The vocabulary is the library's, imported, never redeclared. This crate
//! defines only the driver's observations, their text and the machine.

pub use dcbor::bounded::{
    Answer, Call, Class, Credit, Effect, Event, Forfeit, Hold, Identity, LimitRefusal, Obligation,
    Observed, Performer, RecordStage, Settled, WriteWork,
};
pub use dcbor_record::Evidence;

mod history;
mod machine;
pub mod model;
mod row;
mod text;

pub use history::History;
pub use machine::{calls, check, evidence, settled};
pub use model::{At, Divergence, Rule};
pub use row::{Row, parse_record, parse_row};
pub use text::{parse_observed, render_observed, render_run};

/// The feature column of a row gated on no feature: the name of
/// [`dcbor_record::capabilities::Requirement::Always`], the one spelling every
/// record's requirement column shares.
pub const UNGATED: &str = dcbor_record::capabilities::Requirement::Always.name();

/// What a recorded case was written to reach: its operation publishes, or
/// rejects its input as invalid. A refusal, a physical failure, a defect or
/// a cancellation is never what a case is for, and none of them can be
/// declared.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Published,
    Invalid,
}

impl Outcome {
    pub const ALL: [Self; 2] = [Self::Published, Self::Invalid];

    /// The recorded column of this outcome.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Published => "published",
            Self::Invalid => "invalid",
        }
    }

    /// The outcome whose recorded column is `text`.
    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|outcome| outcome.name() == text)
    }

    /// The end a run reaching this outcome records.
    pub const fn end(self) -> End {
        match self {
            Self::Published => End::Published,
            Self::Invalid => End::Failed(Class::Invalid),
        }
    }
}

/// How a recorded run ended: published, cancelled by its driver, or failed
/// with the class of its terminal error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum End {
    Published,
    Cancelled,
    Failed(Class<LimitRefusal>),
}

/// Why an operation's driver began cleanup: it cancelled the operation, or
/// a step returned a terminal error of this class (a synchronous call's
/// error included, recorded where the call returned).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cause {
    Cancel,
    Error(Class<LimitRefusal>),
}

impl Cause {
    /// The end a run whose cleanup began for this cause reaches.
    pub const fn end(self) -> End {
        match self {
            Self::Cancel => End::Cancelled,
            Self::Error(class) => End::Failed(class),
        }
    }
}

/// One owner's custody at a checkpoint, as the one grouped observation
/// reported it (`dcbor::bounded::CustodySink`): the owner's identity (its
/// `Event::Owner`), each acquisition it holds bound and not yet ended
/// (`CustodySink::bound`, credit or none: the binding a progress position
/// does not carry), each obligation its owning components hold (identity,
/// acquisition, kind and the work it still holds), and each permit they
/// physically own, with a record block's stage under its actual holder
/// ([`Reported`]). Each owning component reports its own group under the
/// owner its stored capability names; groups naming one owner are combined
/// into one entry, so the association is the observation's, never inferred.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Custody {
    pub owner: Identity,
    pub bound: Vec<Identity>,
    pub held: Vec<Hold>,
    pub permits: Vec<Reported>,
}

/// One permit a checkpoint reports: its identity, and, for a record block's,
/// the stage under which its holder holds it (`CustodySink::permit`); none
/// for every permit that is no record block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reported {
    pub permit: Identity,
    pub record: Option<RecordStage>,
}

/// The custody of every owner the run declares, observed at a driver
/// boundary where none of them can change, then placed at the session
/// boundary taken right after the observation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Checkpoint {
    pub boundary: usize,
    pub custody: Vec<Custody>,
}

/// The run's published output: the session boundary right after the step
/// that published it, and the permits the output holds, by identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Publication {
    pub boundary: usize,
    pub permits: Vec<Identity>,
}

/// One recorded run: the session's whole stream, the driver's checkpoints
/// in order, the boundary at which its driver began cleanup and why, its
/// publication, and its end.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Run {
    pub observed: Vec<Observed>,
    pub checkpoints: Vec<Checkpoint>,
    pub cleaning: Option<(usize, Cause)>,
    pub published: Option<Publication>,
    pub end: End,
}

#[cfg(test)]
mod tests;
