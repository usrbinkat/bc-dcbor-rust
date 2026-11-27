//! The bounded policy: finite work, requested and live storage, a deterministic
//! deadline, a fault schedule, and allocation-free observation. Policy
//! construction allocates one shared counter; a recorded family's history is
//! its session's, preallocated before the run ([`Limits::recorded`],
//! [`record`]), and nothing is logged otherwise. Counters measure requested
//! capacities, not process RSS.
extern crate alloc;
use super::boundary::{Boundary, Predicate, Reached};
use super::{
    Acquisition, Allocator, Budget, Credit, Effect, Forfeit, Hold, Identity, Origin, Owner,
    Performer, Settled, WriteWork,
};
/// Kani harnesses of credit conservation (register item 4): compiled only by
/// `cargo kani`.
#[cfg(kani)]
mod proofs;
pub mod record;
use crate::bounded::decode::construction::TypedPosition;
use crate::bounded::decode::construction::reclamation::AbortOnUnwind;
use crate::sync::{AtomicU64, Ordering};
use alloc::{sync::Arc, vec::Vec};
use record::{Recording, Session};

/// The quantum of one bounded turn: three values and 64 bytes.
pub const TURN: WriteWork = WriteWork::new(3, 64);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Why an admission was refused: the one refusal of the accounting core
/// ([`Authority`]), each variant naming the allowance it exhausted, and
/// [`Self::recovery`] the one classification of what a caller does next.
pub enum LimitRefusal {
    /// The current turn's quantum is spent; its lifetime allowance is not.
    Turn,
    /// One unit asks for more work than a whole turn's quantum: no turn can
    /// admit it.
    QuantumTooSmall,
    /// The lifetime work allowance, in values or bytes.
    Work,
    /// The lifetime allowance of requested allocation bytes.
    Requested,
    /// Live capacity: the request fits the ceiling, but not beside what is
    /// held now.
    Storage,
    /// One request larger than the whole live ceiling: no release makes room.
    TooLarge,
    /// Another operation of the same group was admitting at the same
    /// instant (`governance::Governor`): nothing was checked or admitted,
    /// and the next turn's attempt is decided against the group's totals.
    Contended,
    /// The deadline passed: an operation's monotonic deadline
    /// (`governance::OperationBudget::deadline`), or the instrument's
    /// simulated expiry at a call of its admission clock
    /// ([`Limits::expire_at_call`]).
    Deadline,
    /// The operation, or its whole group, was cancelled
    /// (`governance::Cancellation`): sticky, so no later foreground
    /// admission succeeds; its cleanup proceeds.
    Cancelled,
    /// The fault schedule refused the call with this index.
    Scheduled(usize),
    /// A recorded family's session has no permit record left for the grant
    /// ([`record`]): the run is no evidence, and nothing was granted.
    Unrecorded,
}

/// What a caller does after a refusal ([`LimitRefusal::recovery`]): the one
/// classification, so no caller infers it from counters. It is the caller's
/// question, not the engine's: whatever the refusal, the refused operation
/// keeps its progress and may be stepped again ([`crate::bounded::Class::Refused`]);
/// the recovery says whether a later step can be admitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Recovery {
    /// Resume the same operation in a later turn.
    NextTurn,
    /// Resume once held storage is released elsewhere; nothing promises it.
    CapacityRelease,
    /// No later step admits it: cancel and reclaim.
    Stop,
}

impl LimitRefusal {
    /// The recovery this refusal admits: a spent turn, a contended group
    /// admission, and an injected refusal (which stands for one), resume in a
    /// later turn; live capacity held elsewhere resumes after a release;
    /// every exhausted lifetime allowance, an impossible unit or request, the
    /// deadline, a cancellation and an unrecorded session stop.
    pub const fn recovery(self) -> Recovery {
        match self {
            Self::Turn | Self::Contended | Self::Scheduled(_) => Recovery::NextTurn,
            Self::Storage => Recovery::CapacityRelease,
            Self::QuantumTooSmall
            | Self::Work
            | Self::Requested
            | Self::TooLarge
            | Self::Deadline
            | Self::Cancelled
            | Self::Unrecorded => Recovery::Stop,
        }
    }
}

impl core::error::Error for LimitRefusal {}

impl core::fmt::Display for LimitRefusal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Turn => f.write_str("turn quantum spent"),
            Self::QuantumTooSmall => f.write_str("unit exceeds the turn quantum"),
            Self::Work => f.write_str("work limit"),
            Self::Requested => f.write_str("requested-bytes limit"),
            Self::Storage => f.write_str("storage limit"),
            Self::TooLarge => f.write_str("request exceeds the storage ceiling"),
            Self::Contended => f.write_str("group admission contended"),
            Self::Deadline => f.write_str("deadline"),
            Self::Cancelled => f.write_str("cancelled"),
            Self::Scheduled(index) => write!(f, "scheduled refusal of call {index}"),
            Self::Unrecorded => f.write_str("recording session exhausted"),
        }
    }
}

/// The ceilings of one authority, fixed when it is made: work in values and
/// bytes, cumulative requested allocation bytes, and live requested
/// capacity. A ceiling of `u64::MAX` is unlimited.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ceilings {
    pub work: WriteWork,
    pub requested: u64,
    pub live: u64,
}

impl Ceilings {
    /// Every ceiling `u64::MAX`.
    pub const UNLIMITED: Self = Self {
        work: WriteWork::new(u64::MAX, u64::MAX),
        requested: u64::MAX,
        live: u64::MAX,
    };
}

/// An admission an [`Authority`] checked and has not committed: the totals
/// and the turn it reaches ([`Authority::commit`]). Its fields are the
/// core's alone, so no caller can commit totals the core did not compute.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Planned {
    used: WriteWork,
    cleanup: WriteWork,
    turn: Option<Turn>,
}

/// One turn: what the scheduler granted it, at most the quantum, and what it
/// admitted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Turn {
    allowance: WriteWork,
    used: WriteWork,
}

/// The accounting core: the one owner of an authority's ceilings, its
/// committed lifetime totals, its turn, and the order in which an admission
/// is checked. Every policy admits through [`Self::work`],
/// [`Self::reclaim`] and [`Self::request`]; the live counter is the
/// family's ([`Counters`]), reserved by [`Self::request`]'s caller in one
/// atomic update after every other check has passed.
///
/// Its axioms, each held by this type's shape:
///
/// - Lifetime authorization never increases: the ceilings are set when the
///   authority is made and nothing raises them; a turn's allowance bounds
///   work within the lifetime allowance, never beside it.
/// - A turn grants at most the quantum, the largest unit any turn admits: a
///   unit beyond the quantum is impossible in every turn
///   ([`LimitRefusal::QuantumTooSmall`]), and one beyond what this turn
///   still allows waits for the next ([`LimitRefusal::Turn`]).
/// - A refused admission changes no committed quantity: each check computes
///   the totals the admission would reach, and they are stored only once
///   every check has passed.
/// - Refusal precedence is fixed: lifetime exhaustion, then an impossible
///   unit, then the turn's allowance.
/// - Cleanup is never refused for the foreground's allowance
///   ([`Self::reclaim`]): it returns what an operation holds, so it is
///   accounted apart from foreground work and no lifetime ceiling gates
///   it; the quantum and the turn bound it as they bound every unit.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Authority {
    ceilings: Ceilings,
    quantum: WriteWork,
    /// Every admitted unit's work, foreground and cleanup.
    used: WriteWork,
    /// The part of [`Self::used`] admitted as cleanup: never more than it,
    /// both raised together by every cleanup admission.
    cleanup: WriteWork,
    requested: u64,
    turn: Option<Turn>,
}

impl Authority {
    /// An authority of `ceilings` whose turns grant at most `quantum`, and
    /// no turn running.
    pub(crate) const fn new(ceilings: Ceilings, quantum: WriteWork) -> Self {
        Self {
            ceilings,
            quantum,
            used: WriteWork::new(0, 0),
            cleanup: WriteWork::new(0, 0),
            requested: 0,
            turn: None,
        }
    }

    /// The foreground work admitted: every unit's, less cleanup's. Every
    /// cleanup admission raises both totals together ([`Self::reclaim`]),
    /// so the difference never saturates; the policy ships, so it never
    /// panics.
    fn foreground(&self) -> WriteWork {
        WriteWork::new(
            self.used.values.saturating_sub(self.cleanup.values),
            self.used.bytes.saturating_sub(self.cleanup.bytes),
        )
    }

    /// Admit `work` as foreground, or refuse it with nothing committed
    /// ([`Self::plan_work`], then [`Self::commit`]).
    fn work(&mut self, work: WriteWork) -> Result<(), LimitRefusal> {
        let planned = self.plan_work(work)?;
        self.commit(planned);
        Ok(())
    }

    /// Admit `work` as cleanup, or refuse it with nothing committed
    /// ([`Self::plan_reclaim`], then [`Self::commit`]).
    fn reclaim(&mut self, work: WriteWork) -> Result<(), LimitRefusal> {
        let planned = self.plan_reclaim(work)?;
        self.commit(planned);
        Ok(())
    }

    /// The totals and turn a foreground admission of `work` reaches,
    /// committing nothing: the lifetime ceiling over the foreground's total,
    /// then the turn ([`Self::turn_after`]).
    pub(crate) fn plan_work(&self, work: WriteWork) -> Result<Planned, LimitRefusal> {
        let used = self.used.checked_then(work).ok_or(LimitRefusal::Work)?;
        self.foreground()
            .checked_then(work)
            .filter(|foreground| self.ceilings.work.covers(foreground))
            .ok_or(LimitRefusal::Work)?;
        let turn = self.turn_after(work)?;
        Ok(Planned {
            used,
            cleanup: self.cleanup,
            turn,
        })
    }

    /// The totals and turn a cleanup admission of `work` reaches,
    /// committing nothing: no lifetime ceiling, only the turn
    /// ([`Self::turn_after`]). The totals' one refusal of their own is a sum
    /// beyond `u64`, which no bounded operation reaches.
    pub(crate) fn plan_reclaim(&self, work: WriteWork) -> Result<Planned, LimitRefusal> {
        let used = self.used.checked_then(work).ok_or(LimitRefusal::Work)?;
        let cleanup = self.cleanup.checked_then(work).ok_or(LimitRefusal::Work)?;
        let turn = self.turn_after(work)?;
        Ok(Planned {
            used,
            cleanup,
            turn,
        })
    }

    /// Commit `planned`, made by this authority's [`Self::plan_work`] or
    /// [`Self::plan_reclaim`] against its totals as they still are: its
    /// caller commits a plan in the same call that made it, before any other
    /// admission, so no plan is ever committed over another.
    pub(crate) fn commit(&mut self, planned: Planned) {
        self.used = planned.used;
        self.cleanup = planned.cleanup;
        self.turn = planned.turn;
    }

    /// The running turn once `work` is admitted, committing nothing: a unit
    /// beyond the quantum refused as impossible, one beyond what the turn
    /// still allows refused for the next turn; `None` with no turn running.
    fn turn_after(&self, work: WriteWork) -> Result<Option<Turn>, LimitRefusal> {
        let Some(turn) = self.turn else {
            return Ok(None);
        };
        if !self.quantum.covers(&work) {
            return Err(LimitRefusal::QuantumTooSmall);
        }
        let spent = turn
            .used
            .checked_then(work)
            .filter(|spent| turn.allowance.covers(spent))
            .ok_or(LimitRefusal::Turn)?;
        Ok(Some(Turn {
            used: spent,
            ..turn
        }))
    }

    /// Check a request of `bytes` against the requested and live ceilings,
    /// committing nothing: the cumulative requested total it reaches, for
    /// [`Self::granted`] once the live capacity is reserved.
    pub(crate) fn request(&self, bytes: u64) -> Result<u64, LimitRefusal> {
        if bytes > self.ceilings.live {
            return Err(LimitRefusal::TooLarge);
        }
        self.requested
            .checked_add(bytes)
            .filter(|total| *total <= self.ceilings.requested)
            .ok_or(LimitRefusal::Requested)
    }

    /// Commit a granted request's cumulative total ([`Self::request`]).
    pub(crate) fn granted(&mut self, requested: u64) {
        self.requested = requested;
    }

    /// The ceilings fixed when the authority was made.
    pub(crate) const fn ceilings(&self) -> Ceilings {
        self.ceilings
    }

    /// Every admitted unit's work, foreground and cleanup.
    pub(crate) const fn used(&self) -> WriteWork {
        self.used
    }

    /// The part of [`Self::used`] admitted as cleanup.
    pub(crate) const fn cleanup(&self) -> WriteWork {
        self.cleanup
    }

    /// The cumulative bytes of granted requests.
    pub(crate) const fn requested(&self) -> u64 {
        self.requested
    }

    /// Start a turn granting `allowance`, at most the quantum in each
    /// quantity: only the turn's own usage is reset.
    pub(crate) fn begin_turn(&mut self, allowance: WriteWork) {
        self.turn = Some(Turn {
            allowance: WriteWork::new(
                allowance.values.min(self.quantum.values),
                allowance.bytes.min(self.quantum.bytes),
            ),
            used: WriteWork::new(0, 0),
        });
    }

    /// Spend the current turn: a turn granting nothing, so nothing more is
    /// admitted until the next one.
    pub(crate) fn end_turn(&mut self) {
        self.begin_turn(WriteWork::new(0, 0));
    }

    /// No turn quantum: work is bounded by the lifetime allowance alone.
    pub(crate) fn without_turns(&mut self) {
        self.turn = None;
    }

    /// Forget the committed totals, the ceilings kept: the measurement
    /// instrument's restart ([`Limits::measure`]), so a run measures only
    /// what follows it. No production authority calls it.
    fn restart(&mut self) {
        self.used = WriteWork::new(0, 0);
        self.cleanup = WriteWork::new(0, 0);
        self.requested = 0;
    }

    /// The foreground work still admissible now: the lifetime allowance's
    /// remainder, within the turn's when one is running.
    pub(crate) fn remaining(&self) -> WriteWork {
        let foreground = self.foreground();
        let lifetime = WriteWork::new(
            self.ceilings.work.values.saturating_sub(foreground.values),
            self.ceilings.work.bytes.saturating_sub(foreground.bytes),
        );
        match self.turn {
            None => lifetime,
            Some(turn) => WriteWork::new(
                lifetime
                    .values
                    .min(turn.allowance.values.saturating_sub(turn.used.values)),
                lifetime
                    .bytes
                    .min(turn.allowance.bytes.saturating_sub(turn.used.bytes)),
            ),
        }
    }
}

/// Why a policy's history cannot be read ([`Limits::history`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unreadable {
    /// The family is ordinary: it records nothing.
    Unrecorded,
    /// The family's session is no evidence.
    Session(record::Incomplete),
}

/// A policy's recorded history counted: its calls, those admitted, those
/// refused and, of those, the injected. The one derivation of the counts a
/// history's correspondence with its policy's counters compares
/// (`dcbor_test_support::history_agrees`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HistoryCounts {
    pub calls: usize,
    pub admitted: usize,
    pub refusals: usize,
    pub injected: usize,
}

impl HistoryCounts {
    /// The counts of `history` ([`Limits::history`]).
    pub fn of(history: &[(Call, Answer)]) -> Self {
        let mut counts = Self {
            calls: history.len(),
            admitted: 0,
            refusals: 0,
            injected: 0,
        };
        for (_, answer) in history {
            match answer {
                Answer::Refused { injected, .. } => {
                    counts.refusals += 1;
                    counts.injected += usize::from(*injected);
                }
                Answer::Admitted | Answer::Granted(_) => counts.admitted += 1,
            }
        }
        counts
    }
}

/// One admission request, named by the account it is charged to: a
/// foreground unit's work ([`Budget::traverse`]), a cleanup unit's work
/// ([`super::Releasing::reclaim`]), or a storage request
/// ([`Allocator::allocate`]). The history records each as asked, so a
/// reader tells a cleanup admission from a foreground one by the call alone.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Call {
    Work { values: u64, bytes: u64 },
    Reclaim { values: u64, bytes: u64 },
    Allocate(u64),
}

impl Call {
    /// Whether this call is charged to the foreground account: a work unit
    /// or a storage request, every call but cleanup.
    pub const fn is_foreground(self) -> bool {
        !matches!(self, Self::Reclaim { .. })
    }

    /// The work this call asks for: a work or cleanup unit's; `None` for a
    /// storage request.
    pub const fn work(self) -> Option<WriteWork> {
        match self {
            Self::Work { values, bytes } | Self::Reclaim { values, bytes } => {
                Some(WriteWork::new(values, bytes))
            }
            Self::Allocate(_) => None,
        }
    }
}

/// What a policy answered a call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Answer {
    /// A work call admitted.
    Admitted,
    /// An allocation granted: the permit of this identity.
    Granted(Identity),
    /// Refused, with the reason, and whether the policy's fault schedule
    /// injected the refusal.
    Refused {
        refusal: LimitRefusal,
        injected: bool,
    },
}

/// One observation of a recorded family ([`record::Session`]), in the
/// session's one order: the transitions production makes, each published
/// where it is made. The stream the refinement machine (`tests/refinement`)
/// checks a recorded run against.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event {
    /// An attempted call and the policy's answer.
    Call(Call, Answer),
    /// An admission through the route ([`Budget::admitted`],
    /// [`Budget::held`]), or a held obligation's settlement into its origin
    /// ([`super::Origin::settle`]), whoever performs it.
    Credit(Credit),
    /// A physical reservation's outcome ([`Budget::effect`]).
    Effect(Effect),
    /// A permit divided: the child's identity and the bytes it took.
    Split {
        parent: Identity,
        child: Identity,
        bytes: u64,
    },
    /// A permit's bytes passed to another: the survivor, the retired input
    /// and the bytes passed.
    Merge {
        survivor: Identity,
        retired: Identity,
        bytes: u64,
    },
    /// A permit's drop performed its release.
    Released(Identity),
    /// A custody that owns acquisitions was made ([`Budget::owner`]).
    Owner(Identity),
    /// `owner` bound an acquisition ([`Budget::acquisition`]): every
    /// obligation held for it and the permit granted to it name it.
    Bound {
        acquisition: Identity,
        owner: Identity,
    },
    /// `owner`'s acquisition ended ([`super::Acquisition::end`]), published
    /// by the family that minted it: its holder settled everything it held
    /// and keeps no capability of it.
    End {
        acquisition: Identity,
        owner: Identity,
    },
    /// A record block's permit entered `stage` of its record's lifecycle
    /// ([`RecordStage`]) under `owner`, the owner whose acquisition granted
    /// it, published through the permit's own family
    /// ([`super::Releasing::custody`]).
    Custody {
        permit: Identity,
        owner: Identity,
        stage: RecordStage,
    },
}

/// Where a record block is in its record's lifecycle, the permit's holder
/// at each stage: granted to an acquisition token, not yet a record
/// (`Granted`); a record held by its handle (`Handle`); retired into its
/// scope's queue (`Queued`); taken from the queue by the one cleanup that
/// reclaims it (`Active`); its cleanup complete, the block's free next
/// (`Reclaimed`). A permit that is no record block has no stage.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum RecordStage {
    Granted,
    Handle,
    Queued,
    Active,
    Reclaimed,
}

impl core::fmt::Debug for Counters {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Counters")
            .field("live", &self.live)
            .field("peak", &self.peak)
            .field("recorded", &self.recording.is_some())
            .finish_non_exhaustive()
    }
}

#[derive(Default)]
struct Counters {
    live: AtomicU64,
    peak: AtomicU64,
    release_observer: Option<fn(u64)>,
    /// The family's part of its recording session, fixed when the family is
    /// made ([`Limits::recorded`]): `None` for an ordinary family, whose
    /// permits hold their bytes and whose observations are not recorded.
    recording: Option<Recording>,
    /// The boundary valuations reached by every policy over this storage,
    /// shared and terminal ones included, one bit per valuation by predicate
    /// ([`Reached`]): set by one relaxed `fetch_or`, which allocates nothing
    /// and cannot unwind, so cleanup and terminal steps record too. Read once
    /// the run is over ([`Limits::reached`]).
    reached: [AtomicU64; Predicate::COUNT],
    /// The credit ledgers of every policy over this storage, shared and
    /// terminal ones included ([`Ledgers`]), read once the run is quiescent
    /// ([`Limits::credits`]).
    credits: Ledgers,
}

/// A counter family's credit ledgers: A, C and F in values and bytes, and
/// the violation flag, each a family atomic, so a terminal policy minted from
/// a permit's counters records into the ledger its originating policy reads.
/// Every quantity is updated by its own checked compare-exchange, the values
/// and bytes of each of A, C and F one at a time, not together: one that does
/// not fit is left unchanged, while the other quantities of the same event
/// may have advanced, and the sticky violation flag is set, so the ledger is
/// no longer claimed conserved ([`Credits::conserved_with`] is false).
/// Allocation-free and non-unwinding, so cleanup and terminal steps record.
/// Conservation is read only at quiescence.
#[derive(Debug, Default)]
struct Ledgers {
    admitted: [AtomicU64; 2],
    consumed: [AtomicU64; 2],
    forfeited: [AtomicU64; 2],
    violated: AtomicU64,
}

impl Ledgers {
    /// Apply one credit event: the one update rule of every ledger. An
    /// admission adds its work to A and its unheld part to C; a spend adds
    /// to C; a forfeit adds to F. An admission holding more than it
    /// admitted sets the violation flag and changes nothing else. A quantity
    /// that does not fit is left unchanged and sets the flag, while the
    /// event's other quantities and ledgers may have advanced.
    fn record(&self, credit: Credit) {
        let none = WriteWork::new(0, 0);
        let (admitted, consumed, forfeited) = match credit {
            Credit::Admit { work, held } => {
                let consumed = match held {
                    None => Some(work),
                    Some(hold) => less(work, hold.work),
                };
                let Some(consumed) = consumed else {
                    self.violate();
                    return;
                };
                (work, consumed, none)
            }
            Credit::Spend(spent) => (none, spent.work, none),
            Credit::Forfeit(forfeited, _) => (none, none, forfeited.work),
        };
        let fitted = [
            Self::add(&self.admitted, admitted),
            Self::add(&self.consumed, consumed),
            Self::add(&self.forfeited, forfeited),
        ];
        if fitted.contains(&false) {
            self.violate();
        }
    }

    /// `work` added to a ledger, its values and its bytes each by its own
    /// checked compare-exchange: a quantity that does not fit is left
    /// unchanged while the other may have advanced. False when either did
    /// not fit.
    fn add(ledger: &[AtomicU64; 2], work: WriteWork) -> bool {
        let values = Self::add_one(&ledger[0], work.values);
        let bytes = Self::add_one(&ledger[1], work.bytes);
        values && bytes
    }

    fn add_one(ledger: &AtomicU64, amount: u64) -> bool {
        if amount == 0 {
            return true;
        }
        let mut current = ledger.load(Ordering::Acquire);
        loop {
            let Some(next) = current.checked_add(amount) else {
                return false;
            };
            match ledger.compare_exchange_weak(current, next, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => return true,
                Err(actual) => current = actual,
            }
        }
    }

    fn violate(&self) {
        self.violated.fetch_or(1, Ordering::AcqRel);
    }

    /// The ledgers now, as a snapshot.
    fn snapshot(&self) -> Credits {
        let read = |ledger: &[AtomicU64; 2]| {
            WriteWork::new(
                ledger[0].load(Ordering::Acquire),
                ledger[1].load(Ordering::Acquire),
            )
        };
        Credits {
            admitted: read(&self.admitted),
            consumed: read(&self.consumed),
            forfeited: read(&self.forfeited),
            violated: self.violated.load(Ordering::Acquire) != 0,
        }
    }
}

/// Storage admission released when its owning allocation is released. A
/// reservation may be released on any thread; release is one atomic
/// subtraction, allocates nothing, and panics on a release it never admitted.
///
/// Two words, whatever the family's mode ([`crate::bounded::PERMIT_BYTES`]):
/// its family's counters, and `word`, read by the family's mode, which is
/// fixed while the family can issue or hold permits. An ordinary family's
/// `word` is the full-width requested bytes. A recorded family's is the
/// index of the permit's record in its session ([`record`]), which holds
/// its bytes, its identity and its lifecycle; the family is the counters'.
pub struct Reservation {
    counters: Arc<Counters>,
    word: u64,
}

impl core::fmt::Debug for Reservation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Reservation")
            .field("bytes", &self.bytes())
            .field("identity", &self.identity())
            .finish()
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        let recording = self.counters.recording.as_ref();
        // A merged input holds nothing: its bytes passed to the survivor,
        // and its drop is no release.
        if recording.is_some_and(|recording| recording.retired(self.word)) {
            return;
        }
        let bytes = self.bytes();
        let previous = self.counters.live.fetch_sub(bytes, Ordering::AcqRel);
        assert!(previous >= bytes, "reservation released twice");
        if let Some(recording) = recording {
            recording.released(self.word);
            recording.publish(
                Performer::None,
                Event::Released(recording.identity(self.word)),
            );
        }
        if bytes != 0
            && let Some(observer) = self.counters.release_observer
        {
            // A release runs inside cleanup steps, which must not unwind
            // (`Reclaim`): a step a release unwound out of would leave its
            // state recording what it no longer holds. An observer that
            // unwinds aborts the process instead.
            let guard = AbortOnUnwind;
            observer(bytes);
            core::mem::forget(guard);
        }
    }
}

/// Why a transfer between reservations was refused. The reservations involved
/// are unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferRefusal {
    /// A split asked for more bytes than the reservation holds.
    Insufficient { requested: u64, held: u64 },
    /// The reservations count against different storage.
    Foreign,
    /// The merged size does not fit in `u64`.
    Overflow,
    /// A recorded family's session has no permit record left for the
    /// split's child ([`record`]).
    Unrecorded,
}

impl core::error::Error for TransferRefusal {}

impl core::fmt::Display for TransferRefusal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Insufficient { requested, held } => {
                write!(f, "split of {requested} bytes from a reservation of {held}")
            }
            Self::Foreign => f.write_str("reservations count against different storage"),
            Self::Overflow => f.write_str("merged reservation exceeds u64"),
            Self::Unrecorded => f.write_str("recording session exhausted"),
        }
    }
}

impl Reservation {
    /// The requested bytes this reservation holds.
    pub fn bytes(&self) -> u64 {
        match &self.counters.recording {
            None => self.word,
            Some(recording) => recording.bytes(self.word),
        }
    }

    /// This permit's identity: [`Identity::UNOBSERVED`] in an ordinary
    /// family, its record's in a recorded one.
    pub fn identity(&self) -> Identity {
        match &self.counters.recording {
            None => Identity::UNOBSERVED,
            Some(recording) => recording.identity(self.word),
        }
    }

    /// Publish this record block's entry into `stage` under `owner`
    /// ([`Event::Custody`]) through its own family's recording, performed by
    /// no policy: the permit's origin, whichever budget, or none, performs
    /// the step. An ordinary family records nothing.
    pub(crate) fn custody(&self, owner: Identity, stage: RecordStage) {
        if let Some(recording) = &self.counters.recording {
            recording.publish(
                Performer::None,
                Event::Custody {
                    permit: recording.identity(self.word),
                    owner,
                    stage,
                },
            );
        }
    }

    fn set_bytes(&mut self, bytes: u64) {
        match &self.counters.recording {
            None => self.word = bytes,
            Some(recording) => recording.set_bytes(self.word, bytes),
        }
    }

    /// Move `bytes` of this reservation into a new one over the same storage,
    /// as when one allocation's ownership is divided between two owners. Live
    /// and peak storage are unchanged; each part is released with its own
    /// owner. A zero-byte split is an owner of nothing, which releases
    /// nothing. In a recorded family the child's record is reserved before
    /// the parent changes, and the split is published with both identities
    /// and the exact bytes; a session with no record left refuses the split,
    /// nothing changed.
    pub fn split(&mut self, bytes: u64) -> Result<Reservation, TransferRefusal> {
        let held = self.bytes();
        let remaining = held
            .checked_sub(bytes)
            .ok_or(TransferRefusal::Insufficient {
                requested: bytes,
                held,
            })?;
        let word = match &self.counters.recording {
            None => bytes,
            Some(recording) => {
                let (child, id) = recording
                    .reserve(bytes)
                    .ok_or(TransferRefusal::Unrecorded)?;
                recording.commit(child);
                recording.publish(
                    Performer::None,
                    Event::Split {
                        parent: recording.identity(self.word),
                        child: id,
                        bytes,
                    },
                );
                child
            }
        };
        self.set_bytes(remaining);
        Ok(Reservation {
            counters: self.counters.clone(),
            word,
        })
    }

    /// Take over `other`'s bytes, as when two owners' storage passes to one.
    /// Live and peak storage are unchanged. A refused merge returns `other`
    /// unchanged with the reason. The emptied input releases nothing when it
    /// drops; in a recorded family its record is retired and the merge is
    /// published with both identities and the bytes passed, its drop
    /// publishing no release.
    pub fn merge(&mut self, mut other: Reservation) -> Result<(), (Reservation, TransferRefusal)> {
        if !Arc::ptr_eq(&self.counters, &other.counters) {
            return Err((other, TransferRefusal::Foreign));
        }
        let passed = other.bytes();
        let Some(bytes) = self.bytes().checked_add(passed) else {
            return Err((other, TransferRefusal::Overflow));
        };
        self.set_bytes(bytes);
        other.set_bytes(0);
        if let Some(recording) = &self.counters.recording {
            recording.retire(other.word);
            recording.publish(
                Performer::None,
                Event::Merge {
                    survivor: recording.identity(self.word),
                    retired: recording.identity(other.word),
                    bytes: passed,
                },
            );
        }
        Ok(())
    }
}

/// A snapshot of a counter family's credit ledgers ([`Limits::credits`]),
/// from the credit events reported to any of its policies ([`Credit`]):
/// what was admitted through the route (A), consumed (C) and forfeited (F),
/// each from its own events, never computed as a remainder. A family is one
/// [`Limits::new`] and every policy sharing its counters: its
/// [`Limits::share`]s and every terminal policy minted from its permits.
/// Held credit (H) is not a policy's: it is the custody of the operation
/// that admitted it, which reports it as its `held_credit` observation. An
/// operation's credit is conserved when, over the families that served it,
/// `A = C + F + H` ([`Self::conserved_with`]).
///
/// Each ledger is updated by its own atomic update, not together with the
/// others: an admission's A and C are two updates. So a snapshot taken while
/// an operation runs on another thread may hold one and not the other, and
/// conservation is read only at quiescence: after the operation's `Done`,
/// or after its terminal drain returns.
///
/// Consumed counts work performed and work irrevocably committed to a
/// granted permit, whose drop performs its release unconditionally; so the
/// ledgers do not report how much work has physically executed, and no
/// evidence claim may read them that way.
///
/// A quantity whose update does not fit in `u64` is left unchanged while the
/// event's other quantities and ledgers may have advanced, and an admission
/// reporting more held than it admitted changes no ledger; both set
/// [`Self::violated`], sticky, so the ledgers are no longer claimed
/// conserved. The policy ships, so it never panics.
///
/// Credit events are not admission calls ([`Call`]): the admission trace,
/// and every record taken from it, is unchanged by them.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Credits {
    /// Every admission made through the route.
    pub admitted: WriteWork,
    /// The part of each admission not held, and every spend.
    pub consumed: WriteWork,
    /// Every forfeit.
    pub forfeited: WriteWork,
    /// An update was refused: it did not fit, or held more than admitted.
    pub violated: bool,
}

/// `left - right` in both quantities, or none when either falls below zero.
fn less(left: WriteWork, right: WriteWork) -> Option<WriteWork> {
    Some(WriteWork::new(
        left.values.checked_sub(right.values)?,
        left.bytes.checked_sub(right.bytes)?,
    ))
}

impl Credits {
    /// These ledgers and `other`'s, each summed: the credit of the counter
    /// families that served one operation, such as fresh policies across
    /// its turns. `None` when a sum does not fit.
    pub fn checked_add(self, other: Self) -> Option<Self> {
        Some(Self {
            admitted: self.admitted.checked_then(other.admitted)?,
            consumed: self.consumed.checked_then(other.consumed)?,
            forfeited: self.forfeited.checked_then(other.forfeited)?,
            violated: self.violated || other.violated,
        })
    }

    /// What these ledgers recorded since `earlier`, a snapshot of the same
    /// family: the credit of one operation on a family that served others
    /// before it. Summed snapshots prove one operation's conservation only
    /// when they hold that operation's events alone, so a caller serving
    /// several operations takes a delta around each. `None` when a ledger
    /// is below its earlier value, which no snapshot of the same family
    /// is. The delta is violated when these ledgers are: a violation is
    /// never attributed away.
    pub fn checked_sub(self, earlier: Self) -> Option<Self> {
        Some(Self {
            admitted: less(self.admitted, earlier.admitted)?,
            consumed: less(self.consumed, earlier.consumed)?,
            forfeited: less(self.forfeited, earlier.forfeited)?,
            violated: self.violated,
        })
    }

    /// Whether these ledgers and `held`, the custody's held credit, conserve
    /// the operation's credit, `A = C + F + H` in values and in bytes, and
    /// no update was refused. `None` when `C + F + H` does not fit, never a
    /// wrapped or saturated comparison.
    pub fn conserved_with(&self, held: WriteWork) -> Option<bool> {
        let accounted = self
            .consumed
            .checked_then(self.forfeited)?
            .checked_then(held)?;
        Some(!self.violated && accounted == self.admitted)
    }
}

/// One recorded admission and the state it observed.
#[derive(Clone, Copy, Debug)]
pub struct Admission {
    pub index: usize,
    pub call: Call,
    pub result: Result<(), LimitRefusal>,
    /// Cumulative admitted work after the call.
    pub work: WriteWork,
    /// Live and peak storage after the call.
    pub storage: (u64, u64),
    /// The caller-supplied lifecycle position current at the call, its
    /// input's and value's custody elided ([`TypedPosition::outline`]).
    pub position: Option<TypedPosition<(), ()>>,
}

/// The most recent admissions in fixed storage, and the first refusal kept
/// separately so long resumptions cannot overwrite its cause. Recording never
/// allocates. A copy is plain data, kept as a run's diagnostic after its
/// policy is gone.
#[derive(Clone)]
pub struct AdmissionTrace {
    recent: [Option<Admission>; AdmissionTrace::CAPACITY],
    count: usize,
    first_refusal: Option<Admission>,
    context: Option<TypedPosition<(), ()>>,
}

impl AdmissionTrace {
    pub const fn new() -> Self {
        Self {
            recent: [None; Self::CAPACITY],
            count: 0,
            first_refusal: None,
            context: None,
        }
    }

    pub fn context<N, O>(&mut self, position: TypedPosition<N, O>) {
        self.context = Some(position.outline());
    }

    pub fn first_refusal(&self) -> Option<Admission> {
        self.first_refusal
    }

    pub fn count(&self) -> usize {
        self.count
    }

    /// The most recent admission attempt: what a stalled operation last
    /// asked for, and why it was refused.
    pub fn last(&self) -> Option<Admission> {
        let index = self.count.checked_sub(1)?;
        self.recent[index % self.recent.len()]
    }

    /// The admissions still recorded, oldest first: the last
    /// [`Self::CAPACITY`] of [`Self::count`]. Reads the fixed storage in
    /// place; allocates nothing, so an observed window may read it.
    pub fn recent(&self) -> impl Iterator<Item = Admission> + '_ {
        (self.count.saturating_sub(self.recent.len())..self.count)
            .filter_map(|index| self.recent[index % self.recent.len()])
    }

    /// How many admissions the trace keeps.
    pub const CAPACITY: usize = 32;

    fn record(&mut self, mut event: Admission) {
        event.position = self.context;
        if event.result.is_err() && self.first_refusal.is_none() {
            self.first_refusal = Some(event);
        }
        self.recent[self.count % self.recent.len()] = Some(event);
        self.count += 1;
    }

    /// Panic with the first difference and this trace unless `actual` and
    /// `expected` are the same call sequence. `run` names the run by what it
    /// is, never by its position among others: a case's name, or a schedule's
    /// operation and refused call.
    pub fn assert_calls(&self, actual: &[Call], expected: &[Call], run: &str) {
        if actual == expected {
            return;
        }
        let at = actual
            .iter()
            .zip(expected)
            .position(|(a, b)| a != b)
            .unwrap_or(actual.len().min(expected.len()));
        let start = at.saturating_sub(2);
        panic!(
            "admission replay: run={run}, first_difference={at}, actual_len={}, expected_len={}\nactual_window={:?}\nexpected_window={:?}\n{self:?}",
            actual.len(),
            expected.len(),
            &actual[start..actual.len().min(at + 4)],
            &expected[start..expected.len().min(at + 4)]
        );
    }
}

impl Default for AdmissionTrace {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for AdmissionTrace {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        writeln!(
            f,
            "first_refusal={:?}; total_events={}",
            self.first_refusal, self.count
        )?;
        for event in self.recent() {
            writeln!(
                f,
                "call={} {:?} -> {:?}; work={:?}; live_peak={:?}; position={:?}",
                event.index, event.call, event.result, event.work, event.storage, event.position
            )?;
        }
        Ok(())
    }
}

/// The measurement and fault-injection instrument over the accounting core
/// ([`Authority`]): its ceilings, totals and turns are the core's, and what
/// this type adds is the instrument's alone (the fault schedule, the
/// admission clock, measurement restarts, the trace and the recording). The
/// policy is used by one operation at a time; its reservations may move to
/// and be released on other threads.
pub struct Limits {
    authority: Authority,
    counters: Arc<Counters>,
    attempts: usize,
    requests: usize,
    refusals: usize,
    scheduled_refusals: usize,
    injected_refusals: usize,
    last_injected: bool,
    refused: Option<(usize, LimitRefusal)>,
    fail_at: Option<(usize, LimitRefusal)>,
    /// Refuse every admission once: each call is refused on its first
    /// attempt and admitted on the attempt after.
    refuse_each: bool,
    /// The last attempt was refused under `refuse_each`, so the next is
    /// its retry.
    retrying: bool,
    fail_request: Option<usize>,
    fail_requests: usize,
    clock: u64,
    /// The simulated expiry, a call of the admission clock
    /// ([`Self::expire_at_call`]).
    expiry: Option<u64>,
    observer: Option<fn(u64)>,
    strict: bool,
    terminal: bool,
    /// This policy's number in its family's recording session, which every
    /// observation it publishes carries; 0 in an ordinary family.
    policy: u64,
    /// The calls of this policy made before the last [`Self::measure`]:
    /// the reports skip them.
    measured: usize,
    trace: AdmissionTrace,
}

impl Limits {
    /// `values` and `bytes` of work in total and `storage` live requested
    /// bytes. The shared counter allocation belongs to policy setup.
    pub fn new(values: u64, bytes: u64, storage: u64) -> Self {
        Self::with_counters(
            Self::ceilings(values, bytes, storage),
            Arc::new(Counters::default()),
        )
    }

    /// The ceilings of [`Self::new`]: no requested-bytes limit.
    const fn ceilings(values: u64, bytes: u64, storage: u64) -> Ceilings {
        Ceilings {
            work: WriteWork::new(values, bytes),
            requested: u64::MAX,
            live: storage,
        }
    }

    fn with_counters(ceilings: Ceilings, counters: Arc<Counters>) -> Self {
        let policy = counters
            .recording
            .as_ref()
            .map_or(0, |recording| recording.policy());
        Self {
            authority: Authority::new(ceilings, TURN),
            counters,
            attempts: 0,
            requests: 0,
            refusals: 0,
            scheduled_refusals: 0,
            injected_refusals: 0,
            last_injected: false,
            refused: None,
            fail_at: None,
            refuse_each: false,
            retrying: false,
            fail_request: None,
            fail_requests: 0,
            clock: 0,
            expiry: None,
            observer: None,
            strict: false,
            terminal: false,
            policy,
            measured: 0,
            trace: AdmissionTrace::new(),
        }
    }

    /// A new family recorded in `session` ([`record`]), with the limits of
    /// [`Self::new`]: its permits are the session's records, and every
    /// observation of it, its shares and its terminal policies is published
    /// into the session's one order. The mode is a fact of the family's
    /// construction and fixed for its life: no family changes mode.
    pub fn recorded(values: u64, bytes: u64, storage: u64, session: &Session) -> Self {
        let counters = Counters {
            recording: Some(Recording::join(session)),
            ..Counters::default()
        };
        Self::with_counters(Self::ceilings(values, bytes, storage), Arc::new(counters))
    }

    /// A new unlimited family recorded in `session` ([`Self::recorded`],
    /// [`Self::unlimited`]).
    pub fn recorded_unlimited(session: &Session) -> Self {
        Self::recorded(u64::MAX, u64::MAX, u64::MAX, session)
    }

    /// Whether this family is recorded in `session`.
    pub fn records_in(&self, session: &Session) -> bool {
        self.counters
            .recording
            .as_ref()
            .is_some_and(|recording| recording.of(session))
    }

    /// Publish `event` as this policy's, when its family is recorded.
    fn publish(&self, event: Event) {
        if let Some(recording) = &self.counters.recording {
            recording.publish(self.performer(), event);
        }
    }

    /// The family's next identity: [`Identity::UNOBSERVED`] in an ordinary
    /// family; in a recorded one, refused [`LimitRefusal::Unrecorded`] when
    /// the session has none left (the session is then, stickily, no
    /// evidence). A recorded family never yields an unidentified identity.
    fn mint(&self) -> Result<Identity, LimitRefusal> {
        match &self.counters.recording {
            None => Ok(Identity::UNOBSERVED),
            Some(recording) => recording.mint().ok_or(LimitRefusal::Unrecorded),
        }
    }

    /// A fresh policy over the same live storage, of no work or
    /// requested-bytes limit of its own ([`Self::share_within`] of
    /// [`Ceilings::UNLIMITED`]).
    pub fn share(&self) -> Self {
        self.share_within(Ceilings::UNLIMITED)
    }

    /// A fresh policy over the same live storage, its reservations counting
    /// against this policy's capacity, peak and live bytes, under `ceilings`
    /// of its own: its work and requested bytes its own totals, and its live
    /// ceiling at most this policy's, so a share never admits storage its
    /// family's ceiling refuses.
    pub fn share_within(&self, ceilings: Ceilings) -> Self {
        let mut shared = Self::with_counters(
            Ceilings {
                live: ceilings.live.min(self.authority.ceilings.live),
                ..ceilings
            },
            self.counters.clone(),
        );
        shared.observer = self.observer;
        shared.strict = self.strict;
        shared
    }

    /// No work, storage or requested-bytes limit.
    pub fn unlimited() -> Self {
        Self::new(u64::MAX, u64::MAX, u64::MAX)
    }

    /// Unlimited storage and one fresh turn of work.
    pub fn turns() -> Self {
        let mut limits = Self::unlimited();
        limits.fresh();
        limits
    }

    /// Panic when a call follows a refusal that was not cleared with
    /// [`Self::clear_refusal`]: the operation under test must stop at a
    /// refusal and resume only in a later turn.
    pub fn strict(mut self) -> Self {
        self.strict = true;
        self
    }

    /// Refuse the attempted call with index `at`, once.
    pub fn refusing(mut self, at: Option<usize>) -> Self {
        self.fail_call(at.map(|at| (at, LimitRefusal::Scheduled(at))));
        self
    }

    /// Refuse the attempted call with the given index, for the given reason.
    pub fn fail_call(&mut self, at: Option<(usize, LimitRefusal)>) {
        self.fail_at = at;
    }

    /// Refuse every admission once, as a scheduled refusal of its attempt:
    /// each call is refused when first attempted and admitted when next
    /// attempted. One run then suspends at every admission an operation
    /// makes, each from the state the unrefused run reaches there, so the
    /// refusal contract of every step is checked in one pass.
    pub fn refusing_each(mut self) -> Self {
        self.fail_each();
        self
    }

    /// Refuse every admission from the next attempt on, once each
    /// ([`Self::refusing_each`]).
    pub fn fail_each(&mut self) {
        self.refuse_each = true;
        self.retrying = false;
    }

    /// Whether every admission is refused once ([`Self::refusing_each`]):
    /// each takes two attempts, so a turn bound counts twice as many turns.
    pub fn refuses_each(&self) -> bool {
        self.refuse_each
    }

    /// The steps an operation of `steps` steps
    /// ([`crate::bounded::ResourceBound::steps`]) may take under this
    /// policy's refusals: twice as many, and one more, when every admission is
    /// refused once ([`Self::refuses_each`]), since each refused admission
    /// costs a step of its own. The one refusal allowance of every bounded
    /// driver, in this crate's tests and its integration harness alike.
    /// Refused, never saturated, when the result does not fit in `u64`.
    pub fn allowed<R>(&self, steps: u64) -> Result<u64, crate::bounded::BoundedError<R>> {
        if self.refuse_each {
            crate::bounded::add(crate::bounded::mul(steps, 2)?, 1)
        } else {
            Ok(steps)
        }
    }

    /// Refuse the next call, of either kind, once.
    pub fn refuse_next(&mut self) {
        let at = self.attempts;
        self.fail_call(Some((at, LimitRefusal::Scheduled(at))));
    }

    /// Forget the current refusal so that calls may continue.
    pub fn clear_refusal(&mut self) {
        self.refused = None;
    }

    /// Refuse the allocation request with index `at`, once.
    pub fn refusing_request(mut self, at: Option<usize>) -> Self {
        self.fail_request(at);
        self
    }

    /// Refuse the allocation request with index `at` among requests counted
    /// since construction or the last [`Self::measure`], once.
    pub fn fail_request(&mut self, at: Option<usize>) {
        self.fail_request = at;
    }

    /// Refuse the next `count` allocation requests.
    pub fn refusing_requests(mut self, count: usize) -> Self {
        self.fail_requests(count);
        self
    }

    /// Refuse the next `count` allocation requests.
    pub fn fail_requests(&mut self, count: usize) {
        self.fail_requests = count;
    }

    /// Refuse cumulative requested allocation bytes beyond `bytes`: the
    /// ceiling lowered to `bytes`, never raised.
    pub fn requesting_at_most(mut self, bytes: u64) -> Self {
        let ceiling = &mut self.authority.ceilings.requested;
        *ceiling = (*ceiling).min(bytes);
        self
    }

    /// The instrument's simulated expiry: refuse every foreground call
    /// [`LimitRefusal::Deadline`] once the deterministic admission clock
    /// ([`Self::clock`], one tick per attempted call, cleanup's included)
    /// reaches `call`; cleanup ([`super::Releasing::reclaim`]) is never
    /// refused for it. A clock of calls, not of time: it places an expiry at
    /// an exact call so a test can stop there. A production deadline is a
    /// monotonic instant (`governance::OperationBudget::deadline`).
    pub fn expire_at_call(&mut self, call: Option<u64>) {
        self.expiry = call;
    }

    /// Called with the bytes of each granted allocation, before the caller
    /// performs the physical allocation.
    pub fn observe(mut self, observer: fn(u64)) -> Self {
        self.observer = Some(observer);
        self
    }

    /// Observe nonzero reservation releases on the thread performing the
    /// release, including releases through shared policies and split permits.
    /// Configure before sharing the policy or issuing any reservation.
    ///
    /// The callback runs inside cleanup steps, allocation-free terminal
    /// cleanup and unwinding included, so it is held to their contract: it
    /// performs bounded, nonblocking work and does not allocate. A callback
    /// that panics aborts the process: a release never unwinds out of a
    /// cleanup step.
    pub fn observe_releases(mut self, observer: fn(u64)) -> Self {
        Arc::get_mut(&mut self.counters)
            .expect("release observation must be configured before sharing")
            .release_observer = Some(observer);
        self
    }

    /// Whether this storage pool reports reservation releases.
    pub fn observes_releases(&self) -> bool {
        self.counters.release_observer.is_some()
    }

    /// Start a new turn of one whole quantum ([`TURN`]): the turn's usage
    /// reset, the lifetime allowance and its totals unchanged.
    pub fn fresh(&mut self) {
        self.authority.begin_turn(TURN);
    }

    /// A new scheduler turn: forget the current refusal and start a turn of
    /// one whole quantum.
    pub fn turn(&mut self) {
        self.turn_with(TURN);
    }

    /// A new scheduler turn granting `allowance`, at most the quantum in each
    /// quantity: forget the current refusal and start the turn. A unit within
    /// the quantum but beyond the allowance is refused [`LimitRefusal::Turn`]
    /// and waits for a later turn.
    pub fn turn_with(&mut self, allowance: WriteWork) {
        self.clear_refusal();
        self.authority.begin_turn(allowance);
    }

    /// Run without a turn quantum, as for setup outside a measured
    /// operation: work is bounded by the lifetime allowance alone.
    pub fn open(&mut self) {
        self.authority.without_turns();
    }

    /// End the current turn: no further work is admitted until `fresh`.
    pub fn exhaust(&mut self) {
        self.authority.end_turn();
    }

    /// Forget counts, logs and the fault schedule's progress so that only the
    /// following calls are measured, and start a turn. Live storage and the
    /// ceilings are unaffected.
    pub fn measure(&mut self) {
        self.authority.restart();
        self.fresh();
        self.attempts = 0;
        self.requests = 0;
        self.refusals = 0;
        self.scheduled_refusals = 0;
        self.injected_refusals = 0;
        self.last_injected = false;
        self.refused = None;
        self.retrying = false;
        // Both terms count this policy's slots of one preallocated store,
        // whose length is a `usize`: their sum fits. An ordinary family has
        // no history to skip.
        if self.counters.recording.is_some() {
            self.measured += self.view().len();
        }
        self.trace = AdmissionTrace::new();
    }

    /// Foreground work admissible now: the lifetime allowance's remainder,
    /// within the current turn's when one is running. Successful foreground
    /// admissions consume it permanently; cleanup never does.
    pub fn remaining(&self) -> WriteWork {
        self.authority.remaining()
    }

    /// Cumulative admitted work, foreground and cleanup.
    pub fn used(&self) -> WriteWork {
        self.authority.used
    }

    /// The part of [`Self::used`] admitted as cleanup
    /// ([`super::Releasing::reclaim`]), which no lifetime ceiling counts.
    pub fn cleanup_used(&self) -> WriteWork {
        self.authority.cleanup
    }

    /// Requested capacities currently held by live reservations.
    pub fn live_bytes(&self) -> u64 {
        self.counters.live.load(Ordering::Acquire)
    }

    /// The most live bytes held at once.
    pub fn peak_bytes(&self) -> u64 {
        self.counters.peak.load(Ordering::Acquire)
    }

    /// Every boundary valuation reached by the policies over this storage,
    /// this one, those it shares with and their terminal policies, since the
    /// first of them was made ([`super::boundary`]). Not reset by
    /// [`Self::measure`]: a run's predicates include its setup's.
    pub fn reached(&self) -> Reached {
        Reached::from_bits(core::array::from_fn(|predicate| {
            self.counters.reached[predicate].load(Ordering::Relaxed)
        }))
    }

    /// This policy's counter family's credit ledgers, as a snapshot: what
    /// the family admitted through the route, consumed and forfeited
    /// ([`Credits`]). A family is this policy's counters: every
    /// [`Self::share`] of it and every terminal policy minted from its
    /// permits records into the same ledger, so a scope drained terminally
    /// is read here. Fresh policies are families of their own, summed
    /// ([`Credits::checked_add`]); a family serving several operations is
    /// read as a delta around each ([`Credits::checked_sub`]). Read at
    /// quiescence ([`Credits`]). Not reset by [`Self::measure`]: credit held
    /// across it is spent or forfeited after it. The ledgers count work
    /// committed, not work physically executed.
    pub fn credits(&self) -> Credits {
        self.counters.credits.snapshot()
    }

    /// Cumulative bytes of granted allocation requests.
    pub fn requested_bytes(&self) -> u64 {
        self.authority.requested
    }

    /// Attempted calls, refused ones included.
    pub fn attempts(&self) -> usize {
        self.attempts
    }

    /// Allocation requests, refused ones included.
    pub fn requests(&self) -> usize {
        self.requests
    }

    /// Refusals returned.
    pub fn refusals(&self) -> usize {
        self.refusals
    }

    /// Refusals whose reason is `Scheduled`. Use `injected_refusals` to count
    /// explicit injections carrying any reason, including Work or Storage.
    pub fn scheduled_refusals(&self) -> usize {
        self.scheduled_refusals
    }

    /// Refusals caused by an explicit fault injection, whatever its reason.
    pub fn injected_refusals(&self) -> usize {
        self.injected_refusals
    }

    /// This policy's own calls since construction or the last
    /// [`Self::measure`], each with its answer, as its recorded family's
    /// session holds them, the one record of them ([`record`]); refused,
    /// naming why, for a family that records nothing or a session that
    /// cannot report them. Never panics, never an empty or short history:
    /// the one read of a policy's history, which [`Self::view`] asserts.
    pub fn history(&self) -> Result<Vec<(Call, Answer)>, Unreadable> {
        let recording = self
            .counters
            .recording
            .as_ref()
            .ok_or(Unreadable::Unrecorded)?;
        let events = recording
            .view(self.performer())
            .map_err(Unreadable::Session)?;
        Ok(events
            .into_iter()
            .filter_map(|event| match event {
                Event::Call(call, answer) => Some((call, answer)),
                _ => None,
            })
            .skip(self.measured)
            .collect())
    }

    /// Whether this policy's recorded family's session is still evidence:
    /// one load of its sticky invalid flag, no history read
    /// ([`Self::history`] reads it whole). Refused [`Unreadable::Unrecorded`]
    /// for a family that records nothing, and
    /// [`Unreadable::Session`]`(`[`record::Incomplete::Exhausted`]`)` once a
    /// claim was exhausted or an owner of another session was paired with
    /// it: from then on nothing it records is evidence. A driver checks it
    /// after a refused turn, so the refusal that preceded the invalidation is
    /// named rather than masked by a later history read's panic.
    pub fn evidence(&self) -> Result<(), Unreadable> {
        match &self.counters.recording {
            None => Err(Unreadable::Unrecorded),
            Some(recording) if recording.valid() => Ok(()),
            Some(_) => Err(Unreadable::Session(record::Incomplete::Exhausted)),
        }
    }

    /// What first made this policy's recorded family's session no evidence
    /// ([`record::Invalidation`]), if anything has: the dimension
    /// [`Self::evidence`]'s [`record::Incomplete::Exhausted`] does not name.
    /// `None` for a valid session and for a family that records nothing.
    pub fn invalidation(&self) -> Option<record::Invalidation> {
        self.counters
            .recording
            .as_ref()
            .and_then(Recording::invalidation)
    }

    /// [`Self::history`], asserted: a test instrument's report, read by
    /// [`Self::calls`], [`Self::admitted_calls`], [`Self::refused_calls`]
    /// and [`Self::assert_units`].
    fn view(&self) -> Vec<(Call, Answer)> {
        self.history()
            .unwrap_or_else(|unreadable| match unreadable {
                Unreadable::Unrecorded => {
                    panic!("this policy records no history; construct it with Limits::recorded")
                }
                Unreadable::Session(incomplete) => {
                    panic!("the recording session is unusable: {incomplete:?}")
                }
            })
    }

    /// Refused calls: index among this policy's calls, reason, and whether
    /// the fault schedule injected it ([`Self::view`]).
    pub fn refused_calls(&self) -> Vec<(usize, LimitRefusal, bool)> {
        self.view()
            .into_iter()
            .enumerate()
            .filter_map(|(index, (_, answer))| match answer {
                Answer::Refused { refusal, injected } => Some((index, refusal, injected)),
                _ => None,
            })
            .collect()
    }

    /// The refusal not yet cleared: its call index and reason.
    pub fn first_refusal(&self) -> Option<(usize, LimitRefusal)> {
        self.refused
    }

    /// The deterministic clock: one tick per attempted call.
    pub fn clock(&self) -> u64 {
        self.clock
    }

    /// Attempted calls ([`Self::view`]: panics on an unrecorded family).
    pub fn calls(&self) -> Vec<Call> {
        self.view().into_iter().map(|(call, _)| call).collect()
    }

    /// Admitted calls: admitted work and granted allocations
    /// ([`Self::view`]). Named apart from the admission observation
    /// [`Budget::admitted`], which a `&mut Limits` receiver would otherwise
    /// resolve to first.
    pub fn admitted_calls(&self) -> Vec<Call> {
        self.view()
            .into_iter()
            .filter(|(_, answer)| !matches!(answer, Answer::Refused { .. }))
            .map(|(call, _)| call)
            .collect()
    }

    pub fn trace(&self) -> &AdmissionTrace {
        &self.trace
    }

    pub fn trace_mut(&mut self) -> &mut AdmissionTrace {
        &mut self.trace
    }

    /// Panic unless every recorded work and cleanup unit fit in `quantum`.
    #[cfg_attr(
        kani,
        expect(
            unused_variables,
            reason = "Kani's assert! override does not evaluate its message, the only reader of index"
        )
    )]
    pub fn assert_units(&self, quantum: WriteWork) {
        for (index, call) in self.calls().into_iter().enumerate() {
            if let Some(work) = call.work() {
                assert!(
                    work.values <= quantum.values && work.bytes <= quantum.bytes,
                    "indivisible operation {index}: {call:?} exceeds {quantum:?}"
                );
            }
        }
    }

    /// The one admission of a call. A granted allocation in a recorded family
    /// returns its committed record and identity.
    ///
    /// A recorded grant claims its record only after the policy's own checks
    /// have passed and its live capacity is reserved by the one atomic
    /// check-and-increment, so a refused request never consumes a record:
    /// a complete session's records are exactly one per grant and per split
    /// child. When the session has no record or identity left, the reserved
    /// capacity is subtracted again before anything else changes (no peak,
    /// requested total, grant or observer effect) and the call is refused
    /// [`LimitRefusal::Unrecorded`]. Between that reservation and its
    /// subtraction a concurrent request of the same family may see the
    /// capacity taken and be refused; that happens only once the session is
    /// exhausted, when the run is no evidence.
    fn admit(&mut self, call: Call) -> Result<Option<(u64, Identity)>, LimitRefusal> {
        if self.strict {
            assert!(
                self.refused.is_none(),
                "execution continued after refusal {:?}",
                self.refused
            );
        }
        let index = self.attempts;
        self.attempts += 1;
        let now = self.clock;
        self.clock = self.clock.saturating_add(1);
        if call.is_foreground() && self.expiry.is_some_and(|expiry| now >= expiry) {
            return Err(LimitRefusal::Deadline);
        }
        if let Some((at, reason)) = self.fail_at
            && at == index
        {
            self.last_injected = true;
            return Err(reason);
        }
        if self.refuse_each {
            self.retrying = !self.retrying;
            if self.retrying {
                self.last_injected = true;
                return Err(LimitRefusal::Scheduled(index));
            }
        }
        match call {
            Call::Reclaim { values, bytes } => {
                self.authority.reclaim(WriteWork::new(values, bytes))?;
                Ok(None)
            }
            Call::Work { values, bytes } => {
                self.authority.work(WriteWork::new(values, bytes))?;
                Ok(None)
            }
            Call::Allocate(bytes) => {
                let request = self.requests;
                self.requests += 1;
                if self.fail_request == Some(request) {
                    self.last_injected = true;
                    return Err(LimitRefusal::Scheduled(index));
                }
                if self.fail_requests > 0 {
                    self.last_injected = true;
                    self.fail_requests -= 1;
                    return Err(LimitRefusal::Scheduled(index));
                }
                let requested = self.authority.request(bytes)?;
                // Shared policies can admit concurrently. Check capacity and
                // reserve it in one atomic update, retrying against the latest
                // total when another admission or release wins the race.
                let ceiling = self.authority.ceilings.live;
                let mut previous = self.counters.live.load(Ordering::Acquire);
                let live = loop {
                    let next = previous
                        .checked_add(bytes)
                        .filter(|next| *next <= ceiling)
                        .ok_or(LimitRefusal::Storage)?;
                    match self.counters.live.compare_exchange_weak(
                        previous,
                        next,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    ) {
                        Ok(_) => break next,
                        Err(current) => previous = current,
                    }
                };
                let granted = match &self.counters.recording {
                    None => None,
                    Some(recording) => match recording.reserve(bytes) {
                        Some((record, id)) => {
                            recording.commit(record);
                            Some((record, id))
                        }
                        None => {
                            self.counters.live.fetch_sub(bytes, Ordering::AcqRel);
                            return Err(LimitRefusal::Unrecorded);
                        }
                    },
                };
                self.counters.peak.fetch_max(live, Ordering::AcqRel);
                self.authority.granted(requested);
                Ok(granted)
            }
        }
    }

    /// The call's answer as an observation: a granted allocation's is
    /// published by [`Allocator::allocate`] once its permit's identity is
    /// committed, every other answer here.
    fn publish_call(&self, call: Call, result: Result<(), LimitRefusal>) {
        match (call, result) {
            (Call::Allocate(_), Ok(())) => {}
            (_, Ok(())) => self.publish(Event::Call(call, Answer::Admitted)),
            (_, Err(refusal)) => self.publish(Event::Call(
                call,
                Answer::Refused {
                    refusal,
                    injected: self.last_injected,
                },
            )),
        }
    }

    fn admit_traced(&mut self, call: Call) -> Result<Option<(u64, Identity)>, LimitRefusal> {
        if self.terminal {
            // A terminal policy's units are admitted uncounted and its
            // requests refused, each published as asked: publication
            // allocates nothing.
            let result = match call {
                Call::Work { .. } | Call::Reclaim { .. } => Ok(()),
                Call::Allocate(_) => Err(LimitRefusal::Storage),
            };
            self.publish_call(call, result);
            return result.map(|()| None);
        }
        self.last_injected = false;
        let granted = self.admit(call);
        let result = granted.map(|_| ());
        if let Err(reason) = result {
            self.refusals += 1;
            self.injected_refusals += usize::from(self.last_injected);
            if matches!(reason, LimitRefusal::Scheduled(_)) {
                self.scheduled_refusals += 1;
            }
            self.refused.get_or_insert((self.attempts - 1, reason));
        }
        self.publish_call(call, result);
        self.trace.record(Admission {
            index: self.attempts - 1,
            call,
            result,
            work: self.authority.used,
            storage: (self.live_bytes(), self.peak_bytes()),
            position: None,
        });
        granted
    }
}

impl Default for Limits {
    fn default() -> Self {
        Self::unlimited()
    }
}

impl Budget for Limits {
    type Refusal = LimitRefusal;
    fn traverse(&mut self, values: u64, bytes: u64) -> Result<(), LimitRefusal> {
        self.admit_traced(Call::Work { values, bytes }).map(|_| ())
    }

    fn boundary(&mut self, boundary: Boundary) {
        self.counters.reached[boundary.predicate.index()]
            .fetch_or(1u64 << boundary.valuation.index(), Ordering::Relaxed);
    }

    type Origin = Family;

    fn origin(&self) -> Family {
        Family {
            counters: self.counters.clone(),
        }
    }

    /// Recorded into the family's shared ledgers (`Ledgers::record`), in
    /// every mode, the terminal one included: checked compare-exchange
    /// updates of the family atomics; and, in a recorded family, published
    /// into its session. Both allocate nothing and do not unwind.
    fn admitted(&mut self, work: WriteWork) {
        let credit = Credit::Admit { work, held: None };
        self.counters.credits.record(credit);
        self.publish(Event::Credit(credit));
    }

    /// As [`Self::admitted`], the held part's identity minted from the
    /// family's session; an ordinary family's, or an exhausted session's,
    /// is [`Identity::UNOBSERVED`].
    fn identify(&mut self) -> Result<Identity, LimitRefusal> {
        self.mint()
    }

    fn held(&mut self, work: WriteWork, hold: Hold) {
        let credit = Credit::Admit {
            work,
            held: Some(hold),
        };
        self.counters.credits.record(credit);
        self.publish(Event::Credit(credit));
    }

    fn effect(&mut self, effect: Effect) {
        self.publish(Event::Effect(effect));
    }

    /// An ordinary family's owner is [`Owner::unobserved`]; a recorded
    /// family's is minted in its session and published, or refused
    /// [`LimitRefusal::Unrecorded`] when the session has no identity left
    /// (the session is then, stickily, no evidence).
    fn owner(&mut self) -> Result<Owner, LimitRefusal> {
        let by = self.performer();
        match &self.counters.recording {
            None => Ok(Owner::unobserved()),
            Some(recording) => recording.owner(by).ok_or(LimitRefusal::Unrecorded),
        }
    }

    /// [`Self::validate_owner`], then, in a recorded family, the
    /// acquisition's identity minted and its binding published; refused
    /// [`LimitRefusal::Unrecorded`] when validation refuses or the session
    /// has no identity left. An ordinary family's acquisition is
    /// [`Identity::UNOBSERVED`].
    fn acquisition(&mut self, owner: &Owner) -> Result<Acquisition<Family>, LimitRefusal> {
        self.validate_owner(owner)?;
        let Some(recording) = &self.counters.recording else {
            // An ordinary family's origin records nothing, and its validated
            // owner is ordinary.
            return Acquisition::ordinary(self.origin(), owner).ok_or(LimitRefusal::Unrecorded);
        };
        let acquisition = recording.mint().ok_or(LimitRefusal::Unrecorded)?;
        self.publish(Event::Bound {
            acquisition,
            owner: owner.id(),
        });
        Acquisition::minted(self.origin(), acquisition, owner).ok_or(LimitRefusal::Unrecorded)
    }

    /// The one compatibility rule: an ordinary family performs only for an
    /// ordinary owner, a recorded family only for an owner of its own,
    /// still valid, session. Every other pairing is refused
    /// [`LimitRefusal::Unrecorded`] and invalidates, stickily, every
    /// recording session involved: the family's, and the owner's when the
    /// family is ordinary or of another session. Accounting is unchanged;
    /// recording validity becomes sticky-invalid.
    fn validate_owner(&mut self, owner: &Owner) -> Result<(), LimitRefusal> {
        let compatible = match &self.counters.recording {
            None => !owner.recorded_in_any(),
            Some(recording) => recording.owns(owner) && recording.valid(),
        };
        if compatible {
            return Ok(());
        }
        if let Some(recording) = &self.counters.recording {
            // An owner of this session paired after the session became no
            // evidence is refused too; its cause stays the first one.
            recording.invalidate(record::Invalidation::ForeignOwner);
        }
        owner.invalidate();
        Err(LimitRefusal::Unrecorded)
    }

    /// This policy's number in its recorded family's session; an ordinary
    /// family's policies perform as no recorded policy.
    fn performer(&self) -> Performer {
        if self.counters.recording.is_some() && self.policy != 0 {
            Performer::Policy(self.policy)
        } else {
            Performer::None
        }
    }
}

/// A [`Limits`] family's credit capability ([`Origin`]): the right to
/// settle held credit into the family's ledgers, and to publish the
/// settlement into the family's session, and nothing else. It holds a
/// counted reference to the family's counters, made without admission or
/// allocation; it is no permit, holds no storage, and no policy is made
/// from it. Dropping it releases nothing.
///
/// It is no [`Budget`]:
/// ```compile_fail,E0599
/// use dcbor::bounded::{Budget, Limits};
/// let family = Limits::unlimited().origin();
/// let _ = family.traverse(1, 0);
/// ```
/// It is no permit, so no terminal policy is minted from it:
/// ```compile_fail,E0308
/// use dcbor::bounded::{Budget, Limits, TerminalAllocator};
/// let family = Limits::unlimited().origin();
/// let _ = Limits::terminal(&family);
/// ```
/// Its counters are unreachable:
/// ```compile_fail,E0616
/// use dcbor::bounded::{Budget, Limits};
/// let family = Limits::unlimited().origin();
/// let _ = family.counters;
/// ```
pub struct Family {
    counters: Arc<Counters>,
}

impl Origin for Family {
    fn family(&self) -> u64 {
        self.counters
            .recording
            .as_ref()
            .map_or(0, Recording::family)
    }

    /// One `Ledgers::record`, the one update rule, and in a recorded family
    /// one publication under its performer: allocation-free, non-unwinding.
    fn settle(&self, settled: Settled, rule: Option<Forfeit>, by: Performer) {
        let credit = match rule {
            None => Credit::Spend(settled),
            Some(rule) => Credit::Forfeit(settled, rule),
        };
        self.counters.credits.record(credit);
        if let Some(recording) = &self.counters.recording {
            recording.publish(by, Event::Credit(credit));
        }
    }

    /// In a recorded family, one publication under its performer
    /// ([`Event::End`]), through the family's own recording: the family
    /// that minted the acquisition, since only its capability reaches here.
    /// An end naming no acquisition this family minted (unidentified, or of
    /// another family) is never discarded silently: it invalidates the
    /// session, stickily, before publishing, so the run is no evidence.
    /// An unrecorded family publishes nothing.
    fn end(&self, acquisition: Identity, owner: Identity, by: Performer) {
        let Some(recording) = &self.counters.recording else {
            return;
        };
        if acquisition == Identity::UNOBSERVED || acquisition.family() != recording.family() {
            recording.invalidate(record::Invalidation::ForeignAcquisition);
        }
        recording.publish(by, Event::End { acquisition, owner });
    }
}

// SAFETY: terminal: constructing this policy only clones an existing Arc,
// which allocates nothing and never unwinds, and its fields have
// allocation-free, non-unwinding drops. traverse: terminal admissions,
// through `traverse` and `reclaim` alike, bypass the policy's limits and
// counters and never refuse work; recording a
// boundary is one relaxed `fetch_or` on the shared counters, a credit event
// checked compare-exchange updates and a `fetch_or` on the same counters, and
// publishing an observation into a recorded family's session claims a
// preallocated slot and stores its words (`record`), all allocation-free and
// non-unwinding, a failed update or an exhausted session setting a flag
// rather than panicking. allocate: a terminal policy rejects every
// allocation request, allocating nothing. borrow: the policy holds its own
// clone of the permit's counters, never a reference to `permit`.
unsafe impl super::TerminalAllocator for Limits {
    fn terminal(permit: &Reservation) -> Self {
        let mut policy = Self::with_counters(Ceilings::UNLIMITED, permit.counters.clone());
        policy.terminal = true;
        policy
    }
}

impl super::Releasing for Limits {
    type Permit = Reservation;

    /// The cleanup account ([`Authority::reclaim`]): attempted, clocked,
    /// traced and published as every call is, and refused by the fault
    /// schedule as every call is, the instrument's alone; never by the
    /// deadline or the lifetime work ceiling.
    fn reclaim(&mut self, values: u64, bytes: u64) -> Result<(), LimitRefusal> {
        self.admit_traced(Call::Reclaim { values, bytes })
            .map(|_| ())
    }

    fn permit_identity(permit: &Reservation) -> Identity {
        permit.identity()
    }

    fn custody(permit: &Reservation, owner: Identity, stage: RecordStage) {
        permit.custody(owner, stage);
    }
}

impl Allocator for Limits {
    /// The one admission ([`Self::admit_traced`]) grants or refuses; a
    /// recorded grant arrives with its committed record and identity. The
    /// owning permit is made at once, before the allocation observer runs,
    /// so an observer that unwinds drops a permit that releases what was
    /// admitted: no admitted storage is ever left without an owner.
    fn allocate(&mut self, bytes: u64) -> Result<Reservation, LimitRefusal> {
        let granted = self.admit_traced(Call::Allocate(bytes))?;
        let word = granted.map_or(bytes, |(index, _)| index);
        let permit = Reservation {
            counters: self.counters.clone(),
            word,
        };
        if let Some((_, id)) = granted {
            self.publish(Event::Call(Call::Allocate(bytes), Answer::Granted(id)));
        }
        if let Some(observer) = self.observer {
            observer(bytes);
        }
        Ok(permit)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::format;

    #[test]
    fn refusals_name_their_cause() {
        assert_eq!(format!("{}", LimitRefusal::Turn), "turn quantum spent");
        assert_eq!(
            format!("{}", LimitRefusal::QuantumTooSmall),
            "unit exceeds the turn quantum"
        );
        assert_eq!(format!("{}", LimitRefusal::Work), "work limit");
        assert_eq!(
            format!("{}", LimitRefusal::Requested),
            "requested-bytes limit"
        );
        assert_eq!(format!("{}", LimitRefusal::Storage), "storage limit");
        assert_eq!(
            format!("{}", LimitRefusal::TooLarge),
            "request exceeds the storage ceiling"
        );
        assert_eq!(
            format!("{}", LimitRefusal::Contended),
            "group admission contended"
        );
        assert_eq!(format!("{}", LimitRefusal::Deadline), "deadline");
        assert_eq!(format!("{}", LimitRefusal::Cancelled), "cancelled");
        assert_eq!(
            format!("{}", LimitRefusal::Scheduled(7)),
            "scheduled refusal of call 7"
        );
        assert_eq!(
            format!(
                "{}",
                TransferRefusal::Insufficient {
                    requested: 9,
                    held: 4
                }
            ),
            "split of 9 bytes from a reservation of 4"
        );
        assert_eq!(
            format!("{}", TransferRefusal::Foreign),
            "reservations count against different storage"
        );
        assert_eq!(
            format!("{}", TransferRefusal::Overflow),
            "merged reservation exceeds u64"
        );
    }

    /// A trace counts every attempt, keeps the last and the first refusal,
    /// and renders them; an empty trace is its default.
    #[test]
    #[expect(
        clippy::disallowed_methods,
        reason = "the policy's own trace is driven by direct admissions"
    )]
    fn a_trace_counts_keeps_and_renders_its_admissions() {
        let empty = AdmissionTrace::default();
        assert_eq!(empty.count(), 0);
        assert!(empty.last().is_none() && empty.first_refusal().is_none());
        let mut m = Limits::new(1, 64, 0);
        m.traverse(1, 8).unwrap();
        assert_eq!(m.traverse(1, 8), Err(LimitRefusal::Work));
        let trace = m.trace();
        assert_eq!(trace.count(), 2);
        let last = trace.last().expect("an attempt was recorded");
        assert_eq!((last.index, last.result), (1, Err(LimitRefusal::Work)));
        assert_eq!(trace.first_refusal().map(|refusal| refusal.index), Some(1));
        let rendered = format!("{trace:?}");
        assert!(
            rendered.starts_with("first_refusal=Some(") && rendered.contains("total_events=2"),
            "{rendered}"
        );
        assert!(
            rendered.contains("call=0 Work { values: 1, bytes: 8 } -> Ok(())")
                && rendered.contains("call=1 Work { values: 1, bytes: 8 } -> Err(Work)"),
            "{rendered}"
        );
        let calls = [
            Call::Allocate(4),
            Call::Work {
                values: 1,
                bytes: 0,
            },
        ];
        trace.assert_calls(&calls, &calls, "equal calls");
    }

    #[test]
    #[should_panic(expected = "admission replay: run=differing calls, first_difference=1")]
    fn differing_call_sequences_are_reported_at_their_first_difference() {
        AdmissionTrace::new().assert_calls(
            &[Call::Allocate(4), Call::Allocate(8)],
            &[Call::Allocate(4), Call::Allocate(16)],
            "differing calls",
        );
    }

    /// Every admission refused once: each attempt is refused as a scheduled
    /// refusal of its own index, and its retry admitted; the allowance of a
    /// bound of `n` steps is `2n + 1`.
    #[test]
    #[expect(
        clippy::disallowed_methods,
        reason = "the policy's refusal schedule is driven by direct admissions"
    )]
    fn every_admission_is_refused_once_then_admitted() {
        let mut m = Limits::unlimited().refusing_each();
        assert!(m.refuses_each());
        assert_eq!(m.allowed::<()>(3), Ok(7));
        assert_eq!(m.traverse(1, 0), Err(LimitRefusal::Scheduled(0)));
        assert_eq!(m.traverse(1, 0), Ok(()));
        assert_eq!(
            m.allocate(4).map(|permit| permit.bytes()).unwrap_err(),
            LimitRefusal::Scheduled(2)
        );
        assert_eq!(m.allocate(4).map(|permit| permit.bytes()), Ok(4));
        assert_eq!(m.injected_refusals(), 2);
        assert!(!Limits::unlimited().refuses_each());
    }

    /// The selected allocation request is refused once, counted among
    /// requests only, whether selected at construction or later.
    #[test]
    fn the_selected_allocation_request_is_refused_once() {
        let mut m = Limits::unlimited().refusing_request(Some(1));
        assert_eq!(m.allocate(4).map(|permit| permit.bytes()), Ok(4));
        assert_eq!(
            m.allocate(4).map(|permit| permit.bytes()).unwrap_err(),
            LimitRefusal::Scheduled(1)
        );
        assert_eq!(m.allocate(4).map(|permit| permit.bytes()), Ok(4));
        let mut later = Limits::unlimited();
        later.fail_request(Some(0));
        assert_eq!(
            later.allocate(2).map(|permit| permit.bytes()).unwrap_err(),
            LimitRefusal::Scheduled(0)
        );
        assert_eq!(later.allocate(2).map(|permit| permit.bytes()), Ok(2));
        assert_eq!(later.requests(), 2);
    }

    mod credits {
        use super::*;
        use crate::bounded::{BoundedError, Caller, Forfeit, Obligation, Unit};

        const TEN: WriteWork = WriteWork::new(1, 10);
        const ZERO: WriteWork = WriteWork::new(0, 0);

        /// `work` held for `obligation`, of no recorded identity.
        fn hold(obligation: Obligation, work: WriteWork) -> Hold {
            Hold {
                obligation,
                work,
                id: Identity::UNOBSERVED,
                acquisition: Identity::UNOBSERVED,
            }
        }

        /// `work` of `obligation` settled, of no recorded identity.
        fn settlement(obligation: Obligation, work: WriteWork) -> Settled {
            Settled {
                obligation,
                work,
                id: Identity::UNOBSERVED,
                acquisition: Identity::UNOBSERVED,
                permit: None,
            }
        }

        /// An admission of `work`, all of it held for a release.
        fn held(work: WriteWork) -> Credit {
            Credit::Admit {
                work,
                held: Some(hold(Obligation::Release, work)),
            }
        }

        fn consumed(work: WriteWork) -> Credit {
            Credit::Admit { work, held: None }
        }

        fn spend(obligation: Obligation, work: WriteWork) -> Credit {
            Credit::Spend(settlement(obligation, work))
        }

        fn forfeit(obligation: Obligation, work: WriteWork, rule: Forfeit) -> Credit {
            Credit::Forfeit(settlement(obligation, work), rule)
        }

        /// `credit` recorded by `policy` through the production seams: an
        /// admission through the budget's observations ([`Budget::admitted`],
        /// [`Budget::held`]), a settlement through the family's origin
        /// ([`Budget::origin`], [`Origin::settle`]), performed by `policy`.
        fn record(policy: &mut Limits, credit: Credit) {
            match credit {
                Credit::Admit { work, held: None } => policy.admitted(work),
                Credit::Admit {
                    work,
                    held: Some(hold),
                } => policy.held(work, hold),
                Credit::Spend(settled) => policy.origin().settle(settled, None, policy.performer()),
                Credit::Forfeit(settled, rule) => {
                    policy
                        .origin()
                        .settle(settled, Some(rule), policy.performer())
                }
            }
        }

        /// A fresh family that recorded `events`, through the production
        /// seams ([`record`]).
        fn family(events: &[Credit]) -> Limits {
            let mut policy = Limits::unlimited();
            for &event in events {
                record(&mut policy, event);
            }
            policy
        }

        /// The ledgers of a fresh family that recorded `events`.
        fn ledgers(events: &[Credit]) -> Credits {
            family(events).credits()
        }

        /// The terminal oracle of one operation: conserved with what its
        /// custody still holds, and nothing held.
        fn settled(credits: Credits, held: WriteWork) -> bool {
            credits.conserved_with(held) == Some(true) && held == ZERO
        }

        /// Each event moves exactly its own ledgers: an admission A and its
        /// unheld part C, a spend C, a forfeit F; an admission part held
        /// conserves only with its custody's held credit beside it.
        #[test]
        fn each_event_moves_its_own_ledgers() {
            let mut policy = family(&[consumed(TEN)]);
            assert_eq!(
                policy.credits(),
                Credits {
                    admitted: TEN,
                    consumed: TEN,
                    ..Credits::default()
                }
            );
            record(
                &mut policy,
                Credit::Admit {
                    work: WriteWork::new(1, 64),
                    held: Some(hold(Obligation::BucketWindow, WriteWork::new(0, 64))),
                },
            );
            let credits = policy.credits();
            assert_eq!(credits.admitted, WriteWork::new(2, 74));
            assert_eq!(credits.consumed, WriteWork::new(2, 10));
            assert_eq!(credits.conserved_with(WriteWork::new(0, 64)), Some(true));
            assert_eq!(credits.conserved_with(ZERO), Some(false));
            record(
                &mut policy,
                spend(Obligation::BucketWindow, WriteWork::new(0, 60)),
            );
            record(
                &mut policy,
                forfeit(
                    Obligation::BucketWindow,
                    WriteWork::new(0, 4),
                    Forfeit::EnumerationComplete,
                ),
            );
            let credits = policy.credits();
            assert_eq!(credits.consumed, WriteWork::new(2, 70));
            assert_eq!(credits.forfeited, WriteWork::new(0, 4));
            assert!(settled(credits, ZERO));
            assert!(!credits.violated);
        }

        /// Every policy of one family records into one ledger: a share's
        /// events and a terminal policy's, minted from a permit the family
        /// granted, are read through the originating policy; a fresh policy
        /// is a family of its own.
        #[test]
        fn a_family_shares_one_ledger_and_a_fresh_policy_does_not() {
            let mut origin = Limits::unlimited();
            record(&mut origin, held(TEN));
            let mut shared = origin.share();
            record(
                &mut shared,
                spend(Obligation::Release, WriteWork::new(1, 4)),
            );
            let permit = origin.allocate(1).expect("an unlimited policy grants");
            let mut terminal = <Limits as crate::bounded::TerminalAllocator>::terminal(&permit);
            record(
                &mut terminal,
                forfeit(
                    Obligation::Release,
                    WriteWork::new(0, 6),
                    Forfeit::Cancelled,
                ),
            );
            drop(terminal);
            assert_eq!(
                origin.credits(),
                Credits {
                    admitted: TEN,
                    consumed: WriteWork::new(1, 4),
                    forfeited: WriteWork::new(0, 6),
                    violated: false,
                }
            );
            assert!(settled(origin.credits(), ZERO));
            assert_eq!(Limits::unlimited().credits(), Credits::default());
            drop(permit);
        }

        /// An update that does not fit, and an admission holding more than
        /// it admitted, change no ledger and set the violation, which
        /// conservation then refuses; sums, deltas and the conservation
        /// check refuse what does not fit, at `u64::MAX`.
        #[test]
        fn every_ledger_sum_is_checked_at_u64_max() {
            let full = WriteWork::new(u64::MAX, u64::MAX);
            let credits = ledgers(&[consumed(full), consumed(TEN)]);
            assert_eq!((credits.admitted, credits.consumed), (full, full));
            assert!(credits.violated);
            assert_eq!(credits.conserved_with(ZERO), Some(false));
            let spent = ledgers(&[consumed(full), spend(Obligation::Release, TEN)]);
            assert!(spent.violated && spent.consumed == full);
            let forfeited = ledgers(&[
                forfeit(Obligation::Release, full, Forfeit::Cancelled),
                forfeit(Obligation::Grant, TEN, Forfeit::Cancelled),
            ]);
            assert!(forfeited.violated && forfeited.forfeited == full);
            let overheld = ledgers(&[Credit::Admit {
                work: TEN,
                held: Some(hold(Obligation::Grant, WriteWork::new(1, 11))),
            }]);
            assert_eq!(overheld.admitted, ZERO, "an overheld admission was applied");
            assert!(overheld.violated);
            let whole = ledgers(&[consumed(full)]);
            assert_eq!(whole.checked_add(ledgers(&[consumed(TEN)])), None);
            assert_eq!(ledgers(&[consumed(TEN)]).checked_sub(whole), None);
            assert_eq!(
                whole.conserved_with(TEN),
                None,
                "C + F + H beyond u64 compared"
            );
            assert_eq!(
                whole.checked_sub(whole),
                Some(Credits::default()),
                "a delta of nothing"
            );
        }

        /// The route reports an admission's disposition only once the policy
        /// admits it: a refused admission records nothing, an admitted held
        /// one records A and leaves C to its spend.
        #[test]
        fn a_refused_admission_records_no_credit() {
            let unit = Unit::new(Caller, 1, 10);
            let owner = Owner::unobserved();
            let mut refusing = Limits::unlimited().refusing(Some(0));
            assert!(matches!(
                unit.admit_held(
                    &mut refusing,
                    Obligation::Release,
                    &owner,
                    Identity::UNOBSERVED
                ),
                Err(BoundedError::Refused(_))
            ));
            assert_eq!(refusing.credits(), Credits::default());
            let retained = unit
                .admit_held(
                    &mut refusing,
                    Obligation::Release,
                    &owner,
                    Identity::UNOBSERVED,
                )
                .expect("the retry is admitted");
            assert_eq!(
                refusing.credits(),
                Credits {
                    admitted: TEN,
                    ..Credits::default()
                }
            );
            assert_eq!(refusing.credits().conserved_with(TEN), Some(true));
            retained.spend(None, refusing.performer());
            assert_eq!(refusing.credits().conserved_with(ZERO), Some(true));
        }

        /// Planted control, "dropped Spend": the custody advanced past its
        /// grant, so it holds nothing, but the spend was never recorded:
        /// conservation fails, though nothing is held.
        #[test]
        fn a_dropped_spend_fails_conservation() {
            let honest = ledgers(&[held(TEN), spend(Obligation::Release, TEN)]);
            assert!(settled(honest, ZERO));
            let dropped = ledgers(&[held(TEN)]);
            assert_eq!(dropped.conserved_with(ZERO), Some(false));
            assert!(!settled(dropped, ZERO));
        }

        /// Planted control, "lost credit across suspension": a custody whose
        /// held credit falls across a suspension with no spend or forfeit
        /// recorded, the observation wrapped to drop it, is refused.
        #[test]
        fn credit_lost_across_a_suspension_fails_conservation() {
            let before = ledgers(&[held(TEN)]);
            let observed = |held: WriteWork| held;
            let lost = |_: WriteWork| ZERO;
            assert_eq!(before.conserved_with(observed(TEN)), Some(true));
            assert_eq!(before.conserved_with(lost(TEN)), Some(false));
        }

        /// Planted control, "spend recorded twice": one obligation spent on
        /// two policy instances, a held credit's spend recorded once per
        /// policy; the instances' sum is refused.
        #[test]
        fn a_spend_recorded_on_two_policies_fails_conservation() {
            let holder = ledgers(&[held(TEN), spend(Obligation::Release, TEN)]);
            let resumed = ledgers(&[spend(Obligation::Release, TEN)]);
            let once = holder
                .checked_add(Credits::default())
                .expect("small ledgers sum");
            assert!(settled(once, ZERO));
            let twice = holder.checked_add(resumed).expect("small ledgers sum");
            assert_eq!(twice.conserved_with(ZERO), Some(false));
        }

        /// Planted control, "obligation left held": a terminal custody
        /// observation still reporting outstanding credit fails the
        /// terminal zero-held check, though the ledgers conserve with it.
        #[test]
        fn an_obligation_left_held_fails_the_terminal_check() {
            let credits = ledgers(&[held(TEN)]);
            assert_eq!(credits.conserved_with(TEN), Some(true));
            assert!(!settled(credits, TEN));
        }

        /// Two operations on one policy, the first defective: it spends
        /// credit it never admitted, while the second still holds credit it
        /// admitted. The whole snapshot, checked against the first's custody,
        /// masks the defect; the delta around the first finds it.
        #[test]
        fn a_delta_per_operation_finds_what_the_whole_snapshot_masks() {
            let mut policy = family(&[held(TEN)]);
            let start = policy.credits();
            record(&mut policy, spend(Obligation::Release, TEN));
            let end = policy.credits();
            // The first operation's custody holds nothing once it ends.
            assert_eq!(
                end.conserved_with(ZERO),
                Some(true),
                "the whole snapshot masks the defect"
            );
            let delta = end.checked_sub(start).expect("a later snapshot");
            assert_eq!(
                delta.conserved_with(ZERO),
                Some(false),
                "the operation's delta finds it"
            );
        }
    }

    /// The default policy is unlimited: every quantity's allowance is the
    /// whole of `u64`.
    #[test]
    fn the_default_policy_is_unlimited() {
        let mut m = Limits::default();
        assert_eq!(m.remaining(), WriteWork::new(u64::MAX, u64::MAX));
        let permit = m.allocate(u64::MAX).expect("unlimited storage");
        assert_eq!(m.live_bytes(), u64::MAX);
        drop(permit);
        assert_eq!(m.live_bytes(), 0);
    }

    /// The accounting core's axioms ([`Authority`]), each through the
    /// instrument's public surface.
    mod authority {
        use super::*;
        use crate::bounded::Releasing;

        const ONE: WriteWork = WriteWork::new(1, 0);

        /// Lifetime authorization never increases: a policy of five values
        /// stepped one quantum at a time admits exactly five, every later
        /// turn refusing the lifetime allowance ([`LimitRefusal::Work`],
        /// which stops), never the turn's; the turns' own usage is all that
        /// a turn resets, and the remainder of a quantity the policy leaves
        /// unlimited is the turn's.
        #[test]
        #[expect(
            clippy::disallowed_methods,
            reason = "the policy's axioms are driven by direct admissions"
        )]
        fn turns_never_raise_lifetime_authorization() {
            let mut m = Limits::new(5, u64::MAX, u64::MAX);
            let mut admitted = 0;
            for _ in 0..10 {
                m.turn();
                while m.traverse(1, 0).is_ok() {
                    admitted += 1;
                }
            }
            assert_eq!(admitted, 5, "turns raised the lifetime allowance");
            assert_eq!(m.used(), WriteWork::new(5, 0));
            m.turn();
            assert_eq!(m.traverse(1, 0), Err(LimitRefusal::Work));
            // Each quantity's remainder is its own: the values are spent for
            // good, the bytes the policy leaves unlimited are the turn's, and
            // exactly that remainder is admissible.
            assert_eq!(m.remaining(), WriteWork::new(0, TURN.bytes));
            m.traverse(0, TURN.bytes).unwrap();
            assert_eq!(m.remaining(), WriteWork::new(0, 0));
            assert_eq!(LimitRefusal::Work.recovery(), Recovery::Stop);
        }

        /// A refused admission commits nothing: work refused for its turn,
        /// for its quantum and for the lifetime allowance leaves the totals
        /// as they were; a request refused for the requested ceiling, for
        /// the whole live ceiling and for live capacity leaves the requested
        /// total, live and peak bytes as they were.
        #[test]
        #[expect(
            clippy::disallowed_methods,
            reason = "the policy's axioms are driven by direct admissions"
        )]
        fn a_refused_admission_commits_nothing() {
            // Ten values in all: the turn's and the quantum's refusals come
            // well within the lifetime allowance, its own refusal last.
            let mut m = Limits::new(10, u64::MAX, 8).requesting_at_most(10);
            m.turn_with(WriteWork::new(2, 64));
            m.traverse(2, 0).unwrap();
            let before = (m.used(), m.remaining());
            assert_eq!(m.traverse(1, 0), Err(LimitRefusal::Turn));
            assert_eq!(
                m.traverse(TURN.values + 1, 0),
                Err(LimitRefusal::QuantumTooSmall)
            );
            assert_eq!(
                (m.used(), m.remaining()),
                before,
                "a refused unit committed"
            );
            for _ in 0..2 {
                m.turn();
                m.traverse(TURN.values, 0).unwrap();
            }
            m.turn();
            assert_eq!(m.traverse(TURN.values, 0), Err(LimitRefusal::Work));
            assert_eq!(
                m.used(),
                WriteWork::new(2 + 2 * TURN.values, 0),
                "a refused unit committed"
            );
            let held = m.allocate(6).unwrap();
            let before = (m.requested_bytes(), m.live_bytes(), m.peak_bytes());
            assert_eq!(m.allocate(9).unwrap_err(), LimitRefusal::TooLarge);
            assert_eq!(m.allocate(3).unwrap_err(), LimitRefusal::Storage);
            assert_eq!(m.allocate(5).unwrap_err(), LimitRefusal::Requested);
            assert_eq!(
                (m.requested_bytes(), m.live_bytes(), m.peak_bytes()),
                before,
                "a refused request committed"
            );
            drop(held);
            assert_eq!(m.live_bytes(), 0);
        }

        /// The quantum bounds a unit in every turn, the allowance what one
        /// turn admits: a unit beyond the quantum is impossible
        /// ([`LimitRefusal::QuantumTooSmall`], which stops) whatever the
        /// turn grants; one within the quantum and beyond what the turn
        /// still allows waits ([`LimitRefusal::Turn`], the next turn), a
        /// turn granting nothing included; a grant beyond the quantum is
        /// held to it.
        #[test]
        #[expect(
            clippy::disallowed_methods,
            reason = "the policy's axioms are driven by direct admissions"
        )]
        fn the_quantum_bounds_a_unit_and_the_allowance_bounds_a_turn() {
            let mut m = Limits::turns();
            assert_eq!(
                m.traverse(TURN.values + 1, 0),
                Err(LimitRefusal::QuantumTooSmall)
            );
            assert_eq!(LimitRefusal::QuantumTooSmall.recovery(), Recovery::Stop);
            m.turn_with(WriteWork::new(0, 0));
            assert_eq!(m.traverse(1, 0), Err(LimitRefusal::Turn));
            assert_eq!(LimitRefusal::Turn.recovery(), Recovery::NextTurn);
            m.turn_with(ONE);
            m.traverse(1, 0).unwrap();
            assert_eq!(m.traverse(1, 0), Err(LimitRefusal::Turn));
            m.turn_with(WriteWork::new(u64::MAX, u64::MAX));
            assert_eq!(m.remaining(), TURN, "a grant beyond the quantum");
            m.exhaust();
            assert_eq!(m.remaining(), WriteWork::new(0, 0));
            assert_eq!(m.traverse(1, 0), Err(LimitRefusal::Turn));
            m.open();
            m.traverse(TURN.values + 1, 0).unwrap();
        }

        /// Refusal precedence is fixed: an exhausted lifetime allowance is
        /// named before the turn's, and before an impossible unit.
        #[test]
        #[expect(
            clippy::disallowed_methods,
            reason = "the policy's axioms are driven by direct admissions"
        )]
        fn lifetime_exhaustion_precedes_the_turn_and_the_quantum() {
            let mut m = Limits::new(1, u64::MAX, u64::MAX);
            m.turn_with(ONE);
            m.traverse(1, 0).unwrap();
            assert_eq!(m.traverse(1, 0), Err(LimitRefusal::Work));
            assert_eq!(m.traverse(TURN.values + 1, 0), Err(LimitRefusal::Work));
        }

        /// A requested-bytes ceiling is only ever lowered, and a share's
        /// live ceiling is at most its family's: a share asking for more
        /// refuses a request beyond the family's whole ceiling, and its own
        /// work ceiling refuses its own work.
        #[test]
        #[expect(
            clippy::disallowed_methods,
            reason = "the policy's axioms are driven by direct admissions"
        )]
        fn no_ceiling_is_raised_by_a_builder_or_a_share() {
            let mut lowered = Limits::unlimited()
                .requesting_at_most(4)
                .requesting_at_most(100);
            assert_eq!(lowered.allocate(5).unwrap_err(), LimitRefusal::Requested);
            let family = Limits::new(u64::MAX, u64::MAX, 8);
            let mut share = family.share_within(Ceilings {
                work: WriteWork::new(0, u64::MAX),
                ..Ceilings::UNLIMITED
            });
            assert_eq!(share.allocate(9).unwrap_err(), LimitRefusal::TooLarge);
            assert_eq!(share.traverse(1, 0), Err(LimitRefusal::Work));
            let held = share.allocate(8).unwrap();
            assert_eq!(family.live_bytes(), 8, "a share's storage is its family's");
            drop(held);
            assert_eq!(family.live_bytes(), 0);
        }

        /// Every refusal's recovery, the one classification: a spent turn, a
        /// contended group admission and an injected refusal resume next
        /// turn, live capacity after a release, every other refusal stops, a
        /// cancellation among them.
        #[test]
        fn every_refusal_has_one_recovery() {
            for (refusal, recovery) in [
                (LimitRefusal::Turn, Recovery::NextTurn),
                (LimitRefusal::Contended, Recovery::NextTurn),
                (LimitRefusal::Scheduled(3), Recovery::NextTurn),
                (LimitRefusal::Storage, Recovery::CapacityRelease),
                (LimitRefusal::QuantumTooSmall, Recovery::Stop),
                (LimitRefusal::Work, Recovery::Stop),
                (LimitRefusal::Requested, Recovery::Stop),
                (LimitRefusal::TooLarge, Recovery::Stop),
                (LimitRefusal::Deadline, Recovery::Stop),
                (LimitRefusal::Cancelled, Recovery::Stop),
                (LimitRefusal::Unrecorded, Recovery::Stop),
            ] {
                assert_eq!(refusal.recovery(), recovery, "{refusal:?}");
            }
        }

        /// Cleanup completes whatever the foreground's state: with the
        /// lifetime work allowance spent, and again past the deadline, a
        /// cleanup admission is admitted where a foreground one is refused,
        /// accounted apart ([`Limits::cleanup_used`]) and never taken from
        /// the foreground's remainder.
        #[test]
        #[expect(
            clippy::disallowed_methods,
            reason = "the policy's axioms are driven by direct admissions"
        )]
        fn cleanup_is_never_refused_for_the_foreground() {
            let mut m = Limits::new(1, u64::MAX, u64::MAX);
            m.traverse(1, 0).unwrap();
            assert_eq!(m.traverse(1, 0), Err(LimitRefusal::Work));
            assert_eq!(
                m.reclaim(1, 0),
                Ok(()),
                "cleanup was refused for the lifetime allowance"
            );
            m.expire_at_call(Some(0));
            assert_eq!(m.traverse(0, 0), Err(LimitRefusal::Deadline));
            assert_eq!(
                m.reclaim(1, 0),
                Ok(()),
                "cleanup was refused for the deadline"
            );
            assert_eq!(m.used(), WriteWork::new(3, 0));
            assert_eq!(m.cleanup_used(), WriteWork::new(2, 0));
            assert_eq!(
                m.remaining(),
                WriteWork::new(0, u64::MAX),
                "cleanup was taken from the foreground's remainder"
            );
        }

        /// Cleanup is scheduled as every unit is: a unit beyond the quantum
        /// is impossible, and cleanup spends the running turn's allowance,
        /// the one turn it shares with foreground work, so a spent turn
        /// refuses both for the next.
        #[test]
        #[expect(
            clippy::disallowed_methods,
            reason = "the policy's axioms are driven by direct admissions"
        )]
        fn cleanup_spends_the_turn_and_is_held_to_the_quantum() {
            let mut m = Limits::turns();
            assert_eq!(
                m.reclaim(TURN.values + 1, 0),
                Err(LimitRefusal::QuantumTooSmall)
            );
            m.turn_with(ONE);
            m.reclaim(1, 0).unwrap();
            assert_eq!(m.reclaim(1, 0), Err(LimitRefusal::Turn));
            assert_eq!(m.traverse(1, 0), Err(LimitRefusal::Turn));
            m.turn_with(ONE);
            m.traverse(1, 0).unwrap();
            assert_eq!(m.reclaim(1, 0), Err(LimitRefusal::Turn));
            assert_eq!(m.cleanup_used(), ONE);
            assert_eq!(m.used(), WriteWork::new(2, 0));
        }

        /// A unit admitted through the cleanup capability is the policy's
        /// cleanup: under a policy of no foreground work at all it is
        /// admitted, through the route, and charged to the cleanup account;
        /// a foreground unit beside it is refused.
        #[test]
        fn a_unit_under_the_cleanup_capability_is_charged_as_cleanup() {
            use crate::bounded::decode::construction::reclamation::Cleanup;
            use crate::bounded::{Caller, Unit};
            let unit = Unit::new(Caller, 1, 8);
            let mut m = Limits::new(0, 0, u64::MAX);
            assert!(
                unit.admit(&mut Cleanup::new(&mut m)).is_ok(),
                "cleanup was charged to the foreground"
            );
            assert_eq!(m.cleanup_used(), WriteWork::new(1, 8));
            assert!(unit.admit(&mut m).is_err());
            assert_eq!(m.used(), m.cleanup_used());
        }

        /// The history names the account each unit was charged to: a
        /// foreground unit is recorded as work, a unit through the cleanup
        /// capability as reclaim, refused or admitted, so a reader of the
        /// history alone tells which calls an expiry may refuse.
        #[test]
        #[expect(
            clippy::disallowed_methods,
            reason = "the policy's history is driven by direct admissions"
        )]
        fn the_history_names_each_units_account() {
            use crate::bounded::decode::construction::reclamation::Cleanup;
            use crate::bounded::{Caller, Capacity, Session, Unit};
            let session = Session::new(Capacity::DEFAULT);
            let mut m = Limits::recorded_unlimited(&session);
            m.traverse(1, 0).unwrap();
            Unit::new(Caller, 1, 8)
                .admit(&mut Cleanup::new(&mut m))
                .unwrap();
            m.expire_at_call(Some(0));
            Unit::new(Caller, 2, 0)
                .admit(&mut Cleanup::new(&mut m))
                .unwrap();
            assert_eq!(m.traverse(1, 0), Err(LimitRefusal::Deadline));
            assert_eq!(
                m.calls(),
                [
                    Call::Work {
                        values: 1,
                        bytes: 0
                    },
                    Call::Reclaim {
                        values: 1,
                        bytes: 8
                    },
                    Call::Reclaim {
                        values: 2,
                        bytes: 0
                    },
                    Call::Work {
                        values: 1,
                        bytes: 0
                    },
                ],
                "a cleanup unit was recorded as foreground work"
            );
            assert!(
                Call::Work {
                    values: 1,
                    bytes: 0
                }
                .is_foreground()
            );
            assert!(Call::Allocate(1).is_foreground());
            assert!(
                !Call::Reclaim {
                    values: 1,
                    bytes: 0
                }
                .is_foreground()
            );
            drop(m);
            session
                .finish()
                .unwrap_or_else(|incomplete| panic!("the session is incomplete: {incomplete:?}"));
        }
    }
}
