//! Shared governance: a group of operations under aggregate ceilings
//! ([`Governor`]), each operation admitting through a budget of its own
//! ([`OperationBudget`]) under its own ceilings, quantum and turns.
//!
//! One accounting core decides every admission: the operation's
//! [`Authority`] plans it (its ceilings, its quantum, its turn and the fixed
//! refusal precedence), the group commits it against the group's ceilings,
//! and only then does the operation commit its plan. So a refusal at either
//! level commits nothing at either level, and no second implementation of
//! the core exists. The group's checks are the core's own
//! ([`Ceilings::foreground_after`], [`Ceilings::requested_after`]), and
//! each level's live storage is the one implementation of it
//! ([`Storage`]): both levels reserve, and both keep only once both have
//! granted.
//!
//! The group's foreground admissions are nonblocking: one admission checks
//! and commits the group's totals at a time, holding the group's admitting
//! flag, and an admission that finds it held is refused
//! [`LimitRefusal::Contended`], nothing checked or admitted, to be retried
//! next turn ([`super::Recovery::NextTurn`]). A refusal made under the flag
//! is therefore decided against committed totals alone: classification is
//! deterministic. Cleanup ([`Releasing::reclaim`]) never takes the flag: it
//! is never refused for either level's lifetime ceilings, and the group
//! counts it apart, never refusing, each quantity one wait-free addition
//! ([`Count`]). A terminal policy ([`super::TerminalAllocator`]) admits every
//! unit as cleanup of its permit's operation and group, counted the same
//! way, so a scope drained after its scheduler has gone is still counted.
//!
//! Before the core is consulted, a foreground admission is held to the
//! operation's standing: a cancellation of the operation or of its whole
//! group ([`Cancellation`]), sticky, refuses it [`LimitRefusal::Cancelled`];
//! then, under `std`, the operation's monotonic deadline
//! ([`OperationBudget::deadline`]) refuses it [`LimitRefusal::Deadline`].
//! Both stop the operation; neither refuses its cleanup, which returns what
//! the operation holds.
//!
//! A permit names its operation's counters, which name the group's: its
//! drop releases its bytes from both live totals, on any thread. It is two
//! words, within [`super::PERMIT_BYTES`].
//!
//! The family records nothing: its credit origin is `()`, every identity it
//! mints is unobserved, and it performs only for ordinary owners.
extern crate alloc;
use alloc::sync::Arc;

use super::policy::{Authority, Ceilings, Count, LimitRefusal, Planned, Storage, TURN};
use super::{
    Acquisition, Allocator, Budget, Effect, Hold, Identity, Owner, Performer, RecordStage,
    Releasing, WriteWork,
};
use crate::sync::{AtomicBool, AtomicU64, Ordering};

/// The state every operation of a group shares: its ceilings, its committed
/// foreground totals, its cleanup totals, and its live storage.
struct Group {
    ceilings: Ceilings,
    /// Held by the one admission checking and committing the totals below.
    admitting: AtomicBool,
    /// Foreground work committed, values and bytes: written only under
    /// `admitting`.
    values: AtomicU64,
    bytes: AtomicU64,
    /// Cumulative requested bytes granted: written only under `admitting`.
    requested: AtomicU64,
    /// Cleanup work admitted, values and bytes, every operation's and every
    /// terminal policy's: never gated and never refused ([`Count`]).
    cleanup_values: Count,
    cleanup_bytes: Count,
    /// Live requested bytes of every operation's permits, reserved only
    /// under `admitting`, released by any permit's drop.
    storage: Storage,
    /// Every operation of the group cancelled: set once, never cleared.
    cancelled: AtomicBool,
}

/// `work` counted in a pair of [`Count`]s, its values and its bytes, never
/// refused: a sum beyond `u64` saturates its total.
fn count(values: &Count, bytes: &Count, work: WriteWork) {
    values.add(work.values);
    bytes.add(work.bytes);
}

/// The admitting flag, held: released on every exit of the admission.
struct Admitting<'g>(&'g AtomicBool);

impl Drop for Admitting<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

impl Group {
    /// The admitting flag, or [`LimitRefusal::Contended`] when another
    /// admission holds it. Never waits.
    fn admitting(&self) -> Result<Admitting<'_>, LimitRefusal> {
        self.admitting
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .map(|_| Admitting(&self.admitting))
            .map_err(|_| LimitRefusal::Contended)
    }

    /// The foreground work committed.
    fn foreground(&self) -> WriteWork {
        WriteWork::new(
            self.values.load(Ordering::Acquire),
            self.bytes.load(Ordering::Acquire),
        )
    }

    /// The cleanup work counted.
    fn cleanup(&self) -> WriteWork {
        WriteWork::new(self.cleanup_values.get(), self.cleanup_bytes.get())
    }

    /// Commit `work` as foreground against the group's work ceiling, or
    /// refuse it with nothing committed.
    fn work(&self, work: WriteWork) -> Result<(), LimitRefusal> {
        let _admitting = self.admitting()?;
        let used = self.ceilings.foreground_after(self.foreground(), work)?;
        self.values.store(used.values, Ordering::Release);
        self.bytes.store(used.bytes, Ordering::Release);
        Ok(())
    }

    /// Count `work` as cleanup: no ceiling, no flag, never refused
    /// ([`Count`]). A refused cleanup unit could not release what it holds,
    /// so no total's arithmetic refuses one.
    fn reclaim(&self, work: WriteWork) {
        count(&self.cleanup_values, &self.cleanup_bytes, work);
    }
}

/// The counters one operation's permits share: its live storage, its
/// cancellation, the cleanup its terminal policies admitted, and the group
/// it belongs to.
struct Operation {
    group: Arc<Group>,
    /// Live requested bytes of this operation's permits ([`Storage`]).
    storage: Storage,
    /// This operation cancelled: set once, never cleared.
    cancelled: AtomicBool,
    /// Cleanup admitted by terminal policies minted from this operation's
    /// permits, values and bytes ([`Count`]): the operation's own budget
    /// counts the rest of its cleanup.
    terminal_values: Count,
    terminal_bytes: Count,
}

impl Operation {
    /// Whether this operation, or its whole group, was cancelled.
    fn cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire) || self.group.cancelled.load(Ordering::Acquire)
    }

    /// The cleanup its terminal policies admitted.
    fn terminal(&self) -> WriteWork {
        WriteWork::new(self.terminal_values.get(), self.terminal_bytes.get())
    }

    /// Count `work`, admitted by a terminal policy, as cleanup of this
    /// operation and of its group ([`Count`]): never refused, four
    /// wait-free additions and at most four flag stores, allocation-free
    /// and non-unwinding.
    fn count_terminal(&self, work: WriteWork) {
        count(&self.terminal_values, &self.terminal_bytes, work);
        self.group.reclaim(work);
    }
}

/// What a [`Cancellation`] cancels.
#[derive(Clone)]
enum Scope {
    Group(Arc<Group>),
    Operation(Arc<Operation>),
}

/// The authority to cancel one operation ([`OperationBudget::cancellation`])
/// or every operation of a group ([`Governor::cancellation`]), from any
/// thread. Sticky: once cancelled, every later foreground admission of what
/// it cancels is refused [`LimitRefusal::Cancelled`], which stops; cleanup is
/// never refused for it. One atomic store, allocation-free and
/// non-unwinding. A handle: clones cancel the same scope.
#[derive(Clone)]
pub struct Cancellation {
    scope: Scope,
}

impl Cancellation {
    /// Cancel, for good.
    pub fn cancel(&self) {
        self.flag().store(true, Ordering::Release);
    }

    /// Whether this scope was cancelled.
    pub fn is_cancelled(&self) -> bool {
        self.flag().load(Ordering::Acquire)
    }

    fn flag(&self) -> &AtomicBool {
        match &self.scope {
            Scope::Group(group) => &group.cancelled,
            Scope::Operation(operation) => &operation.cancelled,
        }
    }
}

/// A group of operations under aggregate ceilings: the lifetime work of
/// every operation together, their cumulative requested bytes, and their
/// live storage. A handle: clones govern the same group.
#[derive(Clone)]
pub struct Governor {
    group: Arc<Group>,
}

impl Governor {
    /// A group under `ceilings`, nothing admitted. The one allocation of
    /// the group's shared state belongs to its setup.
    pub fn new(ceilings: Ceilings) -> Self {
        Self {
            group: Arc::new(Group {
                ceilings,
                admitting: AtomicBool::new(false),
                values: AtomicU64::new(0),
                bytes: AtomicU64::new(0),
                requested: AtomicU64::new(0),
                cleanup_values: Count::default(),
                cleanup_bytes: Count::default(),
                storage: Storage::default(),
                cancelled: AtomicBool::new(false),
            }),
        }
    }

    /// The authority to cancel every operation of the group, those made
    /// after the cancellation included.
    pub fn cancellation(&self) -> Cancellation {
        Cancellation {
            scope: Scope::Group(self.group.clone()),
        }
    }

    /// One operation of the group, under `ceilings` of its own, its live
    /// ceiling at most the group's, its first turn a whole quantum
    /// ([`TURN`]). The one allocation of its counters belongs to its setup.
    pub fn operation(&self, ceilings: Ceilings) -> OperationBudget {
        let ceilings = Ceilings {
            live: ceilings.live.min(self.group.ceilings.live),
            ..ceilings
        };
        let mut authority = Authority::new(ceilings, TURN);
        authority.begin_turn(TURN);
        OperationBudget {
            authority,
            operation: Arc::new(Operation {
                group: self.group.clone(),
                storage: Storage::default(),
                cancelled: AtomicBool::new(false),
                terminal_values: Count::default(),
                terminal_bytes: Count::default(),
            }),
            #[cfg(feature = "std")]
            deadline: None,
            terminal: false,
        }
    }

    /// The group's ceilings.
    pub fn ceilings(&self) -> Ceilings {
        self.group.ceilings
    }

    /// Every unit the group's operations admitted, foreground and cleanup,
    /// as [`OperationBudget::used`] and [`super::Limits::used`] count. Each
    /// total is bounded by the group's committed work, so the sum
    /// saturates only past `u64`, which no bounded operation reaches; the
    /// policy ships, so it never panics.
    pub fn used(&self) -> WriteWork {
        let (foreground, cleanup) = (self.group.foreground(), self.group.cleanup());
        WriteWork::new(
            foreground.values.saturating_add(cleanup.values),
            foreground.bytes.saturating_add(cleanup.bytes),
        )
    }

    /// The part of [`Self::used`] admitted as cleanup, which no ceiling
    /// counts.
    pub fn cleanup_used(&self) -> WriteWork {
        self.group.cleanup()
    }

    /// The foreground work the group still admits.
    pub fn remaining(&self) -> WriteWork {
        let used = self.group.foreground();
        let ceiling = self.group.ceilings.work;
        WriteWork::new(
            ceiling.values.saturating_sub(used.values),
            ceiling.bytes.saturating_sub(used.bytes),
        )
    }

    /// The cumulative bytes of the group's granted requests.
    pub fn requested_bytes(&self) -> u64 {
        self.group.requested.load(Ordering::Acquire)
    }

    /// The bytes every live permit of the group holds.
    pub fn live_bytes(&self) -> u64 {
        self.group.storage.live()
    }

    /// The most bytes the group's permits held at once.
    pub fn peak_bytes(&self) -> u64 {
        self.group.storage.peak()
    }
}

/// One operation's budget within its group ([`Governor::operation`]): its
/// own ceilings, quantum and turns, decided by the accounting core
/// ([`Authority`]), each admission then committed against the group's
/// ceilings. Used by one operation at a time; its permits may move to and be
/// released on other threads.
pub struct OperationBudget {
    authority: Authority,
    operation: Arc<Operation>,
    /// The instant from which every foreground admission is refused
    /// ([`Self::deadline`]).
    #[cfg(feature = "std")]
    deadline: Option<std::time::Instant>,
    /// A terminal policy ([`super::TerminalAllocator`]): every admission
    /// admitted and counted as cleanup of the permit's operation and group
    /// ([`Operation::count_terminal`]), every request refused.
    terminal: bool,
}

/// Storage admission of a governed operation, released from its operation's
/// and its group's live totals when it drops. Two words.
pub struct GovernedPermit {
    operation: Arc<Operation>,
    bytes: u64,
}

const _: () = assert!(
    core::mem::size_of::<GovernedPermit>() <= super::PERMIT_BYTES,
    "a governed permit takes more than PERMIT_BYTES bytes"
);

impl GovernedPermit {
    /// The requested bytes this permit holds.
    pub fn bytes(&self) -> u64 {
        self.bytes
    }
}

impl Drop for GovernedPermit {
    /// One release from each level's storage ([`Storage::release`]),
    /// allocation-free. Each was raised by these bytes, kept, before the
    /// permit existed ([`OperationBudget::allocate`]), and a permit's bytes
    /// never change, so neither release panics.
    fn drop(&mut self) {
        self.operation.storage.release(self.bytes);
        self.operation.group.storage.release(self.bytes);
    }
}

impl OperationBudget {
    /// A new scheduler turn granting one whole quantum.
    pub fn turn(&mut self) {
        self.turn_with(TURN);
    }

    /// A new scheduler turn granting `allowance`, at most the quantum in
    /// each quantity: a unit within the quantum but beyond the allowance is
    /// refused [`LimitRefusal::Turn`] and waits for a later turn.
    pub fn turn_with(&mut self, allowance: WriteWork) {
        self.authority.begin_turn(allowance);
    }

    /// End the current turn: nothing more is admitted until the next.
    pub fn exhaust(&mut self) {
        self.authority.end_turn();
    }

    /// No turn quantum: work bounded by the operation's and the group's
    /// ceilings alone, for an operation run in one call that no scheduler
    /// steps ([`crate::bounded::decode::decode_typed`],
    /// [`crate::bounded::encode`]). The next [`Self::turn`] schedules it
    /// again.
    pub fn unscheduled(&mut self) {
        self.authority.without_turns();
    }

    /// Refuse every foreground admission [`LimitRefusal::Deadline`] from the
    /// instant `at` of the monotonic clock ([`std::time::Instant`]) on;
    /// `None` lifts it. Read once per foreground admission; cleanup is never
    /// refused for it.
    #[cfg(feature = "std")]
    pub fn deadline(&mut self, at: Option<std::time::Instant>) {
        self.deadline = at;
    }

    /// The authority to cancel this operation alone, from any thread.
    pub fn cancellation(&self) -> Cancellation {
        Cancellation {
            scope: Scope::Operation(self.operation.clone()),
        }
    }

    /// Whether a foreground admission may be considered at all: refused
    /// [`LimitRefusal::Cancelled`] once this operation or its group is
    /// cancelled, then [`LimitRefusal::Deadline`] once its deadline has
    /// come. Commits nothing; the core and the group decide the rest.
    fn standing(&self) -> Result<(), LimitRefusal> {
        if self.operation.cancelled() {
            return Err(LimitRefusal::Cancelled);
        }
        #[cfg(feature = "std")]
        if self
            .deadline
            .is_some_and(|at| std::time::Instant::now() >= at)
        {
            return Err(LimitRefusal::Deadline);
        }
        Ok(())
    }

    /// This operation's ceilings, its live ceiling at most its group's.
    pub fn ceilings(&self) -> Ceilings {
        self.authority.ceilings()
    }

    /// The group this operation belongs to.
    pub fn governor(&self) -> Governor {
        Governor {
            group: self.operation.group.clone(),
        }
    }

    /// Every unit this operation admitted, foreground and cleanup, the
    /// cleanup of terminal policies minted from its permits included. Each
    /// total is bounded by the operation's work, so the sum saturates only
    /// past `u64`, which no bounded operation reaches.
    pub fn used(&self) -> WriteWork {
        Self::with_terminal(self.authority.used(), self.operation.terminal())
    }

    /// The part of [`Self::used`] admitted as cleanup, by this budget and
    /// by terminal policies minted from its permits.
    pub fn cleanup_used(&self) -> WriteWork {
        Self::with_terminal(self.authority.cleanup(), self.operation.terminal())
    }

    fn with_terminal(own: WriteWork, terminal: WriteWork) -> WriteWork {
        WriteWork::new(
            own.values.saturating_add(terminal.values),
            own.bytes.saturating_add(terminal.bytes),
        )
    }

    /// The foreground work this operation still admits on its own
    /// ceilings, within its turn; the group's remainder is
    /// [`Governor::remaining`].
    pub fn remaining(&self) -> WriteWork {
        self.authority.remaining()
    }

    /// The cumulative bytes of this operation's granted requests.
    pub fn requested_bytes(&self) -> u64 {
        self.authority.requested()
    }

    /// The bytes this operation's live permits hold.
    pub fn live_bytes(&self) -> u64 {
        self.operation.storage.live()
    }

    /// The most bytes this operation's permits held at once.
    pub fn peak_bytes(&self) -> u64 {
        self.operation.storage.peak()
    }

    /// `planned`, the operation's own plan, committed once the group has
    /// committed its part (`group`): the group first, so a group refusal
    /// leaves the operation unchanged.
    fn admit(
        &mut self,
        planned: Planned,
        group: impl FnOnce(&Group) -> Result<(), LimitRefusal>,
    ) -> Result<(), LimitRefusal> {
        group(&self.operation.group)?;
        self.authority.commit(planned);
        Ok(())
    }
}

impl Budget for OperationBudget {
    type Refusal = LimitRefusal;

    /// Held to the operation's standing ([`Self::standing`]), planned on its
    /// core, committed on the group, then on the operation.
    fn traverse(&mut self, values: u64, bytes: u64) -> Result<(), LimitRefusal> {
        let work = WriteWork::new(values, bytes);
        if self.terminal {
            self.operation.count_terminal(work);
            return Ok(());
        }
        self.standing()?;
        let planned = self.authority.plan_work(work)?;
        self.admit(planned, |group| group.work(work))
    }

    type Origin = ();

    fn origin(&self) {}

    fn admitted(&mut self, _: WriteWork) {}

    fn identify(&mut self) -> Result<Identity, LimitRefusal> {
        Ok(Identity::UNOBSERVED)
    }

    fn held(&mut self, _: WriteWork, _: Hold) {}

    fn effect(&mut self, _: Effect) {}

    fn owner(&mut self) -> Result<Owner, LimitRefusal> {
        Ok(Owner::unobserved())
    }

    fn acquisition(&mut self, owner: &Owner) -> Result<Acquisition<()>, LimitRefusal> {
        self.validate_owner(owner)?;
        Acquisition::unobserved(owner).ok_or(LimitRefusal::Unrecorded)
    }

    /// An ordinary family performs only for an ordinary owner: a recorded
    /// one is refused [`LimitRefusal::Unrecorded`] and its session made, stickily,
    /// no evidence, as [`super::Limits`] refuses the same pairing.
    fn validate_owner(&mut self, owner: &Owner) -> Result<(), LimitRefusal> {
        if owner.recorded_in_any() {
            owner.invalidate();
            return Err(LimitRefusal::Unrecorded);
        }
        Ok(())
    }

    fn performer(&self) -> Performer {
        Performer::None
    }
}

impl Releasing for OperationBudget {
    type Permit = GovernedPermit;

    /// Planned on the operation's core as cleanup (its turn and quantum,
    /// no ceiling), counted on the group without its flag, then committed:
    /// never refused for either level's lifetime ceilings, a cancellation
    /// or the deadline, nor contended.
    fn reclaim(&mut self, values: u64, bytes: u64) -> Result<(), LimitRefusal> {
        let work = WriteWork::new(values, bytes);
        if self.terminal {
            self.operation.count_terminal(work);
            return Ok(());
        }
        let planned = self.authority.plan_reclaim(work)?;
        self.admit(planned, |group| {
            group.reclaim(work);
            Ok(())
        })
    }

    fn permit_identity(_: &GovernedPermit) -> Identity {
        Identity::UNOBSERVED
    }

    fn custody(_: &GovernedPermit, _: Identity, _: RecordStage) {}
}

impl Allocator for OperationBudget {
    /// The operation's standing ([`OperationBudget::standing`]), then its
    /// request checked by its core (its whole live ceiling, then its
    /// requested ceiling), then, holding the group's flag, the group's
    /// ([`Ceilings::requested_after`]), then the operation's live capacity
    /// and the group's ([`Storage::reserve`]): every check before any
    /// commitment, and each pending reservation returned by any later
    /// refusal, so a refusal commits nothing at either level. Both
    /// reservations are kept, each level's peak raised, only once both
    /// levels have granted.
    fn allocate(&mut self, bytes: u64) -> Result<GovernedPermit, LimitRefusal> {
        if self.terminal {
            return Err(LimitRefusal::Storage);
        }
        self.standing()?;
        let requested = self.authority.request(bytes)?;
        let operation = &self.operation;
        let group = &operation.group;
        let _admitting = group.admitting()?;
        let group_requested = group
            .ceilings
            .requested_after(group.requested.load(Ordering::Acquire), bytes)?;
        let operation_reserved = operation
            .storage
            .reserve(self.authority.ceilings().live, bytes)?;
        let group_reserved = group.storage.reserve(group.ceilings.live, bytes)?;
        operation_reserved.keep();
        group_reserved.keep();
        group.requested.store(group_requested, Ordering::Release);
        self.authority.granted(requested);
        Ok(GovernedPermit {
            operation: operation.clone(),
            bytes,
        })
    }
}

// SAFETY: terminal: constructing this policy only clones an existing Arc and
// builds an authority of constants, allocating nothing and never unwinding,
// and its fields' drops are allocation-free and non-unwinding. traverse: a
// terminal policy's `traverse` and `reclaim` always succeed, counting each
// unit by four wait-free `fetch_add`s and at most four flag stores
// (`Operation::count_terminal`, `Count`), a fixed number of instructions
// whatever other threads do, allocation-free and non-unwinding. allocate: a
// terminal policy refuses every request, allocating nothing. borrow: the
// policy holds its own clone of the permit's counters, never a reference to
// `permit`.
unsafe impl super::TerminalAllocator for OperationBudget {
    fn terminal(permit: &GovernedPermit) -> Self {
        Self {
            authority: Authority::new(Ceilings::UNLIMITED, TURN),
            operation: permit.operation.clone(),
            #[cfg(feature = "std")]
            deadline: None,
            terminal: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bounded::decode::construction::reclamation::Cleanup;
    use crate::bounded::{Caller, Recovery, TerminalAllocator, Unit};

    const ONE: WriteWork = WriteWork::new(1, 0);

    fn work(values: u64) -> Ceilings {
        Ceilings {
            work: WriteWork::new(values, u64::MAX),
            ..Ceilings::UNLIMITED
        }
    }

    /// The group's work ceiling is aggregate: two operations, each under an
    /// unlimited ceiling of its own, together admit exactly the group's
    /// five values, every later unit refused [`LimitRefusal::Work`] by the
    /// group, which stops, and nothing committed on the refused operation.
    #[test]
    #[expect(
        clippy::disallowed_methods,
        reason = "the governor's axioms are driven by direct admissions"
    )]
    fn the_group_work_ceiling_is_aggregate() {
        let governor = Governor::new(work(5));
        let mut first = governor.operation(Ceilings::UNLIMITED);
        let mut second = governor.operation(Ceilings::UNLIMITED);
        first.traverse(3, 0).unwrap();
        second.traverse(2, 0).unwrap();
        second.turn();
        assert_eq!(
            second.traverse(1, 0),
            Err(LimitRefusal::Work),
            "the group admitted past its ceiling"
        );
        assert_eq!(
            second.used(),
            WriteWork::new(2, 0),
            "a refused unit committed"
        );
        assert_eq!(governor.used(), WriteWork::new(5, 0));
        assert_eq!(governor.remaining(), WriteWork::new(0, u64::MAX));
        assert_eq!(LimitRefusal::Work.recovery(), Recovery::Stop);
    }

    /// The operation's own core decides first: its ceiling, its quantum and
    /// its turn refuse with nothing committed on the group.
    #[test]
    #[expect(
        clippy::disallowed_methods,
        reason = "the governor's axioms are driven by direct admissions"
    )]
    fn the_operation_core_refuses_before_the_group_commits() {
        let governor = Governor::new(Ceilings::UNLIMITED);
        let mut operation = governor.operation(work(1));
        assert_eq!(
            operation.traverse(TURN.values + 1, 0),
            Err(LimitRefusal::Work)
        );
        operation.traverse(1, 0).unwrap();
        assert_eq!(operation.traverse(1, 0), Err(LimitRefusal::Work));
        let mut turned = governor.operation(Ceilings::UNLIMITED);
        turned.turn_with(ONE);
        turned.traverse(1, 0).unwrap();
        assert_eq!(turned.traverse(1, 0), Err(LimitRefusal::Turn));
        assert_eq!(
            turned.traverse(TURN.values + 1, 0),
            Err(LimitRefusal::QuantumTooSmall)
        );
        assert_eq!(
            governor.used(),
            WriteWork::new(2, 0),
            "an operation's refusal committed on the group"
        );
    }

    /// An admission finding the group's flag held is refused
    /// [`LimitRefusal::Contended`], which resumes next turn, with nothing
    /// checked or committed at either level; once released, the same unit
    /// is admitted.
    #[test]
    #[expect(
        clippy::disallowed_methods,
        reason = "the governor's axioms are driven by direct admissions"
    )]
    fn a_contended_group_admission_commits_nothing() {
        let governor = Governor::new(Ceilings::UNLIMITED);
        let mut operation = governor.operation(Ceilings::UNLIMITED);
        let held = governor.group.admitting().expect("the flag is free");
        assert_eq!(operation.traverse(1, 0), Err(LimitRefusal::Contended));
        assert_eq!(
            operation
                .allocate(8)
                .map(|permit| permit.bytes())
                .unwrap_err(),
            LimitRefusal::Contended
        );
        assert_eq!(LimitRefusal::Contended.recovery(), Recovery::NextTurn);
        assert_eq!(
            operation.used(),
            WriteWork::default(),
            "a contended unit committed"
        );
        assert_eq!(governor.used(), WriteWork::default());
        assert_eq!((operation.live_bytes(), governor.live_bytes()), (0, 0));
        drop(held);
        operation.traverse(1, 0).unwrap();
        assert_eq!(governor.used(), ONE);
    }

    /// Live storage is held at both levels: each operation's ceiling and the
    /// group's bound it, a request beyond the group's whole ceiling is
    /// impossible, a group refusal returns the operation's reservation, and
    /// each permit's drop releases its bytes from both totals.
    #[test]
    fn live_storage_is_held_at_both_levels() {
        let governor = Governor::new(Ceilings {
            live: 8,
            ..Ceilings::UNLIMITED
        });
        let mut first = governor.operation(Ceilings {
            live: 6,
            ..Ceilings::UNLIMITED
        });
        let mut second = governor.operation(Ceilings::UNLIMITED);
        assert_eq!(
            second.ceilings().live,
            8,
            "a live ceiling above the group's"
        );
        assert_eq!(
            first.allocate(7).map(|permit| permit.bytes()).unwrap_err(),
            LimitRefusal::TooLarge
        );
        let held = first.allocate(6).unwrap();
        assert_eq!(
            second.allocate(3).map(|permit| permit.bytes()).unwrap_err(),
            LimitRefusal::Storage
        );
        assert_eq!(
            second.live_bytes(),
            0,
            "a group refusal kept the operation's reservation"
        );
        assert_eq!(
            (second.peak_bytes(), governor.peak_bytes()),
            (0, 6),
            "a group refusal raised a peak"
        );
        let other = second.allocate(2).unwrap();
        assert_eq!((governor.live_bytes(), governor.peak_bytes()), (8, 8));
        assert_eq!((first.live_bytes(), second.live_bytes()), (6, 2));
        drop(held);
        assert_eq!((governor.live_bytes(), first.live_bytes()), (2, 0));
        drop(other);
        assert_eq!((governor.live_bytes(), second.live_bytes()), (0, 0));
        assert_eq!(governor.requested_bytes(), 8);
    }

    /// The group's requested-bytes ceiling is aggregate, refused
    /// [`LimitRefusal::Requested`] with nothing reserved at either level.
    #[test]
    fn the_group_requested_ceiling_is_aggregate() {
        let governor = Governor::new(Ceilings {
            requested: 10,
            ..Ceilings::UNLIMITED
        });
        let mut first = governor.operation(Ceilings::UNLIMITED);
        let mut second = governor.operation(Ceilings::UNLIMITED);
        drop(first.allocate(6).unwrap());
        assert_eq!(
            second.allocate(5).map(|permit| permit.bytes()).unwrap_err(),
            LimitRefusal::Requested
        );
        assert_eq!((second.requested_bytes(), second.live_bytes()), (0, 0));
        drop(second.allocate(4).unwrap());
        assert_eq!(governor.requested_bytes(), 10);
    }

    /// Cleanup completes whatever either level's foreground state: with the
    /// group's work spent, a unit through the cleanup capability is
    /// admitted, counted on the group's cleanup account, never on its
    /// foreground's; it is still held to the operation's turn.
    #[test]
    #[expect(
        clippy::disallowed_methods,
        reason = "the governor's axioms are driven by direct admissions"
    )]
    fn cleanup_is_never_refused_for_either_ceiling() {
        let governor = Governor::new(work(1));
        let mut operation = governor.operation(work(1));
        operation.traverse(1, 0).unwrap();
        assert_eq!(operation.traverse(1, 0), Err(LimitRefusal::Work));
        let unit = Unit::new(Caller, 1, 8);
        assert!(
            unit.admit(&mut Cleanup::new(&mut operation)).is_ok(),
            "cleanup was refused for a lifetime ceiling"
        );
        assert_eq!(operation.cleanup_used(), WriteWork::new(1, 8));
        assert_eq!(governor.cleanup_used(), WriteWork::new(1, 8));
        assert_eq!(
            governor.remaining(),
            WriteWork::new(0, u64::MAX),
            "cleanup was charged to the group's foreground"
        );
        assert_eq!(governor.used(), WriteWork::new(2, 8));
        operation.exhaust();
        assert_eq!(operation.reclaim(1, 0), Err(LimitRefusal::Turn));
    }

    /// A cleanup total never refuses: once a sum passes `u64` the total
    /// reads `u64::MAX` and every later unit is still admitted, at the
    /// group's level (two operations whose cleanup together overflows) and
    /// at a terminal policy's (its operation's terminal count). A refused
    /// cleanup unit could not release what it holds.
    #[test]
    #[expect(
        clippy::disallowed_methods,
        reason = "the governor's axioms are driven by direct admissions"
    )]
    fn a_cleanup_total_saturates_and_never_refuses() {
        let governor = Governor::new(Ceilings::UNLIMITED);
        let mut first = governor.operation(Ceilings::UNLIMITED);
        let mut second = governor.operation(Ceilings::UNLIMITED);
        first.unscheduled();
        second.unscheduled();
        assert_eq!(first.reclaim(u64::MAX, 0), Ok(()));
        assert_eq!(
            second.reclaim(1, 0),
            Ok(()),
            "a cleanup unit was refused for the group's total"
        );
        assert_eq!(second.reclaim(1, 0), Ok(()));
        assert_eq!(governor.cleanup_used(), WriteWork::new(u64::MAX, 0));
        assert_eq!(second.cleanup_used(), WriteWork::new(2, 0));
        let permit = second.allocate(1).unwrap();
        let mut terminal = OperationBudget::terminal(&permit);
        assert_eq!(terminal.reclaim(u64::MAX, 0), Ok(()));
        assert_eq!(terminal.reclaim(1, 0), Ok(()));
        assert_eq!(
            second.cleanup_used(),
            WriteWork::new(u64::MAX, 0),
            "an overflowed terminal count read below what was counted"
        );
        assert_eq!(governor.cleanup_used(), WriteWork::new(u64::MAX, 0));
        drop((terminal, permit));
        assert_eq!(governor.live_bytes(), 0);
    }

    /// A terminal policy minted from a permit admits every unit, its group's
    /// work spent and its operation cancelled, counting each as cleanup of
    /// the permit's operation and group, never as foreground; it refuses
    /// every request, and its permit releases into the same totals.
    #[test]
    #[expect(
        clippy::disallowed_methods,
        reason = "the governor's axioms are driven by direct admissions"
    )]
    fn a_terminal_policy_counts_its_cleanup_and_allocates_nothing() {
        let governor = Governor::new(work(0));
        let mut operation = governor.operation(Ceilings::UNLIMITED);
        let permit = operation.allocate(4).unwrap();
        operation.cancellation().cancel();
        let mut terminal = OperationBudget::terminal(&permit);
        assert_eq!(terminal.traverse(1, 2), Ok(()));
        assert_eq!(terminal.reclaim(3, 4), Ok(()));
        assert_eq!(
            terminal
                .allocate(1)
                .map(|permit| permit.bytes())
                .unwrap_err(),
            LimitRefusal::Storage
        );
        let cleanup = WriteWork::new(4, 6);
        assert_eq!(
            governor.cleanup_used(),
            cleanup,
            "terminal cleanup went uncounted on the group"
        );
        assert_eq!(
            operation.cleanup_used(),
            cleanup,
            "terminal cleanup went uncounted on the operation"
        );
        assert_eq!((governor.used(), operation.used()), (cleanup, cleanup));
        assert_eq!(
            governor.remaining(),
            WriteWork::new(0, u64::MAX),
            "terminal cleanup was charged to the group's foreground"
        );
        drop((terminal, permit));
        assert_eq!((governor.live_bytes(), operation.live_bytes()), (0, 0));
    }

    /// The whole chain under a governed operation: a typed decode admitted
    /// through its operation's budget, its scope drained terminally when the
    /// value drops, every byte released at both levels, the work the group
    /// counted equal to the operation's, its cleanup included.
    #[test]
    fn a_typed_decode_runs_under_a_governed_operation() {
        use crate::bounded::decode::decode_typed;
        use alloc::string::String;
        let governor = Governor::new(Ceilings::UNLIMITED);
        let mut operation = governor.operation(Ceilings::UNLIMITED);
        // A one-call decode is stepped by no scheduler.
        operation.unscheduled();
        let value = decode_typed::<String, _>(&[0x63, b'a', b'b', b'c'], &mut operation)
            .expect("an unlimited governed decode");
        assert_eq!(value.value(), "abc");
        assert_ne!(governor.live_bytes(), 0);
        drop(value);
        assert_eq!((governor.live_bytes(), operation.live_bytes()), (0, 0));
        assert_eq!(governor.used(), operation.used());
        assert_eq!(governor.cleanup_used(), operation.cleanup_used());
    }

    /// A cancellation is sticky and spares cleanup: once an operation is
    /// cancelled, its foreground admissions and requests are refused
    /// [`LimitRefusal::Cancelled`], which stops, a new turn included, with
    /// nothing committed, while a unit through the cleanup capability is
    /// admitted; another operation of the group is untouched. The group's
    /// cancellation refuses every operation of it, one made after it
    /// included.
    #[test]
    #[expect(
        clippy::disallowed_methods,
        reason = "the governor's axioms are driven by direct admissions"
    )]
    fn a_cancellation_is_sticky_and_spares_cleanup() {
        let governor = Governor::new(Ceilings::UNLIMITED);
        let mut cancelled = governor.operation(Ceilings::UNLIMITED);
        let mut other = governor.operation(Ceilings::UNLIMITED);
        let cancellation = cancelled.cancellation();
        cancellation.cancel();
        assert!(cancellation.is_cancelled());
        assert_eq!(cancelled.traverse(1, 0), Err(LimitRefusal::Cancelled));
        assert_eq!(
            cancelled
                .allocate(8)
                .map(|permit| permit.bytes())
                .unwrap_err(),
            LimitRefusal::Cancelled
        );
        cancelled.turn();
        assert_eq!(
            cancelled.traverse(1, 0),
            Err(LimitRefusal::Cancelled),
            "a cancellation was lifted by a turn"
        );
        assert_eq!(LimitRefusal::Cancelled.recovery(), Recovery::Stop);
        assert!(
            Unit::new(Caller, 1, 8)
                .admit(&mut Cleanup::new(&mut cancelled))
                .is_ok(),
            "cleanup was refused for a cancellation"
        );
        assert_eq!(
            cancelled.used(),
            cancelled.cleanup_used(),
            "a cancelled unit committed"
        );
        other.traverse(1, 0).unwrap();
        governor.cancellation().cancel();
        assert_eq!(
            other.traverse(1, 0),
            Err(LimitRefusal::Cancelled),
            "a group cancellation was not observed"
        );
        let mut later = governor.operation(Ceilings::UNLIMITED);
        assert_eq!(later.traverse(1, 0), Err(LimitRefusal::Cancelled));
        assert_eq!(governor.used(), WriteWork::new(2, 8));
        assert_eq!(cancelled.live_bytes(), 0);
    }

    /// The deadline is an instant of the monotonic clock: before it a
    /// foreground unit is admitted; from it on every foreground admission
    /// and request is refused [`LimitRefusal::Deadline`], which stops, with
    /// nothing committed, while cleanup is admitted; lifted, admission
    /// resumes. A cancellation is named before the deadline.
    #[cfg(feature = "std")]
    #[test]
    #[expect(
        clippy::disallowed_methods,
        reason = "the governor's axioms are driven by direct admissions"
    )]
    fn a_monotonic_deadline_refuses_foreground_and_spares_cleanup() {
        use std::time::{Duration, Instant};
        let governor = Governor::new(Ceilings::UNLIMITED);
        let mut operation = governor.operation(Ceilings::UNLIMITED);
        operation.deadline(Some(Instant::now() + Duration::from_secs(3600)));
        operation.traverse(1, 0).unwrap();
        operation.deadline(Some(Instant::now()));
        assert_eq!(operation.traverse(1, 0), Err(LimitRefusal::Deadline));
        assert_eq!(
            operation
                .allocate(8)
                .map(|permit| permit.bytes())
                .unwrap_err(),
            LimitRefusal::Deadline,
            "an allocation was admitted past the deadline"
        );
        assert_eq!(LimitRefusal::Deadline.recovery(), Recovery::Stop);
        assert!(
            Unit::new(Caller, 1, 8)
                .admit(&mut Cleanup::new(&mut operation))
                .is_ok(),
            "cleanup was refused for the deadline"
        );
        assert_eq!(governor.used(), WriteWork::new(2, 8));
        assert_eq!(operation.live_bytes(), 0);
        operation.deadline(None);
        operation.traverse(1, 0).unwrap();
        operation.deadline(Some(Instant::now()));
        operation.cancellation().cancel();
        assert_eq!(
            operation.traverse(1, 0),
            Err(LimitRefusal::Cancelled),
            "the deadline was named before a cancellation"
        );
    }
}
