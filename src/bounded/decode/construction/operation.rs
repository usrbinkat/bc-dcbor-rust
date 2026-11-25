//! The single retained operation controller.
//!
//! Every owned operation (input acquisition, parsing, typed construction,
//! encoding preparation) is a [`Task`] driven by one [`Operation`]: allocate
//! one stable scope record with retained admission, initialize it in admitted
//! units, advance it, and publish it as a pointer-sized handle. A terminal
//! error or `cancel` switches the operation to operation-local cleanup: its
//! own record and any resource the task still holds are reclaimed in place,
//! independent of every other record in the scope. Dropping an operation at
//! any point only hands its records to the scope queue.
use super::reclamation::{
    Acquisition, Cleanup, OwnedInitialized, OwnedRecord, PeekSlot, QueueObservation, Reclaim,
    Reclaimed, ScopeRef, Slot, record_cost,
};
use super::stable::Pending;
use crate::bounded::boundary::{Bound, Predicate};
use crate::bounded::decode::initialization::fields;
use crate::bounded::{
    Allocator, BoundedError, BoundedResult, Budget, Custodial, CustodySink, Failure, Performer,
    PermitsObserved, Places, ResourceBound, Resumable, Step, TerminalAllocator, Unit, WriteWork,
    at, observed_all, total_held, widen,
};

places! {
    /// The places an [`Operation`] charges, one term of its bound
    /// ([`OperationTerms`]) each.
    pub(crate) enum OperationPlace {
        /// The record's admission, its release's included, and its block.
        Record,
        /// The record's initialization, field by field.
        Initialization,
        /// The task's own work and its cleanup.
        Task,
        /// The record's removal from the scope queue.
        Release,
    }
}

/// Removing a retired record from its scope's queue.
pub(crate) const REMOVAL: Unit<OperationPlace> = Unit::new(OperationPlace::Release, 1, 0);

/// The terms of an [`Operation`]'s bound, one per [`OperationPlace`]; its
/// [`Places::bound`] is the operation's [`ResourceBound`]. For a record
/// holding a `T`, initialized in `init` units, whose task's own work, its
/// cleanup's included, is `task` ([`Self::of`]): the record's admission and
/// the release unit of a permit admitted with it, and its block, held while
/// the operation or its published handle holds it; each initialization unit,
/// a field of the `T`, at most its size together; then, released through the
/// scope queue, one removal unit.
pub(crate) struct OperationTerms {
    record: ResourceBound,
    initialization: WriteWork,
    task: ResourceBound,
    release: WriteWork,
}

impl OperationTerms {
    pub(crate) fn of<T: Reclaim<A>, A: Allocator, R>(
        init: usize,
        task: ResourceBound,
    ) -> Result<Self, BoundedError<R>> {
        let (write, block) = const { record_cost::<T, A>() };
        let block = widen(block)?;
        // The record's header written as the scope acquires it, and its
        // release, admitted with it.
        let admitted = write
            .work()
            .checked_then(super::stable::release_cost::<A::Permit>().work())
            .ok_or(BoundedError::Overflow)?;
        Ok(Self {
            // Its whole block held.
            record: ResourceBound {
                values: admitted.values,
                bytes: admitted.bytes,
                allocated: block,
                peak: block,
                retained: block,
            },
            initialization: fields::<T, R>(init)?,
            task,
            release: REMOVAL.times(1)?,
        })
    }
}

impl Places for OperationTerms {
    type Place = OperationPlace;

    fn term(&self, place: OperationPlace) -> ResourceBound {
        match place {
            OperationPlace::Record => self.record,
            OperationPlace::Initialization => ResourceBound::of_work(self.initialization),
            OperationPlace::Task => self.task,
            OperationPlace::Release => ResourceBound::of_work(self.release),
        }
    }

    /// The record is held throughout, the task's peak beside it.
    fn peak<R>(&self) -> Result<u64, BoundedError<R>> {
        self.record
            .checked_then(self.task)
            .map(|bound| bound.peak)
            .ok_or(BoundedError::Overflow)
    }
}

/// The progress of a task's record: the record's own construction state.
pub(crate) type Progress<'s, K, A> = <<K as Task<'s, A>>::State as Reclaim<A>>::State;

/// A task's record as an observation sees it, once allocated: its slot,
/// observed ([`PeekSlot`]), its value possibly uninitialized, its progress
/// saying which parts are, under the operation's exclusive custody, which
/// observing a construction state requires
/// ([`super::reclamation::Custody`]).
pub(crate) type Observed<'r, 's, K, A> =
    Option<PeekSlot<'r, <K as Task<'s, A>>::State, Progress<'s, K, A>>>;

/// One kind of retained work performed in one stable record.
///
/// The record's progress is its own [`Reclaim::State`]: the units of its
/// resource-free prefix initialized ([`super::reclamation::Prefix`]) for a
/// record built field by field, or the value's construction state for a
/// record that is itself a value built in place. The record is received as a
/// [`Slot`], its place and progress together, so a caller holding one has
/// nothing to promise.
///
/// # Safety
/// An implementation keeps four obligations, and the `// SAFETY:` comment on
/// it names each as `label:` (`tests/unsafe_census.rs`, `UNSAFE_TRAITS`,
/// which lists every implementation):
///
/// - *prefix*: `initialize` writes the next unit of the record's
///   resource-free prefix and records it in the progress, which
///   [`Self::initialized`] then counts; the prefix after any unit is
///   reclaimable by the record's `reclaim_step`; once `INIT_STEPS` units are
///   recorded, or once the record's cleanup released a progress that is a
///   [`super::reclamation::Prefix`], it refuses and changes nothing.
/// - *advance*: `advance` refuses and changes nothing until
///   [`Self::initialized`] reports `INIT_STEPS`, keeps the record
///   reclaimable after every return, and reports completion only once the
///   record's value is fully initialized: the operation publishes the record
///   on that report.
/// - *detail*: `detail` and `observe_custody` read only the parts the
///   progress records as initialized, and change, admit and allocate
///   nothing.
/// - *provenance*: the record is reached only through its slot's place, one
///   for its whole life, so a place derived within it in one call stays
///   valid in every later one.
pub unsafe trait Task<'s, A: Allocator>: Sized {
    type State: Reclaim<A, State: Send> + Send + 's;
    type Output;
    type Error: Failure<Refusal = A::Refusal> + From<BoundedError<A::Refusal>>;
    /// Task-specific observation.
    type Detail: Copy + PartialEq + core::fmt::Debug;
    const INIT_STEPS: usize;

    /// The scope in which the record is allocated.
    fn scope(&self) -> Option<&ScopeRef<'s, A>>;

    /// The prefix units `progress` records as initialized, at most
    /// `INIT_STEPS`.
    fn initialized(progress: &<Self::State as Reclaim<A>>::State) -> usize;

    /// One unit of the record's initialization ([`Task`]).
    fn initialize(
        &mut self,
        slot: Slot<'_, Self::State, <Self::State as Reclaim<A>>::State>,
        a: &mut A,
    ) -> Result<(), Self::Error>;

    /// One unit of the task's work on its initialized record ([`Task`]):
    /// true once the record's value is complete. `pending` is the
    /// operation's one acquisition custody, the record's own acquisition's,
    /// idle once the record is owned and bound under the owner the record
    /// stores: a task whose value acquires with no custody field of its own
    /// to keep a pending in (a copied input, whose record is the byte string
    /// itself) binds those acquisitions here, so everything the record holds
    /// is bound under the record's own owner, and the operation settles it
    /// with the record's at cleanup entry and drop
    /// ([`Acquisition::cancel`]). A task whose record keeps its own pending
    /// leaves this one idle.
    fn advance(
        &mut self,
        slot: Slot<'_, Self::State, <Self::State as Reclaim<A>>::State>,
        pending: &mut Pending<A::Origin>,
        a: &mut A,
    ) -> Result<bool, Self::Error>;

    fn publish(&mut self, record: OwnedInitialized<'s, Self::State, A>) -> Self::Output;

    /// One admitted unit of cleanup of resources the task holds outside its
    /// record, such as an input not yet moved into it. Every call admits its
    /// unit, including the one that reports `Done`. Runs under `cleanup`,
    /// the capability the operation's cleanup dispatch minted ([`Cleanup`]).
    fn reclaim_step(&mut self, cleanup: &mut Cleanup<'_, A>) -> BoundedResult<Reclaimed, A>;

    /// Settle, by origin and `by` the performer, the credit of any
    /// acquisition the task itself holds pending outside its record
    /// ([`super::stable::Pending::settle_all`]): called at the operation's
    /// cleanup entry, before anything installed is reclaimed, and when the
    /// operation is dropped. Idempotent; admits, allocates and refuses
    /// nothing, and does not unwind. A task holding no pending credit of
    /// its own (its record's custody keeps any) settles nothing.
    fn settle(&mut self, by: Performer);

    /// The task's observation of `record`, its slot observed once
    /// allocated: only the parts the progress records as initialized are
    /// read, and nothing is changed, admitted or allocated. Takes `&mut
    /// self` because a held input handle's state is observed through its
    /// exclusive custody ([`OwnedInitialized::state`]), as
    /// [`Self::observe_custody`] observes its permits.
    fn detail(&mut self, record: Observed<'_, 's, Self, A>) -> Self::Detail;

    /// The task's custody outside its record, each independently owning
    /// component as a group of its own owner ([`CustodySink`]): an input
    /// handle not yet moved into the record, under the owner its own record
    /// stores; a pending acquisition the task itself keeps, under its
    /// pending's owner. Everything inside the record, its value's custody
    /// included, is the record's to report through its
    /// [`Reclaim::observe_permits`]; `record` is the record as
    /// [`Self::detail`] reads it, for a task whose outside custody depends
    /// on how far the record has taken it. Takes `&mut self` because a held
    /// input handle's record state is observed through its exclusive
    /// custody ([`OwnedInitialized::observe_custody`]). Read-only; returns
    /// the completeness of every group reported, combined.
    fn observe_custody(
        &mut self,
        record: Observed<'_, 's, Self, A>,
        sink: &mut dyn CustodySink<A::Permit>,
    ) -> PermitsObserved;
}

/// Allocation-free observation of an operation: whether its record is
/// allocated and how much of its prefix is written; whether it is cancelling
/// or finished; how many records its scope holds and its scope queue's drain
/// state, which the queue's steps read ([`ScopeRef::queue_position`]); and
/// its task's detail. Where its record's acquisition stands is not observed:
/// cleanup cancels the acquisition at every stage without admitting
/// anything ([`Acquisition::cancel_into`]), so no stage changes what its
/// cleanup admits.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Position<D> {
    pub queue: QueueObservation,
    pub allocated: bool,
    pub initialized: usize,
    pub initialization_steps: usize,
    pub cancelling: bool,
    pub finished: bool,
    pub outstanding: usize,
    pub detail: D,
}

/// How much of a record's prefix its cleanup reads: its exact units, or,
/// for a record whose cleanup before its prefix is complete reads only a
/// slot its task's detail already carries, that the prefix is partial.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum PrefixClass {
    Units(usize),
    Partial,
}

/// The operation's part of a class ([`super::Reduction`]), its task's
/// class `C` beside it: whether its record is allocated, how much of its
/// prefix cleanup reads ([`PrefixClass`]), whether it is finished, how many
/// records its scope holds and where its queue stands. Each is read: a
/// record's cleanup releases its written prefix, and the scope's drain
/// releases every record it holds from where its queue stands (the active
/// record's remaining calls, the records queued behind it, a removal unit
/// already admitted). Whether the operation is cancelling is not: a stop
/// cancels it before its cleanup, which runs alike from either
/// ([`Operation::cancel`], [`Operation::step`]), and its drop reads nothing
/// of it. Nor is where the record's acquisition stands: every cleanup step
/// cancels it first, admitting nothing ([`Acquisition::cancel_into`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub struct OperationClass<C> {
    pub queue: QueueObservation,
    pub allocated: bool,
    pub prefix: PrefixClass,
    pub finished: bool,
    pub outstanding: usize,
    pub task: C,
}

impl<D> Position<D> {
    /// The prefix by its exact units.
    pub(crate) fn units(&self) -> PrefixClass {
        PrefixClass::Units(self.initialized)
    }

    /// The prefix as partial while the record is allocated and its prefix
    /// begun but incomplete, its exact units otherwise: the prefix of a
    /// record whose cleanup then reads only a slot its detail carries.
    pub(crate) fn partial(&self) -> PrefixClass {
        if self.allocated && 0 < self.initialized && self.initialized < self.initialization_steps {
            PrefixClass::Partial
        } else {
            self.units()
        }
    }

    /// The operation's part of a class ([`OperationClass`]), its prefix
    /// read as `prefix` and its task's class `task`: what each operation's
    /// own `class` builds on.
    pub(crate) fn operation_class<C>(&self, prefix: PrefixClass, task: C) -> OperationClass<C> {
        OperationClass {
            queue: self.queue,
            allocated: self.allocated,
            prefix,
            finished: self.finished,
            outstanding: self.outstanding,
            task,
        }
    }
}

/// What an operation holds: its position ([`Operation::position`]).
impl<'s, K: Task<'s, A>, A: TerminalAllocator> super::Custody for Operation<'s, K, A>
where
    K::Detail: Eq + Ord,
{
    type Observation = Position<K::Detail>;

    fn observe(&mut self) -> Position<K::Detail> {
        self.position()
    }
}

/// The controller. Construction allocates nothing.
pub struct Operation<'s, K: Task<'s, A>, A: TerminalAllocator> {
    task: K,
    record: Option<OwnedRecord<'s, K::State, A>>,
    acquisition: Acquisition<'s, K::State, A>,
    cancelling: bool,
    finished: bool,
}

impl<'s, K: Task<'s, A>, A: TerminalAllocator> Operation<'s, K, A> {
    pub(crate) const fn new(task: K) -> Self {
        Self {
            task,
            record: None,
            acquisition: Acquisition::new(),
            cancelling: false,
            finished: false,
        }
    }

    /// Stop permanently. Subsequent steps perform operation-local cleanup.
    pub fn cancel(&mut self) {
        if !self.finished {
            self.cancelling = true;
        }
    }

    /// Whether the operation is performing its operation-local cleanup.
    pub fn is_cancelling(&self) -> bool {
        self.cancelling
    }

    pub fn position(&mut self) -> Position<K::Detail> {
        let scope = self
            .record
            .as_ref()
            .map(|record| record.scope())
            .or_else(|| self.task.scope());
        let outstanding = scope.map_or(0, ScopeRef::outstanding);
        let queue = scope.map_or(QueueObservation::Unscoped, ScopeRef::queue_position);
        let (allocated, initialized, record) = match self.record.as_mut() {
            None => (false, 0, None),
            Some(record) => {
                // The controller's exclusive custody of its record: its slot,
                // observed.
                let mut slot = record.destination().into_observe();
                (true, K::initialized(slot.custody()), Some(slot))
            }
        };
        Position {
            queue,
            allocated,
            initialized,
            initialization_steps: K::INIT_STEPS,
            cancelling: self.cancelling,
            finished: self.finished,
            outstanding,
            detail: self.task.detail(record),
        }
    }
}

/// The operation's custody, one traversal, each independently owning
/// component a group of its own owner ([`CustodySink`]): its record's
/// acquisition token's (the record's write and release held toward a block
/// not yet granted, under the token's owner); its record, once allocated
/// (the block and the value's custody under the owner the record stores);
/// and the task's outside the record ([`Task::observe_custody`]). Read-only;
/// the completeness of every part, combined.
impl<'s, K: Task<'s, A>, A: TerminalAllocator> Custodial<A::Permit> for Operation<'s, K, A> {
    fn observe_custody(&mut self, sink: &mut dyn CustodySink<A::Permit>) -> PermitsObserved {
        let acquisition = self.acquisition.observe_custody(sink);
        let record = match self.record.as_mut() {
            Some(record) => record.observe_custody(sink),
            None => PermitsObserved::Complete,
        };
        // The record and the task are disjoint fields.
        let observed = self
            .record
            .as_mut()
            .map(|record| record.destination().into_observe());
        let task = self.task.observe_custody(observed, sink);
        // The task's own scope reference, before its record holds one.
        let shared = self
            .task
            .scope()
            .map_or(PermitsObserved::Complete, |scope| {
                scope.observe_abandoned(sink)
            });
        observed_all([acquisition, record, task, shared])
    }
}

impl<'s, K: Task<'s, A>, A: TerminalAllocator> Operation<'s, K, A> {
    /// The credit the operation holds ([`Custodial::observe_custody`], summed);
    /// `None` when it does not fit in `u64`, or when the observation is not
    /// whole.
    pub fn held_credit(&mut self) -> Option<WriteWork> {
        total_held(|sink| self.observe_custody(sink))
    }

    pub fn step(&mut self, a: &mut A) -> Result<Step<K::Output>, K::Error> {
        if self.finished {
            return Ok(Step::Finished);
        }
        if self.cancelling {
            // Cleanup's entry, before any installed resource is reclaimed:
            // the credit pending outside the record, the task's own and the
            // record's acquisition's if it was never granted, settled by
            // origin under this step's performer. Idempotent, so every
            // cleanup step after the first, and a refused one retried,
            // settles nothing again.
            self.task.settle(a.performer());
            // The operation's cleanup dispatch, an outermost frame: everything
            // cleanup steps from here runs under the capability minted over
            // `a`, and every scope reference it ends, the acquisition's
            // included, is deferred and released once the step returns.
            let (record, task, acquisition) =
                (&mut self.record, &mut self.task, &mut self.acquisition);
            let reclaimed = super::reclamation::with_cleanup(a, |cleanup| {
                let by = cleanup.performer();
                acquisition.cancel_into(by, cleanup.worklist());
                if record.is_some() {
                    at(OperationPlace::Task, || {
                        OwnedRecord::reclaim_under(record, cleanup)
                    })?;
                    return Ok(Reclaimed::Progress);
                }
                // The task's cleanup admits each unit, including the one
                // that completes it.
                at(OperationPlace::Task, || task.reclaim_step(cleanup))
            })?;
            if reclaimed != Reclaimed::Done {
                return Ok(Step::Progress);
            }
            self.finished = true;
            return Ok(Step::Finished);
        }
        let result = self.advance(a);
        if let Err(error) = &result
            && !error.refused()
        {
            self.cancelling = true;
        }
        result
    }

    fn advance(&mut self, a: &mut A) -> Result<Step<K::Output>, K::Error> {
        let Some(record) = self.record.as_mut() else {
            let scope = self.task.scope().ok_or(BoundedError::PlanMismatch)?;
            let acquisition = &mut self.acquisition;
            self.record = Some(at(OperationPlace::Record, || {
                scope.allocate_step(a, acquisition)
            })?);
            return Ok(Step::Progress);
        };
        // The record is this operation's exclusive stable destination,
        // paired with its own progress for its whole lifetime.
        let mut slot = record.destination();
        let task = &mut self.task;
        if Bound::new(Predicate::Prefix, K::INIT_STEPS).below(a, K::initialized(slot.custody())) {
            at(OperationPlace::Initialization, || {
                task.initialize(slot.reborrow(), a)
            })?;
            return Ok(Step::Progress);
        }
        // The record, the task and the acquisition are disjoint fields.
        let pending = self.acquisition.pending();
        if !at(OperationPlace::Task, || {
            task.advance(slot.reborrow(), pending, a)
        })? {
            return Ok(Step::Progress);
        }
        let record = self.record.take().ok_or(BoundedError::PlanMismatch)?;
        self.finished = true;
        // SAFETY: the task reported completion, which its contract makes
        // only once the record's value is fully initialized.
        let published = unsafe { record.publish() };
        Ok(Step::Complete(self.task.publish(published)))
    }
}

/// Dropped at any point: the credit pending outside the record, the task's
/// own and the record's acquisition's, settled explicitly by origin with no
/// performing policy, never left to the retained obligations' own drop
/// backstop; the records are handed to the scope queue as before.
impl<'s, K: Task<'s, A>, A: TerminalAllocator> Drop for Operation<'s, K, A> {
    fn drop(&mut self) {
        self.task.settle(Performer::None);
        self.acquisition.cancel(Performer::None);
    }
}

impl<'s, K: Task<'s, A>, A: TerminalAllocator> Resumable<A> for Operation<'s, K, A> {
    type Output = K::Output;
    type Error = K::Error;
    type Position = Position<K::Detail>;

    fn step(&mut self, a: &mut A) -> Result<Step<K::Output>, K::Error> {
        Operation::step(self, a)
    }

    fn position(&mut self) -> Position<K::Detail> {
        Operation::position(self)
    }
}

/// The witness every record whose progress is a
/// [`super::reclamation::Prefix`] shares: its task's record driven unit by
/// unit in a destination of the test's own, under a recorded session whose
/// finish refuses while any owner, family, permit or held obligation of it
/// lives ([`crate::bounded::Session::finish`]). Each run is cut at one step,
/// every step from none to completion, then cleaned up to `Done`; from
/// there, released prefix or terminal phase alike, a further cleanup step
/// reports `Done` admitting nothing, the count is the one call reporting it,
/// no permit or credit is observed, initialization and advance are refused
/// admitting nothing, and the task's detail is read, which reads nothing of
/// a dropped or released part. A record cut before its prefix completed is
/// released; one cut after ends in its own terminal phase, or, without one,
/// released. Every capability is released exactly once: the scope shuts
/// down and the session finishes.
#[cfg(all(test, feature = "std"))]
pub(crate) mod cuts {
    use super::*;
    use crate::bounded::decode::construction::reclamation::{
        DecodeOwner, Place, Prefix, with_cleanup,
    };
    use crate::bounded::{Capacity, Limits, Releasing, Session, permits_of};
    use core::fmt::Debug;
    use core::mem::MaybeUninit;
    use core::ptr::NonNull;

    /// The most calls any loop of a run takes: a witness's operation is
    /// small, so a loop that does not end fails here.
    const CALLS: usize = 4096;

    /// The record's slot: its one place paired with `prefix`, its progress,
    /// for one call. Every slot of a run is made here, from the run's one
    /// place over a destination the run owns and reaches only through it,
    /// so the place and the progress are always each other's.
    fn slot<S>(place: Place<S>, prefix: &mut Prefix) -> Slot<'_, S, Prefix> {
        // SAFETY: as above: the destination is the run's own, reached only
        // through `place`, and `prefix` is its progress.
        unsafe { Slot::new(place, prefix) }
    }

    /// Whether `error`, the task's, is the plan mismatch a refused unit
    /// reports.
    fn mismatch(error: &impl Debug) -> bool {
        format!("{error:?}").contains("PlanMismatch")
    }

    /// `owner` shut down to `Done` under `a`.
    fn shut_down(mut owner: DecodeOwner<'static, Limits>, a: &mut Limits, what: &str) {
        for _ in 0..CALLS {
            if owner
                .shutdown_step(a)
                .unwrap_or_else(|error| panic!("{what}: shutdown: {error:?}"))
                == Reclaimed::Done
            {
                return;
            }
        }
        panic!("{what}: the scope did not shut down");
    }

    /// One run of `setup`'s task, cut after `cut` steps, or run to
    /// completion when `None`; `after_done` reads the task's detail of the
    /// record once its cleanup reported `Done`, told whether the record was
    /// released. The steps taken.
    fn run<K>(
        name: &str,
        cut: Option<usize>,
        setup: &impl Fn(&mut Limits) -> (DecodeOwner<'static, Limits>, K),
        after_done: &impl Fn(&K::Detail, bool, &str),
    ) -> usize
    where
        K: Task<'static, Limits>,
        K::State: Reclaim<Limits, State = Prefix>,
        K::Error: Debug,
    {
        let what = format!("{name}, cut {cut:?}");
        let session = Session::new(Capacity::DEFAULT);
        let mut a = Limits::recorded_unlimited(&session);
        let (owner, mut task) = setup(&mut a);
        let mut record = MaybeUninit::<K::State>::uninit();
        let mut prefix = Prefix::EMPTY;
        let mut pending = Pending::deferred();
        // SAFETY: the test owns the record's destination, reached only
        // through this place, each call pairing it with its own progress.
        let place: Place<K::State> = unsafe { Place::root(NonNull::from(&mut record)) };
        let mut steps = 0;
        let mut published = false;
        while !published && cut != Some(steps) {
            assert!(steps < CALLS, "{what}: the task did not complete");
            if prefix.initialized() < K::INIT_STEPS {
                task.initialize(slot(place, &mut prefix), &mut a)
                    .unwrap_or_else(|error| panic!("{what}: initialization: {error:?}"));
            } else {
                published = task
                    .advance(slot(place, &mut prefix), &mut pending, &mut a)
                    .unwrap_or_else(|error| panic!("{what}: advance: {error:?}"));
            }
            steps += 1;
        }
        let complete = prefix.initialized() == K::INIT_STEPS;
        let declared =
            <K::State as Reclaim<Limits>>::remaining(slot(place, &mut prefix).into_observe())
                .expect("a witness's cleanup count fits in u64");
        let mut taken = 0u64;
        loop {
            assert!(
                taken < declared,
                "{what}: cleanup beyond its declared {declared} calls"
            );
            let reclaimed = with_cleanup(&mut a, |cleanup| {
                <K::State as Reclaim<Limits>>::reclaim_step(slot(place, &mut prefix), cleanup)
            })
            .unwrap_or_else(|error| panic!("{what}: cleanup: {error:?}"));
            taken += 1;
            if reclaimed == Reclaimed::Done {
                break;
            }
        }
        let attempts = a.attempts();
        assert_eq!(
            with_cleanup(&mut a, |cleanup| {
                <K::State as Reclaim<Limits>>::reclaim_step(slot(place, &mut prefix), cleanup)
            }),
            Ok(Reclaimed::Done),
            "{what}: a step after Done"
        );
        assert_eq!(a.attempts(), attempts, "{what}: a step after Done admitted");
        // A record cut before its prefix completed is released; one cut
        // after ended in its own terminal phase, or, a record with none,
        // released too.
        assert!(
            complete || prefix.released(),
            "{what}: an incomplete prefix's cleanup left it unreleased"
        );
        assert_eq!(
            <K::State as Reclaim<Limits>>::remaining(slot(place, &mut prefix).into_observe()),
            Some(1),
            "{what}: the count after Done"
        );
        let mut permits = 0;
        let observed = permits_of::<Limits>(
            |sink| {
                <K::State as Reclaim<Limits>>::observe_permits(
                    slot(place, &mut prefix).into_observe(),
                    sink,
                )
            },
            &mut |_| permits += 1,
        );
        assert_eq!(observed, PermitsObserved::Complete, "{what}");
        assert_eq!(permits, 0, "{what}: a permit observed after Done");
        let held = total_held::<<Limits as Releasing>::Permit>(|sink| {
            <K::State as Reclaim<Limits>>::observe_permits(
                slot(place, &mut prefix).into_observe(),
                sink,
            )
        });
        assert_eq!(
            held,
            Some(WriteWork::default()),
            "{what}: credit after Done"
        );
        let initialized = task.initialize(slot(place, &mut prefix), &mut a);
        assert!(
            initialized.as_ref().is_err_and(mismatch),
            "{what}: initialization after Done: {initialized:?}"
        );
        let advanced = task.advance(slot(place, &mut prefix), &mut pending, &mut a);
        assert!(
            advanced.as_ref().is_err_and(mismatch),
            "{what}: advance after Done: {advanced:?}"
        );
        assert_eq!(a.attempts(), attempts, "{what}: a call after Done admitted");
        let detail = task.detail(Some(slot(place, &mut prefix).into_observe()));
        after_done(&detail, prefix.released(), &what);
        for call in 0.. {
            assert!(call < CALLS, "{what}: the task's cleanup did not finish");
            if with_cleanup(&mut a, |cleanup| task.reclaim_step(cleanup))
                .unwrap_or_else(|error| panic!("{what}: the task's cleanup: {error:?}"))
                == Reclaimed::Done
            {
                break;
            }
        }
        shut_down(owner, &mut a, &what);
        assert_eq!(a.live_bytes(), 0, "{what}: storage kept");
        drop((task, pending, a));
        session.finish().unwrap_or_else(|incomplete| {
            panic!("{what}: the run's recording is no evidence: {incomplete:?}")
        });
        steps
    }

    /// [`run`] to completion, then cut at every step it took.
    pub(crate) fn every_cut<K>(
        name: &str,
        setup: impl Fn(&mut Limits) -> (DecodeOwner<'static, Limits>, K),
        after_done: impl Fn(&K::Detail, bool, &str),
    ) where
        K: Task<'static, Limits>,
        K::State: Reclaim<Limits, State = Prefix>,
        K::Error: Debug,
    {
        let steps = run(name, None, &setup, &after_done);
        assert!(
            steps > K::INIT_STEPS,
            "{name}: the task completed within its initialization"
        );
        for cut in 0..steps {
            run(name, Some(cut), &setup, &after_done);
        }
    }

    /// `operation` stepped to its output: a witness's setup, its input or
    /// document made by the operation that makes it in production.
    pub(crate) fn completed<'s, T: Task<'s, Limits>>(
        mut operation: Operation<'s, T, Limits>,
        a: &mut Limits,
    ) -> T::Output
    where
        T::Error: Debug,
    {
        for _ in 0..CALLS {
            match operation.step(a).unwrap() {
                Step::Complete(output) => return output,
                Step::Progress => {}
                Step::Finished => panic!("an operation finished without its output"),
            }
        }
        panic!("an operation took more than {CALLS} steps");
    }

    /// An initialized scope under `a`.
    pub(crate) fn scope(a: &mut Limits) -> DecodeOwner<'static, Limits> {
        let mut owner = DecodeOwner::<'static, Limits>::new();
        owner.initialize_step(a).unwrap();
        owner
    }
}
