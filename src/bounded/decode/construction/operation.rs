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
    Acquisition, OwnedInitialized, OwnedRecord, PeekSlot, Reclaim, Reclaimed, ScopeRef, Slot,
    record_cost,
};
use crate::bounded::decode::initialization::fields;
use crate::bounded::{
    Allocator, BoundedError, BoundedResult, Failure, Places, ResourceBound, Resumable, Step, Unit,
    WriteWork, at, widen,
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
        let (metadata, block) = const { record_cost::<T, A>() };
        let block = widen(block)?;
        // The record's metadata written as the scope acquires it, and its
        // release, admitted with it.
        let admitted = super::stable::acquire_cost(metadata)
            .work()
            .then(super::stable::release_cost::<A::Permit>().work())?;
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
        self.record.then::<R>(self.task).map(|bound| bound.peak)
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
/// `initialize` writes the next unit of the record's resource-free prefix and
/// records it in the progress, which [`Self::initialized`] then counts; the
/// prefix after any unit must be reclaimable by the record's `reclaim_step`;
/// once `INIT_STEPS` units are recorded it refuses and changes nothing.
/// `advance` refuses and changes nothing until [`Self::initialized`] reports
/// `INIT_STEPS`, keeps the record reclaimable after every return, and reports
/// completion only once the record's value is fully initialized: the
/// operation publishes the record on that report. `detail` reads only the
/// parts the progress records as initialized, and changes, admits and
/// allocates nothing. The record is reached only through its slot's place,
/// one for its whole life, so a place derived within it in one call stays
/// valid in every later one.
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
    /// true once the record's value is complete.
    fn advance(
        &mut self,
        slot: Slot<'_, Self::State, <Self::State as Reclaim<A>>::State>,
        a: &mut A,
    ) -> Result<bool, Self::Error>;

    fn publish(&mut self, record: OwnedInitialized<'s, Self::State, A>) -> Self::Output;

    /// One admitted unit of cleanup of resources the task holds outside its
    /// record, such as an input not yet moved into it. Every call admits its
    /// unit, including the one that reports `Done`.
    fn reclaim_step(&mut self, a: &mut A) -> BoundedResult<Reclaimed, A>;

    /// The task's observation of `record`, its slot observed once
    /// allocated: only the parts the progress records as initialized are
    /// read, and nothing is changed, admitted or allocated.
    fn detail(&self, record: Observed<'_, 's, Self, A>) -> Self::Detail;
}

/// Allocation-free observation of an operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Position<D> {
    pub allocated: bool,
    pub initialized: usize,
    pub initialization_steps: usize,
    pub cancelling: bool,
    pub finished: bool,
    pub outstanding: usize,
    pub detail: D,
}

/// The controller. Construction allocates nothing.
pub struct Operation<'s, K: Task<'s, A>, A: Allocator> {
    task: K,
    record: Option<OwnedRecord<'s, K::State, A>>,
    acquisition: Acquisition<'s, K::State, A>,
    cancelling: bool,
    finished: bool,
}

impl<'s, K: Task<'s, A>, A: Allocator> Operation<'s, K, A> {
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
        let outstanding = self
            .record
            .as_ref()
            .map(|record| record.scope())
            .or_else(|| self.task.scope())
            .map_or(0, ScopeRef::outstanding);
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
            allocated,
            initialized,
            initialization_steps: K::INIT_STEPS,
            cancelling: self.cancelling,
            finished: self.finished,
            outstanding,
            detail: self.task.detail(record),
        }
    }

    pub fn step(&mut self, a: &mut A) -> Result<Step<K::Output>, K::Error> {
        if self.finished {
            return Ok(Step::Finished);
        }
        if self.cancelling {
            if self.record.is_some() {
                at(OperationPlace::Task, || {
                    OwnedRecord::reclaim_step(&mut self.record, a)
                })?;
                return Ok(Step::Progress);
            }
            // The task's cleanup admits each unit, including the one that
            // completes it.
            if at(OperationPlace::Task, || self.task.reclaim_step(a))? != Reclaimed::Done {
                return Ok(Step::Progress);
            }
            self.acquisition = Acquisition::new();
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
        if K::initialized(slot.custody()) < K::INIT_STEPS {
            at(OperationPlace::Initialization, || {
                task.initialize(slot.reborrow(), a)
            })?;
            return Ok(Step::Progress);
        }
        if !at(OperationPlace::Task, || task.advance(slot.reborrow(), a))? {
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

impl<'s, K: Task<'s, A>, A: Allocator> Resumable<A> for Operation<'s, K, A> {
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
