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
use core::mem::MaybeUninit;
use core::ptr::NonNull;

use super::reclamation::{
    Acquisition, OwnedInitialized, OwnedRecord, Reclaim, Reclaimed, ScopeRef, record_cost,
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

/// A task's record as an observation sees it, once allocated: its storage,
/// possibly uninitialized, beside the progress that says which parts are,
/// both under the operation's exclusive custody, which observing a
/// construction state requires ([`super::reclamation::Custody`]).
pub(crate) type Observed<'r, 's, K, A> = Option<(
    &'r mut MaybeUninit<<K as Task<'s, A>>::State>,
    &'r mut Progress<'s, K, A>,
)>;

/// One kind of retained work performed in one stable record.
///
/// The record's progress is its own [`Reclaim::State`]: the units of its
/// resource-free prefix initialized ([`super::reclamation::Prefix`]) for a
/// record built field by field, or the value's construction state for a
/// record that is itself a value built in place.
///
/// # Safety
/// `initialize` writes the next unit of the record's resource-free prefix and
/// records it in the progress, which [`Self::initialized`] then counts; the
/// prefix after any unit must be reclaimable by the record's `reclaim_step`.
/// `advance` is called only once [`Self::initialized`] reports `INIT_STEPS`,
/// with the original destination and progress, and must keep the record
/// reclaimable after every return. `publish` is called once, after `advance`
/// reported completion.
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

    /// # Safety
    /// See the trait's contract.
    unsafe fn initialize(
        &mut self,
        place: *mut Self::State,
        progress: &mut <Self::State as Reclaim<A>>::State,
        a: &mut A,
    ) -> Result<(), Self::Error>;

    /// # Safety
    /// See the trait's contract.
    unsafe fn advance(
        &mut self,
        place: NonNull<MaybeUninit<Self::State>>,
        progress: &mut <Self::State as Reclaim<A>>::State,
        a: &mut A,
    ) -> Result<bool, Self::Error>;

    fn publish(&mut self, record: OwnedInitialized<'s, Self::State, A>) -> Self::Output;

    /// One admitted unit of cleanup of resources the task holds outside its
    /// record, such as an input not yet moved into it. Every call admits its
    /// unit, including the one that reports `Done`.
    fn reclaim_step(&mut self, a: &mut A) -> BoundedResult<Reclaimed, A>;

    /// # Safety
    /// `record` is the record's storage and its progress: only the parts the
    /// progress records as initialized may be read, and nothing may be
    /// changed, admitted or allocated.
    unsafe fn detail(&self, record: Observed<'_, 's, Self, A>) -> Self::Detail;
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
                // SAFETY: the controller has exclusive custody of its record;
                // the storage is exposed only as possibly uninitialized, beside
                // the progress that says which parts are initialized.
                let (mut place, progress) = unsafe { record.destination() };
                let storage: &mut MaybeUninit<K::State> = unsafe { place.as_mut() };
                (true, K::initialized(progress), Some((storage, progress)))
            }
        };
        Position {
            allocated,
            initialized,
            initialization_steps: K::INIT_STEPS,
            cancelling: self.cancelling,
            finished: self.finished,
            outstanding,
            // SAFETY: the storage is paired with its own progress.
            detail: unsafe { self.task.detail(record) },
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
        // SAFETY: the record is this operation's exclusive stable destination,
        // paired with its own progress for its whole lifetime.
        let (place, progress) = unsafe { record.destination() };
        let task = &mut self.task;
        if K::initialized(progress) < K::INIT_STEPS {
            // SAFETY: forwarded under the Task contract.
            at(OperationPlace::Initialization, || unsafe {
                task.initialize(place.as_ptr().cast(), progress, a)
            })?;
            return Ok(Step::Progress);
        }
        // SAFETY: initialization is complete.
        if !at(OperationPlace::Task, || unsafe {
            task.advance(place, progress, a)
        })? {
            return Ok(Step::Progress);
        }
        let record = self.record.take().ok_or(BoundedError::PlanMismatch)?;
        self.finished = true;
        // SAFETY: the task reported a fully initialized state.
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
