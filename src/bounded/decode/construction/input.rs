//! Input handles: immutable bytes in scope custody, copied or borrowed.
use super::in_place::Built;
use super::in_place::text::{BufferObservation, BufferState};
use super::operation::{Operation, OperationTerms, Task};
use super::reclamation::{
    Custody, DecodeOwner, OwnedInitialized, PeekSlot, Prefix, Reclaim, Reclaimed, ScopeRef, Slot,
};
use crate::ByteString;
use crate::bounded::decode::initialization::field;
use crate::bounded::{
    Allocator, BoundedError, BoundedResult, Places, ResourceBound, Unit, WriteWork,
};

places! {
    /// The places an input task charges of its own ([`InputBorrow`],
    /// [`InputAcquisition`]), inside its operation's task. A copy's bytes
    /// are its copy's construction ([`ByteString`]'s binding).
    pub(crate) enum InputPlace {
        /// Completing a borrowed record, or, cancelled before that, retiring
        /// the task's scope reference: exactly one of the two per operation.
        Settle,
        /// The borrowed record's own cleanup.
        Borrow,
    }
}

/// Completing a borrowed input's record, or retiring an input task's scope
/// reference.
const SETTLE: Unit<InputPlace> = Unit::new(InputPlace::Settle, 1, 0);

/// Retiring a borrow.
const RETIRE: Unit<InputPlace> = Unit::new(InputPlace::Borrow, 1, 0);

/// Immutable input resource carried by an owning initialized handle. An
/// input's record moves between threads with the handles holding it, so the
/// input and its construction state are both `Send`.
///
/// # Safety
/// `bytes` must return the same byte sequence throughout this resource's live
/// lifetime, including across calls through other shared aliases. No interior
/// mutation may change those bytes. Reclaim must release associated evidence
/// and reservations incrementally under the Reclaim contract.
pub unsafe trait DecodeInput<A: Allocator>: Reclaim<A, State: Send> + Send {
    fn bytes(&self) -> &[u8];
}

// SAFETY: ByteString exposes immutable bytes through a shared reference and
// its Reclaim binding releases its buffer and permits incrementally.
unsafe impl<A: Allocator> DecodeInput<A> for ByteString
where
    A::Permit: Send,
{
    fn bytes(&self) -> &[u8] {
        self.data()
    }
}

/// A borrowed input: the scope's lifetime is bound to the borrow, so the
/// bytes outlive every record and the owner of the scope.
pub struct Borrowed<'s>(&'s [u8]);

// SAFETY: a borrowed slice owns nothing; one admitted unit retires it,
// whether or not its single prefix unit was initialized.
unsafe impl<A: Allocator> Reclaim<A> for Borrowed<'_> {
    type State = Prefix;
    const INITIAL: Prefix = Prefix::EMPTY;

    fn reclaim_step(mut slot: Slot<'_, Self, Prefix>, a: &mut A) -> BoundedResult<Reclaimed, A> {
        RETIRE.admit(a)?;
        *slot.custody() = Prefix::EMPTY;
        Ok(Reclaimed::Done)
    }

    /// One call, which is `Done`.
    fn remaining(_: PeekSlot<'_, Self, Prefix>) -> u64 {
        1
    }
}

// SAFETY: a shared slice is immutable for its whole lifetime.
unsafe impl<A: Allocator> DecodeInput<A> for Borrowed<'_> {
    fn bytes(&self) -> &[u8] {
        self.0
    }
}

/// An input task's own cleanup: it holds only a scope reference, released in
/// one admitted unit, which completes the cleanup.
fn release_scope<'s, A: Allocator>(
    scope: &mut Option<ScopeRef<'s, A>>,
    a: &mut A,
) -> BoundedResult<Reclaimed, A> {
    SETTLE.admit(a)?;
    *scope = None;
    Ok(Reclaimed::Done)
}

/// Progress of an input acquisition, `O` its record's observation: the
/// source's length, the bytes in custody (copied so far, or the whole
/// borrow once recorded), whether the task still holds its scope reference,
/// and the record's own custody once allocated.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct InputDetail<O> {
    pub length: usize,
    pub held: usize,
    pub scope: bool,
    pub record: Option<O>,
}

/// Copies immutable bytes incrementally into scope custody. The source is
/// borrowed only while copying; the published handle owns its copy.
pub struct CopyInput<'src, 's, A: Allocator> {
    source: &'src [u8],
    scope: Option<ScopeRef<'s, A>>,
}

// SAFETY: ByteString's own construction state tracks every initialized part;
// there is no separate initialization prefix.
unsafe impl<'s, A: Allocator> Task<'s, A> for CopyInput<'_, 's, A>
where
    A::Permit: Send,
{
    type State = ByteString;
    type Output = OwnedInitialized<'s, ByteString, A>;
    type Error = BoundedError<A::Refusal>;
    type Detail = InputDetail<BufferObservation>;
    const INIT_STEPS: usize = 0;

    fn scope(&self) -> Option<&ScopeRef<'s, A>> {
        self.scope.as_ref()
    }

    fn initialized(_: &BufferState<A::Permit>) -> usize {
        0
    }

    fn initialize(
        &mut self,
        _: Slot<'_, ByteString, BufferState<A::Permit>>,
        _: &mut A,
    ) -> Result<(), Self::Error> {
        Err(BoundedError::PlanMismatch)
    }

    /// One unit of the copy, whose construction state is the record's own
    /// progress: complete exactly when the byte string is.
    fn advance(
        &mut self,
        slot: Slot<'_, ByteString, BufferState<A::Permit>>,
        a: &mut A,
    ) -> Result<bool, Self::Error> {
        Ok(ByteString::copy_step(self.source, slot, a)? == Built::Done)
    }

    fn publish(&mut self, record: OwnedInitialized<'s, ByteString, A>) -> Self::Output {
        self.scope = None;
        record
    }

    fn reclaim_step(&mut self, a: &mut A) -> BoundedResult<Reclaimed, A> {
        release_scope(&mut self.scope, a)
    }

    fn detail(
        &self,
        record: Option<PeekSlot<'_, ByteString, BufferState<A::Permit>>>,
    ) -> InputDetail<BufferObservation> {
        let record = record.map(|mut slot| slot.custody().observe());
        InputDetail {
            length: self.source.len(),
            held: match record {
                Some(BufferObservation::Held(custody)) => custody.copied,
                Some(BufferObservation::Unallocated(_)) | None => 0,
            },
            scope: self.scope.is_some(),
            record,
        }
    }
}

/// Records a borrowed slice as an input handle, without copying.
pub struct BorrowInput<'s, A: Allocator> {
    source: &'s [u8],
    scope: Option<ScopeRef<'s, A>>,
}

// SAFETY: the single initialization unit writes the whole resource-free value.
unsafe impl<'s, A: Allocator> Task<'s, A> for BorrowInput<'s, A> {
    type State = Borrowed<'s>;
    type Output = OwnedInitialized<'s, Borrowed<'s>, A>;
    type Error = BoundedError<A::Refusal>;
    type Detail = InputDetail<Prefix>;
    const INIT_STEPS: usize = 1;

    fn scope(&self) -> Option<&ScopeRef<'s, A>> {
        self.scope.as_ref()
    }

    fn initialized(prefix: &Prefix) -> usize {
        prefix.initialized()
    }

    fn initialize(
        &mut self,
        mut slot: Slot<'_, Borrowed<'s>, Prefix>,
        a: &mut A,
    ) -> Result<(), Self::Error> {
        let (place, prefix) = slot.parts();
        if prefix.initialized() >= Self::INIT_STEPS {
            return Err(BoundedError::PlanMismatch);
        }
        let source = self.source;
        // SAFETY: the slot pairs the record's place with its progress, which
        // records nothing written: the destination is uninitialized.
        unsafe { field(place.as_ptr(prefix), || Borrowed(source), a)? };
        prefix.advance();
        Ok(())
    }

    /// Completion, once the record is written: the operation publishes the
    /// borrow on it, so it is refused before.
    fn advance(
        &mut self,
        mut slot: Slot<'_, Borrowed<'s>, Prefix>,
        a: &mut A,
    ) -> Result<bool, Self::Error> {
        if slot.custody().initialized() != Self::INIT_STEPS {
            return Err(BoundedError::PlanMismatch);
        }
        SETTLE.admit(a)?;
        Ok(true)
    }

    fn publish(&mut self, record: OwnedInitialized<'s, Borrowed<'s>, A>) -> Self::Output {
        self.scope = None;
        record
    }

    fn reclaim_step(&mut self, a: &mut A) -> BoundedResult<Reclaimed, A> {
        release_scope(&mut self.scope, a)
    }

    fn detail(&self, record: Option<PeekSlot<'_, Borrowed<'s>, Prefix>>) -> InputDetail<Prefix> {
        let record = record.map(|mut slot| slot.custody().observe());
        InputDetail {
            length: self.source.len(),
            held: record.map_or(0, |prefix| {
                if prefix.initialized() == Self::INIT_STEPS {
                    self.source.len()
                } else {
                    0
                }
            }),
            scope: self.scope.is_some(),
            record,
        }
    }
}

/// The [`ResourceBound`] of copying `len` bytes into scope custody
/// ([`InputAcquisition`]): the record holding the copy; the copy's own
/// construction and cleanup ([`super::in_place::InPlace::COST`] of
/// [`ByteString`], its subtree being the copied bytes); and, cancelled, the
/// task's scope reference retired. The copy and its record are what
/// publication retains.
pub fn copy_bound<A: Allocator, R>(len: u64) -> Result<ResourceBound, BoundedError<R>>
where
    A::Permit: Send,
{
    copy_terms::<A, R>(len)?.0.bound()
}

/// The terms of a copy ([`copy_bound`]): its operation's, whose task is the
/// copy's construction and cleanup and the second's.
pub(crate) fn copy_terms<A: Allocator, R>(
    len: u64,
) -> Result<(OperationTerms, InputTerms), BoundedError<R>>
where
    A::Permit: Send,
{
    use super::in_place::InPlace;
    let task = InputTerms::copy::<R>()?;
    let operation = OperationTerms::of::<ByteString, A, R>(
        <CopyInput<'static, 'static, A> as Task<'static, A>>::INIT_STEPS,
        <ByteString as InPlace<A>>::COST
            .bound(len)?
            .then(task.bound()?)?,
    )?;
    Ok((operation, task))
}

/// The [`ResourceBound`] of recording a borrowed input ([`InputBorrow`]):
/// the record and its one field, its completion or its cancelled task's
/// retirement, and the borrow's cleanup unit; the bytes are the caller's.
pub fn borrow_bound<A: Allocator, R>() -> Result<ResourceBound, BoundedError<R>> {
    borrow_terms::<A, R>()?.0.bound()
}

/// The terms of a borrow ([`borrow_bound`]): its operation's, whose task is
/// the second's.
pub(crate) fn borrow_terms<A: Allocator, R>()
-> Result<(OperationTerms, InputTerms), BoundedError<R>> {
    let task = InputTerms::borrow::<R>()?;
    let operation = OperationTerms::of::<Borrowed<'static>, A, R>(
        <BorrowInput<'static, A> as Task<'static, A>>::INIT_STEPS,
        task.bound()?,
    )?;
    Ok((operation, task))
}

/// The terms of an input task's own places, one per [`InputPlace`].
pub(crate) struct InputTerms {
    settle: WriteWork,
    borrow: WriteWork,
}

impl InputTerms {
    /// A copy's: its scope reference retired when cancelled.
    pub(crate) fn copy<R>() -> Result<Self, BoundedError<R>> {
        Ok(Self {
            settle: SETTLE.times(1)?,
            borrow: WriteWork::default(),
        })
    }

    /// A borrow's: its completion or its retirement, and the borrow's own
    /// cleanup.
    pub(crate) fn borrow<R>() -> Result<Self, BoundedError<R>> {
        Ok(Self {
            settle: SETTLE.times(1)?,
            borrow: RETIRE.times(1)?,
        })
    }
}

impl Places for InputTerms {
    type Place = InputPlace;

    fn term(&self, place: InputPlace) -> ResourceBound {
        match place {
            InputPlace::Settle => ResourceBound::of_work(self.settle),
            InputPlace::Borrow => ResourceBound::of_work(self.borrow),
        }
    }
}

pub type InputAcquisition<'src, 's, A> = Operation<'s, CopyInput<'src, 's, A>, A>;
pub type InputBorrow<'s, A> = Operation<'s, BorrowInput<'s, A>, A>;

impl<'s, A: Allocator> DecodeOwner<'s, A> {
    /// Copy immutable bytes incrementally into scope custody. Construction
    /// allocates nothing; initialize the owner first.
    pub fn copy_input<'src>(&self, source: &'src [u8]) -> InputAcquisition<'src, 's, A>
    where
        A::Permit: Send,
    {
        Operation::new(CopyInput {
            source,
            scope: self.reference(),
        })
    }

    /// Record borrowed bytes as an input handle, without copying them.
    pub fn borrow_input(&self, source: &'s [u8]) -> InputBorrow<'s, A> {
        Operation::new(BorrowInput {
            source,
            scope: self.reference(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::reclamation::{Build, Place};
    use super::*;
    use crate::bounded::{Limits, Step};
    use core::{mem::MaybeUninit, ptr::NonNull};

    /// A copy has no prefix of its own: its record is its byte string,
    /// built by `advance`, so an initialization unit is refused and changes
    /// nothing.
    #[test]
    fn a_copy_refuses_an_initialization_unit() {
        let mut task = CopyInput::<'_, 'static, Limits> {
            source: &[1, 2, 3],
            scope: None,
        };
        let mut value = MaybeUninit::<ByteString>::uninit();
        let mut state = <ByteString as Reclaim<Limits>>::INITIAL;
        // SAFETY: the test owns the destination and pairs it with its
        // initial state; nothing else reaches either.
        let slot = unsafe {
            Slot::new(
                Place::<ByteString, Build>::root(NonNull::from(&mut value)),
                &mut state,
            )
        };
        let mut a = Limits::unlimited().logged();
        assert_eq!(
            task.initialize(slot, &mut a),
            Err(BoundedError::PlanMismatch)
        );
        assert_eq!(a.attempts(), 0, "a refused unit admits nothing");
        assert_eq!(
            state.observe(),
            BufferObservation::Unallocated(Default::default())
        );
    }

    /// An operation reports cancelling from its cancellation on, through
    /// its own cleanup to `Finished`; a finished operation is not cancelled
    /// again.
    #[test]
    fn an_operation_reports_cancelling_from_its_cancellation() {
        let mut a = Limits::unlimited();
        let mut owner = DecodeOwner::<'static, Limits>::new();
        owner.initialize_step(&mut a).unwrap();
        let mut copy = owner.copy_input(&[7]);
        assert!(!copy.is_cancelling());
        assert!(
            matches!(copy.step(&mut a).unwrap(), Step::Progress),
            "the record's allocation"
        );
        copy.cancel();
        assert!(copy.is_cancelling());
        let mut finished = false;
        for _ in 0..16 {
            if matches!(copy.step(&mut a).unwrap(), Step::Finished) {
                finished = true;
                break;
            }
        }
        assert!(finished, "the cancelled copy's cleanup did not finish");
        assert!(copy.is_cancelling());
        drop(copy);

        let mut published = owner.copy_input(&[7]);
        let mut input = None;
        for _ in 0..16 {
            if let Step::Complete(record) = published.step(&mut a).unwrap() {
                input = Some(record);
                break;
            }
        }
        let input = input.expect("the copy did not publish");
        published.cancel();
        assert!(
            !published.is_cancelling(),
            "a finished operation was cancelled"
        );
        assert_eq!(input.value().data(), [7]);
        drop((input, published));
        let mut done = false;
        for _ in 0..16 {
            if owner.shutdown_step(&mut a).unwrap() == Reclaimed::Done {
                done = true;
                break;
            }
        }
        assert!(done, "the scope did not shut down");
        assert_eq!(a.live_bytes(), 0);
    }

    /// A borrow cancelled once its record is allocated reclaims the record
    /// in place in one step, then retires its scope reference in the next,
    /// which finishes it.
    #[test]
    fn a_cancelled_borrow_reclaims_its_record_then_retires_its_scope() {
        let mut a = Limits::unlimited();
        let mut owner = DecodeOwner::<'static, Limits>::new();
        owner.initialize_step(&mut a).unwrap();
        let mut borrow = owner.borrow_input(&[1, 2]);
        assert!(
            matches!(borrow.step(&mut a).unwrap(), Step::Progress),
            "the record's allocation"
        );
        assert_eq!(owner.outstanding(), 1);
        borrow.cancel();
        assert!(matches!(borrow.step(&mut a).unwrap(), Step::Progress));
        assert_eq!(owner.outstanding(), 0, "the record was reclaimed in place");
        assert!(borrow.position().detail.scope, "the scope is still held");
        assert!(matches!(borrow.step(&mut a).unwrap(), Step::Finished));
        assert!(!borrow.position().detail.scope, "the scope was retired");
        drop(borrow);
        let mut done = false;
        for _ in 0..4 {
            if owner.shutdown_step(&mut a).unwrap() == Reclaimed::Done {
                done = true;
                break;
            }
        }
        assert!(done, "the scope did not shut down");
        assert_eq!(a.live_bytes(), 0);
    }
}
