//! Construction directly into a reclamation-owned stable destination.
use core::mem::MaybeUninit;
use core::ptr::NonNull;

use super::reclamation::{Cursor, Initialized, Reclaim, Reclaimed, Reclaimer, Record};
use super::{node_at, wrong_type};
use crate::bounded::decode::{ConstructResult, Document, Kind};
use crate::bounded::{Allocator, BoundedError, BoundedResult};

#[doc(hidden)]
pub mod enumeration;
#[doc(hidden)]
pub mod fields;
mod optional;
mod stable_option;
pub use stable_option::StableOption;
mod scalars;
pub use optional::Placeholder;
#[doc(hidden)]
pub mod tagged;
pub(crate) mod text;
mod vector;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Built {
    Progress,
    Done,
}

/// Constructs into stable storage and shares its initialization record with
/// mandatory incremental cleanup. Completion carries no value by value.
///
/// # Safety
/// Each write must be admitted before execution. The initial zero cursor means
/// uninitialized storage. Every successful write or acquired resource must be
/// represented in the cursor before returning, including on error. Done means
/// the destination is fully initialized. No pointer may escape construction;
/// cleanup must be valid after every call. There is no synchronous Drop fallback.
pub unsafe trait InPlace<A: Allocator>: Reclaim<A> {
    const OPTIONAL: bool = false;

    /// Construct a present map field, distinct from standalone nullable values.
    ///
    /// # Safety
    /// The destination and cursor satisfy build_step's requirements.
    unsafe fn build_present(
        document: &Document<'_, A::Permit>,
        index: usize,
        place: NonNull<MaybeUninit<Self>>,
        cursor: &mut Cursor,
        allocator: &mut A,
    ) -> ConstructResult<Built, A> {
        unsafe { Self::build_step(document, index, place, cursor, allocator) }
    }
    /// Initialize an omitted map field. Required fields reject omission.
    ///
    /// # Safety
    /// The destination and cursor satisfy the same requirements as build_step.
    unsafe fn build_absent(
        _place: NonNull<MaybeUninit<Self>>,
        _cursor: &mut Cursor,
        _allocator: &mut A,
    ) -> ConstructResult<Built, A> {
        Err(crate::bounded::decode::DecodeError::Invalid(
            crate::Error::MissingMapKey,
        ))
    }
    /// # Safety
    /// The destination is unique, stable, and paired with this cursor for its
    /// entire construction and reclamation lifetime.
    unsafe fn build_step(
        document: &Document<'_, A::Permit>,
        index: usize,
        place: NonNull<MaybeUninit<Self>>,
        cursor: &mut Cursor,
        allocator: &mut A,
    ) -> ConstructResult<Built, A>;
}

pub enum Step<'r, T: Reclaim<A>, A: Allocator> {
    Progress,
    Complete(Initialized<'r, T, A>),
    Finished,
}

/// In-place construction after parsing. Cancellation and failure hand off the
/// same pre-established record used during construction; no value is assembled.
pub struct Construction<'d, 'input, 'r, T: InPlace<A>, A: Allocator> {
    document: &'d Document<'input, A::Permit>,
    index: usize,
    destination: Destination<'r, T, A>,
}

/// Retained construction custody independent of a document borrow. A decoder
/// can own both its parsed document and this destination without self-borrows.
/// Dropping this controller transfers its existing record to the reclaimer.
pub struct Destination<'r, T: InPlace<A>, A: Allocator> {
    owner: &'r Reclaimer<A>,
    record: Option<Record<'r, T, A>>,
    allocation_admitted: bool,
    phase: Phase,
}

#[derive(Clone, Copy)]
enum Phase {
    Allocate,
    Build,
    Publish,
    Abort,
    Finished,
}

impl<'d, 'input, 'r, T: InPlace<A> + 'static, A: Allocator> Construction<'d, 'input, 'r, T, A> {
    pub fn new(
        owner: &'r Reclaimer<A>,
        document: &'d Document<'input, A::Permit>,
        index: usize,
    ) -> Self {
        Self {
            document,
            index,
            destination: Destination::new(owner),
        }
    }

    pub fn step(&mut self, a: &mut A) -> ConstructResult<Step<'r, T, A>, A> {
        // SAFETY: this wrapper retains the same immutable document and root
        // index for the destination's entire construction lifetime.
        unsafe { self.destination.step(self.document, self.index, a) }
    }
}

impl<'r, T: InPlace<A> + 'static, A: Allocator> Destination<'r, T, A> {
    pub const fn new(owner: &'r Reclaimer<A>) -> Self {
        Self {
            owner,
            record: None,
            allocation_admitted: false,
            phase: Phase::Allocate,
        }
    }

    /// Permanently stop construction. This transfers no value and allocates
    /// nothing; reclaim_step must subsequently drain the retained record.
    pub fn cancel(&mut self) {
        if !matches!(self.phase, Phase::Finished) {
            self.phase = Phase::Abort;
        }
    }

    /// Drain the record without needing access to the source document.
    pub fn reclaim_step(&mut self, a: &mut A) -> BoundedResult<Reclaimed, A> {
        self.cancel();
        let result = Record::reclaim_step(&mut self.record, a)?;
        if result == Reclaimed::Done {
            self.phase = Phase::Finished;
        }
        Ok(result)
    }

    /// # Safety
    /// The document and root index must remain the same across construction
    /// calls. They are only borrowed for this transition, never stored in T.
    pub unsafe fn step(
        &mut self,
        document: &Document<'_, A::Permit>,
        index: usize,
        a: &mut A,
    ) -> ConstructResult<Step<'r, T, A>, A> {
        match self.phase {
            Phase::Allocate => {
                let record = match self
                    .owner
                    .allocate_retained::<T>(a, &mut self.allocation_admitted)
                {
                    Ok(record) => record,
                    Err(error) => {
                        if !matches!(&error, BoundedError::Refused(_)) {
                            self.phase = Phase::Abort;
                        }
                        return Err(error.into());
                    }
                };
                self.record = Some(record);
                self.phase = Phase::Build;
                Ok(Step::Progress)
            }
            Phase::Build => {
                let record = self.record.as_mut().ok_or(BoundedError::PlanMismatch)?;
                // SAFETY: the record owns the unique stable destination; the
                // unsafe InPlace implementation tracks partial initialization.
                let result = unsafe {
                    let (place, cursor) = record.destination();
                    T::build_step(document, index, place, cursor, a)
                };
                match result {
                    Ok(Built::Progress) => Ok(Step::Progress),
                    Ok(Built::Done) => {
                        self.phase = Phase::Publish;
                        Ok(Step::Progress)
                    }
                    Err(error) => {
                        if !matches!(
                            &error,
                            crate::bounded::decode::DecodeError::Resource(BoundedError::Refused(_))
                        ) {
                            self.phase = Phase::Abort;
                        }
                        Err(error)
                    }
                }
            }
            Phase::Publish => {
                a.traverse(1, 0).map_err(BoundedError::Refused)?;
                let record = self.record.take().ok_or(BoundedError::PlanMismatch)?;
                self.phase = Phase::Finished;
                // SAFETY: the preceding build step returned Done; no further
                // construction access to this destination is possible.
                Ok(Step::Complete(unsafe { record.publish() }))
            }
            Phase::Abort => {
                self.reclaim_step(a)?;
                Ok(Step::Progress)
            }
            Phase::Finished => Ok(Step::Finished),
        }
    }
}

macro_rules! integers {
    ($($ty:ty),* $(,)?) => {$(
        // SAFETY: integer storage owns no child resources and has no destructor.
        unsafe impl<A: Allocator> Reclaim<A> for $ty {
            unsafe fn reclaim_step(
                _: NonNull<MaybeUninit<Self>>, cursor: &mut Cursor, a: &mut A,
            ) -> BoundedResult<Reclaimed, A> {
                a.traverse(1, 0).map_err(BoundedError::Refused)?;
                cursor.state = 0;
                Ok(Reclaimed::Done)
            }
        }
        // SAFETY: one admitted scalar write initializes the complete value.
        unsafe impl<A: Allocator> InPlace<A> for $ty {
            unsafe fn build_step(
                document: &Document<'_, A::Permit>, index: usize,
                place: NonNull<MaybeUninit<Self>>, cursor: &mut Cursor, a: &mut A,
            ) -> ConstructResult<Built, A> {
                if cursor.state != 0 { return Err(BoundedError::PlanMismatch.into()); }
                a.traverse(1, core::mem::size_of::<Self>() as u64).map_err(BoundedError::Refused)?;
                let number = match node_at(document, index).map(|node| node.kind()) {
                    Some(Kind::Unsigned(n)) => i128::from(n),
                    Some(Kind::Negative(n)) => i128::from(n),
                    _ => return Err(wrong_type()),
                };
                let value = Self::try_from(number).map_err(|_| crate::bounded::decode::DecodeError::Invalid(crate::Error::OutOfRange))?;
                // SAFETY: caller guarantees unique, aligned scalar storage.
                unsafe { place.as_ptr().write(MaybeUninit::new(value)) };
                cursor.state = 1;
                Ok(Built::Done)
            }
        }
    )*};
}

integers!(u8, u16, u32, u64, usize, i8, i16, i32, i64);
