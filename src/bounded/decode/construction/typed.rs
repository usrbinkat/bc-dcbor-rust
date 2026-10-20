//! Owner-backed decoding into one stable lifecycle record.
use super::in_place::{Built, InPlace};
use super::reclamation::{Cursor, Initialized, Reclaim, Reclaimed, Record, ScopedReclaimer};
use crate::bounded::decode::{
    ConstructResult, DecodeError, Document, Options,
    cursor::{DecodeStep, Decoder, Position},
    initialization::field,
};
use crate::bounded::{Allocator, BoundedError, BoundedResult};
use core::{
    mem::MaybeUninit,
    ptr::{NonNull, addr_of_mut},
};

/// Input-scoped custody for parser, construction and published output records.
pub type DecodeOwner<'input, A> = ScopedReclaimer<'input, A>;

mod observation;
pub use observation::TypedPosition;

#[derive(Clone, Copy)]
enum Phase {
    Parse,
    Transfer,
    Build,
    ReleaseDocument,
    ReleaseParser,
    Publish,
    ReclaimValue,
    ReclaimDocument,
    ReclaimParser,
    Done,
}

struct State<'input, T, P> {
    parser: MaybeUninit<Decoder<'input, P>>,
    document: MaybeUninit<Document<'input, P>>,
    value: MaybeUninit<T>,
    build: Cursor,
    document_initialized: usize,
    document_released: usize,
    phase: Phase,
}

impl<'input, T, P> State<'input, T, P> {
    const INIT_STEPS: usize = 4 + Decoder::<P>::INIT_STEPS;

    unsafe fn initialize<A: Allocator<Permit = P>>(
        place: *mut Self,
        input: &'input [u8],
        options: Options,
        cursor: &mut Cursor,
        a: &mut A,
    ) -> BoundedResult<bool, A> {
        unsafe {
            match cursor.position {
                0 => field(addr_of_mut!((*place).build), Cursor::default, a)?,
                1 => field(addr_of_mut!((*place).document_initialized), || 0, a)?,
                2 => field(addr_of_mut!((*place).document_released), || 0, a)?,
                3 => field(addr_of_mut!((*place).phase), || Phase::Parse, a)?,
                n if n < Self::INIT_STEPS => {
                    let mut sub = n - 4;
                    Decoder::initialize_step(
                        addr_of_mut!((*place).parser).cast(),
                        input,
                        options,
                        &mut sub,
                        a,
                    )?;
                    cursor.position = sub + 4;
                    return Ok(cursor.position == Self::INIT_STEPS);
                }
                _ => return Err(BoundedError::PlanMismatch),
            }
        }
        cursor.position += 1;
        Ok(false)
    }

    fn advance<A: Allocator<Permit = P>>(&mut self, a: &mut A) -> ConstructResult<bool, A>
    where
        T: InPlace<A>,
    {
        // SAFETY: advance is called only after all parser metadata is initialized.
        let parser = unsafe { self.parser.assume_init_mut() };
        match self.phase {
            Phase::Parse => {
                if parser.ready_to_publish() {
                    a.traverse(1, 0).map_err(BoundedError::Refused)?;
                    self.phase = Phase::Transfer;
                } else {
                    match parser.step(a)? {
                        DecodeStep::Progress => {}
                        _ => return Err(BoundedError::PlanMismatch.into()),
                    }
                }
            }
            Phase::Transfer => {
                if unsafe {
                    parser.publish_step(
                        self.document.as_mut_ptr(),
                        &mut self.document_initialized,
                        a,
                    )?
                } {
                    self.phase = Phase::Build;
                }
            }
            Phase::Build => {
                // SAFETY: the transfer committed every document field. The value
                // and its initialization cursor remain in this same allocation.
                let document = unsafe { self.document.assume_init_ref() };
                let place = NonNull::from(&mut self.value);
                if unsafe { T::build_step(document, 0, place, &mut self.build, a)? } == Built::Done
                {
                    self.phase = Phase::ReleaseDocument;
                }
            }
            Phase::ReleaseDocument => {
                if unsafe {
                    Document::release_parts_step(
                        self.document.as_mut_ptr(),
                        self.document_initialized,
                        &mut self.document_released,
                        a,
                    )?
                } {
                    self.phase = Phase::ReleaseParser;
                }
            }
            Phase::ReleaseParser => {
                if parser.reclaim_step(a)? {
                    a.traverse(1, 0).map_err(BoundedError::Refused)?;
                    self.phase = Phase::Publish;
                }
            }
            Phase::Publish => {
                a.traverse(1, 0).map_err(BoundedError::Refused)?;
                return Ok(true);
            }
            _ => return Err(BoundedError::PlanMismatch.into()),
        }
        Ok(false)
    }
}

// SAFETY: a partial metadata prefix owns no resources. Operational records
// retain all value, document and parser cleanup progress in this allocation.
// No whole-state destructor is invoked, and no cleanup transition allocates.
unsafe impl<'input, T: InPlace<A>, P, A: Allocator<Permit = P>> Reclaim<A> for State<'input, T, P> {
    const DISPATCH_DEPTH: usize = T::DISPATCH_DEPTH.saturating_add(1);

    unsafe fn reclaim_step(
        place: NonNull<MaybeUninit<Self>>,
        cursor: &mut Cursor,
        a: &mut A,
    ) -> BoundedResult<Reclaimed, A> {
        if cursor.position < Self::INIT_STEPS {
            a.traverse(1, 0).map_err(BoundedError::Refused)?;
            return Ok(Reclaimed::Done);
        }
        let state = unsafe { &mut *place.as_ptr().cast::<Self>() };
        match state.phase {
            Phase::ReclaimValue => {
                if unsafe { T::reclaim_step(NonNull::from(&mut state.value), &mut state.build, a)? }
                    == Reclaimed::Done
                {
                    state.phase = Phase::ReclaimDocument;
                }
            }
            Phase::ReclaimDocument => {
                if unsafe {
                    Document::release_parts_step(
                        state.document.as_mut_ptr(),
                        state.document_initialized,
                        &mut state.document_released,
                        a,
                    )?
                } {
                    state.phase = Phase::ReclaimParser;
                }
            }
            Phase::ReclaimParser => {
                if unsafe { state.parser.assume_init_mut() }.reclaim_step(a)? {
                    state.phase = Phase::Done;
                    return Ok(Reclaimed::Done);
                }
            }
            Phase::Done => return Ok(Reclaimed::Done),
            _ => {
                a.traverse(1, 0).map_err(BoundedError::Refused)?;
                state.phase = Phase::ReclaimValue;
            }
        }
        Ok(Reclaimed::Progress)
    }
}

/// Pointer-only published output. Dropping it transfers the same lifecycle
/// record to DecodeOwner; callers explicitly step the owner to reclaim it.
///
/// A value borrow cannot outlive the handle that prevents reclamation:
///
/// ```compile_fail,E0515
/// use dcbor::bounded::{Allocator, decode::construction::TypedValue};
/// fn escape<'a, A: Allocator>(value: TypedValue<'_, '_, String, A>) -> &'a String {
///     value.value()
/// }
/// ```
pub struct TypedValue<'input, 'owner, T: InPlace<A>, A: Allocator> {
    record: Initialized<'owner, State<'input, T, A::Permit>, A>,
}

impl<T: InPlace<A>, A: Allocator> TypedValue<'_, '_, T, A> {
    pub fn value(&self) -> &T {
        // SAFETY: only the Publish phase constructs this wrapper, after the
        // builder returned Done and all parser/document resources were drained.
        unsafe { self.record.value().value.assume_init_ref() }
    }
}

pub enum TypedStep<'input, 'owner, T: InPlace<A>, A: Allocator> {
    Progress,
    Complete(TypedValue<'input, 'owner, T, A>),
    Finished,
}

/// Constant-size controller. Construction allocates nothing and performs no
/// schema initialization. Every later stage uses the same stable owning record.
///
/// The input remains borrowed until queued records have been reclaimed and the
/// owner has been dropped, even after cancellation drops the controller:
///
/// ```compile_fail,E0502
/// use dcbor::bounded::{Limits, decode::{Options, construction::{DecodeOwner, TypedDecoder}}};
/// let mut input = vec![0x61, b'a'];
/// let owner = DecodeOwner::<Limits>::new();
/// let decoder = TypedDecoder::<String, Limits>::new(&owner, &input, Options::normalizing(8));
/// drop(decoder);
/// input[1] = b'b';
/// drop(owner);
/// ```
///
/// A live controller prevents destruction of its custody owner:
///
/// ```compile_fail,E0505
/// use dcbor::bounded::{Limits, decode::{Options, construction::{DecodeOwner, TypedDecoder}}};
/// let owner = DecodeOwner::<Limits>::new();
/// let decoder = TypedDecoder::<String, Limits>::new(&owner, &[0x60], Options::normalizing(8));
/// drop(owner);
/// drop(decoder);
/// ```
pub struct TypedDecoder<'input, 'owner, T: InPlace<A>, A: Allocator> {
    owner: &'owner DecodeOwner<'input, A>,
    input: &'input [u8],
    options: Options,
    record: Option<Record<'owner, State<'input, T, A::Permit>, A>>,
    allocation_admitted: bool,
    aborting: bool,
    finished: bool,
}

impl<'input, 'owner, T: InPlace<A> + 'input, A: Allocator> TypedDecoder<'input, 'owner, T, A>
where
    A::Permit: 'input,
{
    pub const fn new(
        owner: &'owner DecodeOwner<'input, A>,
        input: &'input [u8],
        options: Options,
    ) -> Self {
        Self {
            owner,
            input,
            options,
            record: None,
            allocation_admitted: false,
            aborting: false,
            finished: false,
        }
    }

    pub fn cancel(&mut self) {
        self.aborting = true;
    }

    pub fn parser_position(&mut self) -> Option<Position> {
        let record = self.record.as_mut()?;
        let (place, cursor) = unsafe { record.destination() };
        if cursor.position < State::<T, A::Permit>::INIT_STEPS {
            return None;
        }
        let state = unsafe { &*place.as_ptr().cast::<State<'input, T, A::Permit>>() };
        Some(unsafe { state.parser.assume_init_ref() }.position())
    }

    pub fn step(&mut self, a: &mut A) -> ConstructResult<TypedStep<'input, 'owner, T, A>, A> {
        if self.finished {
            return Ok(TypedStep::Finished);
        }
        if self.aborting {
            if Record::reclaim_step(&mut self.record, a)? == Reclaimed::Done {
                self.finished = true;
            }
            return Ok(TypedStep::Progress);
        }
        if self.record.is_none() {
            match self
                .owner
                .allocate_retained(a, &mut self.allocation_admitted)
            {
                Ok(record) => self.record = Some(record),
                Err(error) => {
                    if !matches!(&error, BoundedError::Refused(_)) {
                        self.aborting = true;
                    }
                    return Err(error.into());
                }
            }
            return Ok(TypedStep::Progress);
        }
        let record = self.record.as_mut().ok_or(BoundedError::PlanMismatch)?;
        let (place, cursor) = unsafe { record.destination() };
        let raw = place.as_ptr().cast::<State<'input, T, A::Permit>>();
        let result = if cursor.position < State::<T, A::Permit>::INIT_STEPS {
            unsafe { State::initialize(raw, self.input, self.options, cursor, a) }
                .map(|_| false)
                .map_err(DecodeError::from)
        } else {
            unsafe { &mut *raw }.advance(a)
        };
        match result {
            Ok(false) => Ok(TypedStep::Progress),
            Ok(true) => {
                let record = self.record.take().ok_or(BoundedError::PlanMismatch)?;
                self.finished = true;
                // SAFETY: metadata initialization and typed construction are
                // complete; no subsequent mutable access to the record escapes.
                Ok(TypedStep::Complete(TypedValue {
                    record: unsafe { record.publish() },
                }))
            }
            Err(error) => {
                if !matches!(&error, DecodeError::Resource(BoundedError::Refused(_))) {
                    self.aborting = true;
                }
                Err(error)
            }
        }
    }
}
