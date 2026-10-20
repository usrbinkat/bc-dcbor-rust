//! Owned decoding with temporary input borrows and stable typed publication.
//!
//! Input arrives as an initialized owning resource handle. Its existing custody
//! covers cancellation even before the lifecycle record is allocated. The same
//! scope reclaims input, parser scratch, arena, and typed destination. Retain the
//! scope externally and explicitly drain it after retiring all handles.
use super::in_place::{Built, InPlace};
use super::reclamation::{
    Cursor, OwnedInitialized, OwnedReclaimer, OwnedRecord, Reclaim, Reclaimed,
};
use crate::bounded::decode::{
    ConstructResult, DecodeError, DocumentArena, Options,
    cursor::{DecodeStep, ParserContinuation},
    initialization::field,
};
use crate::bounded::{Allocator, BoundedError, BoundedResult};
use core::{
    mem::MaybeUninit,
    ptr::{NonNull, addr_of_mut},
};

/// Immutable input resource carried by an owning initialized handle.
///
/// # Safety
/// `bytes` must return the same byte sequence throughout this resource's live
/// lifetime, including across calls through other shared aliases. No interior
/// mutation may change those bytes. Reclaim must release associated evidence
/// and reservations incrementally under the Reclaim contract.
pub unsafe trait DecodeInput<A: Allocator>: Reclaim<A> {
    fn bytes(&self) -> &[u8];
}

// SAFETY: ByteString exposes immutable bytes through a shared reference and
// its existing Reclaim binding releases its buffer and permits incrementally.
unsafe impl<A: Allocator> DecodeInput<A> for crate::ByteString {
    fn bytes(&self) -> &[u8] {
        self.data()
    }
}

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
    ReclaimInput,
    Done,
}

struct State<I: DecodeInput<A>, T, A: Allocator> {
    input: Option<OwnedInitialized<I, A>>,
    parser: MaybeUninit<ParserContinuation<(), A::Permit>>,
    document: MaybeUninit<DocumentArena<A::Permit>>,
    value: MaybeUninit<T>,
    build: Cursor,
    initialized: usize,
    released: usize,
    phase: Phase,
}

impl<I: DecodeInput<A>, T: InPlace<A>, A: Allocator> State<I, T, A> {
    const INIT: usize = 5 + ParserContinuation::<(), A::Permit>::INIT_STEPS;

    unsafe fn initialize(
        place: *mut Self,
        input: &mut Option<OwnedInitialized<I, A>>,
        options: Options,
        cursor: &mut Cursor,
        a: &mut A,
    ) -> BoundedResult<(), A> {
        unsafe {
            match cursor.position {
                0 => field(addr_of_mut!((*place).input), || input.take(), a)?,
                1 => field(addr_of_mut!((*place).build), Cursor::default, a)?,
                2 => field(addr_of_mut!((*place).initialized), || 0, a)?,
                3 => field(addr_of_mut!((*place).released), || 0, a)?,
                4 => field(addr_of_mut!((*place).phase), || Phase::Parse, a)?,
                n => {
                    let mut sub = n - 5;
                    ParserContinuation::initialize_step(
                        addr_of_mut!((*place).parser).cast(),
                        (),
                        options,
                        &mut sub,
                        a,
                    )?;
                    cursor.position = sub + 5;
                    return Ok(());
                }
            }
        }
        cursor.position += 1;
        Ok(())
    }

    fn advance(&mut self, a: &mut A) -> ConstructResult<bool, A> {
        let parser = unsafe { self.parser.assume_init_mut() };
        match self.phase {
            Phase::Parse => {
                if parser.ready_to_publish() {
                    a.traverse(1, 0).map_err(BoundedError::Refused)?;
                    self.phase = Phase::Transfer;
                } else {
                    let input = self
                        .input
                        .as_ref()
                        .ok_or(BoundedError::PlanMismatch)?
                        .value()
                        .bytes();
                    if !matches!(parser.step_input(input, a)?, DecodeStep::Progress) {
                        return Err(BoundedError::PlanMismatch.into());
                    }
                }
            }
            Phase::Transfer => {
                if unsafe {
                    parser.publish_arena_step(
                        self.document.as_mut_ptr(),
                        &mut self.initialized,
                        a,
                    )?
                } {
                    self.phase = Phase::Build;
                }
            }
            Phase::Build => {
                let input = self
                    .input
                    .as_ref()
                    .ok_or(BoundedError::PlanMismatch)?
                    .value()
                    .bytes();
                let arena = unsafe { self.document.assume_init_ref() };
                let place = NonNull::from(&mut self.value);
                let built = arena.with_document(input, |document| unsafe {
                    T::build_step(document, 0, place, &mut self.build, a)
                })?;
                if built == Built::Done {
                    self.phase = Phase::ReleaseDocument;
                }
            }
            Phase::ReleaseDocument => {
                if unsafe {
                    DocumentArena::release_parts_step(
                        self.document.as_mut_ptr(),
                        self.initialized,
                        &mut self.released,
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

// SAFETY: cursor tracks the initialized metadata prefix. Once operational, the
// phase and child cursors describe every resource. No ordinary T/I destructor
// runs; the input handle is retired into the same intrusive owner.
unsafe impl<I: DecodeInput<A>, T: InPlace<A>, A: Allocator> Reclaim<A> for State<I, T, A> {
    const DISPATCH_DEPTH: usize = T::DISPATCH_DEPTH.saturating_add(1);
    unsafe fn reclaim_step(
        place: NonNull<MaybeUninit<Self>>,
        cursor: &mut Cursor,
        a: &mut A,
    ) -> BoundedResult<Reclaimed, A> {
        let raw = place.as_ptr().cast::<Self>();
        if cursor.position < Self::INIT {
            a.traverse(
                1,
                core::mem::size_of::<Option<OwnedInitialized<I, A>>>() as u64,
            )
            .map_err(BoundedError::Refused)?;
            if cursor.position > 0 {
                unsafe { core::ptr::drop_in_place(addr_of_mut!((*raw).input)) };
            }
            cursor.position = 0;
            return Ok(Reclaimed::Done);
        }
        let state = unsafe { &mut *raw };
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
                    DocumentArena::release_parts_step(
                        state.document.as_mut_ptr(),
                        state.initialized,
                        &mut state.released,
                        a,
                    )?
                } {
                    state.phase = Phase::ReclaimParser;
                }
            }
            Phase::ReclaimParser => {
                if unsafe { state.parser.assume_init_mut() }.reclaim_step(a)? {
                    state.phase = Phase::ReclaimInput;
                }
            }
            Phase::ReclaimInput => {
                a.traverse(
                    1,
                    core::mem::size_of::<Option<OwnedInitialized<I, A>>>() as u64,
                )
                .map_err(BoundedError::Refused)?;
                state.input = None;
                state.phase = Phase::Done;
                return Ok(Reclaimed::Done);
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

pub struct OwnedTypedValue<I: DecodeInput<A>, T: InPlace<A>, A: Allocator> {
    record: OwnedInitialized<State<I, T, A>, A>,
}
impl<I: DecodeInput<A>, T: InPlace<A>, A: Allocator> OwnedTypedValue<I, T, A> {
    pub fn value(&self) -> &T {
        unsafe { self.record.value().value.assume_init_ref() }
    }
}

pub enum OwnedDecodeStep<I: DecodeInput<A>, T: InPlace<A>, A: Allocator> {
    Progress,
    Complete(OwnedTypedValue<I, T, A>),
    Finished,
}

/// Allocation-free controller over an already-owned input resource. Moving the
/// controller, cleanup authority, or published handle does not move payloads.
pub struct OwnedTypedDecoder<I: DecodeInput<A>, T: InPlace<A>, A: Allocator> {
    record: Option<OwnedRecord<State<I, T, A>, A>>,
    input: Option<OwnedInitialized<I, A>>,
    scope: OwnedReclaimer<A>,
    options: Options,
    admitted: bool,
    aborting: bool,
    finished: bool,
}

impl<I: DecodeInput<A> + 'static, T: InPlace<A> + 'static, A: Allocator + 'static>
    OwnedTypedDecoder<I, T, A>
{
    pub fn new(input: OwnedInitialized<I, A>, options: Options) -> Self {
        let scope = input.scope();
        Self {
            record: None,
            input: Some(input),
            scope,
            options,
            admitted: false,
            aborting: false,
            finished: false,
        }
    }

    pub fn cancel(&mut self) {
        self.aborting = true;
    }

    pub fn step(&mut self, a: &mut A) -> ConstructResult<OwnedDecodeStep<I, T, A>, A> {
        if self.finished {
            return Ok(OwnedDecodeStep::Finished);
        }
        if self.aborting {
            // Retirement itself is constant-sized and allocation-free. Cleanup
            // completion includes the input record transferred by State.
            self.record = None;
            self.input = None;
            if self.scope.step(a)? == Reclaimed::Done {
                self.finished = true;
            }
            return Ok(OwnedDecodeStep::Progress);
        }
        if self.record.is_none() {
            match self.scope.allocate_step(a, &mut self.admitted) {
                Ok(record) => self.record = Some(record),
                Err(error) => {
                    if !matches!(&error, BoundedError::Refused(_)) {
                        self.aborting = true;
                    }
                    return Err(error.into());
                }
            }
            return Ok(OwnedDecodeStep::Progress);
        }
        let record = self.record.as_mut().ok_or(BoundedError::PlanMismatch)?;
        let (place, cursor) = unsafe { record.destination() };
        let raw = place.as_ptr().cast::<State<I, T, A>>();
        let result = if cursor.position < State::<I, T, A>::INIT {
            unsafe { State::initialize(raw, &mut self.input, self.options, cursor, a) }
                .map(|_| false)
                .map_err(DecodeError::from)
        } else {
            unsafe { &mut *raw }.advance(a)
        };
        match result {
            Ok(false) => Ok(OwnedDecodeStep::Progress),
            Ok(true) => {
                let record = self.record.take().ok_or(BoundedError::PlanMismatch)?;
                self.finished = true;
                Ok(OwnedDecodeStep::Complete(OwnedTypedValue {
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
