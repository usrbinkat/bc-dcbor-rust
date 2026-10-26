//! Parsing an input handle into an owned, retained document.
//!
//! The record pairs the flat node arena with the immutable input it indexes;
//! no other input can be supplied to its views. The parser borrows the input
//! only during each step and retains offsets, scalar progress and scratch.
use core::mem::MaybeUninit;
use core::ptr::{NonNull, addr_of, addr_of_mut};

use super::input::DecodeInput;
use super::operation::{Operation, OperationTerms, Task};
use super::reclamation::{
    EMPTIED, OwnedInitialized, Prefix, Reclaim, Reclaimed, ScopeRef, reclaim_within, slot_place,
};
use crate::bounded::decode::cursor::{self, ParserContinuation, Resources};
use crate::bounded::decode::initialization::field;
use crate::bounded::decode::{DecodeError, Document, DocumentArena, Node, Options};
use crate::bounded::{
    Allocator, BoundedError, BoundedResult, Places, ResourceBound, Step, Unit, WriteWork, at,
};

places! {
    /// The places a parse's task charges ([`DocumentDecoder`]), one term of
    /// [`parse_bound`]'s task each.
    pub(crate) enum ParsePlace {
        /// The retained parse ([`cursor::retained_decode_bound`]), its cleanup
        /// and its release once the arena is transferred included.
        Parse,
        /// The transition to transfer and the arena's transfer.
        Transfer,
        Publish,
        /// The record's cleanup: its transition, the arena's parts and an
        /// emptied input slot.
        Cleanup,
        /// The input the record holds, accounted by its acquisition
        /// ([`super::copy_bound`], [`super::borrow_bound`]).
        Input,
    }
}

/// A parse record's transition: to transfer, or into its cleanup.
const TRANSITION: Unit<ParsePlace> = Unit::new(ParsePlace::Transfer, 1, 0);

/// A parse record entering its cleanup, or released before its
/// initialization completed.
const CLEANUP: Unit<ParsePlace> = Unit::new(ParsePlace::Cleanup, 1, 0);

/// Publishing the document.
const PUBLISH: Unit<ParsePlace> = Unit::new(ParsePlace::Publish, 1, 0);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ParsePhase {
    Parse,
    Transfer,
    ReleaseParser,
    Publish,
    Published,
    ReclaimArena,
    ReclaimParser,
    ReclaimInput,
    Done,
}

/// The parse record. Public only as the unnameable state of [`Parse`].
pub struct Parsed<'s, I: DecodeInput<A>, A: Allocator> {
    input: Option<OwnedInitialized<'s, I, A>>,
    parser: MaybeUninit<ParserContinuation<(), A::Permit>>,
    arena: MaybeUninit<DocumentArena<A::Permit>>,
    /// Arena parts transferred from the parser.
    transferred: usize,
    /// Arena parts released.
    released: usize,
    phase: ParsePhase,
}

impl<'s, I: DecodeInput<A>, A: Allocator> Parsed<'s, I, A> {
    const PREFIX: usize = 4;
    const INIT_STEPS: usize = Self::PREFIX + ParserContinuation::<(), A::Permit>::INIT_STEPS;
}

// SAFETY: the initialization prefix is the input handle, scalar metadata and
// the parser's resource-free prefix. Cleanup releases arena, parser, then the
// input, in place; it never reads the arena before transfer recorded it.
unsafe impl<'s, I: DecodeInput<A>, A: Allocator> Reclaim<A> for Parsed<'s, I, A> {
    const DISPATCH_DEPTH: usize = I::DISPATCH_DEPTH.saturating_add(2);
    type State = Prefix;
    const INITIAL: Prefix = Prefix::EMPTY;

    unsafe fn reclaim_step(
        place: NonNull<MaybeUninit<Self>>,
        prefix: &mut Prefix,
        a: &mut A,
    ) -> BoundedResult<Reclaimed, A> {
        let raw = place.as_ptr().cast::<Self>();
        if prefix.initialized() < Self::INIT_STEPS {
            if prefix.initialized() > 0 {
                // SAFETY: a nonempty prefix includes the input field.
                let input = unsafe { &mut *addr_of_mut!((*raw).input) };
                if input.is_some() {
                    at(ParsePlace::Input, || {
                        OwnedInitialized::reclaim_step(input, a)
                    })?;
                    return Ok(Reclaimed::Progress);
                }
            }
            CLEANUP.admit(a)?;
            *prefix = Prefix::EMPTY;
            return Ok(Reclaimed::Done);
        }
        // SAFETY: initialization is complete.
        let state = unsafe { &mut *raw };
        match state.phase {
            ParsePhase::ReclaimArena => {
                let arena = state.arena.as_mut_ptr();
                let (transferred, released) = (state.transferred, &mut state.released);
                // SAFETY: transferred counts exactly the arena parts written.
                if at(ParsePlace::Cleanup, || unsafe {
                    DocumentArena::release_parts_step(arena, transferred, released, a)
                })? {
                    state.phase = ParsePhase::ReclaimParser;
                }
            }
            ParsePhase::ReclaimParser => {
                // SAFETY: the parser prefix is complete.
                let parser = unsafe { state.parser.assume_init_mut() };
                if at(ParsePlace::Parse, || parser.reclaim_step(a))? {
                    state.phase = ParsePhase::ReclaimInput;
                }
            }
            ParsePhase::ReclaimInput => {
                let place = slot_place(&state.input, ParsePlace::Input, ParsePlace::Cleanup);
                if at(place, || {
                    OwnedInitialized::reclaim_step(&mut state.input, a)
                })? == Reclaimed::Done
                {
                    state.phase = ParsePhase::Done;
                    return Ok(Reclaimed::Done);
                }
            }
            ParsePhase::Done => return Ok(Reclaimed::Done),
            _ => {
                CLEANUP.admit(a)?;
                state.phase = ParsePhase::ReclaimArena;
            }
        }
        Ok(Reclaimed::Progress)
    }

    /// Before initialization completes, the held input's own calls, then the
    /// one releasing the record. After it: the transition into cleanup unless
    /// it has begun, the arena's parts not yet released, the parser's own
    /// count and the input slot's.
    unsafe fn remaining(place: NonNull<MaybeUninit<Self>>, prefix: &mut Prefix) -> u64 {
        let raw = place.as_ptr().cast::<Self>();
        if prefix.initialized() < Self::INIT_STEPS {
            if prefix.initialized() == 0 {
                return 1;
            }
            // SAFETY: a nonempty prefix includes the input field.
            let input = unsafe { &mut *addr_of_mut!((*raw).input) };
            return match input {
                Some(_) => OwnedInitialized::remaining(input).saturating_add(1),
                None => 1,
            };
        }
        // SAFETY: initialization is complete.
        let state = unsafe { &mut *raw };
        let input = OwnedInitialized::remaining(&mut state.input);
        // SAFETY: a complete prefix includes the parser's.
        let parser = unsafe { state.parser.assume_init_ref() }
            .reclaim_remaining()
            .saturating_add(input);
        let arena =
            DocumentArena::<A::Permit>::release_remaining(state.released).saturating_add(parser);
        match state.phase {
            ParsePhase::Done => 1,
            ParsePhase::ReclaimInput => input,
            ParsePhase::ReclaimParser => parser,
            ParsePhase::ReclaimArena => arena,
            _ => arena.saturating_add(1),
        }
    }
}

/// Observation of a parse: the record's phase, its parser's position and
/// resources, the arena parts transferred and released, and whether the
/// record or, before the record holds it, the task holds the input handle.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ParseDetail {
    pub phase: Option<ParsePhase>,
    pub parser: Option<cursor::Position>,
    pub resources: Option<Resources>,
    pub transferred: usize,
    pub released: usize,
    pub input: bool,
}

pub struct Parse<'s, I: DecodeInput<A>, A: Allocator> {
    input: Option<OwnedInitialized<'s, I, A>>,
    options: Options,
}

// SAFETY: initialization writes the input handle, three scalars, then the
// parser's resource-free prefix; advance keeps every phase reclaimable.
unsafe impl<'s, I: DecodeInput<A> + 's, A: Allocator + 's> Task<'s, A> for Parse<'s, I, A>
where
    A::Permit: Send,
{
    type State = Parsed<'s, I, A>;
    type Output = OwnedDocument<'s, I, A>;
    type Error = DecodeError<A::Refusal>;
    type Detail = ParseDetail;
    const INIT_STEPS: usize = Parsed::<'s, I, A>::INIT_STEPS;

    fn scope(&self) -> Option<&ScopeRef<'s, A>> {
        self.input.as_ref().map(OwnedInitialized::scope)
    }

    fn initialized(prefix: &Prefix) -> usize {
        prefix.initialized()
    }

    unsafe fn initialize(
        &mut self,
        place: *mut Self::State,
        progress: &mut Prefix,
        a: &mut A,
    ) -> Result<(), Self::Error> {
        let prefix = Parsed::<'s, I, A>::PREFIX;
        // SAFETY: each unit writes one uninitialized field of the destination.
        unsafe {
            match progress.initialized() {
                0 => field(addr_of_mut!((*place).input), || self.input.take(), a)?,
                1 => field(addr_of_mut!((*place).transferred), || 0, a)?,
                2 => field(addr_of_mut!((*place).released), || 0, a)?,
                3 => field(addr_of_mut!((*place).phase), || ParsePhase::Parse, a)?,
                n => {
                    let mut sub = n - prefix;
                    ParserContinuation::initialize_step(
                        addr_of_mut!((*place).parser).cast(),
                        (),
                        self.options,
                        &mut sub,
                        a,
                    )?;
                    progress.set(sub + prefix);
                    return Ok(());
                }
            }
        }
        progress.advance();
        Ok(())
    }

    unsafe fn advance(
        &mut self,
        place: NonNull<MaybeUninit<Self::State>>,
        _: &mut Prefix,
        a: &mut A,
    ) -> Result<bool, Self::Error> {
        // SAFETY: initialization is complete.
        let state = unsafe { &mut *place.as_ptr().cast::<Self::State>() };
        let parser = unsafe { state.parser.assume_init_mut() };
        match state.phase {
            ParsePhase::Parse => {
                if parser.ready_to_publish() {
                    TRANSITION.admit(a)?;
                    state.phase = ParsePhase::Transfer;
                } else {
                    let input = state
                        .input
                        .as_ref()
                        .ok_or(BoundedError::PlanMismatch)?
                        .value()
                        .bytes();
                    if !matches!(
                        at(ParsePlace::Parse, || parser.step_input(input, a))?,
                        Step::Progress
                    ) {
                        return Err(BoundedError::PlanMismatch.into());
                    }
                }
            }
            ParsePhase::Transfer => {
                let arena = state.arena.as_mut_ptr();
                let transferred = &mut state.transferred;
                // SAFETY: the arena slot is uninitialized; transferred counts it.
                if at(ParsePlace::Transfer, || unsafe {
                    parser.publish_arena_step(arena, transferred, a)
                })? {
                    state.phase = ParsePhase::ReleaseParser;
                }
            }
            ParsePhase::ReleaseParser => {
                if at(ParsePlace::Parse, || parser.reclaim_step(a))? {
                    state.phase = ParsePhase::Publish;
                }
            }
            ParsePhase::Publish => {
                PUBLISH.admit(a)?;
                state.phase = ParsePhase::Published;
                return Ok(true);
            }
            _ => return Err(BoundedError::PlanMismatch.into()),
        }
        Ok(false)
    }

    fn publish(&mut self, record: OwnedInitialized<'s, Self::State, A>) -> Self::Output {
        OwnedDocument { record }
    }

    fn reclaim_step(&mut self, a: &mut A) -> BoundedResult<Reclaimed, A> {
        let place = slot_place(&self.input, ParsePlace::Input, ParsePlace::Cleanup);
        at(place, || OwnedInitialized::reclaim_step(&mut self.input, a))
    }

    unsafe fn detail(
        &self,
        record: Option<(&mut MaybeUninit<Self::State>, &mut Prefix)>,
    ) -> ParseDetail {
        // The record takes the input with its first prefix unit; before that,
        // and when no record exists, the task holds it.
        let input = match &record {
            Some((storage, prefix)) if prefix.initialized() > 0 => {
                // SAFETY: a nonempty prefix includes the input field, which
                // is read in place without forming a reference to the rest.
                unsafe { (*addr_of!((*storage.as_ptr()).input)).is_some() }
            }
            _ => self.input.is_some(),
        };
        let complete = record
            .filter(|(_, prefix)| prefix.initialized() >= Self::INIT_STEPS)
            // SAFETY: a complete prefix initializes every field but the
            // parser and the arena, which are themselves `MaybeUninit`.
            .map(|(storage, _)| unsafe { storage.assume_init_ref() });
        ParseDetail {
            input,
            phase: complete.map(|state| state.phase),
            // SAFETY: a complete prefix includes the parser's.
            parser: complete.map(|state| unsafe { state.parser.assume_init_ref() }.position()),
            resources: complete.map(|state| unsafe { state.parser.assume_init_ref() }.resources()),
            transferred: complete.map_or(0, |state| state.transferred),
            released: complete.map_or(0, |state| state.released),
        }
    }
}

/// A retained parsed document. Views borrow this handle; its arena is always
/// paired with its original immutable input. Dropping it queues its record.
pub struct OwnedDocument<'s, I: DecodeInput<A>, A: Allocator> {
    record: OwnedInitialized<'s, Parsed<'s, I, A>, A>,
}

impl<'s, I: DecodeInput<A>, A: Allocator> OwnedDocument<'s, I, A> {
    fn state(&self) -> &Parsed<'s, I, A> {
        self.record.value()
    }

    fn input_handle_ref(&self) -> &OwnedInitialized<'s, I, A> {
        // A published document holds its input until `into_input` consumes it.
        match self.state().input.as_ref() {
            Some(input) => input,
            None => unreachable!("a published document retains its input"),
        }
    }

    /// The original input bytes the document indexes. Identity and signature
    /// checks run over these, never over a re-encoding.
    pub fn bytes(&self) -> &[u8] {
        self.input_handle_ref().value().bytes()
    }

    /// The root value, borrowed from this handle.
    pub fn root(&self) -> Node<'_, '_> {
        // SAFETY: a published document's arena is transferred and unreleased.
        unsafe { self.state().arena.assume_init_ref() }.root(self.bytes())
    }

    /// A temporary view of the whole document.
    pub fn with_document<R>(&self, f: impl FnOnce(&Document<'_, A::Permit>) -> R) -> R {
        // SAFETY: a published document's arena is transferred and unreleased.
        unsafe { self.state().arena.assume_init_ref() }.with_document(self.bytes(), f)
    }

    /// The retained input resource, including any custom evidence.
    pub fn input(&self) -> &I {
        self.input_handle_ref().value()
    }

    /// Give up the document and keep its input: the input handle moves out
    /// without copying; the arena is retired through the scope queue.
    pub fn into_input(mut self) -> OwnedInitialized<'s, I, A> {
        // SAFETY: moving the handle out leaves a reclaimable state: cleanup of
        // an absent input completes immediately.
        let state = unsafe { self.record.value_mut() };
        match state.input.take() {
            Some(input) => input,
            None => unreachable!("a published document retains its input"),
        }
    }

    /// Operation-local cleanup of this document, input included.
    pub fn reclaim_step(slot: &mut Option<Self>, a: &mut A) -> BoundedResult<Reclaimed, A> {
        reclaim_within(
            slot,
            a,
            |document| document.record,
            |record| Self { record },
            OwnedInitialized::reclaim_step,
        )
    }

    /// The calls [`Self::reclaim_step`] still takes from `slot`
    /// ([`OwnedInitialized::remaining`]).
    pub(crate) fn remaining(slot: &mut Option<Self>) -> u64 {
        let mut record = slot.take().map(|document| document.record);
        let remaining = OwnedInitialized::remaining(&mut record);
        *slot = record.map(|record| Self { record });
        remaining
    }

    pub(crate) fn scope(&self) -> &ScopeRef<'s, A> {
        self.record.scope()
    }
}

/// The [`ResourceBound`] of parsing an input handle of at most `len` bytes
/// into an owned document ([`DocumentDecoder`]) under `options`: the record,
/// initialized field by field and then the parser's prefix; the retained
/// parse ([`cursor::retained_decode_bound`]), the parser's release and its
/// last cleanup unit included; the arena's transfer in its storage's three
/// units;
/// publication; and the record's own cleanup: its transition, the arena's
/// two parts and the input slot emptied by [`OwnedDocument::into_input`] or
/// by the record's initialization. The input is held by the record but
/// accounted by its acquisition. The document's arena and record are what
/// publication retains.
pub fn parse_bound<I: DecodeInput<A>, A: Allocator, R>(
    len: u64,
    options: Options,
) -> Result<ResourceBound, BoundedError<R>> {
    parse_terms::<I, A, R>(len, options, ResourceBound::default())?
        .0
        .bound()
}

/// The terms of a parse ([`parse_bound`]): its operation's, whose task is
/// the second's, the record holding an input whose own cleanup is `input`.
/// The record's size and initialization do not depend on its scope.
pub(crate) fn parse_terms<I: DecodeInput<A>, A: Allocator, R>(
    len: u64,
    options: Options,
    input: ResourceBound,
) -> Result<(OperationTerms, ParseTerms), BoundedError<R>> {
    let task = ParseTerms::of::<A, R>(len, options, input)?;
    let operation = OperationTerms::of::<Parsed<'static, I, A>, A, R>(
        Parsed::<'static, I, A>::INIT_STEPS,
        task.bound()?,
    )?;
    Ok((operation, task))
}

/// The terms of a parse's task, one per [`ParsePlace`].
pub(crate) struct ParseTerms {
    parse: ResourceBound,
    transfer: WriteWork,
    publish: WriteWork,
    cleanup: WriteWork,
    input: ResourceBound,
}

impl ParseTerms {
    /// The task of parsing `len` bytes under `options`, the record holding
    /// an input whose own cleanup is `input`.
    pub(crate) fn of<A: Allocator, R>(
        len: u64,
        options: Options,
        input: ResourceBound,
    ) -> Result<Self, BoundedError<R>> {
        Ok(Self {
            parse: cursor::retained_decode_bound::<A::Permit, R>(len, options)?,
            // The transition, then the arena's transfer from its parser.
            transfer: TRANSITION
                .times(1)?
                .then(DocumentArena::<A::Permit>::transfer_work()?)?,
            publish: PUBLISH.times(1)?,
            // The record's transition, or its release before initialization
            // completed; the arena's parts; and one emptied input slot: the
            // record's after `into_input`, or the task's after the record's
            // first initialization unit took the input, never both, since a
            // record holding its input reclaims it at `Input`.
            cleanup: CLEANUP
                .times(1)?
                .then(DocumentArena::<A::Permit>::release_work()?)?
                .then(EMPTIED.times(1)?)?,
            input,
        })
    }
}

impl Places for ParseTerms {
    type Place = ParsePlace;

    fn term(&self, place: ParsePlace) -> ResourceBound {
        match place {
            ParsePlace::Parse => self.parse,
            ParsePlace::Transfer => ResourceBound::of_work(self.transfer),
            ParsePlace::Publish => ResourceBound::of_work(self.publish),
            ParsePlace::Cleanup => ResourceBound::of_work(self.cleanup),
            ParsePlace::Input => self.input,
        }
    }
}

pub type DocumentDecoder<'s, I, A> = Operation<'s, Parse<'s, I, A>, A>;

impl<'s, I: DecodeInput<A> + 's, A: Allocator + 's> DocumentDecoder<'s, I, A>
where
    A::Permit: Send,
{
    /// A parse of `input`. Construction allocates nothing.
    pub fn parse(input: OwnedInitialized<'s, I, A>, options: Options) -> Self {
        Operation::new(Parse {
            input: Some(input),
            options,
        })
    }
}
