//! Parsing an input handle into an owned, retained document.
//!
//! The record pairs the flat node arena with the immutable input it indexes;
//! no other input can be supplied to its views. The parser borrows the input
//! only during each step and retains offsets, scalar progress and scratch.
use core::mem::MaybeUninit;
use core::ptr::addr_of_mut;

use super::input::DecodeInput;
use super::operation::{Observed, Operation, OperationTerms, Task};
use super::reclamation::{
    EMPTIED, Mode, OwnedInitialized, PeekSlot, Place, Prefix, Reclaim, Reclaimed, ScopeRef, Slot,
    reclaim_within, slot_place,
};
use crate::bounded::decode::cursor::{self, ArenaParts, ParserContinuation, Resources};
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
    /// Everything the record holds besides the arena.
    custody: ParseCustody<'s, I, A>,
    arena: MaybeUninit<DocumentArena<A::Permit>>,
}

/// A parse record's own custody ([`super::reclamation::Place::custody`]): its input, its
/// parser, the arena's parts transferred and released, and its phase.
/// Initialized field by field; reached whole, once initialized, through one
/// exclusive borrow of the record's progress, its fields then borrowing
/// disjointly. The arena, which a published document's views borrow, lies
/// outside it; its parts are its custody, paired with its place in one slot
/// for its transfer and its release.
struct ParseCustody<'s, I: DecodeInput<A>, A: Allocator> {
    input: Option<OwnedInitialized<'s, I, A>>,
    parser: MaybeUninit<ParserContinuation<(), A::Permit>>,
    /// Arena parts transferred from the parser, then released.
    parts: ArenaParts,
    phase: ParsePhase,
}

impl<'s, I: DecodeInput<A>, A: Allocator> Parsed<'s, I, A> {
    const PREFIX: usize = 4;
    const INIT_STEPS: usize = Self::PREFIX + ParserContinuation::<(), A::Permit>::INIT_STEPS;

    /// The arena's place within the record, by field projection alone: the
    /// one way its transfer and its release reach it, each paired with the
    /// record's arena parts. A published document's views borrow the arena,
    /// so it is never reborrowed through the record.
    fn arena(slot: &mut Slot<'_, Self, Prefix>) -> Place<DocumentArena<A::Permit>> {
        let (place, _) = slot.parts();
        // SAFETY: a field projection by raw pointer within the slot's own
        // record, forming no reference; `MaybeUninit` lays out its value at
        // its start.
        unsafe {
            place.project(|record| addr_of_mut!((*record).arena).cast::<DocumentArena<A::Permit>>())
        }
    }

    /// The record's whole custody, for as long as the slot is borrowed;
    /// refused unless its progress records every custody field initialized,
    /// the parser's prefix included.
    fn custody<'p, M: Mode, R>(
        slot: &'p mut Slot<'_, Self, Prefix, M>,
    ) -> Result<&'p mut ParseCustody<'s, I, A>, BoundedError<R>> {
        let (place, prefix) = slot.parts();
        if prefix.initialized() < Self::INIT_STEPS {
            return Err(BoundedError::PlanMismatch);
        }
        // SAFETY: the slot pairs the record's place with its progress, which
        // records every custody field initialized; the custody field is
        // disjoint from the arena, no place lies within it, and no document
        // view borrows it.
        Ok(unsafe { place.custody(prefix, |record| addr_of_mut!((*record).custody)) })
    }

    /// The input slot alone, for as long as the slot is borrowed: what the
    /// record holds before its other custody fields are initialized, and what
    /// `into_input` gives up; `None` before the input field is initialized.
    fn input<'p, M: Mode>(
        slot: &'p mut Slot<'_, Self, Prefix, M>,
    ) -> Option<&'p mut Option<OwnedInitialized<'s, I, A>>> {
        let (place, prefix) = slot.parts();
        if prefix.initialized() == 0 {
            return None;
        }
        // SAFETY: the slot pairs the record's place with its progress, which
        // records the input field initialized; the projection reaches that
        // field alone.
        Some(unsafe { place.custody(prefix, |record| addr_of_mut!((*record).custody.input)) })
    }
}

// SAFETY: the initialization prefix is the input handle, scalar metadata and
// the parser's resource-free prefix. Cleanup releases arena, parser, then the
// input, in place; it never reads the arena before transfer recorded it.
unsafe impl<'s, I: DecodeInput<A>, A: Allocator> Reclaim<A> for Parsed<'s, I, A> {
    const DISPATCH_DEPTH: usize = I::DISPATCH_DEPTH.saturating_add(2);
    type State = Prefix;
    const INITIAL: Prefix = Prefix::EMPTY;

    fn reclaim_step(mut slot: Slot<'_, Self, Prefix>, a: &mut A) -> BoundedResult<Reclaimed, A> {
        if slot.custody().initialized() < Self::INIT_STEPS {
            if let Some(input) = Self::input(&mut slot)
                && input.is_some()
            {
                at(ParsePlace::Input, || {
                    OwnedInitialized::reclaim_step(input, a)
                })?;
                return Ok(Reclaimed::Progress);
            }
            CLEANUP.admit(a)?;
            *slot.custody() = Prefix::EMPTY;
            return Ok(Reclaimed::Done);
        }
        // The arena is reached only by raw pointer, taken before the custody
        // is borrowed.
        let arena = Self::arena(&mut slot);
        let ParseCustody {
            input,
            parser,
            parts,
            phase,
        } = Self::custody(&mut slot)?;
        match *phase {
            ParsePhase::ReclaimArena => {
                // SAFETY: the record's parts are its arena's own custody:
                // they count exactly the parts its transfer wrote and its
                // release released.
                let arena = unsafe { Slot::new(arena, parts) };
                if at(ParsePlace::Cleanup, || {
                    DocumentArena::release_parts_step(arena, a)
                })? {
                    *phase = ParsePhase::ReclaimParser;
                }
            }
            ParsePhase::ReclaimParser => {
                // SAFETY: the parser prefix is complete.
                let parser = unsafe { parser.assume_init_mut() };
                if at(ParsePlace::Parse, || parser.reclaim_step(a))? {
                    *phase = ParsePhase::ReclaimInput;
                }
            }
            ParsePhase::ReclaimInput => {
                let charge = slot_place(input, ParsePlace::Input, ParsePlace::Cleanup);
                if at(charge, || OwnedInitialized::reclaim_step(input, a))? == Reclaimed::Done {
                    *phase = ParsePhase::Done;
                    return Ok(Reclaimed::Done);
                }
            }
            ParsePhase::Done => return Ok(Reclaimed::Done),
            _ => {
                CLEANUP.admit(a)?;
                *phase = ParsePhase::ReclaimArena;
            }
        }
        Ok(Reclaimed::Progress)
    }

    /// Before initialization completes, the held input's own calls, then the
    /// one releasing the record. After it: the transition into cleanup unless
    /// it has begun, the arena's parts not yet released, the parser's own
    /// count and the input slot's.
    fn remaining(mut slot: PeekSlot<'_, Self, Prefix>) -> u64 {
        if slot.custody().initialized() < Self::INIT_STEPS {
            return match Self::input(&mut slot) {
                Some(input) if input.is_some() => {
                    OwnedInitialized::remaining(input).saturating_add(1)
                }
                _ => 1,
            };
        }
        // The arena, which a document view borrows, is never reborrowed.
        let Ok(ParseCustody {
            input,
            parser,
            parts,
            phase,
        }) = Self::custody::<_, ()>(&mut slot)
        else {
            return 1;
        };
        let (released, phase) = (parts.released, *phase);
        let input = OwnedInitialized::remaining(input);
        // SAFETY: a complete prefix includes the parser's.
        let parser = unsafe { parser.assume_init_ref() }
            .reclaim_remaining()
            .saturating_add(input);
        let arena = DocumentArena::<A::Permit>::release_remaining(released).saturating_add(parser);
        match phase {
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

    fn initialize(
        &mut self,
        mut slot: Slot<'_, Self::State, Prefix>,
        a: &mut A,
    ) -> Result<(), Self::Error> {
        let prefix = Parsed::<'s, I, A>::PREFIX;
        let (place, progress) = slot.parts();
        if progress.initialized() >= Self::INIT_STEPS {
            return Err(BoundedError::PlanMismatch.into());
        }
        let raw = place.as_ptr(progress);
        match progress.initialized() {
            // SAFETY: the slot pairs the record's place with its progress, so
            // the custody field the progress names next is a field of the
            // record's valid destination, reached by field syntax.
            0 => unsafe { field(addr_of_mut!((*raw).custody.input), || self.input.take(), a)? },
            // SAFETY: as above.
            1 => unsafe { field(addr_of_mut!((*raw).custody.parts.transferred), || 0, a)? },
            // SAFETY: as above.
            2 => unsafe { field(addr_of_mut!((*raw).custody.parts.released), || 0, a)? },
            // SAFETY: as above.
            3 => unsafe { field(addr_of_mut!((*raw).custody.phase), || ParsePhase::Parse, a)? },
            n => {
                let mut units = n - prefix;
                // SAFETY: the parser's place is a field of the record's
                // destination, by field syntax, `MaybeUninit` laying out its
                // value at its start; its units are its own: the record's
                // units are initialized in order, so its progress less the
                // custody fields before it is what the parser holds.
                let parser = unsafe {
                    Slot::new(
                        place.project(|record| {
                            addr_of_mut!((*record).custody.parser)
                                .cast::<ParserContinuation<(), A::Permit>>()
                        }),
                        &mut units,
                    )
                };
                ParserContinuation::initialize_step(parser, (), self.options, a)?;
                progress.set(units + prefix);
                return Ok(());
            }
        }
        progress.advance();
        Ok(())
    }

    fn advance(
        &mut self,
        mut slot: Slot<'_, Self::State, Prefix>,
        a: &mut A,
    ) -> Result<bool, Self::Error> {
        // The arena is reached only by raw pointer, taken before the custody
        // is borrowed; the custody is refused until initialization is
        // complete.
        let arena = Parsed::arena(&mut slot);
        let ParseCustody {
            input,
            parser,
            parts,
            phase,
        } = Parsed::custody(&mut slot)?;
        // SAFETY: a complete prefix includes the parser's.
        let parser = unsafe { parser.assume_init_mut() };
        match *phase {
            ParsePhase::Parse => {
                if parser.ready_to_publish() {
                    TRANSITION.admit(a)?;
                    *phase = ParsePhase::Transfer;
                } else {
                    let input = input
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
                // SAFETY: the record's parts are its arena's own custody:
                // they count exactly the parts its transfer has written.
                let arena = unsafe { Slot::new(arena, parts) };
                if at(ParsePlace::Transfer, || parser.publish_arena_step(arena, a))? {
                    *phase = ParsePhase::ReleaseParser;
                }
            }
            ParsePhase::ReleaseParser => {
                if at(ParsePlace::Parse, || parser.reclaim_step(a))? {
                    *phase = ParsePhase::Publish;
                }
            }
            ParsePhase::Publish => {
                PUBLISH.admit(a)?;
                *phase = ParsePhase::Published;
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

    fn detail(&self, record: Observed<'_, 's, Self, A>) -> ParseDetail {
        // Before the record is complete only whether the input is held is
        // known: the record takes it with its first prefix unit; before that,
        // and when no record exists, the task holds it.
        let incomplete = |input| ParseDetail {
            input,
            phase: None,
            parser: None,
            resources: None,
            transferred: 0,
            released: 0,
        };
        let Some(mut slot) = record else {
            return incomplete(self.input.is_some());
        };
        let (place, prefix) = slot.parts();
        let initialized = prefix.initialized();
        if initialized < Self::INIT_STEPS {
            return incomplete(if initialized > 0 {
                // SAFETY: a nonempty prefix includes the input field, read
                // through a view of that field alone.
                unsafe {
                    place
                        .project(|record| addr_of_mut!((*record).custody.input))
                        .get(&*prefix)
                        .is_some()
                }
            } else {
                self.input.is_some()
            });
        }
        // SAFETY: a complete prefix initializes the whole custody, the
        // parser's prefix included, read through one shared view of it; the
        // arena, which a document view borrows, is not read.
        let custody = unsafe {
            place
                .project(|record| addr_of_mut!((*record).custody))
                .get(&*prefix)
        };
        // SAFETY: a complete prefix includes the parser's.
        let parser = unsafe { custody.parser.assume_init_ref() };
        ParseDetail {
            input: custody.input.is_some(),
            phase: Some(custody.phase),
            parser: Some(parser.position()),
            resources: Some(parser.resources()),
            transferred: custody.parts.transferred,
            released: custody.parts.released,
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
        match self.state().custody.input.as_ref() {
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
        // The published record's slot; the input slot is its own custody,
        // reached alone; the arena, which views borrow, is not touched.
        // Moving the handle out leaves a reclaimable state: cleanup of an
        // absent input completes immediately.
        let mut slot = self.record.destination();
        match Parsed::input(&mut slot).and_then(Option::take) {
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
