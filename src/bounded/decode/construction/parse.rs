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
    Cleanup, Custody, EMPTIED, Mode, OwnedInitialized, PeekSlot, Place, Prefix, Reclaim, Reclaimed,
    ScopeRef, Slot, reclaim_within, slot_place,
};
use super::stable::Pending;
use crate::bounded::boundary::{Bound, Predicate};
use crate::bounded::decode::cursor::{self, ArenaParts, ParserContinuation, Resources};
use crate::bounded::decode::initialization::field;
use crate::bounded::decode::{DecodeError, Document, DocumentArena, Node, Options};
use crate::bounded::{
    Allocator, BoundedError, BoundedResult, Custodial, CustodySink, PermitsObserved, Places,
    ResourceBound, Step, Unit, WriteWork, at, observed_all,
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
    parser: MaybeUninit<ParserContinuation<(), A::Permit, A::Origin>>,
    /// Arena parts transferred from the parser, then released.
    parts: ArenaParts,
    phase: ParsePhase,
}

/// Whether the parse record still holds its parser in `phase`: from the end
/// of `ReclaimParser` on, its drained parser has been dropped in place
/// (`Parsed`'s `reclaim_step`), so its storage arenas' owners have released
/// their session references, and nothing reads the parser again.
const fn holds_parser(phase: ParsePhase) -> bool {
    !matches!(phase, ParsePhase::ReclaimInput | ParsePhase::Done)
}

impl<'s, I: DecodeInput<A>, A: Allocator> Parsed<'s, I, A> {
    const PREFIX: usize = 4;
    const INIT_STEPS: usize =
        Self::PREFIX + ParserContinuation::<(), A::Permit, A::Origin>::INIT_STEPS;

    /// The arena's place within the record, in the slot's mode, by field
    /// projection alone: the one way its transfer, its release and its
    /// observation reach it, each paired with the record's arena parts. A
    /// published document's views borrow the arena, so it is never
    /// reborrowed through the record.
    fn arena<M: Mode>(slot: &mut Slot<'_, Self, Prefix, M>) -> Place<DocumentArena<A::Permit>, M> {
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

    /// The record's observation ([`ParseDetail`]), the one every holder of
    /// it reads: its parse task, and a construction holding the published
    /// document ([`OwnedDocument::detail`]). `unwritten` is the input's
    /// observation while the record's input field is not written (a task
    /// that still holds the input, or none). Before the prefix is complete
    /// only the input is known: the record takes it with its first prefix
    /// unit. The held input's state is read through its exclusive custody
    /// ([`OwnedInitialized::state`]): its cleanup is this record's. Only
    /// the recorded prefix is read, the parser only while it is held
    /// (`holds_parser`), the arena never; nothing is changed, admitted or
    /// allocated.
    fn detail<M: Mode>(
        slot: &mut Slot<'_, Self, Prefix, M>,
        unwritten: Option<InputObservation<I, A>>,
    ) -> ParseDetail<InputObservation<I, A>> {
        let incomplete = |input| ParseDetail {
            input,
            phase: None,
            parser: None,
            resources: None,
            transferred: 0,
            released: 0,
        };
        let initialized = slot.parts().1.initialized();
        if initialized < Self::INIT_STEPS {
            return incomplete(match Self::input(slot) {
                Some(input) => input.as_mut().map(OwnedInitialized::state),
                None => unwritten,
            });
        }
        let Ok(ParseCustody {
            input,
            parser,
            parts,
            phase,
        }) = Self::custody::<_, ()>(slot)
        else {
            return incomplete(unwritten);
        };
        // The parser, read only while it is held (`holds_parser`): dropped
        // once drained, it reports no position and no resources.
        let parser = holds_parser(*phase).then(|| {
            // SAFETY: a complete prefix includes the parser's, held in this
            // phase.
            unsafe { parser.assume_init_ref() }
        });
        ParseDetail {
            input: input.as_mut().map(OwnedInitialized::state),
            phase: Some(*phase),
            parser: parser.map(|parser| parser.position()),
            resources: parser.map(|parser| parser.resources()),
            transferred: parts.transferred,
            released: parts.released,
        }
    }
}

/// The observation of an input `I`'s state: what a parse or a construction
/// holding it reads of its cleanup ([`DecodeInput`]).
pub type InputObservation<I, A> = <<I as Reclaim<A>>::State as Custody>::Observation;

/// The class of an input `I`'s state ([`DecodeInput`]'s reduction).
pub type InputClassOf<I, A> = <<I as Reclaim<A>>::State as super::Reduction>::Class;

// SAFETY: initial: no prefix unit initialized and nothing transferred or
// released. state: the initialization prefix (the input handle, scalar
// metadata and the parser's resource-free prefix), the transfer count and
// the release count record everything initialized and acquired. admission:
// each cleanup unit is admitted before it runs, a refusal changing nothing.
// cleanup: it releases the arena, the parser, then the input, in place,
// through their own cleanup, and drops the drained parser in place, which
// releases its arenas' owners' session references; it never reads the arena
// before the transfer recorded it, nor the parser once dropped
// (`holds_parser`); nothing is allocated, nothing unwinds and no arbitrary
// destructor runs. done: `Done` once the arena, the parser and the input are
// all released; an incomplete prefix's release leaves it released
// (`Prefix::release`). order: a step after `Done` reports `Done`, admitting
// nothing, from `ParsePhase::Done` or a released prefix alike; the count and
// observation read only the recorded prefix, nothing of a released one, and
// never the dropped parser. depth: the input's plus two,
// its own level and the input handle's, the census recording the margin.
// count: the units the recorded state leaves.
unsafe impl<'s, I: DecodeInput<A>, A: Allocator> Reclaim<A> for Parsed<'s, I, A> {
    // One level more than its counted dispatches (its own advance, then the
    // input record's advance): the extra level accounts for the stack frames
    // of the input handle's chain between the two, `OwnedInitialized` then
    // `OwnedRecord::reclaim_under`, `reclaim_within` and
    // `Record::reclaim_step`, which are no dispatch level, as the derive's
    // declaration accounts for its generated frames. The census records the
    // margin.
    const DISPATCH_DEPTH: usize = I::DISPATCH_DEPTH.saturating_add(2);
    type State = Prefix;
    const INITIAL: Prefix = Prefix::EMPTY;

    fn reclaim_step(
        mut slot: Slot<'_, Self, Prefix>,
        cleanup: &mut Cleanup<'_, A>,
    ) -> BoundedResult<Reclaimed, A> {
        // Released: terminal, `Done` admitting nothing.
        if slot.custody().released() {
            return Ok(Reclaimed::Done);
        }
        if Bound::new(Predicate::Prefix, Self::INIT_STEPS)
            .below(cleanup, slot.custody().initialized())
        {
            if let Some(input) = Self::input(&mut slot)
                && input.is_some()
            {
                at(ParsePlace::Input, || {
                    OwnedInitialized::reclaim_under(input, cleanup)
                })?;
                return Ok(Reclaimed::Progress);
            }
            CLEANUP.admit(cleanup)?;
            slot.custody().release();
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
                    DocumentArena::release_parts_step(arena, cleanup)
                })? {
                    *phase = ParsePhase::ReclaimParser;
                }
            }
            ParsePhase::ReclaimParser => {
                let drained = at(ParsePlace::Parse, || {
                    // SAFETY: the parser prefix is complete, and the parser
                    // is held until this phase ends (`holds_parser`).
                    unsafe { parser.assume_init_mut() }.reclaim_under(cleanup)
                })?;
                if drained {
                    // The drained parser dropped in place: the record's block
                    // runs no destructor, and the parser's arenas each keep a
                    // pending whose owner holds its session's store until it
                    // drops. Drained, the arenas hold no allocation and their
                    // pendings no credit, and its normalizer is retired, so
                    // the drop frees nothing, records nothing, allocates
                    // nothing and does not unwind (`Storage`'s `Drop`).
                    // SAFETY: the parser is initialized and held in this
                    // phase; the phase moves past it below, and no later
                    // step, count, observation or detail reads it.
                    unsafe { parser.assume_init_drop() };
                    *phase = ParsePhase::ReclaimInput;
                }
            }
            ParsePhase::ReclaimInput => {
                let charge = slot_place(input, ParsePlace::Input, ParsePlace::Cleanup);
                if at(charge, || OwnedInitialized::reclaim_under(input, cleanup))?
                    == Reclaimed::Done
                {
                    *phase = ParsePhase::Done;
                    return Ok(Reclaimed::Done);
                }
            }
            ParsePhase::Done => return Ok(Reclaimed::Done),
            _ => {
                CLEANUP.admit(cleanup)?;
                *phase = ParsePhase::ReclaimArena;
            }
        }
        Ok(Reclaimed::Progress)
    }

    /// Before initialization completes, the held input's own calls, then the
    /// one releasing the record. After it: the transition into cleanup unless
    /// it has begun, the arena's parts not yet released, the parser's own
    /// count and the input slot's.
    fn remaining(mut slot: PeekSlot<'_, Self, Prefix>) -> Option<u64> {
        // Released: the one call reporting `Done`.
        if slot.custody().released() {
            return Some(1);
        }
        if slot.custody().initialized() < Self::INIT_STEPS {
            return match Self::input(&mut slot) {
                Some(input) if input.is_some() => {
                    OwnedInitialized::remaining(input)?.checked_add(1)
                }
                _ => Some(1),
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
            return Some(1);
        };
        let (released, phase) = (parts.released, *phase);
        let input = OwnedInitialized::remaining(input)?;
        // The parser is read only while it is held (`holds_parser`).
        match phase {
            ParsePhase::Done => return Some(1),
            ParsePhase::ReclaimInput => return Some(input),
            _ => {}
        }
        // SAFETY: a complete prefix includes the parser's, held in this phase.
        let parser = unsafe { parser.assume_init_ref() }
            .reclaim_remaining()?
            .checked_add(input)?;
        let arena = DocumentArena::<A::Permit>::release_remaining(released).checked_add(parser)?;
        match phase {
            ParsePhase::ReclaimParser => Some(parser),
            ParsePhase::ReclaimArena => Some(arena),
            _ => arena.checked_add(1),
        }
    }

    /// The record's value's custody, each independently owning part a group
    /// of its own inside the record's ([`CustodySink`]): its input handle,
    /// once initialized and still held, under the owner its own record
    /// stores ([`OwnedInitialized::observe_custody`]); and, once the
    /// prefix is complete, the parser's ([`ParserContinuation::observe_custody`],
    /// its arenas, normalizer and output under their own owners) and the
    /// document arena's at every transfer and release prefix
    /// ([`DocumentArena::observe_prefix`]): the permit the transfer has
    /// moved, under the parser arena's owner until the arena's own owner
    /// field is written and under that field after, so the permit is
    /// reported by exactly one of the parser and the arena. The parser's
    /// resource-free prefix owns nothing. Read-only; the completeness of
    /// every part, combined.
    fn observe_permits(
        mut slot: PeekSlot<'_, Self, Prefix>,
        sink: &mut dyn CustodySink<A::Permit>,
    ) -> PermitsObserved {
        // Released: nothing held, nothing read.
        if slot.custody().released() {
            return PermitsObserved::Complete;
        }
        if slot.custody().initialized() < Self::INIT_STEPS {
            return match Self::input(&mut slot) {
                Some(Some(input)) => input.observe_custody(sink),
                _ => PermitsObserved::Complete,
            };
        }
        // The arena is reached only by raw pointer, taken before the custody
        // is borrowed.
        let arena = Self::arena(&mut slot);
        let Ok(ParseCustody {
            input,
            parser,
            parts,
            phase,
        }) = Self::custody::<_, ()>(&mut slot)
        else {
            return PermitsObserved::Complete;
        };
        let input = match input {
            Some(input) => input.observe_custody(sink),
            None => PermitsObserved::Complete,
        };
        if !holds_parser(*phase) {
            // The parser dropped once drained, and the arena released before
            // it (`ReclaimArena` precedes `ReclaimParser`): only the input
            // remains.
            return input;
        }
        // SAFETY: a complete prefix includes the parser's, held in this phase.
        let parser = unsafe { parser.assume_init_mut() };
        // Read before the traversal borrows the parser exclusively.
        let arena_owner = parser.arena_owner();
        // SAFETY: the record's parts are its arena's own custody: they count
        // exactly the parts its transfer wrote and its release released.
        let arena = unsafe { Slot::new(arena, parts) };
        observed_all([
            input,
            parser.observe_custody(sink),
            DocumentArena::observe_prefix(arena, arena_owner, sink),
        ])
    }
}

/// Observation of a parse, `N` its input's state observation: the record's
/// phase, its parser's position and resources, the arena parts transferred
/// and released, and the input handle's state while the record or, before
/// the record holds it, the task holds it (`None` once neither does). The
/// input's cleanup is the holder's, so its state, not only its presence, is
/// observed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ParseDetail<N> {
    pub phase: Option<ParsePhase>,
    pub parser: Option<cursor::Position>,
    pub resources: Option<Resources>,
    pub transferred: usize,
    pub released: usize,
    pub input: Option<N>,
}

/// Where a parse record's cleanup stands (`Parsed`'s `reclaim_step`): every
/// phase before reclamation enters it by the same admitted unit; the
/// reclaiming phases are distinct.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ParseRecordStage {
    Active,
    ReclaimArena,
    ReclaimParser,
    ReclaimInput,
    Done,
}

/// Where a parser's cleanup stands ([`cursor::ParserContinuation::reclaim_step`]):
/// every parsing phase enters it by the same admitted unit; the reclaiming
/// phases are distinct.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ParserStage {
    Active,
    ReclaimNormalizer,
    ReclaimEntries,
    ReclaimStack,
    Finished,
}

/// What a parse's cleanup admits from its detail ([`ParseDetail`]), `C` its
/// input's class: the record's stage (every phase before reclamation
/// alike), the arena parts released, and its held input by the input's own
/// reduction ([`DecodeInput`]); the parser's stage (every
/// parsing phase alike), its node and frame arenas, each of plain data
/// stepped to its end ([`StorageClass`] under
/// [`ElementCleanup::Discarded`]), and its normalizer's own cleanup once
/// initialized ([`TextClass`]: the parser reads only that it is, not how far
/// a partial initialization went, which owns nothing). A normalized output
/// still held is released in the unit that ends the normalizer's phase, its
/// request having paid for it, admitting nothing more. The input offset,
/// header bytes, payload validated, bytes compared and children completed
/// are never read by cleanup. The arena parts transferred are not part of
/// the class: the arena's release admits its items' unit and its permit's
/// unit whatever was transferred, the count only selecting which written
/// part is dropped in place, which admits nothing
/// (`DocumentArena::release_parts_step`); what the parser still holds of a
/// partial transfer is its node arena's own class (`entries`).
///
/// [`StorageClass`]: crate::bounded::decode::storage::StorageClass
/// [`ElementCleanup::Discarded`]: crate::bounded::decode::storage::ElementCleanup::Discarded
/// [`TextClass`]: crate::bounded::text_cursor::TextClass
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub struct ParseClass<C> {
    pub record: Option<ParseRecordStage>,
    pub parser: Option<ParserStage>,
    pub entries: Option<crate::bounded::decode::storage::StorageClass>,
    pub stack: Option<crate::bounded::decode::storage::StorageClass>,
    pub normalizer: Option<crate::bounded::text_cursor::TextClass>,
    pub released: usize,
    pub input: Option<C>,
}

impl<N> ParseDetail<N> {
    /// This detail with its input's state elided to whether it is held:
    /// what a record of positions of any input, kept in fixed storage,
    /// holds.
    pub fn outline(self) -> ParseDetail<()> {
        ParseDetail {
            phase: self.phase,
            parser: self.parser,
            resources: self.resources,
            transferred: self.transferred,
            released: self.released,
            input: self.input.map(|_| ()),
        }
    }

    /// This detail's class ([`ParseClass`]), its input's by `S`, the
    /// input state's reduction.
    /// The normalizer's class keeps a finished continuation: the parser
    /// steps an initialized normalizer whatever its phase
    /// ([`cursor::ParserContinuation::reclaim_step`]), so its `Finished` unit
    /// is admitted.
    pub fn class<S: super::Reduction<Observation = N>>(&self) -> ParseClass<S::Class> {
        use crate::bounded::decode::storage::ElementCleanup::Discarded;
        use cursor::Phase;
        ParseClass {
            record: self.phase.map(|phase| match phase {
                ParsePhase::Parse
                | ParsePhase::Transfer
                | ParsePhase::ReleaseParser
                | ParsePhase::Publish
                | ParsePhase::Published => ParseRecordStage::Active,
                ParsePhase::ReclaimArena => ParseRecordStage::ReclaimArena,
                ParsePhase::ReclaimParser => ParseRecordStage::ReclaimParser,
                ParsePhase::ReclaimInput => ParseRecordStage::ReclaimInput,
                ParsePhase::Done => ParseRecordStage::Done,
            }),
            parser: self.parser.map(|parser| match parser.phase {
                Phase::ReclaimNormalizer => ParserStage::ReclaimNormalizer,
                Phase::ReclaimEntries => ParserStage::ReclaimEntries,
                Phase::ReclaimStack => ParserStage::ReclaimStack,
                Phase::Finished => ParserStage::Finished,
                Phase::Header
                | Phase::Interpret
                | Phase::Utf8
                | Phase::InitializeNormalizer
                | Phase::Normalize
                | Phase::CheckText
                | Phase::Entry
                | Phase::Frame
                | Phase::Complete
                | Phase::Compare
                | Phase::Attach
                | Phase::ReleaseStack
                | Phase::Publish => ParserStage::Active,
            }),
            entries: self
                .resources
                .map(|resources| resources.entries.class(Discarded)),
            stack: self
                .resources
                .map(|resources| resources.stack.class(Discarded)),
            normalizer: self
                .resources
                .and_then(|resources| resources.normalizer)
                .map(|position| position.class()),
            released: self.released,
            input: self.input.as_ref().map(S::class),
        }
    }
}

impl<N> super::operation::Position<ParseDetail<N>> {
    /// A parse's class, its input's by `S`, the input state's reduction.
    /// The operation's part reads its prefix as partial: before the record's
    /// prefix is complete its cleanup (`Parsed`'s `reclaim_step`,
    /// `remaining`) reads only the input slot, stepping the held input's
    /// own cleanup, which the detail's `input` carries, then releases the
    /// record in one unit; the rest of the prefix is scalars and the
    /// parser's resource-free prefix, owning nothing. The parse's own part
    /// follows ([`ParseClass`]). Two positions of one class take each unit
    /// alike and land again in one class.
    pub fn class<S: super::Reduction<Observation = N>>(
        &self,
    ) -> super::operation::OperationClass<ParseClass<S::Class>> {
        self.operation_class(self.partial(), self.detail.class::<S>())
    }
}

/// A parse's class is its position's, its input's by the input state's
/// reduction ([`super::operation::Position::class`]).
impl<'s, I: DecodeInput<A> + 's, A: crate::bounded::TerminalAllocator + 's> super::Reduction
    for DocumentDecoder<'s, I, A>
where
    A::Permit: Send,
{
    type Class = super::operation::OperationClass<ParseClass<InputClassOf<I, A>>>;

    fn class(
        position: &super::operation::Position<ParseDetail<InputObservation<I, A>>>,
    ) -> Self::Class {
        position.class::<I::State>()
    }
}

pub struct Parse<'s, I: DecodeInput<A>, A: Allocator> {
    input: Option<OwnedInitialized<'s, I, A>>,
    options: Options,
}

// SAFETY: prefix: initialization writes the input handle, three scalars,
// then the parser's resource-free prefix, one unit each, recorded as it is
// written; every prefix is reclaimable by `Parsed`'s cleanup, and past
// `INIT_STEPS`, or once released, it refuses, changing nothing. advance:
// refused until the prefix is whole, a released prefix recording none, and
// in every cleanup phase before the parser is borrowed; it keeps every phase
// reclaimable and reports completion only once the document is transferred
// whole. detail: `detail` and
// `observe_custody` read only the recorded prefix, changing, admitting and
// allocating nothing. provenance: every field is reached through the
// record's slot place, by raw projection.
unsafe impl<'s, I: DecodeInput<A> + 's, A: Allocator + 's> Task<'s, A> for Parse<'s, I, A>
where
    A::Permit: Send,
{
    type State = Parsed<'s, I, A>;
    type Output = OwnedDocument<'s, I, A>;
    type Error = DecodeError<A::Refusal>;
    type Detail = ParseDetail<InputObservation<I, A>>;
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
        // A released record is terminal: nothing is written again.
        if progress.released()
            || Bound::new(Predicate::Prefix, Self::INIT_STEPS).reached(a, progress.initialized())
        {
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
                            addr_of_mut!((*record).custody.parser).cast::<ParserContinuation<
                                (),
                                A::Permit,
                                A::Origin,
                            >>()
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

    /// The parse's acquisitions are its parser's arenas', each held in its
    /// own storage's pending inside the record: the operation's pending is
    /// left idle.
    fn advance(
        &mut self,
        mut slot: Slot<'_, Self::State, Prefix>,
        _: &mut Pending<A::Origin>,
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
        // Only the construction phases advance; every cleanup phase is
        // refused before the parser is borrowed, since from `ReclaimInput`
        // on it is dropped (`holds_parser`).
        if !matches!(
            *phase,
            ParsePhase::Parse
                | ParsePhase::Transfer
                | ParsePhase::ReleaseParser
                | ParsePhase::Publish
        ) {
            return Err(BoundedError::PlanMismatch.into());
        }
        // SAFETY: a complete prefix includes the parser's, held in every
        // construction phase (`holds_parser`).
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

    fn reclaim_step(&mut self, cleanup: &mut Cleanup<'_, A>) -> BoundedResult<Reclaimed, A> {
        let place = slot_place(&self.input, ParsePlace::Input, ParsePlace::Cleanup);
        at(place, || {
            OwnedInitialized::reclaim_under(&mut self.input, cleanup)
        })
    }

    /// The task holds no pending credit of its own: the parser's arenas
    /// keep theirs within the record ([`ParserContinuation`]).
    fn settle(&mut self, _: crate::bounded::Performer) {}

    /// The record's observation ([`Parsed::detail`]), the input the task
    /// still holds observed while the record's input field is unwritten.
    fn detail(&mut self, record: Observed<'_, 's, Self, A>) -> Self::Detail {
        let held = self.input.as_mut().map(OwnedInitialized::state);
        match record {
            Some(mut slot) => Parsed::detail(&mut slot, held),
            None => ParseDetail {
                input: held,
                phase: None,
                parser: None,
                resources: None,
                transferred: 0,
                released: 0,
            },
        }
    }

    /// The task's custody outside its record: the input handle while the
    /// task, not yet its record, holds it, under the owner its own record
    /// stores ([`OwnedInitialized::observe_custody`]). The task holds no
    /// credit of its own ([`Self::settle`]); everything inside the record is
    /// the record's to report ([`Parsed`]'s [`Reclaim::observe_permits`]).
    fn observe_custody(
        &mut self,
        _: Observed<'_, 's, Self, A>,
        sink: &mut dyn CustodySink<A::Permit>,
    ) -> PermitsObserved {
        match self.input.as_mut() {
            Some(input) => input.observe_custody(sink),
            None => PermitsObserved::Complete,
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

    /// Operation-local cleanup of this document, input included, the
    /// cleanup capability minted here over `a`.
    pub fn reclaim_step(slot: &mut Option<Self>, a: &mut A) -> BoundedResult<Reclaimed, A> {
        super::reclamation::with_cleanup(a, |cleanup| Self::reclaim_under(slot, cleanup))
    }

    /// [`Self::reclaim_step`] under `cleanup`, a capability already minted:
    /// how a cleanup that holds the document (a construction's record, or a
    /// third-party binding's state) steps it.
    pub fn reclaim_under(
        slot: &mut Option<Self>,
        cleanup: &mut Cleanup<'_, A>,
    ) -> BoundedResult<Reclaimed, A> {
        reclaim_within(
            slot,
            cleanup,
            |document| document.record,
            |record| Self { record },
            OwnedInitialized::reclaim_under,
        )
    }

    /// The calls [`Self::reclaim_step`] still takes from `slot`
    /// ([`OwnedInitialized::remaining`]), `None` when it does not fit in
    /// `u64`.
    pub(crate) fn remaining(slot: &mut Option<Self>) -> Option<u64> {
        let mut record = slot.take().map(|document| document.record);
        let remaining = OwnedInitialized::remaining(&mut record);
        *slot = record.map(|record| Self { record });
        remaining
    }

    pub(crate) fn scope(&self) -> &ScopeRef<'s, A> {
        self.record.scope()
    }

    /// The document's record observed: what a holder
    /// stepping its cleanup (a construction's record or task) reads of it.
    /// `&mut self` excludes every view of the document meanwhile; nothing is
    /// changed, admitted or allocated.
    pub fn detail(&mut self) -> ParseDetail<InputObservation<I, A>> {
        Parsed::detail(&mut self.record.destination(), None)
    }
}

/// The document's custody: its record's group, under the owner of the
/// acquisition that allocated it, with its input, parser and arena inside
/// (its record's [`Custodial`] traversal); `&mut self` excludes every view of
/// the document meanwhile. Read-only.
impl<I: DecodeInput<A>, A: Allocator> Custodial<A::Permit> for OwnedDocument<'_, I, A> {
    fn observe_custody(&mut self, sink: &mut dyn CustodySink<A::Permit>) -> PermitsObserved {
        self.record.observe_custody(sink)
    }
}

/// The [`ResourceBound`] of parsing an input handle of at most `len` bytes
/// into an owned document ([`DocumentDecoder`]) under `options`: the record,
/// initialized field by field and then the parser's prefix; the retained
/// parse ([`cursor::retained_decode_bound`]), the parser's release and its
/// last cleanup unit included; the arena's transfer, its storage's parts
/// then its owner's identity, one unit each
/// (`DocumentArena::transfer_work`);
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
        let emptied = EMPTIED.times::<R>(1)?;
        Ok(Self {
            parse: cursor::retained_decode_bound::<A::Permit, A::Origin, R>(len, options)?,
            // The transition, then the arena's transfer from its parser.
            transfer: TRANSITION
                .times(1)?
                .checked_then(DocumentArena::<A::Permit>::transfer_work()?)
                .ok_or(BoundedError::Overflow)?,
            publish: PUBLISH.times(1)?,
            // The record's transition, or its release before initialization
            // completed; the arena's parts; and one emptied input slot: the
            // record's after `into_input`, or the task's after the record's
            // first initialization unit took the input, never both, since a
            // record holding its input reclaims it at `Input`.
            cleanup: CLEANUP
                .times(1)?
                .checked_then(DocumentArena::<A::Permit>::release_work()?)
                .and_then(|work| work.checked_then(emptied))
                .ok_or(BoundedError::Overflow)?,
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

impl<'s, I: DecodeInput<A> + 's, A: crate::bounded::TerminalAllocator + 's>
    DocumentDecoder<'s, I, A>
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

/// The parse record's cleanup at every cut of its task
/// ([`super::cuts::every_cut`]): every capability released exactly once,
/// and after `Done`, released prefix or `ParsePhase::Done`, nothing admitted,
/// initialization refused, advance refused before the dropped parser is
/// borrowed, and no parser observed.
#[cfg(all(test, feature = "std"))]
mod released {
    use super::super::cuts::{completed, every_cut, scope};
    use super::*;
    use crate::ByteString;
    use crate::bounded::Limits;

    #[test]
    fn a_parse_records_cleanup_releases_every_capability_and_admits_nothing_after_done() {
        // The text "first", canonical.
        const TEXT: [u8; 6] = [0x65, b'f', b'i', b'r', b's', b't'];
        every_cut(
            "a parse record",
            |a| {
                let owner = scope(a);
                let input = completed(owner.copy_input(&TEXT), a);
                (
                    owner,
                    Parse::<'static, ByteString, Limits> {
                        input: Some(input),
                        options: Options::normalizing(8),
                    },
                )
            },
            |detail: &ParseDetail<_>, released, what| {
                assert_eq!(detail.parser, None, "{what}: a parser observed after Done");
                assert_eq!(
                    detail.resources, None,
                    "{what}: parser resources observed after Done"
                );
                if released {
                    assert_eq!(detail.phase, None, "{what}: a released record's phase read");
                } else {
                    assert_eq!(detail.phase, Some(ParsePhase::Done), "{what}");
                    assert_eq!(detail.input, None, "{what}: the released input observed");
                }
            },
        );
    }
}
