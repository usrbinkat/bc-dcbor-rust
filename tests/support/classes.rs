//! Cleanup classes of the owned pipeline's stop boundaries.
//!
//! A stop at a boundary (retiring, unwinding or cancelling there) verifies
//! one thing: the cleanup that follows from the state the boundary reached.
//! A class groups boundaries whose cleanup is claimed alike: the same
//! admitted units in the same order, everything released, nothing
//! allocated. Each class below is a projection of the operation's position
//! that keeps everything its cleanup reads and drops counters its cleanup
//! never reads; the argument is stated beside each. The exhaustive layer
//! stops at every member of every class and requires their cleanups to be
//! equal, so a class that merges states of different custody fails there,
//! named.
//!
//! Classes compare boundaries of one pipeline run over one input: the
//! document a construction holds and the input a record holds are the same
//! at every boundary of that run, so a class need not carry their custody.
//!
//! A boundary returns no class when no argument covers it: every stop there
//! runs in both layers.
use core::fmt::Debug;
use dcbor::ByteString;
use dcbor::bounded::Limits;
use dcbor::bounded::decode::construction::in_place::BufferObservation;
use dcbor::bounded::decode::construction::reclamation::{Custody, Reclaim, Reduction};
use dcbor::bounded::decode::construction::{
    ConstructDetail, ConstructPhase, InputDetail, ParseDetail, ParsePhase, Position, TypedPosition,
};
use dcbor::bounded::decode::cursor::Phase as ParserPhase;
use dcbor::bounded::decode::storage::{StoragePosition, StorageStage};
use dcbor::bounded::encoding::{
    OwnedEmitPosition, PlanDetail, PlanPhase, Position as PreparationPosition,
};
use dcbor::bounded::text_cursor::{Phase as TextPhase, Position as TextPosition};

/// A boundary's cleanup class, rendered: classes of different operations
/// and value types compare as their renderings, which name every field.
pub type Class = String;

/// The position of a typed decode of `T`.
pub type Typed<T> = TypedPosition<<<T as Reclaim<Limits>>::State as Custody>::Observation>;

/// The classifiers of one pipeline run: an input acquisition's, a parse's,
/// a typed decode's of the value the run decodes, the owned preparation's of
/// that value's encoding, and its emission's.
pub struct Classes<P> {
    pub input: fn(&Position<InputDetail<BufferObservation>>) -> Option<Class>,
    pub parse: fn(&Position<ParseDetail>) -> Option<Class>,
    pub decode: fn(&P) -> Option<Class>,
    pub prepare: fn(&Position<PlanDetail>) -> Option<Class>,
    pub emit: fn(&OwnedEmitPosition) -> Option<Class>,
}

impl Classes<()> {
    /// Acquisition and inspection: their operations' classes.
    pub fn certified() -> Self {
        Self {
            input,
            parse,
            decode: |_| None,
            prepare,
            emit,
        }
    }
}

impl<P> Classes<P> {
    /// Every boundary its own class: what a planted classifier is compared
    /// against, and what a run claims when it reduces nothing.
    pub fn none() -> Self {
        Self {
            input: |_| None,
            parse: |_| None,
            decode: |_| None,
            prepare: |_| None,
            emit: |_| None,
        }
    }
}

/// A typed decode of `T` whose construction states declare a cleanup
/// reduction: its parse and construction stages both classed.
pub fn reduced<T>() -> Classes<Typed<T>>
where
    T: Reclaim<Limits>,
    T::State: Reduction,
{
    Classes {
        input,
        parse,
        decode: typed::<T>,
        prepare,
        emit,
    }
}

/// A typed decode of `T` whose construction states declare no reduction:
/// its parse stage classed, every construction boundary its own class.
pub fn parsed<T: Reclaim<Limits>>() -> Classes<Typed<T>> {
    Classes {
        input,
        parse,
        decode: |position| match position {
            TypedPosition::Parse(parse_position) => parse(parse_position),
            TypedPosition::Construct(_) | TypedPosition::Finished => None,
        },
        prepare,
        emit,
    }
}

/// How much of a record's prefix its cleanup reads: the exact units
/// written, or, for a record whose cleanup before its prefix is complete
/// reads only what its detail already carries, that the prefix is partial.
#[derive(Debug)]
#[expect(dead_code, reason = "read through the rendering that is the class")]
enum Initialized {
    Units(usize),
    Partial,
}

/// The operation's own part of a class: whether its record is allocated, how
/// much of its prefix is written ([`Initialized`]), whether it is cancelling
/// or finished, and how many records its scope holds. The operation's
/// cleanup reads each: a record's cleanup releases its written prefix, and
/// the scope's drain releases every record it holds.
#[derive(Debug)]
#[expect(dead_code, reason = "read through the rendering that is the class")]
struct Operation<D> {
    allocated: bool,
    initialized: Initialized,
    cancelling: bool,
    finished: bool,
    outstanding: usize,
    detail: D,
}

/// The operation's part of a class, its prefix by its exact units.
fn operation<D, E: Debug>(position: &Position<D>, detail: E) -> Class {
    operation_with(position, Initialized::Units(position.initialized), detail)
}

fn operation_with<D, E: Debug>(
    position: &Position<D>,
    initialized: Initialized,
    detail: E,
) -> Class {
    format!(
        "{:?}",
        Operation {
            allocated: position.allocated,
            initialized,
            cancelling: position.cancelling,
            finished: position.finished,
            outstanding: position.outstanding,
            detail,
        }
    )
}

/// An input copy's class: whether the task holds its scope reference, and
/// its record's byte buffer by the buffer's declared cleanup reduction.
/// The bytes copied so far are dropped: the copy's cleanup drops the
/// buffer whole whatever it holds, which the buffer's reduction states.
pub fn input(position: &Position<InputDetail<BufferObservation>>) -> Option<Class> {
    let record = position
        .detail
        .record
        .map(|record| <<ByteString as Reclaim<Limits>>::State as Reduction>::class(&record));
    Some(operation(position, (position.detail.scope, record)))
}

/// A parse record's cleanup stage: every phase before reclamation enters
/// it by the same unit; the reclaiming phases are distinct.
#[derive(Debug)]
enum RecordStage {
    Active,
    ReclaimArena,
    ReclaimParser,
    ReclaimInput,
    Done,
}

/// A parser's cleanup stage: every parsing phase enters reclamation by the
/// same unit; the reclaiming phases are distinct.
#[derive(Debug)]
enum ParserStage {
    Active,
    ReclaimNormalizer,
    ReclaimEntries,
    ReclaimStack,
    Finished,
}

/// What the cleanup of an arena of plain data reads
/// (`Storage::reclaim_copy_step`): its stage, the permits it holds, and its
/// elements only where they are drained one per unit. Settled with no growth
/// begun, its elements are discarded in one unit whatever their number, so
/// only whether it holds any; with a staged block, the block is released
/// first and the same holds after. While staging, relocating or relocated,
/// each element is drained in its own unit, so their number. Capacities
/// change no unit: each allocation's release is one, paid for by its
/// acquisition.
#[derive(Debug)]
#[expect(dead_code, reason = "read through the rendering that is the class")]
struct Arena {
    stage: StorageStage,
    current_permit: bool,
    staged_permit: bool,
    relocating_permit: bool,
    elements: usize,
}

fn arena(position: &StoragePosition) -> Arena {
    let drained_one_by_one = matches!(
        position.stage,
        StorageStage::Staging(_) | StorageStage::Relocating | StorageStage::Relocated
    );
    Arena {
        stage: position.stage,
        current_permit: position.has_current_permit,
        staged_permit: position.has_staged_permit,
        relocating_permit: position.has_relocating_permit,
        elements: if drained_one_by_one {
            position.initialized + position.relocating_remaining
        } else {
            usize::from(position.initialized > 0)
        },
    }
}

/// A text normalizer's cleanup stage
/// (`TextContinuation::reclaim_step`): every normalizing phase enters
/// reclamation by the same unit; the reclaiming phases are distinct.
#[derive(Debug)]
enum NormalizerStage {
    Active,
    ReclaimOrdering,
    ReclaimChars,
    Finished,
}

/// What a text normalizer's cleanup reads: its stage, its ordering
/// scratch and its characters, each an arena of plain characters. Its
/// read, composition, measurement and emission counters, its pending
/// decomposition and its ordering's counters and run are never read by
/// cleanup. Its output, if one is held, is released in the unit that
/// completes the characters' cleanup, its request having paid for it.
#[derive(Debug)]
#[expect(dead_code, reason = "read through the rendering that is the class")]
struct Normalizer {
    stage: NormalizerStage,
    scratch: Arena,
    chars: Arena,
}

fn normalizer(position: &TextPosition) -> Normalizer {
    Normalizer {
        stage: match position.phase {
            TextPhase::ReclaimOrdering => NormalizerStage::ReclaimOrdering,
            TextPhase::ReclaimChars => NormalizerStage::ReclaimChars,
            TextPhase::Finished => NormalizerStage::Finished,
            TextPhase::Read
            | TextPhase::Append
            | TextPhase::Order
            | TextPhase::ReleaseOrdering
            | TextPhase::Compose
            | TextPhase::Measure
            | TextPhase::ReleaseOutput
            | TextPhase::Allocate
            | TextPhase::Header
            | TextPhase::Emit
            | TextPhase::ReleaseChars
            | TextPhase::Publish => NormalizerStage::Active,
        },
        scratch: arena(&position.ordering_state.scratch),
        chars: arena(&position.characters),
    }
}

/// What a parse's cleanup reads, with the parser's counters dropped.
#[derive(Debug)]
#[expect(dead_code, reason = "read through the rendering that is the class")]
struct Parse {
    record: Option<RecordStage>,
    parser: Option<ParserStage>,
    entries: Option<Arena>,
    stack: Option<Arena>,
    normalizer: Option<Normalizer>,
    normalized: Option<bool>,
    transferred: usize,
    released: usize,
    input: bool,
}

/// A parse's class. The record's cleanup reads its phase (every phase
/// before reclamation alike), the arena parts transferred and released,
/// and its input slot; the parser's cleanup reads its phase (every parsing
/// phase alike), its node and frame arenas, each of plain data
/// ([`arena`]), its normalizer's own cleanup when one is initialized
/// ([`normalizer`]: the parser reads only that it is, not how far a partial
/// initialization went, which owns nothing), and whether a normalized
/// output is held. The input offset, header bytes, payload validated, bytes
/// compared and children completed are never read by cleanup, and are
/// dropped. Before the record's prefix is complete its cleanup
/// (`Parsed::reclaim_step`, `remaining`) reads only whether the input slot
/// is written and holds the input, which the detail's `input` carries, then
/// releases the record in one unit; the rest of the prefix is scalars and
/// the parser's resource-free prefix, owning nothing. So every partial
/// prefix of an allocated record is one class, its exact units dropped. The
/// exhaustive layer stops at every member of every class and requires their
/// cleanups to be equal, so a projection that dropped what cleanup reads
/// fails there, named.
pub fn parse(position: &Position<ParseDetail>) -> Option<Class> {
    let detail = &position.detail;
    let initialized = if position.allocated
        && 0 < position.initialized
        && position.initialized < position.initialization_steps
    {
        Initialized::Partial
    } else {
        Initialized::Units(position.initialized)
    };
    let record = detail.phase.map(|phase| match phase {
        ParsePhase::Parse
        | ParsePhase::Transfer
        | ParsePhase::ReleaseParser
        | ParsePhase::Publish
        | ParsePhase::Published => RecordStage::Active,
        ParsePhase::ReclaimArena => RecordStage::ReclaimArena,
        ParsePhase::ReclaimParser => RecordStage::ReclaimParser,
        ParsePhase::ReclaimInput => RecordStage::ReclaimInput,
        ParsePhase::Done => RecordStage::Done,
    });
    let parser = detail.parser.map(|parser| match parser.phase {
        ParserPhase::ReclaimNormalizer => ParserStage::ReclaimNormalizer,
        ParserPhase::ReclaimEntries => ParserStage::ReclaimEntries,
        ParserPhase::ReclaimStack => ParserStage::ReclaimStack,
        ParserPhase::Finished => ParserStage::Finished,
        ParserPhase::Header
        | ParserPhase::Interpret
        | ParserPhase::Utf8
        | ParserPhase::InitializeNormalizer
        | ParserPhase::Normalize
        | ParserPhase::CheckText
        | ParserPhase::Entry
        | ParserPhase::Frame
        | ParserPhase::Complete
        | ParserPhase::Compare
        | ParserPhase::Attach
        | ParserPhase::ReleaseStack
        | ParserPhase::Publish => ParserStage::Active,
    });
    Some(operation_with(
        position,
        initialized,
        Parse {
            record,
            parser,
            entries: detail.resources.map(|resources| arena(&resources.entries)),
            stack: detail.resources.map(|resources| arena(&resources.stack)),
            normalizer: detail
                .resources
                .and_then(|resources| resources.normalizer)
                .map(|position| normalizer(&position)),
            normalized: detail
                .resources
                .map(|resources| resources.normalized_output),
            transferred: detail.transferred,
            released: detail.released,
            input: detail.input,
        },
    ))
}

/// A construction record's cleanup stage: every phase before reclamation
/// enters it by the same unit; the reclaiming phases are distinct.
#[derive(Debug)]
enum ConstructStage {
    Active,
    ReclaimValue,
    ReclaimDocument,
    ReclaimInput,
    Done,
}

/// What a construction's cleanup reads, its value by the value's declared
/// cleanup reduction.
#[derive(Debug)]
#[expect(dead_code, reason = "read through the rendering that is the class")]
struct Construct<C> {
    record: Option<ConstructStage>,
    document: bool,
    input: bool,
    value: Option<C>,
}

/// A typed decode's class: its parse's, then its construction's. The
/// construction record's cleanup reads its phase (every phase before
/// reclamation alike), its document and input slots, and its value through
/// the value's own cleanup, whose class the value's [`Reduction`] declares.
/// Before the record's prefix is complete its cleanup
/// (`Constructed::reclaim_step`, `remaining`) reads only whether the
/// document slot is written and holds the document, then releases the
/// record in one unit; the rest of the prefix (the empty input slot, the
/// value's initial state, the phase) owns nothing. So every partial prefix
/// of an allocated record is one class, by its document alone.
pub fn typed<T>(position: &Typed<T>) -> Option<Class>
where
    T: Reclaim<Limits>,
    T::State: Reduction,
{
    match position {
        TypedPosition::Parse(parse_position) => parse(parse_position),
        TypedPosition::Construct(construct)
            if construct.allocated
                && 0 < construct.initialized
                && construct.initialized < construct.initialization_steps =>
        {
            Some(operation_with(
                construct,
                Initialized::Partial,
                Construct::<<T::State as Reduction>::Class> {
                    record: None,
                    document: construct.detail.document,
                    input: false,
                    value: None,
                },
            ))
        }
        TypedPosition::Construct(construct) => Some(operation(
            construct,
            construction::<T::State>(&construct.detail),
        )),
        TypedPosition::Finished => Some("finished".into()),
    }
}

/// An owned preparation record's cleanup stage (`Planned::reclaim_step`):
/// preparing and published alike enter reclamation by the same unit; the
/// reclaiming phases are distinct.
#[derive(Debug)]
enum PlanStage {
    Active,
    ReclaimPreparation,
    ReclaimSource,
    Done,
}

/// What a preparation's cleanup reads (`Preparation::reclaim_step`), part
/// by part in the order it releases them: its text continuation, through
/// the normalizer's own cleanup once the continuation is whole, or how far
/// its initialization for the current text went (the cleanup reads the
/// phase that initialization may have rewritten); a copied normalized text,
/// released in one unit; then each arena, all of plain data ([`arena`]):
/// frames, open maps, plan bytes, gaps, entry cursors, and the dynamic map
/// engine's descriptors, merge scratch and permutation bitmap. Its
/// instruction, depth, inspection, bignum and every other counter are never
/// read by cleanup, and are dropped.
#[derive(Debug)]
#[expect(dead_code, reason = "read through the rendering that is the class")]
struct Preparing {
    normalizer: Option<Normalizer>,
    text_initialized: Option<usize>,
    normalized: bool,
    frames: Arena,
    maps: Arena,
    bytes: Arena,
    holes: Arena,
    cursors: Arena,
    entries: Arena,
    merge: Arena,
    bitmap: Arena,
}

fn preparing(position: &PreparationPosition) -> Preparing {
    let normalizer = position.normalization.as_ref().map(normalizer);
    Preparing {
        text_initialized: normalizer.is_none().then_some(position.text_initialized),
        normalizer,
        normalized: position.normalized_output.is_some(),
        frames: arena(&position.frames),
        maps: arena(&position.maps),
        bytes: arena(&position.bytes),
        holes: arena(&position.holes),
        cursors: arena(&position.cursor_storage),
        entries: arena(&position.dynamic.entry_storage),
        merge: arena(&position.dynamic.merge_storage),
        bitmap: arena(&position.dynamic.bitmap_storage),
    }
}

/// What an owned preparation's cleanup reads: its record's stage, its
/// preparation's own cleanup ([`preparing`]), and whether the record or the
/// task holds the source value, whose cleanup is the same at every boundary
/// of one run, the value being the same.
#[derive(Debug)]
#[expect(dead_code, reason = "read through the rendering that is the class")]
struct Prepare {
    record: Option<PlanStage>,
    preparation: Option<Preparing>,
    source: bool,
}

/// An owned preparation's class. Before the record's prefix is complete its
/// cleanup (`Planned::reclaim_step`, `remaining`) reads only whether the
/// source slot is written and holds the source, which the detail's `source`
/// carries, reclaims the source through its own record, which empties the
/// slot, then releases the record in one unit; the phase and the
/// preparation's prefix own nothing (`Preparation::initialize_step`
/// acquires nothing). So every partial prefix of an allocated record is one
/// class, its exact units dropped.
pub fn prepare(position: &Position<PlanDetail>) -> Option<Class> {
    let detail = &position.detail;
    let initialized = if position.allocated
        && 0 < position.initialized
        && position.initialized < position.initialization_steps
    {
        Initialized::Partial
    } else {
        Initialized::Units(position.initialized)
    };
    Some(operation_with(position, initialized, plan(detail)))
}

/// What a plan record's cleanup reads ([`Prepare`]), from its detail.
fn plan(detail: &PlanDetail) -> Prepare {
    Prepare {
        record: detail.phase.map(|phase| match phase {
            PlanPhase::Prepare | PlanPhase::Published => PlanStage::Active,
            PlanPhase::ReclaimPreparation => PlanStage::ReclaimPreparation,
            PlanPhase::ReclaimSource => PlanStage::ReclaimSource,
            PlanPhase::Done => PlanStage::Done,
        }),
        preparation: detail.preparation.as_ref().map(preparing),
        source: detail.source,
    }
}

/// An emission boundary's class: its plan record's cleanup ([`plan`]),
/// marked as an emission's, the emission's own progress dropped. Every stop
/// at an emission boundary retires the writer (it holds no operation in
/// progress), which hands its record to the scope's drain; the drain reads
/// only the record. An emission step reads the record through a shared view
/// of its plan and writes only the writer's own progress
/// (`OwnedWriter::step`), and the writer's own cleanup carries that progress
/// only to rebuild itself (`OwnedWriter::reclaim_step`), so nothing an
/// emission step changes is read by any cleanup: the boundaries of one
/// emission are one class whatever their offset, gaps passed or bytes
/// written.
pub fn emit(position: &OwnedEmitPosition) -> Option<Class> {
    /// The emission's mark beside its record's cleanup: a plan record's
    /// state at an emission boundary is never compared with one at a
    /// preparation boundary, whose operation's cleanup differs.
    #[derive(Debug)]
    #[expect(dead_code, reason = "read through the rendering that is the class")]
    struct Emitting(Prepare);
    Some(format!("{:?}", Emitting(plan(&position.plan))))
}

fn construction<S: Reduction>(detail: &ConstructDetail<S::Observation>) -> Construct<S::Class> {
    Construct {
        record: detail.phase.map(|phase| match phase {
            ConstructPhase::Build
            | ConstructPhase::Detach
            | ConstructPhase::Publish
            | ConstructPhase::Published => ConstructStage::Active,
            ConstructPhase::ReclaimValue => ConstructStage::ReclaimValue,
            ConstructPhase::ReclaimDocument => ConstructStage::ReclaimDocument,
            ConstructPhase::ReclaimInput => ConstructStage::ReclaimInput,
            ConstructPhase::Done => ConstructStage::Done,
        }),
        document: detail.document,
        input: detail.input,
        value: detail.build.as_ref().map(S::class),
    }
}
