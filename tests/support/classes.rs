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

/// A boundary's cleanup class, rendered: classes of different operations
/// and value types compare as their renderings, which name every field.
pub type Class = String;

/// The position of a typed decode of `T`.
pub type Typed<T> = TypedPosition<<<T as Reclaim<Limits>>::State as Custody>::Observation>;

/// The classifiers of one pipeline run: an input acquisition's, a parse's,
/// and a typed decode's of the value the run decodes.
pub struct Classes<P> {
    pub input: fn(&Position<InputDetail<BufferObservation>>) -> Option<Class>,
    pub parse: fn(&Position<ParseDetail>) -> Option<Class>,
    pub decode: fn(&P) -> Option<Class>,
}

impl Classes<()> {
    /// Acquisition and inspection: their operations' classes.
    pub fn certified() -> Self {
        Self {
            input,
            parse,
            decode: |_| None,
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
    }
}

/// The operation's own part of a class: whether its record is allocated, how
/// many of its prefix units are written, whether it is cancelling or
/// finished, and how many records its scope holds. The operation's cleanup
/// reads each: a record's cleanup releases its written prefix, and the
/// scope's drain releases every record it holds.
#[derive(Debug)]
#[expect(dead_code, reason = "read through the rendering that is the class")]
struct Operation<D> {
    allocated: bool,
    initialized: usize,
    cancelling: bool,
    finished: bool,
    outstanding: usize,
    detail: D,
}

fn operation<D, E: Debug>(position: &Position<D>, detail: E) -> Class {
    format!(
        "{:?}",
        Operation {
            allocated: position.allocated,
            initialized: position.initialized,
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

/// What a parse's cleanup reads, with the parser's counters dropped.
#[derive(Debug)]
#[expect(dead_code, reason = "read through the rendering that is the class")]
struct Parse<S> {
    record: Option<RecordStage>,
    parser: Option<ParserStage>,
    entries: Option<S>,
    stack: Option<S>,
    normalizer_initialized: Option<usize>,
    normalizer: Option<dcbor::bounded::text_cursor::Position>,
    normalized: Option<bool>,
    transferred: usize,
    released: usize,
    input: bool,
}

/// A parse's class. The record's cleanup reads its phase (every phase
/// before reclamation alike), the arena parts transferred and released,
/// and its input slot; the parser's cleanup reads its phase (every parsing
/// phase alike), its two arenas' stages and counts, whether its normalizer
/// is initialized and whether a normalized output is held. The input
/// offset, header bytes, payload validated, bytes compared and children
/// completed are never read by cleanup, and are dropped. The normalizer's
/// complete position is retained, including both arena stages and output
/// custody. Equal such positions clean up alike: their elements are plain
/// characters, whose values cannot change a drain or release. No normalizer
/// progress distinction is erased by this classifier.
pub fn parse(position: &Position<ParseDetail>) -> Option<Class> {
    let detail = &position.detail;
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
    Some(operation(
        position,
        Parse {
            record,
            parser,
            entries: detail.resources.map(|resources| resources.entries),
            stack: detail.resources.map(|resources| resources.stack),
            normalizer_initialized: detail
                .resources
                .map(|resources| resources.normalizer_initialized),
            normalizer: detail.resources.and_then(|resources| resources.normalizer),
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
pub fn typed<T>(position: &Typed<T>) -> Option<Class>
where
    T: Reclaim<Limits>,
    T::State: Reduction,
{
    match position {
        TypedPosition::Parse(parse_position) => parse(parse_position),
        TypedPosition::Construct(construct) => Some(operation(
            construct,
            construction::<T::State>(&construct.detail),
        )),
        TypedPosition::Finished => Some("finished".into()),
    }
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
