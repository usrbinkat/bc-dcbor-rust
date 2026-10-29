//! Retained iterative canonical parser over a complete immutable input.
use super::comparison::RangeComparison;
// Named by path: the bare `Place` is the accounting trait `bounded::Place`,
// which `RetainedPlace::ALL` needs.
use super::construction::reclamation;
use super::header::{Header, HeaderState};
use super::storage::Storage;
use super::utf8::Utf8;
use super::*;
use crate::bounded::text_cursor::TextContinuation;
use core::cmp::Ordering;
use core::mem::MaybeUninit;
use core::ptr::NonNull;
use unicode_normalization::IsNormalized;
mod initialization;
mod observation;
mod publication;
pub use observation::Resources;
pub(crate) use publication::ArenaParts;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Phase {
    Header,
    Interpret,
    Utf8,
    InitializeNormalizer,
    Normalize,
    CheckText,
    Entry,
    Frame,
    Complete,
    Compare,
    Attach,
    ReleaseStack,
    Publish,
    ReclaimNormalizer,
    ReclaimEntries,
    ReclaimStack,
    Finished,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Position {
    pub phase: Phase,
    pub input: usize,
    pub header_bytes: usize,
    pub payload_validated: usize,
    pub compared_bytes: usize,
    pub completed_children: usize,
    pub nodes: usize,
    pub arena_relocated: usize,
    pub stack_relocated: usize,
}

pub type Decoder<'a, P> = ParserContinuation<&'a [u8], P>;

/// The [`ResourceBound`] of a retained parse ([`Decoder`], and the owned
/// parse built on the same continuation) of any input of at most `input`
/// bytes under `options`, malformed input included, from its first step to
/// publication or to any failure and the cleanup after it. It is this
/// parser's own: it normalizes undecided text with a [`TextContinuation`],
/// not the synchronous normalizer [`decode_bound`] is derived from.
///
/// An input of `n` bytes has at most `n` nodes, each with a head byte, at
/// most `n` texts and `n` text bytes, and at most `min(max_depth, n)` open
/// frames. Each term is charged where the parser charges it:
///
/// - heads: one unit of a byte per head byte acquired and one to validate
///   each head of at most nine bytes, plus a head the input ends inside;
/// - interpretation: one unit of nine bytes per node;
/// - UTF-8: one unit of four bytes per scalar and one per text: each text
///   has a head byte and each scalar at least one, so at most `n` units;
/// - under normalization, a text the quick check leaves undecided, at most
///   `n / 3` of them ([`text::MIN_UNPROVEN_TEXT_BYTES`] and a head): its
///   normalizer initialized field by field, its normalization and encoding
///   (`text_cursor::normalizations` of the texts one after another, their
///   counts together at most a worst text of the input's length, its longest
///   run traded against its parts ([`text_cursor::TextShape::worst_bound`])),
///   its output's release among them, and its comparison in units of at
///   most 64 bytes;
/// - the node arena and the frame stack ([`storage_growth`]): one unit per
///   node and per frame pushed and per element relocated, and on cleanup,
///   plain data, a settled arena discarded in one unit
///   (`Storage::reclaim_copy_step`) but one cancelled while staging a
///   growth or relocating drained one unit per element, the most charged,
///   and two releases each, each at most 64 bytes; the
///   arena's nodes and an interrupted text share the input, so cleanup
///   drains the more of the two at their extremes, the input all nodes or
///   all one text;
/// - completion and attachment: one unit per node and per child;
/// - key comparison: a byte lies in the keys of at most one map per nesting
///   level, so at most `min(max_depth, n) * n` key bytes, in units of at
///   most 64 and one per key; each compared key has a value beside it, each
///   a node of at least one byte, so at most `n / 2` keys;
/// - publication: the stack's cleanup and one unit; cleanup's transition
///   units, and an interrupted normalizer's own cleanup, its arenas drained.
///   Every release, of an arena allocation or of a normalized output, was
///   admitted by its acquisition.
///
/// The arena is what publication retains. The peak is the most held at
/// once, not the sum of each part's most: the arena or the stack grows only
/// in its own phase, beside the other's held capacity, with no text being
/// normalized; a text's normalizer scratch and normalized encoding are
/// released before its node is pushed, so a text of `m` bytes is normalized
/// beside the arena and the stack held for the `n - m` bytes before it, and
/// the most is at the least `m` of each level of the normalization's peak
/// ([`next_rise`]). Refused, never saturated, when a quantity does not fit
/// in `u64`.
pub fn retained_decode_bound<P, R>(
    input: u64,
    options: Options,
) -> Result<ResourceBound, BoundedError<R>> {
    RetainedTerms::of::<P, R>(input, options)?.bound()
}

places! {
    /// The places a retained parse ([`ParserContinuation`]) charges, one term
    /// of [`retained_decode_bound`] each.
    pub(crate) enum RetainedPlace {
        Heads,
        Interpretation,
        Utf8,
        NormalizerInit,
        Normalization,
        TextCheck,
        Arena,
        Stack,
        Completion,
        Attach,
        Keys,
        Publication,
        Cleanup,
    }
}

/// Interpreting a head: one value and at most a head's bytes.
const INTERPRET: Unit<RetainedPlace> =
    Unit::new(RetainedPlace::Interpretation, 1, MAX_HEAD_LEN as u64);

/// Comparing a normalized text with its source: one value and at most a
/// quantum of byte pairs.
const TEXT_CHECK: Capped<RetainedPlace> = Capped::new(
    RetainedPlace::TextCheck,
    1,
    super::construction::stable::QUANTUM as u64,
);

/// Pushing one node to the arena.
const ENTRY: Unit<RetainedPlace> = Unit::new(RetainedPlace::Arena, 1, 0);

/// Pushing one frame to the stack.
const FRAME: Unit<RetainedPlace> = Unit::new(RetainedPlace::Stack, 1, 0);

/// Completing one node.
const COMPLETE: Unit<RetainedPlace> = Unit::new(RetainedPlace::Completion, 1, 0);

/// Attaching one child to its parent.
const ATTACH: Unit<RetainedPlace> = Unit::new(RetainedPlace::Attach, 1, 0);

/// Publishing the document.
const PUBLISH: Unit<RetainedPlace> = Unit::new(RetainedPlace::Publication, 1, 0);

/// A cleanup transition: one unit of no bytes.
const CLEANUP: Unit<RetainedPlace> = Unit::new(RetainedPlace::Cleanup, 1, 0);

/// A published parser's cleanup call ([`ParserContinuation::reclaim_step`] at
/// [`Phase::Finished`]): the one unit it admits, what an owned document's
/// in-place cleanup charges for its released parser.
#[cfg(test)]
#[cfg(feature = "std")]
pub(crate) fn finished_cleanup<R>() -> Result<WriteWork, BoundedError<R>> {
    CLEANUP.times(1)
}

/// The terms [`retained_decode_bound`] sums, one per [`RetainedPlace`], and
/// the most held at once ([`RetainedTerms::peak_of`]).
struct RetainedTerms {
    terms: [ResourceBound; RetainedPlace::ALL.len()],
    peak: u64,
}

impl RetainedTerms {
    fn of<P, R>(input: u64, options: Options) -> Result<Self, BoundedError<R>> {
        use core::mem::size_of;
        let n = input;
        let depth = widen(options.max_depth)?.min(n);
        let entry = widen(size_of::<Entry>())?;
        let frame = widen(size_of::<Frame>())?;
        // A storage of at most `elements` of `size` bytes, each pushed once
        // in a unit of `push`, each relocation one unit of its bytes, each
        // growth's writes and each allocation's release.
        let arena = |elements: u64, size: u64, push: Unit<RetainedPlace>, retained: bool| {
            let (growth, growing) = storage_growth::<R>(elements, size)?;
            let work = push.times(n)?.then(growing)?.then(growth.released()?)?;
            Ok::<_, BoundedError<R>>(ResourceBound {
                values: work.values,
                bytes: work.bytes,
                allocated: growth.allocated,
                peak: growth.peak,
                retained: if retained { growth.held } else { 0 },
            })
        };
        let work = ResourceBound::of_work;
        let normalizing = options.text == TextPolicy::Normalize;
        let mut terms = [ResourceBound::default(); RetainedPlace::ALL.len()];
        let mut set = |place: RetainedPlace, term: ResourceBound| {
            terms[place as usize] = term;
        };
        set(RetainedPlace::Heads, work(header::heads_work(n)?));
        set(RetainedPlace::Interpretation, work(INTERPRET.times(n)?));
        // One unit per scalar and one per text: a text's head byte and each
        // scalar's at least one byte, so at most one unit per input byte.
        set(RetainedPlace::Utf8, work(utf8::SCALAR.times(n)?));
        set(RetainedPlace::Arena, arena(add(n, 1)?, entry, ENTRY, true)?);
        set(
            RetainedPlace::Stack,
            arena(add(depth, 1)?, frame, FRAME, false)?,
        );
        set(RetainedPlace::Completion, work(COMPLETE.times(n)?));
        set(RetainedPlace::Attach, work(ATTACH.times(n)?));
        // A byte lies in the keys of at most one map per nesting level; each
        // key's comparison in units of at most a quantum, one partial; each
        // compared key and its value are two nodes, so at most `n / 2` keys.
        set(
            RetainedPlace::Keys,
            work(super::comparison::COMPARE.covering(mul(depth, n)?, n / 2)?),
        );
        // Completion settled the stack and popped every frame. Publication
        // therefore needs only the empty-stack completion and publication
        // units. Its allocation release was prepaid; the interrupted-
        // relocation reset belongs exclusively to cancellation cleanup.
        set(
            RetainedPlace::Publication,
            work(Storage::<Frame, P>::step_work(1)?.then(PUBLISH.times(1)?)?),
        );
        // Cleanup: the arena and the stack drained and cleaned up, each
        // charged a unit per element, the most it takes: settled, each is
        // discarded in one unit (`Storage::reclaim_copy_step`), cancelled
        // while staging a growth or relocating, drained per element; the
        // transitions, and, under normalization, an interrupted text's
        // continuation; every release paid for by its acquisition. The arena's
        // nodes and the interrupted text share the input: a text of `L`
        // payload bytes leaves at most `n - L` other nodes. For `L >= 1`
        // both are at most affine in `L`, the text's whole parts below its
        // rate by less than one, which one more drained element in each of
        // its two arenas covers, so together they are most at `L = 1` or
        // `L = n` in each dimension; the text taken at `max(L, 1)` makes
        // `L = 0` cover `L = 1`.
        let shared = |text: u64| -> Result<WriteWork, BoundedError<R>> {
            // An interrupted text's cleanup drains its arenas of parts and
            // charges nothing for its run: the worst text's parts are the
            // most any text of its length has.
            let interrupted = if normalizing {
                text_cursor::interrupted::<R>(text_cursor::TextShape::worst(text.max(1))?)?
                    .then(Storage::<char, P>::element_work(2)?)?
            } else {
                WriteWork::default()
            };
            Storage::<Entry, P>::element_work(add(n - text, 1)?)?.then(interrupted)
        };
        let (all_nodes, all_text) = (shared(0)?, shared(n)?);
        set(
            RetainedPlace::Cleanup,
            work(
                WriteWork::new(
                    all_nodes.values.max(all_text.values),
                    all_nodes.bytes.max(all_text.bytes),
                )
                .then(Storage::<Entry, P>::cleanup_work(true)?)?
                .then(Storage::<Frame, P>::element_work(add(depth, 1)?)?)?
                .then(Storage::<Frame, P>::cleanup_work(true)?)?
                .then(CLEANUP.times(3)?)?,
            ),
        );
        if normalizing {
            // Only an undecided text is normalized: it holds a scalar of at
            // least `MIN_UNPROVEN_TEXT_BYTES`, besides its head byte.
            let undecided = n / add(text::MIN_UNPROVEN_TEXT_BYTES, 1)?;
            // Every undecided text's normalization, one after another, their
            // counts together at most a worst text of the input's length.
            let normalizations = text_cursor::TextShape::worst_bound(n, |shape| {
                text_cursor::normalizations::<P, R>(shape, undecided)
            })?;
            set(
                RetainedPlace::NormalizerInit,
                work(
                    super::initialization::fields::<TextContinuation<(), P>, R>(
                        TextContinuation::<(), P>::INIT_STEPS,
                    )?
                    .times(undecided)?,
                ),
            );
            set(RetainedPlace::Normalization, normalizations);
            set(
                RetainedPlace::TextCheck,
                work(TEXT_CHECK.covering(n, undecided)?),
            );
        }
        let peak = Self::peak_of::<P, R>(
            n,
            depth,
            normalizing,
            terms[RetainedPlace::Arena as usize].peak,
            terms[RetainedPlace::Stack as usize].peak,
        )?;
        Ok(Self { terms, peak })
    }

    /// The most a retained parse holds at once over an input of `n` bytes
    /// and `depth` open frames at most ([`retained_decode_bound`]): the
    /// arena (`arena_peak`) growing beside the stack held, or the stack
    /// (`stack_peak`) growing beside the arena held, no text being
    /// normalized; or, normalizing, one text of `m` bytes normalized and
    /// encoded beside the arena and the stack held for the `n - m` bytes
    /// before it, at the least `m` of each level of the normalization's
    /// peak. Each arena holds one slot more than it uses.
    fn peak_of<P, R>(
        n: u64,
        depth: u64,
        normalizing: bool,
        arena_peak: u64,
        stack_peak: u64,
    ) -> Result<u64, BoundedError<R>> {
        use core::mem::size_of;
        let entry = widen(size_of::<Entry>())?;
        let frame = widen(size_of::<Frame>())?;
        let held = |elements: u64, size: u64| {
            storage_growth::<R>(add(elements, 1)?, size).map(|(growth, _)| growth.held)
        };
        let mut peak = add(arena_peak, held(depth, frame)?)?.max(add(held(n, entry)?, stack_peak)?);
        if !normalizing {
            return Ok(peak);
        }
        // One text of `m` bytes, its head included; a text that short
        // cannot be undecided holds nothing.
        let normalization = |m: u64| {
            let texts = u64::from(m > text::MIN_UNPROVEN_TEXT_BYTES);
            text_cursor::TextShape::worst_bound(m, |shape| {
                text_cursor::normalizations::<P, R>(shape, texts)
            })
            .map(|bound| bound.peak)
        };
        let mut m = 1;
        while m <= n {
            let level = normalization(m)?;
            let rest = n - m;
            let beside = add(held(rest, entry)?, held(depth.min(rest), frame)?)?;
            peak = peak.max(add(beside, level)?);
            match next_rise(m, n, level, &normalization)? {
                Some(next) => m = next,
                None => break,
            }
        }
        Ok(peak)
    }
}

impl Places for RetainedTerms {
    type Place = RetainedPlace;

    fn term(&self, place: RetainedPlace) -> ResourceBound {
        self.terms[place as usize]
    }

    /// The most held at once ([`RetainedTerms::peak_of`]), not every
    /// place's at once.
    fn peak<R>(&self) -> Result<u64, BoundedError<R>> {
        Ok(self.peak)
    }
}

#[doc(hidden)]
pub struct ParserContinuation<I, P> {
    input: I,
    options: Options,
    entries: Storage<Entry, P>,
    stack: Storage<Frame, P>,
    phase: Phase,
    header: HeaderState,
    parsed: Option<Header>,
    start: usize,
    position: usize,
    payload_end: usize,
    kind: StoredKind,
    children: u64,
    completed: usize,
    child_count: usize,
    utf8: Option<Utf8>,
    normalizer: MaybeUninit<TextContinuation<(), P>>,
    normalizer_init: usize,
    normalized: Option<Encoded<P>>,
    text_compared: usize,
    comparison: Option<RangeComparison>,
}

impl<'a, P> Decoder<'a, P> {
    pub fn step<A: Allocator<Permit = P>>(
        &mut self,
        allocator: &mut A,
    ) -> Result<Step<Document<'a, P>>, DecodeError<A::Refusal>> {
        self.step_input(self.input, allocator)
    }
}

impl<'a, P, A: Allocator<Permit = P>> Resumable<A> for Decoder<'a, P> {
    type Output = Document<'a, P>;
    type Error = DecodeError<A::Refusal>;
    type Position = Position;

    fn step(&mut self, allocator: &mut A) -> Result<Step<Document<'a, P>>, Self::Error> {
        Decoder::step(self, allocator)
    }

    fn position(&mut self) -> Position {
        ParserContinuation::position(self)
    }
}

impl<I, P> ParserContinuation<I, P> {
    pub fn new(input: I, options: Options) -> Self {
        Self {
            input,
            options,
            entries: Storage::new(),
            stack: Storage::new(),
            phase: Phase::Header,
            header: HeaderState::new(),
            parsed: None,
            start: 0,
            position: 0,
            payload_end: 0,
            kind: StoredKind::Null,
            children: 0,
            completed: 0,
            child_count: 0,
            utf8: None,
            normalizer: MaybeUninit::uninit(),
            normalizer_init: 0,
            normalized: None,
            text_compared: 0,
            comparison: None,
        }
    }

    pub fn position(&self) -> Position {
        Position {
            phase: self.phase,
            input: self.position,
            header_bytes: self.header.acquired(),
            payload_validated: self.utf8.as_ref().map_or(0, |text| text.position),
            compared_bytes: self
                .comparison
                .as_ref()
                .map_or(self.text_compared, RangeComparison::position),
            completed_children: self.child_count,
            nodes: self.entries.len(),
            arena_relocated: self.entries.relocated(),
            stack_relocated: self.stack.relocated(),
        }
    }

    pub(crate) fn step_input<'a, A: Allocator<Permit = P>>(
        &mut self,
        input: &'a [u8],
        allocator: &mut A,
    ) -> Result<Step<Document<'a, P>>, DecodeError<A::Refusal>> {
        let result = self.advance(input, allocator);
        if matches!(&result, Err(error) if !matches!(error, DecodeError::Resource(BoundedError::Refused(_))))
        {
            self.phase = Phase::ReclaimNormalizer;
        }
        result
    }

    /// Close parser admission and reclaim one resource unit. Terminal errors
    /// enter this same path, retaining partial relocation and normalization.
    pub fn reclaim_step<A: Allocator<Permit = P>>(
        &mut self,
        allocator: &mut A,
    ) -> BoundedResult<bool, A> {
        let cleanup = RetainedPlace::Cleanup;
        match self.phase {
            Phase::ReclaimNormalizer => {
                if self.normalizer_init == TextContinuation::<(), P>::INIT_STEPS {
                    // SAFETY: all resource-free metadata fields were initialized
                    // before the normalizer could acquire any resources.
                    let normalizer = unsafe { self.normalizer.assume_init_mut() };
                    if !at(cleanup, || normalizer.reclaim_step(allocator))? {
                        return Ok(false);
                    }
                }
                CLEANUP.admit(allocator)?;
                self.normalizer_init = 0;
                // A normalized output still held is released in the same
                // unit: its request paid for its release.
                self.normalized = None;
                self.phase = Phase::ReclaimEntries;
            }
            // Nodes and frames are plain data: a settled arena of them is
            // discarded in one unit, whatever it holds; one cancelled while
            // relocating or staging drains per element, which the bound counts.
            Phase::ReclaimEntries => {
                if at(cleanup, || self.entries.reclaim_copy_step(allocator))? {
                    self.phase = Phase::ReclaimStack;
                }
            }
            Phase::ReclaimStack => {
                if at(cleanup, || self.stack.reclaim_copy_step(allocator))? {
                    self.phase = Phase::Finished;
                    return Ok(true);
                }
            }
            // Publication transferred everything; this call admits the
            // completion it reports, as every cleanup call admits its unit.
            Phase::Finished => {
                CLEANUP.admit(allocator)?;
                return Ok(true);
            }
            _ => {
                CLEANUP.admit(allocator)?;
                self.phase = Phase::ReclaimNormalizer;
            }
        }
        Ok(false)
    }

    /// The most successful calls [`Self::reclaim_step`] still takes, the one
    /// returning true included: the transition into cleanup unless it has
    /// begun; an initialized normalizer's own count, or one transition; each
    /// arena's own count; one once finished. Admits nothing and changes
    /// nothing.
    pub(crate) fn reclaim_remaining(&self) -> u64 {
        let normalizer = if self.normalizer_init == TextContinuation::<(), P>::INIT_STEPS {
            // SAFETY: a complete prefix is an initialized normalizer.
            unsafe { self.normalizer.assume_init_ref() }.reclaim_remaining()
        } else {
            1
        };
        let stack = self.stack.reclaim_remaining();
        let entries = self.entries.reclaim_remaining().saturating_add(stack);
        match self.phase {
            Phase::Finished => 1,
            Phase::ReclaimStack => stack,
            Phase::ReclaimEntries => entries,
            Phase::ReclaimNormalizer => normalizer.saturating_add(entries),
            _ => normalizer.saturating_add(entries).saturating_add(1),
        }
    }

    fn next_header(&mut self) {
        self.start = self.position;
        self.header = HeaderState::new();
        self.parsed = None;
        self.children = 0;
        self.utf8 = None;
        self.comparison = None;
        self.phase = Phase::Header;
    }

    fn advance<'a, A: Allocator<Permit = P>>(
        &mut self,
        input: &'a [u8],
        allocator: &mut A,
    ) -> Result<Step<Document<'a, P>>, DecodeError<A::Refusal>> {
        match self.phase {
            Phase::Header => match at(RetainedPlace::Heads, || {
                self.header.step(&input[self.position..], allocator)
            })? {
                Step::Progress => {}
                Step::Complete(header) => {
                    self.position += header.length;
                    self.parsed = Some(header);
                    self.phase = Phase::Interpret;
                }
                Step::Finished => return Err(BoundedError::PlanMismatch.into()),
            },
            Phase::Interpret => {
                INTERPRET.admit(allocator)?;
                let header = self.parsed.ok_or(BoundedError::PlanMismatch)?;
                self.phase = Phase::Entry;
                let kind = match header.major {
                    MajorType::Unsigned => Kind::Unsigned(header.argument),
                    MajorType::Negative => {
                        if header.argument > i64::MAX as u64 {
                            return Err(Error::OutOfRange.into());
                        }
                        Kind::Negative(-1 - header.argument as i64)
                    }
                    MajorType::ByteString | MajorType::Text => {
                        if header.argument > widen(input.len() - self.position)? {
                            return Err(Error::Underrun.into());
                        }
                        let length =
                            usize::try_from(header.argument).map_err(|_| BoundedError::Overflow)?;
                        let end = self
                            .position
                            .checked_add(length)
                            .ok_or(BoundedError::Overflow)?;
                        let bytes = input.get(self.position..end).ok_or(Error::Underrun)?;
                        if header.major == MajorType::Text {
                            self.payload_end = end;
                            self.utf8 = Some(Utf8::new());
                            self.phase = Phase::Utf8;
                            Kind::Null
                        } else {
                            // Byte-string payload is opaque: validation is the
                            // checked extent, not an artificial whole-byte scan.
                            self.position = end;
                            Kind::Bytes(bytes)
                        }
                    }
                    MajorType::Array => {
                        self.children = header.argument;
                        Kind::Array(header.argument)
                    }
                    MajorType::Map => {
                        if header.argument > widen((input.len() - self.position) / 2)? {
                            return Err(Error::Underrun.into());
                        }
                        self.children = header
                            .argument
                            .checked_mul(2)
                            .ok_or(BoundedError::Overflow)?;
                        Kind::Map(header.argument)
                    }
                    MajorType::Tagged => {
                        self.children = 1;
                        Kind::Tagged(header.argument)
                    }
                    MajorType::Simple => match header.length {
                        3 => {
                            let n = f16::from_bits(header.argument as u16);
                            validate_canonical_f16(n)?;
                            Kind::Float(n.to_f64())
                        }
                        5 => {
                            let n = f32::from_bits(header.argument as u32);
                            validate_canonical_f32(n)?;
                            Kind::Float(f64::from(n))
                        }
                        9 => {
                            let n = f64::from_bits(header.argument);
                            validate_canonical_f64(n)?;
                            Kind::Float(n)
                        }
                        _ => match header.argument {
                            20 => Kind::Bool(false),
                            21 => Kind::Bool(true),
                            22 => Kind::Null,
                            _ => return Err(Error::InvalidSimpleValue.into()),
                        },
                    },
                };
                if self.children > widen(input.len() - self.position)? {
                    return Err(Error::Underrun.into());
                }
                self.kind = StoredKind::retain(kind, self.position);
                if self.children > 0 && self.stack.len() >= self.options.max_depth {
                    return Err(DecodeError::DepthLimit {
                        limit: self.options.max_depth,
                    });
                }
            }
            Phase::Utf8 => {
                let validator = self.utf8.as_mut().ok_or(BoundedError::PlanMismatch)?;
                let payload = &input[self.position..self.payload_end];
                if let Some(text) = at(RetainedPlace::Utf8, || validator.step(payload, allocator))?
                {
                    self.kind = StoredKind::retain(Kind::Text(text), self.payload_end);
                    self.position = self.payload_end;
                    match (validator.quick.result(), self.options.text) {
                        (IsNormalized::Yes, _) => self.phase = Phase::Entry,
                        (_, TextPolicy::QuickOnly) => return Err(DecodeError::UnprovenText),
                        (IsNormalized::No, _) => return Err(Error::NonCanonicalString.into()),
                        (IsNormalized::Maybe, _) => {
                            self.normalizer_init = 0;
                            self.phase = Phase::InitializeNormalizer;
                        }
                    }
                }
            }
            Phase::InitializeNormalizer => {
                let StoredKind::Text { .. } = self.kind else {
                    return Err(BoundedError::PlanMismatch.into());
                };
                // SAFETY: the normalizer's place is rooted at an exclusive
                // borrow of its own `MaybeUninit` field, valid, aligned and
                // writable for it, and no place derived from it outlives this
                // call; its units are `normalizer_init`, which counts exactly
                // the units written since the field was last reset. Its
                // prefix owns no resources, and nothing reads it as a
                // normalizer until every unit has committed.
                let normalizer = unsafe {
                    reclamation::Slot::new(
                        reclamation::Place::root(NonNull::from(&mut self.normalizer)),
                        &mut self.normalizer_init,
                    )
                };
                if at(RetainedPlace::NormalizerInit, || {
                    TextContinuation::initialize_step(normalizer, (), allocator)
                })? {
                    self.phase = Phase::Normalize;
                }
            }
            Phase::Normalize => {
                if self.normalizer_init != TextContinuation::<(), P>::INIT_STEPS {
                    return Err(BoundedError::PlanMismatch.into());
                }
                let normalizer = unsafe { self.normalizer.assume_init_mut() };
                let Kind::Text(source) = self.kind.borrow(input) else {
                    return Err(BoundedError::PlanMismatch.into());
                };
                match at(RetainedPlace::Normalization, || {
                    normalizer.step_source(source, allocator)
                })? {
                    Step::Progress => {}
                    Step::Complete(bytes) => {
                        self.normalized = Some(bytes);
                        // Completion has already drained the normalizer scratch
                        // and transferred its output reservation. The old slot
                        // may now be reused without a whole-state destructor.
                        self.normalizer_init = 0;
                        self.text_compared = 0;
                        self.phase = Phase::CheckText;
                    }
                    Step::Finished => return Err(BoundedError::PlanMismatch.into()),
                }
            }
            Phase::CheckText => {
                let canonical = self
                    .normalized
                    .as_ref()
                    .ok_or(BoundedError::PlanMismatch)?
                    .as_ref();
                let original = &input[self.start..self.position];
                let remaining = canonical.len().min(original.len()) - self.text_compared;
                let count = remaining.min(super::construction::stable::QUANTUM);
                TEXT_CHECK.admit(allocator, count as u64)?;
                let end = self.text_compared + count;
                if canonical[self.text_compared..end] != original[self.text_compared..end] {
                    return Err(Error::NonCanonicalString.into());
                }
                self.text_compared = end;
                if end == canonical.len().min(original.len()) {
                    if canonical.len() != original.len() {
                        return Err(Error::NonCanonicalString.into());
                    }
                    // The text is proven canonical: its normalized output is
                    // released in the same unit, its request having paid for
                    // its release.
                    self.normalized = None;
                    self.phase = Phase::Entry;
                }
            }
            Phase::Entry => {
                let entries = &mut self.entries;
                // A growth unit of the arena, or a free slot for the node.
                let Some(spare) = at(RetainedPlace::Arena, || {
                    entries.reserve_step(usize::MAX, allocator)
                })?
                else {
                    return Ok(Step::Progress);
                };
                ENTRY.admit(allocator)?;
                self.completed = spare.len();
                spare.push(Entry {
                    kind: self.kind,
                    start: self.start,
                    end: self.position,
                    next: self.completed + 1,
                });
                self.phase = if self.children > 0 {
                    Phase::Frame
                } else {
                    Phase::Complete
                };
            }
            Phase::Frame => {
                let stack = &mut self.stack;
                // A growth unit of the stack, or a free slot for the frame.
                let Some(spare) = at(RetainedPlace::Stack, || {
                    stack.reserve_step(usize::MAX, allocator)
                })?
                else {
                    return Ok(Step::Progress);
                };
                FRAME.admit(allocator)?;
                spare.push(Frame {
                    node: self.completed,
                    remaining: self.children,
                    map: matches!(self.kind, StoredKind::Map(_)),
                    key: true,
                    previous_key: None,
                });
                self.next_header();
            }
            Phase::Complete => {
                let stack = &mut self.stack;
                let Some(stack) = at(RetainedPlace::Stack, || stack.settle_step(allocator))? else {
                    return Ok(Step::Progress);
                };
                let entries = &mut self.entries;
                let Some(entries) = at(RetainedPlace::Arena, || entries.settle_step(allocator))?
                else {
                    return Ok(Step::Progress);
                };
                COMPLETE.admit(allocator)?;
                let Some(parent) = stack.as_slice().last() else {
                    if self.position != input.len() {
                        return Err(Error::UnusedData(input.len() - self.position).into());
                    }
                    self.phase = Phase::ReleaseStack;
                    return Ok(Step::Progress);
                };
                self.phase = Phase::Attach;
                if parent.map
                    && parent.key
                    && let Some((start, end)) = parent.previous_key
                {
                    let entry = &entries.as_slice()[self.completed];
                    self.comparison =
                        Some(RangeComparison::new(start..end, entry.start..entry.end));
                    self.phase = Phase::Compare;
                }
            }
            Phase::ReleaseStack => {
                if at(RetainedPlace::Publication, || {
                    self.stack.reclaim_copy_step(allocator)
                })? {
                    self.phase = Phase::Publish;
                }
            }
            Phase::Publish => {
                let entries = &mut self.entries;
                let Some(arena) = at(RetainedPlace::Arena, || entries.settle_step(allocator))?
                else {
                    return Ok(Step::Progress);
                };
                PUBLISH.admit(allocator)?;
                let entries = core::mem::take(arena);
                self.phase = Phase::Finished;
                return Ok(Step::Complete(Document { input, entries }));
            }
            Phase::Compare => {
                let comparison = self.comparison.as_mut().ok_or(BoundedError::PlanMismatch)?;
                match at(RetainedPlace::Keys, || comparison.step(input, allocator))? {
                    Step::Progress => {}
                    Step::Complete(Ordering::Less) => self.phase = Phase::Attach,
                    Step::Complete(Ordering::Equal) => {
                        return Err(Error::DuplicateMapKey.into());
                    }
                    Step::Complete(Ordering::Greater) => {
                        return Err(Error::MisorderedMapKey.into());
                    }
                    Step::Finished => return Err(BoundedError::PlanMismatch.into()),
                }
            }
            Phase::Attach => {
                let stack = &mut self.stack;
                let Some(stack) = at(RetainedPlace::Stack, || stack.settle_step(allocator))? else {
                    return Ok(Step::Progress);
                };
                let entries = &mut self.entries;
                let Some(entries) = at(RetainedPlace::Arena, || entries.settle_step(allocator))?
                else {
                    return Ok(Step::Progress);
                };
                ATTACH.admit(allocator)?;
                let parent = stack
                    .as_mut_slice()
                    .last_mut()
                    .ok_or(BoundedError::PlanMismatch)?;
                let entries = entries.as_mut_slice();
                if parent.map && parent.key {
                    let entry = &entries[self.completed];
                    parent.previous_key = Some((entry.start, entry.end));
                }
                parent.key = !parent.key;
                parent.remaining -= 1;
                self.child_count += 1;
                if parent.remaining == 0 {
                    self.completed = parent.node;
                    let next = entries.len();
                    entries[self.completed].end = self.position;
                    entries[self.completed].next = next;
                    stack.pop();
                    self.phase = Phase::Complete;
                } else {
                    self.next_header();
                }
            }
            Phase::ReclaimNormalizer | Phase::ReclaimEntries | Phase::ReclaimStack => {
                self.reclaim_step(allocator)?;
            }
            Phase::Finished => return Ok(Step::Finished),
        }
        Ok(Step::Progress)
    }
}

/// Place attribution of the retained parse, which this crate's tests record
/// under `std`.
#[cfg(test)]
#[cfg(feature = "std")]
mod attribution {
    use super::*;
    use crate::bounded::places::{self, Factor, Ledgered, Permit, Run, STORAGE, WORK};
    use crate::{ByteString, CBOR, Map};

    /// Where a parse is cancelled into its cleanup: before the first step
    /// whose resources the condition holds of.
    type Cancel = Option<fn(&Resources) -> bool>;

    #[test]
    fn publication_of_a_drained_stack_charges_only_two_transitions() {
        for depth in [0, 1, 4, 5, 16, 17, 64] {
            let mut value = CBOR::from(0u64);
            for _ in 0..depth {
                value = CBOR::from(vec![value]);
            }
            let input = value.to_cbor_data();
            let options = Options::quick_only(depth);
            let (policy, document) = parsed("drained stack", &input, options, None);
            assert!(document.is_some());
            let expected = ResourceBound::of_work(WriteWork::new(2, 0));
            assert_eq!(
                policy.ledger().measured(RetainedPlace::Publication),
                expected
            );
            assert_eq!(
                RetainedTerms::of::<Permit, ()>(input.len() as u64, options)
                    .unwrap()
                    .term(RetainedPlace::Publication),
                expected
            );
        }
    }

    /// A text the quick check leaves undecided (U+0301), of a starter and
    /// `pairs` pairs of marks in canonical order (U+0316 of class 220, then
    /// U+0301 of 230), one unbroken run: its normal form is itself.
    fn undecided_run(pairs: usize) -> Vec<u8> {
        CBOR::from(format!("q{}", "\u{316}\u{301}".repeat(pairs)).as_str()).to_cbor_data()
    }

    /// An input whose retained parse charges `place`, the options it is
    /// parsed under, and where it is cancelled, if it is: a place without a
    /// witness does not compile. A leading mark keeps the quick check from
    /// proving a text normal; a truncated array fails, and its cleanup
    /// follows.
    fn witness(place: RetainedPlace) -> (&'static str, Vec<u8>, Options, Cancel) {
        match place {
            RetainedPlace::Heads
            | RetainedPlace::Interpretation
            | RetainedPlace::Arena
            | RetainedPlace::Completion
            | RetainedPlace::Publication => (
                "flat array",
                CBOR::from(vec![0u64; 300]).to_cbor_data(),
                Options::normalizing(1),
                None,
            ),
            // A scalar per byte.
            RetainedPlace::Utf8 => (
                "ascii text",
                CBOR::from("x".repeat(300).as_str()).to_cbor_data(),
                Options::normalizing(0),
                None,
            ),
            // An undecided text in every three bytes.
            RetainedPlace::NormalizerInit | RetainedPlace::TextCheck => (
                "undecided texts",
                CBOR::from(vec![CBOR::from("\u{301}"); 300]).to_cbor_data(),
                Options::normalizing(1),
                None,
            ),
            // An undecided text whose marks run unbroken, in canonical order:
            // every mark ordered at every merge level.
            RetainedPlace::Normalization => (
                "undecided run",
                undecided_run(100),
                Options::normalizing(0),
                None,
            ),
            RetainedPlace::Stack | RetainedPlace::Attach => {
                let mut nested = CBOR::from(0u64);
                for _ in 0..23 {
                    nested = CBOR::from(vec![nested]);
                }
                (
                    "nested arrays",
                    nested.to_cbor_data(),
                    Options::normalizing(23),
                    None,
                )
            }
            // Short keys, most of the input's nodes, each compared over most
            // of its bytes.
            RetainedPlace::Keys => {
                let mut keys = Map::new();
                for key in 0..1000u64 {
                    keys.insert(key, 0u64);
                }
                (
                    "many keys",
                    CBOR::from(keys).to_cbor_data(),
                    Options::normalizing(1),
                    None,
                )
            }
            // Half the input nodes, discarded in one unit, and half an
            // undecided text whose normalization is interrupted while its
            // characters relocate their last growth, so cleanup drains them
            // one per unit, as its term charges: a leading mark and 150
            // letters of two parts are 301 parts, filling a capacity of 256
            // whose growth relocates all 256.
            RetainedPlace::Cleanup => {
                let mut items = vec![CBOR::from(0u64); 300];
                items.push(CBOR::from(
                    format!("\u{301}{}", "\u{e9}".repeat(150)).as_str(),
                ));
                (
                    "cancelled text",
                    CBOR::from(items).to_cbor_data(),
                    Options::normalizing(1),
                    Some(|resources| {
                        resources.normalizer.is_some_and(|normalizer| {
                            normalizer.characters.stage
                                == super::super::storage::StorageStage::Relocating
                                && normalizer.characters.relocating_remaining >= 256
                        })
                    }),
                )
            }
        }
    }

    /// How far each place's term may exceed what its witness measured.
    fn factor(place: RetainedPlace) -> Factor {
        match place {
            RetainedPlace::Heads
            | RetainedPlace::Interpretation
            | RetainedPlace::Utf8
            | RetainedPlace::NormalizerInit
            | RetainedPlace::Normalization
            | RetainedPlace::TextCheck
            | RetainedPlace::Arena
            | RetainedPlace::Stack
            | RetainedPlace::Completion
            | RetainedPlace::Attach
            | RetainedPlace::Keys
            | RetainedPlace::Publication
            | RetainedPlace::Cleanup => Factor::Measured,
        }
    }

    /// `input` parsed under `options` and a policy of its own, to its
    /// document or, after a terminal error or where `cancel` puts it, through
    /// the parser's own cleanup.
    fn parsed<'a>(
        name: &str,
        input: &'a [u8],
        options: Options,
        cancel: Cancel,
    ) -> (Ledgered, Option<Document<'a, Permit>>) {
        let mut policy = Ledgered::new();
        let mut parser = Decoder::<Permit>::new(input, options);
        let bound = retained_decode_bound::<Permit, ()>(input.len() as u64, options)
            .expect("the bound of a fixture fits in u64");
        let mut rejected = false;
        let document = crate::bounded::within(name, bound, || {
            if cancel.is_some_and(|cancel| cancel(&parser.resources())) {
                crate::bounded::within(name, bound, || {
                    if parser
                        .reclaim_step(&mut policy)
                        .expect("an unlimited policy never refuses")
                    {
                        core::ops::ControlFlow::Break(())
                    } else {
                        core::ops::ControlFlow::Continue(())
                    }
                });
                return core::ops::ControlFlow::Break(None);
            }
            match parser.step(&mut policy) {
                Ok(Step::Progress) => core::ops::ControlFlow::Continue(()),
                Ok(Step::Complete(document)) => {
                    assert!(!rejected, "{name}: publication after rejection");
                    core::ops::ControlFlow::Break(Some(document))
                }
                Ok(Step::Finished) => {
                    assert!(
                        rejected,
                        "{name}: finished without publication or rejection"
                    );
                    core::ops::ControlFlow::Break(None)
                }
                // A terminal error: the parser's own steps clean up. Only an
                // input rejected as invalid is an outcome a run may measure;
                // a defect, a refusal or a physical failure never is.
                Err(error) => {
                    assert!(
                        matches!(error.class(), Class::Invalid),
                        "{name}: {error:?}, of class {:?}",
                        error.class()
                    );
                    assert!(!rejected, "{name}: repeated terminal rejection");
                    rejected = true;
                    core::ops::ControlFlow::Continue(())
                }
            }
        });
        (policy, document)
    }

    /// The peak covers what a retained parse holds at once at every split of
    /// an input between nodes before a text and the text: precomposed
    /// letters behind a leading mark, which the quick check leaves undecided
    /// and the parse normalizes, beside the arena of the nodes before it, at
    /// counts on each side of the arenas' capacities; and the peak is no
    /// more than the sum of each place's.
    #[test]
    fn the_peak_covers_a_text_beside_the_nodes_before_it() {
        let options = Options::normalizing(1);
        for nodes in [0usize, 3, 4, 5, 63, 64, 65, 700] {
            for letters in [0usize, 1, 3, 4, 5, 31, 32, 33, 700] {
                let mut items = vec![CBOR::from(0u64); nodes];
                items.push(CBOR::from(
                    format!("\u{301}{}", "\u{e9}".repeat(letters)).as_str(),
                ));
                let input = CBOR::from(items).to_cbor_data();
                let name = format!("{nodes} nodes, {letters} letters");
                let (policy, document) = parsed(&name, &input, options, None);
                assert!(document.is_some(), "{name}: not published");
                drop(document);
                let held = policy.ledger().total().peak;
                let terms = RetainedTerms::of::<Permit, ()>(input.len() as u64, options).unwrap();
                let bound = terms.bound::<()>().unwrap();
                assert!(
                    held <= bound.peak,
                    "{name}: held {held} beyond {}",
                    bound.peak
                );
                let summed = RetainedPlace::ALL.iter().try_fold(0u64, |total, &place| {
                    add::<()>(total, terms.term(place).peak)
                });
                assert!(bound.peak <= summed.unwrap(), "{name}");
            }
        }
    }

    /// Every place of a retained parse is within its term on generated
    /// inputs: values of every major type nested and their encodings
    /// mutated, a byte changed or cut short, under normalizing and
    /// quick-only options; every admission and request is made at some
    /// place.
    #[test]
    fn every_place_of_a_retained_parse_is_within_its_term_on_generated_inputs() {
        let mut generator = crate::bounded::tests::Generator::new(0x5eed_0001);
        let mut inputs = Vec::new();
        for index in 0..400 {
            let encoded = generator.value(4).to_cbor_data();
            let mutated = generator.mutated(&encoded);
            inputs.push((format!("generated {index}"), encoded));
            inputs.push((format!("generated {index} mutated"), mutated));
        }
        let mut runs = Vec::new();
        let mut documents = Vec::new();
        for (name, input) in &inputs {
            for options in [Options::normalizing(4), Options::quick_only(4)] {
                let (policy, document) = parsed(name, input, options, None);
                let outcome = if document.is_some() {
                    places::Outcome::Published
                } else {
                    places::Outcome::Invalid
                };
                documents.extend(document);
                runs.push(Run {
                    outcome,
                    name: format!("{name} {options:?}"),
                    policy,
                    terms: RetainedTerms::of::<Permit, ()>(input.len() as u64, options).unwrap(),
                });
            }
        }
        places::check(&runs);
        drop(documents);
    }

    /// Every place a retained parse charges is within its term, in work,
    /// requests, peak and what its document retains; every admission and
    /// request is made at some place; each place's witness charges it.
    /// Beside the witnesses: quick-only text, a misordered map that fails
    /// after its comparison, keys that are maps, long keys, and a truncated
    /// array whose terminal error is followed by its cleanup. Each input
    /// states whether it publishes a document; a cancelled or failing one
    /// does not, and any other outcome fails, naming the input.
    #[test]
    fn every_place_of_a_retained_parse_is_within_its_term() {
        let mut key_maps = CBOR::from(0u64);
        for _ in 0..3 {
            let mut next = Map::new();
            next.insert(CBOR::from(vec![CBOR::from(0u64), key_maps.clone()]), 0u64);
            next.insert(CBOR::from(vec![CBOR::from(1u64), key_maps.clone()]), 0u64);
            key_maps = CBOR::from(next);
        }
        let mut long_keys = Map::new();
        for i in 0..11u8 {
            long_keys.insert(ByteString::new(vec![i; 200]), 0u64);
        }
        let mut truncated = CBOR::from(vec![1u64; 40]).to_cbor_data();
        truncated.truncate(30);
        type Input = (
            String,
            Option<RetainedPlace>,
            Vec<u8>,
            Options,
            Cancel,
            bool,
        );
        let mut inputs: Vec<Input> = RetainedPlace::ALL
            .iter()
            .map(|&place| {
                let (name, input, options, cancel) = witness(place);
                (
                    format!("{name} ({place:?})"),
                    Some(place),
                    input,
                    options,
                    cancel,
                    cancel.is_none(),
                )
            })
            .collect();
        inputs.extend([
            (
                "quick text".to_string(),
                None,
                CBOR::from("x".repeat(300).as_str()).to_cbor_data(),
                Options::quick_only(0),
                None,
                true,
            ),
            // A text of `e` and U+0301 as its own bytes: the symbolic
            // encoding would normalize it to U+00E9, which the quick check
            // proves normal.
            (
                "quick-only failure".to_string(),
                None,
                vec![0x63, b'e', 0xcc, 0x81],
                Options::quick_only(0),
                None,
                false,
            ),
            (
                "misordered keys".to_string(),
                None,
                vec![0xa2, 0x02, 0x00, 0x01, 0x00],
                Options::normalizing(1),
                None,
                false,
            ),
            (
                "key maps".to_string(),
                None,
                key_maps.to_cbor_data(),
                Options::normalizing(8),
                None,
                true,
            ),
            (
                "long keys".to_string(),
                None,
                CBOR::from(long_keys).to_cbor_data(),
                Options::normalizing(1),
                None,
                true,
            ),
            (
                "truncated array".to_string(),
                None,
                truncated,
                Options::normalizing(1),
                None,
                false,
            ),
            (
                "large flat array".to_string(),
                None,
                CBOR::from(vec![0u64; 4096]).to_cbor_data(),
                Options::normalizing(1),
                None,
                true,
            ),
            (
                "long undecided run".to_string(),
                None,
                undecided_run(1000),
                Options::normalizing(0),
                None,
                true,
            ),
        ]);
        let mut runs = Vec::new();
        let mut witnesses = Vec::new();
        let mut documents = Vec::new();
        for (name, place, input, options, cancel, publishes) in &inputs {
            let (policy, document) = parsed(name, input, *options, *cancel);
            assert_eq!(
                document.is_some(),
                *publishes,
                "{name}: published a document"
            );
            documents.extend(document);
            if let Some(place) = place {
                witnesses.push((runs.len(), *place));
            }
            runs.push(Run {
                name: name.clone(),
                outcome: if cancel.is_some() {
                    places::Outcome::Cancelled
                } else if *publishes {
                    places::Outcome::Published
                } else {
                    places::Outcome::Invalid
                },
                policy,
                terms: RetainedTerms::of::<Permit, ()>(input.len() as u64, *options).unwrap(),
            });
        }
        places::check(&runs);
        places::witnessed(&runs, &witnesses);
        let work = "one undecided text of the whole input, its marks one unbroken run: its \
                    normalization, the dominant work term, orders every mark at every merge \
                    level; its heads, UTF-8 and comparison besides";
        let storage = "a flat array of one-byte items: a node per byte, the most the arena \
                       holds and publication retains";
        places::Tightness::new("retained_parse")
            .places(&runs, &witnesses, factor)
            .joint(&runs, "undecided run (Normalization)", WORK, work)
            .joint(&runs, "long undecided run", WORK, work)
            .joint(&runs, "flat array (Arena)", STORAGE, storage)
            .joint(&runs, "large flat array", STORAGE, storage)
            .finish();
        drop(documents);
    }
}
