//! Retained NFC preparation and canonical text emission over immutable input.
use super::decode::storage::Storage;
use super::*;
use unicode_normalization::char::{canonical_combining_class, compose, decompose_canonical};
mod initialization;
mod ordering;
pub use ordering::{OrderingPhase, OrderingPosition};
pub mod pipeline;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Phase {
    Read,
    Append,
    Order,
    ReleaseOrdering,
    Compose,
    Measure,
    /// The output's length is known; its release is admitted next, before
    /// it is requested.
    ReleaseOutput,
    Allocate,
    Header,
    Emit,
    ReleaseChars,
    Publish,
    ReclaimOrdering,
    ReclaimChars,
    Finished,
}

/// Progress and resource custody of the authoritative text continuation.
/// Counts describe initialized prefixes; observing never reads spare output
/// capacity or advances the normalizer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Position {
    pub phase: Phase,
    pub source_bytes: usize,
    pub ordering_index: usize,
    pub ordering_state: OrderingPosition,
    pub composed_input: usize,
    pub composed_output: usize,
    pub measured_scalars: usize,
    pub relocated_scalars: usize,
    pub emitted_bytes: usize,
    /// Character arena, including a partially admitted growth or relocation.
    pub characters: decode::storage::StoragePosition,
    /// Pending decomposition and its initialized/consumed prefix.
    pub pending: [char; text::MAX_SCALAR_PARTS],
    pub pending_len: usize,
    pub pending_at: usize,
    pub starter: Option<usize>,
    pub last_class: u8,
    pub payload_len: u64,
    pub header_len: usize,
    pub emitted_scalars: usize,
    /// Physical output capacity and whether its reservation remains held.
    pub output_capacity: usize,
    pub output_permit: bool,
}

/// Each step performs one scalar decomposition, one ordering unit (a part
/// examined, counted, scattered or copied back, or a counter table cleared
/// or summed), one composition, one storage relocation, or one scalar
/// emission. All
/// intermediate values and their reservations remain owned across refusal.
pub type TextEncoder<'a, P> = TextContinuation<&'a str, P>;

/// Normalization progress with an explicit source attachment. Owned decoding
/// uses `()` here and supplies a temporary source borrow to each turn.
#[doc(hidden)]
pub struct TextContinuation<S, P> {
    source: S,
    chars: Storage<char, P>,
    phase: Phase,
    source_at: usize,
    /// One scalar's canonical decomposition ([`text::MAX_SCALAR_PARTS`]).
    pending: [char; text::MAX_SCALAR_PARTS],
    pending_len: usize,
    pending_at: usize,
    ordering: ordering::Ordering<P>,
    read: usize,
    written: usize,
    starter: Option<usize>,
    last_class: u8,
    measure_at: usize,
    payload_len: u64,
    header: [u8; MAX_HEAD_LEN],
    header_len: usize,
    emit_at: usize,
    bytes: Vec<u8>,
    permit: Option<P>,
}

impl<P> TextEncoder<'_, P> {
    /// One step. A terminal error enters cleanup: later steps release the
    /// retained scratch and output, then return [`Step::Finished`].
    pub fn step<A: Allocator<Permit = P>>(
        &mut self,
        allocator: &mut A,
    ) -> BoundedResult<Step<Encoded<P>>, A> {
        let result = self.step_source(self.source, allocator);
        if matches!(&result, Err(error) if !error.refused()) {
            self.phase = Phase::ReclaimOrdering;
        }
        result
    }
}

/// What normalizing and encoding one text depends on, each at most: its
/// bytes, scalars, canonical decomposition parts and their UTF-8 bytes, the
/// parts of a nonzero combining class, and how those lie in runs: the
/// maximal runs of combining parts between starters, and the parts and runs
/// among them of two or more parts, the only ones the ordering sorts
/// ([`encode_bound`]). A character normalization leaves composed is never
/// longer than its decomposition, so the normalized text has at most the
/// parts' bytes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TextShape {
    pub bytes: u64,
    pub scalars: u64,
    pub parts: u64,
    pub part_bytes: u64,
    pub combining: u64,
    /// Maximal runs of combining parts, a run of one included: each ends
    /// in one find unit of the ordering.
    pub runs: u64,
    /// Combining parts in runs of two or more: each is counted, scattered
    /// and copied back in both radix passes.
    pub sorted_parts: u64,
    /// Runs of two or more combining parts: each clears and sums the
    /// counter table in both radix passes.
    pub sorted_runs: u64,
}

impl TextShape {
    /// The most any text of `bytes` bytes has in each count alone: a scalar
    /// per byte, at most [`text::PARTS_PER_BYTE`] parts, of at most
    /// [`text::PART_BYTES_PER_BYTE`] bytes together, and
    /// [`text::COMBINING_PARTS_PER_BYTE`] combining parts; a run per
    /// combining part, every combining part in a sorted run, and half as many
    /// sorted runs, each holding at least two. Every text's shape is within
    /// it; a bound of text not yet seen, such as a decode's input, is
    /// [`Self::worst_bound`], since no text has every count at once: its
    /// scalars trade against its parts, and its runs against its sorted
    /// parts.
    pub fn worst<R>(bytes: u64) -> Result<Self, BoundedError<R>> {
        // Each count is at most its per-byte rate times the bytes, rounded
        // down: every scalar holds the rate exactly, and counts are whole.
        let parts = parts::<R>(bytes)?;
        let (per, of) = text::COMBINING_PARTS_PER_BYTE;
        let combining = (mul(bytes, per)? / of).min(parts);
        let (part_bytes, of_bytes) = text::PART_BYTES_PER_BYTE;
        Ok(Self {
            bytes,
            scalars: bytes,
            parts,
            part_bytes: mul(bytes, part_bytes)? / of_bytes,
            combining,
            // A run holds at least one combining part, a sorted run two.
            runs: combining,
            sorted_parts: if combining < 2 { 0 } else { combining },
            sorted_runs: combining / 2,
        })
    }

    /// The most `bound` charges any text of `bytes` bytes, or texts of
    /// `bytes` bytes together, in every quantity. The parts, the combining
    /// parts and the part bytes of [`Self::worst`] are attained at once
    /// (`text::the_joint_counts_are_the_releases_own`); only the scalars
    /// trade against the parts ([`text::SCALARS_AND_PARTS_PER_BYTE`]), a sum
    /// over scalars. A bound of a text's shape, as every one of [`TextTerms`]
    /// is, rises with each count and charges each part at least what a
    /// scalar's read costs: so a scalar given up for a part never lowers it,
    /// and the most is at every part the bytes allow with every scalar those
    /// parts leave ([`Self::jointly`]). The part bytes are not traded against
    /// the scalars: a part byte charges no value, which a scalar's read does.
    ///
    /// The runs trade against the sorted parts: of `C` combining parts, `S`
    /// in `Q` sorted runs, the rest are runs of one, so a text has at most
    /// `C - S + Q` runs, and `Q <= floor(S / 2)`. Only the ordering charges
    /// them, `FIND (P + runs + 2) + MARK 6 S + TABLE 4 Q`; at the most runs
    /// that is `FIND (P + C + 2) + (6 MARK - FIND) S + (FIND + 4 TABLE) Q`,
    /// both coefficients positive in values and in bytes, so the most is at
    /// `S = C`, `Q = floor(C / 2)` and `floor(C / 2)` runs: every combining
    /// part in runs of two, as a letter of two marks in two bytes has them
    /// (U+01D5, U+0390).
    pub fn worst_bound<R>(
        bytes: u64,
        bound: impl Fn(Self) -> Result<ResourceBound, BoundedError<R>>,
    ) -> Result<ResourceBound, BoundedError<R>> {
        // Every part is appended in a unit of at least a scalar's read, in
        // values and in bytes; a scalar charges nothing else.
        const {
            assert!(APPEND.values() >= READ.values() && APPEND.bytes() >= READ.bytes());
        }
        bound(Self::jointly(bytes)?)
    }

    /// The shape [`Self::worst_bound`] charges for texts of `bytes` bytes:
    /// every part, combining part and part byte the bytes allow, every
    /// scalar those parts leave, and every combining part sorted in runs of
    /// two, the runs those leave.
    pub(crate) fn jointly<R>(bytes: u64) -> Result<Self, BoundedError<R>> {
        // Derived: the coefficients of the sorted parts and the sorted runs
        // at the most runs ([`Self::worst_bound`]) are positive in both
        // dimensions.
        const {
            let (find, mark, table) = (ordering::FIND, ordering::MARK, ordering::TABLE);
            assert!(6 * mark.values() > find.values() && 6 * mark.bytes() > find.bytes());
            assert!(find.values() + 4 * table.values() > 0);
        }
        let worst = Self::worst::<R>(bytes)?;
        let scalars = worst.scalars.min(
            mul(bytes, text::SCALARS_AND_PARTS_PER_BYTE)?
                .checked_sub(worst.parts)
                .ok_or(BoundedError::Overflow)?,
        );
        // Fewer than two combining parts sort nothing: one is a run of one.
        let (runs, sorted_parts, sorted_runs) = match worst.combining {
            combining @ 0..2 => (combining, 0, 0),
            combining => (combining / 2, combining, combining / 2),
        };
        Ok(Self {
            scalars,
            runs,
            sorted_parts,
            sorted_runs,
            ..worst
        })
    }

    /// `text`'s own counts, each scalar decomposed as the encoder decomposes
    /// it, its runs of combining parts continuing across scalars and ended by
    /// a starter or the text's end, as the ordering finds them. Counted in
    /// the same pass over the parts as the other counts.
    pub fn of(text: &str) -> Self {
        let mut shape = Self {
            bytes: text.len() as u64,
            ..Self::default()
        };
        let mut run = 0u64;
        for ch in text.chars() {
            shape.scalars += 1;
            decompose_canonical(ch, |part| {
                shape.parts += 1;
                shape.part_bytes += part.len_utf8() as u64;
                if canonical_combining_class(part) != 0 {
                    shape.combining += 1;
                    run += 1;
                } else {
                    shape.close(run);
                    run = 0;
                }
            });
        }
        shape.close(run);
        shape
    }

    /// A run of `run` combining parts ended: counted, and as sorted when it
    /// holds two or more.
    fn close(&mut self, run: u64) {
        if run > 0 {
            self.runs += 1;
        }
        if run >= 2 {
            self.sorted_parts += run;
            self.sorted_runs += 1;
        }
    }

    /// The larger of this text and `other` in every count: at most either.
    pub fn larger(self, other: Self) -> Self {
        Self {
            bytes: self.bytes.max(other.bytes),
            scalars: self.scalars.max(other.scalars),
            parts: self.parts.max(other.parts),
            part_bytes: self.part_bytes.max(other.part_bytes),
            combining: self.combining.max(other.combining),
            runs: self.runs.max(other.runs),
            sorted_parts: self.sorted_parts.max(other.sorted_parts),
            sorted_runs: self.sorted_runs.max(other.sorted_runs),
        }
    }
}

/// The [`ResourceBound`] of normalizing and encoding a text of `text`'s
/// shape with a [`TextContinuation`], from its first step to publication,
/// or to any failure and the cleanup after it. For `S` scalars, `P` parts
/// and `C` combining parts, each charged where `step_source` charges it:
///
/// - reading: one unit of one value and four bytes per scalar, and one at
///   the end;
/// - appending: one unit per part, and one per character the arena of
///   decomposed characters relocates as it grows ([`storage_growth`]);
/// - ordering ([`ordering`]): one unit per character copied into the
///   scratch, and one per relocated scratch character; one unit of a
///   character to begin, one per part examined and one per run's end to
///   find the runs, and one to end: `P + runs + 2`. A run of one combining
///   part is in order; a run of `r >= 2` is sorted by two stable counting
///   passes over the low and the high four bits of its classes, each a
///   cleared table, `r` counts, a summed table, `r` scatters and `r` copies
///   back: `4` table units and `6r` part units, `6 S + 4 Q` for `S` sorted
///   parts in `Q` sorted runs. Linear in the text, whatever its runs;
/// - releasing the scratch, then later the characters: plain data, a settled
///   arena discarded in one unit of no bytes (`Storage::reclaim_copy_step`),
///   one cancelled while staging a growth or relocating drained one unit per
///   element, the most charged; and at most two releases, each at most 64
///   bytes; a text of no parts never allocates either arena, and each
///   release is one unit of no bytes; cancelled after either release,
///   cleanup passes over that released arena in one more unit of no bytes;
/// - composing: one unit of two values and eight bytes per part and one at
///   the end; measuring and emitting: one unit per composed character, at
///   most `P`, and one at the end each; the header: one unit of its bytes,
///   the head of a payload of at most the parts' bytes;
/// - publishing: one unit of the published encoding's own size.
///
/// The output is allocated once at its exact length, at most the parts'
/// bytes and their head, no head being shorter for a longer payload; it is
/// what publication retains. The peak
/// holds the characters with the scratch's growth, or the characters with
/// the output. Refused, never saturated, when a quantity does not fit in
/// `u64`.
pub fn encode_bound<P, R>(text: TextShape) -> Result<ResourceBound, BoundedError<R>> {
    TextTerms::of::<R>(
        text,
        publication::<P, R>()?,
        output_release::<P, R>()?,
        cleanup::<R>()?,
    )?
    .bound()
}

/// The [`ResourceBound`] of [`encode_bound`] but for its publication, its
/// output's release and its cleanup, the only terms that depend on the
/// permit type: what a walk over a source's texts sums per text before the
/// permit is known.
pub fn normalization_bound<R>(text: TextShape) -> Result<ResourceBound, BoundedError<R>> {
    TextTerms::of::<R>(
        text,
        WriteWork::default(),
        WriteWork::default(),
        WriteWork::default(),
    )?
    .bound()
}

places! {
    /// The places a [`TextContinuation`] charges, one term of
    /// [`encode_bound`] each.
    pub(crate) enum TextPlace {
        Reading,
        Appending,
        Copying,
        Ordering,
        ReleasingScratch,
        Composing,
        Measuring,
        Output,
        Header,
        Emitting,
        ReleasingChars,
        Publishing,
        Cleanup,
    }
}

/// Reading one scalar of the source, or its end: one value and a scalar's
/// bytes.
const READ: Unit<TextPlace> = Unit::of::<char>(TextPlace::Reading);

/// Appending one decomposed part to the arena of characters.
const APPEND: Unit<TextPlace> = Unit::of::<char>(TextPlace::Appending);

/// Composing one character with the current starter, or the end: two
/// characters read.
const COMPOSE: Unit<TextPlace> = Unit::new(
    TextPlace::Composing,
    2,
    2 * core::mem::size_of::<char>() as u64,
);

/// Measuring one composed character's encoded length, or the end.
const MEASURE: Unit<TextPlace> = Unit::of::<char>(TextPlace::Measuring);

/// Writing the head: one value and its bytes, at most [`MAX_HEAD_LEN`].
const HEADER: Capped<TextPlace> = Capped::new(TextPlace::Header, 1, MAX_HEAD_LEN as u64);

/// Emitting one composed character, or the end.
const EMIT: Unit<TextPlace> = Unit::of::<char>(TextPlace::Emitting);

/// A cleanup transition: one unit of no bytes.
const CLEANUP: Unit<TextPlace> = Unit::new(TextPlace::Cleanup, 1, 0);

/// Publishing the encoding with permits of `P`: one value and the published
/// value's bytes.
const fn published<P>() -> Unit<TextPlace> {
    Unit::of::<Encoded<P>>(TextPlace::Publishing)
}

/// Releasing the output with permits of `P`: its bytes freed and its permit
/// dropped, one value and the bytes of both. Admitted before the output is
/// requested, so its release, by cleanup or by whoever drops the published
/// encoding, is paid for.
const fn output_released<P>() -> Unit<TextPlace> {
    const { Unit::written::<(Vec<u8>, Option<P>)>(TextPlace::Output) }
}

/// The publication's work ([`published`]): what an encoding charges to
/// publish, wherever its caller counts it.
pub(crate) fn publication<P, R>() -> Result<WriteWork, BoundedError<R>> {
    published::<P>().times(1)
}

/// The output's release with permits of `P` ([`output_released`]), admitted
/// before the output is requested.
pub(crate) fn output_release<P, R>() -> Result<WriteWork, BoundedError<R>> {
    output_released::<P>().times(1)
}

/// Cleanup after a terminal error: its transition, one unit. The output's
/// release, if one was requested, was paid for by its request.
fn cleanup<R>() -> Result<WriteWork, BoundedError<R>> {
    CLEANUP.times(1)
}

/// The cleanup of a continuation interrupted in a text of `text`'s shape
/// ([`TextContinuation::reclaim_step`]): its scratch and its characters
/// drained and released, and its transition; none of the normalization it
/// did, which its own place charged.
pub(crate) fn interrupted<R>(text: TextShape) -> Result<WriteWork, BoundedError<R>> {
    let terms = TextTerms::of::<R>(
        text,
        WriteWork::default(),
        WriteWork::default(),
        cleanup::<R>()?,
    )?;
    terms
        .releasing_scratch
        .then(terms.releasing_chars)?
        .then(terms.cleanup)
}

/// The [`ResourceBound`] of normalizing and encoding `texts` texts one after
/// another, each published and released by its caller before the next, their
/// counts together at most `total`'s and none beyond `total` in any count,
/// without a cleanup: what a parse charges for every text it normalizes,
/// before it sees them. Each text's bound ([`encode_bound`]) is affine in
/// its counts but for its two arenas' growth, so the sum is at most:
///
/// - the bound at the summed counts, each affine term at the sum and every
///   fixed term once;
/// - an empty text's bound for each other text: its fixed terms;
/// - the arenas of characters and of ordering scratch growing apart in each
///   text: of `P` parts, fewer than `2P` relocated and at most `4P + 4`
///   requested each, and released in two units each;
/// - each text's head, of its output and of its header write, at most the
///   summed parts' head.
///
/// One text is held at a time: the peak is the summed shape's, at least any
/// one text's. Nothing is retained.
pub(crate) fn normalizations<P, R>(
    total: TextShape,
    texts: u64,
) -> Result<ResourceBound, BoundedError<R>> {
    if texts == 0 {
        return Ok(ResourceBound::default());
    }
    let publication = publication::<P, R>()?;
    let released = output_release::<P, R>()?;
    let summed =
        TextTerms::of::<R>(total, publication, released, WriteWork::default())?.bound::<R>()?;
    let fixed = TextTerms::of::<R>(
        TextShape::default(),
        publication,
        released,
        WriteWork::default(),
    )?
    .bound::<R>()?
    .repeated::<R>(texts - 1)?;
    const ARENAS: u64 = 2;
    let scalar = widen(core::mem::size_of::<char>())?;
    // Each arena of a text of `p` parts grows at most `floor(p / 4) + 1`
    // times, its capacity doubling from four: over the texts at most a
    // quarter of the parts and one per text, for each arena. Each growth
    // writes in its own units, stages a block of at most a quantum and
    // admits the releases of its two allocations.
    let growths = mul(add(total.parts / 4, texts)?, ARENAS)?;
    let apart = Storage::<char, ()>::element_work(mul(mul(total.parts, 2)?, ARENAS)?)?
        .then(Storage::<char, ()>::cleanup_work(true)?.times(mul(texts, ARENAS)?)?)?
        .then(Storage::<char, ()>::growth_work(growths)?)?
        .then(RELEASED.times(mul(growths, 2)?)?)?;
    let requested = add(
        mul(
            mul(add(mul(total.parts, 4)?, mul(texts, 4)?)?, ARENAS)?,
            scalar,
        )?,
        mul(growths, TURN.bytes)?,
    )?;
    let heads = mul(texts, widen(head_len(total.part_bytes))?)?;
    Ok(ResourceBound {
        values: add(add(summed.values, fixed.values)?, apart.values)?,
        bytes: add(add(add(summed.bytes, fixed.bytes)?, apart.bytes)?, heads)?,
        allocated: add(
            add(add(summed.allocated, fixed.allocated)?, requested)?,
            heads,
        )?,
        peak: summed.peak,
        retained: 0,
    })
}

/// The terms [`encode_bound`] sums, one per [`TextPlace`].
pub(crate) struct TextTerms {
    reading: WriteWork,
    appending: ResourceBound,
    copying: ResourceBound,
    ordering: WriteWork,
    releasing_scratch: WriteWork,
    composing: WriteWork,
    measuring: WriteWork,
    output: ResourceBound,
    header: WriteWork,
    emitting: WriteWork,
    releasing_chars: WriteWork,
    publishing: WriteWork,
    cleanup: WriteWork,
    /// The characters' arena: held while the scratch grows, and while the
    /// output is written.
    chars: Growth,
}

impl TextTerms {
    /// The terms of a text of `text`'s shape, its publication `publication`,
    /// its output's release `released`, admitted before the output is
    /// requested, and its cleanup after a terminal error `cleanup`.
    pub(crate) fn of<R>(
        text: TextShape,
        publication: WriteWork,
        released: WriteWork,
        cleanup: WriteWork,
    ) -> Result<Self, BoundedError<R>> {
        let parts = text.parts;
        let scalar = widen(core::mem::size_of::<char>())?;
        let (chars, growing) = storage_growth::<R>(parts, scalar)?;
        let growing = growing.then(chars.released()?)?;
        // Derived from `Ordering::step`: a find unit per part examined, per
        // run's end and to begin and end; for each sorted run, per pass, a
        // cleared and a summed table and per part a count, a scatter and a
        // copy back: `6` part units per sorted part, `4` table units per
        // sorted run. A run of one is in order: nothing but its end.
        let ordering = ordering::FIND
            .times(add(add(parts, text.runs)?, 2)?)?
            .then(ordering::MARK.times(mul(text.sorted_parts, 6)?)?)?
            .then(ordering::TABLE.times(mul(text.sorted_runs, 4)?)?)?;
        // The payload is at most the parts' bytes, and its head at most
        // theirs: no head is shorter for a longer payload.
        let head = widen(head_len(text.part_bytes))?;
        let output = add(text.part_bytes, head)?;
        // Every element drained, the most a release takes: a settled arena
        // of plain characters is discarded in one unit, but one cancelled
        // while staging a growth or relocating drains one unit per element
        // (`Storage::reclaim_copy_step`); then the arena's cleanup, its
        // releases paid for by its growths; and, cancelled after that
        // cleanup, cleanup's pass over the released arena, one step of no
        // bytes.
        let drained = Storage::<char, ()>::element_work(parts)?
            .then(Storage::<char, ()>::cleanup_work(parts != 0)?)?
            .then(Storage::<char, ()>::step_work(1)?)?;
        // An arena grown to hold every part: every relocated element one
        // unit of its bytes, each growth's writes, and each allocation's
        // release.
        let arena = |unit: Unit<TextPlace>| -> Result<ResourceBound, BoundedError<R>> {
            let work = unit.times(parts)?.then(growing)?;
            Ok(ResourceBound {
                values: work.values,
                bytes: work.bytes,
                allocated: chars.allocated,
                peak: chars.peak,
                retained: 0,
            })
        };
        // One unit per part and one at the end.
        let ends = add(parts, 1)?;
        Ok(Self {
            reading: READ.times(add(text.scalars, 1)?)?,
            appending: arena(APPEND)?,
            copying: arena(ordering::COPY)?,
            ordering,
            releasing_scratch: drained,
            composing: COMPOSE.times(ends)?,
            measuring: MEASURE.times(ends)?,
            output: ResourceBound {
                values: released.values,
                bytes: released.bytes,
                allocated: output,
                peak: output,
                retained: output,
            },
            header: HEADER.covering(head, 0)?,
            emitting: EMIT.times(ends)?,
            releasing_chars: drained,
            publishing: publication,
            cleanup,
            chars,
        })
    }

    /// The terms of a [`pipeline::TextPreparation`]: the normalization as
    /// far as its output's release and allocation, which it never reaches,
    /// so neither the output, the header, the emission, the characters'
    /// release nor the publication; it publishes the characters' arena.
    pub(crate) fn prepared(self) -> Self {
        Self {
            appending: ResourceBound {
                retained: self.chars.held,
                ..self.appending
            },
            output: ResourceBound::default(),
            header: WriteWork::default(),
            emitting: WriteWork::default(),
            releasing_chars: WriteWork::default(),
            publishing: WriteWork::default(),
            ..self
        }
    }
}

impl Places for TextTerms {
    type Place = TextPlace;

    fn term(&self, place: TextPlace) -> ResourceBound {
        match place {
            TextPlace::Reading => ResourceBound::of_work(self.reading),
            TextPlace::Appending => self.appending,
            TextPlace::Copying => self.copying,
            TextPlace::Ordering => ResourceBound::of_work(self.ordering),
            TextPlace::ReleasingScratch => ResourceBound::of_work(self.releasing_scratch),
            TextPlace::Composing => ResourceBound::of_work(self.composing),
            TextPlace::Measuring => ResourceBound::of_work(self.measuring),
            TextPlace::Output => self.output,
            TextPlace::Header => ResourceBound::of_work(self.header),
            TextPlace::Emitting => ResourceBound::of_work(self.emitting),
            TextPlace::ReleasingChars => ResourceBound::of_work(self.releasing_chars),
            TextPlace::Publishing => ResourceBound::of_work(self.publishing),
            TextPlace::Cleanup => ResourceBound::of_work(self.cleanup),
        }
    }

    /// The characters' arena held while the scratch grows, or while the
    /// output is written; never both of those at once.
    fn peak<R>(&self) -> Result<u64, BoundedError<R>> {
        add(self.chars.held, self.copying.peak.max(self.output.peak))
    }
}

/// The most decomposed parts a text of `source` bytes has
/// ([`text::PARTS_PER_BYTE`]), rounded down: whole parts within the rate.
fn parts<R>(source: u64) -> Result<u64, BoundedError<R>> {
    let (per, of) = text::PARTS_PER_BYTE;
    Ok(mul(source, per)? / of)
}

impl<P, A: Allocator<Permit = P>> Resumable<A> for TextEncoder<'_, P> {
    type Output = Encoded<P>;
    type Error = BoundedError<A::Refusal>;
    type Position = Position;

    fn step(&mut self, allocator: &mut A) -> BoundedResult<Step<Encoded<P>>, A> {
        TextEncoder::step(self, allocator)
    }

    fn position(&mut self) -> Position {
        TextContinuation::position(self)
    }
}

impl<S, P> TextContinuation<S, P> {
    pub const fn new(source: S) -> Self {
        Self {
            source,
            chars: Storage::new(),
            phase: Phase::Read,
            source_at: 0,
            pending: ['\0'; text::MAX_SCALAR_PARTS],
            pending_len: 0,
            pending_at: 0,
            ordering: ordering::Ordering::new(),
            read: 0,
            written: 0,
            starter: None,
            last_class: 0,
            measure_at: 0,
            payload_len: 0,
            header: [0; MAX_HEAD_LEN],
            header_len: 0,
            emit_at: 0,
            bytes: Vec::new(),
            permit: None,
        }
    }

    pub fn position(&self) -> Position {
        Position {
            phase: self.phase,
            source_bytes: self.source_at,
            ordering_index: self.ordering.position(),
            ordering_state: self.ordering.state(),
            composed_input: self.read,
            composed_output: self.written,
            measured_scalars: self.measure_at,
            relocated_scalars: self.chars.relocated(),
            emitted_bytes: self.bytes.len(),
            characters: self.chars.position(),
            pending: self.pending,
            pending_len: self.pending_len,
            pending_at: self.pending_at,
            starter: self.starter,
            last_class: self.last_class,
            payload_len: self.payload_len,
            header_len: self.header_len,
            emitted_scalars: self.emit_at,
            output_capacity: self.bytes.capacity(),
            output_permit: self.permit.is_some(),
        }
    }

    /// Incomplete bytes are observation only, never a published CBOR value.
    pub fn emitted_prefix(&self) -> &[u8] {
        &self.bytes
    }

    /// Cancel and release one retained resource unit. Admission closes before
    /// cleanup starts; subsequent calls cannot resume text production.
    pub fn reclaim_step<A: Allocator<Permit = P>>(
        &mut self,
        allocator: &mut A,
    ) -> BoundedResult<bool, A> {
        match self.phase {
            Phase::ReclaimOrdering => {
                if at(TextPlace::ReleasingScratch, || {
                    self.ordering.reclaim_step(allocator)
                })? {
                    self.phase = Phase::ReclaimChars;
                }
            }
            // Characters are plain data: a settled arena of them is discarded
            // in one unit, whatever it holds; one cancelled while relocating
            // or staging drains per element, which the bound counts.
            Phase::ReclaimChars => {
                if at(TextPlace::ReleasingChars, || {
                    self.chars.reclaim_copy_step(allocator)
                })? {
                    // The output, if one was requested, is released in the
                    // same unit: its request paid for its release.
                    self.bytes = Vec::new();
                    self.permit = None;
                    self.phase = Phase::Finished;
                    return Ok(true);
                }
            }
            Phase::Finished => return Ok(true),
            _ => {
                CLEANUP.admit(allocator)?;
                self.phase = Phase::ReclaimOrdering;
            }
        }
        Ok(false)
    }

    /// The most successful calls [`Self::reclaim_step`] still takes, the one
    /// returning true included: the transition into cleanup unless it has
    /// begun, the scratch's own count while it is being released, then the
    /// characters'; one once finished. Admits nothing and changes nothing.
    pub(crate) fn reclaim_remaining(&self) -> u64 {
        let ordering = self.ordering.reclaim_remaining();
        let chars = self.chars.reclaim_remaining();
        match self.phase {
            Phase::Finished => 1,
            Phase::ReclaimChars => chars,
            Phase::ReclaimOrdering => ordering.saturating_add(chars),
            _ => ordering.saturating_add(chars).saturating_add(1),
        }
    }

    pub(crate) fn step_source<A: Allocator<Permit = P>>(
        &mut self,
        source: &str,
        allocator: &mut A,
    ) -> BoundedResult<Step<Encoded<P>>, A> {
        match self.phase {
            Phase::Read => {
                READ.admit(allocator)?;
                let Some(ch) = source[self.source_at..].chars().next() else {
                    self.phase = Phase::Order;
                    return Ok(Step::Progress);
                };
                let mut count = 0usize;
                decompose_canonical(ch, |part| {
                    if let Some(slot) = self.pending.get_mut(count) {
                        *slot = part;
                    }
                    count += 1;
                });
                // The pinned release decomposes no scalar into more parts
                // than the scratch holds (`text::MAX_SCALAR_PARTS`, held by
                // its test); a release that did is refused here, not
                // truncated.
                if count > self.pending.len() {
                    return Err(BoundedError::OutOfRange);
                }
                self.pending_len = count;
                self.pending_at = 0;
                self.source_at += ch.len_utf8();
                self.phase = Phase::Append;
            }
            Phase::Append => {
                let chars = &mut self.chars;
                // A growth unit of the arena, or a free slot for the part.
                let Some(spare) = at(TextPlace::Appending, || {
                    chars.reserve_step(usize::MAX, allocator)
                })?
                else {
                    return Ok(Step::Progress);
                };
                APPEND.admit(allocator)?;
                spare.push(self.pending[self.pending_at]);
                self.pending_at += 1;
                self.phase = if self.pending_at == self.pending_len {
                    Phase::Read
                } else {
                    Phase::Append
                };
            }
            Phase::Order => {
                let Some(chars) = self.chars.settle_step(allocator)? else {
                    return Ok(Step::Progress);
                };
                if self.ordering.step(chars.as_mut_slice(), allocator)? {
                    self.phase = Phase::ReleaseOrdering;
                }
            }
            Phase::ReleaseOrdering => {
                if at(TextPlace::ReleasingScratch, || {
                    self.ordering.reclaim_step(allocator)
                })? {
                    self.phase = Phase::Compose;
                }
            }
            Phase::Compose => {
                let Some(chars) = self.chars.settle_step(allocator)? else {
                    return Ok(Step::Progress);
                };
                COMPOSE.admit(allocator)?;
                let chars = chars.as_mut_slice();
                if self.read == chars.len() {
                    self.phase = Phase::Measure;
                    return Ok(Step::Progress);
                }
                let ch = chars[self.read];
                let class = canonical_combining_class(ch);
                let combined = self.starter.and_then(|at| {
                    if self.last_class == 0 || self.last_class < class {
                        compose(chars[at], ch)
                    } else {
                        None
                    }
                });
                if let Some(combined) = combined {
                    if let Some(at) = self.starter {
                        chars[at] = combined;
                    }
                } else {
                    if class == 0 {
                        self.starter = Some(self.written);
                    }
                    chars[self.written] = ch;
                    self.written += 1;
                    self.last_class = class;
                }
                self.read += 1;
            }
            Phase::Measure => {
                let Some(chars) = self.chars.settle_step(allocator)? else {
                    return Ok(Step::Progress);
                };
                MEASURE.admit(allocator)?;
                if self.measure_at == self.written {
                    self.header_len = write_argument(
                        MajorType::Text,
                        Argument::Shortest(self.payload_len),
                        &mut self.header,
                    );
                    self.phase = Phase::ReleaseOutput;
                } else {
                    self.payload_len = add(
                        self.payload_len,
                        chars.as_slice()[self.measure_at].len_utf8() as u64,
                    )?;
                    self.measure_at += 1;
                }
            }
            Phase::ReleaseOutput => {
                output_released::<P>().admit(allocator)?;
                self.phase = Phase::Allocate;
            }
            Phase::Allocate => {
                let length = add(self.payload_len, self.header_len as u64)?;
                let size = usize::try_from(length).map_err(|_| BoundedError::Overflow)?;
                let permit = at(TextPlace::Output, || allocator.allocate(length))
                    .map_err(BoundedError::Refused)?;
                self.bytes
                    .try_reserve_exact(size)
                    .map_err(|_| BoundedError::Allocation { bytes: length })?;
                self.permit = Some(permit);
                self.phase = Phase::Header;
                // Continue to actual emission; a refusal retains the newly
                // allocated output and never repeats allocation admission.
                return self.step_source(source, allocator);
            }
            Phase::Header => {
                HEADER.admit(allocator, self.header_len as u64)?;
                self.bytes
                    .extend_from_slice(&self.header[..self.header_len]);
                self.phase = Phase::Emit;
            }
            Phase::Emit => {
                let Some(chars) = self.chars.settle_step(allocator)? else {
                    return Ok(Step::Progress);
                };
                EMIT.admit(allocator)?;
                if self.emit_at == self.written {
                    self.phase = Phase::ReleaseChars;
                    return Ok(Step::Progress);
                }
                let mut encoded = [0; 4];
                self.bytes.extend_from_slice(
                    chars.as_slice()[self.emit_at]
                        .encode_utf8(&mut encoded)
                        .as_bytes(),
                );
                self.emit_at += 1;
            }
            Phase::ReleaseChars => {
                if at(TextPlace::ReleasingChars, || {
                    self.chars.reclaim_copy_step(allocator)
                })? {
                    self.phase = Phase::Publish;
                }
            }
            Phase::Publish => {
                published::<P>().admit(allocator)?;
                let permit = self.permit.take().ok_or(BoundedError::PlanMismatch)?;
                self.phase = Phase::Finished;
                return Ok(Step::Complete(Encoded {
                    bytes: core::mem::take(&mut self.bytes),
                    _permit: permit,
                }));
            }
            Phase::ReclaimOrdering | Phase::ReclaimChars => {
                self.reclaim_step(allocator)?;
            }
            Phase::Finished => return Ok(Step::Finished),
        }
        Ok(Step::Progress)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bounded::{Limits, Reservation, within};
    use core::ops::ControlFlow;
    use pipeline::{TextPreparation, preparation_bound};
    use unicode_normalization::UnicodeNormalization;

    /// What preparing `text` reported, requested and held at its peak, and
    /// what its published plan holds.
    fn prepared(text: &str) -> (WriteWork, u64, u64, u64) {
        let bound = preparation_bound::<Reservation, ()>(TextShape::of(text)).unwrap();
        let mut limits = Limits::unlimited();
        let mut preparation = TextPreparation::<Reservation>::new(text);
        let plan = within("text preparation", bound, || {
            match preparation.step(&mut limits).unwrap() {
                Step::Progress => ControlFlow::Continue(()),
                Step::Complete(plan) => ControlFlow::Break(plan),
                Step::Finished => unreachable!("preparation finished without a plan"),
            }
        });
        let retained = limits.live_bytes();
        let expected: String = text.nfc().collect();
        assert_eq!(
            plan.len(),
            item_len::<()>(expected.len() as u64, expected.len() as u64).unwrap()
        );
        drop(plan);
        assert_eq!(limits.live_bytes(), 0);
        (
            limits.used(),
            limits.requested_bytes(),
            limits.peak_bytes(),
            retained,
        )
    }

    /// What encoding `text` reported, requested and held at its peak, and
    /// what its published output holds.
    fn measured(text: &str) -> (WriteWork, u64, u64, u64) {
        let bound = encode_bound::<Reservation, ()>(TextShape::of(text)).unwrap();
        let mut limits = Limits::unlimited();
        let mut encoder = TextEncoder::<Reservation>::new(text);
        let encoded = within("text encoding", bound, || {
            match encoder.step(&mut limits).unwrap() {
                Step::Progress => ControlFlow::Continue(()),
                Step::Complete(encoded) => ControlFlow::Break(encoded),
                Step::Finished => unreachable!("encoding finished without output"),
            }
        });
        let retained = limits.live_bytes();
        let expected: String = text.nfc().collect();
        assert_eq!(
            &encoded.as_ref()[encoded.as_ref().len() - expected.len()..],
            expected.as_bytes()
        );
        drop(encoded);
        assert_eq!(limits.live_bytes(), 0);
        (
            limits.used(),
            limits.requested_bytes(),
            limits.peak_bytes(),
            retained,
        )
    }

    /// A text with the most parts per byte: the precomposed letter with the
    /// longest canonical decomposition.
    fn maximal() -> char {
        (0..=0x10_ffffu32)
            .filter_map(char::from_u32)
            .max_by_key(|ch| {
                let mut parts = 0u64;
                unicode_normalization::char::decompose_canonical(*ch, |_| parts += 1);
                parts
            })
            .unwrap()
    }

    /// The texts the bounds are checked on: long disordered combining runs,
    /// maximal decompositions, Hangul, runs of one class, leading marks, and
    /// text already normal; letters of a starter and two marks in two bytes,
    /// every part the bytes allow in runs of two; a letter whose three
    /// trailing marks begin a run of marks one per byte; and scalars of a
    /// byte beside letters of three parts in two, the scalars traded against
    /// the parts ([`text::SCALARS_AND_PARTS_PER_BYTE`]).
    fn texts() -> [String; 12] {
        [
            String::new(),
            "ordinary".into(),
            "x".repeat(10_000),
            format!("q{}", "\u{301}\u{316}".repeat(2048)),
            "a\u{301}\u{316}".repeat(500),
            "\u{1100}\u{1161}\u{11a8}".repeat(300),
            maximal().to_string().repeat(500),
            "\u{301}".repeat(2000),
            "\u{e9}".repeat(1000),
            "\u{1d5}".repeat(1000),
            format!("\u{1f82}{}", "\u{344}".repeat(1000)),
            format!("{}{}", "x".repeat(1000), "\u{390}".repeat(500)),
        ]
    }

    /// Every text is encoded, and prepared, within the bound of its own
    /// shape, which the worst shape of its length covers in every count.
    #[test]
    fn the_encode_and_preparation_bounds_cover_every_text() {
        for text in &texts() {
            let encoding = measured(text);
            let preparation = prepared(text);
            let shape = TextShape::of(text);
            let worst = TextShape::worst::<()>(text.len() as u64).unwrap();
            assert_eq!(
                worst.larger(shape),
                worst,
                "{} bytes: {shape:?}",
                text.len()
            );
            let length = text.len() as u64;
            for (what, encoding_of, preparation_of) in [
                (
                    format!("{shape:?}"),
                    encode_bound::<Reservation, ()>(shape).unwrap(),
                    preparation_bound::<Reservation, ()>(shape).unwrap(),
                ),
                (
                    format!("{worst:?}"),
                    encode_bound::<Reservation, ()>(worst).unwrap(),
                    preparation_bound::<Reservation, ()>(worst).unwrap(),
                ),
                (
                    format!("the joint worst of {length} bytes"),
                    TextShape::worst_bound(length, encode_bound::<Reservation, ()>).unwrap(),
                    TextShape::worst_bound(length, preparation_bound::<Reservation, ()>).unwrap(),
                ),
            ] {
                let bounds = [
                    ("encoding", encoding_of, encoding),
                    ("preparation", preparation_of, preparation),
                ];
                for (name, bound, (used, requested, peak, retained)) in bounds {
                    assert!(
                        bound.covers(used, requested, peak, retained),
                        "{name} of {what}: used {used:?}, requested {requested}, peak {peak}, retained {retained}; {bound:?}"
                    );
                }
            }
        }
        assert_eq!(
            TextShape::worst::<()>(u64::MAX),
            Err(BoundedError::Overflow)
        );
        let full = TextShape {
            bytes: u64::MAX,
            scalars: u64::MAX,
            parts: u64::MAX,
            part_bytes: u64::MAX,
            combining: u64::MAX,
            runs: u64::MAX,
            sorted_parts: u64::MAX,
            sorted_runs: u64::MAX,
        };
        assert_eq!(
            encode_bound::<Reservation, ()>(full),
            Err(BoundedError::Overflow)
        );
        assert_eq!(
            preparation_bound::<Reservation, ()>(full),
            Err(BoundedError::Overflow)
        );
    }

    /// A text's shape is within the worst shape of its length in every count.
    /// Every count but the run counts is a sum over the text's scalars, and
    /// the worst shape takes each sum's per-byte maximum, rounded down: every
    /// scalar within those maxima exactly, without rounding, puts every text
    /// of any length within them. The run counts are within the combining
    /// parts by their definition ([`joint_counts_hold`]), which the worst
    /// shape takes at their most. The per-scalar derivation is checked for
    /// every scalar, then the dominance itself on texts that maximize each
    /// count.
    #[test]
    fn the_worst_shape_dominates_every_text_of_its_length() {
        let (parts_per, parts_of) = text::PARTS_PER_BYTE;
        let (combining_per, combining_of) = text::COMBINING_PARTS_PER_BYTE;
        let (bytes_per, bytes_of) = text::PART_BYTES_PER_BYTE;
        for ch in (0..=0x10_ffffu32).filter_map(char::from_u32) {
            let mut stable = [0; 4];
            let shape = TextShape::of(ch.encode_utf8(&mut stable));
            let at = || format!("U+{:04X}: {shape:?}", ch as u32);
            assert!(shape.scalars <= shape.bytes, "{}", at());
            assert!(
                shape.parts * parts_of <= shape.bytes * parts_per,
                "{} beyond the parts per byte",
                at()
            );
            assert!(
                shape.combining * combining_of <= shape.bytes * combining_per,
                "{} beyond the combining parts per byte",
                at()
            );
            assert!(
                shape.part_bytes * bytes_of <= shape.bytes * bytes_per,
                "{} beyond the part bytes per byte",
                at()
            );
        }
        let adversarial = [
            "\u{344}".repeat(4096),
            format!("q{}", "\u{344}".repeat(4096)),
            format!("a{}", "\u{301}\u{344}".repeat(1000)),
            format!("{}\u{344}", "e\u{301}".repeat(500)),
        ];
        for text in adversarial.iter().chain(texts().iter()) {
            let shape = TextShape::of(text);
            let worst = TextShape::worst::<()>(text.len() as u64).unwrap();
            assert_eq!(
                worst.larger(shape),
                worst,
                "{} bytes: {shape:?} beyond {worst:?}",
                text.len()
            );
        }
    }

    /// One scalar of each distinct way a scalar enters a text's shape under
    /// the pinned release: its bytes, parts, combining parts, part bytes and
    /// which of its parts are combining, in order. A text's shape is a
    /// function of its scalars' entries in order, so the texts built of these
    /// have every shape texts of their lengths have.
    const ALPHABET: [char; 33] = [
        'x',
        '\u{37e}',
        '\u{80}',
        '\u{300}',
        '\u{c0}',
        '\u{1e2}',
        '\u{344}',
        '\u{1d5}',
        '\u{390}',
        '\u{1fef}',
        '\u{1fbe}',
        '\u{800}',
        '\u{fa6c}',
        '\u{816}',
        '\u{9cb}',
        '\u{1e00}',
        '\u{1e9b}',
        '\u{1fcd}',
        '\u{929}',
        '\u{f73}',
        '\u{ccb}',
        '\u{ddd}',
        '\u{1e08}',
        '\u{1f02}',
        '\u{1f82}',
        '\u{2f800}',
        '\u{10000}',
        '\u{101fd}',
        '\u{1112e}',
        '\u{105c9}',
        '\u{1109a}',
        '\u{16126}',
        '\u{1d160}',
    ];

    /// How a scalar enters a text's shape: its bytes, parts, part bytes and
    /// whether each part is combining.
    fn entry(ch: char) -> (usize, u64, Vec<bool>) {
        let mut combining = Vec::new();
        let mut part_bytes = 0;
        decompose_canonical(ch, |part| {
            combining.push(canonical_combining_class(part) != 0);
            part_bytes += part.len_utf8() as u64;
        });
        (ch.len_utf8(), part_bytes, combining)
    }

    /// The alphabet holds one scalar of every entry the pinned release has,
    /// and no two of one.
    #[test]
    fn the_alphabet_holds_every_entry_once() {
        // The prelude's set (`import_stdlib!`): `alloc`'s without `std`.
        let every: BTreeSet<_> = (0..=0x10_ffffu32)
            .filter_map(char::from_u32)
            .map(entry)
            .collect();
        let alphabet: BTreeSet<_> = ALPHABET.into_iter().map(entry).collect();
        assert_eq!(alphabet.len(), ALPHABET.len(), "two scalars share an entry");
        assert_eq!(alphabet, every);
    }

    /// The joint counts a text's shape satisfies, failing with the text
    /// named: its scalars beside its parts
    /// ([`text::SCALARS_AND_PARTS_PER_BYTE`]); and its runs, which the joint
    /// worst bound trades against its sorted parts
    /// ([`TextShape::worst_bound`]): a sorted run holds at least two parts,
    /// every other run one, so the sorted parts and the runs of one together
    /// are at most the combining parts.
    fn joint_counts_hold(name: &str, shape: TextShape) {
        assert!(
            shape.scalars + shape.parts <= text::SCALARS_AND_PARTS_PER_BYTE * shape.bytes,
            "{name}: {shape:?}: the scalars beside the parts"
        );
        assert!(
            2 * shape.sorted_runs <= shape.sorted_parts,
            "{name}: {shape:?}: a sorted run of fewer than two parts"
        );
        assert!(
            shape.sorted_runs <= shape.runs,
            "{name}: {shape:?}: more sorted runs than runs"
        );
        assert!(
            shape.sorted_parts + (shape.runs - shape.sorted_runs) <= shape.combining,
            "{name}: {shape:?}: the runs beside the sorted parts"
        );
    }

    /// Every text of the alphabet of at most `most` bytes, by its length.
    fn texts_of(most: usize) -> Vec<Vec<String>> {
        let mut by_length = vec![Vec::new(); most + 1];
        by_length[0].push(String::new());
        for length in 1..=most {
            let mut texts = Vec::new();
            for ch in ALPHABET {
                let width = ch.len_utf8();
                if width <= length {
                    for prefix in &by_length[length - width] {
                        let mut text = prefix.clone();
                        text.push(ch);
                        texts.push(text);
                    }
                }
            }
            by_length[length] = texts;
        }
        by_length
    }

    /// A bound of a text's shape.
    type Consumer = fn(TextShape) -> Result<ResourceBound, BoundedError<()>>;

    /// The bounds of a text's shape [`TextShape::worst_bound`] is taken
    /// over: an encoding, a preparation, and one text's normalization as a
    /// parse charges it.
    fn consumers() -> [(&'static str, Consumer); 3] {
        [
            ("encoding", encode_bound::<Reservation, ()>),
            ("preparation", preparation_bound::<Reservation, ()>),
            ("normalization", |shape| {
                normalizations::<Reservation, ()>(shape, 1)
            }),
        ]
    }

    /// The joint counts lift from scalars to texts: every text of the
    /// alphabet of up to eight bytes, every order of every entry and so every
    /// run crossing a scalar, satisfies them; and long texts drawn from it do
    /// too.
    #[test]
    fn the_joint_counts_hold_of_every_text() {
        for (length, texts) in texts_of(8).into_iter().enumerate() {
            for text in texts {
                joint_counts_hold(&format!("{length} bytes {text:?}"), TextShape::of(&text));
            }
        }
        let mut state = 0x2545_f491_4f6c_dd1du64;
        for index in 0..2000 {
            let mut text = String::new();
            let scalars = (index % 64) * 16;
            for _ in 0..scalars {
                state = state
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                text.push(ALPHABET[(state >> 33) as usize % ALPHABET.len()]);
            }
            joint_counts_hold(&format!("generated {index}"), TextShape::of(&text));
        }
    }

    /// The joint worst bound reaches the exact most each consumer charges
    /// any text of the alphabet, and so any text, of up to eight bytes, in
    /// every quantity; how far above it lies is recorded for each length.
    #[cfg(feature = "std")]
    #[test]
    fn the_joint_worst_bound_reaches_every_text_and_is_recorded_against_the_most() {
        use crate::bounded::places::{EVERY, Tightness};
        let mut tightness = Tightness::new("text_joint");
        for (length, texts) in texts_of(8).into_iter().enumerate().skip(1) {
            let length = length as u64;
            for (name, consumer) in consumers() {
                let bound = TextShape::worst_bound(length, consumer).unwrap();
                let mut most = ResourceBound::default();
                for text in &texts {
                    let charged = consumer(TextShape::of(text)).unwrap();
                    assert!(
                        bound.covers(
                            charged.work(),
                            charged.allocated,
                            charged.peak,
                            charged.retained
                        ),
                        "{name} of {text:?}: {charged:?} beyond {bound:?}"
                    );
                    most = most.larger(charged);
                }
                tightness.exact(&format!("{name} of {length} bytes"), bound, most, EVERY);
            }
        }
        tightness.finish();
    }

    /// The ordering of a text's combining runs charges exactly the per-phase
    /// count its term derives ([`ordering`]): one find unit per part, per
    /// run's end and to begin and end; and for each run of `r >= 2` parts,
    /// `6r` part units and `4` table units, whatever its length; a run of one
    /// nothing more. The term at the text's own shape is that count exactly,
    /// and the shape's run counts are the runs counted here independently.
    /// Checked on one long run, many short runs, runs of one, runs of two,
    /// mixed runs, runs continuing across a scalar's decomposition, a
    /// leading run and none.
    #[cfg(feature = "std")]
    #[test]
    fn ordering_charges_its_derived_per_phase_count() {
        use crate::bounded::places::{Ledgered, Permit};
        for text in [
            String::new(),
            "ordinary".into(),
            format!(
                "q{}{}{}",
                "\u{301}".repeat(512),
                "\u{316}".repeat(512),
                "\u{334}".repeat(512)
            ),
            "a\u{301}\u{316}".repeat(300),
            "e\u{301}".repeat(300),
            "\u{1d5}".repeat(300),
            "\u{390}".repeat(300),
            "\u{301}".repeat(700),
            format!("q{}", "\u{344}".repeat(400)),
            format!("e\u{301}a\u{301}\u{316}q{}x", "\u{316}\u{301}".repeat(40)).repeat(20),
            format!("a\u{301}{}e\u{301}", "\u{344}".repeat(30)).repeat(20),
            "\u{1100}\u{1161}\u{11a8}".repeat(50),
        ] {
            // The runs of combining parts the decomposition holds, starters
            // delimiting them.
            let (mut parts, mut runs, mut long) = (0u64, Vec::new(), 0u64);
            let mut run = 0u64;
            for ch in text.chars() {
                decompose_canonical(ch, |part| {
                    parts += 1;
                    if canonical_combining_class(part) == 0 {
                        if run > 0 {
                            runs.push(run);
                        }
                        run = 0;
                    } else {
                        run += 1;
                    }
                });
            }
            if run > 0 {
                runs.push(run);
            }
            let mut sorted = 0;
            for &length in &runs {
                if length >= 2 {
                    sorted += 1;
                    long += length;
                }
            }
            let expected = ordering::FIND
                .times(parts + runs.len() as u64 + 2)
                .and_then(|work| work.then(ordering::MARK.times::<()>(6 * long)?))
                .and_then(|work| work.then(ordering::TABLE.times::<()>(4 * sorted)?))
                .unwrap();
            let mut policy = Ledgered::new();
            let mut encoder = TextEncoder::<Permit>::new(&text);
            let bound = encode_bound::<Permit, ()>(TextShape::of(&text)).unwrap();
            let output = within("ordered text encoding", bound, || {
                match encoder.step(&mut policy).unwrap() {
                    Step::Complete(output) => ControlFlow::Break(output),
                    _ => ControlFlow::Continue(()),
                }
            });
            let normal: String = text.nfc().collect();
            assert!(
                output.as_ref().ends_with(normal.as_bytes()),
                "{text:?}: not its normalization"
            );
            let measured = policy.ledger().measured(TextPlace::Ordering).work();
            assert_eq!(measured, expected, "{text:?}: runs {runs:?}");
            let shape = TextShape::of(&text);
            assert_eq!(
                (shape.runs, shape.sorted_parts, shape.sorted_runs),
                (runs.len() as u64, long, sorted),
                "{text:?}: runs {runs:?}"
            );
            let term = TextTerms::of::<()>(
                shape,
                publication::<Permit, ()>().unwrap(),
                output_release::<Permit, ()>().unwrap(),
                cleanup::<()>().unwrap(),
            )
            .unwrap()
            .term(TextPlace::Ordering)
            .work();
            assert_eq!(term, measured, "{text:?}: the term is not the work done");
        }
    }

    /// The trade the joint worst bound makes between a text's runs and its
    /// sorted parts ([`TextShape::worst_bound`]): over every feasible split
    /// of `C` combining parts into `S` sorted parts in `Q` sorted runs and
    /// `C - S` runs of one, no consumer charges more than at every part in
    /// runs of two, the shape [`TextShape::jointly`] takes.
    #[test]
    fn every_part_sorted_in_pairs_is_the_most_any_runs_charge() {
        for (name, consumer) in consumers() {
            for combining in [0u64, 1, 2, 3, 4, 7, 8, 15, 16, 35, 64] {
                let base = TextShape {
                    bytes: 140,
                    scalars: 70,
                    parts: 105,
                    part_bytes: 210,
                    combining,
                    ..TextShape::default()
                };
                let jointly = TextShape::jointly::<()>(base.bytes).unwrap();
                let paired = consumer(TextShape {
                    runs: if combining < 2 {
                        combining
                    } else {
                        combining / 2
                    },
                    sorted_parts: if combining < 2 { 0 } else { combining },
                    sorted_runs: combining / 2,
                    ..base
                })
                .unwrap();
                // The same split the joint worst shape takes at its own
                // combining parts.
                assert_eq!(
                    (jointly.runs, jointly.sorted_parts, jointly.sorted_runs),
                    (
                        jointly.combining / 2,
                        jointly.combining,
                        jointly.combining / 2
                    )
                );
                for sorted_parts in 0..=combining {
                    for sorted_runs in 0..=sorted_parts / 2 {
                        // A sorted part lies in a sorted run of two or more.
                        if (sorted_parts > 0) != (sorted_runs > 0) {
                            continue;
                        }
                        let runs = combining - sorted_parts + sorted_runs;
                        let charged = consumer(TextShape {
                            runs,
                            sorted_parts,
                            sorted_runs,
                            ..base
                        })
                        .unwrap();
                        assert_eq!(
                            paired.larger(charged),
                            paired,
                            "{name}: {combining} combining, {sorted_parts} sorted in \
                             {sorted_runs} runs"
                        );
                    }
                }
            }
        }
    }

    /// Ordering work, and a whole encoding's, grows linearly in a run's
    /// length: at a run of `n`, `2n`, `4n` and `8n` combining parts the
    /// ordering's work rises by exactly twice the step before, and the
    /// encoding's at most eight times over eight times the text.
    #[cfg(feature = "std")]
    #[test]
    fn ordering_and_encoding_work_grow_linearly_in_a_run() {
        use crate::bounded::places::{Ledgered, Permit};
        let run = |n: usize| {
            let text = format!("q{}", "\u{316}\u{301}".repeat(n));
            let mut policy = Ledgered::new();
            let mut encoder = TextEncoder::<Permit>::new(&text);
            let bound = encode_bound::<Permit, ()>(TextShape::of(&text)).unwrap();
            let output = within("run encoding", bound, || {
                match encoder.step(&mut policy).unwrap() {
                    Step::Complete(output) => ControlFlow::Break(output),
                    _ => ControlFlow::Continue(()),
                }
            });
            drop(output);
            let ledger = policy.ledger();
            (
                ledger.measured(TextPlace::Ordering).work(),
                ledger.total().work(),
            )
        };
        let n = 256;
        let [one, two, four, eight] = [n, 2 * n, 4 * n, 8 * n].map(run);
        for (field, of) in [
            (
                "values",
                (|work: WriteWork| work.values) as fn(WriteWork) -> u64,
            ),
            ("bytes", |work| work.bytes),
        ] {
            let step =
                |low: (WriteWork, WriteWork), high: (WriteWork, WriteWork)| of(high.0) - of(low.0);
            assert_eq!(step(two, four), 2 * step(one, two), "ordering {field}");
            assert_eq!(step(four, eight), 2 * step(two, four), "ordering {field}");
            assert!(
                of(eight.1) <= 8 * of(one.1),
                "encoding {field}: {} at {}, {} at {}",
                of(one.1),
                n,
                of(eight.1),
                8 * n
            );
        }
    }

    /// A part given for a scalar never lowers any consumer's charge, in any
    /// quantity, over shapes of every count around the arenas' growths: the
    /// trade the joint worst bound makes.
    #[test]
    fn a_part_for_a_scalar_never_lowers_a_charge() {
        for (name, consumer) in consumers() {
            for parts in 0..=70u64 {
                for scalars in 1..=70u64 {
                    for combining in [0, 1, 2, 3, 4, 7, 8, 15, 16, 35] {
                        let combining = combining.min(parts);
                        // Every combining part alone, and every one in pairs.
                        for (runs, sorted_parts, sorted_runs) in
                            [(combining, 0, 0), (combining / 2, combining, combining / 2)]
                        {
                            let shape = TextShape {
                                bytes: 140,
                                scalars,
                                parts,
                                part_bytes: 3 * parts,
                                combining,
                                runs,
                                sorted_parts,
                                sorted_runs,
                            };
                            let traded = TextShape {
                                scalars: scalars - 1,
                                parts: parts + 1,
                                ..shape
                            };
                            let (before, after) =
                                (consumer(shape).unwrap(), consumer(traded).unwrap());
                            assert_eq!(after.larger(before), after, "{name}: {shape:?}");
                        }
                    }
                }
            }
        }
    }

    /// The joint worst bound is refused, never wrapped, where a count does
    /// not fit in `u64`, and is charged at the largest lengths that fit.
    #[test]
    fn the_joint_worst_bound_is_total() {
        for (name, consumer) in consumers() {
            assert_eq!(
                TextShape::worst_bound(u64::MAX, consumer),
                Err(BoundedError::Overflow),
                "{name}"
            );
            assert!(TextShape::worst_bound(1 << 40, consumer).is_ok(), "{name}");
        }
        assert_eq!(
            TextShape::jointly::<()>(u64::MAX),
            Err(BoundedError::Overflow)
        );
    }

    /// A shape counts the scalars, parts and combining parts the encoder
    /// decomposes: U+0344 into two marks, U+00E9 into a letter and a mark,
    /// a Hangul syllable into its jamo; and the runs of marks, continuing
    /// across scalars and ended by a starter: U+0344's two marks a sorted
    /// run, U+00E9's mark a run of one. The larger of two shapes is the
    /// larger in every count.
    #[test]
    fn a_text_shape_counts_its_decomposition() {
        assert_eq!(TextShape::of(""), TextShape::default());
        let mixed = TextShape::of("a\u{344}\u{e9}\u{ac00}");
        assert_eq!(
            mixed,
            TextShape {
                bytes: 1 + 2 + 2 + 3,
                scalars: 4,
                parts: 1 + 2 + 2 + 2,
                part_bytes: 1 + (2 + 2) + (1 + 2) + (3 + 3),
                combining: 3,
                runs: 2,
                sorted_parts: 2,
                sorted_runs: 1,
            }
        );
        // Two marks and U+0344's two: one sorted run of four across
        // scalars; then a run of one. Five combining parts.
        let crossing = TextShape::of("a\u{301}\u{316}\u{344}e\u{301}");
        assert_eq!(
            (
                crossing.combining,
                crossing.runs,
                crossing.sorted_parts,
                crossing.sorted_runs
            ),
            (5, 2, 4, 1)
        );
        let wide = TextShape::of("xxxxxxxxxxxx");
        assert_eq!(
            mixed.larger(wide),
            TextShape {
                bytes: 12,
                scalars: 12,
                parts: 12,
                part_bytes: 14,
                combining: 3,
                runs: 2,
                sorted_parts: 2,
                sorted_runs: 1,
            }
        );
    }

    /// No character normalization leaves composed is longer in UTF-8 than
    /// its full canonical decomposition. Every character of a normalized
    /// text is a part, or a composition of the parts it absorbed, whose full
    /// decomposition those parts are and which normalization leaves
    /// composed; so a normalized text has at most its parts' bytes. A
    /// singleton such as U+037E, longer than its decomposition, is never
    /// composed again.
    #[test]
    fn no_composition_is_longer_than_its_decomposition() {
        let mut composed = 0;
        for ch in (0..=0x10_ffffu32).filter_map(char::from_u32) {
            let mut decomposed = 0;
            let mut parts = 0;
            decompose_canonical(ch, |part| {
                decomposed += part.len_utf8();
                parts += 1;
            });
            let mut stable = [0; 4];
            let source: &str = ch.encode_utf8(&mut stable);
            if source.nfc().eq(source.chars()) && (parts, decomposed) != (1, ch.len_utf8()) {
                composed += 1;
                assert!(
                    ch.len_utf8() <= decomposed,
                    "U+{:04X}: {} bytes, decomposed into {decomposed}",
                    ch as u32,
                    ch.len_utf8()
                );
            }
        }
        assert!(composed > 0, "no composed character was examined");
        let mut singleton = 0;
        decompose_canonical('\u{37e}', |part| singleton += part.len_utf8());
        assert!(singleton < '\u{37e}'.len_utf8());
        assert_eq!("\u{37e}".nfc().collect::<String>(), ";");
    }

    /// Where an encoding is cancelled into its cleanup: before the step
    /// numbered by the count of steps taken, at a position the condition
    /// holds of.
    #[cfg(feature = "std")]
    type Cancel = fn(usize, &Position) -> bool;

    /// A text whose encoding charges `place`, and where it is cancelled into
    /// its cleanup, if it is: a place without a witness does not compile.
    /// The releases are witnessed where they drain one character per unit,
    /// which their terms charge: an arena is discarded in one unit once
    /// settled, so each is cancelled while relocating, at its last growth.
    /// The text's 129 parts fill each arena's capacity of 128, whose growth
    /// relocates all 128.
    #[cfg(feature = "std")]
    fn witness(place: TextPlace) -> (String, Option<Cancel>) {
        use crate::bounded::decode::storage::{StoragePosition, StorageStage};
        /// Whether an arena relocates its last growth's 128 characters.
        fn last_growth(arena: StoragePosition) -> bool {
            arena.stage == StorageStage::Relocating && arena.relocating_remaining >= 128
        }
        match place {
            TextPlace::Reading
            | TextPlace::Appending
            | TextPlace::Composing
            | TextPlace::Measuring
            | TextPlace::Output
            | TextPlace::Header
            | TextPlace::Emitting
            | TextPlace::Publishing => ("ordinary".into(), None),
            TextPlace::ReleasingChars => (
                format!("q{}", "\u{301}\u{316}".repeat(64)),
                Some(|_, position| last_growth(position.characters)),
            ),
            TextPlace::Copying | TextPlace::Ordering => {
                (format!("q{}", "\u{301}\u{316}".repeat(64)), None)
            }
            TextPlace::ReleasingScratch => (
                format!("q{}", "\u{301}\u{316}".repeat(64)),
                Some(|_, position| last_growth(position.ordering_state.scratch)),
            ),
            TextPlace::Cleanup => (
                format!("q{}", "\u{301}\u{316}".repeat(64)),
                Some(|steps, _| steps == 200),
            ),
        }
    }

    /// Every place an encoding, and a preparation, charges is within its
    /// term on every text, in work, requests, peak and what it publishes;
    /// every admission and request is made at some place; each place's
    /// witness charges it. Outputs are held until the check.
    #[cfg(feature = "std")]
    #[test]
    fn every_place_of_an_encoding_and_a_preparation_is_within_its_term() {
        use crate::bounded::places::{self, EVERY, Factor, Ledgered, Permit, Run, WORK};
        // U+0390: a starter and two marks in two bytes, six bytes of parts:
        // every part, combining part and part byte per byte at once, every
        // mark in a sorted run of two, a scalar per two bytes.
        let worst = "\u{390}".repeat(2048);
        let encoding = |shape| {
            TextTerms::of::<()>(
                shape,
                publication::<Permit, ()>().unwrap(),
                output_release::<Permit, ()>().unwrap(),
                cleanup::<()>().unwrap(),
            )
            .unwrap()
        };
        let mut cases: Vec<(String, Option<TextPlace>, String, Option<Cancel>)> = TextPlace::ALL
            .iter()
            .map(|&place| {
                let (text, cancel) = witness(place);
                (format!("witness of {place:?}"), Some(place), text, cancel)
            })
            .collect();
        for text in texts() {
            cases.push((format!("{:?}", TextShape::of(&text)), None, text, None));
        }
        cases.push(("worst text".into(), None, worst, None));
        let mut encodings = Vec::new();
        let mut witnesses = Vec::new();
        let mut outputs = Vec::new();
        for (name, place, text, cancel) in &cases {
            let shape = TextShape::of(text);
            let bound = encode_bound::<Permit, ()>(shape).unwrap();
            let mut policy = Ledgered::new();
            let mut encoder = TextEncoder::<Permit>::new(text);
            let mut steps = 0;
            let outcome = within(name, bound, || {
                if cancel.is_some_and(|cancel| cancel(steps, &encoder.position())) {
                    within(name, bound, || {
                        if encoder.reclaim_step(&mut policy).unwrap() {
                            ControlFlow::Break(())
                        } else {
                            ControlFlow::Continue(())
                        }
                    });
                    return ControlFlow::Break(places::Outcome::Cancelled);
                }
                steps += 1;
                match encoder.step(&mut policy).unwrap() {
                    Step::Complete(output) => {
                        outputs.push(output);
                        ControlFlow::Break(places::Outcome::Published)
                    }
                    _ => ControlFlow::Continue(()),
                }
            });
            assert_eq!(
                outcome,
                if cancel.is_some() {
                    places::Outcome::Cancelled
                } else {
                    places::Outcome::Published
                },
                "{name}: declared outcome not reached"
            );
            if let Some(place) = place {
                witnesses.push((encodings.len(), *place));
            }
            encodings.push(Run {
                name: name.clone(),
                outcome,
                policy,
                terms: encoding(shape),
            });
        }
        // The worst text checked at the worst shape of its length, which it
        // reaches in every count but its scalars and runs.
        {
            let text = "\u{390}".repeat(2048);
            let bound = encode_bound::<Permit, ()>(TextShape::of(&text)).unwrap();
            let mut policy = Ledgered::new();
            let mut encoder = TextEncoder::<Permit>::new(&text);
            outputs.push(within("worst text encoding", bound, || {
                match encoder.step(&mut policy).unwrap() {
                    Step::Complete(output) => ControlFlow::Break(output),
                    _ => ControlFlow::Continue(()),
                }
            }));
            encodings.push(Run {
                name: "worst text at the worst shape".into(),
                outcome: places::Outcome::Published,
                policy,
                terms: encoding(TextShape::worst::<()>(text.len() as u64).unwrap()),
            });
        }
        let mut plans = Vec::new();
        for (name, _, text, _) in &cases {
            let shape = TextShape::of(text);
            let bound = preparation_bound::<Permit, ()>(shape).unwrap();
            let mut policy = Ledgered::new();
            let mut preparation = TextPreparation::<Permit>::new(text);
            plans.push(within(name, bound, || {
                match preparation.step(&mut policy).unwrap() {
                    Step::Complete(plan) => ControlFlow::Break(plan),
                    _ => ControlFlow::Continue(()),
                }
            }));
            // A preparation reaches its cleanup only after a physical
            // allocation failure; the encodings' cancellations exercise it.
            encodings.push(Run {
                name: format!("preparation of {name}"),
                outcome: places::Outcome::Published,
                policy,
                terms: TextTerms::of::<()>(
                    shape,
                    WriteWork::default(),
                    WriteWork::default(),
                    cleanup::<()>().unwrap(),
                )
                .unwrap()
                .prepared(),
            });
        }
        places::check(&encodings);
        places::witnessed(&encodings, &witnesses);
        places::Tightness::new("text_encode")
            .places(&encodings, &witnesses, |place| match place {
                TextPlace::Reading
                | TextPlace::Appending
                | TextPlace::Copying
                | TextPlace::Ordering
                | TextPlace::ReleasingScratch
                | TextPlace::Composing
                | TextPlace::Measuring
                | TextPlace::Output
                | TextPlace::Header
                | TextPlace::Emitting
                | TextPlace::ReleasingChars
                | TextPlace::Publishing
                | TextPlace::Cleanup => Factor::Measured,
            })
            .joint(
                &encodings,
                "worst text",
                EVERY,
                "a starter and two marks per two bytes: every part appended, copied and \
                 composed, every mark in a sorted run of two, counted, scattered and copied \
                 back in both radix passes with a table per run, at its own shape",
            )
            // What a caller charges a text of its length not yet seen.
            .joint_bound(
                &encodings,
                "worst text",
                "joint worst",
                TextShape::worst_bound(
                    "\u{390}".repeat(2048).len() as u64,
                    encode_bound::<Permit, ()>,
                )
                .unwrap(),
                EVERY,
                "every part, combining part and part byte the bytes allow, beside every \
                 scalar those parts leave, every mark in a sorted run of two",
            )
            // Every text's encoding and preparation, at its own shape and the
            // worst text at the worst shape, recorded: an overstated term
            // moves a record, as an understated one fails the check above.
            .totals(&encodings, WORK)
            .finish();
        drop((outputs, plans));
    }

    /// Every place of an encoding is within its term on generated texts,
    /// every fifth cancelled partway into its cleanup; each text's shape is
    /// within the worst of its length; each completed output is the text's
    /// normalization.
    #[cfg(feature = "std")]
    #[test]
    fn every_place_of_an_encoding_is_within_its_term_on_generated_texts() {
        use crate::bounded::places::{self, Ledgered, Permit, Run};
        let mut generator = crate::bounded::tests::Generator::new(0x5eed_0002);
        let mut runs = Vec::new();
        let mut outputs = Vec::new();
        for index in 0..400usize {
            let text = generator.text(64);
            let name = format!("generated {index}: {text:?}");
            let shape = TextShape::of(&text);
            let worst = TextShape::worst::<()>(text.len() as u64).unwrap();
            assert_eq!(worst.larger(shape), worst, "{name}");
            let cancel = (index % 5 == 0).then_some(index % 20 + 1);
            let bound = encode_bound::<Permit, ()>(shape).unwrap();
            let mut policy = Ledgered::new();
            let mut encoder = TextEncoder::<Permit>::new(&text);
            let mut steps = 0;
            let outcome = within(&name, bound, || {
                if cancel == Some(steps) {
                    within(&name, bound, || {
                        if encoder
                            .reclaim_step(&mut policy)
                            .expect("an unlimited policy never refuses")
                        {
                            ControlFlow::Break(())
                        } else {
                            ControlFlow::Continue(())
                        }
                    });
                    return ControlFlow::Break(places::Outcome::Cancelled);
                }
                steps += 1;
                let step = encoder
                    .step(&mut policy)
                    .expect("an unlimited policy never refuses");
                if let Step::Complete(encoded) = step {
                    let expected: String = text.nfc().collect();
                    assert!(
                        encoded.as_ref().ends_with(expected.as_bytes()),
                        "{name}: not its normalization"
                    );
                    outputs.push(encoded);
                    return ControlFlow::Break(places::Outcome::Published);
                }
                ControlFlow::Continue(())
            });
            runs.push(Run {
                name,
                outcome,
                policy,
                terms: TextTerms::of::<()>(
                    shape,
                    publication::<Permit, ()>().unwrap(),
                    output_release::<Permit, ()>().unwrap(),
                    cleanup::<()>().unwrap(),
                )
                .unwrap(),
            });
        }
        places::check(&runs);
        drop(outputs);
    }

    /// Encoding is its normalization, one publication unit of the published
    /// encoding's size, the output's release admitted before it is
    /// requested, of its bytes and its permit, and the cleanup a terminal
    /// error leaves: a transition.
    #[test]
    fn encoding_is_normalization_publication_and_cleanup() {
        use core::mem::size_of;
        let shape = TextShape::of("a\u{344}");
        let normalization = normalization_bound::<()>(shape).unwrap();
        let encoding = encode_bound::<Reservation, ()>(shape).unwrap();
        assert_eq!(
            encoding,
            ResourceBound {
                values: normalization.values + 1 + 1 + 1,
                bytes: normalization.bytes
                    + size_of::<Encoded<Reservation>>() as u64
                    + size_of::<(Vec<u8>, Option<Reservation>)>() as u64,
                ..normalization
            }
        );
    }
}
