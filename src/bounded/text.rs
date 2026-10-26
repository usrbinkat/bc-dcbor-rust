//! Text under the bounded encoding: the NFC form's length and bytes,
//! produced without the allocating `.nfc()` iterator the symbolic path
//! collects (`cbor.rs`).
//!
//! Text the quick check proves already in NFC (`is_nfc_quick`, which reads
//! only lookup tables and allocates nothing) is its own normal form: its
//! write copies it. Every other text, `No` and `Maybe` alike, is normalized
//! once, during preparation, by `normalize`, and its normal form is kept
//! in the plan for the write to copy.
//!
//! `normalize` is a push-model restatement of `unicode-normalization`
//! 0.1.25's `Decompositions` and `Recompositions` (`decompose.rs`,
//! `recompose.rs`) over the same public character primitives
//! (`decompose_canonical`, `canonical_combining_class`, `compose`), so the
//! Unicode data, the Hangul algorithms and the composition rules are that
//! crate's; the dependency is pinned exactly for that reason, and its tests
//! compare this restatement with that crate's own iterator. Its buffers, the
//! combining characters awaiting canonical order, the characters blocked
//! from the current starter, and the normal form, grow only through
//! [`Owned`], each allocation admitted before it is made and released when
//! it is freed. Canonical ordering uses stable counting sort over the 256
//! possible combining classes. Each run takes O(n + 256) work and O(n)
//! admitted scratch, with no insertion shifts or comparison sort. Unicode's
//! fixed maximum decomposition length makes the complete normalization linear
//! in the input length. Finite budgets can refuse before each pass.

import_stdlib!();

use unicode_normalization::{
    IsNormalized,
    char::{canonical_combining_class, compose, decompose_canonical},
    is_nfc_quick,
};

use super::{
    Allocator, BoundedError, BoundedResult, Budget, Capped, Owned, Places, Rate, ResourceBound,
    Scan, Unit, WriteWork, at, owned_growth, widen,
};

places! {
    /// The places strict validation ([`is_normalized`]) charges, one term of
    /// [`validation_bound`] each. Each groups the sites its term derives
    /// together: the quick checks, character visits and byte passes share
    /// the input's bytes, which no two of them count twice.
    pub(crate) enum ValidationPlace {
        Reading,
        Decomposing,
        Ordering,
        Emitting,
        Buffers,
    }
}

/// The quick check of a text: one value and its bytes.
const QUICK: Scan<ValidationPlace> = Scan::new(ValidationPlace::Reading, 1);

/// A pass over a text's bytes: its characters decoded, its normal form
/// compared.
const PASS: Scan<ValidationPlace> = Scan::new(ValidationPlace::Reading, 0);

/// Each source character, before its decomposition.
const CHARACTER: Unit<ValidationPlace> = Unit::new(ValidationPlace::Reading, 1, 0);

/// Each decomposed part.
const PART: Unit<ValidationPlace> = Unit::new(ValidationPlace::Decomposing, 1, 0);

/// The classes a counting pass counts over: every combining class.
const CLASSES: u64 = 256;

/// A counting pass over the waiting combining parts: the histogram and the
/// prefix sum over twice [`CLASSES`] counters, and per part its count, its
/// placement and its slot's initialization, four pair slots of bytes.
const COUNTING: Rate<ValidationPlace> = Rate::based(
    ValidationPlace::Ordering,
    WriteWork::new(
        2 * CLASSES,
        2 * CLASSES * core::mem::size_of::<usize>() as u64,
    ),
    WriteWork::new(3, 4 * core::mem::size_of::<(u8, char)>() as u64),
);

/// Each part a counting pass hands to composition.
const HANDED: Unit<ValidationPlace> = Unit::new(ValidationPlace::Ordering, 1, 0);

/// Each character of the normal form: one value and its bytes.
const EMITTED: Capped<ValidationPlace> =
    Capped::new(ValidationPlace::Emitting, 1, char::MAX.len_utf8() as u64);

/// The normalization of one text: its buffers and the composition state.
struct Normalizer<'b, A: Allocator> {
    allocator: &'b mut A,
    /// Combining characters since the last starter, in source order.
    pending: Owned<(u8, char), A::Permit>,
    /// Reusable destination for stable counting sort.
    ordered: Owned<(u8, char), A::Permit>,
    /// Characters blocked from `composee`, in order.
    blocked: Owned<char, A::Permit>,
    /// The normal form, in UTF-8.
    normal: Owned<u8, A::Permit>,
    composee: Option<char>,
    last_ccc: Option<u8>,
}

impl<A: Allocator> Normalizer<'_, A> {
    /// One character of the normal form.
    fn emit(&mut self, ch: char) -> BoundedResult<(), A> {
        EMITTED.admit(&mut *self.allocator, widen(ch.len_utf8())?)?;
        let mut encoded = [0u8; 4];
        let bytes = ch.encode_utf8(&mut encoded).as_bytes();
        at(ValidationPlace::Buffers, || {
            self.normal.extend_from_slice(bytes, &mut *self.allocator)
        })
    }

    /// One character of the canonical decomposition, in text order
    /// (`Decompositions::push_back`): a starter releases the combining
    /// characters before it in canonical order, then itself; a combining
    /// character waits for stable counting sort at the next boundary.
    fn decomposed(&mut self, ch: char) -> BoundedResult<(), A> {
        PART.admit(&mut *self.allocator)?;
        let class = canonical_combining_class(ch);
        if class == 0 {
            self.release()?;
            return self.composed(ch);
        }
        at(ValidationPlace::Buffers, || {
            self.pending.push((class, ch), &mut *self.allocator)
        })
    }

    /// Release the waiting combining characters, in canonical order, to
    /// composition. Composition never touches `pending`; the emptied buffer
    /// is put back with its allocation for the next run.
    fn release(&mut self) -> BoundedResult<(), A> {
        if self.pending.is_empty() {
            return Ok(());
        }
        let count = self.pending.len();
        // Histogram, prefix sum, stable distribution and initialization are
        // admitted before reading or filling either buffer.
        COUNTING.admit(&mut *self.allocator, widen(count)?)?;
        at(ValidationPlace::Buffers, || {
            self.ordered.reserve(count, &mut *self.allocator)
        })?;
        let mut offsets = [0usize; CLASSES as usize];
        for &(class, _) in self.pending.as_slice() {
            offsets[usize::from(class)] += 1;
        }
        let mut start = 0;
        for offset in &mut offsets {
            let length = *offset;
            *offset = start;
            start += length;
        }
        self.ordered.items.resize(count, (0, '\0'));
        for &entry in self.pending.as_slice() {
            let offset = &mut offsets[usize::from(entry.0)];
            self.ordered.items[*offset] = entry;
            *offset += 1;
        }
        self.pending.items.clear();
        core::mem::swap(&mut self.pending, &mut self.ordered);
        let mut waiting = core::mem::take(&mut self.pending);
        for (_, ch) in waiting.drain() {
            HANDED.admit(&mut *self.allocator)?;
            self.composed(ch)?;
        }
        self.pending = waiting;
        Ok(())
    }

    /// One character of the canonically ordered decomposition, composed
    /// with the current starter where `Recompositions::next` composes it,
    /// emitted in the order it emits.
    fn composed(&mut self, ch: char) -> BoundedResult<(), A> {
        let class = canonical_combining_class(ch);
        let Some(starter) = self.composee else {
            if class != 0 {
                // A combining character before any starter is emitted as it
                // comes.
                return self.emit(ch);
            }
            self.composee = Some(ch);
            return Ok(());
        };
        match self.last_ccc {
            None => match compose(starter, ch) {
                Some(composed) => {
                    self.composee = Some(composed);
                    Ok(())
                }
                None if class == 0 => {
                    self.composee = Some(ch);
                    self.emit(starter)
                }
                None => self.block(ch, class),
            },
            Some(last) if last >= class => {
                if class != 0 {
                    return self.block(ch, class);
                }
                // A starter blocked from the current one: the current one,
                // then everything blocked, then the new one composes.
                self.composee = Some(ch);
                self.last_ccc = None;
                self.emit(starter)?;
                self.purge()
            }
            Some(_) => match compose(starter, ch) {
                Some(composed) => {
                    self.composee = Some(composed);
                    Ok(())
                }
                None => self.block(ch, class),
            },
        }
    }

    fn block(&mut self, ch: char, class: u8) -> BoundedResult<(), A> {
        at(ValidationPlace::Buffers, || {
            self.blocked.push(ch, &mut *self.allocator)
        })?;
        self.last_ccc = Some(class);
        Ok(())
    }

    /// Emit everything blocked, in order, and empty the buffer.
    fn purge(&mut self) -> BoundedResult<(), A> {
        let mut blocked = core::mem::take(&mut self.blocked);
        for ch in blocked.drain() {
            self.emit(ch)?;
        }
        self.blocked = blocked;
        Ok(())
    }

    /// The end of the text: the waiting combining characters in order,
    /// then the current starter, then everything blocked
    /// (`Recompositions`' `Finished` state).
    fn finish(&mut self) -> BoundedResult<(), A> {
        self.release()?;
        if let Some(starter) = self.composee.take() {
            self.emit(starter)?;
        }
        self.purge()
    }
}

/// The NFC form of `text`, every allocation admitted by `allocator` before
/// it is made and every unit of work reported to it first: the pass over
/// the source bytes before the first character is decoded, then each
/// character before its decomposition, each decomposed character, each
/// ordering pass and each emitted character before it is processed. The three
/// working buffers are released when it returns; the normal form keeps its
/// allocation.
fn normalize<A: Allocator>(
    text: &str,
    allocator: &mut A,
) -> BoundedResult<Owned<u8, A::Permit>, A> {
    PASS.admit(allocator, widen(text.len())?)?;
    let mut normalizer = Normalizer {
        allocator,
        pending: Owned::new(),
        ordered: Owned::new(),
        blocked: Owned::new(),
        normal: Owned::new(),
        composee: None,
        last_ccc: None,
    };
    for ch in text.chars() {
        CHARACTER.admit(&mut *normalizer.allocator)?;
        let mut failure = None;
        decompose_canonical(ch, |part| {
            if failure.is_none()
                && let Err(error) = normalizer.decomposed(part)
            {
                failure = Some(error);
            }
        });
        if let Some(error) = failure {
            return Err(error);
        }
    }
    normalizer.finish()?;
    Ok(normalizer.normal)
}

/// Whether `text` is proven already in NFC, examining its `bytes` bytes as
/// one visited value, charged as `check`: the quick check of the
/// synchronous validations ([`is_normalized`], [`is_proven_normal`]). A
/// retained operation checks a quantum at a time ([`QuickCheck`]).
fn already_normal<B: Budget>(
    text: &str,
    bytes: u64,
    check: Scan<ValidationPlace>,
    budget: &mut B,
) -> BoundedResult<bool, B> {
    check.admit(budget, bytes)?;
    Ok(is_nfc_quick(text.chars()) == IsNormalized::Yes)
}

/// The NFC quick check (`is_nfc_quick`) carried one scalar at a time, so a
/// retained operation can check a text across turns: the pinned release's
/// `quick_check` (`quick_check.rs`) keeps only the last combining class and
/// the result between scalars, a scalar of a lower nonzero class after a
/// higher one is `No`, and each scalar's own quick-check property otherwise
/// decides (ASCII, class zero and `Yes`, its shortcut). The same result over
/// the same scalars as `is_nfc_quick` of the whole text, which
/// `a_scalar_quick_check_is_the_releases_own` checks.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct QuickCheck {
    last_class: u8,
    result: IsNormalized,
}

impl QuickCheck {
    /// Nothing checked: proven so far.
    pub(crate) const fn new() -> Self {
        Self {
            last_class: 0,
            result: IsNormalized::Yes,
        }
    }

    /// The next scalar of the text.
    pub(crate) fn scalar(&mut self, ch: char) {
        let class = canonical_combining_class(ch);
        if class != 0 && self.last_class > class {
            self.result = IsNormalized::No;
        } else if self.result != IsNormalized::No {
            match is_nfc_quick(core::iter::once(ch)) {
                IsNormalized::No => self.result = IsNormalized::No,
                IsNormalized::Maybe => self.result = IsNormalized::Maybe,
                IsNormalized::Yes => {}
            }
        }
        self.last_class = class;
    }

    /// The result over every scalar so far.
    pub(crate) const fn result(&self) -> &IsNormalized {
        &self.result
    }
}

/// Strict NFC validation with the same admitted, linear normalization path.
/// Quick-check Maybe is resolved exactly, not rejected as noncanonical.
pub(super) fn is_normalized<A: Allocator>(text: &str, allocator: &mut A) -> BoundedResult<bool, A> {
    let bytes = widen(text.len())?;
    if already_normal(text, bytes, QUICK, allocator)? {
        return Ok(true);
    }
    let normal = normalize(text, allocator)?;
    PASS.admit(allocator, bytes)?;
    Ok(normal.as_slice() == text.as_bytes())
}

/// The most decomposed parts per UTF-8 byte any scalar value has under the
/// pinned `unicode-normalization` release (`decompose_canonical`, Hangul
/// syllables included), as `(parts, bytes)`: every scalar has
/// `bytes * its parts <= parts * its bytes`, a sum over a text's scalars
/// keeps that, and parts are whole, so a text of `L` bytes decomposes into
/// at most `floor(L * parts / bytes)` parts. Every work and storage bound of
/// normalization scales with it. Established for that release over every
/// scalar value, and attained, by
/// `the_parts_per_byte_maximum_is_the_releases_own`.
pub const PARTS_PER_BYTE: (u64, u64) = (3, 2);

/// The most parts any one scalar value's canonical decomposition has under
/// the pinned release (`decompose_canonical`, Hangul syllables included):
/// the scratch the retained normalizer holds one scalar's parts in
/// ([`TextContinuation`](super::text_cursor::TextContinuation)), which
/// refuses a decomposition longer than it as out of range. In that release
/// a decomposition is a Hangul syllable's two or three jamo
/// (`normalize.rs`, `decompose_hangul`) or one entry of
/// `CANONICAL_DECOMPOSED_KV` (`tables.rs`), whose longest entries hold four
/// parts (U+1F80 through U+1FAF among them, U+1F82 a letter and three
/// marks). Established for that release over every scalar value, and
/// attained, by `the_scalar_parts_maximum_is_the_releases_own`.
pub const MAX_SCALAR_PARTS: usize = 4;

/// The most combining decomposed parts (canonical combining class other than
/// zero) per UTF-8 byte any scalar value has under the pinned release, as
/// `(parts, bytes)`: only these are ever reordered, so ordering work scales
/// with them. Established for that release over every scalar value, and
/// attained, by `the_combining_parts_per_byte_maximum_is_the_releases_own`.
pub const COMBINING_PARTS_PER_BYTE: (u64, u64) = (1, 1);

/// The most UTF-8 bytes of canonical decomposition parts per UTF-8 byte any
/// scalar value has under the pinned release, as `(part bytes, bytes)`: a
/// text of `L` bytes decomposes into at most `L * 3` bytes of parts, and its
/// normal form, never longer than the parts it composes, into no more.
/// Established for that release over every scalar value, and attained, by
/// `the_part_bytes_per_byte_maximum_is_the_releases_own`.
pub const PART_BYTES_PER_BYTE: (u64, u64) = (3, 1);

/// What a text's scalars and parts take of its bytes together: a text of `L`
/// bytes, `S` scalars and `P` parts has
/// `S + P <= SCALARS_AND_PARTS_PER_BYTE * L`. A scalar of one byte is one
/// part; the most parts a scalar has per byte are in scalars of two bytes
/// (U+01D5: three parts). So a text of a scalar per byte has a part per
/// byte, and one of the most parts per byte a scalar per two bytes. The
/// parts, the combining parts and the part bytes per byte are attained by
/// one scalar at once (U+0390), so this is the only trade among a text's
/// counts. Established for that release over every scalar value, and
/// attained, by `the_joint_counts_are_the_releases_own`.
pub const SCALARS_AND_PARTS_PER_BYTE: u64 = 2;

/// The fewest payload bytes of a text the NFC quick check does not prove
/// normal, under the pinned release: every one-byte scalar value is proven
/// normal and a starter, so such a text holds a scalar of at least two bytes.
/// A text strict validation normalizes, with its head of at least a byte,
/// fills at least three. Established for that release over every one-byte
/// scalar value, and attained, by `the_fewest_unproven_text_bytes_are_the_releases_own`.
pub const MIN_UNPROVEN_TEXT_BYTES: u64 = 2;

/// The [`ResourceBound`] of strict NFC validation (`is_normalized`) of
/// every text of an input of at most `input` bytes: each text has at least
/// a one-byte head, so there are at most `input` texts, and their payloads
/// together are at most `input` bytes. Its peak is the most one text's
/// validation holds at once, each text's scratch released before the next
/// is validated; it retains nothing.
///
/// Per text of `L` bytes, `c <= L` characters, `P <= floor(L * 3/2)`
/// decomposed parts ([`PARTS_PER_BYTE`]), `C <= P` of them combining:
///
/// - the quick check: one value, `L` bytes;
/// - when it does not prove the text normal, `normalize`: `L` bytes for the
///   source pass; one value per character and per part; per non-empty
///   release of `m` waiting parts `3m + 512` values and `4m` pair slots and
///   512 counters of bytes, then one value per released part, the released
///   parts summing to `C`; one value per emitted character, at most `P` of
///   them, and their bytes, the normal form's, at most `3L`
///   ([`PART_BYTES_PER_BYTE`]); the growth of the four buffers: the
///   pending/ordered pair of `(u8, char)` (they exchange storage) and the
///   blocked buffer of characters hold only combining parts, at most `C`
///   each, `C <= L` ([`COMBINING_PARTS_PER_BYTE`]), and the normal form at
///   most `3L` bytes ([`owned_growth`]), each allocation's release admitted
///   with it, a buffer of `M` elements allocating at most `floor(M / 4) + 1`
///   times;
/// - the comparison: `L` bytes.
///
/// The four buffers keep their allocations until the text's normalization
/// returns, so they are held at once: the peak is their held capacities
/// together and the one relocation in progress, never two. A buffer of at
/// most `M` elements, its capacity doubling from four and below `2M` once
/// past it, relocates fewer than `2M` elements and requests at most
/// `4M + 4` in all; one holding nothing never allocates.
///
/// Only a text the quick check leaves unproven is normalized, and such a
/// text fills at least three bytes with its head
/// ([`MIN_UNPROVEN_TEXT_BYTES`]): at most `input / 3` texts pay what a
/// normalization pays per text.
///
/// A non-empty release needs a waiting combining part, and every release
/// but the one at the text's end is made by a starter part after it, so a
/// text makes at most `min(starters + 1, C) <= floor((P + 1) / 2)` of them: the
/// 512-value counting pass is paid at most once per two parts.
///
/// Each text has a head of at least one byte, so the `T` texts and their
/// payloads together fill at most `input` bytes (`T + sum L <= input`). The
/// parts need no rounding, `sum P <= 3 * sum L / 2 <= 3 * input / 2`; the
/// head bytes pay for the releases' rounding,
/// `sum R <= (sum P + T) / 2 <= 3 * input / 4`; and one text's `P` is at most
/// the same `3 * input / 2`. The buffers' relocations and requests are linear in the
/// texts' combining parts and bytes together, each at most `input`, and
/// their `+4` is paid once per normalized text and buffer; the peak is one
/// text's at its largest.
/// Refused, never saturated, when a quantity does not fit in `u64`.
pub fn validation_bound<R>(input: u64) -> Result<ResourceBound, BoundedError<R>> {
    ValidationTerms::of::<R>(input)?.bound()
}

/// The terms [`validation_bound`] sums, one per [`ValidationPlace`].
struct ValidationTerms {
    reading: WriteWork,
    decomposing: WriteWork,
    ordering: WriteWork,
    emitting: WriteWork,
    buffers: ResourceBound,
}

impl ValidationTerms {
    fn of<R>(input: u64) -> Result<Self, BoundedError<R>> {
        use super::{add, mul};
        let (per, of) = PARTS_PER_BYTE;
        // The parts of every text sum without rounding (`of * P <= per * L`
        // for each); the head bytes cover the rounding of its releases
        // (`2 * of - 1 <= per`).
        const { assert!(2 * PARTS_PER_BYTE.1 - 1 <= PARTS_PER_BYTE.0) };
        // A quick check and a character visit are one value each, so the
        // `T + sum L <= input` of them are `input` values together.
        const { assert!(QUICK.values() == CHARACTER.values()) };
        let pair = widen(core::mem::size_of::<(u8, char)>())?;
        let scalar = widen(core::mem::size_of::<char>())?;
        // Only an unproven text is normalized, each at least a head byte and
        // `MIN_UNPROVEN_TEXT_BYTES` of payload.
        let texts = input / add(MIN_UNPROVEN_TEXT_BYTES, 1)?;
        let parts = mul(input, per)? / of;
        let (part_bytes, of_bytes) = PART_BYTES_PER_BYTE;
        let emitted_bytes = mul(input, part_bytes)? / of_bytes;
        let releases = mul(input, per)? / mul(of, 2)?;
        // The pending/ordered pair and the blocked buffer hold combining
        // parts only, at most one per byte; the normal form holds at most
        // `emitted_bytes`. Each buffer of `M` elements of `size` bytes
        // relocates fewer than `2M` elements and requests at most `4M + 4`.
        let (c_per, c_of) = COMBINING_PARTS_PER_BYTE;
        let combining = mul(input, c_per)? / c_of;
        let combining_bytes = add(mul(pair, 2)?, scalar)?;
        let relocated = add(
            mul(mul(combining, 2)?, combining_bytes)?,
            mul(emitted_bytes, 2)?,
        )?;
        let requested = add(
            add(
                mul(mul(combining, 4)?, combining_bytes)?,
                mul(emitted_bytes, 4)?,
            )?,
            mul(texts, add(mul(combining_bytes, 4)?, 4)?)?,
        )?;
        // Each allocation admits its release ([`Owned::reserve`]). A buffer
        // of `M` elements, its capacity doubling from four, allocates at most
        // `floor(M / 4) + 1` times; over the texts the floors sum to at most
        // the floor of the sum, and the `+1` is paid per normalized text and
        // buffer. Three buffers hold combining parts, the normal form bytes.
        let allocations = add(
            add(mul(combining / 4, 3)?, emitted_bytes / 4)?,
            mul(texts, 4)?,
        )?;
        let released = crate::bounded::RELEASED.times(allocations)?;
        // One text's buffers held at once, and the one relocation in
        // progress.
        let buffers = [
            owned_growth::<R>(combining, pair)?,
            owned_growth(combining, pair)?,
            owned_growth(combining, scalar)?,
            owned_growth(emitted_bytes, 1)?,
        ];
        let mut held = 0u64;
        let mut overlap = 0u64;
        for growth in buffers {
            held = add(held, growth.held)?;
            overlap = overlap.max(growth.peak - growth.held);
        }
        let peak = add(held, overlap)?;
        Ok(Self {
            // The quick checks and character visits; the check, the source
            // pass and the comparison, each over the payloads.
            reading: CHARACTER
                .times(input)?
                .then(QUICK.units(0, input)?)?
                .then(PASS.units(0, mul(input, 2)?)?)?,
            decomposing: PART.times(parts)?,
            // Each release's counting pass, and each part it hands on.
            ordering: COUNTING.over(releases, parts)?.then(HANDED.times(parts)?)?,
            // A value per emitted character, and the normal form's bytes.
            emitting: WriteWork::new(mul(parts, EMITTED.values())?, emitted_bytes),
            buffers: ResourceBound {
                values: released.values,
                bytes: add(relocated, released.bytes)?,
                allocated: requested,
                peak,
                retained: 0,
            },
        })
    }
}

impl Places for ValidationTerms {
    type Place = ValidationPlace;

    fn term(&self, place: ValidationPlace) -> ResourceBound {
        match place {
            ValidationPlace::Reading => ResourceBound::of_work(self.reading),
            ValidationPlace::Decomposing => ResourceBound::of_work(self.decomposing),
            ValidationPlace::Ordering => ResourceBound::of_work(self.ordering),
            ValidationPlace::Emitting => ResourceBound::of_work(self.emitting),
            ValidationPlace::Buffers => self.buffers,
        }
    }
}

/// Whether the NFC quick check alone proves `text` normal, at one value and
/// its bytes, allocating nothing: the validation of
/// `decode::TextPolicy::QuickOnly`.
pub(super) fn is_proven_normal<B: Budget>(text: &str, budget: &mut B) -> BoundedResult<bool, B> {
    already_normal(text, widen(text.len())?, QUICK, budget)
}

/// The [`ResourceBound`] of quick-check validation (`is_proven_normal`)
/// of every text of an input of at most `input` bytes: one quick check per
/// text and the payload bytes, at most `input` of each (every text has a
/// head byte), nothing allocated or retained.
pub const fn quick_validation_bound(input: u64) -> ResourceBound {
    const { assert!(QUICK.values() == 1) };
    ResourceBound::of_work(WriteWork::new(input, input))
}

#[cfg(test)]
mod tests {
    use unicode_normalization::UnicodeNormalization;

    use super::super::tests::{check, limited};
    use super::*;
    use crate::bounded::{LimitRefusal, Limits};
    use crate::{ByteString, CBOR};

    /// Each text's bounded encoding is the symbolic one, which normalizes
    /// through `unicode-normalization`'s own `.nfc()` iterator: the oracle
    /// shares no normalization code with this module.
    fn equivalent(text: &str) -> Vec<u8> {
        let bytes = check(text, &CBOR::from(text).to_cbor_data());
        let expected: String = text.nfc().collect();
        let decoded: String = CBOR::try_from_data(&bytes).unwrap().try_into().unwrap();
        assert_eq!(decoded, expected, "{text:?}");
        bytes
    }

    /// Text the quick check proves normal is copied as it is: its encoding
    /// is the symbolic one, and preparing it requests the plan's arena
    /// alone, nothing for normalization.
    #[test]
    fn normal_text_is_copied_and_matches_the_symbolic_encoding() {
        for text in ["", "a", "sha256:00ff", "\u{c5}\u{3a9}", "caf\u{e9}"] {
            assert_eq!(is_nfc_quick(text.chars()), IsNormalized::Yes, "{text:?}");
            equivalent(text);
        }
        let text = "sha256:00ff";
        let mut limits = Limits::unlimited();
        let encoded = crate::bounded::encode(text, &mut limits).unwrap();
        let mut arena = Limits::unlimited();
        let bytes = crate::bounded::encode(&ByteString::new(text.as_bytes()), &mut arena).unwrap();
        assert_eq!(encoded.as_ref().len(), bytes.as_ref().len());
        assert_eq!(
            limits.requested_bytes(),
            arena.requested_bytes(),
            "a proven text requests what a byte string of its bytes requests: no normalization"
        );
        equivalent(&"x".repeat(70_000));
    }

    /// Text the quick check cannot prove normal is normalized to the
    /// iterator's result: decomposed and composed forms, reordering by
    /// class, equal classes kept in order, blocking, a combining mark
    /// before any starter, Hangul composition across jamo, singletons, and
    /// class-zero boundaries.
    #[test]
    fn text_needing_normalization_matches_the_iterator() {
        let texts = [
            "e\u{301}",
            "A\u{30a}\u{3a9}",
            "a\u{316}\u{301}",
            "a\u{301}\u{316}",
            "a\u{301}\u{302}\u{316}\u{317}",
            "a\u{301}\u{301}",
            "\u{301}a",
            "\u{301}\u{316}",
            "\u{1100}\u{1161}\u{11a8}",
            "\u{1100}\u{1161}x\u{1100}\u{1161}\u{11a8}\u{301}",
            "\u{ac00}\u{11a8}",
            "\u{212b}",
            "\u{2126}",
            "\u{f900}",
            "\u{1e0a}\u{323}",
            "q\u{307}\u{323}",
            "e\u{301}\u{301}e\u{301}",
        ];
        for text in texts {
            equivalent(text);
        }
    }

    /// Strings drawn deterministically from the characters normalization
    /// treats specially, mixed with arbitrary scalar values, normalize as
    /// the iterator does. Each pool targets one rule.
    #[test]
    fn generated_text_matches_the_iterator() {
        const POOLS: [&[char]; 7] = [
            // Hangul leading, vowel and trailing jamo, and syllables with
            // and without a trailing consonant.
            &[
                '\u{1100}', '\u{1112}', '\u{1161}', '\u{1175}', '\u{11a7}', '\u{11a8}', '\u{11c2}',
                '\u{ac00}', '\u{ac01}', '\u{d7a3}',
            ],
            // Combining marks across classes, several sharing one class.
            &[
                '\u{300}', '\u{301}', '\u{302}', '\u{316}', '\u{317}', '\u{323}', '\u{327}',
                '\u{334}', '\u{345}', '\u{5b0}', '\u{93c}', '\u{3099}',
            ],
            // Starters that compose with the marks above.
            &[
                'a', 'e', 'o', 'u', 'A', 'O', '\u{3b1}', '\u{3c9}', '\u{304b}',
            ],
            // Singletons and characters with canonical decompositions.
            &[
                '\u{212b}',
                '\u{2126}',
                '\u{f900}',
                '\u{2f800}',
                '\u{c5}',
                '\u{1e0a}',
                '\u{1f80}',
                '\u{344}',
            ],
            // Quick check `Maybe` and `No` characters.
            &[
                '\u{300}', '\u{306}', '\u{653}', '\u{9be}', '\u{b3e}', '\u{1161}', '\u{340}',
                '\u{374}',
            ],
            // ASCII.
            &['x', '0', ' ', ':'],
            &[],
        ];
        let mut state = 0x853c_49e6_748f_ea9bu64;
        let mut next = move || {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (state >> 33) as u32
        };
        for _ in 0..20_000 {
            let length = next() % 12;
            let mut text = String::new();
            for _ in 0..length {
                let pool = POOLS[(next() as usize) % POOLS.len()];
                let ch = if pool.is_empty() {
                    char::from_u32(next() % 0x11_0000).unwrap_or('\u{fffd}')
                } else {
                    pool[(next() as usize) % pool.len()]
                };
                text.push(ch);
            }
            equivalent(&text);
        }
    }

    /// The quick check one scalar at a time is the pinned release's own over
    /// the whole text: every scalar alone and after a mark of each class,
    /// texts drawn from the pools above, and runs of marks in and out of
    /// canonical order.
    #[test]
    fn a_scalar_quick_check_is_the_releases_own() {
        let check = |text: &str| {
            let mut quick = QuickCheck::new();
            for ch in text.chars() {
                quick.scalar(ch);
            }
            assert_eq!(quick.result(), &is_nfc_quick(text.chars()), "{text:?}");
        };
        for ch in (0..=0x10_ffffu32).filter_map(char::from_u32) {
            let mut alone = [0; 4];
            check(ch.encode_utf8(&mut alone));
            for mark in ['\u{316}', '\u{301}', '\u{345}'] {
                check(&format!("{mark}{ch}"));
            }
        }
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        let pool = [
            'a', 'x', '\u{e9}', '\u{301}', '\u{316}', '\u{344}', '\u{1100}', '\u{1161}',
            '\u{ac00}', '\u{212b}', '\u{1d5}', '\u{340}', '\u{653}',
        ];
        for _ in 0..20_000 {
            let mut text = String::new();
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            for _ in 0..(state >> 60) {
                state = state
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                text.push(pool[(state >> 33) as usize % pool.len()]);
            }
            check(&text);
        }
        check(&format!("q{}", "\u{316}\u{301}".repeat(64)));
        check(&format!("q{}", "\u{301}\u{316}".repeat(64)));
    }

    /// A long run of combining marks of mixed classes, which grows every
    /// buffer, is reordered and composed as the iterator does; its
    /// allocations are all released when the preparation drops.
    #[test]
    fn a_long_combining_run_matches_and_releases_its_allocations() {
        let mut text = String::from("a");
        for _ in 0..300 {
            text.push('\u{301}');
            text.push('\u{316}');
        }
        text.push('b');
        assert_ne!(is_nfc_quick(text.chars()), IsNormalized::Yes);
        equivalent(&text);
        let mut limits = Limits::unlimited();
        {
            let encoded = crate::bounded::encode(text.as_str(), &mut limits).unwrap();
            assert!(
                limits.live_bytes() >= encoded.as_ref().len() as u64,
                "the encoding holds the normal form"
            );
        }
        assert!(limits.requested_bytes() > 0);
        assert!(limits.peak_bytes() >= limits.live_bytes());
        assert_eq!(limits.live_bytes(), 0, "every allocation is released");
    }

    /// Normalization pressure is refused before the allocation, or the
    /// comparison, that would pass the allowance: the refusal is the
    /// budget's own, nothing beyond the allowance was requested, and
    /// everything requested is released.
    #[test]
    fn combining_pressure_is_refused_within_its_allowance() {
        let mut text = String::from("a");
        for _ in 0..1_000 {
            text.push('\u{316}');
            text.push('\u{301}');
        }
        let mut scratch = Limits::unlimited().requesting_at_most(256);
        assert_eq!(
            crate::bounded::prepare(text.as_str(), &mut scratch).map(|prepared| prepared.len()),
            Err(BoundedError::Refused(LimitRefusal::Storage))
        );
        assert!(
            scratch.requested_bytes() <= 256,
            "{} requested",
            scratch.requested_bytes()
        );
        assert_eq!(scratch.live_bytes(), 0);
        let mut comparisons = limited(500);
        assert_eq!(
            crate::bounded::prepare(text.as_str(), &mut comparisons).map(|prepared| prepared.len()),
            Err(BoundedError::Refused(LimitRefusal::Work))
        );
        assert!(comparisons.used().values <= 500);
        assert_eq!(comparisons.live_bytes(), 0);
    }

    /// The most decomposed parts per UTF-8 byte the normalization bound
    /// uses is the pinned release's own: no scalar value decomposes into
    /// more parts per byte of its encoding, and one attains it.
    #[test]
    fn the_parts_per_byte_maximum_is_the_releases_own() {
        let (parts, bytes) = PARTS_PER_BYTE;
        let mut attained = false;
        for ch in (0..=0x10_ffffu32).filter_map(char::from_u32) {
            let mut count = 0u64;
            decompose_canonical(ch, |_| count += 1);
            let length = ch.len_utf8() as u64;
            assert!(
                count * bytes <= parts * length,
                "U+{:04X} decomposes into {count} parts in {length} bytes",
                ch as u32
            );
            attained |= count * bytes == parts * length;
        }
        assert!(attained, "{parts}/{bytes} is not attained");
    }

    /// The retained normalizer's scratch holds every scalar value's whole
    /// canonical decomposition under the pinned release, and no less would:
    /// no scalar decomposes into more parts, and one decomposes into as many.
    #[test]
    fn the_scalar_parts_maximum_is_the_releases_own() {
        let mut attained = false;
        for ch in (0..=0x10_ffffu32).filter_map(char::from_u32) {
            let mut count = 0usize;
            decompose_canonical(ch, |_| count += 1);
            assert!(
                count <= MAX_SCALAR_PARTS,
                "U+{:04X} decomposes into {count} parts",
                ch as u32
            );
            attained |= count == MAX_SCALAR_PARTS;
        }
        assert!(attained, "{MAX_SCALAR_PARTS} parts are not attained");
    }

    /// The most combining parts per UTF-8 byte the ordering bound uses is
    /// the pinned release's own: no scalar value decomposes into more parts
    /// of a nonzero combining class per byte of its encoding, and one
    /// attains it.
    #[test]
    fn the_combining_parts_per_byte_maximum_is_the_releases_own() {
        let (parts, bytes) = COMBINING_PARTS_PER_BYTE;
        let mut attained = false;
        for ch in (0..=0x10_ffffu32).filter_map(char::from_u32) {
            let mut count = 0u64;
            decompose_canonical(ch, |part| {
                count += u64::from(canonical_combining_class(part) != 0)
            });
            let length = ch.len_utf8() as u64;
            assert!(
                count * bytes <= parts * length,
                "U+{:04X} decomposes into {count} combining parts in {length} bytes",
                ch as u32
            );
            attained |= count * bytes == parts * length;
        }
        assert!(attained, "{parts}/{bytes} is not attained");
    }

    /// The most decomposed bytes per UTF-8 byte the emission bound uses is
    /// the pinned release's own: no scalar value decomposes into more bytes
    /// of parts per byte of its encoding, and one attains it.
    #[test]
    fn the_part_bytes_per_byte_maximum_is_the_releases_own() {
        let (part_bytes, bytes) = PART_BYTES_PER_BYTE;
        let mut attained = false;
        for ch in (0..=0x10_ffffu32).filter_map(char::from_u32) {
            let mut decomposed = 0u64;
            decompose_canonical(ch, |part| decomposed += part.len_utf8() as u64);
            let length = ch.len_utf8() as u64;
            assert!(
                decomposed * bytes <= part_bytes * length,
                "U+{:04X} decomposes into {decomposed} bytes from {length}",
                ch as u32
            );
            attained |= decomposed * bytes == part_bytes * length;
        }
        assert!(attained, "{part_bytes}/{bytes} is not attained");
    }

    /// The joint counts of a text are the pinned release's own. A text's
    /// counts are sums over its scalars, so the scalars and parts per byte
    /// ([`SCALARS_AND_PARTS_PER_BYTE`]) hold of every text when every scalar
    /// holds them, and one scalar attains them. One scalar also attains the
    /// parts, the combining parts and the part bytes per byte at once, so
    /// those need no trade.
    #[test]
    fn the_joint_counts_are_the_releases_own() {
        let (per, of) = PARTS_PER_BYTE;
        let (c_per, c_of) = COMBINING_PARTS_PER_BYTE;
        let (b_per, b_of) = PART_BYTES_PER_BYTE;
        let (mut scalars_and_parts, mut jointly) = (false, false);
        for ch in (0..=0x10_ffffu32).filter_map(char::from_u32) {
            let (mut parts, mut combining, mut part_bytes) = (0u64, 0u64, 0u64);
            decompose_canonical(ch, |part| {
                parts += 1;
                combining += u64::from(canonical_combining_class(part) != 0);
                part_bytes += part.len_utf8() as u64;
            });
            let bytes = ch.len_utf8() as u64;
            jointly |= parts * of == per * bytes
                && combining * c_of == c_per * bytes
                && part_bytes * b_of == b_per * bytes;
            // The scalar itself and its parts.
            assert!(
                parts < SCALARS_AND_PARTS_PER_BYTE * bytes,
                "U+{:04X}: {parts} parts in {bytes} bytes, beyond the scalars and parts per byte",
                ch as u32
            );
            scalars_and_parts |= parts + 1 == SCALARS_AND_PARTS_PER_BYTE * bytes;
        }
        assert!(
            scalars_and_parts,
            "the scalars and parts per byte are not attained"
        );
        assert!(jointly, "no scalar attains every per-byte maximum at once");
    }

    /// The fewest payload bytes of a text the quick check leaves unproven is
    /// the pinned release's own: every one-byte scalar value is proven normal
    /// and a starter, so a text of them alone is proven, its starters never
    /// out of canonical order; and a text of one two-byte scalar is not.
    #[test]
    fn the_fewest_unproven_text_bytes_are_the_releases_own() {
        for ch in (0..0x80u32).filter_map(char::from_u32) {
            assert_eq!(ch.len_utf8() as u64, MIN_UNPROVEN_TEXT_BYTES - 1);
            assert_eq!(
                is_nfc_quick(core::iter::once(ch)),
                IsNormalized::Yes,
                "U+{:04X}",
                ch as u32
            );
            assert_eq!(canonical_combining_class(ch), 0, "U+{:04X}", ch as u32);
        }
        assert_eq!("\u{301}".len() as u64, MIN_UNPROVEN_TEXT_BYTES);
        assert_ne!(is_nfc_quick("\u{301}".chars()), IsNormalized::Yes);
    }

    /// The validation bound covers what strict validation reports for texts
    /// of every kind the quick check cannot prove normal, valid and not:
    /// long combining runs, maximal decompositions, Hangul jamo, and many
    /// short texts, each measured alone and the bound taken at its length.
    #[test]
    fn the_validation_bound_covers_every_text() {
        let maximal: char = (0..=0x10_ffffu32)
            .filter_map(char::from_u32)
            .max_by_key(|ch| {
                let mut parts = 0u64;
                decompose_canonical(*ch, |_| parts += 1);
                parts
            })
            .unwrap();
        let texts = [
            String::new(),
            "ordinary".into(),
            "q\u{316}\u{301}".repeat(200),
            "a\u{301}\u{316}".repeat(200),
            "\u{1100}\u{1161}\u{11a8}".repeat(100),
            maximal.to_string().repeat(300),
            "\u{301}".repeat(500),
            "e\u{301}".into(),
        ];
        for text in &texts {
            let mut limits = Limits::unlimited();
            let normal = is_normalized(text, &mut limits);
            assert!(normal.is_ok(), "{text:?}");
            // The bound is over an input holding the text: its payload and
            // at least its one-byte head.
            let bound = validation_bound::<()>(text.len() as u64 + 1).unwrap();
            let used = limits.used();
            assert!(used.values <= bound.values, "{text:?} values");
            assert!(used.bytes <= bound.bytes, "{text:?} bytes");
            assert!(
                limits.requested_bytes() <= bound.allocated,
                "{text:?} allocated"
            );
            assert!(limits.peak_bytes() <= bound.peak, "{text:?} peak");
            assert_eq!(limits.live_bytes(), 0, "{text:?} released");
        }
        assert_eq!(
            validation_bound::<()>(u64::MAX),
            Err(BoundedError::Overflow)
        );
    }

    /// A text whose strict validation charges `place`, and drives it toward
    /// its term: a place without a witness does not compile. A leading mark
    /// keeps the quick check from proving the text normal. Reading is
    /// largest per byte on one-byte characters, every pass over them;
    /// each precomposed letter decomposes into a starter and a mark the
    /// next starter releases. U+1D160 is excluded from composition: its
    /// normal form is its whole decomposition, three bytes per byte.
    fn witness(place: ValidationPlace) -> String {
        match place {
            ValidationPlace::Reading => format!("\u{301}{}", "x".repeat(64)),
            ValidationPlace::Emitting => "\u{1d160}".repeat(16),
            // U+0344 decomposes into two marks, one per byte: one run, every
            // mark pending, ordered and blocked from the starter at once.
            ValidationPlace::Buffers => format!("q{}", "\u{344}".repeat(256)),
            ValidationPlace::Decomposing | ValidationPlace::Ordering => {
                format!("\u{301}{}", "\u{e9}".repeat(64))
            }
        }
    }

    /// Every place strict validation charges is within its term, at a bound
    /// over an input holding the text and its one-byte head; every admission
    /// and request is made at some place; each place's witness charges it.
    /// Beside the witnesses: disordered runs, Hangul, leading marks, and
    /// text that is not in NFC.
    #[cfg(feature = "std")]
    #[test]
    fn every_place_of_a_validation_is_within_its_term() {
        use crate::bounded::Place;
        use crate::bounded::places::{self, Factor, Ledgered, Run, STORAGE, WORK};
        let mut texts: Vec<(String, Option<ValidationPlace>, String)> = ValidationPlace::ALL
            .iter()
            .map(|&place| (format!("witness of {place:?}"), Some(place), witness(place)))
            .collect();
        for (name, text) in [
            ("disordered", "q\u{316}\u{301}".repeat(200)),
            ("hangul", "\u{1100}\u{1161}\u{11a8}".repeat(100)),
            ("leading marks", "\u{301}".repeat(500)),
            ("not NFC", "e\u{301}".into()),
            ("quick", "ordinary".into()),
            // A counting pass per two bytes and three parts per two bytes,
            // the work the bound maximizes, at a larger size than the
            // decomposition witness; and of a letter of three parts in two
            // bytes (U+01D5: U, a diaeresis, a macron), the parts per byte
            // the bound takes at their maximum.
            ("long letters", format!("\u{301}{}", "\u{e9}".repeat(4096))),
            (
                "long three-part letters",
                format!("\u{301}{}", "\u{1d5}".repeat(4096)),
            ),
        ] {
            texts.push((name.into(), None, text));
        }
        let mut runs = Vec::new();
        let mut witnesses = Vec::new();
        for (name, place, text) in texts {
            let mut policy = Ledgered::new();
            assert!(is_normalized(&text, &mut policy).is_ok(), "{name}");
            if let Some(place) = place {
                witnesses.push((runs.len(), place));
            }
            runs.push(Run {
                outcome: places::Outcome::Published,
                name,
                policy,
                terms: ValidationTerms::of::<()>(text.len() as u64 + 1).unwrap(),
            });
        }
        places::check(&runs);
        places::witnessed(&runs, &witnesses);
        let work = "precomposed letters behind a leading mark: each decomposed into a \
                    starter and a mark the next starter releases, a counting pass per two \
                    bytes and three parts per two bytes";
        places::Tightness::new("validation")
            .places(&runs, &witnesses, |place| match place {
                ValidationPlace::Reading
                | ValidationPlace::Decomposing
                | ValidationPlace::Ordering
                | ValidationPlace::Emitting
                | ValidationPlace::Buffers => Factor::Measured,
            })
            .joint(&runs, "witness of Decomposing", WORK, work)
            .joint(&runs, "long letters", WORK, work)
            .joint(&runs, "long three-part letters", WORK, work)
            .joint(
                &runs,
                "witness of Buffers",
                STORAGE,
                "one run of combining marks, one per byte: every mark pending, ordered and \
                 blocked at once, the buffers held together",
            )
            // Every text's bound, recorded: an overstated term moves a
            // record, as an understated one fails the check above.
            .totals(&runs, WORK)
            .finish();
    }
}
