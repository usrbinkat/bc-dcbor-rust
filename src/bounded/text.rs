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
    Allocator, BoundedError, BoundedResult, Budget, Cursor, MajorType, Measure, Output, Owned,
    Plan, WriteWork, item_len, widen,
};

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
    fn visit(&mut self, values: u64) -> BoundedResult<(), A> {
        self.allocator
            .traverse(values, 0)
            .map_err(BoundedError::Refused)
    }

    /// One character of the normal form.
    fn emit(&mut self, ch: char) -> BoundedResult<(), A> {
        self.allocator
            .traverse(1, widen(ch.len_utf8())?)
            .map_err(BoundedError::Refused)?;
        let mut encoded = [0u8; 4];
        self.normal.extend_from_slice(
            ch.encode_utf8(&mut encoded).as_bytes(),
            &mut *self.allocator,
        )
    }

    /// One character of the canonical decomposition, in text order
    /// (`Decompositions::push_back`): a starter releases the combining
    /// characters before it in canonical order, then itself; a combining
    /// character waits for stable counting sort at the next boundary.
    fn decomposed(&mut self, ch: char) -> BoundedResult<(), A> {
        self.visit(1)?;
        let class = canonical_combining_class(ch);
        if class == 0 {
            self.release()?;
            return self.composed(ch);
        }
        self.pending.push((class, ch), &mut *self.allocator)
    }

    /// Release the waiting combining characters, in canonical order, to
    /// composition. Composition never touches `pending`; the emptied buffer
    /// is put back with its allocation for the next run.
    fn release(&mut self) -> BoundedResult<(), A> {
        if self.pending.is_empty() {
            return Ok(());
        }
        let count = self.pending.len();
        let n = widen(count)?;
        // Histogram, prefix sum, stable distribution and initialization are
        // admitted before reading or filling either buffer.
        self.allocator
            .traverse(
                super::add(super::mul(n, 3)?, 512)?,
                super::add(
                    super::mul(
                        super::mul(n, 4)?,
                        widen(core::mem::size_of::<(u8, char)>())?,
                    )?,
                    super::mul(512, widen(core::mem::size_of::<usize>())?)?,
                )?,
            )
            .map_err(BoundedError::Refused)?;
        self.ordered.reserve(count, &mut *self.allocator)?;
        let mut offsets = [0usize; 256];
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
            self.visit(1)?;
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
        self.blocked.push(ch, &mut *self.allocator)?;
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
    allocator
        .traverse(0, widen(text.len())?)
        .map_err(BoundedError::Refused)?;
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
        normalizer.visit(1)?;
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

/// Whether `text` is proven already in NFC, examining its `bytes` bytes
/// as one visited value.
fn already_normal<B: Budget>(text: &str, bytes: u64, budget: &mut B) -> BoundedResult<bool, B> {
    budget.traverse(1, bytes).map_err(BoundedError::Refused)?;
    Ok(is_nfc_quick(text.chars()) == IsNormalized::Yes)
}

/// Strict NFC validation with the same admitted, linear normalization path.
/// Quick-check Maybe is resolved exactly, not rejected as noncanonical.
pub(super) fn is_normalized<A: Allocator>(text: &str, allocator: &mut A) -> BoundedResult<bool, A> {
    let bytes = widen(text.len())?;
    if already_normal(text, bytes, allocator)? {
        return Ok(true);
    }
    let normal = normalize(text, allocator)?;
    allocator
        .traverse(0, bytes)
        .map_err(BoundedError::Refused)?;
    Ok(normal.as_slice() == text.as_bytes())
}

/// The measure of `text`'s encoding: a text head and its NFC bytes. Text
/// not proven normal is normalized here, once, and its normal form pushed
/// to `plan`; the write checks the text again, then copies.
pub fn measure_text<A: Allocator>(
    text: &str,
    plan: &mut Plan<A::Permit>,
    allocator: &mut A,
) -> BoundedResult<Measure, A> {
    let bytes = widen(text.len())?;
    let checked = WriteWork::new(1, bytes);
    if already_normal(text, bytes, allocator)? {
        return Ok(Measure {
            len: item_len(bytes, bytes)?,
            write: checked.then(WriteWork::new(0, bytes))?,
        });
    }
    let normal = normalize(text, allocator)?;
    let length = widen(normal.len())?;
    plan.push_text(text.len(), normal, allocator)?;
    Ok(Measure {
        len: item_len(length, length)?,
        write: checked.then(WriteWork::new(0, length))?,
    })
}

/// Write `text`'s encoding: its head and its NFC bytes, copied from the
/// text itself or from the plan.
pub fn write_text<P, B: Budget>(
    text: &str,
    plan: &mut Cursor<'_, P>,
    output: &mut Output<'_>,
    budget: &mut B,
) -> BoundedResult<(), B> {
    let bytes = widen(text.len())?;
    let normal = if already_normal(text, bytes, budget)? {
        text.as_bytes()
    } else {
        plan.next_text(text.len())?
    };
    let length = widen(normal.len())?;
    budget.traverse(0, length).map_err(BoundedError::Refused)?;
    output.head(MajorType::Text, length)?;
    output.slice(normal)
}

#[cfg(test)]
mod tests {
    use unicode_normalization::UnicodeNormalization;

    use super::super::tests::{Tally, check};
    use super::*;
    use crate::CBOR;

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

    #[test]
    fn normal_text_is_copied_and_matches_the_symbolic_encoding() {
        for text in ["", "a", "sha256:00ff", "\u{c5}\u{3a9}", "caf\u{e9}"] {
            assert_eq!(is_nfc_quick(text.chars()), IsNormalized::Yes, "{text:?}");
            equivalent(text);
        }
        let mut tally = Tally::unlimited();
        let mut plan = Plan::new();
        measure_text("sha256:00ff", &mut plan, &mut tally).unwrap();
        assert_eq!(tally.requested, 0, "normal text allocates nothing");
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
        let mut tally = Tally::unlimited();
        {
            let mut plan = Plan::new();
            measure_text(&text, &mut plan, &mut tally).unwrap();
            assert!(tally.live() > 0, "the plan holds the normal form");
        }
        assert!(tally.requested > 0);
        assert!(tally.peak() >= tally.live());
        assert_eq!(tally.live(), 0, "every allocation is released");
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
        let mut scratch = Tally::scratch_limited(256);
        assert_eq!(
            measure_text(&text, &mut Plan::new(), &mut scratch),
            Err(BoundedError::Refused("allocation refused"))
        );
        assert!(scratch.requested <= 256, "{} requested", scratch.requested);
        assert_eq!(scratch.live(), 0);
        let mut comparisons = Tally::limited(500);
        assert_eq!(
            measure_text(&text, &mut Plan::new(), &mut comparisons),
            Err(BoundedError::Refused("traversal refused"))
        );
        assert!(comparisons.values <= 500);
        assert_eq!(comparisons.live(), 0);
    }

    /// A write against a plan that is not its preparation's is refused.
    #[test]
    fn a_write_needs_its_own_plan() {
        let text = "e\u{301}";
        let plan: Plan<()> = Plan::new();
        let mut cursor = plan.cursor();
        let mut bytes = [0u8; 8];
        let mut output = Output::new(&mut bytes);
        assert_eq!(
            write_text(text, &mut cursor, &mut output, &mut Tally::unlimited()),
            Err(BoundedError::PlanMismatch)
        );
    }
}
