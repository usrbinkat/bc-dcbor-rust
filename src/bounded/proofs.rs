//! Kani proofs of the bound algebra: the arithmetic and overflow level of the
//! proof hierarchy (register item 4) and the composition lemmas every bound
//! rests on. Each harness is universal over its stated domain: every input
//! is `kani::any()`, constrained only by the `kani::assume` the harness
//! names, so a passing harness is a proof over that domain, not a sample.
//!
//! The reference semantics is the exact arithmetic of `u128`, in which no
//! sum or product of two `u64` quantities overflows: each combinator is
//! proved to return `None` exactly when some quantity it computes exceeds
//! `u64::MAX`, and otherwise the value its documentation states per
//! quantity. The composition lemmas prove that the closed forms of the
//! repetitions are the folds of the binary combinators they abbreviate, over
//! the repetition counts a bounded model checker unrolls (`MAX_UNROLLED`);
//! that bound is the stated domain of those lemmas, never a sample of a
//! larger one.
//!
//! Compiled only under `cfg(kani)` (`cargo kani`), so no other build sees
//! the `kani` crate.

use super::{ResourceBound, WriteWork, grown_capacity};

/// The repetition counts the composition lemmas are proved over: every
/// count from zero through this one.
const MAX_UNROLLED: u64 = 4;

const MAX: u128 = u64::MAX as u128;

/// A bound of arbitrary quantities.
fn any_bound() -> ResourceBound {
    ResourceBound {
        values: kani::any(),
        bytes: kani::any(),
        allocated: kani::any(),
        peak: kani::any(),
        retained: kani::any(),
    }
}

/// A bound whose retained output is part of its peak (`R <= P`), the
/// invariant every bound the crate composes satisfies: what an operation
/// publishes is held while it runs.
fn any_coherent_bound() -> ResourceBound {
    let bound = any_bound();
    kani::assume(bound.retained <= bound.peak);
    bound
}

fn wide(value: u64) -> u128 {
    u128::from(value)
}

/// `value` as a `u64`, or none when it exceeds `u64::MAX`.
fn narrow(value: u128) -> Option<u64> {
    if value > MAX {
        None
    } else {
        Some(value as u64)
    }
}

/// The exact result of a quantity, or none.
fn sum(left: u64, right: u64) -> Option<u64> {
    narrow(wide(left) + wide(right))
}

fn product(left: u64, right: u64) -> Option<u64> {
    narrow(wide(left) * wide(right))
}

/// `checked_then`: none exactly when one of its five sums overflows; else
/// work and requests summed, peak `max(P_a, R_a + P_b)`, retained
/// `R_a + R_b`.
#[kani::proof]
fn checked_then_is_exact() {
    let (a, b) = (any_bound(), any_bound());
    let expected = (|| {
        Some(ResourceBound {
            values: sum(a.values, b.values)?,
            bytes: sum(a.bytes, b.bytes)?,
            allocated: sum(a.allocated, b.allocated)?,
            peak: a.peak.max(sum(a.retained, b.peak)?),
            retained: sum(a.retained, b.retained)?,
        })
    })();
    assert_eq!(a.checked_then(b), expected);
}

/// `checked_followed_by`: none exactly when work or requests overflow; else
/// those summed, peak `max(P_a, P_b)`, retained `R_b`.
#[kani::proof]
fn checked_followed_by_is_exact() {
    let (a, b) = (any_bound(), any_bound());
    let expected = (|| {
        Some(ResourceBound {
            values: sum(a.values, b.values)?,
            bytes: sum(a.bytes, b.bytes)?,
            allocated: sum(a.allocated, b.allocated)?,
            peak: a.peak.max(b.peak),
            retained: b.retained,
        })
    })();
    assert_eq!(a.checked_followed_by(b), expected);
}

/// `checked_add`: every quantity summed, none when any overflows.
#[kani::proof]
fn checked_add_is_exact() {
    let (a, b) = (any_bound(), any_bound());
    let expected = (|| {
        Some(ResourceBound {
            values: sum(a.values, b.values)?,
            bytes: sum(a.bytes, b.bytes)?,
            allocated: sum(a.allocated, b.allocated)?,
            peak: sum(a.peak, b.peak)?,
            retained: sum(a.retained, b.retained)?,
        })
    })();
    assert_eq!(a.checked_add(b), expected);
}

/// `checked_mul`: every quantity times `count`, none when any overflows.
#[kani::proof]
fn checked_mul_is_exact() {
    let a = any_bound();
    let count: u64 = kani::any();
    let expected = (|| {
        Some(ResourceBound {
            values: product(a.values, count)?,
            bytes: product(a.bytes, count)?,
            allocated: product(a.allocated, count)?,
            peak: product(a.peak, count)?,
            retained: product(a.retained, count)?,
        })
    })();
    assert_eq!(a.checked_mul(count), expected);
}

/// `checked_repeated`: work and requests times `count`, none when any
/// overflows; peak and retained the bound's own for `count > 0`, nothing
/// for `count == 0`.
#[kani::proof]
fn checked_repeated_is_exact() {
    let a = any_bound();
    let count: u64 = kani::any();
    let once = count != 0;
    let expected = (|| {
        Some(ResourceBound {
            values: product(a.values, count)?,
            bytes: product(a.bytes, count)?,
            allocated: product(a.allocated, count)?,
            peak: if once { a.peak } else { 0 },
            retained: if once { a.retained } else { 0 },
        })
    })();
    assert_eq!(a.checked_repeated(count), expected);
}

/// `checked_repeated_retained`: work, requests and retained times `count`,
/// peak `(count - 1) R + P`, none when any overflows; nothing for zero.
#[kani::proof]
fn checked_repeated_retained_is_exact() {
    let a = any_bound();
    let count: u64 = kani::any();
    let expected = if count == 0 {
        Some(ResourceBound::default())
    } else {
        (|| {
            Some(ResourceBound {
                values: product(a.values, count)?,
                bytes: product(a.bytes, count)?,
                allocated: product(a.allocated, count)?,
                peak: narrow(wide(product(a.retained, count - 1)?) + wide(a.peak))?,
                retained: product(a.retained, count)?,
            })
        })()
    };
    assert_eq!(a.checked_repeated_retained(count), expected);
}

/// `larger`: every quantity the larger of the two; never fails, and covers
/// both alternatives.
#[kani::proof]
fn larger_covers_both_alternatives() {
    let (a, b) = (any_bound(), any_bound());
    let larger = a.larger(b);
    assert_eq!(larger, b.larger(a), "the alternative is symmetric");
    for alternative in [a, b] {
        assert!(larger.covers(
            alternative.work(),
            alternative.allocated,
            alternative.peak,
            alternative.retained
        ));
    }
}

/// The fold of `step` over `count` copies of `a`, from nothing, none at the
/// first step that does not fit.
fn fold(
    a: ResourceBound,
    count: u64,
    step: fn(ResourceBound, ResourceBound) -> Option<ResourceBound>,
) -> Option<ResourceBound> {
    let mut total = ResourceBound::default();
    let mut done = 0;
    while done < count {
        total = step(total, a)?;
        done += 1;
    }
    Some(total)
}

/// Lemma: `checked_repeated` is `checked_followed_by` folded, for every
/// count through [`MAX_UNROLLED`].
#[kani::proof]
#[kani::unwind(6)]
fn checked_repeated_is_the_followed_by_fold() {
    let a = any_bound();
    let count: u64 = kani::any();
    kani::assume(count <= MAX_UNROLLED);
    assert_eq!(
        a.checked_repeated(count),
        fold(a, count, ResourceBound::checked_followed_by)
    );
}

/// Lemma: `checked_repeated_retained` is `checked_then` folded, for every
/// count through [`MAX_UNROLLED`], over coherent bounds (`R <= P`): the
/// closed form's peak rests on the last run being the highest, which holds
/// exactly when an operation's retained output is part of its peak.
#[kani::proof]
#[kani::unwind(6)]
fn checked_repeated_retained_is_the_then_fold() {
    let a = any_coherent_bound();
    let count: u64 = kani::any();
    kani::assume(count <= MAX_UNROLLED);
    assert_eq!(
        a.checked_repeated_retained(count),
        fold(a, count, ResourceBound::checked_then)
    );
}

/// Lemma: `checked_mul` is `checked_add` folded, for every count through
/// [`MAX_UNROLLED`].
#[kani::proof]
#[kani::unwind(6)]
fn checked_mul_is_the_add_fold() {
    let a = any_bound();
    let count: u64 = kani::any();
    kani::assume(count <= MAX_UNROLLED);
    assert_eq!(
        a.checked_mul(count),
        fold(a, count, ResourceBound::checked_add)
    );
}

/// Lemma: sequencing preserves coherence (`R <= P`) when both parts are
/// coherent: the composed bound's retained output is part of its peak.
#[kani::proof]
fn checked_then_preserves_coherence() {
    let (a, b) = (any_coherent_bound(), any_coherent_bound());
    if let Some(composed) = a.checked_then(b) {
        assert!(composed.retained <= composed.peak);
    }
}

/// `WriteWork::checked_then` and `checked_times`: exact, none on overflow.
#[kani::proof]
fn write_work_arithmetic_is_exact() {
    let a = WriteWork::new(kani::any(), kani::any());
    let b = WriteWork::new(kani::any(), kani::any());
    let count: u64 = kani::any();
    let then = (|| {
        Some(WriteWork::new(
            sum(a.values, b.values)?,
            sum(a.bytes, b.bytes)?,
        ))
    })();
    assert_eq!(a.checked_then(b), then);
    let times = (|| {
        Some(WriteWork::new(
            product(a.values, count)?,
            product(a.bytes, count)?,
        ))
    })();
    assert_eq!(a.checked_times(count), times);
}

/// The growth rule: four from empty, double otherwise, none exactly when
/// doubling overflows; a growth never shrinks an arena.
#[kani::proof]
fn the_growth_rule_is_exact_and_never_shrinks() {
    let capacity: u64 = kani::any();
    let grown = grown_capacity(capacity);
    if capacity == 0 {
        assert_eq!(grown, Some(4), "an empty arena grows to four");
    } else {
        assert_eq!(
            grown,
            product(capacity, 2),
            "a nonempty arena doubles, none exactly when doubling overflows"
        );
    }
    if let Some(grown) = grown {
        assert!(grown > capacity, "a growth never shrinks an arena");
    }
}
