//! Kani harnesses of map-key order and of its comparison's work: the
//! canonicality level of the proof hierarchy (register item 4) for the order
//! the decoder enforces between adjacent map keys and the encoder sorts keys
//! by. Both run the one comparison unit ([`super::compare_step`]):
//! [`super::KeyComparison`] over borrowed keys and the decoder's arena
//! comparison over ranges of its input (`RangeComparison`).
//!
//! Reference semantics, stated here from the specification, never computed
//! by calling the code under proof:
//!
//! - Order: canonical key order is the bytewise lexicographic order of the
//!   keys' encodings (RFC 8949 section 4.2.1), a key that is a proper prefix
//!   of another first: Rust's order on byte slices, `Ord for [u8]`.
//! - Work: a comparison of keys whose shorter has `s` bytes, first differing
//!   at pair `d` (or `d = s` when the shorter is a prefix of the longer),
//!   takes turns `0, 1, ...`, turn `k` authorizing the window of
//!   `min(64, s - 64k)` pairs, admitted as one value and that window's bytes
//!   before any pair of it is examined. It ends in turn `d / 64` when
//!   `d < s`, else in turn `max(ceil(s / 64), 1) - 1`. So it admits
//!   `turns` values and `min(64 * turns, s)` bytes ([`schedule`]), whatever
//!   pair of the last window differs.
//!
//! Two quantities are kept apart: the bytes *examined* (the pairs read,
//! [`super::KeyComparison::position`], `d + 1` or `s`) and the bytes
//! *authorized* for its turns (admitted, every window whole). A window is
//! authorized whole even when its first pair differs, so authorized bytes
//! can exceed examined ones; the harnesses check both, each against its own
//! statement.
//!
//! Domains, stated:
//!
//! - [`short_keys_compare_in_canonical_order`]: every pair of keys of at
//!   most [`SHORT`] bytes, every byte any value.
//! - [`long_keys_compare_in_canonical_order`]: every pair of keys of
//!   [`SPAN`] bytes or fewer, at least `SPAN - TAIL`, whose bytes before
//!   their last [`TAIL`] are all one value, any value, and whose last bytes
//!   are any values. A restricted domain: not every pair of byte strings of
//!   at most 67 bytes. Its executions include ones that end in the first
//!   turn and ones that cross into the second.
//! - [`a_comparison_crosses_its_quantum_and_resumes_after_refusal`]: every
//!   pair of keys of 65 to [`SPAN`] bytes sharing their first 64 bytes,
//!   those bytes any one sequence and the rest any values: each crosses the
//!   quantum, is refused at its second turn, resumes under another budget,
//!   completes, and is finished.
//!
//! The loop over a turn's pairs runs at most 64 times, the reference's over
//! a key at most [`SPAN`] = 67 times: the longest is the reference's,
//! `kani::unwind(68)`, its 67 iterations and its exit; the short domain's
//! loops run at most [`SHORT`] + 1 times, `kani::unwind(6)`. A whole
//! comparison is driven for a constant [`TURNS`] turns, the reference
//! schedule's most for keys of [`SPAN`] bytes, never an open loop to
//! completion: with the driver bounded only by the unwinding bound, a
//! retained run of the long domain expanded the driver 58 times and the pair
//! loop 118 times, to its 67th iteration each, without finishing symbolic
//! execution in 30 minutes. Status: written and unverified until the gate
//! runs them. Compiled only under `cfg(kani)`.

use core::cmp::Ordering;

use super::super::super::proof_budget::Counting;
use super::super::super::{BoundedError, Step, WriteWork};
use super::{KeyComparison, comparison_bound};

/// The longest keys of the short domain.
const SHORT: usize = 4;

/// The longest keys of the long domains: past one quantum of byte pairs.
const SPAN: usize = 67;

/// The bytes the keys of the long agreement domain may differ in, at their
/// ends.
const TAIL: usize = 4;

/// A turn's quantum of byte pairs, as the specification states it.
const WINDOW: usize = 64;

/// The reference: the first pair at which `left` and `right` differ within
/// the shorter, or the shorter's length.
fn first_difference(left: &[u8], right: &[u8]) -> usize {
    let shorter = left.len().min(right.len());
    let mut at = 0;
    while at < shorter {
        if left[at] != right[at] {
            return at;
        }
        at += 1;
    }
    shorter
}

/// The reference work schedule (the module's "Work"): the values and bytes
/// a comparison of a shorter key of `shorter` bytes, first differing at
/// `differ`, admits; and the pairs it examines.
fn schedule(shorter: usize, differ: usize) -> (WriteWork, usize) {
    let turns = if differ < shorter {
        differ / WINDOW + 1
    } else {
        shorter.div_ceil(WINDOW).max(1)
    };
    let authorized = (WINDOW * turns).min(shorter);
    let examined = if differ < shorter {
        differ + 1
    } else {
        shorter
    };
    (WriteWork::new(turns as u64, authorized as u64), examined)
}

/// The most turns a comparison of keys of at most [`SPAN`] bytes takes, by
/// the reference schedule ([`schedule`]): one per window of the shorter key,
/// `ceil(SPAN / WINDOW)`.
const TURNS: usize = SPAN.div_ceil(WINDOW);

/// One run of a comparison, driven to its result under one unrefusing
/// budget within [`TURNS`] turns: the order, the pairs examined, and the
/// work admitted; then the next step, which must be `Finished` and admit
/// nothing. A comparison not complete within its turns fails the harness.
/// The driving loop runs a constant number of times, so its expansion is
/// those turns, each one window of [`super::compare_step`], whatever the
/// harness's unwinding bound.
fn compared(left: &[u8], right: &[u8]) -> (Ordering, usize, WriteWork) {
    let mut budget = Counting::new(false);
    let mut comparison = KeyComparison::new(left, right);
    let mut completed = None;
    for _ in 0..TURNS {
        match comparison.step(&mut budget) {
            Ok(Step::Progress) => {}
            Ok(Step::Complete(ordering)) => {
                completed = Some(ordering);
                break;
            }
            Ok(Step::Finished) | Err(_) => {
                panic!("a comparison of in-bounds keys under an unrefusing budget completes")
            }
        }
    }
    let Some(ordering) = completed else {
        panic!("a comparison of keys of at most SPAN bytes completes within its turns")
    };
    let (admitted, attempts) = (budget.admitted, budget.attempts);
    assert!(
        matches!(comparison.step(&mut budget), Ok(Step::Finished)),
        "a completed comparison is finished"
    );
    assert!(
        budget.admitted == admitted && budget.attempts == attempts,
        "a finished comparison asks for no admission"
    );
    (ordering, comparison.position(), admitted)
}

/// The comparison's order against the reference order, its work against the
/// reference schedule exactly, and against its public bound.
fn agrees(left: &[u8], right: &[u8]) {
    let (ordering, examined, admitted) = compared(left, right);
    let shorter = left.len().min(right.len());
    let (work, pairs) = schedule(shorter, first_difference(left, right));
    let bound = comparison_bound(shorter as u64);
    assert!(
        ordering == left.cmp(right),
        "two keys compare in the bytewise lexicographic order of their encodings"
    );
    assert!(
        examined == pairs,
        "a comparison examines the pairs through the first that differs"
    );
    assert!(
        admitted == work,
        "a comparison admits one value and its whole window per turn, before the window"
    );
    assert!(
        admitted.values <= bound.values && admitted.bytes <= bound.bytes,
        "a comparison admits no more than its bound"
    );
}

/// Every pair of keys of at most [`SHORT`] bytes, every byte any value.
/// Its loops run at most `SHORT + 1` times (a turn's pairs, the
/// reference's scan and the slices' own comparison, each over the shorter
/// key, and the one turn and the finished step): `kani::unwind(SHORT + 2)`,
/// its unwinding assertions enabled, so a bound short of a reachable
/// iteration fails the harness, never passes it.
#[kani::proof]
#[kani::unwind(6)]
fn short_keys_compare_in_canonical_order() {
    let left: [u8; SHORT] = kani::any();
    let right: [u8; SHORT] = kani::any();
    let (left_len, right_len): (usize, usize) = (kani::any(), kani::any());
    kani::assume(left_len <= SHORT && right_len <= SHORT);
    agrees(&left[..left_len], &right[..right_len]);
}

/// Every pair of keys of `SPAN - TAIL` to [`SPAN`] bytes whose bytes before
/// their last [`TAIL`] are one shared value: the restricted long domain (the
/// module's "Domains"), ending in either turn.
#[kani::proof]
#[kani::unwind(68)]
fn long_keys_compare_in_canonical_order() {
    let shared: u8 = kani::any();
    let mut left = [shared; SPAN];
    let mut right = [shared; SPAN];
    let left_tail: [u8; TAIL] = kani::any();
    let right_tail: [u8; TAIL] = kani::any();
    left[SPAN - TAIL..].copy_from_slice(&left_tail);
    right[SPAN - TAIL..].copy_from_slice(&right_tail);
    let (left_len, right_len): (usize, usize) = (kani::any(), kani::any());
    kani::assume(left_len >= SPAN - TAIL && left_len <= SPAN);
    kani::assume(right_len >= SPAN - TAIL && right_len <= SPAN);
    agrees(&left[..left_len], &right[..right_len]);
}

/// Every pair of keys of 65 to [`SPAN`] bytes sharing their first 64 bytes,
/// any 64: the first turn authorizes and examines exactly the quantum and
/// returns `Progress` at 64; the second turn's admission, refused, changes
/// neither the position nor the work and leaves the comparison resumable;
/// resumed under another budget, the second turn authorizes the rest of the
/// shorter key and completes in the reference order; the next step is
/// `Finished` and asks for no admission.
#[kani::proof]
#[kani::unwind(68)]
fn a_comparison_crosses_its_quantum_and_resumes_after_refusal() {
    let prefix: [u8; WINDOW] = kani::any();
    let mut left: [u8; SPAN] = kani::any();
    let mut right: [u8; SPAN] = kani::any();
    left[..WINDOW].copy_from_slice(&prefix);
    right[..WINDOW].copy_from_slice(&prefix);
    let (left_len, right_len): (usize, usize) = (kani::any(), kani::any());
    kani::assume(left_len > WINDOW && left_len <= SPAN);
    kani::assume(right_len > WINDOW && right_len <= SPAN);
    let (left, right) = (&left[..left_len], &right[..right_len]);
    let shorter = left_len.min(right_len);
    let mut comparison = KeyComparison::new(left, right);

    let mut first = Counting::new(false);
    assert!(
        matches!(comparison.step(&mut first), Ok(Step::Progress)),
        "keys sharing a quantum do not end in its turn"
    );
    assert!(
        comparison.position() == WINDOW,
        "the first turn examines exactly the quantum"
    );
    assert!(
        first.admitted == WriteWork::new(1, WINDOW as u64),
        "the first turn authorizes one value and the whole quantum"
    );

    let mut refusing = Counting::new(true);
    assert!(
        matches!(
            comparison.step(&mut refusing),
            Err(BoundedError::Refused(()))
        ),
        "a refused second turn returns the refusal"
    );
    assert!(
        comparison.position() == WINDOW && refusing.admitted == WriteWork::new(0, 0),
        "a refused turn examines and admits nothing"
    );

    let mut resumed = Counting::new(false);
    let ordering = match comparison.step(&mut resumed) {
        Ok(Step::Complete(ordering)) => ordering,
        _ => panic!("the resumed turn completes"),
    };
    assert!(
        ordering == left.cmp(right),
        "a resumed comparison completes in the bytewise lexicographic order"
    );
    assert!(
        resumed.admitted == WriteWork::new(1, (shorter - WINDOW) as u64),
        "the resumed turn authorizes one value and the rest of the shorter key"
    );
    let attempts = resumed.attempts;
    assert!(
        matches!(comparison.step(&mut resumed), Ok(Step::Finished)),
        "a completed comparison is finished"
    );
    assert!(
        resumed.attempts == attempts
            && resumed.admitted == WriteWork::new(1, (shorter - WINDOW) as u64),
        "a finished comparison asks for no admission"
    );
}
