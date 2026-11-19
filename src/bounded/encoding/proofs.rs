//! Kani harnesses of the encoding's count recurrences (register item 4).
//! Status: written and unverified until the gate runs them.
//!
//! # `tree_height`: the B-tree height recurrence
//!
//! Reference, from the standard library's B-tree (`MIN_LEN = B - 1 = 5`,
//! `alloc::collections::btree`): every node but the root holds at least 5
//! entries, so a tree of `h` levels holds at least `m(h) = 2 * 6^(h - 1) - 1`
//! entries (`m(1) = 1`, the root's least nonempty; an empty tree has one
//! level). The height bound of a tree of `len` entries is the greatest `h`
//! with `m(h) <= len`, and 1 below `m(2) = 11`.
//!
//! [`tree_height`] computes it by the recurrence `fewest = (fewest + 1) * 6
//! - 1` from `fewest = m(2) = 11`. [`the_height_recurrence_keeps_its_invariant`]
//! checks its step over every height a `usize` count reaches (base:
//! `m(2) = 11`; step: `(m(h) + 1) * 6 - 1 = m(h + 1)`, for arbitrary `h`), so
//! by induction the loop's `fewest` is `m(height + 1)` at every iteration;
//! [`tree_height_is_the_greatest_height_its_entries_fill`] checks the
//! function's result, for every `usize` count, is the reference's greatest
//! `h`, and [`tree_moves`] twice it. No finite prefix of counts is assumed.
//!
//! # `levels`
//!
//! Not a recurrence: `floor(log2 n) + 1`, one for none.
//! [`levels_brackets_its_count`] checks `2^(levels - 1) <= max(n, 1) <
//! 2^levels` for every `u64`, so it is at least the levels a merge of `n`
//! entries passes (`ceil(log2 n)`) and the probes a binary lookup makes.
//!
//! Elsewhere: the B-tree construction's height and plan (`in_place/btree.rs`
//! `raised`, `height`, `planned`), construction's harnesses to write (6f);
//! the shape walk's counts (`Shape::walk`), a traversal over a source, not a
//! recurrence, covered by the preparation's whole-operation bound
//! (`encoding/preparation_proofs.rs`).
//!
//! Loops: `tree_height`'s runs at most 25 times over a 64-bit count (6^25
//! exceeds 2^64); the reference's power the same: `kani::unwind(28)`.
//! Compiled only under `cfg(kani)`.

use super::{levels, tree_height, tree_moves};

/// The fewest entries a tree of `h` levels holds (the module's reference).
fn fewest(h: u32) -> u128 {
    if h <= 1 { 1 } else { 2 * 6u128.pow(h - 1) - 1 }
}

/// The step of the recurrence, at any height whose least count fits a
/// `u128`: from `m(h)`, `(m(h) + 1) * 6 - 1` is `m(h + 1)`; and its base,
/// `m(2) = 11`.
#[kani::proof]
#[kani::unwind(28)]
fn the_height_recurrence_keeps_its_invariant() {
    assert!(fewest(2) == 11, "the recurrence starts at m(2) = 11");
    let h: u32 = kani::any();
    kani::assume((2..=26).contains(&h));
    assert!(
        (fewest(h) + 1) * 6 - 1 == fewest(h + 1),
        "one step of the recurrence is the next height's least count"
    );
}

/// For every `usize` count, `tree_height` is the greatest height the count
/// fills, and `tree_moves` twice it.
#[kani::proof]
#[kani::unwind(28)]
fn tree_height_is_the_greatest_height_its_entries_fill() {
    let len: usize = kani::any();
    let height = tree_height(len);
    let h = u32::try_from(height).expect("a height fits a u32");
    let len = len as u128;
    assert!(
        h >= 1 && fewest(h) <= len.max(1),
        "a tree of that height holds no more than its entries"
    );
    assert!(
        fewest(h + 1) > len,
        "a tree one level taller holds more than its entries"
    );
    assert!(
        tree_moves(len as usize) == 2 * height,
        "an iterator step moves at most twice the height"
    );
}

/// For every `u64`, `levels` brackets its count: `2^(levels - 1) <= max(n,
/// 1) < 2^levels`.
#[kani::proof]
fn levels_brackets_its_count() {
    let n: u64 = kani::any();
    let levels = levels::<()>(n).expect("levels of a u64 fit");
    let n = u128::from(n.max(1));
    assert!(
        1u128 << (levels - 1) <= n && n < 1u128 << levels,
        "levels is floor(log2 n) + 1, one for none"
    );
}
