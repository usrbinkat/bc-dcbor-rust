//! Kani harnesses of the arenas' growth recurrence: the count-recurrence
//! level of the proof hierarchy (register item 4), for [`owned_growth`] and
//! [`storage_growth`], the bounds of [`Owned`] and of the retained arena
//! (`decode::storage::Storage`). Status: written and unverified until the
//! gate runs them.
//!
//! # The recurrence
//!
//! An arena of `s`-byte elements grows when it is full: from capacity `c`
//! to `g(c)`, the growth rule [`grown_capacity`] (four from empty, double
//! otherwise; its own harness in `src/bounded/proofs.rs`, reused here, never
//! restated). One growth relocates the `c` elements the full arena holds,
//! requests `g(c) * s` bytes, holds the old and the new allocation at once,
//! `(c + g(c)) * s`, and keeps `g(c) * s`. That one step is [`grow`], the
//! operational model. A retained arena's growth also requests a staging
//! block of at most a quantum, [`TURN`]`.bytes`; makes at most four writes of
//! at most a quantum each (`storage.rs` `GROWTH_WRITES`: the staging block's,
//! the grant's, the publication's and the settlement's; the first growth,
//! from an empty arena, publishes settled at once and makes three,
//! `storage.rs:877-889`, so `storage_growth` counts one write more than it
//! makes, a bound); and admits a release per allocation, two per growth
//! (`Storage::allocate_grown` uses the same rule, `crate::bounded::grown`,
//! `storage.rs:945`). That a real arena's growth admits what this formula
//! counts is the coordinator's exhaustive native test in `storage.rs`.
//!
//! # The invariant, and its closed form
//!
//! After `k` growths from empty, in exact arithmetic (`u128`):
//!
//! - `k = 0`: every count zero;
//! - `k >= 1`: capacity `c = 4 * 2^(k - 1)`; relocated elements `c - 4`;
//!   copied bytes `s * (c - 4)`; requested bytes `s * (2c - 4)`; held
//!   `s * c`; peak `s * (c + c / 2)`, or `4s` at `k = 1`.
//!
//! [`the_recurrence_starts_at_its_base_case`] checks `k = 0`;
//! [`one_growth_preserves_the_invariant`] checks that one growth from any
//! state satisfying it at `k`, for every `k` whose capacity fits a `u64`
//! and every `u64` element size, satisfies it at `k + 1`. By induction on `k` the
//! closed form holds after every number of growths: no finite prefix is
//! assumed. The number of growths reaching `n` elements is the least `k`
//! whose capacity holds them: `c(n) = max(4, n.next_power_of_two())`, `0`
//! for `n = 0`.
//!
//! [`owned_growth_is_the_closed_form`] and
//! [`storage_growth_is_the_closed_form`] then check the production bounds
//! equal that closed form for every `u64` element count and size, and
//! refuse (`Overflow`) exactly when a quantity of it does not fit: a
//! harness over arbitrary counts, its loop over growths bounded by the 63
//! a `u64` capacity admits (`kani::unwind(66)`). Monotonicity is not used.
//!
//! # Every growth count, each at a constant capacity
//!
//! The closed form's capacity is `4 << (k - 1)`: at a symbolic `k`, every
//! quantity is a product of two symbolic 128-bit values (`size` and a
//! capacity), which a SAT encoding proves only through multiplier
//! circuits. Run that way, the step harness's 80 conditions did not decide
//! in 30 minutes under CaDiCaL nor 10 under kissat or Z3; Bitwuzla, through
//! CBMC's SMT2 encoding, reported six failures whose concrete inputs all
//! pass when replayed natively (`--concrete-playback`), so no verdict of it
//! is taken. The harnesses quantify over `k` instead by enumeration, every
//! count from 0 to [`MAX_GROWTHS`] a concrete iteration of a loop
//! ([`one_growth_preserves_the_invariant`]) or a concrete case of one
//! selection ([`closed_at`]): each capacity is then a constant, each
//! quantity a constant shift of `size` ([`bytes`], [`closed`]), and the
//! domain is unchanged, every `k`. Production's own loop (`owned_growth`)
//! multiplies a concrete capacity per growth.
//! Compiled only under `cfg(kani)`.

use super::{Growth, TURN, WriteWork, grown_capacity, owned_growth, storage_growth};

const MAX: u128 = u64::MAX as u128;

/// An arena's growth counts in exact arithmetic.
#[derive(Clone, Copy, PartialEq, Eq)]
struct State {
    capacity: u128,
    growths: u128,
    relocated: u128,
    copied: u128,
    requested: u128,
    held: u128,
    peak: u128,
}

const EMPTY: State = State {
    capacity: 0,
    growths: 0,
    relocated: 0,
    copied: 0,
    requested: 0,
    held: 0,
    peak: 0,
};

/// `size` elements' bytes in an arena of `capacity` elements, `capacity`
/// zero or a power of two (every capacity the growth rule makes): its
/// product with `size`, stated as `size` shifted by the capacity's one bit.
fn bytes(capacity: u128, size: u128) -> u128 {
    if capacity == 0 {
        0
    } else {
        size << capacity.trailing_zeros()
    }
}

/// One growth of a full arena of `size`-byte elements: the operational
/// model (the module's "The recurrence"), its capacity by the growth rule,
/// every capacity's bytes by [`bytes`].
fn grow(state: State, size: u128) -> Option<State> {
    let next = u128::from(grown_capacity(u64::try_from(state.capacity).ok()?)?);
    Some(State {
        capacity: next,
        growths: state.growths + 1,
        relocated: state.relocated + state.capacity,
        copied: state.copied + bytes(state.capacity, size),
        requested: state.requested + bytes(next, size),
        held: bytes(next, size),
        peak: bytes(state.capacity, size) + bytes(next, size),
    })
}

/// The closed form after `k` growths (the module's "The invariant"). The
/// capacity is `2^(k + 1)`, so every multiple of it is stated as a shift of
/// `size` by `k`: `size * c = size << (k + 1)`, `size * 2c = size << (k + 2)`,
/// `size * c / 2 = size << k`, `size * 4 = size << 2`. Exact in `u128` for
/// every `k` to [`MAX_GROWTHS`] and every `u64` size (`size << 64` at most);
/// at a concrete `k` each shift is a constant one (the module's "Every
/// growth count, each at a constant capacity").
fn closed(k: u128, size: u128) -> State {
    if k == 0 {
        return EMPTY;
    }
    let capacity = 4u128 << (k - 1);
    State {
        capacity,
        growths: k,
        relocated: capacity - 4,
        copied: (size << (k + 1)) - (size << 2),
        requested: (size << (k + 2)) - (size << 2),
        held: size << (k + 1),
        peak: if k == 1 {
            size << 2
        } else {
            (size << (k + 1)) + (size << k)
        },
    }
}

/// The most growths a `u64` capacity admits: `4 * 2^62 = 2^64` does not
/// fit, `4 * 2^61 = 2^63` does.
const MAX_GROWTHS: u128 = 62;

/// [`closed`] at `k`, any count to [`MAX_GROWTHS`], evaluated at each
/// concrete count and selected by `k` (the module's "Every growth count,
/// each at a constant capacity"): the same value, each case's capacity a
/// constant. Past [`MAX_GROWTHS`], whose capacity no `u64` holds, the
/// closed form is not taken: [`EMPTY`], which every caller refuses first by
/// its capacity check.
fn closed_at(k: u128, size: u128) -> State {
    let mut state = EMPTY;
    let mut count = 0;
    while count <= MAX_GROWTHS {
        if count == k {
            state = closed(count, size);
        }
        count += 1;
    }
    state
}

/// The base case: an arena that never grew has every count zero.
#[kani::proof]
fn the_recurrence_starts_at_its_base_case() {
    let size = u128::from(kani::any::<u64>());
    assert!(closed(0, size) == EMPTY, "no growth, no counts");
}

/// The step: one growth from the closed form at every `k` to
/// [`MAX_GROWTHS`], each a concrete iteration, for every `u64` element size,
/// is the closed form at `k + 1`; past the last capacity a `u64` holds, the
/// growth rule refuses. Each field is a separate assertion, avoiding the
/// short-circuit conjunction of derived `State::eq` across byte quantities.
/// Its loop runs `MAX_GROWTHS + 1` times (`kani::unwind(64)`, its iterations
/// and its exit).
#[kani::proof]
#[kani::unwind(64)]
fn one_growth_preserves_the_invariant() {
    let size = u128::from(kani::any::<u64>());
    let mut k = 0;
    while k <= MAX_GROWTHS {
        let grown = grow(closed(k, size), size);
        if k < MAX_GROWTHS {
            let grown = grown.expect("one growth within the capacity domain succeeds");
            let expected = closed(k + 1, size);
            assert!(
                grown.capacity == expected.capacity,
                "one growth preserves the invariant: capacity"
            );
            assert!(
                grown.growths == expected.growths,
                "one growth preserves the invariant: growth count"
            );
            assert!(
                grown.relocated == expected.relocated,
                "one growth preserves the invariant: relocated elements"
            );
            assert!(
                grown.copied == expected.copied,
                "one growth preserves the invariant: copied bytes"
            );
            assert!(
                grown.requested == expected.requested,
                "one growth preserves the invariant: requested bytes"
            );
            assert!(
                grown.held == expected.held,
                "one growth preserves the invariant: held bytes"
            );
            assert!(
                grown.peak == expected.peak,
                "one growth preserves the invariant: peak bytes"
            );
        } else {
            assert!(
                grown.is_none(),
                "no growth past the largest capacity a u64 holds"
            );
        }
        k += 1;
    }
}

/// The capacity reaching `elements`, and the growths it took.
fn reach(elements: u64) -> (u128, u128) {
    if elements == 0 {
        return (0, 0);
    }
    let capacity = u128::from(elements).next_power_of_two().max(4);
    (capacity, u128::from(capacity.trailing_zeros()) - 1)
}

/// `value` as a `u64`, if it fits.
fn fits(value: u128) -> Option<u64> {
    (value <= MAX).then(|| value as u64)
}

/// `owned_growth(elements, size)` is the closed form at the growths reaching
/// `elements`, for every `u64` count and size, and refuses exactly when a
/// quantity does not fit (or the capacity would pass `2^63`).
#[kani::proof]
#[kani::unwind(66)]
fn owned_growth_is_the_closed_form() {
    let (elements, size): (u64, u64) = (kani::any(), kani::any());
    let (capacity, growths) = reach(elements);
    let state = closed_at(growths, u128::from(size));
    let expected = (|| {
        if capacity > 1u128 << 63 {
            return None;
        }
        Some(Growth {
            copied: fits(state.copied)?,
            allocations: fits(state.growths)?,
            allocated: fits(state.requested)?,
            held: fits(state.held)?,
            peak: fits(state.peak)?,
        })
    })();
    assert!(
        owned_growth::<()>(elements, size).ok() == expected,
        "owned_growth is the closed form, refused exactly when it does not fit"
    );
}

/// `storage_growth(elements, size)` is the closed form of the retained
/// arena at the growths reaching `elements`: the arena's growth, a staging
/// block of a quantum and a release per allocation, two per growth, and the
/// work of relocating every element and four writes per growth; refused
/// exactly when a quantity does not fit.
#[kani::proof]
#[kani::unwind(66)]
fn storage_growth_is_the_closed_form() {
    let (elements, size): (u64, u64) = (kani::any(), kani::any());
    let (capacity, growths) = reach(elements);
    let state = closed_at(growths, u128::from(size));
    let block = u128::from(TURN.bytes);
    let writes = 4 * growths;
    let expected = (|| {
        if capacity > 1u128 << 63 {
            return None;
        }
        // The arena's own growth must fit, as the bound computes it first.
        fits(state.requested)?;
        fits(state.peak)?;
        let growth = Growth {
            copied: fits(state.copied)?,
            allocations: fits(2 * state.growths)?,
            allocated: fits(state.requested + growths * block)?,
            held: fits(state.held)?,
            peak: if growths == 0 {
                0
            } else {
                fits(state.peak + block)?
            },
        };
        // One value and at most a quantum of bytes per write: a growth write
        // is one unit of the retained arena's capped write (`storage.rs`
        // `WRITE`, `Capped::new(Caller, 1, TURN.bytes)`), and `Capped::times`
        // counts each at one value and its full cap, not at a turn's values.
        let work = WriteWork::new(
            fits(state.relocated + writes)?,
            fits(state.copied + writes * block)?,
        );
        Some((growth, work))
    })();
    assert!(
        storage_growth::<()>(elements, size).ok() == expected,
        "storage_growth is the closed form, refused exactly when it does not fit"
    );
}
