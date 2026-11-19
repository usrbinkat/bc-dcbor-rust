//! Kani harnesses of numeric reduction over binary64: the numeric level of
//! the proof hierarchy (register item 4). Status: written and unverified
//! until the gate runs them. Each harness is universal over every one of
//! the 2^64 bit patterns (`kani::any()`, no assumption), so a harness that
//! passes is a proof over that whole domain, against the reference
//! semantics stated from the bits alone ([`super::reference`]). binary16 and
//! binary32 are enumerated natively instead (`float.rs` tests): every
//! binary16 pattern in every run, every binary32 pattern in the exhaustive
//! layer (`DCBOR_RIGOR`, `run_tests.sh`) and its rules' edges in the fast.
//!
//! No harness loops: the implementation, the reference and the stubs below
//! are straight-line code over one value. `kani::unwind(1)` states it, so
//! any loop reached fails its unwinding assertion rather than passing
//! unexamined.
//!
//! # The `half` conversion: what Kani cannot run, and how it is discharged
//!
//! Read, with `std` on x86_64 (`half` 2.7.1, the rust fork's library):
//! `half`'s `f64_to_f16` and `f16_to_f64` choose their path at run time
//! (`binary16/arch.rs:42-51`, `is_x86_feature_detected!("f16c")`). The
//! macro expands to `std_detect::detect::__is_feature_detected::f16c()`
//! (`std_detect/src/detect/macros.rs:8-10`, `:197-199`), which reads the
//! feature cache (`detect/mod.rs:89-90`, `detect/cache.rs:207-217`); the
//! cache starts uninitialized in every execution (`cache.rs:65`), so the
//! first read runs `os::detect_features` (`cache.rs:190-193`), which
//! executes `__cpuid` (`os/x86.rs:44`, `:57` and on) and `_xgetbv`
//! (`:197`); `__cpuid` is an `asm!` block (`core_arch/src/x86/cpuid.rs:
//! 86-98`). Kani compiles inline assembly to a reachable failing assertion
//! (Kani `docs/src/rust-feature-support.md:115-135`). So, by the sources
//! read (`half` 2.7.1 as `Cargo.lock` resolves it, and the rust fork's
//! `library/`, the standard library the Miri gate builds), no harness can
//! run production's x86_64 conversion. The standard library Kani's own
//! toolchain builds was not read; the conclusion is scoped to these
//! sources. The detection function is in
//! `std_detect`, which this crate cannot name, so it cannot be stubbed by
//! the name resolution Kani's stubbing uses (`stubbing.md:33-35`); and the
//! f16c path it selects narrows binary64 through binary32 (`arch.rs:104`)
//! in an intrinsic whose model in Kani is not established.
//!
//! The harnesses therefore reason compositionally (`stubbing.md:9-12`).
//! Production reaches `half` through two adapters only, `float.rs`'s
//! [`super::narrowed`] (`f16::from_f64`) and [`super::widened`]
//! (`f16::to_f64`), called by the reduction, the validators, the f16
//! conversion and the bounded decoders. The adapters are stubbed (`-Z
//! stubbing`) with their contract, [`from_f64_contract`] and
//! [`to_f64_contract`], and the contract is a separate obligation,
//! discharged on the real path, whichever branch `half` takes there:
//!
//! - `widened` is exact: every binary16 pattern widens to the reference's
//!   widening (`reference::binary16`), bit for bit, a NaN to a NaN;
//! - `narrowed` returns the value itself for every value binary16 holds:
//!   every non-NaN pattern widened converts back to its own bits, and the
//!   reference names exactly those bits (`reference::binary16_bits`).
//!
//! Outside this obligation: `exact.rs`'s conversions into an `f16` host
//! value (`f16::from_f64` at `exact.rs:146`, `to_f64` at `:158`), the
//! decoding of a CBOR value into an `f16`, not the reduction.
//!
//! Both are exhaustive, every binary16 pattern, in `float.rs`'s
//! `every_f16_reduces_as_its_reference_and_decodes_only_if_canonical`,
//! evidence class checked. No other property of `from_f64` is used: for a
//! value binary16 does not hold, the stub returns any pattern at all
//! (`kani::any`), since the reduction reads only whether the round trip is
//! exact, and no binary16 pattern widens to such a value. The proofs below
//! hold for every conversion meeting the contract, the f16c path's
//! narrowing through binary32 included.
//!
//! The contract test names the branch it ran on, once every pattern has
//! passed, one tab-separated line on standard output: `DCBOR_F16_BRANCH`,
//! the branch (`f16c`, `software`, or `fp16` as `half` names aarch64's),
//! the target architecture, the compile-time `f16c` feature (`on`/`off`),
//! and `half`'s version, from the predicate `half` dispatches on
//! (`float.rs`, `half_branch`). aarch64's `fp16` branch is outside the
//! evidenced domain: no gate builds aarch64. Under
//! Miri `std_detect` reports every runtime feature absent
//! (`detect/mod.rs:35-44`), so a Miri run takes, and names, the software
//! branch. The gate requires one native run named `f16c` and one Miri run
//! named `software`; a host without f16c leaves the accelerated obligation
//! unmet.
//!
//! # Evidence classes
//!
//! - Reduction over every binary64 pattern, assuming the contract
//!   ([`every_f64_reduces_as_its_reference`],
//!   [`the_f64_validator_accepts_exactly_the_canonical_patterns`]): proved,
//!   once Kani discharges it.
//! - Reference consistency ([`every_held_pattern_is_named_back_as_itself`],
//!   [`every_named_pattern_widens_to_its_value`],
//!   [`every_held_value_is_named`]): proved, once Kani discharges it.
//! - The accelerated conversion meets the contract: checked, exhaustively,
//!   on the f16c branch (the contract test, run natively, named `f16c`).
//! - The software conversion meets the contract: checked, exhaustively,
//!   on the software branch (the contract test, run under Miri, named
//!   `software`).
//! - The production conclusion, that `prepare_f64` and the validators
//!   reduce every binary64 value as the reference does on either branch:
//!   the composition of the above, under its assumptions: `half`'s dispatch
//!   (`arch.rs:47`) picks one of the two branches checked; the branch the
//!   host and Miri took is the one their markers name; and Kani and Miri
//!   are sound for what they ran. `half` itself is never proved.
//!
//! Each class above is the class the result has once the gate records its
//! row; until then every harness here is written and unverified.
//!
//! What these harnesses establish once they pass, and no more: `prepare_f64` agrees with
//! the reference reduction over every binary64 pattern, the integer range of
//! float-to-integer reduction included; `validate_canonical_f64` accepts
//! exactly the patterns the reference leaves unreduced at binary64; and the
//! implementation's canonical NaN is the specified one. None executes the
//! decoder's rejection of a negative integer argument beyond the range
//! (`src/decode.rs`, [`crate::decode::negative`]), which has its own harness
//! (`src/decode/proofs.rs`). Compiled only under `cfg(kani)`.

use half::f16;

use super::{CANONICAL_NAN, Numeric, prepare_f64, reference, validate_canonical_f64};

/// [`super::narrowed`]'s contract: a value binary16 holds converts to its
/// own bits; any other value to any pattern. Shared with the decode
/// harness (`src/decode/proofs.rs`).
#[expect(
    dead_code,
    reason = "referenced only by #[kani::stub] attributes, which rustc does not count as a use"
)]
pub(crate) fn from_f64_contract(value: f64) -> f16 {
    match reference::binary16_bits(value) {
        Some(bits) => f16::from_bits(bits),
        None => f16::from_bits(kani::any()),
    }
}

/// [`super::widened`]'s contract: the exact widening.
#[expect(
    dead_code,
    reason = "referenced only by #[kani::stub] attributes, which rustc does not count as a use"
)]
pub(crate) fn to_f64_contract(value: f16) -> f64 {
    reference::binary16(value.to_bits())
}

/// Reference consistency (a): every non-NaN binary16 pattern, widened by
/// the reference, is named back as itself by `binary16_bits`. Over all
/// 2^16 patterns, the NaNs excluded by the contract. Evidence class:
/// proved, once Kani discharges it.
#[kani::proof]
#[kani::unwind(1)]
fn every_held_pattern_is_named_back_as_itself() {
    let bits: u16 = kani::any();
    let widened = reference::binary16(bits);
    kani::assume(!widened.is_nan());
    assert!(
        reference::binary16_bits(widened) == Some(bits),
        "a widened binary16 pattern is named back as itself"
    );
}

/// Reference consistency (b): whatever `binary16_bits` names for a binary64
/// value widens to exactly that value, bit for bit (so `-0.0` and `+0.0`
/// are told apart). Over all 2^64 patterns. Evidence class: proved, once
/// Kani discharges it.
#[kani::proof]
#[kani::unwind(1)]
fn every_named_pattern_widens_to_its_value() {
    let x = f64::from_bits(kani::any());
    if let Some(bits) = reference::binary16_bits(x) {
        assert!(
            reference::binary16(bits).to_bits() == x.to_bits(),
            "a named binary16 pattern widens to exactly its value"
        );
    }
}

/// Reference consistency (c): every non-NaN binary64 value some binary16
/// pattern widens to, bit for bit, is named by `binary16_bits`. Over all
/// 2^64 values and all 2^16 patterns. With (b), `binary16_bits` names
/// exactly the values binary16 holds. Evidence class: proved, once Kani
/// discharges it.
#[kani::proof]
#[kani::unwind(1)]
fn every_held_value_is_named() {
    let x = f64::from_bits(kani::any());
    kani::assume(!x.is_nan());
    let bits: u16 = kani::any();
    if reference::binary16(bits).to_bits() == x.to_bits() {
        assert!(
            reference::binary16_bits(x).is_some(),
            "a value binary16 holds is named"
        );
    }
}

/// The implementation's canonical NaN is the specification's
/// ([`reference::SPECIFIED_NAN`], stated from the draft, not from the
/// implementation), and every NaN, whatever its payload and sign, reduces
/// to it. A NaN never reaches `half` (`prepare_f64` answers it first), so
/// this harness stubs nothing and assumes no contract.
#[kani::proof]
#[kani::unwind(1)]
fn the_implementation_names_the_specified_nan() {
    assert!(
        CANONICAL_NAN == reference::SPECIFIED_NAN,
        "the implementation's canonical NaN is the specified 7e00"
    );
    let bits: u64 = kani::any();
    let value = f64::from_bits(bits);
    kani::assume(value.is_nan());
    assert!(
        prepare_f64(value) == Numeric::Float16(reference::SPECIFIED_NAN),
        "every NaN reduces to the specified 7e00"
    );
}

/// Every binary64 value encodes as its reference reduction: NaN as the one
/// canonical NaN; zero and every integral value in `[-2^63, 2^64 - 1]` as
/// that integer; every other value at the narrowest exact width.
#[kani::proof]
#[kani::unwind(1)]
#[kani::stub(super::narrowed, from_f64_contract)]
#[kani::stub(super::widened, to_f64_contract)]
fn every_f64_reduces_as_its_reference() {
    let value = f64::from_bits(kani::any());
    assert!(
        prepare_f64(value) == reference::reduce(value),
        "a binary64 value reduces as its reference"
    );
}

/// The decoder's validator of an eight-byte float head accepts exactly the
/// binary64 values whose reduction is themselves at that width: a value
/// that reduces to an integer, a narrower width or the canonical NaN is
/// refused.
#[kani::proof]
#[kani::unwind(1)]
#[kani::stub(super::narrowed, from_f64_contract)]
#[kani::stub(super::widened, to_f64_contract)]
fn the_f64_validator_accepts_exactly_the_canonical_patterns() {
    let bits: u64 = kani::any();
    let value = f64::from_bits(bits);
    assert!(
        validate_canonical_f64(value).is_ok()
            == (reference::reduce(value) == Numeric::Float64(bits)),
        "an eight-byte float head is accepted exactly when it is canonical"
    );
}
