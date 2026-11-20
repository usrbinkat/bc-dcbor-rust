//! Kani harnesses of the numeric profile a scalar item meets after its
//! head: the checks the head harnesses (`src/varint/proofs.rs`) leave to the
//! decoder, each over every one-item input of an unsigned, negative or
//! simple head, of every length up to the widest head (register item 4).
//!
//! Given the head the parser read (whose representation those harnesses
//! check), the symbolic decoder ([`super::decode_cbor`]) accepts the input
//! exactly when, by the reference stated here:
//!
//! - the head is the whole input (`decode_cbor`'s `UnusedData`);
//! - an unsigned argument is any `u64`;
//! - a negative argument is at most `2^63 - 1`, the item `-1 - n` at least
//!   `-2^63` ([`super::negative`], the one range rule every decoder calls;
//!   checked on its own over every `u64` argument by
//!   [`the_negative_range_rule_is_exact`]);
//! - a two-, four- or eight-byte simple head is a float that is canonical at
//!   its width, its reduction ([`crate::float::reference::reduce`]) the
//!   float itself at that width (the validators the `MajorType::Simple` arm
//!   of `decode_cbor_internal` calls); the binary16
//!   value is widened by the reference's own widening, the binary32 by
//!   Rust's exact `f32` to `f64` conversion;
//! - any other simple head carries `false`, `true` or `null`, 20 to 22
//!   (the same arm's `InvalidSimpleValue`).
//!
//! The scalar harness is the symbolic decoder's alone. The bounded decoders
//! share its head parser (`parse_header_varint`, at `bounded/decode.rs:391`
//! and `bounded/decode/header.rs:220`) and its range rule
//! ([`super::negative`], called by `bounded/decode.rs` `decode_with` and the
//! retained cursor's `advance`; found by search, each site read), so
//! [`the_negative_range_rule_is_exact`] is their range check's proof too;
//! their own float and simple-value checks are not covered here.
//!
//! The scalar harness uses symbolic bytes and input length, restricting only
//! the head's major type to unsigned, negative or simple. It has no
//! enumeration loop. `kani::unwind(1)` keeps speculative container paths
//! short; unwinding assertions must establish that no reachable execution
//! needs more iterations or recursive calls. The returned decoded
//! value is forgotten because this property checks acceptance, not
//! destruction; internal decoder cleanup remains part of the checked code.
//! The range rule's harness reaches no loop (`kani::unwind(1)`).
//! Compiled only under `cfg(kani)`.

use super::{decode_cbor, negative, parse_header_varint};
use crate::Error;
use crate::float::{Numeric, reference};
use crate::varint::{MAX_HEAD_LEN, MajorType};

/// The integer-wire range rule over every `u64` argument, against the
/// reference stated in `i128` arithmetic, where no value overflows: a
/// major-type-1 argument `n` encodes `-1 - n`; it is in dCBOR's integer
/// range exactly when `-1 - n >= -2^63`, and then decodes to that integer;
/// otherwise it is refused `OutOfRange`. Separate from float-to-integer
/// reduction (`float/proofs.rs`), which never executes this rule.
#[kani::proof]
#[kani::unwind(1)]
fn the_negative_range_rule_is_exact() {
    let argument: u64 = kani::any();
    let value = -1 - i128::from(argument);
    let in_range = value >= -(1i128 << 63);
    match negative(argument) {
        Ok(decoded) => assert!(
            in_range && i128::from(decoded) == value,
            "an argument in the range decodes to -1 - n"
        ),
        Err(error) => assert!(
            !in_range && matches!(error, Error::OutOfRange),
            "an argument beyond the range is refused OutOfRange, and only such"
        ),
    }
}

/// Every one-item input of an unsigned, negative or simple head, of one to
/// [`MAX_HEAD_LEN`] bytes, any bytes, is accepted exactly as the reference
/// states. The `half` conversion the float heads reach is stubbed with its
/// contract, discharged natively and exhaustively (`float/proofs.rs`, "The
/// `half` conversion").
#[kani::proof]
#[kani::unwind(1)]
#[kani::stub(crate::float::narrowed, crate::float::proofs::from_f64_contract)]
#[kani::stub(crate::float::widened, crate::float::proofs::to_f64_contract)]
fn a_scalar_item_is_accepted_exactly_in_the_profile() {
    let bytes: [u8; MAX_HEAD_LEN] = kani::any();
    let major = bytes[0] >> 5;
    kani::assume(major == 0 || major == 1 || major == 7);
    let length: usize = kani::any();
    kani::assume(length >= 1 && length <= MAX_HEAD_LEN);
    let input = &bytes[..length];
    let expected = match parse_header_varint(input) {
        Ok((_, _, head)) if head != length => false,
        Ok((MajorType::Unsigned, _, _)) => true,
        Ok((MajorType::Negative, argument, _)) => argument <= i64::MAX as u64,
        Ok((MajorType::Simple, argument, 3)) => {
            reference::reduce(reference::binary16(argument as u16))
                == Numeric::Float16(argument as u16)
        }
        Ok((MajorType::Simple, argument, 5)) => {
            reference::reduce(f64::from(f32::from_bits(argument as u32)))
                == Numeric::Float32(argument as u32)
        }
        Ok((MajorType::Simple, argument, 9)) => {
            reference::reduce(f64::from_bits(argument)) == Numeric::Float64(argument)
        }
        Ok((MajorType::Simple, argument, _)) => (20..=22).contains(&argument),
        Ok(_) | Err(_) => false,
    };
    let decoded = decode_cbor(input);
    let accepted = decoded.is_ok();
    core::mem::forget(decoded);
    assert!(
        accepted == expected,
        "a scalar item is accepted exactly when its value is in the dCBOR profile"
    );
}
