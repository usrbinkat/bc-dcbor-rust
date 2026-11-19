//! `MinimalBigInt`: one encoding per integer, in every build. dCBOR places no
//! rule on tags 2 and 3 beyond those on byte strings (draft 18, section 8.5,
//! "Limiting Principles"), so the generic decoder keeps `c2 41 01` and
//! `c2 42 00 01` as two values; the type accepts only each value's minimal
//! encoding, decoding then encoding byte-identical, symbolic and bounded.

use dcbor::bounded::{Limits, encode};
use dcbor::prelude::*;
use dcbor::{Error, MinimalBigInt};

/// `hex` decoded by dCBOR's generic decoder, which treats tags 2 and 3 as
/// application data.
fn generic(hex: &str) -> CBOR {
    CBOR::try_from_hex(hex).unwrap_or_else(|error| panic!("{hex} is not dCBOR: {error}"))
}

/// `hex` refused by the minimal type as a non-canonical numeric.
#[track_caller]
fn refused(hex: &str) {
    assert!(
        matches!(
            MinimalBigInt::try_from(generic(hex)),
            Err(Error::NonCanonicalNumeric)
        ),
        "{hex} was not refused as non-canonical"
    );
}

/// `hex` accepted by the minimal type with sign `negative` and argument bytes
/// `magnitude`, its encoding, symbolic and bounded, the same bytes again.
#[track_caller]
fn minimal(hex: &str, negative: bool, magnitude: &[u8]) {
    let decoded = MinimalBigInt::try_from(generic(hex))
        .unwrap_or_else(|error| panic!("{hex} was refused: {error}"));
    assert_eq!(decoded.as_parts(), (negative, magnitude), "{hex}");
    assert_eq!(hex::encode(CBOR::from(&decoded).to_cbor_data()), hex);
    let bounded = encode(&decoded, &mut Limits::unlimited()).expect("an unlimited encoding");
    assert_eq!(
        hex::encode(bounded.as_ref()),
        hex,
        "bounded encoding of {hex}"
    );
}

/// The generic tagged layer keeps two byte strings as two values: `c2 41 01`
/// and `c2 42 00 01` both decode, as distinct tagged byte strings. The
/// minimal type refuses both, one for its range (1 is a plain integer) and
/// one for its leading zero, and `c2 40` (zero, as an empty byte string).
#[test]
fn the_generic_layer_keeps_byte_strings_and_the_minimal_type_refuses_them() {
    let one = generic("c24101");
    let padded = generic("c2420001");
    assert_ne!(one, padded, "two byte strings decoded as one value");
    assert_eq!(
        padded,
        CBOR::to_tagged_value(2u64, CBOR::to_byte_string([0u8, 1u8]))
    );
    refused("c24101");
    refused("c2420001");
    refused("c240");
}

/// Values at each edge of the plain range, both sides, plain and tagged:
/// inside, the plain integer is accepted and the bignum refused; outside,
/// the least bignum of each sign is accepted, every round trip
/// byte-identical. The magnitude is the argument `n`: the value is `n`, or
/// `-1 - n` when negative.
#[test]
fn the_minimal_type_accepts_exactly_one_encoding_at_each_range_edge() {
    let two_64 = [1, 0, 0, 0, 0, 0, 0, 0, 0];
    // u64::MAX and 2^64.
    minimal("1bffffffffffffffff", false, &[0xff; 8]);
    refused("c248ffffffffffffffff");
    minimal("c249010000000000000000", false, &two_64);
    // -2^63, the profile's least integer (n = 2^63 - 1), and -2^63 - 1
    // (n = 2^63).
    minimal(
        "3b7fffffffffffffff",
        true,
        &[0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
    );
    refused("c3487fffffffffffffff");
    minimal("c3488000000000000000", true, &[0x80, 0, 0, 0, 0, 0, 0, 0]);
    // -(2^64 + 1), RFC 8949 Appendix A (n = 2^64).
    minimal("c349010000000000000000", true, &two_64);
    // Small values: plain integers only.
    minimal("00", false, &[]);
    minimal("01", false, &[1]);
    minimal("20", true, &[]);
    minimal("1818", false, &[0x18]);
    refused("c34100");
    refused("c340");
}

/// A value outside the plain range whose byte string has a leading zero:
/// the range alone would accept it (2^64, and -2^64 - 1), so only the
/// leading-zero rule refuses it, symbolically here and in the bounded
/// decoding (`reclamation_owner.rs`). The planted control's target: removing
/// the leading-zero rule from `minimal_bigint::bignum` makes this test fail.
#[test]
fn a_leading_zero_outside_the_plain_range_is_refused() {
    refused("c24a00010000000000000000");
    refused("c34a00010000000000000000");
}

/// A symbolic negative integer whose argument is beyond dCBOR's range
/// (`n >= 2^63`), which the decoder refuses on the wire and so never yields,
/// is refused alike as out of range: re-encoded it would become a tag 3, not
/// the plain integer it is. The range's last negative argument is accepted.
#[test]
fn a_symbolic_negative_beyond_the_range_is_out_of_range() {
    let beyond = CBOR::from(dcbor::CBORCase::Negative(1 << 63));
    assert!(matches!(
        MinimalBigInt::try_from(beyond),
        Err(Error::OutOfRange)
    ));
    let last = CBOR::from(dcbor::CBORCase::Negative((1 << 63) - 1));
    let value = MinimalBigInt::try_from(last).expect("-2^63 is in range");
    assert_eq!(
        hex::encode(CBOR::from(value).to_cbor_data()),
        "3b7fffffffffffffff"
    );
}

/// Anything but an integer or a bignum is the wrong type: another tag, a
/// tag 2 around a text, a byte string untagged, a float.
#[test]
fn anything_else_is_the_wrong_type() {
    for hex in ["d82a4101", "c26131", "4101", "f93e00"] {
        assert!(
            matches!(MinimalBigInt::try_from(generic(hex)), Err(Error::WrongType)),
            "{hex}"
        );
    }
}

/// Construction takes the minimal form: from `u64` and `i64`, a plain
/// integer; from parts, a leading zero refused; and every form encodes,
/// symbolically and bounded, as the value's one encoding.
#[test]
fn construction_and_encoding_take_the_minimal_form() {
    for (value, hex) in [
        (MinimalBigInt::from(0u64), "00"),
        (MinimalBigInt::from(u64::MAX), "1bffffffffffffffff"),
        (MinimalBigInt::from(-1i64), "20"),
        (MinimalBigInt::from(i64::MIN), "3b7fffffffffffffff"),
        (
            MinimalBigInt::from_parts(false, [1, 0, 0, 0, 0, 0, 0, 0, 0]).unwrap(),
            "c249010000000000000000",
        ),
        (MinimalBigInt::from_parts(true, [0u8; 0]).unwrap(), "20"),
    ] {
        assert_eq!(hex::encode(CBOR::from(&value).to_cbor_data()), hex);
        let bounded = encode(&value, &mut Limits::unlimited()).expect("an unlimited encoding");
        assert_eq!(hex::encode(bounded.as_ref()), hex);
    }
    assert!(matches!(
        MinimalBigInt::from_parts(true, [0, 1]),
        Err(Error::NonCanonicalNumeric)
    ));
}
