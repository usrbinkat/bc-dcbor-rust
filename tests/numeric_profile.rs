use dcbor::CBOR;
use dcbor::CBORDecodable;
use dcbor::bounded::*;
use half::f16;

#[test]
fn int_coerced_to_float() {
    let n = 42;
    let c: CBOR = n.into();
    let f = f64::try_from_cbor(&c).unwrap();
    assert_eq!(f, n as f64);
    let c2: CBOR = f.into();
    assert_eq!(c2, c);
    let i: i32 = c.try_into().unwrap();
    assert_eq!(i, n);
}

#[test]
fn fail_float_coerced_to_int() {
    let n = 42.5;
    let c: CBOR = n.into();
    let f = f64::try_from_cbor(&c).unwrap();
    assert_eq!(f, n);
    assert!(i32::try_from(c).is_err());
}

fn encoded(value: &(impl Schema + ?Sized)) -> Vec<u8> {
    encode(value, &mut Limits::unlimited())
        .expect("an unlimited encoding completes")
        .as_ref()
        .to_vec()
}

/// Draft-12 section 7.1: literals are the authority, not another serializer.
/// Integers unrepresentable in f64 are tested separately as integers.
#[test]
fn published_numeric_vectors_in_every_exact_source_precision() {
    let fixtures: &[(f64, &str)] = &[
        (0.0, "00"),
        (1.0, "01"),
        (23.0, "17"),
        (24.0, "1818"),
        (255.0, "18ff"),
        (65535.0, "19ffff"),
        (65536.0, "1a00010000"),
        (4294967295.0, "1affffffff"),
        (4294967296.0, "1b0000000100000000"),
        (-1.0, "20"),
        (-2.0, "21"),
        (-127.0, "387e"),
        (-128.0, "387f"),
        (-32768.0, "397fff"),
        (-2147483648.0, "3a7fffffff"),
        (-9223372036854775808.0, "3b7fffffffffffffff"),
        (1.5, "f93e00"),
        (2345678.25, "fa4a0f2b39"),
        (1.2, "fb3ff3333333333333"),
        (42.0, "182a"),
        (2345678.0, "1a0023cace"),
        (-2345678.0, "3a0023cacd"),
        (-0.0, "00"),
        (5.960464477539063e-8, "f90001"),
        (1.401298464324817e-45, "fa00000001"),
        (5e-324, "fb0000000000000001"),
        (2.2250738585072014e-308, "fb0010000000000000"),
        (6.103515625e-5, "f90400"),
        (65504.0, "19ffe0"),
        (33554430.0, "1a01fffffe"),
        (-9223372036854774784.0, "3b7ffffffffffffbff"),
        (18446744073709550000.0, "1bfffffffffffff800"),
        (18446744073709552000.0, "fa5f800000"),
        (-18446742974197924000.0, "fadf7fffff"),
        (3.4028234663852886e38, "fa7f7fffff"),
        (3.402823466385289e38, "fb47efffffe0000001"),
        (f64::MAX, "fb7fefffffffffffff"),
        (f64::INFINITY, "f97c00"),
        (f64::NEG_INFINITY, "f9fc00"),
        (f64::NAN, "f97e00"),
        (-33554432.0, "3a01ffffff"),
        (-18446744073709551616.0, "fadf800000"),
        // Whole doubles below the dCBOR integer range are not reduced: each
        // stays at the narrowest float that holds it exactly.
        (-9223372036854777856.0, "fbc3e0000000000001"),
        (-18446744073709549568.0, "fbc3efffffffffffff"),
        (-18446744073709555712.0, "fbc3f0000000000001"),
    ];
    for &(value, expected) in fixtures {
        let expected = hex::decode(expected).unwrap();
        assert_eq!(encoded(&value), expected, "bounded f64 {value}");
        assert_eq!(
            CBOR::from(value).to_cbor_data(),
            expected,
            "symbolic f64 {value}"
        );
        let decoded = f64::try_from(CBOR::try_from_data(&expected).unwrap()).unwrap();
        assert!(decoded == value || (decoded.is_nan() && value.is_nan()));
        let single = value as f32;
        if single as f64 == value || value.is_nan() {
            assert_eq!(encoded(&single), expected, "bounded f32 {value}");
            assert_eq!(CBOR::from(single).to_cbor_data(), expected);
        }
        let half = f16::from_f64(value);
        if half.to_f64() == value || value.is_nan() {
            assert_eq!(encoded(&half), expected, "bounded f16 {value}");
            assert_eq!(CBOR::from(half).to_cbor_data(), expected);
        }
    }
    assert_eq!(
        encoded(&u64::MAX),
        hex::decode("1bffffffffffffffff").unwrap()
    );
    assert_eq!(CBOR::from(u64::MAX).to_cbor_data(), encoded(&u64::MAX));
    // An integer with more precision than any float holds stays an integer.
    let precise = -9223372036854775807i64;
    let expected = hex::decode("3b7ffffffffffffffe").unwrap();
    assert_eq!(encoded(&precise), expected);
    assert_eq!(CBOR::from(precise).to_cbor_data(), expected);
    assert_eq!(
        i64::try_from(CBOR::try_from_data(&expected).unwrap()).unwrap(),
        precise
    );
}

/// Noncanonical NaN payload examples at each source precision encode as the
/// canonical half-precision NaN on both paths.
#[test]
fn noncanonical_nan_payloads_encode_as_the_canonical_nan() {
    let canonical = hex::decode("f97e00").unwrap();
    let double = f64::from_bits(0x7ff9_1000_0000_0001);
    let single = f32::from_bits(0xffc0_0001);
    let half = f16::from_bits(0x7e01);
    assert!(double.is_nan() && single.is_nan() && half.is_nan());
    assert_eq!(encoded(&double), canonical, "bounded f64 NaN payload");
    assert_eq!(encoded(&single), canonical, "bounded f32 NaN payload");
    assert_eq!(encoded(&half), canonical, "bounded f16 NaN payload");
    assert_eq!(CBOR::from(double).to_cbor_data(), canonical);
    assert_eq!(CBOR::from(single).to_cbor_data(), canonical);
    assert_eq!(CBOR::from(half).to_cbor_data(), canonical);
}

/// Each invalid vector is rejected with its exact class: a float or head
/// not in its narrowest canonical form is `NonCanonicalNumeric`
/// (`decode::parse_header_varint`, `float::validate_canonical_*`); a negative
/// integer below the dCBOR range is `OutOfRange` (`decode_cbor_internal`).
#[test]
fn published_invalid_numeric_vectors_are_rejected() {
    use dcbor::Error;
    use std::mem::discriminant;
    let noncanonical = Error::NonCanonicalNumeric;
    let range = Error::OutOfRange;
    for (hex, expected) in [
        // 10.0 at half precision: must be the integer 10.
        ("f94a00", &noncanonical),
        // 1.5 at double precision: fits a half.
        ("fb3ff8000000000000", &noncanonical),
        // 2^32 at single precision: must be an integer.
        ("fa4f800000", &noncanonical),
        // -2^63 - 1, -2^64 + 1 and -2^64: 65-bit negatives (draft 7.2).
        ("3b8000000000000000", &range),
        ("3bfffffffffffffffe", &range),
        ("3bffffffffffffffff", &range),
        // Infinities wider than a half.
        ("fb7ff0000000000000", &noncanonical),
        ("fa7f800000", &noncanonical),
        ("fbfff0000000000000", &noncanonical),
        ("faff800000", &noncanonical),
        // NaNs other than the canonical f97e00.
        ("fb7ff9100000000001", &noncanonical),
        ("faffc00001", &noncanonical),
        ("f97e01", &noncanonical),
    ] {
        match CBOR::try_from_hex(hex) {
            Ok(value) => panic!("accepted {hex} as {value:?}"),
            Err(error) => assert_eq!(
                discriminant(&error),
                discriminant(expected),
                "{hex}: rejected as {error:?}, expected {expected:?}"
            ),
        }
    }
}

#[test]
fn all_half_patterns_preserve_value_and_reject_noncanonical_forms() {
    for bits in 0..=u16::MAX {
        let value = f16::from_bits(bits);
        let bytes = encoded(&value);
        assert_eq!(bytes, encoded(&value.to_f32()));
        assert_eq!(bytes, encoded(&value.to_f64()));
        let decoded: f64 = CBOR::try_from_data(&bytes).unwrap().try_into().unwrap();
        assert!(
            decoded == value.to_f64() || (decoded.is_nan() && value.is_nan()),
            "{bits:04x}"
        );
        let raw = [0xf9, (bits >> 8) as u8, bits as u8];
        assert_eq!(
            CBOR::try_from_data(raw).is_ok(),
            raw.as_slice() == bytes,
            "{bits:04x}"
        );
    }
}

/// Exercise adjacent representable values around every binary exponent, rather
/// than relying on random sampling to hit a reduction or narrowing boundary.
#[test]
fn single_precision_exponent_boundaries_preserve_values() {
    for exponent in 1..255u32 {
        for sign in [0, 1u32 << 31] {
            let boundary = sign | (exponent << 23);
            for bits in [boundary - 1, boundary, boundary + 1] {
                let value = f32::from_bits(bits);
                let bytes = encoded(&value);
                assert_eq!(bytes, encoded(&(value as f64)), "{bits:08x}");
                let decoded: f64 = CBOR::try_from_data(bytes).unwrap().try_into().unwrap();
                assert_eq!(decoded, value as f64, "{bits:08x}");
            }
        }
    }
}

#[test]
fn double_precision_exponent_boundaries_preserve_values() {
    for exponent in 1..2047u64 {
        for sign in [0, 1u64 << 63] {
            let boundary = sign | (exponent << 52);
            for bits in [boundary - 1, boundary, boundary + 1] {
                let value = f64::from_bits(bits);
                let bytes = encoded(&value);
                let decoded = f64::try_from(CBOR::try_from_data(&bytes).unwrap()).unwrap();
                assert_eq!(decoded, value, "{bits:016x}");
                assert_eq!(CBOR::from(value).to_cbor_data(), bytes);
                let single = value as f32;
                if f64::from(single) == value {
                    assert_eq!(encoded(&single), bytes);
                }
            }
        }
    }
}

#[test]
fn equal_numeric_map_keys_have_one_canonical_identity() {
    for (single, expected) in [
        (-33554432.0f32, "a13a01ffffff02"),
        (4294967296.0f32, "a11b000000010000000002"),
        (-0.0f32, "a10002"),
    ] {
        let mut map = dcbor::Map::new();
        map.insert(single, 1u64);
        map.insert(f64::from(single), 2u64);
        let bytes = CBOR::from(map).to_cbor_data();
        assert_eq!(bytes, hex::decode(expected).unwrap());
        assert!(CBOR::try_from_data(bytes).is_ok());
    }
}

#[test]
fn public_float_extraction_refuses_rounded_integers() {
    for integer in [u64::MAX, i64::MAX as u64] {
        assert!(matches!(
            f64::try_from(CBOR::from(integer)),
            Err(dcbor::Error::OutOfRange)
        ));
        assert!(matches!(
            f32::try_from(CBOR::from(integer)),
            Err(dcbor::Error::OutOfRange)
        ));
    }
    assert_eq!(
        f64::try_from(CBOR::from(u64::MAX - 2047)).unwrap(),
        18446744073709549568.0
    );
}

#[test]
fn equal_source_values_have_identical_encodings() {
    for single in [
        -33554432.0f32,
        -16777216.0,
        4294967296.0,
        18446742974197923840.0,
    ] {
        let single_cbor = CBOR::from(single);
        assert_eq!(
            single_cbor.to_cbor_data(),
            CBOR::from(single as f64).to_cbor_data()
        );
        assert_eq!(f32::try_from(single_cbor).unwrap(), single);
    }
    assert_eq!(
        CBOR::from(-33554432.0f32).to_cbor_data(),
        [0x3a, 0x01, 0xff, 0xff, 0xff]
    );
}
