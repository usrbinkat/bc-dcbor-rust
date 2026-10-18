//! # Floating Point Number Support in dCBOR
//!
//! dCBOR provides canonical encoding for floating point values through
//! implementation of the `From<T>` and `TryFrom<CBOR>` traits for `f16`,
//! `f32`, and `f64` types.
//!
//! Per the dCBOR specification, the canonical encoding rules ensure
//! deterministic representation:
//!
//! - Numeric reduction: a float with zero fractional part converts to the
//!   integer it equals when that integer is in the reduction range of its
//!   dCBOR profile: `[-2^63, 2^64 - 1]`, independently of its source
//!   precision. A float that does not reduce is serialized at the narrowest
//!   precision holding it exactly. Reduction precedes precision selection.
//! - All NaN values are canonicalized to a single representation: `f9 7e 00`.
//! - Positive and negative infinity are serialized at half precision.
//!
//! Each of these decisions is made once, before anything is written
//! ([`Numeric`]): the conversions (`convert_f16`, `convert_f32`,
//! `convert_f64`), the symbolic serialization of `Simple::Float`
//! ([`f64_cbor_data`]) and the bounded encoding (`bounded.rs`) all read it.

import_stdlib!();

use half::f16;

use super::varint::{Argument, MajorType, head_vec};
use crate::{CBOR, CBORCase, Error, ExactFrom, Result, Simple};

/// The bits of the one canonical NaN, half precision: `f9 7e 00`.
const CANONICAL_NAN: u16 = 0x7e00;

pub(crate) const DCBOR_INT_MIN: i128 = -(1i128 << 63);
pub(crate) const DCBOR_INT_MAX: u128 = (1u128 << 64) - 1;

/// What a float converts to before it is serialized (`From<f16>`,
/// `From<f32>`, `From<f64>`): an integer it reduces to exactly, or the
/// float, widened exactly to `f64`, held as `Simple::Float`.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) enum Converted {
    Unsigned(u64),
    Negative(u64),
    Float(f64),
}

impl Converted {
    fn into_cbor(self) -> CBOR {
        match self {
            Self::Unsigned(i) => CBORCase::Unsigned(i).into(),
            Self::Negative(i) => CBORCase::Negative(i).into(),
            Self::Float(n) => CBORCase::Simple(Simple::Float(n)).into(),
        }
    }

    /// The canonical encoding of what this conversion holds: an integer as
    /// itself, a float as `Simple::Float` serializes ([`prepare_f64`]).
    pub(crate) fn prepared(self) -> Numeric {
        match self {
            Self::Unsigned(i) => Numeric::Unsigned(i),
            Self::Negative(i) => Numeric::Negative(i),
            Self::Float(n) => prepare_f64(n),
        }
    }
}

/// The canonical encoding a number serializes as, decided before anything
/// is written: an integer by its shortest head, or a float's bits at the
/// precision its reduction selected, NaN as [`CANONICAL_NAN`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Numeric {
    Unsigned(u64),
    Negative(u64),
    Float16(u16),
    Float32(u32),
    Float64(u64),
}

impl Numeric {
    /// The head this encoding is: its major type and its argument, whose
    /// width the variant fixes.
    pub(crate) const fn head(self) -> (MajorType, Argument) {
        match self {
            Self::Unsigned(i) => (MajorType::Unsigned, Argument::Shortest(i)),
            Self::Negative(i) => (MajorType::Negative, Argument::Shortest(i)),
            Self::Float16(bits) => (MajorType::Simple, Argument::Fixed16(bits)),
            Self::Float32(bits) => (MajorType::Simple, Argument::Fixed32(bits)),
            Self::Float64(bits) => (MajorType::Simple, Argument::Fixed64(bits)),
        }
    }

    /// Bytes of this encoding.
    pub(crate) const fn len(self) -> usize {
        self.head().1.head_len()
    }

    pub(crate) fn cbor_data(self) -> Vec<u8> {
        let (major_type, argument) = self.head();
        head_vec(major_type, argument)
    }
}

/// Reduce within DCBOR_INT. The upper bound is exclusive because converting
/// `u64::MAX` to `f64` rounds to 2^64. Subtract only after integer conversion:
/// floating subtraction of one can change a large negative value.
pub(crate) fn convert_f64(n: f64) -> Converted {
    if (DCBOR_INT_MIN as f64..(DCBOR_INT_MAX + 1) as f64).contains(&n) {
        let integer = n as i128;
        if integer as f64 == n {
            return if integer < 0 {
                Converted::Negative((-1 - integer) as u64)
            } else {
                Converted::Unsigned(integer as u64)
            };
        }
    }
    Converted::Float(n)
}

impl From<f64> for CBOR {
    fn from(value: f64) -> Self {
        convert_f64(value).into_cbor()
    }
}

/// Reduce first, then choose the narrowest exact floating representation.
pub(crate) fn prepare_f64(value: f64) -> Numeric {
    match convert_f64(value) {
        Converted::Unsigned(i) => Numeric::Unsigned(i),
        Converted::Negative(i) => Numeric::Negative(i),
        Converted::Float(_) if value.is_nan() => Numeric::Float16(CANONICAL_NAN),
        Converted::Float(_) => {
            let half = f16::from_f64(value);
            if half.to_f64() == value {
                Numeric::Float16(half.to_bits())
            } else if (value as f32) as f64 == value {
                Numeric::Float32((value as f32).to_bits())
            } else {
                Numeric::Float64(value.to_bits())
            }
        }
    }
}

/// The symbolic serialization of `Simple::Float(value)`.
pub(crate) fn f64_cbor_data(value: f64) -> Vec<u8> {
    prepare_f64(value).cbor_data()
}

pub(crate) fn validate_canonical_f64(n: f64) -> Result<()> {
    if prepare_f64(n) != Numeric::Float64(n.to_bits()) {
        return Err(Error::NonCanonicalNumeric);
    }
    Ok(())
}

/// The integer a CBOR negative argument `n` encodes, `-1 - n`.
const fn negative_value(n: u64) -> i128 {
    -1 - n as i128
}

impl TryFrom<CBOR> for f64 {
    type Error = Error;

    fn try_from(cbor: CBOR) -> Result<Self> {
        match cbor.into_case() {
            CBORCase::Unsigned(n) => {
                if let Some(f) = f64::exact_from_u64(n) {
                    Ok(f)
                } else {
                    Err(Error::OutOfRange)
                }
            }
            // The integer itself must be exact in `f64`, not merely its
            // argument: `-1 - n` can round where `n` does not.
            CBORCase::Negative(n) => {
                f64::exact_from_i128(negative_value(n)).ok_or(Error::OutOfRange)
            }
            CBORCase::Simple(Simple::Float(n)) => Ok(n),
            _ => Err(Error::WrongType),
        }
    }
}

/// Widening is exact; every source precision uses the same reduction.
pub(crate) fn convert_f32(n: f32) -> Converted {
    convert_f64(n as f64)
}

impl From<f32> for CBOR {
    fn from(value: f32) -> Self {
        convert_f32(value).into_cbor()
    }
}

pub(crate) fn validate_canonical_f32(n: f32) -> Result<()> {
    if prepare_f64(n as f64) != Numeric::Float32(n.to_bits()) {
        return Err(Error::NonCanonicalNumeric);
    }
    Ok(())
}

impl TryFrom<CBOR> for f32 {
    type Error = Error;

    fn try_from(cbor: CBOR) -> Result<Self> {
        match cbor.into_case() {
            CBORCase::Unsigned(n) => {
                if let Some(f) = f32::exact_from_u64(n) {
                    Ok(f)
                } else {
                    Err(Error::OutOfRange)
                }
            }
            // The negative integer `-1 - n`, exactly, never the argument.
            CBORCase::Negative(n) => {
                f32::exact_from_i128(negative_value(n)).ok_or(Error::OutOfRange)
            }
            CBORCase::Simple(Simple::Float(n)) => {
                if let Some(f) = f32::exact_from_f64(n) {
                    Ok(f)
                } else {
                    Err(Error::OutOfRange)
                }
            }
            _ => Err(Error::WrongType),
        }
    }
}

/// Widening is exact; every source precision uses the same reduction.
pub(crate) fn convert_f16(value: f16) -> Converted {
    convert_f64(value.to_f64())
}

impl From<f16> for CBOR {
    fn from(value: f16) -> Self {
        convert_f16(value).into_cbor()
    }
}

impl TryFrom<CBOR> for f16 {
    type Error = Error;

    fn try_from(cbor: CBOR) -> Result<Self> {
        match cbor.into_case() {
            CBORCase::Unsigned(n) => {
                if let Some(f) = f16::exact_from_u64(n) {
                    Ok(f)
                } else {
                    Err(Error::OutOfRange)
                }
            }
            CBORCase::Negative(n) => {
                if let Some(f) = f16::exact_from_i128(negative_value(n)) {
                    Ok(f)
                } else {
                    Err(Error::OutOfRange)
                }
            }
            CBORCase::Simple(Simple::Float(n)) => {
                if let Some(f) = f16::exact_from_f64(n) {
                    Ok(f)
                } else {
                    Err(Error::OutOfRange)
                }
            }
            _ => Err(Error::WrongType),
        }
    }
}

pub(crate) fn validate_canonical_f16(n: f16) -> Result<()> {
    if prepare_f64(n.to_f64()) != Numeric::Float16(n.to_bits()) {
        return Err(Error::NonCanonicalNumeric);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integer_extraction_must_not_round() {
        for value in [CBOR::from(u64::MAX), CBOR::from(i64::MAX)] {
            assert!(matches!(
                f64::try_from(value.clone()),
                Err(Error::OutOfRange)
            ));
            assert!(matches!(f32::try_from(value), Err(Error::OutOfRange)));
        }
        assert_eq!(
            f64::try_from(CBOR::from(i64::MIN)).unwrap(),
            -9223372036854775808.0
        );
        assert_eq!(
            f32::try_from(CBOR::from(i64::MIN)).unwrap(),
            -9223372036854775808.0
        );
    }

    fn bounded_bytes(value: &impl crate::bounded::BoundedEncodable) -> Vec<u8> {
        use crate::bounded::*;
        struct Admit;
        impl Budget for Admit {
            type Refusal = ();
            fn traverse(&mut self, _: u64, _: u64) -> core::result::Result<(), ()> {
                Ok(())
            }
        }
        impl Allocator for Admit {
            type Permit = ();
            fn allocate(&mut self, _: u64) -> core::result::Result<(), ()> {
                Ok(())
            }
        }
        let prepared = prepare(value, &mut Admit).unwrap();
        let mut bytes = vec![0; usize::try_from(prepared.len()).unwrap()];
        prepared.encode_into(&mut bytes, &mut Admit).unwrap();
        bytes
    }

    /// Supplementary consistency evidence; literal profile vectors and value
    /// preservation are independently tested in tests/numeric_profile.rs.
    #[test]
    fn every_f16_symbolic_and_bounded_agree() {
        for bits in 0..=u16::MAX {
            let value = f16::from_bits(bits);
            let expected = bounded_bytes(&value);
            assert_eq!(CBOR::from(value).to_cbor_data(), expected, "{bits:#06x}");
            assert_eq!(
                convert_f16(value).prepared().cbor_data(),
                expected,
                "{bits:#06x}"
            );
            assert_eq!(convert_f16(value).prepared().len(), expected.len());
        }
    }

    /// `f32` and `f64` patterns across both signs, subnormals, narrowing
    /// and reduction boundaries, infinities and NaN payloads, plus a
    /// deterministic spread over the whole bit space.
    #[test]
    fn f32_and_f64_symbolic_and_bounded_agree() {
        let mut f32_bits: Vec<u32> = vec![
            0x0000_0000,
            0x8000_0000,
            0x0000_0001,
            0x8000_0001,
            0x007f_ffff,
            0x0080_0000,
            0x3380_0000,
            0x3880_0000,
            0x477f_e000,
            0x477f_f000,
            0x4780_0000,
            0x4f80_0000,
            0x4f7f_ffff,
            0x5f80_0000,
            0xdf80_0000,
            0x7f7f_ffff,
            0xff7f_ffff,
            0x7f80_0000,
            0xff80_0000,
            0x7fc0_0000,
            0xffc0_0000,
            0x7f80_0001,
            0x7fff_ffff,
        ];
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        for _ in 0..200_000 {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            f32_bits.push((state >> 32) as u32);
        }
        for bits in f32_bits {
            let value = f32::from_bits(bits);
            let expected = bounded_bytes(&value);
            assert_eq!(CBOR::from(value).to_cbor_data(), expected, "{bits:#010x}");
            assert_eq!(
                convert_f32(value).prepared().cbor_data(),
                expected,
                "{bits:#010x}"
            );
        }
        let mut f64_values: Vec<f64> = vec![
            0.0,
            -0.0,
            f64::MIN_POSITIVE,
            5e-324,
            -5e-324,
            1.1,
            -1.1,
            0.5,
            65504.0,
            65505.0,
            16777216.0,
            16777217.0,
            4294967295.0,
            4294967296.0,
            9007199254740991.0,
            9007199254740992.0,
            18446744073709549568.0,
            18446744073709551616.0,
            -18446744073709551616.0,
            -18446744073709555712.0,
            f64::MAX,
            f64::MIN,
            f64::INFINITY,
            f64::NEG_INFINITY,
            f64::NAN,
            f64::from_bits(0x7ff0_0000_0000_0001),
            f64::from_bits(0xfff8_0000_0000_0000),
        ];
        for _ in 0..200_000 {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            f64_values.push(f64::from_bits(state));
        }
        for value in f64_values {
            let expected = bounded_bytes(&value);
            assert_eq!(CBOR::from(value).to_cbor_data(), expected, "{value:e}");
            assert_eq!(
                convert_f64(value).prepared().cbor_data(),
                expected,
                "{value:e}"
            );
            assert_eq!(f64_cbor_data(value), expected, "{value:e}");
        }
    }

    /// Canonical bytes stated independently of either serializer.
    #[test]
    fn floats_have_their_canonical_bytes() {
        let fixtures: [(CBOR, &[u8]); 14] = [
            (f16::from_bits(0x0001).into(), &[0xf9, 0x00, 0x01]),
            (f64::INFINITY.into(), &[0xf9, 0x7c, 0x00]),
            (f64::NEG_INFINITY.into(), &[0xf9, 0xfc, 0x00]),
            (f64::NAN.into(), &[0xf9, 0x7e, 0x00]),
            (
                f64::from_bits(0xfff8_0000_0000_0001).into(),
                &[0xf9, 0x7e, 0x00],
            ),
            (0.0f64.into(), &[0x00]),
            ((-0.0f64).into(), &[0x00]),
            (1.5f64.into(), &[0xf9, 0x3e, 0x00]),
            (f32::MAX.into(), &[0xfa, 0x7f, 0x7f, 0xff, 0xff]),
            (
                1.1f64.into(),
                &[0xfb, 0x3f, 0xf1, 0x99, 0x99, 0x99, 0x99, 0x99, 0x9a],
            ),
            (
                18446744073709549568.0f64.into(),
                &[0x1b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xf8, 0x00],
            ),
            (
                18446744073709551616.0f64.into(),
                &[0xfa, 0x5f, 0x80, 0x00, 0x00],
            ),
            (
                (-18446744073709551616.0f64).into(),
                &[0xfa, 0xdf, 0x80, 0x00, 0x00],
            ),
            (4294967296.0f32.into(), &[0x1b, 0, 0, 0, 1, 0, 0, 0, 0]),
        ];
        for (cbor, expected) in fixtures {
            assert_eq!(cbor.to_cbor_data(), expected, "{cbor:?}");
            assert!(CBOR::try_from_data(expected).is_ok(), "{expected:02x?}");
        }
        // Source precision does not change the encoding of an equal value.
        assert_eq!(
            CBOR::from(4294967296.0f64).to_cbor_data(),
            [0x1b, 0, 0, 0, 1, 0, 0, 0, 0]
        );
        assert_eq!(Numeric::Float16(1).cbor_data(), [0xf9, 0x00, 0x01]);
    }

    /// Decoding a negative integer gives `-1 - n` exactly, or refuses.
    #[test]
    fn negative_integers_decode_to_their_value_or_refuse() {
        let minus_one = CBOR::from(-1i64);
        assert_eq!(f32::try_from(minus_one.clone()).ok(), Some(-1.0f32));
        assert_eq!(f64::try_from(minus_one.clone()).ok(), Some(-1.0f64));
        assert_eq!(f16::try_from(minus_one).ok(), Some(f16::from_f64(-1.0)));
        let exact: CBOR = CBORCase::Negative((1u64 << 53) - 1).into();
        assert_eq!(f64::try_from(exact).ok(), Some(-9007199254740992.0f64));
        let inexact: CBOR = CBORCase::Negative(1u64 << 53).into();
        assert!(matches!(
            f64::try_from(inexact.clone()),
            Err(Error::OutOfRange)
        ));
        assert!(matches!(f32::try_from(inexact), Err(Error::OutOfRange)));
        let wide: CBOR = CBORCase::Negative((1u64 << 40) - 1).into();
        assert_eq!(f32::try_from(wide).ok(), Some(-1099511627776.0f32));
        assert!(matches!(
            f16::try_from(CBOR::from(-70000i64)),
            Err(Error::OutOfRange)
        ));
    }
}
