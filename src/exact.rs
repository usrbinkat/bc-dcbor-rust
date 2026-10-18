//! This module is based on the Swift `exactly` initializers.
//! See <https://github.com/apple/swift-evolution/blob/main/proposals/0080-failable-numeric-initializers.md>
//! See <https://github.com/apple/swift/blob/main/stdlib/public/core/IntegerTypes.swift.gyb>
//!
//! To expand the `.gyb` file, run:
//! ```bash
//! $ git clone https://github.com/apple/swift.git
//! $ cd swift
//! $ python3 ./utils/gyb.py -DCMAKE_SIZEOF_VOID_P=8 --line-directive '' -o output_file.swift stdlib/public/core/IntegerTypes.swift.gyb
//! ```

use half::f16;

pub trait ExactFrom {
    /// Creates a target numeric value from the given `f64`, if it can be
    /// represented exactly.
    ///
    /// If the value passed as `source` is not representable exactly, the result
    /// is `None`. For example, converting 21.0 will succeed, but 21.5 will
    /// fail:
    ///
    ///    use exact::ExactFrom;
    ///    assert_eq!(i64::exact_from_f64(21.0), Some(21));
    ///    assert_eq!(i64::exact_from_f64(21.5), None);
    ///
    /// - Parameter source: The value to convert.
    fn exact_from_f64(source: f64) -> Option<Self>
    where
        Self: Sized;

    /// Creates a target numeric value from the given `u64`, if it can be
    /// represented exactly.
    ///
    /// If the value passed as `source` is not representable exactly, the result
    /// is `None`. For example, converting 21 to f64 will succeed, but
    /// 9223372036854775809 will fail:
    ///
    ///    use exact::ExactFrom;
    ///    assert_eq!(f64::exact_from_u64(21u64), Some(21.0));
    ///    assert_eq!(f64::exact_from_u64(u64::MAX), None); assert_eq!
    /// (f64::exact_from_u64(9223372036854775809u64), None);
    ///
    /// - Parameter source: The value to convert.
    fn exact_from_u64(source: u64) -> Option<Self>
    where
        Self: Sized;

    fn exact_from_u128(source: u128) -> Option<Self>
    where
        Self: Sized;

    fn exact_from_i128(source: i128) -> Option<Self>
    where
        Self: Sized;
}

/// Range is checked against exact powers of two before any float-to-integer
/// cast. The caller supplies its target's inclusive lower and exclusive upper
/// bounds, including the full unsigned 128-bit range.
fn integral_in_range(value: f64, lower: f64, upper: f64) -> bool {
    value.is_finite() && value >= lower && value < upper && value % 1.0 == 0.0
}

/// An integer is exact when no significant bits are discarded and its highest
/// set bit lies in the finite exponent range (LLVM APFloat's truncation rule).
/// At the maximum exponent, the precision check also excludes magnitudes above
/// the largest finite significand, so rounding to infinity cannot pass.
const fn fits_binary_float(magnitude: u128, precision: u32, max_exp: u32) -> bool {
    if magnitude == 0 {
        return true;
    }
    let bits = 128 - magnitude.leading_zeros();
    bits <= max_exp && bits - magnitude.trailing_zeros() <= precision
}

macro_rules! exact_int_target {
    ($($t:ty),* $(,)?) => {$(
        impl ExactFrom for $t {
            fn exact_from_f64(source: f64) -> Option<Self> {
                // MIN is zero or an exact negative power of two. MAX's
                // successor, formed in u128, is an exact positive power of two.
                let lower = <$t>::MIN as f64;
                let upper = if lower < 0.0 {
                    -lower
                } else {
                    // For u128 the successor cannot be formed as an integer.
                    // 2 * 2^127 is exactly 2^128 in f64.
                    ((<$t>::MAX as u128 / 2 + 1) as f64) * 2.0
                };
                if integral_in_range(source, lower, upper) {
                    Some(source as Self)
                } else {
                    None
                }
            }
            fn exact_from_u64(source: u64) -> Option<Self> {
                Self::try_from(source).ok()
            }
            fn exact_from_u128(source: u128) -> Option<Self> {
                Self::try_from(source).ok()
            }
            fn exact_from_i128(source: i128) -> Option<Self> {
                Self::try_from(source).ok()
            }
        }
    )*};
}

exact_int_target!(i16, i32, i64, i128, u16, u32, u64, u128);

macro_rules! exact_float_target {
    ($t:ty, $precision:expr, $max_exp:expr, $from_f64:expr) => {
        impl ExactFrom for $t {
            fn exact_from_f64(source: f64) -> Option<Self> {
                if source.is_nan() {
                    return Some(Self::NAN);
                }
                let narrowed: Self = ($from_f64)(source);
                if f64::from(narrowed) == source {
                    Some(narrowed)
                } else {
                    None
                }
            }
            fn exact_from_u64(source: u64) -> Option<Self> {
                Self::exact_from_u128(u128::from(source))
            }
            fn exact_from_u128(source: u128) -> Option<Self> {
                if !fits_binary_float(source, $precision, $max_exp) {
                    return None;
                }
                // Every admitted integer is also exact in the f64 intermediate:
                // its precision and exponent range cover all three targets.
                Some(($from_f64)(source as f64))
            }
            fn exact_from_i128(source: i128) -> Option<Self> {
                if !fits_binary_float(source.unsigned_abs(), $precision, $max_exp) {
                    return None;
                }
                Some(($from_f64)(source as f64))
            }
        }
    };
}

exact_float_target!(f16, 11, 16, f16::from_f64);
exact_float_target!(f32, 24, 128, |v: f64| v as f32);
exact_float_target!(f64, 53, 1024, |v: f64| v);

#[cfg(test)]
mod tests {
    use super::*;

    // Source types with no production caller widen exactly into the shared
    // implementation. Keep their behavioral coverage without production APIs.
    trait ExactSourceHelpers: ExactFrom + Sized {
        fn exact_from_f16(source: f16) -> Option<Self> {
            Self::exact_from_f64(source.to_f64())
        }

        fn exact_from_i64(source: i64) -> Option<Self> {
            Self::exact_from_i128(i128::from(source))
        }
    }
    impl<T: ExactFrom> ExactSourceHelpers for T {}

    fn exact_from_single<T: ExactFrom>(value: f32) -> Option<T> {
        T::exact_from_f64(f64::from(value))
    }

    #[test]
    fn integer_target_boundaries() {
        macro_rules! signed_bounds {
            ($($t:ty),*) => {$(
                let min = <$t>::MIN as f64;
                assert_eq!(<$t>::exact_from_f64(min), Some(<$t>::MIN));
                assert_eq!(<$t>::exact_from_f64(-min), None);
                assert_eq!(<$t>::exact_from_f64(f64::from_bits(min.to_bits() + 1)), None);
                assert_eq!(<$t>::exact_from_f64(-0.0), Some(0));
                assert_eq!(<$t>::exact_from_f64(f64::from_bits(1)), None);
            )*};
        }
        signed_bounds!(i16, i32, i64, i128);
        assert_eq!(i16::exact_from_f16(f16::from_f64(-32768.0)), Some(i16::MIN));
        assert_eq!(exact_from_single::<i128>(f32::MAX), None);
        assert_eq!(i128::exact_from_f64(f64::MAX), None);
        assert_eq!(i128::exact_from_f64(f64::MIN), None);
        assert_eq!(u128::exact_from_f64(f64::MAX), None);
        let two127 = 170141183460469231731687303715884105728.0f64;
        assert_eq!(u128::exact_from_f64(two127), Some(1u128 << 127));
        assert_eq!(u128::exact_from_f64(two127 * 1.5), Some(3u128 << 126));
        let two128 = two127 * 2.0;
        assert_eq!(u128::exact_from_f64(two128), None);
        assert_eq!(
            u128::exact_from_f64(f64::from_bits(two128.to_bits() - 1)),
            Some(u128::MAX - ((1u128 << 75) - 1))
        );
        assert_eq!(u128::exact_from_f64(-1.0), None);
        assert_eq!(u128::exact_from_f64(-0.0), Some(0));
    }

    #[test]
    fn integer_significand_and_exponent_boundaries() {
        assert_eq!(f32::exact_from_i128(1 << 40), Some(1099511627776.0));
        assert_eq!(
            f32::exact_from_u128(0xff_ffffu128 << 40),
            Some(18446742974197923840.0)
        );
        assert_eq!(f32::exact_from_u128(0x1ff_ffffu128 << 40), None);
        assert_eq!(f16::exact_from_u64(65504), Some(f16::MAX));
        assert_eq!(f16::exact_from_u64(65505), None);
        assert_eq!(f16::exact_from_u64(65536), None);
        // Every integer power of two in each target's finite exponent range.
        for exponent in 0..128 {
            let integer = 1u128 << exponent;
            let expected = f64::from_bits(((1023 + exponent) as u64) << 52);
            assert_eq!(f64::exact_from_u128(integer), Some(expected));
            assert_eq!(f32::exact_from_u128(integer), Some(expected as f32));
            if exponent >= 53 {
                assert_eq!(f64::exact_from_u128(integer + 1), None);
            }
            if exponent >= 24 {
                assert_eq!(f32::exact_from_u128(integer + 1), None);
            }
            if exponent < 16 {
                assert_eq!(f16::exact_from_u128(integer), Some(f16::from_f64(expected)));
            } else {
                assert_eq!(f16::exact_from_u128(integer), None);
            }
        }
    }

    #[test]
    fn text_exact_i16() {
        assert_eq!(i16::exact_from_f16(f16::from_f64(21.0)), Some(21));
        assert_eq!(i16::exact_from_f16(f16::from_f64(21.5)), None);
        assert_eq!(i16::exact_from_f16(f16::from_f64(f64::NAN)), None);
        assert_eq!(i16::exact_from_f16(f16::from_f64(f64::INFINITY)), None);
        assert_eq!(i16::exact_from_f16(f16::from_f64(f64::NEG_INFINITY)), None);

        assert_eq!(exact_from_single::<i16>(21.0f32), Some(21));
        assert_eq!(exact_from_single::<i16>(21.5f32), None);
        assert_eq!(exact_from_single::<i16>(f32::NAN), None);
        assert_eq!(exact_from_single::<i16>(f32::INFINITY), None);
        assert_eq!(exact_from_single::<i16>(f32::NEG_INFINITY), None);

        assert_eq!(i16::exact_from_f64(21.0), Some(21));
        assert_eq!(i16::exact_from_f64(21.5), None);
        assert_eq!(i16::exact_from_f64(f64::NAN), None);
        assert_eq!(i16::exact_from_f64(f64::INFINITY), None);
        assert_eq!(i16::exact_from_f64(f64::NEG_INFINITY), None);

        assert_eq!(i16::exact_from_u64(21u64), Some(21));
        assert_eq!(i16::exact_from_u64(u64::MAX), None);
        assert_eq!(i16::exact_from_u64(65536u64), None);

        assert_eq!(i16::exact_from_i64(21i64), Some(21));
        assert_eq!(i16::exact_from_i64(-21i64), Some(-21));
        assert_eq!(i16::exact_from_i64(i64::MAX), None);
        assert_eq!(i16::exact_from_i64(i64::MIN), None);
        assert_eq!(i16::exact_from_i64(-65536i64), None);

        assert_eq!(i16::exact_from_u128(21u128), Some(21));
        assert_eq!(i16::exact_from_u128(u128::MAX), None);
        assert_eq!(i16::exact_from_u128(65536u128), None);

        assert_eq!(i16::exact_from_i128(21i128), Some(21));
        assert_eq!(i16::exact_from_i128(-21i128), Some(-21));
        assert_eq!(i16::exact_from_i128(i128::MAX), None);
        assert_eq!(i16::exact_from_i128(i128::MIN), None);
        assert_eq!(i16::exact_from_i128(-65536i128), None);
    }

    #[test]
    fn test_exact_i32() {
        assert_eq!(i32::exact_from_f16(f16::from_f64(21.0)), Some(21));
        assert_eq!(i32::exact_from_f16(f16::from_f64(21.5)), None);
        assert_eq!(i32::exact_from_f16(f16::from_f64(f64::NAN)), None);
        assert_eq!(i32::exact_from_f16(f16::from_f64(f64::INFINITY)), None);
        assert_eq!(i32::exact_from_f16(f16::from_f64(f64::NEG_INFINITY)), None);

        assert_eq!(exact_from_single::<i32>(21.0f32), Some(21));
        assert_eq!(exact_from_single::<i32>(21.5f32), None);
        assert_eq!(exact_from_single::<i32>(f32::NAN), None);
        assert_eq!(exact_from_single::<i32>(f32::INFINITY), None);
        assert_eq!(exact_from_single::<i32>(f32::NEG_INFINITY), None);

        assert_eq!(i32::exact_from_f64(21.0), Some(21));
        assert_eq!(i32::exact_from_f64(21.5), None);
        assert_eq!(i32::exact_from_f64(f64::NAN), None);
        assert_eq!(i32::exact_from_f64(f64::INFINITY), None);
        assert_eq!(i32::exact_from_f64(f64::NEG_INFINITY), None);

        assert_eq!(i32::exact_from_u64(21u64), Some(21));
        assert_eq!(i32::exact_from_u64(u64::MAX), None);
        assert_eq!(i32::exact_from_u64(4294967296u64), None);

        assert_eq!(i32::exact_from_i64(21i64), Some(21));
        assert_eq!(i32::exact_from_i64(-21i64), Some(-21));
        assert_eq!(i32::exact_from_i64(i64::MAX), None);
        assert_eq!(i32::exact_from_i64(i64::MIN), None);
        assert_eq!(i32::exact_from_i64(-4294967296i64), None);

        assert_eq!(i32::exact_from_u128(21u128), Some(21));
        assert_eq!(i32::exact_from_u128(u128::MAX), None);
        assert_eq!(i32::exact_from_u128(4294967296u128), None);

        assert_eq!(i32::exact_from_i128(21i128), Some(21));
        assert_eq!(i32::exact_from_i128(-21i128), Some(-21));
        assert_eq!(i32::exact_from_i128(i128::MAX), None);
        assert_eq!(i32::exact_from_i128(i128::MIN), None);
        assert_eq!(i32::exact_from_i128(-4294967296i128), None);
    }

    #[test]
    fn test_exact_i64() {
        assert_eq!(i64::exact_from_f16(f16::from_f64(21.0)), Some(21));
        assert_eq!(i64::exact_from_f16(f16::from_f64(21.5)), None);
        assert_eq!(i64::exact_from_f16(f16::from_f64(f64::NAN)), None);
        assert_eq!(i64::exact_from_f16(f16::from_f64(f64::INFINITY)), None);
        assert_eq!(i64::exact_from_f16(f16::from_f64(f64::NEG_INFINITY)), None);

        assert_eq!(exact_from_single::<i64>(21.0f32), Some(21));
        assert_eq!(exact_from_single::<i64>(21.5f32), None);
        assert_eq!(exact_from_single::<i64>(f32::NAN), None);
        assert_eq!(exact_from_single::<i64>(f32::INFINITY), None);
        assert_eq!(exact_from_single::<i64>(f32::NEG_INFINITY), None);

        assert_eq!(i64::exact_from_f64(21.0), Some(21));
        assert_eq!(i64::exact_from_f64(21.5), None);
        assert_eq!(i64::exact_from_f64(f64::NAN), None);
        assert_eq!(i64::exact_from_f64(f64::INFINITY), None);
        assert_eq!(i64::exact_from_f64(f64::NEG_INFINITY), None);

        assert_eq!(i64::exact_from_u64(21u64), Some(21));
        assert_eq!(i64::exact_from_u64(u64::MAX), None);
        assert_eq!(i64::exact_from_u64(9223372036854775809u64), None);

        assert_eq!(i64::exact_from_i64(21i64), Some(21));
        assert_eq!(i64::exact_from_i64(-21i64), Some(-21));
        assert_eq!(i64::exact_from_i64(i64::MAX), Some(9223372036854775807));
        assert_eq!(i64::exact_from_i64(i64::MIN), Some(-9223372036854775808));

        assert_eq!(i64::exact_from_u128(21u128), Some(21));
        assert_eq!(i64::exact_from_u128(u128::MAX), None);
        assert_eq!(i64::exact_from_u128(9223372036854775809u128), None);

        assert_eq!(i64::exact_from_i128(21i128), Some(21));
        assert_eq!(i64::exact_from_i128(-21i128), Some(-21));
        assert_eq!(i64::exact_from_i128(i128::MAX), None);
        assert_eq!(i64::exact_from_i128(i128::MIN), None);
    }

    #[test]
    fn test_exact_i128() {
        assert_eq!(i128::exact_from_f16(f16::from_f64(21.0)), Some(21));
        assert_eq!(i128::exact_from_f16(f16::from_f64(21.5)), None);
        assert_eq!(i128::exact_from_f16(f16::from_f64(f64::NAN)), None);
        assert_eq!(i128::exact_from_f16(f16::from_f64(f64::INFINITY)), None);
        assert_eq!(i128::exact_from_f16(f16::from_f64(f64::NEG_INFINITY)), None);

        assert_eq!(exact_from_single::<i128>(21.0f32), Some(21));
        assert_eq!(exact_from_single::<i128>(21.5f32), None);
        assert_eq!(exact_from_single::<i128>(f32::NAN), None);
        assert_eq!(exact_from_single::<i128>(f32::INFINITY), None);
        assert_eq!(exact_from_single::<i128>(f32::NEG_INFINITY), None);

        assert_eq!(i128::exact_from_f64(21.0), Some(21));
        assert_eq!(i128::exact_from_f64(21.5), None);
        assert_eq!(i128::exact_from_f64(f64::NAN), None);
        assert_eq!(i128::exact_from_f64(f64::INFINITY), None);
        assert_eq!(i128::exact_from_f64(f64::NEG_INFINITY), None);

        assert_eq!(i128::exact_from_u64(21u64), Some(21));
        assert_eq!(i128::exact_from_u64(u64::MAX), Some(u64::MAX as i128));

        assert_eq!(i128::exact_from_i64(21i64), Some(21));
        assert_eq!(i128::exact_from_i64(-21i64), Some(-21));
        assert_eq!(i128::exact_from_i64(i64::MAX), Some(i64::MAX as i128));
        assert_eq!(i128::exact_from_i64(i64::MIN), Some(i64::MIN as i128));

        assert_eq!(i128::exact_from_u128(21u128), Some(21));
        assert_eq!(i128::exact_from_u128(u128::MAX), None);

        assert_eq!(i128::exact_from_i128(21i128), Some(21));
        assert_eq!(i128::exact_from_i128(-21i128), Some(-21));
        assert_eq!(i128::exact_from_i128(i128::MAX), Some(i128::MAX));
        assert_eq!(i128::exact_from_i128(i128::MIN), Some(i128::MIN));
    }

    #[test]
    fn test_exact_u16() {
        assert_eq!(u16::exact_from_f16(f16::from_f64(21.0)), Some(21));
        assert_eq!(u16::exact_from_f16(f16::from_f64(21.5)), None);
        assert_eq!(u16::exact_from_f16(f16::from_f64(f64::NAN)), None);
        assert_eq!(u16::exact_from_f16(f16::from_f64(f64::INFINITY)), None);
        assert_eq!(u16::exact_from_f16(f16::from_f64(f64::NEG_INFINITY)), None);

        assert_eq!(exact_from_single::<u16>(21.0f32), Some(21));
        assert_eq!(exact_from_single::<u16>(21.5f32), None);
        assert_eq!(exact_from_single::<u16>(f32::NAN), None);
        assert_eq!(exact_from_single::<u16>(f32::INFINITY), None);
        assert_eq!(exact_from_single::<u16>(f32::NEG_INFINITY), None);

        assert_eq!(u16::exact_from_f64(21.0), Some(21));
        assert_eq!(u16::exact_from_f64(21.5), None);
        assert_eq!(u16::exact_from_f64(f64::NAN), None);
        assert_eq!(u16::exact_from_f64(f64::INFINITY), None);
        assert_eq!(u16::exact_from_f64(f64::NEG_INFINITY), None);

        assert_eq!(u16::exact_from_u64(21u64), Some(21));
        assert_eq!(u16::exact_from_u64(u64::MAX), None);
        assert_eq!(u16::exact_from_u64(65536u64), None);

        assert_eq!(u16::exact_from_i64(21i64), Some(21));
        assert_eq!(u16::exact_from_i64(-21i64), None);
        assert_eq!(u16::exact_from_i64(i64::MAX), None);
        assert_eq!(u16::exact_from_i64(i64::MIN), None);
        assert_eq!(u16::exact_from_i64(-65536i64), None);

        assert_eq!(u16::exact_from_u128(21u128), Some(21));
        assert_eq!(u16::exact_from_u128(u128::MAX), None);
        assert_eq!(u16::exact_from_u128(65536u128), None);

        assert_eq!(u16::exact_from_i128(21i128), Some(21));
        assert_eq!(u16::exact_from_i128(-21i128), None);
        assert_eq!(u16::exact_from_i128(i128::MAX), None);
        assert_eq!(u16::exact_from_i128(i128::MIN), None);
        assert_eq!(u16::exact_from_i128(-65536i128), None);
    }

    #[test]
    fn test_exact_u32() {
        assert_eq!(u32::exact_from_f16(f16::from_f64(21.0)), Some(21));
        assert_eq!(u32::exact_from_f16(f16::from_f64(21.5)), None);
        assert_eq!(u32::exact_from_f16(f16::from_f64(f64::NAN)), None);
        assert_eq!(u32::exact_from_f16(f16::from_f64(f64::INFINITY)), None);
        assert_eq!(u32::exact_from_f16(f16::from_f64(f64::NEG_INFINITY)), None);

        assert_eq!(exact_from_single::<u32>(21.0f32), Some(21));
        assert_eq!(exact_from_single::<u32>(21.5f32), None);
        assert_eq!(exact_from_single::<u32>(f32::NAN), None);
        assert_eq!(exact_from_single::<u32>(f32::INFINITY), None);
        assert_eq!(exact_from_single::<u32>(f32::NEG_INFINITY), None);

        assert_eq!(u32::exact_from_f64(21.0), Some(21));
        assert_eq!(u32::exact_from_f64(21.5), None);
        assert_eq!(u32::exact_from_f64(f64::NAN), None);
        assert_eq!(u32::exact_from_f64(f64::INFINITY), None);
        assert_eq!(u32::exact_from_f64(f64::NEG_INFINITY), None);

        assert_eq!(u32::exact_from_u64(21u64), Some(21));
        assert_eq!(u32::exact_from_u64(u64::MAX), None);
        assert_eq!(u32::exact_from_u64(4294967296u64), None);

        assert_eq!(u32::exact_from_i64(21i64), Some(21));
        assert_eq!(u32::exact_from_i64(-21i64), None);
        assert_eq!(u32::exact_from_i64(i64::MAX), None);
        assert_eq!(u32::exact_from_i64(i64::MIN), None);
        assert_eq!(u32::exact_from_i64(-4294967296i64), None);

        assert_eq!(u32::exact_from_u128(21u128), Some(21));
        assert_eq!(u32::exact_from_u128(u128::MAX), None);
        assert_eq!(u32::exact_from_u128(4294967296u128), None);

        assert_eq!(u32::exact_from_i128(21i128), Some(21));
        assert_eq!(u32::exact_from_i128(-21i128), None);
        assert_eq!(u32::exact_from_i128(i128::MAX), None);
        assert_eq!(u32::exact_from_i128(i128::MIN), None);
        assert_eq!(u32::exact_from_i128(-4294967296i128), None);
    }

    #[test]
    fn test_exact_u64() {
        assert_eq!(u64::exact_from_f16(f16::from_f64(21.0)), Some(21));
        assert_eq!(u64::exact_from_f16(f16::from_f64(21.5)), None);
        assert_eq!(u64::exact_from_f16(f16::from_f64(f64::NAN)), None);
        assert_eq!(u64::exact_from_f16(f16::from_f64(f64::INFINITY)), None);
        assert_eq!(u64::exact_from_f16(f16::from_f64(f64::NEG_INFINITY)), None);

        assert_eq!(exact_from_single::<u64>(21.0f32), Some(21));
        assert_eq!(exact_from_single::<u64>(21.5f32), None);
        assert_eq!(exact_from_single::<u64>(f32::NAN), None);
        assert_eq!(exact_from_single::<u64>(f32::INFINITY), None);
        assert_eq!(exact_from_single::<u64>(f32::NEG_INFINITY), None);

        assert_eq!(u64::exact_from_f64(21.0), Some(21));
        assert_eq!(u64::exact_from_f64(21.5), None);
        assert_eq!(u64::exact_from_f64(f64::NAN), None);
        assert_eq!(u64::exact_from_f64(f64::INFINITY), None);
        assert_eq!(u64::exact_from_f64(f64::NEG_INFINITY), None);

        assert_eq!(u64::exact_from_u64(21u64), Some(21));
        assert_eq!(u64::exact_from_u64(u64::MAX), Some(18446744073709551615));

        assert_eq!(u64::exact_from_i64(21i64), Some(21));
        assert_eq!(u64::exact_from_i64(-21i64), None);
        assert_eq!(u64::exact_from_i64(i64::MAX), Some(9223372036854775807));
        assert_eq!(u64::exact_from_i64(i64::MIN), None);

        assert_eq!(u64::exact_from_u128(21u128), Some(21));
        assert_eq!(u64::exact_from_u128(u128::MAX), None);

        assert_eq!(u64::exact_from_i128(21i128), Some(21));
        assert_eq!(u64::exact_from_i128(-21i128), None);
        assert_eq!(u64::exact_from_i128(i128::MAX), None);
        assert_eq!(u64::exact_from_i128(i128::MIN), None);
    }

    #[test]
    fn test_exact_u128() {
        assert_eq!(u128::exact_from_f16(f16::from_f64(21.0)), Some(21));
        assert_eq!(u128::exact_from_f16(f16::from_f64(21.5)), None);
        assert_eq!(u128::exact_from_f16(f16::from_f64(f64::NAN)), None);
        assert_eq!(u128::exact_from_f16(f16::from_f64(f64::INFINITY)), None);
        assert_eq!(u128::exact_from_f16(f16::from_f64(f64::NEG_INFINITY)), None);

        assert_eq!(exact_from_single::<u128>(21.0f32), Some(21));
        assert_eq!(exact_from_single::<u128>(21.5f32), None);
        assert_eq!(exact_from_single::<u128>(f32::NAN), None);
        assert_eq!(exact_from_single::<u128>(f32::INFINITY), None);
        assert_eq!(exact_from_single::<u128>(f32::NEG_INFINITY), None);

        assert_eq!(u128::exact_from_f64(21.0), Some(21));
        assert_eq!(u128::exact_from_f64(21.5), None);
        assert_eq!(u128::exact_from_f64(f64::NAN), None);
        assert_eq!(u128::exact_from_f64(f64::INFINITY), None);
        assert_eq!(u128::exact_from_f64(f64::NEG_INFINITY), None);

        assert_eq!(u128::exact_from_u64(21u64), Some(21));
        assert_eq!(u128::exact_from_u64(u64::MAX), Some(u64::MAX as u128));

        assert_eq!(u128::exact_from_i64(21i64), Some(21));
        assert_eq!(u128::exact_from_i64(-21i64), None);
        assert_eq!(u128::exact_from_i64(i64::MAX), Some(i64::MAX as u128));
        assert_eq!(u128::exact_from_i64(i64::MIN), None);

        assert_eq!(u128::exact_from_u128(21u128), Some(21));
        assert_eq!(u128::exact_from_u128(u128::MAX), Some(u128::MAX));

        assert_eq!(u128::exact_from_i128(21i128), Some(21));
        assert_eq!(u128::exact_from_i128(-21i128), None);
        assert_eq!(u128::exact_from_i128(i128::MAX), Some(i128::MAX as u128));
        assert_eq!(u128::exact_from_i128(i128::MIN), None);
    }

    #[test]
    fn test_exact_f16() {
        assert_eq!(
            f16::exact_from_f16(f16::from_f64(21.0)),
            Some(f16::from_f64(21.0))
        );
        assert_eq!(
            f16::exact_from_f16(f16::from_f64(21.5)),
            Some(f16::from_f64(21.5))
        );
        assert!(f16::exact_from_f16(f16::NAN).unwrap().is_nan());
        assert_eq!(f16::exact_from_f16(f16::INFINITY), Some(f16::INFINITY));
        assert_eq!(
            f16::exact_from_f16(f16::NEG_INFINITY),
            Some(f16::NEG_INFINITY)
        );

        assert_eq!(exact_from_single::<f16>(21.0f32), Some(f16::from_f64(21.0)));
        assert_eq!(exact_from_single::<f16>(21.5f32), Some(f16::from_f64(21.5)));
        assert!(exact_from_single::<f16>(f32::NAN).unwrap().is_nan());
        assert_eq!(exact_from_single::<f16>(f32::INFINITY), Some(f16::INFINITY));
        assert_eq!(
            exact_from_single::<f16>(f32::NEG_INFINITY),
            Some(f16::NEG_INFINITY)
        );

        assert_eq!(f16::exact_from_f64(21.0), Some(f16::from_f64(21.0)));
        assert_eq!(f16::exact_from_f64(21.5), Some(f16::from_f64(21.5)));
        assert!(f16::exact_from_f64(f64::NAN).unwrap().is_nan());
        assert_eq!(
            f16::exact_from_f64(f64::INFINITY),
            Some(f16::from_f64(f64::INFINITY))
        );
        assert_eq!(
            f16::exact_from_f64(f64::NEG_INFINITY),
            Some(f16::from_f64(f64::NEG_INFINITY))
        );

        assert_eq!(f16::exact_from_u64(21u64), Some(f16::from_f64(21.0)));
        assert_eq!(f16::exact_from_u64(u64::MAX), None);
        assert_eq!(f16::exact_from_u64(65536u64), None);

        assert_eq!(f16::exact_from_i64(21i64), Some(f16::from_f64(21.0)));
        assert_eq!(f16::exact_from_i64(-21i64), Some(f16::from_f64(-21.0)));
        assert_eq!(f16::exact_from_i64(i64::MAX), None);
        assert_eq!(f16::exact_from_i64(i64::MIN), None);
        assert_eq!(f16::exact_from_i64(-65536i64), None);

        assert_eq!(f16::exact_from_u128(21u128), Some(f16::from_f64(21.0)));
        assert_eq!(f16::exact_from_u128(u128::MAX), None);
        assert_eq!(f16::exact_from_u128(65536u128), None);

        assert_eq!(f16::exact_from_i128(21i128), Some(f16::from_f64(21.0)));
        assert_eq!(f16::exact_from_i128(-21i128), Some(f16::from_f64(-21.0)));
        assert_eq!(f16::exact_from_i128(i128::MAX), None);
        assert_eq!(f16::exact_from_i128(i128::MIN), None);
        assert_eq!(f16::exact_from_i128(-65536i128), None);
    }

    #[test]
    fn test_exact_f32() {
        assert_eq!(f32::exact_from_f16(f16::from_f64(21.0)), Some(21.0f32));
        assert_eq!(f32::exact_from_f16(f16::from_f64(21.5)), Some(21.5f32));
        assert!(f32::exact_from_f16(f16::NAN).unwrap().is_nan());
        assert_eq!(f32::exact_from_f16(f16::INFINITY), Some(f32::INFINITY));
        assert_eq!(
            f32::exact_from_f16(f16::NEG_INFINITY),
            Some(f32::NEG_INFINITY)
        );

        assert_eq!(exact_from_single::<f32>(21.0f32), Some(21.0f32));
        assert_eq!(exact_from_single::<f32>(21.5f32), Some(21.5f32));
        assert!(exact_from_single::<f32>(f32::NAN).unwrap().is_nan());
        assert_eq!(exact_from_single::<f32>(f32::INFINITY), Some(f32::INFINITY));
        assert_eq!(
            exact_from_single::<f32>(f32::NEG_INFINITY),
            Some(f32::NEG_INFINITY)
        );

        assert_eq!(f32::exact_from_f64(21.0), Some(21.0f32));
        assert_eq!(f32::exact_from_f64(21.5), Some(21.5f32));
        assert!(f32::exact_from_f64(f64::NAN).unwrap().is_nan());
        assert_eq!(f32::exact_from_f64(f64::INFINITY), Some(f32::INFINITY));
        assert_eq!(
            f32::exact_from_f64(f64::NEG_INFINITY),
            Some(f32::NEG_INFINITY)
        );

        assert_eq!(f32::exact_from_u64(21u64), Some(21.0f32));
        assert_eq!(f32::exact_from_u64(u64::MAX), None);
        assert_eq!(f32::exact_from_u64(1 << 63), Some(9223372036854775808.0));
        assert_eq!(f32::exact_from_u64(9223372036854775809u64), None);

        assert_eq!(f32::exact_from_i64(21i64), Some(21.0f32));
        assert_eq!(f32::exact_from_i64(-21i64), Some(-21.0f32));
        assert_eq!(f32::exact_from_i64(i64::MAX), None);
        assert_eq!(
            f32::exact_from_i64(i64::MIN),
            Some(-9223372036854775808.0f32)
        );
        assert_eq!(f32::exact_from_i64(-9223372036854775807i64), None);

        assert_eq!(f32::exact_from_u128(21u128), Some(21.0f32));
        assert_eq!(f32::exact_from_u128(u128::MAX), None);
        assert_eq!(f32::exact_from_u128(9223372036854775809u128), None);

        assert_eq!(f32::exact_from_i128(21i128), Some(21.0f32));
        assert_eq!(f32::exact_from_i128(-21i128), Some(-21.0f32));
        assert_eq!(f32::exact_from_i128(i128::MAX), None);
        assert_eq!(f32::exact_from_i128(i128::MIN), Some(-1.7014118e38));
        assert_eq!(f32::exact_from_i128(-9223372036854775807i128), None);
    }

    #[test]
    fn test_exact_f64() {
        assert_eq!(f64::exact_from_f16(f16::from_f64(21.0)), Some(21.0));
        assert_eq!(f64::exact_from_f16(f16::from_f64(21.5)), Some(21.5));
        assert!(f64::exact_from_f16(f16::NAN).unwrap().is_nan());
        assert_eq!(f64::exact_from_f16(f16::INFINITY), Some(f64::INFINITY));
        assert_eq!(
            f64::exact_from_f16(f16::NEG_INFINITY),
            Some(f64::NEG_INFINITY)
        );

        assert_eq!(exact_from_single::<f64>(21.0f32), Some(21.0));
        assert_eq!(exact_from_single::<f64>(21.5f32), Some(21.5));
        assert!(exact_from_single::<f64>(f32::NAN).unwrap().is_nan());
        assert_eq!(exact_from_single::<f64>(f32::INFINITY), Some(f64::INFINITY));
        assert_eq!(
            exact_from_single::<f64>(f32::NEG_INFINITY),
            Some(f64::NEG_INFINITY)
        );

        assert_eq!(f64::exact_from_f64(21.0), Some(21.0));
        assert_eq!(f64::exact_from_f64(21.5), Some(21.5));
        assert!(f64::exact_from_f64(f64::NAN).unwrap().is_nan());
        assert_eq!(f64::exact_from_f64(f64::INFINITY), Some(f64::INFINITY));
        assert_eq!(
            f64::exact_from_f64(f64::NEG_INFINITY),
            Some(f64::NEG_INFINITY)
        );

        assert_eq!(f64::exact_from_u64(21u64), Some(21.0));
        assert_eq!(f64::exact_from_u64(u64::MAX), None);
        assert_eq!(
            f64::exact_from_u64(u64::MAX - 2047),
            Some(18446744073709549568.0)
        );
        assert_eq!(f64::exact_from_u64(9223372036854775809u64), None);

        assert_eq!(f64::exact_from_i64(21i64), Some(21.0));
        assert_eq!(f64::exact_from_i64(-21i64), Some(-21.0));
        assert_eq!(f64::exact_from_i64(i64::MAX), None);
        assert_eq!(f64::exact_from_i64(i64::MIN), Some(-9223372036854775808.0));
        assert_eq!(f64::exact_from_i64(-9223372036854775807i64), None);

        assert_eq!(f64::exact_from_u128(21u128), Some(21.0));
        assert_eq!(f64::exact_from_u128(u128::MAX), None);
        assert_eq!(
            f64::exact_from_u128(1 << 100),
            Some(1267650600228229401496703205376.0)
        );
        assert_eq!(f64::exact_from_u128(9223372036854775809u128), None);

        assert_eq!(f64::exact_from_i128(21i128), Some(21.0));
        assert_eq!(f64::exact_from_i128(-21i128), Some(-21.0));
        assert_eq!(f64::exact_from_i128(i128::MAX), None);
        assert_eq!(
            f64::exact_from_i128(i128::MIN),
            Some(-170141183460469231731687303715884105728.0)
        );
        assert_eq!(f64::exact_from_i128(-9223372036854775807i128), None);
    }

    #[test]
    fn test_exact_u64_from_f64() {
        fn test_value(n: f64, i: Option<u64>) {
            assert_eq!(u64::exact_from_f64(n), i);
        }

        test_value(1234.0, Some(1234));
        test_value(-1234.0, None);
        test_value(18446744073709550000.0, Some(18446744073709549568));
        test_value(18446744073709552000.0, None);
        test_value(0.0, Some(0));
        test_value(-0.0, Some(0));
        test_value(0.5, None);
        test_value(-0.5, None);
        test_value(f64::NAN, None);
        test_value(f64::INFINITY, None);
        test_value(f64::NEG_INFINITY, None);

        // Largest and smallest positive integers exactly representable in f64
        test_value(9007199254740991.0, Some(9007199254740991)); // 2^53 - 1
        test_value(1.0, Some(1));

        // Subnormal numbers
        test_value(5e-324, None); // Smallest positive subnormal f64 number

        // Boundary conditions
        test_value(u64::MAX as f64, None); // Largest u64 as f64 - cannot be exactly converted back
        test_value((u64::MAX - 1) as f64, None); // Close to u64::MAX, precision loss expected
        test_value((u64::MAX - 2) as f64, None); // Close to u64::MAX, precision loss expected

        // Precision limits
        test_value(1.0000000000000002, None); // 1 + smallest increment > 1 in f64
        test_value(4503599627370495.5, None); // 2^52 - 0.5

        // Special floating-point values
        test_value(f64::MIN_POSITIVE, None); // Smallest positive normal f64 number FAILING
        test_value(f64::MAX, None); // Largest positive f64 number
    }

    #[test]
    fn test_exact_i64_from_f64_exact() {
        fn test_value(n: f64, i: Option<i64>) {
            assert_eq!(i64::exact_from_f64(n), i);
        }

        test_value(0.0, Some(0));
        test_value(-0.0, Some(0));
        test_value(0.5, None);
        test_value(-0.5, None);
        test_value(1234.0, Some(1234));
        test_value(-1234.0, Some(-1234));
        test_value(f64::NAN, None);
        test_value(f64::INFINITY, None);
        test_value(f64::NEG_INFINITY, None);

        // Max and Min i64 values
        test_value(i64::MAX as f64, None);
        test_value(i64::MIN as f64, Some(i64::MIN));

        // Subnormal numbers
        test_value(1e-308, None); // A typical subnormal number
        test_value(-1e-308, None);

        // Boundary values
        test_value((i64::MAX as f64) + 1.0, None);
        test_value((i64::MIN as f64) - 2048.0, None);

        // Power of two
        test_value(1024.0, Some(1024));
        test_value(-1024.0, Some(-1024));

        // Non-integer floating points
        test_value(1234.56, None);
        test_value(-1234.56, None);

        // Large integers
        test_value(9007199254740991.0, Some(9007199254740991)); // Largest exact integer in f64
        test_value(-9007199254740991.0, Some(-9007199254740991));

        test_value(-9223372036854774784.0, Some(-9223372036854774784)); // Most negative double that converts to int64.
    }
}
