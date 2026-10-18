import_stdlib!();

use super::CBORCase;
use crate::{CBOR, Error, Result};

/// `value` when it is within `min ..= max`, the range of the target type.
fn in_range(value: i128, min: i128, max: i128) -> Result<i128> {
    if value < min || value > max {
        return Err(Error::OutOfRange);
    }
    Ok(value)
}

macro_rules! impl_cbor {
    ($type:ty) => {
        impl From<$type> for CBOR {
            fn from(value: $type) -> Self {
                #[allow(unused_comparisons)]
                if value < 0 {
                    CBORCase::Negative((-1 - (value as i128)) as u64).into()
                } else {
                    CBORCase::Unsigned(value as u64).into()
                }
            }
        }

        /// An unsigned argument `n` is the integer `n`; a negative argument
        /// `n` is the integer `-1 - n`. Either is this type's value only
        /// within its range: an unsigned type refuses every negative
        /// integer.
        impl TryFrom<CBOR> for $type {
            type Error = Error;

            fn try_from(cbor: CBOR) -> Result<Self> {
                let value = match cbor.into_case() {
                    CBORCase::Unsigned(n) => n as i128,
                    CBORCase::Negative(n) => -1 - (n as i128),
                    _ => return Err(Error::WrongType),
                };
                in_range(value, <$type>::MIN as i128, <$type>::MAX as i128)
                    .map(|value| value as $type)
            }
        }
    };
}

impl_cbor!(u8);
impl_cbor!(u16);
impl_cbor!(u32);
impl_cbor!(u64);
impl_cbor!(usize);
impl_cbor!(i8);
impl_cbor!(i16);
impl_cbor!(i32);
impl_cbor!(i64);

#[cfg(test)]
mod tests {
    use super::*;

    /// Negative integers decode to their value in a signed type and are
    /// refused by every unsigned type, never wrapped.
    #[test]
    fn negative_integers_decode_by_value_or_refuse() {
        let minus_one = CBOR::from(-1i64);
        assert!(matches!(
            u8::try_from(minus_one.clone()),
            Err(Error::OutOfRange)
        ));
        assert!(matches!(
            u64::try_from(minus_one.clone()),
            Err(Error::OutOfRange)
        ));
        assert!(matches!(
            usize::try_from(minus_one.clone()),
            Err(Error::OutOfRange)
        ));
        assert_eq!(i8::try_from(minus_one).ok(), Some(-1));
        assert_eq!(i8::try_from(CBOR::from(-128i64)).ok(), Some(i8::MIN));
        assert!(matches!(
            i8::try_from(CBOR::from(-129i64)),
            Err(Error::OutOfRange)
        ));
        assert_eq!(i64::try_from(CBOR::from(i64::MIN)).ok(), Some(i64::MIN));
        let below: CBOR = CBORCase::Negative(i64::MAX as u64 + 1).into();
        assert!(matches!(i64::try_from(below), Err(Error::OutOfRange)));
        assert!(matches!(
            u8::try_from(CBOR::from(256u64)),
            Err(Error::OutOfRange)
        ));
        assert_eq!(u64::try_from(CBOR::from(u64::MAX)).ok(), Some(u64::MAX));
        assert!(matches!(
            i64::try_from(CBOR::from(u64::MAX)),
            Err(Error::OutOfRange)
        ));
    }
}
