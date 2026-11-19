//! CBOR bignum (tags 2 and 3) support for `num-bigint` types.
//!
//! This module provides conversion between [`CBOR`] and the `num-bigint`
//! crate's [`BigInt`] and [`BigUint`] types, implementing RFC 8949 §3.4.3
//! (Bignums) with dCBOR/CDE canonical encoding rules.
//!
//! # Encoding
//!
//! - [`BigUint`] always encodes as tag 2 (positive bignum) with a byte string
//!   content.
//! - [`BigInt`] encodes as tag 2 for non-negative values or tag 3 (negative
//!   bignum) for negative values.
//! - No numeric reduction is performed: values are always encoded as bignums,
//!   even if they would fit in normal CBOR integers.
//!
//! # Decoding
//!
//! - Accepts CBOR integers (major types 0 and 1) and converts them to bignums.
//! - Accepts tag 2 (positive bignum) and tag 3 (negative bignum) with byte
//!   string content.
//! - Enforces shortest-form canonical representation for bignum magnitudes.
//! - Rejects floating-point values.
//!
//! # Examples
//!
//! ```
//! use dcbor::prelude::*;
//! use num_bigint::{BigInt, BigUint};
//!
//! // Encode a BigUint
//! let big = BigUint::from(256u32);
//! let cbor = CBOR::from(big.clone());
//! assert_eq!(cbor.diagnostic(), "2(h'0100')");
//!
//! // Decode back to BigUint
//! let decoded: BigUint = cbor.try_into().unwrap();
//! assert_eq!(decoded, big);
//!
//! // Encode a negative BigInt
//! let neg = BigInt::from(-1);
//! let cbor = CBOR::from(neg.clone());
//! assert_eq!(cbor.diagnostic(), "3(h'00')");
//!
//! // Decode back to BigInt
//! let decoded: BigInt = cbor.try_into().unwrap();
//! assert_eq!(decoded, neg);
//! ```

import_stdlib!();

pub use num_bigint::{BigInt, BigUint, Sign};

use crate::minimal_bigint::{bignum_tag, drop_leading_zeros};
use crate::{ByteString, CBOR, CBORCase, Error, Result, TAG_NEGATIVE_BIGNUM, TAG_POSITIVE_BIGNUM};

/// Validates that a bignum magnitude byte string is in shortest canonical form.
///
/// Rules:
/// - For positive bignums (tag 2): empty byte string represents zero; non-empty
///   must not have leading zero bytes.
/// - For negative bignums (tag 3): byte string must not be empty (magnitude
///   zero is encoded as `0x00`); must not have leading zero bytes except when
///   the magnitude is zero (single `0x00`).
fn validate_bignum_magnitude(bytes: &[u8], is_negative: bool) -> Result<()> {
    if is_negative {
        // Tag 3: byte string must not be empty
        if bytes.is_empty() {
            return Err(Error::NonCanonicalNumeric);
        }
        // No leading zeros unless the entire magnitude is zero (single 0x00
        // byte)
        if bytes.len() > 1 && bytes[0] == 0 {
            return Err(Error::NonCanonicalNumeric);
        }
    } else {
        // Tag 2: empty byte string is valid (represents zero)
        // Non-empty must not have leading zeros
        if !bytes.is_empty() && bytes[0] == 0 {
            return Err(Error::NonCanonicalNumeric);
        }
    }
    Ok(())
}

/// The bignum of the argument whose big-endian bytes `to_bytes_be` returned:
/// tag 2, or tag 3 when `negative`, around those bytes with their leading
/// zeros drained in place, the vector then moved into the byte string,
/// never copied. A positive zero is the empty byte string; a negative
/// argument of zero (the value -1) is `00`, as the decoder's canonical form
/// requires ([`validate_bignum_magnitude`]). The one definition every
/// bignum conversion uses.
fn bignum(negative: bool, mut bytes: Vec<u8>) -> CBOR {
    drop_leading_zeros(&mut bytes);
    if negative && bytes.is_empty() {
        bytes.push(0);
    }
    CBOR::to_tagged_value(
        bignum_tag(negative),
        CBORCase::ByteString(ByteString::from(bytes)),
    )
}

/// Tag 2 around the magnitude: always a bignum, whatever its size; zero is
/// the empty byte string. Reads the borrow: the integer is never cloned.
impl From<&BigUint> for CBOR {
    fn from(value: &BigUint) -> Self {
        bignum(false, value.to_bytes_be())
    }
}

/// As the borrowed conversion, which reads the integer in place.
impl From<BigUint> for CBOR {
    fn from(value: BigUint) -> Self {
        CBOR::from(&value)
    }
}

/// Tag 2 for a non-negative value; tag 3 for a negative one, around the
/// argument `|value| - 1` (RFC 8949 §3.4.3). Reads the borrow: a
/// non-negative value's magnitude is read in place, and a negative value's
/// argument is the one integer computed.
impl From<&BigInt> for CBOR {
    fn from(value: &BigInt) -> Self {
        match value.sign() {
            Sign::Minus => bignum(true, (value.magnitude() - 1u32).to_bytes_be()),
            Sign::NoSign | Sign::Plus => CBOR::from(value.magnitude()),
        }
    }
}

/// As the borrowed conversion; a negative value's magnitude is consumed by
/// the subtraction rather than read.
impl From<BigInt> for CBOR {
    fn from(value: BigInt) -> Self {
        match value.into_parts() {
            (Sign::Minus, magnitude) => bignum(true, (magnitude - 1u32).to_bytes_be()),
            (Sign::NoSign | Sign::Plus, magnitude) => CBOR::from(&magnitude),
        }
    }
}

/// Decodes a [`BigUint`] from an untagged CBOR byte string.
///
/// This function is intended for use in tag summarizers where the tag has
/// already been stripped. It expects a CBOR byte string representing the
/// big-endian magnitude of a positive bignum (tag 2 content).
///
/// Enforces canonical encoding: no leading zero bytes (except empty for zero).
pub fn biguint_from_untagged_cbor(cbor: CBOR) -> Result<BigUint> {
    let bytes = cbor.try_into_byte_string()?;
    validate_bignum_magnitude(&bytes, false)?;
    Ok(BigUint::from_bytes_be(&bytes))
}

/// Decodes a [`BigInt`] from an untagged CBOR byte string for a negative
/// bignum.
///
/// This function is intended for use in tag summarizers where the tag has
/// already been stripped. It expects a CBOR byte string representing `n` where
/// the actual value is `-1 - n` (tag 3 content per RFC 8949).
///
/// Enforces canonical encoding: no leading zero bytes (except single `0x00`
/// for -1).
pub fn bigint_from_negative_untagged_cbor(cbor: CBOR) -> Result<BigInt> {
    let bytes = cbor.try_into_byte_string()?;
    validate_bignum_magnitude(&bytes, true)?;
    let n = BigUint::from_bytes_be(&bytes);
    let magnitude = n + 1u32;
    Ok(BigInt::from_biguint(Sign::Minus, magnitude))
}

impl TryFrom<CBOR> for BigUint {
    type Error = Error;

    /// Converts CBOR to a [`BigUint`].
    ///
    /// Accepts:
    /// - Major type 0 (unsigned integer)
    /// - Tag 2 (positive bignum) with canonical byte string
    ///
    /// Rejects:
    /// - Major type 1 (negative integer)
    /// - Tag 3 (negative bignum)
    /// - Floating-point values
    /// - Non-canonical bignum encodings
    fn try_from(cbor: CBOR) -> Result<Self> {
        match cbor.into_case() {
            CBORCase::Unsigned(n) => Ok(BigUint::from(n)),
            CBORCase::Negative(_) => Err(Error::OutOfRange),
            CBORCase::Tagged(tag, inner) => {
                let tag_value = tag.value();
                if tag_value == TAG_POSITIVE_BIGNUM {
                    // Tag 2: positive bignum
                    let bytes = inner.try_into_byte_string()?;
                    validate_bignum_magnitude(&bytes, false)?;
                    Ok(BigUint::from_bytes_be(&bytes))
                } else if tag_value == TAG_NEGATIVE_BIGNUM {
                    // Tag 3: negative bignum - not allowed for BigUint
                    Err(Error::OutOfRange)
                } else {
                    Err(Error::WrongType)
                }
            }
            CBORCase::Simple(_) => {
                // This covers floats (Simple::Float) - reject them
                Err(Error::WrongType)
            }
            _ => Err(Error::WrongType),
        }
    }
}

impl TryFrom<CBOR> for BigInt {
    type Error = Error;

    /// Converts CBOR to a [`BigInt`].
    ///
    /// Accepts:
    /// - Major type 0 (unsigned integer)
    /// - Major type 1 (negative integer)
    /// - Tag 2 (positive bignum) with canonical byte string
    /// - Tag 3 (negative bignum) with canonical byte string
    ///
    /// Rejects:
    /// - Floating-point values
    /// - Non-canonical bignum encodings
    fn try_from(cbor: CBOR) -> Result<Self> {
        match cbor.into_case() {
            CBORCase::Unsigned(n) => Ok(BigInt::from(n)),
            CBORCase::Negative(n) => {
                // CBOR negative: value = -1 - n
                // n is the raw u64 from the encoding
                let magnitude = BigUint::from(n) + 1u32;
                Ok(BigInt::from_biguint(Sign::Minus, magnitude))
            }
            CBORCase::Tagged(tag, inner) => {
                let tag_value = tag.value();
                if tag_value == TAG_POSITIVE_BIGNUM {
                    // Tag 2: positive bignum
                    let bytes = inner.try_into_byte_string()?;
                    validate_bignum_magnitude(&bytes, false)?;
                    let magnitude = BigUint::from_bytes_be(&bytes);
                    if magnitude == BigUint::ZERO {
                        Ok(BigInt::from(0))
                    } else {
                        Ok(BigInt::from_biguint(Sign::Plus, magnitude))
                    }
                } else if tag_value == TAG_NEGATIVE_BIGNUM {
                    // Tag 3: negative bignum, value = -1 - n
                    let bytes = inner.try_into_byte_string()?;
                    validate_bignum_magnitude(&bytes, true)?;
                    let n = BigUint::from_bytes_be(&bytes);
                    let magnitude = n + 1u32;
                    Ok(BigInt::from_biguint(Sign::Minus, magnitude))
                } else {
                    Err(Error::WrongType)
                }
            }
            CBORCase::Simple(_) => {
                // This covers floats (Simple::Float) - reject them
                Err(Error::WrongType)
            }
            _ => Err(Error::WrongType),
        }
    }
}

// A `MinimalBigInt` and num-bigint's integers convert at the symbolic edge,
// outside any policy: a magnitude's bytes are a vector `to_bytes_be`
// allocates, moved into the result without a second copy (num-bigint keeps
// zero and one inline, `BigDigits::Inline`, but its byte form is still a
// vector). Every integer has exactly one minimal form, so each conversion is
// total.

impl From<&BigUint> for crate::MinimalBigInt {
    /// The magnitude's big-endian bytes, its leading zeros dropped: the
    /// argument `n` of a non-negative value is the value.
    fn from(value: &BigUint) -> Self {
        crate::MinimalBigInt::from_vec(false, value.to_bytes_be())
    }
}

impl From<&BigInt> for crate::MinimalBigInt {
    /// A non-negative value as [`BigUint`]'s; a negative value `v` as the
    /// argument `n = -1 - v`, its bytes without leading zeros.
    fn from(value: &BigInt) -> Self {
        match value.sign() {
            Sign::Minus => {
                let n = value.magnitude() - 1u32;
                crate::MinimalBigInt::from_vec(true, n.to_bytes_be())
            }
            Sign::NoSign | Sign::Plus => Self::from(value.magnitude()),
        }
    }
}

impl From<&crate::MinimalBigInt> for BigInt {
    /// `n` when non-negative, `-1 - n` when negative.
    fn from(value: &crate::MinimalBigInt) -> Self {
        let (negative, magnitude) = value.as_parts();
        let n = BigUint::from_bytes_be(magnitude);
        if negative {
            BigInt::from_biguint(Sign::Minus, n + 1u32)
        } else {
            BigInt::from_biguint(Sign::Plus, n)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_biguint_zero() {
        let big = BigUint::from(0u32);
        let cbor = CBOR::from(big.clone());
        assert_eq!(cbor.diagnostic(), "2(h'')");
        let decoded: BigUint = cbor.try_into().unwrap();
        assert_eq!(decoded, big);
    }

    #[test]
    fn test_biguint_one() {
        let big = BigUint::from(1u32);
        let cbor = CBOR::from(big.clone());
        assert_eq!(cbor.diagnostic(), "2(h'01')");
        let decoded: BigUint = cbor.try_into().unwrap();
        assert_eq!(decoded, big);
    }

    #[test]
    fn test_biguint_255() {
        let big = BigUint::from(255u32);
        let cbor = CBOR::from(big.clone());
        assert_eq!(cbor.diagnostic(), "2(h'ff')");
        let decoded: BigUint = cbor.try_into().unwrap();
        assert_eq!(decoded, big);
    }

    #[test]
    fn test_biguint_256() {
        let big = BigUint::from(256u32);
        let cbor = CBOR::from(big.clone());
        assert_eq!(cbor.diagnostic(), "2(h'0100')");
        let decoded: BigUint = cbor.try_into().unwrap();
        assert_eq!(decoded, big);
    }

    #[test]
    fn test_bigint_zero() {
        let big = BigInt::from(0);
        let cbor = CBOR::from(big.clone());
        assert_eq!(cbor.diagnostic(), "2(h'')");
        let decoded: BigInt = cbor.try_into().unwrap();
        assert_eq!(decoded, big);
    }

    #[test]
    fn test_bigint_positive() {
        let big = BigInt::from(256);
        let cbor = CBOR::from(big.clone());
        assert_eq!(cbor.diagnostic(), "2(h'0100')");
        let decoded: BigInt = cbor.try_into().unwrap();
        assert_eq!(decoded, big);
    }

    #[test]
    fn test_bigint_negative_one() {
        let big = BigInt::from(-1);
        let cbor = CBOR::from(big.clone());
        // -1 -> magnitude = 1, n = 0 -> 0x00
        assert_eq!(cbor.diagnostic(), "3(h'00')");
        let decoded: BigInt = cbor.try_into().unwrap();
        assert_eq!(decoded, big);
    }

    #[test]
    fn test_bigint_negative_two() {
        let big = BigInt::from(-2);
        let cbor = CBOR::from(big.clone());
        // -2 -> magnitude = 2, n = 1 -> 0x01
        assert_eq!(cbor.diagnostic(), "3(h'01')");
        let decoded: BigInt = cbor.try_into().unwrap();
        assert_eq!(decoded, big);
    }

    #[test]
    fn test_bigint_negative_256() {
        let big = BigInt::from(-256);
        let cbor = CBOR::from(big.clone());
        // -256 -> magnitude = 256, n = 255 -> 0xff
        assert_eq!(cbor.diagnostic(), "3(h'ff')");
        let decoded: BigInt = cbor.try_into().unwrap();
        assert_eq!(decoded, big);
    }

    #[test]
    fn test_bigint_negative_257() {
        let big = BigInt::from(-257);
        let cbor = CBOR::from(big.clone());
        // -257 -> magnitude = 257, n = 256 -> 0x0100
        assert_eq!(cbor.diagnostic(), "3(h'0100')");
        let decoded: BigInt = cbor.try_into().unwrap();
        assert_eq!(decoded, big);
    }

    #[test]
    fn test_decode_plain_unsigned_to_biguint() {
        let cbor = CBOR::from(12345u64);
        let big: BigUint = cbor.try_into().unwrap();
        assert_eq!(big, BigUint::from(12345u64));
    }

    #[test]
    fn test_decode_plain_unsigned_to_bigint() {
        let cbor = CBOR::from(12345u64);
        let big: BigInt = cbor.try_into().unwrap();
        assert_eq!(big, BigInt::from(12345));
    }

    #[test]
    fn test_decode_plain_negative_to_bigint() {
        let cbor = CBOR::from(-12345i64);
        let big: BigInt = cbor.try_into().unwrap();
        assert_eq!(big, BigInt::from(-12345));
    }

    #[test]
    fn test_decode_plain_negative_to_biguint_fails() {
        let cbor = CBOR::from(-1i64);
        let result: Result<BigUint> = cbor.try_into();
        assert!(matches!(result, Err(Error::OutOfRange)));
    }

    #[test]
    fn test_decode_tag3_to_biguint_fails() {
        let big = BigInt::from(-1);
        let cbor = CBOR::from(big);
        let result: Result<BigUint> = cbor.try_into();
        assert!(matches!(result, Err(Error::OutOfRange)));
    }
}
