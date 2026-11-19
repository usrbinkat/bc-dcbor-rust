//! An integer of any size with exactly one dCBOR encoding.
//!
//! dCBOR places no rule on tags 2 and 3 beyond those on every byte string
//! (draft 18, section 8.5, "Limiting Principles"): the generic decoder
//! accepts `c2 41 01` and `c2 42 00 01` as two distinct tagged byte strings.
//! [`MinimalBigInt`] is the typed domain above that, whose identity is its
//! encoding: a plain integer (major type 0 or 1) inside dCBOR's integer
//! range, a bignum outside it whose byte string has no leading zero byte.
//! Its representation is that encoding's own bytes, so the bounded decoder
//! builds it in admitted storage as it builds a byte string, and num-bigint
//! is a conversion at the symbolic edge only (`num_bigint.rs`).

import_stdlib!();

use crate::{
    ByteString, CBOR, CBORCase, Error, Result, TAG_NEGATIVE_BIGNUM, TAG_POSITIVE_BIGNUM, Tag,
};

/// An integer of any size, held as the argument `n` of its encoding: the
/// value is `n` when not negative, and `-1 - n` when negative, the meaning
/// major type 1 and tag 3 share. `magnitude` is `n`'s big-endian bytes with
/// no leading zero byte, empty for `n = 0`: zero is `(false, [])` and `-1`
/// is `(true, [])`.
///
/// One encoding per value, and decoding then encoding is byte-identical for
/// every encoding the dCBOR decoder accepts (a symbolic `CBOR` holding a
/// negative argument beyond the range, which the decoder never produces, is
/// refused as [`Error::OutOfRange`]):
///
/// - inside dCBOR's integer range, `[-2^63, 2^64 - 1]` (`plain`), the plain
///   integer of argument `n`, which decoding accepts;
/// - outside it, tag 2 (or 3, negative) around `n`'s bytes. Decoding refuses,
///   with [`Error::NonCanonicalNumeric`], a bignum whose byte string is empty
///   or has a leading zero byte, and then one whose value a plain integer
///   carries (`bignum`);
/// - anything else is [`Error::WrongType`].
///
/// ```
/// use dcbor::prelude::*;
/// use dcbor::MinimalBigInt;
///
/// # fn main() -> dcbor::Result<()> {
/// // 1 as a bignum is dCBOR, but not 1's minimal encoding.
/// let tagged = CBOR::try_from_hex("c24101")?;
/// assert!(matches!(
///     MinimalBigInt::try_from(tagged),
///     Err(dcbor::Error::NonCanonicalNumeric)
/// ));
/// assert_eq!(CBOR::from(MinimalBigInt::from(1u64)).hex(), "01");
/// // 2^64, the least positive value outside the plain range.
/// let big = CBOR::try_from_hex("c249010000000000000000")?;
/// let minimal = MinimalBigInt::try_from(big.clone())?;
/// assert_eq!(minimal.as_parts(), (false, &[1, 0, 0, 0, 0, 0, 0, 0, 0][..]));
/// assert_eq!(CBOR::from(minimal).to_cbor_data(), big.to_cbor_data());
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct MinimalBigInt {
    pub(crate) negative: bool,
    pub(crate) magnitude: ByteString,
}

/// Whether the integer of argument bytes `magnitude`, negative when
/// `negative`, lies in dCBOR's integer range, `[-2^63, 2^64 - 1]`: a positive
/// argument of at most eight bytes, a negative one of at most eight bytes
/// whose top bit is clear (`n < 2^63`, so `-1 - n >= -2^63`, `float.rs`
/// `DCBOR_INT_MIN`, which the decoder enforces, `decode.rs`). Read from the
/// length and the first byte alone. The one definition of the range a
/// [`MinimalBigInt`] encodes without a tag, read by its symbolic and bounded
/// encodings and decodings.
pub(crate) fn plain(negative: bool, magnitude: &[u8]) -> bool {
    match magnitude.len() {
        0..=7 => true,
        8 => !negative || magnitude[0] & 0x80 == 0,
        _ => false,
    }
}

/// The argument a plain `magnitude` ([`plain`]) carries.
pub(crate) fn argument(magnitude: &[u8]) -> u64 {
    magnitude
        .iter()
        .fold(0, |n, &byte| (n << 8) | u64::from(byte))
}

/// `n`'s big-endian bytes, and where its bytes without leading zeros begin:
/// a magnitude, recomputed alike from the same `n`.
pub(crate) fn argument_bytes(n: u64) -> ([u8; 8], usize) {
    (n.to_be_bytes(), (n.leading_zeros() / 8) as usize)
}

/// The bignum tag of a sign: 2, or 3 when `negative`. The one choice every
/// bignum encoding makes, this type's and num-bigint's (`num_bigint.rs`).
pub(crate) fn bignum_tag(negative: bool) -> Tag {
    Tag::with_value(if negative {
        TAG_NEGATIVE_BIGNUM
    } else {
        TAG_POSITIVE_BIGNUM
    })
}

/// `bytes` without its leading zero bytes, drained in place, the vector kept:
/// the one definition both num-bigint edges use (`num_bigint.rs`).
#[cfg(feature = "num-bigint")]
pub(crate) fn drop_leading_zeros(bytes: &mut Vec<u8>) {
    let leading = bytes.iter().take_while(|&&byte| byte == 0).count();
    bytes.drain(..leading);
}

/// A tag 2 (or 3, `negative`) byte string `bytes`, refused with
/// [`Error::NonCanonicalNumeric`] unless it is the minimal encoding of its
/// value: not empty and without a leading zero byte; then outside the plain
/// range, which a plain integer would carry. Each rule reads the length and
/// the first byte alone.
pub(crate) fn bignum(negative: bool, bytes: &[u8]) -> Result<()> {
    match bytes.first() {
        None | Some(0) => return Err(Error::NonCanonicalNumeric),
        Some(_) => {}
    }
    if plain(negative, bytes) {
        return Err(Error::NonCanonicalNumeric);
    }
    Ok(())
}

impl MinimalBigInt {
    /// The integer of argument bytes `magnitude`, negative when `negative`,
    /// refused with [`Error::NonCanonicalNumeric`] when `magnitude` has a
    /// leading zero byte, which no argument's minimal bytes have. An empty
    /// magnitude is the argument zero: `0`, or, negative, `-1`.
    pub fn from_parts(negative: bool, magnitude: impl AsRef<[u8]>) -> Result<Self> {
        let magnitude = magnitude.as_ref();
        if magnitude.first() == Some(&0) {
            return Err(Error::NonCanonicalNumeric);
        }
        Ok(Self::minimal(negative, magnitude))
    }

    /// The integer of `magnitude`, already without a leading zero byte.
    pub(crate) fn minimal(negative: bool, magnitude: &[u8]) -> Self {
        Self {
            negative,
            magnitude: ByteString::new(magnitude),
        }
    }

    /// The integer of the argument bytes `bytes`, its leading zero bytes
    /// dropped in place: the vector is moved in, never copied whole. The
    /// num-bigint conversions' constructor (`num_bigint.rs`).
    #[cfg(feature = "num-bigint")]
    pub(crate) fn from_vec(negative: bool, mut bytes: Vec<u8>) -> Self {
        drop_leading_zeros(&mut bytes);
        Self {
            negative,
            magnitude: ByteString::from(bytes),
        }
    }

    /// Whether the value is negative, and its argument's bytes.
    pub fn as_parts(&self) -> (bool, &[u8]) {
        (self.negative, self.magnitude.data())
    }

    /// The argument's bytes, as the byte string a bignum encodes.
    pub(crate) fn magnitude(&self) -> &ByteString {
        &self.magnitude
    }

    pub fn is_negative(&self) -> bool {
        self.negative
    }
}

impl From<u64> for MinimalBigInt {
    fn from(value: u64) -> Self {
        let (bytes, start) = argument_bytes(value);
        Self::minimal(false, &bytes[start..])
    }
}

impl From<i64> for MinimalBigInt {
    /// A negative `value` as the argument `-1 - value`, `!value`, which is
    /// not negative.
    fn from(value: i64) -> Self {
        if value < 0 {
            let (bytes, start) = argument_bytes((!value).unsigned_abs());
            Self::minimal(true, &bytes[start..])
        } else {
            Self::from(value.unsigned_abs())
        }
    }
}

/// Which form a value takes: the plain integer inside the range, or a
/// bignum of this tag outside it.
enum Form {
    Plain(CBOR),
    Bignum(Tag),
}

/// The form of the integer of `magnitude`: the one choice both encodings
/// make.
fn form(negative: bool, magnitude: &[u8]) -> Form {
    if plain(negative, magnitude) {
        let n = argument(magnitude);
        Form::Plain(if negative {
            CBORCase::Negative(n).into()
        } else {
            CBORCase::Unsigned(n).into()
        })
    } else {
        Form::Bignum(bignum_tag(negative))
    }
}

impl From<&MinimalBigInt> for CBOR {
    /// The plain integer inside the range, the tagged byte string outside,
    /// its bytes copied from the borrowed value.
    fn from(value: &MinimalBigInt) -> Self {
        let (negative, magnitude) = value.as_parts();
        match form(negative, magnitude) {
            Form::Plain(plain) => plain,
            Form::Bignum(tag) => CBOR::to_tagged_value(tag, CBOR::to_byte_string(magnitude)),
        }
    }
}

impl From<MinimalBigInt> for CBOR {
    /// As the borrowed conversion, the magnitude moved into the byte string,
    /// never copied.
    fn from(value: MinimalBigInt) -> Self {
        let MinimalBigInt {
            negative,
            magnitude,
        } = value;
        match form(negative, magnitude.data()) {
            Form::Plain(plain) => plain,
            Form::Bignum(tag) => CBOR::to_tagged_value(tag, CBOR::from(magnitude)),
        }
    }
}

impl TryFrom<CBOR> for MinimalBigInt {
    type Error = Error;

    /// An unsigned integer, or a negative one within dCBOR's range, its
    /// argument's bytes; a negative argument beyond the range, which a
    /// symbolic value can hold but the decoder refuses (`decode.rs`), refused
    /// alike as [`Error::OutOfRange`]: re-encoded, it would become a tag 3,
    /// not the plain integer it is. A tag 2 or 3 byte string refused unless
    /// minimal (`bignum`), then moved in: no copy beyond what
    /// [`CBOR::into_case`] makes, which moves the case out of a uniquely held
    /// value and clones it, bytes included, out of a shared one. Anything
    /// else the wrong type.
    fn try_from(cbor: CBOR) -> Result<Self> {
        match cbor.into_case() {
            CBORCase::Unsigned(n) => Ok(Self::from(n)),
            CBORCase::Negative(n) => {
                let (bytes, start) = argument_bytes(n);
                if !plain(true, &bytes[start..]) {
                    return Err(Error::OutOfRange);
                }
                Ok(Self::minimal(true, &bytes[start..]))
            }
            CBORCase::Tagged(tag, inner) => {
                let negative = match tag.value() {
                    TAG_POSITIVE_BIGNUM => false,
                    TAG_NEGATIVE_BIGNUM => true,
                    _ => return Err(Error::WrongType),
                };
                let CBORCase::ByteString(bytes) = inner.into_case() else {
                    return Err(Error::WrongType);
                };
                bignum(negative, bytes.data())?;
                Ok(Self {
                    negative,
                    magnitude: bytes,
                })
            }
            _ => Err(Error::WrongType),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The plain range is dCBOR's integer range: `u64::MAX` inside, eight
    /// bytes; nine bytes outside; the least negative argument the decoder
    /// accepts, `-1 - DCBOR_INT_MIN`, inside, and one more outside.
    #[test]
    fn the_plain_range_is_dcbors_integer_range() {
        let least = u64::try_from(-1 - crate::float::DCBOR_INT_MIN).unwrap();
        let (bytes, start) = argument_bytes(least);
        assert!(plain(true, &bytes[start..]));
        let (bytes, start) = argument_bytes(least + 1);
        assert!(!plain(true, &bytes[start..]));
        let (bytes, start) = argument_bytes(u64::MAX);
        assert!(plain(false, &bytes[start..]));
        assert!(plain(true, &[]) && plain(false, &[]));
        assert!(!plain(false, &[1, 0, 0, 0, 0, 0, 0, 0, 0]));
    }

    /// An argument's bytes have no leading zero, and zero has none at all.
    #[test]
    fn an_arguments_bytes_are_minimal() {
        for (n, expected) in [
            (0u64, &[][..]),
            (1, &[1]),
            (255, &[255]),
            (256, &[1, 0]),
            (u64::MAX, &[255; 8]),
        ] {
            let (bytes, start) = argument_bytes(n);
            assert_eq!(&bytes[start..], expected, "{n}");
            assert_eq!(argument(expected), n);
        }
    }

    /// A bignum's rules, in order: empty and a leading zero refused, then a
    /// value inside the plain range.
    #[test]
    fn a_bignum_is_refused_unless_minimal() {
        let two_64 = [1, 0, 0, 0, 0, 0, 0, 0, 0];
        assert!(bignum(false, &two_64).is_ok());
        assert!(bignum(true, &two_64).is_ok());
        assert!(bignum(true, &[0x80, 0, 0, 0, 0, 0, 0, 0]).is_ok());
        for (negative, bytes) in [
            (false, &[][..]),
            (true, &[]),
            (false, &[1]),
            (true, &[0]),
            (false, &[0, 1]),
            (false, &[0xff; 8]),
            (true, &[0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]),
            (false, &[0, 1, 0, 0, 0, 0, 0, 0, 0, 0]),
        ] {
            assert!(
                matches!(bignum(negative, bytes), Err(Error::NonCanonicalNumeric)),
                "{negative} {bytes:02x?}"
            );
        }
        assert!(matches!(
            MinimalBigInt::from_parts(false, [0, 1]),
            Err(Error::NonCanonicalNumeric)
        ));
    }
}
