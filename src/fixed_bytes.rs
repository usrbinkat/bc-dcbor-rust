//! A byte string of exactly `N` bytes: a digest, a key, an identifier whose
//! length its type fixes. A CBOR byte string (major type 2) of any other
//! length is refused by every decoder, [`Error::WrongLength`], and its CDDL
//! is `bstr .size N` (RFC 8610, section 3.8.1). Distinct from `[u8; N]`,
//! which is a CBOR array of `N` integers.
//!
//! The bytes are held inline, so the value owns no allocation: its bounded
//! decoding (`InPlace`) copies the document's bytes into the value's own
//! place in units of at most a quantum, each admitted before it is copied.

import_stdlib!();

use crate::{CBOR, CBORCase, Error, Result};

/// Exactly `N` bytes, encoded as a CBOR byte string of length `N`.
///
/// ```
/// use dcbor::prelude::*;
/// use dcbor::FixedBytes;
///
/// # fn main() -> dcbor::Result<()> {
/// let digest = FixedBytes::new([0xab; 4]);
/// let cbor = CBOR::from(digest);
/// assert_eq!(cbor.hex(), "44abababab");
/// assert_eq!(FixedBytes::<4>::try_from(cbor)?, digest);
/// // A byte string of another length is refused, naming both lengths.
/// assert!(matches!(
///     FixedBytes::<4>::try_from(CBOR::to_byte_string([1u8, 2, 3])),
///     Err(dcbor::Error::WrongLength { expected: 4, actual: 3 })
/// ));
/// # Ok(())
/// # }
/// ```
///
/// Transparent over its array: the bounded decoding writes the bytes at the
/// value's own place.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct FixedBytes<const N: usize>([u8; N]);

impl<const N: usize> FixedBytes<N> {
    /// The length every value of this type has.
    pub const LEN: usize = N;

    pub const fn new(bytes: [u8; N]) -> Self {
        Self(bytes)
    }

    /// `bytes` as a value, refused [`Error::WrongLength`] unless exactly `N`
    /// bytes long.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        <[u8; N]>::try_from(bytes)
            .map(Self)
            .map_err(|_| Error::WrongLength {
                expected: N,
                actual: bytes.len(),
            })
    }

    pub const fn as_array(&self) -> &[u8; N] {
        &self.0
    }

    pub const fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub const fn into_array(self) -> [u8; N] {
        self.0
    }
}

impl<const N: usize> From<[u8; N]> for FixedBytes<N> {
    fn from(bytes: [u8; N]) -> Self {
        Self(bytes)
    }
}

impl<const N: usize> From<FixedBytes<N>> for [u8; N] {
    fn from(bytes: FixedBytes<N>) -> Self {
        bytes.0
    }
}

impl<const N: usize> AsRef<[u8]> for FixedBytes<N> {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<const N: usize> TryFrom<&[u8]> for FixedBytes<N> {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self> {
        Self::from_slice(bytes)
    }
}

impl<const N: usize> From<FixedBytes<N>> for CBOR {
    fn from(bytes: FixedBytes<N>) -> Self {
        CBOR::to_byte_string(bytes.0)
    }
}

/// A CBOR byte string of exactly `N` bytes; one of another length is
/// [`Error::WrongLength`], and any other value [`Error::WrongType`].
impl<const N: usize> TryFrom<CBOR> for FixedBytes<N> {
    type Error = Error;

    fn try_from(cbor: CBOR) -> Result<Self> {
        match cbor.as_case() {
            CBORCase::ByteString(bytes) => Self::from_slice(bytes.data()),
            _ => Err(Error::WrongType),
        }
    }
}

impl<const N: usize> crate::CBOREncodable for FixedBytes<N> {
    fn encode_cbor(&self) -> Result<CBOR> {
        Ok(CBOR::from(*self))
    }
}

/// Bounded encoding: the byte string's head of length `N`, then its bytes,
/// as a [`crate::ByteString`] is written.
impl<const N: usize> crate::bounded::encoding::Schema for FixedBytes<N> {
    fn instruction(&self, index: usize) -> crate::bounded::encoding::Instruction<'_> {
        use crate::bounded::encoding::Instruction;
        use crate::bounded::{Argument, MajorType};
        match index {
            0 => Instruction::Head(MajorType::ByteString, Argument::Shortest(N as u64)),
            1 => Instruction::Bytes(&self.0),
            _ => Instruction::End,
        }
    }
}

// SAFETY: references: a head computed from `N`, then the value's own bytes,
// held immutably by the value while it is retained. cursors: none, no
// instruction is `Entries`. recursion: none, no instruction is a child.
unsafe impl<const N: usize> crate::bounded::encoding::TransferableSchema for FixedBytes<N> {}

/// `bstr .size N`: a byte string of exactly `N` bytes (RFC 8610, section
/// 3.8.1), the set every decoder of the type accepts.
impl<const N: usize> crate::cddl::Cddl for FixedBytes<N> {
    fn cddl(_: &mut crate::cddl::Rules) -> String {
        format!("bstr .size {N}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every length but the type's is refused, naming both, by the slice
    /// and the symbolic conversions alike; the type's own length is
    /// accepted, and its bytes kept.
    #[test]
    fn only_the_types_length_is_accepted() {
        for actual in [0usize, 1, 31, 33, 64] {
            let bytes = vec![7u8; actual];
            let expected = Error::WrongLength {
                expected: 32,
                actual,
            };
            assert_eq!(
                FixedBytes::<32>::from_slice(&bytes)
                    .unwrap_err()
                    .to_string(),
                expected.to_string()
            );
            assert!(matches!(
                FixedBytes::<32>::try_from(CBOR::to_byte_string(bytes.clone())),
                Err(Error::WrongLength { expected: 32, actual: a }) if a == actual
            ));
        }
        let value = FixedBytes::<32>::from_slice(&[9; 32]).unwrap();
        assert_eq!(value.as_array(), &[9; 32]);
        assert_eq!(
            FixedBytes::<32>::try_from(CBOR::from(value)).unwrap(),
            value
        );
    }

    /// A value of another kind is the wrong type, whatever its length: a
    /// text of `N` bytes and an array of `N` integers (`[u8; N]`'s form).
    #[test]
    fn a_text_or_an_array_of_the_length_is_the_wrong_type() {
        assert!(matches!(
            FixedBytes::<2>::try_from(CBOR::from("ab")),
            Err(Error::WrongType)
        ));
        assert!(matches!(
            FixedBytes::<2>::try_from(CBOR::from([1u8, 2])),
            Err(Error::WrongType)
        ));
    }

    /// The empty type: a byte string of no bytes, and nothing else.
    #[test]
    fn the_empty_type_is_the_empty_byte_string() {
        let empty = FixedBytes::<0>::new([]);
        assert_eq!(CBOR::from(empty).to_cbor_data(), [0x40]);
        assert_eq!(
            FixedBytes::<0>::try_from(CBOR::to_byte_string([0u8; 0])).unwrap(),
            empty
        );
        assert!(matches!(
            FixedBytes::<0>::try_from(CBOR::to_byte_string([0u8])),
            Err(Error::WrongLength {
                expected: 0,
                actual: 1
            })
        ));
    }

    /// Its CDDL names its length.
    #[test]
    fn its_cddl_is_a_sized_byte_string() {
        use crate::cddl::{Cddl, Rules};
        let mut rules = Rules::new();
        assert_eq!(FixedBytes::<32>::cddl(&mut rules), "bstr .size 32");
        assert_eq!(FixedBytes::<0>::cddl(&mut rules), "bstr .size 0");
    }
}
