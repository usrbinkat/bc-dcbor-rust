import_stdlib!();

/// The eight CBOR major types (RFC 8949 section 3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MajorType {
    Unsigned,
    Negative,
    ByteString,
    Text,
    Array,
    Map,
    Tagged,
    Simple,
}

pub(crate) const fn type_bits(t: MajorType) -> u8 {
    let b = match t {
        MajorType::Unsigned => 0,
        MajorType::Negative => 1,
        MajorType::ByteString => 2,
        MajorType::Text => 3,
        MajorType::Array => 4,
        MajorType::Map => 5,
        MajorType::Tagged => 6,
        MajorType::Simple => 7,
    };
    b << 5
}

/// The most bytes one data item head occupies: the initial byte and an
/// eight-byte argument.
pub const MAX_HEAD_LEN: usize = 9;

/// A head's argument and the width it is written at, the width fixed by
/// the variant so no value is ever truncated to fit it.
///
/// Two policies choose a width. An integer argument (an integer, a length,
/// a count, a tag, a simple value) takes the shortest width holding it,
/// the only width dCBOR admits for them ([`Argument::Shortest`]). A
/// floating-point payload takes the width of the precision its canonical
/// reduction selected (`float.rs`), whatever its bits' magnitude:
/// half-precision `0x0001` is `f9 00 01`, not the shortest head of 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Argument {
    /// The shortest width holding the value.
    Shortest(u64),
    /// One following byte.
    Fixed8(u8),
    /// Two following bytes.
    Fixed16(u16),
    /// Four following bytes.
    Fixed32(u32),
    /// Eight following bytes.
    Fixed64(u64),
}

/// The additional information of each width (RFC 8949 section 3).
const ONE_BYTE: u8 = 24;
const TWO_BYTES: u8 = 25;
const FOUR_BYTES: u8 = 26;
const EIGHT_BYTES: u8 = 27;

impl Argument {
    /// The additional information, the number of following bytes and the
    /// value, the width resolved.
    const fn resolved(self) -> (u8, usize, u64) {
        match self {
            Self::Shortest(value) => {
                if value <= 23 {
                    (value as u8, 0, value)
                } else if value <= u8::MAX as u64 {
                    (ONE_BYTE, 1, value)
                } else if value <= u16::MAX as u64 {
                    (TWO_BYTES, 2, value)
                } else if value <= u32::MAX as u64 {
                    (FOUR_BYTES, 4, value)
                } else {
                    (EIGHT_BYTES, 8, value)
                }
            }
            Self::Fixed8(value) => (ONE_BYTE, 1, value as u64),
            Self::Fixed16(value) => (TWO_BYTES, 2, value as u64),
            Self::Fixed32(value) => (FOUR_BYTES, 4, value as u64),
            Self::Fixed64(value) => (EIGHT_BYTES, 8, value),
        }
    }

    /// Bytes of a head carrying this argument.
    pub const fn head_len(self) -> usize {
        1 + self.resolved().1
    }
}

/// Bytes of the shortest head carrying integer argument `value`.
pub const fn head_len(value: u64) -> usize {
    Argument::Shortest(value).head_len()
}

/// Write the head of `major_type` carrying `argument` into `out`, returning
/// its length: the initial byte, then the argument in network order. The
/// one writer of heads: the symbolic encoders and the bounded output both
/// write through it.
pub(crate) const fn write_argument(
    major_type: MajorType,
    argument: Argument,
    out: &mut [u8; MAX_HEAD_LEN],
) -> usize {
    let (additional, following, value) = argument.resolved();
    out[0] = additional | type_bits(major_type);
    let mut index = 0;
    while index < following {
        out[1 + index] = (value >> (8 * (following - 1 - index))) as u8;
        index += 1;
    }
    1 + following
}

/// The head of `major_type` carrying `argument`, as a vector.
pub(crate) fn head_vec(major_type: MajorType, argument: Argument) -> Vec<u8> {
    let mut head = [0u8; MAX_HEAD_LEN];
    let length = write_argument(major_type, argument, &mut head);
    head[..length].to_vec()
}

/// The shortest head carrying an integer argument: the one form dCBOR
/// admits for integers, lengths, counts, tags and simple values. A
/// floating-point payload is written at its fixed width through
/// [`Argument`] directly (`float.rs`).
pub trait EncodeVarInt {
    /// The shortest head carrying this value.
    fn encode_varint(&self, major_type: MajorType) -> Vec<u8>;
}

macro_rules! impl_encode_varint {
    ($($type:ty),*) => {$(
        impl EncodeVarInt for $type {
            fn encode_varint(&self, major_type: MajorType) -> Vec<u8> {
                head_vec(major_type, Argument::Shortest(*self as u64))
            }
        }
    )*};
}

impl_encode_varint!(u8, u16, u32, u64, usize);

#[cfg(test)]
mod tests {
    use super::*;

    /// The shortest head at every width boundary, by fixed bytes.
    #[test]
    fn shortest_heads_have_their_fixed_bytes() {
        let fixtures: [(u64, &[u8]); 11] = [
            (0, &[0x60]),
            (23, &[0x77]),
            (24, &[0x78, 0x18]),
            (255, &[0x78, 0xff]),
            (256, &[0x79, 0x01, 0x00]),
            (65_535, &[0x79, 0xff, 0xff]),
            (65_536, &[0x7a, 0x00, 0x01, 0x00, 0x00]),
            (4_294_967_295, &[0x7a, 0xff, 0xff, 0xff, 0xff]),
            (4_294_967_296, &[0x7b, 0, 0, 0, 1, 0, 0, 0, 0]),
            (
                u64::MAX - 1,
                &[0x7b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe],
            ),
            (
                u64::MAX,
                &[0x7b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
            ),
        ];
        for (value, expected) in fixtures {
            assert_eq!(value.encode_varint(MajorType::Text), expected, "{value}");
            assert_eq!(head_len(value), expected.len(), "{value}");
        }
        assert_eq!(0u64.encode_varint(MajorType::Unsigned), [0x00]);
        assert_eq!(24u64.encode_varint(MajorType::Negative), [0x38, 0x18]);
        assert_eq!(2u64.encode_varint(MajorType::Map), [0xa2]);
        assert_eq!(300u64.encode_varint(MajorType::Array), [0x99, 0x01, 0x2c]);
    }

    /// A fixed width keeps its width whatever the value: the float
    /// payloads' form, never the shortest head.
    #[test]
    fn fixed_widths_keep_their_width() {
        assert_eq!(
            head_vec(MajorType::Simple, Argument::Fixed16(1)),
            [0xf9, 0x00, 0x01]
        );
        assert_eq!(
            head_vec(MajorType::Simple, Argument::Fixed16(0x7c00)),
            [0xf9, 0x7c, 0x00]
        );
        assert_eq!(
            head_vec(MajorType::Simple, Argument::Fixed32(0)),
            [0xfa, 0, 0, 0, 0]
        );
        assert_eq!(
            head_vec(MajorType::Simple, Argument::Fixed64(1)),
            [0xfb, 0, 0, 0, 0, 0, 0, 0, 1]
        );
        assert_eq!(
            head_vec(MajorType::Unsigned, Argument::Fixed8(5)),
            [0x18, 0x05]
        );
        assert_eq!(Argument::Fixed16(1).head_len(), 3);
        assert_eq!(Argument::Shortest(1).head_len(), 1);
        assert_eq!(5usize.encode_varint(MajorType::Unsigned), [0x05]);
    }
}
