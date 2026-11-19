import_stdlib!();

use half::f16;
use unicode_normalization::is_nfc;

use super::varint::MajorType;
use crate::{
    CBOR, CBORCase, Map,
    error::{Error, Result},
    float::{validate_canonical_f16, validate_canonical_f32, validate_canonical_f64},
};

/// Decode CBOR binary representation to symbolic representation.
///
/// Returns an error if the data is not well-formed deterministic CBOR.
pub fn decode_cbor(data: impl AsRef<[u8]>) -> Result<CBOR> {
    let data = data.as_ref();
    // The root is the first frame of the symbolic profile.
    let (cbor, len) = decode_cbor_internal(data, 1)?;
    let remaining = data.len() - len;
    if remaining > 0 {
        return Err(Error::UnusedData(remaining));
    }
    Ok(cbor)
}

fn parse_header(header: u8) -> (MajorType, u8) {
    let major_type = match header >> 5 {
        0 => MajorType::Unsigned,
        1 => MajorType::Negative,
        2 => MajorType::ByteString,
        3 => MajorType::Text,
        4 => MajorType::Array,
        5 => MajorType::Map,
        6 => MajorType::Tagged,
        7 => MajorType::Simple,
        _ => panic!(),
    };
    let header_value = header & 31;
    (major_type, header_value)
}

pub(crate) fn parse_header_varint(data: &[u8]) -> Result<(MajorType, u64, usize)> {
    if data.is_empty() {
        return Err(Error::Underrun);
    }
    let header = data[0];
    let (major_type, header_value) = parse_header(header);
    let data_remaining = data.len() - 1;
    let (value, varint_len) = match header_value {
        0..=23 => (header_value as u64, 1),
        24 => {
            if data_remaining < 1 {
                return Err(Error::Underrun);
            }
            let val = data[1] as u64;
            if val < 24 {
                return Err(Error::NonCanonicalNumeric);
            }
            (val, 2)
        }
        25 => {
            if data_remaining < 2 {
                return Err(Error::Underrun);
            }
            let val = ((data[1] as u64) << 8) | (data[2] as u64);
            if val <= (u8::MAX as u64) && header != 0xf9 {
                return Err(Error::NonCanonicalNumeric);
            }
            (val, 3)
        }
        26 => {
            if data_remaining < 4 {
                return Err(Error::Underrun);
            }
            let val = ((data[1] as u64) << 24)
                | ((data[2] as u64) << 16)
                | ((data[3] as u64) << 8)
                | (data[4] as u64);
            if val <= (u16::MAX as u64) && header != 0xfa {
                return Err(Error::NonCanonicalNumeric);
            }
            (val, 5)
        }
        27 => {
            if data_remaining < 8 {
                return Err(Error::Underrun);
            }
            let val = ((data[1] as u64) << 56)
                | ((data[2] as u64) << 48)
                | ((data[3] as u64) << 40)
                | ((data[4] as u64) << 32)
                | ((data[5] as u64) << 24)
                | ((data[6] as u64) << 16)
                | ((data[7] as u64) << 8)
                | (data[8] as u64);
            if val <= (u32::MAX as u64) && header != 0xfb {
                return Err(Error::NonCanonicalNumeric);
            }
            (val, 9)
        }
        v => {
            return Err(Error::UnsupportedHeaderValue(v));
        }
    };
    Ok((major_type, value, varint_len))
}

/// The integer a major-type-1 head carrying `argument` encodes, `-1 -
/// argument`, when it is in dCBOR's integer range, at least `-2^63`
/// (`float::DCBOR_INT_MIN`): an argument of at most `2^63 - 1`. A larger
/// argument is refused [`Error::OutOfRange`]. The one range rule of every
/// decoder: the symbolic decoder below, the bounded flat decoder
/// (`bounded::decode::decode_with`) and the retained cursor
/// (`bounded::decode::cursor`) each call it.
pub(crate) fn negative(argument: u64) -> Result<i64> {
    if argument > i64::MAX as u64 {
        return Err(Error::OutOfRange);
    }
    Ok(-1 - argument as i64)
}

fn parse_bytes(data: &[u8], len: usize) -> Result<&[u8]> {
    if data.len() < len {
        return Err(Error::Underrun);
    }
    Ok(&data[0..len])
}

/// The item at the front of `data`, at frame `depth` of the symbolic profile,
/// and its encoded length. Each array element, map key, map value and tagged
/// item is decoded one frame deeper; a frame past
/// [`crate::bounded::SYMBOLIC_DEPTH`] is refused before it is read, so the
/// recursion never goes deeper than the profile, and `depth + 1` never
/// exceeds `SYMBOLIC_DEPTH + 1`.
fn decode_cbor_internal(data: &[u8], depth: usize) -> Result<(CBOR, usize)> {
    if depth > crate::bounded::SYMBOLIC_DEPTH {
        return Err(Error::DepthLimit);
    }
    if data.is_empty() {
        return Err(Error::Underrun);
    }
    let (major_type, value, header_varint_len) = parse_header_varint(data)?;
    match major_type {
        MajorType::Unsigned => Ok((CBORCase::Unsigned(value).into(), header_varint_len)),
        MajorType::Negative => {
            negative(value)?;
            Ok((CBORCase::Negative(value).into(), header_varint_len))
        }
        MajorType::ByteString => {
            // A length beyond the address space exceeds any input.
            let data_len = usize::try_from(value).map_err(|_| Error::Underrun)?;
            let bytes = parse_bytes(&data[header_varint_len..], data_len)?
                .to_vec()
                .into();
            Ok((
                CBORCase::ByteString(bytes).into(),
                header_varint_len + data_len,
            ))
        }
        MajorType::Text => {
            let data_len = usize::try_from(value).map_err(|_| Error::Underrun)?;
            let buf = parse_bytes(&data[header_varint_len..], data_len)?;
            let string = str::from_utf8(buf)?;
            if !is_nfc(string) {
                return Err(Error::NonCanonicalString);
            }
            Ok((string.into(), header_varint_len + data_len))
        }
        MajorType::Array => {
            let count = usize::try_from(value).map_err(|_| Error::Underrun)?;
            let mut pos = header_varint_len;
            // Every element takes at least one byte of the input, so the
            // reservation is at most the input's remaining length, whatever
            // count the head claims.
            let mut items = Vec::with_capacity(count.min(data.len() - header_varint_len));
            for _ in 0..count {
                let (item, item_len) = decode_cbor_internal(&data[pos..], depth + 1)?;
                items.push(item);
                pos += item_len;
            }
            Ok((items.into(), pos))
        }
        MajorType::Map => {
            let mut pos = header_varint_len;
            let mut map = Map::new();
            for _ in 0..value {
                let (key, key_len) = decode_cbor_internal(&data[pos..], depth + 1)?;
                pos += key_len;
                let (value, value_len) = decode_cbor_internal(&data[pos..], depth + 1)?;
                pos += value_len;
                map.insert_next(key, value)?;
            }
            Ok((map.into(), pos))
        }
        MajorType::Tagged => {
            let (item, item_len) = decode_cbor_internal(&data[header_varint_len..], depth + 1)?;
            let tagged = CBOR::to_tagged_value(value, item);
            Ok((tagged, header_varint_len + item_len))
        }
        MajorType::Simple => match header_varint_len {
            3 => {
                let f = f16::from_bits(value as u16);
                validate_canonical_f16(f)?;
                Ok((f.into(), header_varint_len))
            }
            5 => {
                let f = f32::from_bits(value as u32);
                validate_canonical_f32(f)?;
                Ok((f.into(), header_varint_len))
            }
            9 => {
                let f = f64::from_bits(value);
                validate_canonical_f64(f)?;
                Ok((f.into(), header_varint_len))
            }
            _ => match value {
                20 => Ok((CBOR::r#false(), header_varint_len)),
                21 => Ok((CBOR::r#true(), header_varint_len)),
                22 => Ok((CBOR::null(), header_varint_len)),
                _ => Err(Error::InvalidSimpleValue),
            },
        },
    }
}

/// Kani harnesses of the checks a scalar item meets after its head (register
/// item 4): compiled only by `cargo kani`.
#[cfg(kani)]
mod proofs;
