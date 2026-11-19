//! The functions the symbolic derives' expansions call (`dcbor-derive`,
//! `CBOREncodable` and `CBORDecodable`). Public, because every expansion in
//! a user's crate calls it, and hidden from the documentation, because no
//! user calls it directly: a cross-crate interface between `dcbor` and
//! `dcbor-derive`. Its signatures change only together with the derive's
//! generator, in the same change; the derive's trybuild pass fixtures
//! (`dcbor-derive/tests/ui/pass`), which build and run expansions against
//! this crate, are the compatibility check.
//!
//! The expansion lands in the user's crate, where `Vec`, `vec!`, `From`,
//! `TryFrom`, `Iterator`, `Ok` and `Some` may be shadowed or absent; every
//! operation the expansion needs on them is here, inside dCBOR, so the
//! expansion names only these functions, `dcbor`'s types and `::core`
//! paths. Each function consumes what it is given: an owned array's elements
//! move out, never cloned (a clone of a handle followed by
//! [`CBOR::into_case`] would copy the case it shares).

import_stdlib!();

use crate::{CBOR, CBORCase, Error, Map, Result, Tag};

/// The one tag a derived tagged type lists.
pub fn tags(value: u64) -> Vec<Tag> {
    Vec::from([Tag::with_value(value)])
}

/// A unit variant's encoding: its discriminant.
pub fn discriminant(discriminant: u64) -> CBOR {
    CBOR::from(discriminant)
}

/// A record's encoding: its map of fields, moved in.
pub fn map(map: Map) -> CBOR {
    CBOR::from(map)
}

/// A variant with a payload: the array of its discriminant, then each
/// payload value, moved in.
pub fn variant<const N: usize>(discriminant: u64, payload: [CBOR; N]) -> CBOR {
    let mut items = Vec::with_capacity(N + 1);
    items.push(CBOR::from(discriminant));
    items.extend(payload);
    CBORCase::Array(items).into()
}

/// `cbor` converted to `T`, its error made a dCBOR error.
pub fn convert<T>(cbor: CBOR) -> Result<T>
where
    T: TryFrom<CBOR>,
    Error: From<T::Error>,
{
    Ok(T::try_from(cbor)?)
}

/// A required field of a decoded record: the value of `key` moved out of
/// `map` and converted, refused [`Error::MissingMapKey`] when absent and
/// with the conversion's error when it does not convert. Keys the record
/// does not name stay in the map, ignored.
pub fn field<T>(map: &mut Map, key: u64) -> Result<T>
where
    T: TryFrom<CBOR>,
    Error: From<T::Error>,
{
    convert(map.take(key)?.ok_or(Error::MissingMapKey)?)
}

/// An optional field of a decoded record: `None` when `key` is absent, the
/// value moved out and converted when present, refused with the
/// conversion's error when present but not converting, never read as
/// absent.
pub fn optional<T>(map: &mut Map, key: u64) -> Result<Option<T>>
where
    T: TryFrom<CBOR>,
    Error: From<T::Error>,
{
    map.take(key)?.map(convert).transpose()
}

/// The payload of a decoded variant array, its discriminant already read.
pub struct Payload(<Vec<CBOR> as IntoIterator>::IntoIter);

impl Payload {
    /// The payload values left.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether no payload value is left.
    pub fn is_empty(&self) -> bool {
        self.0.len() == 0
    }

    /// The next payload value, moved out; refused as the wrong type when
    /// none is left: a payload shorter than its variant declares.
    pub fn take_value(&mut self) -> Result<CBOR> {
        self.0.next().ok_or(Error::WrongType)
    }
}

/// An array's discriminant and payload, the array moved apart: refused as
/// the wrong type when it is empty or its first element is not an unsigned
/// integer.
pub fn variant_array(items: Vec<CBOR>) -> Result<(u64, Payload)> {
    let mut items = items.into_iter();
    let discriminant = convert::<u64>(items.next().ok_or(Error::WrongType)?)?;
    Ok((discriminant, Payload(items)))
}
