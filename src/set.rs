import_stdlib!();

use crate::{CBOR, CBORCase, CBOREncodable, Error, Map, MapIter, Result};

#[derive(Clone, Default, PartialEq, Eq)]
pub struct Set(Map);

impl Set {
    /// Makes a new, empty CBOR `Set`.
    pub fn new() -> Self {
        Self(Map::new())
    }

    /// Returns the number of elements in the set.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Checks if the set is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Gets an iterator over the elements in the CBOR set.
    ///
    /// Order is lexicographically by the value's binary-encoded CBOR.
    pub fn iter(&self) -> SetIter<'_> {
        SetIter::new(self.0.iter())
    }

    /// Inserts a value into the set, refused with [`Error::DuplicateMapKey`]
    /// when the set holds it already: elements are compared by their
    /// canonical encoding, after numeric reduction and NFC, so `10` and
    /// `10.0`, or `"\u{e9}"` and `"e\u{301}"`, are one element
    /// ([`Map::insert`]). A value that does not encode is refused with its
    /// own error. The set is unchanged on either refusal.
    pub fn insert(&mut self, value: impl CBOREncodable) -> Result<()> {
        let value = value.into_encoded_cbor()?;
        self.0.insert(value.clone(), value)
    }

    pub(crate) fn insert_next(&mut self, value: CBOR) -> Result<()> {
        self.0.insert_next(value.clone(), value)
    }

    /// Whether the set holds `value`, compared by its canonical encoding as
    /// in [`Self::insert`]. A value that does not encode is refused with its
    /// own error, never taken as absent.
    pub fn contains<T: CBOREncodable>(&self, value: T) -> Result<bool> {
        self.0.contains_key(value)
    }
}

impl Set {
    pub fn as_vec(&self) -> Vec<CBOR> {
        self.0.iter().map(|(_, v)| v.clone()).collect()
    }

    /// A set of `values`, in any order, refused with
    /// [`Error::DuplicateMapKey`] when two of them have one canonical
    /// encoding ([`Self::insert`]): no element is ever silently dropped. An
    /// element that does not encode is refused with its own error, at any
    /// depth of nesting.
    pub fn try_from_values<I>(values: I) -> Result<Self>
    where
        I: IntoIterator,
        I::Item: CBOREncodable,
    {
        let mut set = Set::new();
        for value in values {
            set.insert(value)?;
        }
        Ok(set)
    }

    /// A set of `vec`, whose elements must come in canonical order, each
    /// encoding after the one before it, as a decoded set's do: refused with
    /// [`Error::MisorderedMapKey`] or [`Error::DuplicateMapKey`] otherwise,
    /// and an element that does not encode with its own error.
    pub fn try_from_vec<T: CBOREncodable>(vec: Vec<T>) -> Result<Self> {
        let mut set = Set::new();
        for item in vec {
            set.insert_next(item.into_encoded_cbor()?)?;
        }
        Ok(set)
    }

    pub fn cbor_data(&self) -> Vec<u8> {
        CBOR::from(self).to_cbor_data()
    }
}

/// The set's elements moved into the array, in canonical order.
impl From<Set> for CBOR {
    fn from(value: Set) -> Self {
        CBORCase::Array(value.0.into_values().collect()).into()
    }
}

/// The set's elements, in canonical order, each a cloned handle (a reference
/// count, never the element's case): the array the output needs and nothing
/// else. Cloning the set first would also copy its internal keys, each
/// element's encoded bytes, only to drop them.
impl From<&Set> for CBOR {
    fn from(value: &Set) -> Self {
        CBORCase::Array(value.as_vec()).into()
    }
}

impl<T: CBOREncodable> TryFrom<Vec<T>> for Set {
    type Error = Error;

    fn try_from(vec: Vec<T>) -> Result<Self> {
        Self::try_from_vec(vec)
    }
}

/// The elements of `set`, each moved out in canonical order and converted
/// lazily, the conversion's error carried per element. No element is
/// cloned.
fn converted<T>(set: Set) -> impl Iterator<Item = Result<T>>
where
    T: TryFrom<CBOR>,
    Error: From<T::Error>,
{
    set.0
        .into_values()
        .map(|element| T::try_from(element).map_err(Error::from))
}

/// A hash set of `items`, the first conversion failure returned, and
/// [`Error::DuplicateMapKey`] when two items are equal: distinct source
/// elements a coarser `T` equates are refused, never silently collapsed into
/// one. The one definition every hash set decoder uses (from a [`Set`], and
/// from an array, `array.rs`).
pub(crate) fn distinct<T, S>(items: impl Iterator<Item = Result<T>>) -> Result<HashSet<T, S>>
where
    T: Eq + hash::Hash,
    S: hash::BuildHasher + Default,
{
    let mut set = HashSet::with_hasher(S::default());
    for item in items {
        if !set.insert(item?) {
            return Err(Error::DuplicateMapKey);
        }
    }
    Ok(set)
}

impl<T> TryFrom<Set> for Vec<T>
where
    T: TryFrom<CBOR>,
    Error: From<T::Error>,
{
    type Error = Error;

    fn try_from(set: Set) -> Result<Self> {
        converted(set).collect()
    }
}

/// A hash set encodes as a CBOR array sorted by its elements' encodings,
/// through a [`Set`] ([`Set::try_from_values`]): the same bytes whatever the
/// set's insertion order or hasher, and two elements of one encoding (`10`
/// and `10.0`; `"\u{e9}"` and `"e\u{301}"`) refused with
/// [`Error::DuplicateMapKey`], since deduplicating would drop an element
/// silently and emitting both would change the set's size when it is decoded.
impl<T: CBOREncodable, S> CBOREncodable for HashSet<T, S> {
    fn encode_cbor(&self) -> Result<CBOR> {
        Ok(Set::try_from_values(self)?.into())
    }

    /// The elements moved into the set, each encoded by value.
    fn into_encoded_cbor(self) -> Result<CBOR> {
        Ok(Set::try_from_values(self)?.into())
    }
}

impl<T, S> TryFrom<Set> for HashSet<T, S>
where
    T: TryFrom<CBOR> + Eq + hash::Hash,
    S: hash::BuildHasher + Default,
    Error: From<T::Error>,
{
    type Error = Error;

    fn try_from(set: Set) -> Result<Self> {
        distinct(converted(set))
    }
}

impl fmt::Debug for Set {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.as_vec())
    }
}

#[derive(Debug)]
pub struct SetIter<'a>(MapIter<'a>);

impl<'a> SetIter<'a> {
    pub fn new(iter: MapIter<'a>) -> Self {
        Self(iter)
    }
}

impl<'a> Iterator for SetIter<'a> {
    type Item = &'a CBOR;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next().map(|(_, v)| v)
    }
}

/// Every test here builds its hash sets from `core` hashers and collection,
/// so it runs in every domain: the standard library's `HashSet` with `std`,
/// hashbrown's without it.
#[cfg(test)]
mod tests {
    use super::*;
    use core::hash::{BuildHasher, BuildHasherDefault, Hasher};

    /// A hasher under which every element collides, so the table's order is
    /// its insertion order.
    #[derive(Default)]
    struct Collisions;

    impl Hasher for Collisions {
        fn finish(&self) -> u64 {
            0
        }
        fn write(&mut self, _: &[u8]) {}
    }

    /// A hasher that spreads its input (FNV-1a), so the table's order
    /// follows the elements' hashes, not their insertion.
    struct Spread(u64);

    impl Default for Spread {
        fn default() -> Self {
            Spread(0xcbf2_9ce4_8422_2325)
        }
    }

    impl Hasher for Spread {
        fn finish(&self) -> u64 {
            self.0
        }
        fn write(&mut self, bytes: &[u8]) {
            for &byte in bytes {
                self.0 = (self.0 ^ u64::from(byte)).wrapping_mul(0x0100_0000_01b3);
            }
        }
    }

    /// A hash set of `elements`, inserted in order, under the hasher `S`.
    fn hash_set<T, S>(elements: impl IntoIterator<Item = T>) -> HashSet<T, S>
    where
        T: Eq + hash::Hash,
        S: BuildHasher + Default,
    {
        elements.into_iter().collect()
    }

    /// One hash set's bytes are the same whatever its insertion order and
    /// hasher: its elements sorted by their encodings.
    #[test]
    fn a_hash_sets_bytes_do_not_depend_on_insertion_order_or_hasher() {
        type Colliding = BuildHasherDefault<Collisions>;
        type Spreading = BuildHasherDefault<Spread>;
        let elements = [300u64, 1, 24, 0, 1000, 23];
        let forward: HashSet<u64, Colliding> = hash_set(elements);
        let backward: HashSet<u64, Colliding> = hash_set(elements.into_iter().rev());
        let spread: HashSet<u64, Spreading> = hash_set(elements);
        let spread_backward: HashSet<u64, Spreading> = hash_set(elements.into_iter().rev());
        let expected = forward.encode_cbor_data().unwrap();
        assert_eq!(backward.encode_cbor_data().unwrap(), expected);
        assert_eq!(spread.encode_cbor_data().unwrap(), expected);
        assert_eq!(spread_backward.encode_cbor_data().unwrap(), expected);
        assert_eq!(
            expected,
            [
                0x86, 0x00, 0x01, 0x17, 0x18, 0x18, 0x19, 0x01, 0x2c, 0x19, 0x03, 0xe8
            ]
        );
    }

    /// Two elements of one canonical encoding are refused, never
    /// deduplicated: numerically equal after reduction, and NFC-equal text.
    #[test]
    fn a_hash_set_refuses_elements_of_one_encoding() {
        let texts: HashSet<String, BuildHasherDefault<Spread>> =
            hash_set(["\u{e9}", "e\u{301}"].map(String::from));
        assert!(matches!(texts.encode_cbor(), Err(Error::DuplicateMapKey)));
        let mut set = Set::new();
        set.insert(10).unwrap();
        let before = set.clone();
        assert!(matches!(set.insert(10.0), Err(Error::DuplicateMapKey)));
        assert_eq!(set, before, "a refused insertion changed the set");
    }

    /// Membership takes any encodable value, compared by its canonical
    /// encoding; a value that does not encode is refused with its own error.
    #[test]
    fn membership_propagates_an_element_that_does_not_encode() {
        let set = Set::try_from_values([10u64, 11]).unwrap();
        assert!(set.contains(10.0).unwrap());
        assert!(!set.contains(12).unwrap());
        let colliding: HashSet<String, BuildHasherDefault<Spread>> =
            hash_set(["\u{e9}", "e\u{301}"].map(String::from));
        assert!(matches!(
            set.contains(&colliding),
            Err(Error::DuplicateMapKey)
        ));
    }

    /// A set's owned and borrowed encodings agree with its conversion, and a
    /// hash set's owned and borrowed encodings agree.
    #[test]
    fn owned_and_borrowed_set_encodings_agree() {
        let set = Set::try_from_values([300u64, 1]).unwrap();
        let borrowed = set.encode_cbor().unwrap();
        assert_eq!(set.clone().into_encoded_cbor().unwrap(), borrowed);
        assert_eq!(CBOR::from(set.clone()), borrowed);
        assert_eq!(CBOR::from(&set), borrowed);
        assert_eq!(borrowed.to_cbor_data(), set.cbor_data());
        let hashed: HashSet<u64, BuildHasherDefault<Spread>> = hash_set([300, 1]);
        assert_eq!(
            hashed.encode_cbor().unwrap(),
            hashed.clone().into_encoded_cbor().unwrap()
        );
        assert_eq!(hashed.encode_cbor().unwrap(), borrowed);
    }
}
