import_stdlib!();

use super::varint::{EncodeVarInt, MajorType};
use crate::{CBOR, CBORCase, CBOREncodable, Error, Result};

/// # Map Support in dCBOR
///
/// A deterministic CBOR map implementation that ensures maps with the same
/// content always produce identical binary encodings, regardless of insertion
/// order.
///
/// ## Deterministic Map Representation
///
/// The `Map` type follows strict deterministic encoding rules as specified by
/// dCBOR:
///
/// - Map keys are always sorted in lexicographic order of their encoded CBOR
///   bytes
/// - Duplicate keys are refused, [`Error::DuplicateMapKey`], never silently
///   replaced: keys are compared after numeric reduction and NFC, so `10`
///   and `10.0`, or `"\u{e9}"` and `"e\u{301}"`, are one key
///   ([`Map::insert`]); [`Map::insert_or_replace`] replaces explicitly
/// - Keys and values can be any type that implements [`CBOREncodable`], a
///   value that does not encode refused with its own error
/// - Numeric reduction is applied (e.g., 3.0 is stored as integer 3)
///
/// This deterministic encoding ensures that equivalent maps always produce
/// identical byte representations, which is crucial for applications that rely
/// on consistent hashing, digital signatures, or other cryptographic
/// operations.
///
/// ## Features
///
/// The `Map` type provides:
/// - Encodings of standard Rust collections like `HashMap` and `BTreeMap`
///   ([`CBOREncodable`]), refused when two keys collide after numeric
///   reduction or NFC, at any depth of nesting
/// - Type-safe conversions when extracting values with `get<K, V>()` and
///   `extract<K, V>()`
/// - Automatic deterministic ordering of keys
/// - Prevention of duplicate keys
/// - Support for heterogeneous key and value types
///
/// ## Examples
///
/// ### Creating and using maps
///
/// ```
/// use std::collections::HashMap;
///
/// use dcbor::prelude::*;
///
/// # fn main() -> dcbor::Result<()> {
/// // Create a new Map directly
/// let mut map = Map::new();
/// map.insert(1, "one")?; // Integer key
/// map.insert("two", 2)?; // String key
/// map.insert([1, 2, 3], "array key")?; // Array key
/// map.insert(3.0, "numeric reduction")?; // Float key (stored as integer 3)
///
/// // Check the map size
/// assert_eq!(map.len(), 4);
///
/// // Create a CBOR value from the map
/// let cbor_map: CBOR = map.into();
///
/// // Round-trip through binary encoding
/// let encoded = cbor_map.to_cbor_data();
/// let decoded = CBOR::try_from_data(&encoded)?;
///
/// // View the diagnostic representation
/// assert!(decoded.diagnostic_flat().contains(r#""two": 2"#));
/// # Ok(())
/// # }
/// ```
///
/// ### Converting from standard Rust collections
///
/// ```
/// use std::collections::BTreeMap;
///
/// // The crate's `HashMap`: the standard library's, or `hashbrown`'s
/// // without it.
/// use dcbor::{HashMap, prelude::*};
///
/// # fn main() -> dcbor::Result<()> {
/// // Encode a HashMap as a CBOR map
/// let mut hash_map = HashMap::new();
/// hash_map.insert("a", 1);
/// hash_map.insert("b", 2);
/// let cbor_from_hashmap = hash_map.encode_cbor()?;
///
/// // Encode a BTreeMap as a CBOR map
/// let mut btree_map = BTreeMap::new();
/// btree_map.insert("x", "value1");
/// btree_map.insert("y", "value2");
/// let cbor_from_btree = btree_map.encode_cbor()?;
/// assert_eq!(cbor_from_btree.diagnostic_flat(), r#"{"x": "value1", "y": "value2"}"#);
/// # let _ = cbor_from_hashmap;
/// # Ok(())
/// # }
/// ```
///
/// ### Type-safe extraction of values
///
/// ```
/// use dcbor::prelude::*;
///
/// # fn main() -> dcbor::Result<()> {
/// // Create a map with various types
/// let mut typed_map = Map::new();
/// typed_map.insert("number", 42)?;
/// typed_map.insert("text", "hello")?;
/// typed_map.insert("array", vec![1, 2, 3])?;
///
/// // Type-safe extraction
/// let number: i32 = typed_map.extract("number")?;
/// let text: String = typed_map.extract("text")?;
/// let array: Vec<i32> = typed_map.extract("array")?;
///
/// assert_eq!(number, 42);
/// assert_eq!(text, "hello");
/// assert_eq!(array, vec![1, 2, 3]);
///
/// // Using get() for optional extraction
/// let present: Option<i32> = typed_map.get("number")?;
/// let absent: Option<i32> = typed_map.get("missing")?;
///
/// assert_eq!(present, Some(42));
/// assert_eq!(absent, None);
/// assert!(typed_map.contains_key("text")?);
///
/// // A present value of another type is refused, never taken as absent.
/// assert!(typed_map.get::<_, i32>("text").is_err());
/// # Ok(())
/// # }
/// ```
///
/// ## Implementation Details
///
/// The `Map` implementation:
/// - Uses a `BTreeMap` internally to maintain the sorted order of keys
/// - Encodes keys with their CBOR representation for lexicographic sorting
/// - Applies all dCBOR deterministic encoding rules automatically
#[derive(Clone)]
pub struct Map(BTreeMap<MapKey, MapValue>);

impl Map {
    /// Makes a new, empty CBOR `Map`.
    pub fn new() -> Self {
        Map(BTreeMap::new())
    }

    /// Returns the number of entries in the map.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Checks if the map is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Gets an iterator over the entries of the CBOR map, sorted by key.
    ///
    /// Key sorting order is lexicographic by the key's binary-encoded CBOR.
    pub fn iter(&self) -> MapIter<'_> {
        MapIter::new(self.0.values())
    }

    /// Inserts a key-value pair, refused with [`Error::DuplicateMapKey`] when
    /// the map holds the key already. Keys are compared by their canonical
    /// encoding, after numeric reduction and NFC, so `10` and `10.0`, `-0.0`
    /// and `0`, or `"\u{e9}"` and `"e\u{301}"`, are one key (dCBOR §2.5): a
    /// second insertion of either is refused, never a silent replacement. A
    /// key or value that does not encode ([`CBOREncodable`]) is refused with
    /// its own error. Both are encoded before the map is touched, so the map
    /// is unchanged on every refusal. [`Self::insert_or_replace`] replaces an
    /// entry explicitly.
    ///
    /// ```
    /// use dcbor::prelude::*;
    ///
    /// # fn main() -> dcbor::Result<()> {
    /// let mut map = Map::new();
    /// map.insert(10, "ten")?;
    /// assert!(matches!(
    ///     map.insert(10.0, "floating ten"),
    ///     Err(dcbor::Error::DuplicateMapKey)
    /// ));
    /// assert_eq!(map.get::<_, String>(10)?, Some("ten".to_string()));
    /// # Ok(())
    /// # }
    /// ```
    pub fn insert(&mut self, key: impl CBOREncodable, value: impl CBOREncodable) -> Result<()> {
        let key = key.into_encoded_cbor()?;
        let value = value.into_encoded_cbor()?;
        let encoded = MapKey::new(key.to_cbor_data());
        if self.0.contains_key(&encoded) {
            return Err(Error::DuplicateMapKey);
        }
        self.0.insert(encoded, MapValue::new(key, value));
        Ok(())
    }

    /// Sets the value of `key`, inserting the entry or replacing the one the
    /// map holds for it, keys compared by their canonical encoding as in
    /// [`Self::insert`]: the value replaced, if there was one. A key or value
    /// that does not encode is refused with its own error, the map
    /// unchanged.
    ///
    /// ```
    /// use dcbor::prelude::*;
    ///
    /// # fn main() -> dcbor::Result<()> {
    /// let mut map = Map::new();
    /// assert_eq!(map.insert_or_replace(10, "ten")?, None);
    /// assert_eq!(
    ///     map.insert_or_replace(10.0, "floating ten")?,
    ///     Some(CBOR::from("ten"))
    /// );
    /// assert_eq!(map.len(), 1);
    /// # Ok(())
    /// # }
    /// ```
    pub fn insert_or_replace(
        &mut self,
        key: impl CBOREncodable,
        value: impl CBOREncodable,
    ) -> Result<Option<CBOR>> {
        let key = key.into_encoded_cbor()?;
        let value = value.into_encoded_cbor()?;
        Ok(self
            .0
            .insert(MapKey::new(key.to_cbor_data()), MapValue::new(key, value))
            .map(|replaced| replaced.value))
    }

    /// A map of `pairs`, refused with [`Error::DuplicateMapKey`] when two of
    /// them have one canonical key ([`Self::insert`]): no entry is ever
    /// silently dropped. A key or value that does not encode is refused with
    /// its own error, at any depth of nesting.
    pub fn try_from_pairs<T, K, V>(pairs: T) -> Result<Self>
    where
        T: IntoIterator<Item = (K, V)>,
        K: CBOREncodable,
        V: CBOREncodable,
    {
        let mut map = Map::new();
        for (key, value) in pairs {
            map.insert(key, value)?;
        }
        Ok(map)
    }

    /// The entries, keys and values moved out in canonical key order: the
    /// iteration clones no key or value handle. A consumer's
    /// [`CBOR::into_case`] then moves a case wherever that case is uniquely
    /// held; a case shared elsewhere (by another entry, another part of the
    /// value, or the caller) is still copied there.
    pub(crate) fn into_entries(self) -> impl Iterator<Item = (CBOR, CBOR)> {
        self.0.into_values().map(|entry| (entry.key, entry.value))
    }

    /// The values, moved out in canonical key order: a set's elements
    /// ([`crate::Set`]).
    pub(crate) fn into_values(self) -> impl Iterator<Item = CBOR> {
        self.into_entries().map(|(_, value)| value)
    }

    pub(crate) fn insert_next(&mut self, key: CBOR, value: CBOR) -> Result<()> {
        match self.0.last_key_value() {
            None => {
                self.0
                    .insert(MapKey::new(key.to_cbor_data()), MapValue::new(key, value));
                Ok(())
            }
            Some(entry) => {
                let new_key = MapKey::new(key.to_cbor_data());
                if self.0.contains_key(&new_key) {
                    return Err(Error::DuplicateMapKey);
                }
                if entry.0 >= &new_key {
                    return Err(Error::MisorderedMapKey);
                }
                self.0.insert(new_key, MapValue::new(key, value));
                Ok(())
            }
        }
    }

    /// The entry of `key`, compared by its canonical encoding as in
    /// [`Self::insert`]: the one lookup every query reads. A key that does not
    /// encode is refused with its own error, never taken as absent.
    fn entry(&self, key: impl CBOREncodable) -> Result<Option<&MapValue>> {
        Ok(self.0.get(&Self::key(key)?))
    }

    /// The canonical key of `key`: the one definition every lookup and
    /// removal compares by.
    fn key(key: impl CBOREncodable) -> Result<MapKey> {
        Ok(MapKey::new(key.encode_cbor_data()?))
    }

    /// The value of `key` removed from the map and moved out, `None` when
    /// the map holds no such key: no handle is cloned, so a consuming
    /// decoder of the value then holds the map's handle to it (its case
    /// moved by [`CBOR::into_case`] when held nowhere else). A key that does
    /// not encode is refused with its own error, the map unchanged. The
    /// derived decoders' field extraction (`crate::__derive`).
    pub(crate) fn take(&mut self, key: impl CBOREncodable) -> Result<Option<CBOR>> {
        Ok(self.0.remove(&Self::key(key)?).map(|entry| entry.value))
    }

    /// The value of `key`, converted to `V`: `None` when the map holds no
    /// such key. A key that does not encode is refused with its own error,
    /// and a present value that does not convert to `V` with the
    /// conversion's: neither is taken as absent.
    pub fn get<K, V>(&self, key: K) -> Result<Option<V>>
    where
        K: CBOREncodable,
        V: TryFrom<CBOR>,
        Error: From<V::Error>,
    {
        match self.entry(key)? {
            Some(entry) => Ok(Some(V::try_from(entry.value.clone())?)),
            None => Ok(None),
        }
    }

    /// Whether the map holds `key`, compared by its canonical encoding. A key
    /// that does not encode is refused with its own error.
    pub fn contains_key<K: CBOREncodable>(&self, key: K) -> Result<bool> {
        Ok(self.entry(key)?.is_some())
    }

    /// The value of `key`, converted to `V`, refused with
    /// [`Error::MissingMapKey`] when the map holds no such key, and as
    /// [`Self::get`] refuses otherwise.
    pub fn extract<K, V>(&self, key: K) -> Result<V>
    where
        K: CBOREncodable,
        V: TryFrom<CBOR>,
        Error: From<V::Error>,
    {
        self.get(key)?.ok_or(Error::MissingMapKey)
    }
}

impl Default for Map {
    fn default() -> Self {
        Self::new()
    }
}

impl PartialEq for Map {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Eq for Map {}

impl hash::Hash for Map {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

impl Map {
    pub fn cbor_data(&self) -> Vec<u8> {
        let pairs: Vec<(Vec<u8>, Vec<u8>)> = self
            .0
            .iter()
            .map(|x| {
                let a: Vec<u8> = x.0.0.to_owned();
                let cbor: &CBOR = &x.1.value;
                let b: Vec<u8> = cbor.to_cbor_data();
                (a, b)
            })
            .collect();
        let mut buf = pairs.len().encode_varint(MajorType::Map);
        for pair in pairs {
            buf.extend(pair.0);
            buf.extend(pair.1);
        }
        buf
    }
}

/// The map moved into the value, its tree never copied.
impl From<Map> for CBOR {
    fn from(value: Map) -> Self {
        CBORCase::Map(value).into()
    }
}

impl From<&Map> for CBOR {
    fn from(value: &Map) -> Self {
        value.clone().into()
    }
}

impl fmt::Debug for Map {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

/// Bounded encoding: the map's entries, keyed by their encoded keys, come in
/// canonical key order, so the engine checks each key against the one
/// before it instead of sorting. The tree is walked by its stepped cursor
/// on the bounded-collection standard library, one admitted transition per
/// instruction, and by its standard iterator elsewhere.
impl crate::bounded::encoding::Schema for Map {
    fn instruction(&self, index: usize) -> crate::bounded::encoding::Instruction<'_> {
        use crate::bounded::encoding::Instruction;
        match index {
            0 => Instruction::CountedUnorderedMap(self.0.len() as u64),
            1 => Instruction::Entries(self),
            _ => Instruction::End,
        }
    }
}

// SAFETY: cursor type: `start` stores the tree's own cursor
// (`encoding::values`, `TreeCursor`, `tree_start`), which `next` reads back
// as the same type (`tree_next`). self-reference: the cursor borrows the
// tree, owns nothing and never refers to itself or its slot. transfer: the
// cursor and every entry it yields refer only into the tree's immutable
// symbolic keys and values, transferable in multithreaded builds (`Map`'s
// and `CBOR`'s `TransferableSchema` impls, `values.rs`), and it holds no
// thread-local state. moves: a call makes at most `tree_step_moves` node
// moves beyond its transition, fixed by the tree's length
// (`bounded::tests::a_maps_iteration_order_is_its_encoded_key_order`).
unsafe impl crate::bounded::encoding::Entries for Map {
    fn start(&self, slot: &mut crate::bounded::encoding::Slot) {
        crate::bounded::encoding::tree_start(&self.0, slot);
    }

    fn moves(&self) -> u64 {
        crate::bounded::encoding::tree_step_moves(&self.0)
    }

    /// Keyed by the entries' encoded keys, compared bytewise.
    fn ordered(&self) -> bool {
        true
    }

    unsafe fn next<'a>(
        &'a self,
        slot: &mut crate::bounded::encoding::Slot,
    ) -> crate::bounded::encoding::EntryStep<'a> {
        use crate::bounded::encoding::Schema;
        // SAFETY: `start` stored this tree's cursor.
        unsafe {
            crate::bounded::encoding::tree_next::<MapKey, MapValue>(slot, |_, entry| {
                (&entry.key as &dyn Schema, &entry.value as &dyn Schema)
            })
        }
    }
}

/// An iterator over the entries of a CBOR map.
///
/// This iterator provides a way to traverse the key-value pairs in a CBOR map.
/// It always returns entries in lexicographic order by the key's binary-encoded
/// CBOR value, which is a requirement for deterministic encoding in dCBOR.
///
/// Each item returned by the iterator is a tuple of references to the key and
/// value CBOR objects: `(&'a CBOR, &'a CBOR)`.
///
/// ## Examples
///
/// ```
/// use dcbor::prelude::*;
///
/// # fn main() -> dcbor::Result<()> {
/// // Create a map with several entries
/// let mut map = Map::new();
/// map.insert(1, "one")?;
/// map.insert(2, "two")?;
/// map.insert(3, "three")?;
///
/// // Iterate through the map entries
/// for (key, value) in map.iter() {
///     // Process each key-value pair
///     let k_option: Option<i64> = key.clone().try_into().ok();
///     let v_option: Option<String> = value.clone().try_into().ok();
///
///     if let (Some(k), Some(v)) = (k_option, v_option) {
///         // This would normally print entries in order: 1, 2, 3
///         assert!(k >= 1 && k <= 3);
///         assert!(v == "one" || v == "two" || v == "three");
///     }
/// }
///
/// // Use iterator methods directly
/// let first_entry = map.iter().next().unwrap();
/// let key_as_i64: i64 = first_entry.0.clone().try_into()?;
/// assert_eq!(key_as_i64, 1);
/// # Ok(())
/// # }
/// ```
///
/// Note that unlike standard Rust collections which may have
/// implementation-specific ordering, CBOR maps in dCBOR guarantee deterministic
/// iteration order based on the binary encoding of keys.
#[derive(Debug)]
pub struct MapIter<'a>(BTreeMapValues<'a, MapKey, MapValue>);

impl<'a> MapIter<'a> {
    fn new(values: BTreeMapValues<'a, MapKey, MapValue>) -> MapIter<'a> {
        MapIter(values)
    }
}

impl<'a> Iterator for MapIter<'a> {
    type Item = (&'a CBOR, &'a CBOR);

    fn next(&mut self) -> Option<Self::Item> {
        let entry = self.0.next()?;
        Some((&entry.key, &entry.value))
    }
}

#[derive(Clone, Eq)]
struct MapValue {
    key: CBOR,
    value: CBOR,
}

impl MapValue {
    fn new(key: CBOR, value: CBOR) -> MapValue {
        MapValue { key, value }
    }
}

impl PartialEq for MapValue {
    fn eq(&self, other: &Self) -> bool {
        self.key == other.key && self.value == other.value
    }
}

impl hash::Hash for MapValue {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.key.hash(state);
        self.value.hash(state);
    }
}

impl fmt::Debug for MapValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_fmt(format_args!("({:?}, {:?})", self.key, self.value))
    }
}

#[derive(Clone)]
struct MapKey(Vec<u8>);

impl MapKey {
    fn new(key_data: Vec<u8>) -> MapKey {
        MapKey(key_data)
    }
}

impl PartialEq for MapKey {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Eq for MapKey {}

impl hash::Hash for MapKey {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

impl PartialOrd for MapKey {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for MapKey {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        self.0.cmp(&other.0)
    }
}

impl fmt::Debug for MapKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_fmt(format_args!("0x{}", hex::encode(&self.0)))
    }
}

/// A hash map encodes as a CBOR map, its entries in canonical key order
/// whatever its hasher or insertion order, refused with
/// [`Error::DuplicateMapKey`] when two of its keys have one canonical
/// encoding, and with a key's or value's own error when one does not encode
/// ([`Map::try_from_pairs`]).
impl<K: CBOREncodable, V: CBOREncodable, S> CBOREncodable for HashMap<K, V, S> {
    fn encode_cbor(&self) -> Result<CBOR> {
        Ok(Map::try_from_pairs(self)?.into())
    }

    fn into_encoded_cbor(self) -> Result<CBOR> {
        Ok(Map::try_from_pairs(self)?.into())
    }
}

/// A CBOR map decoded entry by entry, each key and value moved out of the
/// map and converted, the first failure returned. Two distinct CBOR keys
/// that convert to one `K` (a key type equal under a coarser rule than
/// dCBOR's) are refused with [`Error::DuplicateMapKey`], never one entry
/// silently replacing the other. Neither `K` nor `V` is cloned, so neither
/// needs `Clone`. `CBOR` itself converts to `CBOR` (core's reflexive
/// `TryFrom`), so a `HashMap<CBOR, CBOR>` is one instance.
impl<K, V, S> TryFrom<CBOR> for HashMap<K, V, S>
where
    K: TryFrom<CBOR> + cmp::Eq + hash::Hash,
    V: TryFrom<CBOR>,
    S: hash::BuildHasher + Default,
    Error: From<K::Error> + From<V::Error>,
{
    type Error = Error;

    fn try_from(cbor: CBOR) -> Result<Self> {
        match cbor.into_case() {
            CBORCase::Map(map) => {
                let mut container = HashMap::with_hasher(S::default());
                for (key, value) in map.into_entries() {
                    if container
                        .insert(K::try_from(key)?, V::try_from(value)?)
                        .is_some()
                    {
                        return Err(Error::DuplicateMapKey);
                    }
                }
                Ok(container)
            }
            _ => Err(Error::WrongType),
        }
    }
}

/// A B-tree map encodes as a CBOR map, its entries in canonical key order,
/// not the tree's, refused with [`Error::DuplicateMapKey`] when two of its
/// keys, distinct by their own order, have one canonical encoding, and with a
/// key's or value's own error when one does not encode
/// ([`Map::try_from_pairs`]).
impl<K: CBOREncodable, V: CBOREncodable> CBOREncodable for BTreeMap<K, V> {
    fn encode_cbor(&self) -> Result<CBOR> {
        Ok(Map::try_from_pairs(self)?.into())
    }

    fn into_encoded_cbor(self) -> Result<CBOR> {
        Ok(Map::try_from_pairs(self)?.into())
    }
}

/// A CBOR map decoded entry by entry, as a hash map is: each key and value
/// moved out and converted, neither cloned, two keys converting to one `K`
/// refused with [`Error::DuplicateMapKey`].
impl<K, V> TryFrom<CBOR> for BTreeMap<K, V>
where
    K: TryFrom<CBOR> + cmp::Ord,
    V: TryFrom<CBOR>,
    Error: From<K::Error> + From<V::Error>,
{
    type Error = Error;

    fn try_from(cbor: CBOR) -> Result<Self> {
        match cbor.into_case() {
            CBORCase::Map(map) => {
                let mut container = BTreeMap::new();
                for (key, value) in map.into_entries() {
                    if container
                        .insert(K::try_from(key)?, V::try_from(value)?)
                        .is_some()
                    {
                        return Err(Error::DuplicateMapKey);
                    }
                }
                Ok(container)
            }
            _ => Err(Error::WrongType),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A host key whose values are distinct but whose canonical encodings
    /// can coincide: an integer, or a float by its bits, which numeric
    /// reduction turns into the integer when it is integral.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
    enum Number {
        Integer(i64),
        Float(u64),
    }

    impl CBOREncodable for Number {
        fn encode_cbor(&self) -> Result<CBOR> {
            Ok(match *self {
                Number::Integer(value) => value.into(),
                Number::Float(bits) => f64::from_bits(bits).into(),
            })
        }
    }

    fn float(value: f64) -> Number {
        Number::Float(value.to_bits())
    }

    /// A host map whose two keys are one canonical key: a value whose
    /// encoding fails, for the failure-propagation tests.
    fn failing() -> BTreeMap<Number, u64> {
        BTreeMap::from([(Number::Integer(10), 1u64), (float(10.0), 2u64)])
    }

    /// Keys that reduce to one canonical key collide: the second insertion
    /// of each pair is refused and leaves the map as it was.
    #[test]
    fn keys_colliding_after_numeric_reduction_are_refused() {
        for (first, second) in [
            (CBOR::from(10), CBOR::from(10.0)),
            (CBOR::from(10.0), CBOR::from(10)),
            (CBOR::from(-0.0), CBOR::from(0)),
            (CBOR::from(0), CBOR::from(-0.0)),
        ] {
            let mut map = Map::new();
            map.insert(first.clone(), "first").unwrap();
            let before = CBOR::from(map.clone()).to_cbor_data();
            assert!(
                matches!(
                    map.insert(second.clone(), "second"),
                    Err(Error::DuplicateMapKey)
                ),
                "{second:?} after {first:?} is one canonical key"
            );
            assert_eq!(
                CBOR::from(map.clone()).to_cbor_data(),
                before,
                "a refused insertion changed the map"
            );
            assert_eq!(
                map.get::<_, String>(second).unwrap(),
                Some("first".to_string())
            );
        }
    }

    /// Distinct canonical keys are all kept; an explicit replacement returns
    /// the value it replaced and keeps one entry.
    #[test]
    fn distinct_keys_insert_and_replacement_is_explicit() {
        let mut map = Map::new();
        map.insert(10, "ten").unwrap();
        map.insert(10.5, "ten and a half").unwrap();
        map.insert("10", "text").unwrap();
        assert_eq!(map.len(), 3);
        assert_eq!(
            map.insert_or_replace(10.0, "floating ten").unwrap(),
            Some(CBOR::from("ten"))
        );
        assert_eq!(map.insert_or_replace(11, "eleven").unwrap(), None);
        assert_eq!(map.len(), 4);
        assert_eq!(
            map.get::<_, String>(10).unwrap(),
            Some("floating ten".to_string())
        );
    }

    /// Queries take any encodable key, compared by its canonical encoding;
    /// a key that does not encode is refused with its own error, and a
    /// present value of another type with the conversion's, never `None`.
    #[test]
    fn queries_take_encodable_keys_and_propagate_failures() {
        let mut map = Map::new();
        let key = BTreeMap::from([(1u64, 2u64)]);
        map.insert(&key, "keyed by a map").unwrap();
        map.insert("\u{e9}", 1).unwrap();
        assert!(map.contains_key(&key).unwrap());
        assert!(map.contains_key("e\u{301}").unwrap());
        assert!(!map.contains_key(BTreeMap::<u64, u64>::new()).unwrap());
        assert_eq!(
            map.get::<_, String>(&key).unwrap(),
            Some("keyed by a map".to_string())
        );
        assert_eq!(map.extract::<_, u64>("e\u{301}").unwrap(), 1);
        assert!(matches!(
            map.get::<_, u64>(failing()),
            Err(Error::DuplicateMapKey)
        ));
        assert!(matches!(
            map.contains_key(failing()),
            Err(Error::DuplicateMapKey)
        ));
        assert!(matches!(
            map.extract::<_, u64>(failing()),
            Err(Error::DuplicateMapKey)
        ));
        assert!(matches!(map.get::<_, u64>(&key), Err(Error::WrongType)));
        assert!(matches!(
            map.extract::<_, u64>("missing"),
            Err(Error::MissingMapKey)
        ));
        assert_eq!(map.get::<_, u64>("missing").unwrap(), None);
    }

    /// Keys that are distinct Rust strings but one NFC text collide, through
    /// insertion, a B-tree map and a hash map alike.
    #[test]
    fn nfc_equal_text_keys_are_one_key() {
        let composed = String::from("\u{e9}");
        let decomposed = String::from("e\u{301}");
        let mut map = Map::new();
        map.insert(composed.as_str(), 1).unwrap();
        assert!(matches!(
            map.insert(decomposed.as_str(), 2),
            Err(Error::DuplicateMapKey)
        ));
        let tree = BTreeMap::from([(composed.clone(), 1), (decomposed.clone(), 2)]);
        assert!(matches!(tree.encode_cbor(), Err(Error::DuplicateMapKey)));
        let table: HashMap<String, i32> = HashMap::from([(composed, 1), (decomposed, 2)]);
        assert!(matches!(table.encode_cbor(), Err(Error::DuplicateMapKey)));
    }

    /// A failed insertion or replacement, its key colliding or its value not
    /// encoding, leaves the map byte for byte as it was.
    #[test]
    fn a_failed_insertion_or_replacement_leaves_the_map_unchanged() {
        let mut map = Map::new();
        map.insert(1, "one").unwrap();
        let before = CBOR::from(map.clone()).to_cbor_data();
        assert!(matches!(
            map.insert(2, failing()),
            Err(Error::DuplicateMapKey)
        ));
        assert!(matches!(
            map.insert(failing(), 2),
            Err(Error::DuplicateMapKey)
        ));
        assert!(matches!(
            map.insert_or_replace(1, failing()),
            Err(Error::DuplicateMapKey)
        ));
        assert!(matches!(
            map.insert_or_replace(failing(), 1),
            Err(Error::DuplicateMapKey)
        ));
        assert_eq!(CBOR::from(map.clone()).to_cbor_data(), before);
        assert_eq!(map.get::<_, String>(1).unwrap(), Some("one".to_string()));
    }

    /// Building from pairs, and encoding a hash map or a B-tree map, is
    /// refused when two distinct host keys have one canonical encoding, and
    /// succeeds with every entry when none do.
    #[test]
    fn host_maps_refuse_colliding_keys() {
        let colliding = [(Number::Integer(10), "ten"), (float(10.0), "floating ten")];
        let distinct = [
            (Number::Integer(10), "ten"),
            (float(10.5), "ten and a half"),
        ];
        assert!(matches!(
            Map::try_from_pairs(colliding),
            Err(Error::DuplicateMapKey)
        ));
        assert_eq!(Map::try_from_pairs(distinct).unwrap().len(), 2);
        assert!(matches!(
            colliding
                .into_iter()
                .collect::<HashMap<_, _>>()
                .encode_cbor(),
            Err(Error::DuplicateMapKey)
        ));
        assert!(matches!(
            colliding
                .into_iter()
                .collect::<BTreeMap<_, _>>()
                .encode_cbor(),
            Err(Error::DuplicateMapKey)
        ));
        let negative_zero = [(Number::Integer(0), "zero"), (float(-0.0), "negative zero")];
        assert!(matches!(
            negative_zero
                .into_iter()
                .collect::<BTreeMap<_, _>>()
                .encode_cbor(),
            Err(Error::DuplicateMapKey)
        ));
        let encoded = distinct
            .into_iter()
            .collect::<BTreeMap<_, _>>()
            .into_encoded_cbor()
            .unwrap();
        let CBORCase::Map(map) = encoded.into_case() else {
            panic!("a map encodes as a map");
        };
        assert_eq!(map.len(), 2);
    }

    /// Host maps nest in every composition: as values and keys of maps, as
    /// elements of a vector, inside an option, and a collision at any depth is
    /// refused, its error propagated, never a panic.
    #[test]
    fn host_maps_nest_and_refuse_collisions_at_any_depth() {
        let nested = BTreeMap::from([(1u64, BTreeMap::from([(2u64, 3u64)]))]);
        assert_eq!(
            nested.encode_cbor_data().unwrap(),
            [0xa1, 0x01, 0xa1, 0x02, 0x03]
        );
        let keyed = BTreeMap::from([(BTreeMap::from([(1u64, 0u64)]), 7u64)]);
        assert_eq!(
            keyed.encode_cbor_data().unwrap(),
            [0xa1, 0xa1, 0x01, 0x00, 0x07]
        );
        let listed = vec![BTreeMap::from([(1u64, 2u64)]), BTreeMap::new()];
        assert_eq!(
            listed.encode_cbor_data().unwrap(),
            [0x82, 0xa1, 0x01, 0x02, 0xa0]
        );
        let optional: Option<HashMap<u64, u64>> = Some(HashMap::from([(1, 2)]));
        assert_eq!(optional.encode_cbor_data().unwrap(), [0xa1, 0x01, 0x02]);
        let colliding = BTreeMap::from([(0u64, failing())]);
        assert!(matches!(
            colliding.encode_cbor(),
            Err(Error::DuplicateMapKey)
        ));
        assert!(matches!(
            vec![failing()].encode_cbor(),
            Err(Error::DuplicateMapKey)
        ));
        assert!(matches!(
            Some(vec![Some(failing())]).encode_cbor(),
            Err(Error::DuplicateMapKey)
        ));
    }
}
