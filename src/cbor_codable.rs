import_stdlib!();

use half::f16;

use crate::{
    ByteString, CBOR, CBORCase, Date, Map, MinimalBigInt, Result, Set, Simple, StabilizedText,
};

/// # CBOR Encoding and Decoding Traits
///
/// These traits provide functionality for converting between Rust types and
/// CBOR data. They form the foundation of the dCBOR serialization
/// infrastructure.
///
/// The main traits are:
///
/// - `CBOREncodable`: For types that can be encoded to CBOR
/// - `CBORDecodable`: For types that can be decoded from CBOR
/// - `CBORCodable`: For types that can do both (a combination of the above)
///
/// A trait for types that can be encoded to dCBOR: the one encoding trait,
/// whose encoding may fail.
///
/// Encoding fails where the value has no dCBOR form: a host map or set two of
/// whose keys or elements reduce to one canonical encoding
/// ([`crate::Error::DuplicateMapKey`]; numeric reduction makes `10` and
/// `10.0` one key, NFC makes `"\u{e9}"` and `"e\u{301}"` one), at any depth
/// of nesting, through arrays, options, maps, sets, tagged values and
/// derived records alike. A failure is returned, never replaced by a panic
/// or a partial encoding.
///
/// The types whose `From<_> for CBOR` cannot fail (integers, floats,
/// `bool`, text, byte strings, [`CBOR`], [`CBORCase`], [`Map`], [`Set`],
/// [`Date`], [`Simple`], [`StabilizedText`], [`crate::MinimalBigInt`], and
/// the num-bigint integers) implement it by that conversion, so the two
/// agree wherever both apply; that conversion stays their infallible form,
/// and the owned encoding moves the value into it. Every other type
/// implements it explicitly: sequences, options, boxes and references by
/// their elements, host maps through [`Map::try_from_pairs`], host sets
/// through [`Set::try_from_values`], and derived records by the derive.
///
/// The methods have their own names, apart from [`CBOR::to_cbor_data`], the
/// inherent serialization of a value already symbolic, which cannot fail:
/// the fallible encoding is `encode_cbor_data`, never a second
/// `to_cbor_data` that a concrete `CBOR` receiver would shadow.
///
/// ## Example
///
/// ```
/// use dcbor::prelude::*;
///
/// # fn main() -> dcbor::Result<()> {
/// // A type of fields that encode: each field's encoding, any failure
/// // returned.
/// struct Person {
///     name: String,
///     age: u8,
/// }
///
/// impl CBOREncodable for Person {
///     fn encode_cbor(&self) -> dcbor::Result<CBOR> {
///         let mut map = Map::new();
///         map.insert("name", &self.name)?;
///         map.insert("age", self.age)?;
///         Ok(map.into())
///     }
/// }
///
/// let person = Person { name: "Alice".to_string(), age: 30 };
/// let cbor = person.encode_cbor()?;
/// let data = person.encode_cbor_data()?;
/// assert_eq!(data, cbor.to_cbor_data());
///
/// // A collision at any depth is refused: the two keys are distinct Rust
/// // strings and one NFC text.
/// let mut inner = std::collections::BTreeMap::new();
/// inner.insert("\u{e9}".to_string(), 1);
/// inner.insert("e\u{301}".to_string(), 2);
/// assert!(matches!(
///     vec![inner].encode_cbor(),
///     Err(dcbor::Error::DuplicateMapKey)
/// ));
/// # Ok(())
/// # }
/// ```
pub trait CBOREncodable {
    /// This value's dCBOR encoding, symbolic.
    fn encode_cbor(&self) -> Result<CBOR>;

    /// This value's dCBOR encoding, taking the value: an owned value's
    /// storage (a text, a byte string, a symbolic value, a map, the elements
    /// of a vector or set) moves into the encoding rather than being copied.
    /// The default encodes by reference, for types holding nothing to move.
    fn into_encoded_cbor(self) -> Result<CBOR>
    where
        Self: Sized,
    {
        self.encode_cbor()
    }

    /// This value's dCBOR encoding, serialized: [`Self::encode_cbor`], then
    /// [`CBOR::to_cbor_data`].
    fn encode_cbor_data(&self) -> Result<Vec<u8>> {
        Ok(self.encode_cbor()?.to_cbor_data())
    }
}

/// The types whose conversion into [`CBOR`] cannot fail: their encoding is
/// that conversion, so the two agree by construction. The owned encoding
/// moves the value into the conversion. The borrowed encoding is the
/// borrowed conversion where one exists (`by reference`), which reads the
/// value in place; otherwise the value is cloned into the owned conversion,
/// a clone the output needs (a scalar's copy, a text's or byte string's own
/// storage, a symbolic value's reference count).
macro_rules! infallible {
    (by value: $($ty:ty),* $(,)?) => {$(
        impl CBOREncodable for $ty {
            fn encode_cbor(&self) -> Result<CBOR> {
                Ok(CBOR::from(self.clone()))
            }

            fn into_encoded_cbor(self) -> Result<CBOR> {
                Ok(CBOR::from(self))
            }
        }
    )*};
    (by reference: $($ty:ty),* $(,)?) => {$(
        impl CBOREncodable for $ty {
            fn encode_cbor(&self) -> Result<CBOR> {
                Ok(CBOR::from(self))
            }

            fn into_encoded_cbor(self) -> Result<CBOR> {
                Ok(CBOR::from(self))
            }
        }
    )*};
}

infallible!(by value:
    u8,
    u16,
    u32,
    u64,
    usize,
    i8,
    i16,
    i32,
    i64,
    bool,
    f16,
    f32,
    f64,
    String,
    ByteString,
    CBOR,
    CBORCase,
    Date,
    Simple,
    StabilizedText,
);

infallible!(by reference: Map, Set, MinimalBigInt);

#[cfg(feature = "num-bigint")]
infallible!(by reference: crate::BigInt, crate::BigUint);

impl CBOREncodable for str {
    fn encode_cbor(&self) -> Result<CBOR> {
        Ok(CBOR::from(self))
    }
}

/// A reference encodes as what it refers to.
impl<T: CBOREncodable + ?Sized> CBOREncodable for &T {
    fn encode_cbor(&self) -> Result<CBOR> {
        (**self).encode_cbor()
    }
}

/// A box encodes as what it holds, its content moved out by the owned
/// encoding.
impl<T: CBOREncodable> CBOREncodable for Box<T> {
    fn encode_cbor(&self) -> Result<CBOR> {
        (**self).encode_cbor()
    }

    fn into_encoded_cbor(self) -> Result<CBOR> {
        (*self).into_encoded_cbor()
    }
}

/// A boxed text encodes as the text.
impl CBOREncodable for Box<str> {
    fn encode_cbor(&self) -> Result<CBOR> {
        (**self).encode_cbor()
    }

    /// The text moved into a `String`, without a copy, then into the value.
    fn into_encoded_cbor(self) -> Result<CBOR> {
        self.into_string().into_encoded_cbor()
    }
}

/// A boxed slice encodes as the slice, its elements moved out by the owned
/// encoding.
impl<T: CBOREncodable> CBOREncodable for Box<[T]> {
    fn encode_cbor(&self) -> Result<CBOR> {
        (**self).encode_cbor()
    }

    fn into_encoded_cbor(self) -> Result<CBOR> {
        self.into_vec().into_encoded_cbor()
    }
}

/// `None` is null and `Some(v)` is `v`, as the bounded encoding of a
/// standalone option writes it (`bounded/encoding/values.rs`); so `None` and
/// `Some(null)` have one encoding.
impl<T: CBOREncodable> CBOREncodable for Option<T> {
    fn encode_cbor(&self) -> Result<CBOR> {
        match self {
            Some(value) => value.encode_cbor(),
            None => Ok(CBOR::null()),
        }
    }

    fn into_encoded_cbor(self) -> Result<CBOR> {
        match self {
            Some(value) => value.into_encoded_cbor(),
            None => Ok(CBOR::null()),
        }
    }
}

/// A trait for types that can be decoded from CBOR.
///
/// This trait is automatically implemented for any type that implements
/// `TryFrom<CBOR>`. It serves as a marker trait to indicate that a type
/// supports being created from CBOR data.
///
/// ## Example
///
/// ```
/// use dcbor::prelude::*;
///
/// // Custom type that implements TryFrom<CBOR>
/// struct Person {
///     name: String,
///     age: u8,
/// }
///
/// // Implement conversion from CBOR
/// impl TryFrom<CBOR> for Person {
///     type Error = dcbor::Error;
///
///     fn try_from(cbor: CBOR) -> dcbor::Result<Self> {
///         if let CBORCase::Map(map) = cbor.into_case() {
///             let name: String = map.extract("name")?;
///             let age: u8 = map.extract("age")?;
///             Ok(Person { name, age })
///         } else {
///             Err("Expected a CBOR map".into())
///         }
///     }
/// }
///
/// // The CBORDecodable trait is automatically implemented
/// // Convert a CBOR object to our type
///
/// // Create a sample CBOR map
/// let mut map = Map::new();
/// map.insert("name", "Alice").unwrap();
/// map.insert("age", 42).unwrap();
/// let cbor = CBOR::from(map);
///
/// // Parse from CBOR to our type
/// let person: Person = cbor.try_into().unwrap();
/// assert_eq!((person.name.as_str(), person.age), ("Alice", 42));
/// ```
pub trait CBORDecodable: TryFrom<CBOR, Error = crate::Error> {
    fn try_from_cbor(cbor: &CBOR) -> crate::Result<Self> {
        Self::try_from(cbor.clone())
    }
}

impl<T> CBORDecodable for T where T: TryFrom<CBOR, Error = crate::Error> {}

/// A trait for types that can be both encoded to and decoded from CBOR.
///
/// This trait is automatically implemented for any type that implements both
/// `CBOREncodable` and `CBORDecodable`. It serves as a convenience marker trait
/// to indicate full CBOR serialization support.
///
/// ## Example
///
/// ```
/// use dcbor::prelude::*;
///
/// # fn main() -> dcbor::Result<()> {
/// // Custom type that implements both directions
/// struct Person {
///     name: String,
///     age: u8,
/// }
///
/// impl CBOREncodable for Person {
///     fn encode_cbor(&self) -> dcbor::Result<CBOR> {
///         let mut map = Map::new();
///         map.insert("name", &self.name)?;
///         map.insert("age", self.age)?;
///         Ok(map.into())
///     }
/// }
///
/// impl TryFrom<CBOR> for Person {
///     type Error = dcbor::Error;
///
///     fn try_from(cbor: CBOR) -> dcbor::Result<Self> {
///         if let CBORCase::Map(map) = cbor.into_case() {
///             let name: String = map.extract("name")?;
///             let age: u8 = map.extract("age")?;
///             Ok(Person { name, age })
///         } else {
///             Err("Expected a CBOR map".into())
///         }
///     }
/// }
///
/// // Person now implements CBORCodable: a round trip.
/// let person = Person { name: "Alice".to_string(), age: 30 };
/// let copy = Person::try_from(person.encode_cbor()?)?;
/// assert_eq!(copy.name, "Alice");
/// # Ok(())
/// # }
/// ```
pub trait CBORCodable {}

impl<T> CBORCodable for T where T: CBORDecodable + CBOREncodable {}

#[cfg(test)]
mod tests {
    use super::*;

    /// Where both apply, the infallible conversion and the encoding agree:
    /// the encoding of every infallible type is its conversion, by
    /// reference and by value.
    #[test]
    fn the_infallible_conversions_and_the_encoding_agree() {
        fn agree<T: CBOREncodable + Clone + Into<CBOR>>(value: T) {
            let converted: CBOR = value.clone().into();
            assert_eq!(value.encode_cbor().unwrap(), converted);
            assert_eq!(value.clone().into_encoded_cbor().unwrap(), converted);
            assert_eq!(value.encode_cbor_data().unwrap(), converted.to_cbor_data());
        }
        agree(7u8);
        agree(-7i64);
        agree(1.5f64);
        agree(2.0f32);
        agree(f16::from_f64(0.5));
        agree(true);
        agree(String::from("e\u{301}"));
        agree(ByteString::new([1, 2]));
        agree(CBOR::from("x"));
        agree(Map::new());
        agree(Set::try_from_values([2u8, 1]).unwrap());
        agree(Simple::Null);
        agree(CBORCase::Unsigned(2));
        agree(Date::from_timestamp(1.5));
        agree(StabilizedText::new("x".to_string()).unwrap());
        agree(MinimalBigInt::from(u64::MAX));
        agree(MinimalBigInt::from(i64::MIN));
        assert_eq!("x".encode_cbor().unwrap(), CBOR::from("x"));
        assert_eq!((&&7u8).encode_cbor().unwrap(), CBOR::from(7u8));
        assert_eq!(Box::new(7u8).encode_cbor().unwrap(), CBOR::from(7u8));
    }

    /// A key a map insertion takes may be a symbolic case: its conversion is
    /// infallible and it is encodable.
    #[test]
    fn a_case_is_a_map_key_and_value() {
        let mut map = Map::new();
        map.insert(1u64, CBORCase::Unsigned(2)).unwrap();
        map.insert(CBORCase::Unsigned(3), 4u64).unwrap();
        assert_eq!(
            CBOR::from(map).to_cbor_data(),
            [0xa2, 0x01, 0x02, 0x03, 0x04]
        );
    }

    /// Two distinct strings of one NFC text: a host map of them does not
    /// encode.
    fn failing() -> BTreeMap<String, u8> {
        BTreeMap::from([(String::from("\u{e9}"), 1), (String::from("e\u{301}"), 2)])
    }

    fn refused<T: CBOREncodable>(value: T, what: &str) {
        assert!(
            matches!(value.encode_cbor(), Err(crate::Error::DuplicateMapKey)),
            "{what}: borrowed encoding not refused"
        );
        assert!(
            matches!(value.encode_cbor_data(), Err(crate::Error::DuplicateMapKey)),
            "{what}: serialized encoding not refused"
        );
        assert!(
            matches!(
                value.into_encoded_cbor(),
                Err(crate::Error::DuplicateMapKey)
            ),
            "{what}: owned encoding not refused"
        );
    }

    /// A hash map of `pairs`: the crate's host map in every domain (the
    /// standard library's, or hashbrown's without it), built by collection
    /// so no domain needs an array conversion.
    fn hash_map<K: Eq + hash::Hash, V>(pairs: impl IntoIterator<Item = (K, V)>) -> HashMap<K, V> {
        pairs.into_iter().collect()
    }

    /// A hash set of `elements`, as [`hash_map`].
    fn hash_set<T: Eq + hash::Hash>(elements: impl IntoIterator<Item = T>) -> HashSet<T> {
        elements.into_iter().collect()
    }

    /// A value that does not encode refuses every container holding it, by
    /// reference, serialized and by value, its own error propagated; in every
    /// domain.
    #[test]
    fn a_nested_failure_refuses_every_container() {
        refused(failing(), "map");
        refused(vec![BTreeMap::new(), failing()], "vector");
        refused([failing()], "array");
        refused(VecDeque::from([failing()]), "deque");
        refused(vec![failing()].as_slice(), "slice");
        refused(Some(failing()), "option");
        // The reference impl itself (`&T`), named so the borrow is the case.
        refused::<&BTreeMap<String, u8>>(&failing(), "reference");
        refused(Box::new(failing()), "box");
        refused(vec![failing()].into_boxed_slice(), "boxed slice");
        refused(BTreeMap::from([(0u8, failing())]), "map value");
        refused(BTreeMap::from([(failing(), 0u8)]), "map key");
        refused(hash_map([(0u8, failing())]), "hash map value");
        refused(hash_map([(failing(), 0u8)]), "hash map key");
        refused(hash_set([vec![failing()]]), "hash set element");
        refused(Some(vec![Some(Box::new(failing()))]), "deep nesting");
    }

    /// A tagged value whose untagged encoding fails is refused tagged and
    /// untagged with that failure.
    #[test]
    fn a_nested_failure_refuses_a_tagged_value() {
        use crate::{CBORTagged, CBORTaggedEncodable, Tag};
        struct Wrapped(BTreeMap<String, u8>);
        impl CBORTagged for Wrapped {
            fn cbor_tags() -> Vec<Tag> {
                vec![Tag::with_value(40_000)]
            }
        }
        impl CBORTaggedEncodable for Wrapped {
            fn untagged_cbor(&self) -> Result<CBOR> {
                self.0.encode_cbor()
            }
        }
        let wrapped = Wrapped(failing());
        assert!(matches!(
            wrapped.untagged_cbor(),
            Err(crate::Error::DuplicateMapKey)
        ));
        assert!(matches!(
            wrapped.tagged_cbor(),
            Err(crate::Error::DuplicateMapKey)
        ));
        assert!(matches!(
            wrapped.tagged_cbor_data(),
            Err(crate::Error::DuplicateMapKey)
        ));
        let accepted = Wrapped(BTreeMap::from([(String::from("a"), 1)]));
        assert_eq!(
            accepted.tagged_cbor_data().unwrap(),
            [0xd9, 0x9c, 0x40, 0xa1, 0x61, b'a', 0x01]
        );
    }

    /// Owned and borrowed encodings agree for every type implementing both:
    /// containers, boxes, options, host maps and sets; in every domain. This
    /// is equal bytes only: what each path clones is
    /// `encodings_and_sorts_clone_only_what_they_return`'s.
    #[test]
    fn owned_and_borrowed_encodings_agree() {
        fn agree<T: CBOREncodable + Clone>(value: T) {
            let borrowed = value.encode_cbor().unwrap();
            assert_eq!(value.clone().into_encoded_cbor().unwrap(), borrowed);
            assert_eq!(value.encode_cbor_data().unwrap(), borrowed.to_cbor_data());
        }
        let map = BTreeMap::from([(String::from("a"), vec![1u8, 2])]);
        agree(map.clone());
        agree(hash_map([(1u8, String::from("x"))]));
        agree(hash_set([3u8, 1, 2]));
        agree(MinimalBigInt::from(u64::MAX));
        agree(Map::try_from_pairs([(1u8, 2u8)]).unwrap());
        agree(vec![map.clone(), BTreeMap::new()]);
        agree([map.clone()]);
        agree(VecDeque::from([1u8, 2]));
        agree(Some(map.clone()));
        agree(None::<BTreeMap<String, u8>>);
        agree(Box::new(map.clone()));
        agree(Box::<str>::from("text"));
        agree(vec![1u8, 2].into_boxed_slice());
        agree(String::from("e\u{301}"));
        agree(ByteString::new([1, 2]));
    }

    /// Every clone of a [`Counted`], counted apart from the element itself so
    /// the element holds no interior mutability: a set's key whose hash and
    /// equality cannot change while it is stored, in every build. Only
    /// [`encodings_and_sorts_clone_only_what_they_return`] makes a `Counted`,
    /// so no other test moves the count.
    static COUNTED_CLONES: core::sync::atomic::AtomicUsize =
        core::sync::atomic::AtomicUsize::new(0);

    /// The clones of every [`Counted`] since the last reset.
    fn counted_clones() -> usize {
        COUNTED_CLONES.load(core::sync::atomic::Ordering::SeqCst)
    }

    /// An element whose clones are counted ([`COUNTED_CLONES`]); equal,
    /// ordered and hashed by its number, its whole state.
    #[derive(Debug)]
    struct Counted {
        number: u64,
    }

    impl Clone for Counted {
        fn clone(&self) -> Self {
            COUNTED_CLONES.fetch_add(1, core::sync::atomic::Ordering::SeqCst);
            Counted {
                number: self.number,
            }
        }
    }

    impl PartialEq for Counted {
        fn eq(&self, other: &Self) -> bool {
            self.number == other.number
        }
    }

    impl Eq for Counted {}

    impl hash::Hash for Counted {
        fn hash<H: hash::Hasher>(&self, state: &mut H) {
            self.number.hash(state);
        }
    }

    impl CBOREncodable for Counted {
        fn encode_cbor(&self) -> Result<CBOR> {
            Ok(CBOR::from(self.number))
        }
    }

    /// Encoding clones no element, by reference or by value; sorting a
    /// borrowed collection clones each element exactly once, into the
    /// vector it returns. Counted against the elements' clone counter
    /// ([`COUNTED_CLONES`]), so a second copy anywhere on the path fails,
    /// which equal bytes alone cannot show.
    #[test]
    fn encodings_and_sorts_clone_only_what_they_return() {
        use crate::CBORSortable;
        use core::sync::atomic::Ordering;
        COUNTED_CLONES.store(0, Ordering::SeqCst);
        let counted = |number| Counted { number };
        let elements = [300u64, 1, 24];
        let set: HashSet<Counted> = elements.iter().map(|&n| counted(n)).collect();
        let vec: Vec<Counted> = elements.iter().map(|&n| counted(n)).collect();
        let deque: VecDeque<Counted> = elements.iter().map(|&n| counted(n)).collect();
        let map: BTreeMap<u64, Counted> = elements.iter().map(|&n| (n, counted(n))).collect();
        let table: HashMap<u64, Counted> = elements.iter().map(|&n| (n, counted(n))).collect();
        assert_eq!(counted_clones(), 0);

        set.encode_cbor().unwrap();
        vec.encode_cbor().unwrap();
        deque.encode_cbor().unwrap();
        map.encode_cbor().unwrap();
        table.encode_cbor().unwrap();
        Some(&vec).encode_cbor().unwrap();
        assert_eq!(counted_clones(), 0, "a borrowed encoding cloned an element");

        let sorted = set.sort_by_cbor_encoding().unwrap();
        assert_eq!(counted_clones(), 3, "a set's sort clones each element once");
        assert_eq!(
            sorted.iter().map(|c| c.number).collect::<Vec<_>>(),
            [1, 24, 300]
        );
        vec.sort_by_cbor_encoding().unwrap();
        assert_eq!(
            counted_clones(),
            6,
            "a vector's sort clones each element once"
        );
        COUNTED_CLONES.store(0, Ordering::SeqCst);

        set.into_encoded_cbor().unwrap();
        vec.into_encoded_cbor().unwrap();
        deque.into_encoded_cbor().unwrap();
        map.into_encoded_cbor().unwrap();
        table.into_encoded_cbor().unwrap();
        Box::new(sorted).into_encoded_cbor().unwrap();
        assert_eq!(counted_clones(), 0, "an owned encoding cloned an element");
    }

    /// A decoded type that is not `Clone`: every collection decoder takes it.
    #[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
    struct Unclonable(u64);

    impl TryFrom<CBOR> for Unclonable {
        type Error = crate::Error;

        fn try_from(cbor: CBOR) -> Result<Self> {
            Ok(Unclonable(u64::try_from(cbor)?))
        }
    }

    /// Every collection decoder converts each element by value and needs no
    /// `Clone`: sequences, sets, host maps (keys and values), and a set
    /// decoded from [`Set`]; an element that does not convert refuses the
    /// whole collection with its own error. In every domain.
    #[test]
    fn collection_decoders_need_no_clone() {
        let array = CBOR::from(vec![2u64, 1]);
        let decoded: Vec<Unclonable> = array.clone().try_into().unwrap();
        assert_eq!(decoded, [Unclonable(2), Unclonable(1)]);
        let decoded: VecDeque<Unclonable> = array.clone().try_into().unwrap();
        assert_eq!(decoded.len(), 2);
        let decoded: HashSet<Unclonable> = array.try_into().unwrap();
        assert!(decoded.contains(&Unclonable(1)));
        let map = CBOR::from(Map::try_from_pairs([(1u64, 10u64), (2, 20)]).unwrap());
        let decoded: BTreeMap<Unclonable, Unclonable> = map.clone().try_into().unwrap();
        assert_eq!(decoded.get(&Unclonable(2)), Some(&Unclonable(20)));
        let decoded: HashMap<Unclonable, Unclonable> = map.clone().try_into().unwrap();
        assert_eq!(decoded.get(&Unclonable(1)), Some(&Unclonable(10)));
        let decoded: HashMap<CBOR, CBOR> = map.try_into().unwrap();
        assert_eq!(decoded.get(&CBOR::from(1u64)), Some(&CBOR::from(10u64)));
        let set = Set::try_from_values([5u64, 4]).unwrap();
        let decoded: Vec<Unclonable> = set.clone().try_into().unwrap();
        assert_eq!(decoded, [Unclonable(4), Unclonable(5)]);
        let decoded: HashSet<Unclonable> = set.try_into().unwrap();
        assert_eq!(decoded.len(), 2);
        let mixed = CBOR::from(vec![CBOR::from(1u64), CBOR::from("x")]);
        assert!(matches!(
            Vec::<Unclonable>::try_from(mixed),
            Err(crate::Error::WrongType)
        ));
    }

    /// A text key equal to another ignoring ASCII case: a destination type
    /// coarser than dCBOR's key equality.
    #[derive(Debug, Eq)]
    struct Caseless(String);

    impl PartialEq for Caseless {
        fn eq(&self, other: &Self) -> bool {
            self.0.eq_ignore_ascii_case(&other.0)
        }
    }

    impl hash::Hash for Caseless {
        fn hash<H: hash::Hasher>(&self, state: &mut H) {
            self.0.to_ascii_lowercase().hash(state);
        }
    }

    impl TryFrom<CBOR> for Caseless {
        type Error = crate::Error;

        fn try_from(cbor: CBOR) -> Result<Self> {
            Ok(Caseless(String::try_from(cbor)?))
        }
    }

    /// Valid source maps and sets whose distinct keys or elements collapse
    /// in the destination type are refused, never one entry silently
    /// replacing or absorbing another: hash maps (text equal ignoring case),
    /// B-tree maps (integers ordered by parity), hash sets from an array and
    /// from a [`Set`], and an array repeating a value into a hash set. The
    /// same sources into a type that keeps them apart decode whole.
    #[test]
    fn decoded_keys_and_elements_collapsing_in_the_destination_are_refused() {
        let map = CBOR::from(Map::try_from_pairs([("A", 1u64), ("a", 2)]).unwrap());
        assert!(matches!(
            HashMap::<Caseless, u64>::try_from(map.clone()),
            Err(crate::Error::DuplicateMapKey)
        ));
        assert_eq!(
            HashMap::<String, u64>::try_from(map.clone()).unwrap().len(),
            2
        );
        assert_eq!(
            BTreeMap::<String, u64>::try_from(map.clone())
                .unwrap()
                .len(),
            2
        );
        let numbers = CBOR::from(Map::try_from_pairs([(1u64, 1u64), (3, 3)]).unwrap());
        assert_eq!(
            BTreeMap::<u64, u64>::try_from(numbers.clone())
                .unwrap()
                .len(),
            2
        );
        assert!(matches!(
            BTreeMap::<Parity, u64>::try_from(numbers),
            Err(crate::Error::DuplicateMapKey)
        ));
        let array = CBOR::from(vec!["A", "a"]);
        assert!(matches!(
            HashSet::<Caseless>::try_from(array.clone()),
            Err(crate::Error::DuplicateMapKey)
        ));
        assert_eq!(HashSet::<String>::try_from(array).unwrap().len(), 2);
        let repeated = CBOR::from(vec![1u64, 1]);
        assert!(matches!(
            HashSet::<u64>::try_from(repeated.clone()),
            Err(crate::Error::DuplicateMapKey)
        ));
        assert_eq!(Vec::<u64>::try_from(repeated).unwrap(), [1, 1]);
        let set = Set::try_from_values(["A", "a"]).unwrap();
        assert!(matches!(
            HashSet::<Caseless>::try_from(set.clone()),
            Err(crate::Error::DuplicateMapKey)
        ));
        assert_eq!(HashSet::<String>::try_from(set).unwrap().len(), 2);
    }

    /// An integer key ordered and compared by its parity alone: a B-tree
    /// map's destination equality coarser than dCBOR's.
    #[derive(Debug)]
    struct Parity(u64);

    impl PartialEq for Parity {
        fn eq(&self, other: &Self) -> bool {
            self.0 % 2 == other.0 % 2
        }
    }

    impl Eq for Parity {}

    impl PartialOrd for Parity {
        fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
            Some(self.cmp(other))
        }
    }

    impl Ord for Parity {
        fn cmp(&self, other: &Self) -> cmp::Ordering {
            (self.0 % 2).cmp(&(other.0 % 2))
        }
    }

    impl TryFrom<CBOR> for Parity {
        type Error = crate::Error;

        fn try_from(cbor: CBOR) -> Result<Self> {
            Ok(Parity(u64::try_from(cbor)?))
        }
    }

    /// `None` is null, and `Some` is its value: the bounded encoding's
    /// standalone option.
    #[test]
    fn an_option_encodes_as_null_or_its_value() {
        assert_eq!(None::<u8>.encode_cbor().unwrap(), CBOR::null());
        assert_eq!(Some(3u8).encode_cbor().unwrap(), CBOR::from(3u8));
        assert_eq!(Some(CBOR::null()).encode_cbor().unwrap(), CBOR::null());
    }
}
