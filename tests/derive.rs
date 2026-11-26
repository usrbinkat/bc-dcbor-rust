#![cfg(feature = "derive")]

use std::collections::{BTreeMap, HashMap};

use dcbor::prelude::*;
use dcbor::{CBORCodable, CBORDecodable, CBOREncodable};

// --- Named struct with integer keys ---

#[derive(Clone, Debug, PartialEq, CBOREncodable, CBORDecodable)]
struct Person {
    #[cbor(n = 0)]
    name: String,
    #[cbor(n = 1)]
    age: u8,
}

#[test]
fn struct_roundtrip() {
    let p = Person {
        name: "Alice".to_string(),
        age: 30,
    };
    let cbor = p.encode_cbor().unwrap();
    let p2: Person = cbor.try_into().unwrap();
    assert_eq!(p, p2);
}

#[test]
fn struct_deterministic() {
    let p = Person {
        name: "Alice".to_string(),
        age: 30,
    };
    let bytes1 = p.encode_cbor_data().unwrap();
    let bytes2 = p.encode_cbor_data().unwrap();
    assert_eq!(bytes1, bytes2);

    // Decode from bytes and re-encode must produce identical bytes
    let decoded = CBOR::try_from_data(&bytes1).unwrap();
    let p3: Person = decoded.try_into().unwrap();
    let bytes3 = p3.encode_cbor_data().unwrap();
    assert_eq!(bytes1, bytes3);
}

// --- Optional fields ---

#[derive(Clone, Debug, PartialEq, CBOREncodable, CBORDecodable)]
struct PersonOptional {
    #[cbor(n = 0)]
    name: String,
    #[cbor(n = 1)]
    age: u8,
    #[cbor(n = 2)]
    email: Option<String>,
}

#[test]
fn optional_field_present() {
    let p = PersonOptional {
        name: "Bob".to_string(),
        age: 25,
        email: Some("bob@example.com".to_string()),
    };
    let cbor = p.encode_cbor().unwrap();
    let p2: PersonOptional = cbor.try_into().unwrap();
    assert_eq!(p, p2);
}

#[test]
fn optional_field_absent() {
    let p = PersonOptional {
        name: "Carol".to_string(),
        age: 40,
        email: None,
    };
    let cbor = p.encode_cbor().unwrap();
    let p2: PersonOptional = cbor.try_into().unwrap();
    assert_eq!(p, p2);
}

// --- Newtype struct ---

#[test]
fn newtype_roundtrip() {
    let w = Newtype(vec![1, 1000]);
    let cbor = w.encode_cbor().unwrap();
    let w2: Newtype = cbor.try_into().unwrap();
    assert_eq!(w, w2);
}

// --- Enum with unit, tuple, and struct variants ---

#[test]
fn enum_unit_roundtrip() {
    let s = Mixed::Point;
    let cbor = s.encode_cbor().unwrap();
    let s2: Mixed = cbor.try_into().unwrap();
    assert_eq!(s, s2);
}

#[test]
fn enum_tuple_roundtrip() {
    let s = Mixed::Circle(42);
    let cbor = s.encode_cbor().unwrap();
    let s2: Mixed = cbor.try_into().unwrap();
    assert_eq!(s, s2);
}

#[test]
fn enum_struct_roundtrip() {
    let s = Mixed::Frame {
        width: Some(10),
        height: 20,
    };
    let cbor = s.encode_cbor().unwrap();
    let s2: Mixed = cbor.try_into().unwrap();
    assert_eq!(s, s2);
}

// --- Tagged type ---

#[test]
fn tagged_roundtrip() {
    let t = Labelled {
        data: vec![1, 2, 3],
    };
    let tagged_cbor = t.tagged_cbor().unwrap();
    let t2: Labelled = tagged_cbor.try_into().unwrap();
    assert_eq!(t, t2);
}

#[test]
fn tagged_wrong_tag_rejected() {
    let t = Labelled {
        data: vec![1, 2, 3],
    };
    // Encode with correct tag, then re-wrap with wrong tag
    let untagged = t.untagged_cbor().unwrap();
    let wrong_tagged = CBOR::to_tagged_value(99, untagged);
    let result: dcbor::Result<Labelled> = wrong_tagged.try_into();
    assert!(result.is_err());
}

// --- CBORCodable (both at once) ---

#[derive(Clone, Debug, PartialEq, CBORCodable)]
struct Pair {
    #[cbor(n = 0)]
    left: String,
    #[cbor(n = 1)]
    right: u64,
}

#[test]
fn codable_roundtrip() {
    let p = Pair {
        left: "key".to_string(),
        right: 100,
    };
    let bytes = p.encode_cbor_data().unwrap();
    let cbor = CBOR::try_from_data(&bytes).unwrap();
    let p2: Pair = cbor.try_into().unwrap();
    assert_eq!(p, p2);
}

// --- Wrong type rejection ---

#[test]
fn struct_rejects_non_map() {
    let cbor: CBOR = 42u64.into();
    let result: dcbor::Result<Person> = cbor.try_into();
    assert!(result.is_err());
}

#[test]
fn enum_rejects_non_matching() {
    let cbor: CBOR = "not a shape".into();
    let result: dcbor::Result<Mixed> = cbor.try_into();
    assert!(result.is_err());
}

// --- Fallible fields: composition and propagation ---

/// Two distinct Rust strings of one NFC form: one canonical key.
fn colliding() -> BTreeMap<String, u8> {
    BTreeMap::from([("\u{e9}".to_string(), 1), ("e\u{301}".to_string(), 2)])
}

/// The NFC pair as a std hash map, under its default hasher.
fn colliding_hash() -> HashMap<String, u8> {
    HashMap::from([("\u{e9}".to_string(), 1), ("e\u{301}".to_string(), 2)])
}

/// Host collections at every depth a record can hold them; no field type
/// and the record itself implement `Clone`, which the encoding never needs.
#[derive(CBOREncodable)]
struct Holder {
    #[cbor(n = 0)]
    names: BTreeMap<String, u8>,
    #[cbor(n = 1)]
    nested: Vec<BTreeMap<String, u8>>,
    #[cbor(n = 2)]
    optional: Option<HashMap<String, u8>>,
}

#[derive(CBOREncodable)]
struct HolderNewtype(Holder);

#[derive(CBOREncodable)]
enum HolderVariant {
    #[cbor(n = 0)]
    Tuple(u8, BTreeMap<String, u8>),
    #[cbor(n = 1)]
    Named {
        #[cbor(n = 0)]
        inner: Option<Holder>,
    },
}

#[derive(CBOREncodable)]
#[cbor(tag = 40_000)]
struct TaggedHolder {
    #[cbor(n = 0)]
    holder: Holder,
}

fn holder() -> Holder {
    Holder {
        names: BTreeMap::from([("a".to_string(), 1)]),
        nested: vec![BTreeMap::from([("b".to_string(), 2)]), BTreeMap::new()],
        optional: Some(HashMap::from([("c".to_string(), 3)])),
    }
}

fn duplicate<T: std::fmt::Debug>(result: dcbor::Result<T>, what: &str) {
    assert!(
        matches!(result, Err(dcbor::Error::DuplicateMapKey)),
        "{what}: {result:?}"
    );
}

/// Records whose fields hold host maps encode through them: the bytes are
/// the canonical map, nested vector and option included.
#[test]
fn records_holding_host_collections_encode_through_them() {
    let bytes = holder().encode_cbor_data().unwrap();
    assert_eq!(
        bytes,
        [
            0xa3, // map(3)
            0x00, 0xa1, 0x61, b'a', 0x01, // 0: {"a": 1}
            0x01, 0x82, 0xa1, 0x61, b'b', 0x02, 0xa0, // 1: [{"b": 2}, {}]
            0x02, 0xa1, 0x61, b'c', 0x03, // 2: {"c": 3}
        ]
    );
    assert_eq!(
        HolderNewtype(holder()).encode_cbor_data().unwrap(),
        bytes,
        "a newtype is its field's encoding"
    );
    let empty = Holder {
        names: BTreeMap::new(),
        nested: Vec::new(),
        optional: None,
    };
    assert_eq!(
        empty.encode_cbor_data().unwrap(),
        [0xa2, 0x00, 0xa0, 0x01, 0x80]
    );
}

/// A colliding host map refuses the record that holds it, at every depth and
/// shape: a direct field, inside a vector, inside an option (a hash map), a
/// newtype, both variant shapes, and the tagged and untagged encodings of a
/// tagged record. The refusal is the map's own, `DuplicateMapKey`.
#[test]
fn a_colliding_map_refuses_every_record_that_holds_it() {
    duplicate(
        Holder {
            names: colliding(),
            ..holder()
        }
        .encode_cbor(),
        "direct field",
    );
    duplicate(
        Holder {
            nested: vec![BTreeMap::new(), colliding()],
            ..holder()
        }
        .encode_cbor(),
        "vector of maps",
    );
    duplicate(
        Holder {
            optional: Some(colliding_hash()),
            ..holder()
        }
        .encode_cbor(),
        "optional hash map",
    );
    duplicate(
        HolderNewtype(Holder {
            names: colliding(),
            ..holder()
        })
        .encode_cbor_data(),
        "newtype",
    );
    duplicate(
        HolderVariant::Tuple(1, colliding()).encode_cbor(),
        "tuple variant",
    );
    duplicate(
        HolderVariant::Named {
            inner: Some(Holder {
                names: colliding(),
                ..holder()
            }),
        }
        .encode_cbor(),
        "named variant",
    );
    let tagged = TaggedHolder {
        holder: Holder {
            nested: vec![colliding()],
            ..holder()
        },
    };
    duplicate(tagged.untagged_cbor(), "untagged");
    duplicate(tagged.tagged_cbor(), "tagged");
    duplicate(tagged.tagged_cbor_data(), "tagged data");
    duplicate(vec![tagged].encode_cbor(), "a vector of tagged records");
}

/// The control: without the collision, each of those shapes encodes, so the
/// refusals above are the collision's.
#[test]
fn the_same_shapes_without_a_collision_encode() {
    holder().encode_cbor().unwrap();
    HolderNewtype(holder()).encode_cbor().unwrap();
    // The discriminant, then the two payload values: an array of three.
    assert_eq!(
        HolderVariant::Tuple(1, BTreeMap::new())
            .encode_cbor_data()
            .unwrap(),
        [0x83, 0x00, 0x01, 0xa0]
    );
    HolderVariant::Named {
        inner: Some(holder()),
    }
    .encode_cbor()
    .unwrap();
    assert_eq!(
        HolderVariant::Named { inner: None }
            .encode_cbor_data()
            .unwrap(),
        [0x82, 0x01, 0xa0]
    );
    let tagged = TaggedHolder { holder: holder() };
    let untagged = tagged.untagged_cbor().unwrap();
    assert_eq!(
        tagged.tagged_cbor().unwrap(),
        CBOR::to_tagged_value(40_000, untagged.clone())
    );
    assert_eq!(tagged.encode_cbor().unwrap(), untagged);
}

// --- Ownership: what each encoding path clones ---

/// What happened to the [`Counted`] fields: clones made, and which of their
/// two encodings was called, each counted apart.
#[derive(Default)]
struct Calls {
    clones: std::cell::Cell<usize>,
    borrowed: std::cell::Cell<usize>,
    owned: std::cell::Cell<usize>,
}

impl Calls {
    fn bump(cell: &std::cell::Cell<usize>) {
        cell.set(cell.get() + 1);
    }

    /// `(clones, borrowed encodings, owned encodings)`, then reset.
    fn take(&self) -> (usize, usize, usize) {
        (
            self.clones.replace(0),
            self.borrowed.replace(0),
            self.owned.replace(0),
        )
    }
}

/// A field that records each clone and each encoding call. Both encodings
/// give the same value, so only the counters tell the paths apart: a
/// consuming record encoding that fell back to borrowing would call
/// `encode_cbor` where `into_encoded_cbor` is required.
struct Counted {
    number: u64,
    calls: std::rc::Rc<Calls>,
}

impl Clone for Counted {
    fn clone(&self) -> Self {
        Calls::bump(&self.calls.clones);
        Counted {
            number: self.number,
            calls: self.calls.clone(),
        }
    }
}

impl dcbor::CBOREncodable for Counted {
    fn encode_cbor(&self) -> dcbor::Result<CBOR> {
        Calls::bump(&self.calls.borrowed);
        Ok(CBOR::from(self.number))
    }

    fn into_encoded_cbor(self) -> dcbor::Result<CBOR> {
        Calls::bump(&self.calls.owned);
        Ok(CBOR::from(self.number))
    }
}

#[derive(CBOREncodable)]
struct CountedRecord {
    #[cbor(n = 0)]
    one: Counted,
    #[cbor(n = 1)]
    maybe: Option<Counted>,
    #[cbor(n = 2)]
    many: Vec<Counted>,
}

#[derive(CBOREncodable)]
struct CountedNewtype(Counted);

#[derive(CBOREncodable)]
enum CountedVariant {
    #[cbor(n = 0)]
    Tuple(Counted, Vec<Counted>),
    #[cbor(n = 1)]
    Named {
        #[cbor(n = 0)]
        one: Counted,
        #[cbor(n = 1)]
        maybe: Option<Counted>,
    },
}

#[derive(CBOREncodable)]
#[cbor(tag = 40_001)]
struct CountedTagged {
    #[cbor(n = 0)]
    one: Counted,
}

/// Derived records encode by reference and by value without cloning a
/// field, in every shape (named, optional, sequence, newtype, both variant
/// forms, tagged), and both paths give the same value. The owned path
/// moves every field into its own consuming encoding (each `Counted` field
/// sees `into_encoded_cbor`, none `encode_cbor`); the borrowed path reads
/// every field through its borrowed encoding. Equal values and an absent
/// clone show neither: the per-method counters do, and restoring borrowed
/// dispatch in the derive's consuming body fails the owned assertion.
#[test]
fn derived_encodings_clone_no_field() {
    let calls = std::rc::Rc::new(Calls::default());
    let counted = |number| Counted {
        number,
        calls: calls.clone(),
    };
    let record = || CountedRecord {
        one: counted(1),
        maybe: Some(counted(2)),
        many: vec![counted(3), counted(4)],
    };
    let tuple = || CountedVariant::Tuple(counted(5), vec![counted(6)]);
    let named = || CountedVariant::Named {
        one: counted(7),
        maybe: None,
    };
    let expected = [
        record().encode_cbor().unwrap(),
        CountedNewtype(counted(8)).encode_cbor().unwrap(),
        tuple().encode_cbor().unwrap(),
        named().encode_cbor().unwrap(),
        CountedTagged { one: counted(9) }.tagged_cbor().unwrap(),
    ];
    // Fields: record 4, newtype 1, tuple 2, named 1 (its option empty),
    // tagged 1.
    assert_eq!(calls.take(), (0, 9, 0), "the borrowed encodings");
    let owned = [
        record().into_encoded_cbor().unwrap(),
        CountedNewtype(counted(8)).into_encoded_cbor().unwrap(),
        tuple().into_encoded_cbor().unwrap(),
        named().into_encoded_cbor().unwrap(),
        CBOR::to_tagged_value(
            40_001,
            CountedTagged { one: counted(9) }
                .into_encoded_cbor()
                .unwrap(),
        ),
    ];
    assert_eq!(calls.take(), (0, 0, 9), "the owned encodings");
    // Each shape's encoding runs inside its own iteration, after the
    // previous iteration's counters were taken: an array of encoded values
    // would run every encoding before the first take.
    let shapes: [(&str, &dyn Fn() -> dcbor::Result<CBOR>); 5] = [
        ("record", &|| record().into_encoded_cbor()),
        ("newtype", &|| {
            CountedNewtype(counted(8)).into_encoded_cbor()
        }),
        ("tuple variant", &|| tuple().into_encoded_cbor()),
        ("named variant", &|| named().into_encoded_cbor()),
        ("tagged", &|| {
            CountedTagged { one: counted(9) }.into_encoded_cbor()
        }),
    ];
    for (shape, encode) in shapes {
        encode().unwrap();
        let (clones, borrowed, owned) = calls.take();
        assert_eq!(
            (clones, borrowed),
            (0, 0),
            "{shape}: a field was borrowed or cloned"
        );
        assert!(owned > 0, "{shape}: no field was moved into its encoding");
    }
    assert_eq!(owned, expected);
    assert_eq!(
        expected[0].to_cbor_data(),
        [0xa3, 0x00, 0x01, 0x01, 0x02, 0x02, 0x82, 0x03, 0x04]
    );
    // The discriminant, then the two payload values: an array of three.
    assert_eq!(expected[2].to_cbor_data(), [0x83, 0x00, 0x05, 0x81, 0x06]);
    assert_eq!(expected[3].to_cbor_data(), [0x82, 0x01, 0xa1, 0x00, 0x07]);
}

/// An owned derived record's byte-string field moves into its encoding:
/// the encoding's byte string holds the field's own allocation, not a copy
/// of it.
#[test]
fn an_owned_derived_record_moves_its_byte_string() {
    #[derive(CBOREncodable)]
    struct Holder {
        #[cbor(n = 0)]
        bytes: ByteString,
    }
    let bytes = ByteString::from(vec![7u8; 64]);
    let address = bytes.data().as_ptr();
    let encoded = Holder { bytes }.into_encoded_cbor().unwrap();
    let CBORCase::Map(map) = encoded.into_case() else {
        panic!("a record encodes as a map");
    };
    let (_, value) = map.iter().next().expect("one field");
    let CBORCase::ByteString(moved) = value.as_case() else {
        panic!("the field encodes as a byte string");
    };
    assert_eq!(
        moved.data().as_ptr(),
        address,
        "the field's bytes were copied"
    );
}

#[derive(Debug, CBORCodable)]
struct BytesNewtype(ByteString);

#[derive(Debug, CBORCodable)]
enum BytesVariant {
    #[cbor(n = 0)]
    Tuple(ByteString),
    #[cbor(n = 1)]
    Named {
        #[cbor(n = 0)]
        bytes: ByteString,
        #[cbor(n = 1)]
        maybe: Option<ByteString>,
    },
}

#[derive(Debug, CBORCodable)]
struct BytesRecord {
    #[cbor(n = 0)]
    bytes: ByteString,
    #[cbor(n = 1)]
    maybe: Option<ByteString>,
}

/// Sixty-four bytes in an allocation of their own, and its address.
fn bytes() -> (ByteString, *const u8) {
    let bytes = ByteString::from(vec![7u8; 64]);
    let address = bytes.data().as_ptr();
    (bytes, address)
}

/// The address of the byte string `value` is, or holds at `path`: array
/// elements and map entries, each step an index or a key.
fn address_in(value: &CBOR, path: &[u64]) -> *const u8 {
    let mut value = value;
    for &step in path {
        value = match value.as_case() {
            CBORCase::Array(items) => &items[step as usize],
            CBORCase::Map(map) => map
                .iter()
                .find(|(key, _)| **key == CBOR::from(step))
                .map(|(_, value)| value)
                .expect("the key is present"),
            other => panic!("no element {step} in {other:?}"),
        };
    }
    match value.as_case() {
        CBORCase::ByteString(bytes) => bytes.data().as_ptr(),
        other => panic!("not a byte string: {other:?}"),
    }
}

/// The newtype, the tuple variant and the named variant move an owned byte
/// string field into their encoding, its allocation kept, as the named
/// record does (`an_owned_derived_record_moves_its_byte_string`).
#[test]
fn every_owned_derived_shape_moves_its_byte_string() {
    let (field, address) = bytes();
    let encoded = BytesNewtype(field).into_encoded_cbor().unwrap();
    assert_eq!(address_in(&encoded, &[]), address, "newtype");
    let (field, address) = bytes();
    let encoded = BytesVariant::Tuple(field).into_encoded_cbor().unwrap();
    assert_eq!(address_in(&encoded, &[1]), address, "tuple variant");
    let (field, address) = bytes();
    let (optional, optional_address) = bytes();
    let encoded = BytesVariant::Named {
        bytes: field,
        maybe: Some(optional),
    }
    .into_encoded_cbor()
    .unwrap();
    assert_eq!(address_in(&encoded, &[1, 0]), address, "named variant");
    assert_eq!(
        address_in(&encoded, &[1, 1]),
        optional_address,
        "named variant, optional field"
    );
}

/// Decoding a uniquely held value moves each named field's bytes out of the
/// decoded map into the field: a named record's required and optional
/// fields, and a named variant's, keep the allocation they had in the map.
/// The control reads the same field through `Map::get`, which converts a
/// clone of the map's handle and so copies the bytes: the witness tells a
/// moving extraction from a copying one.
#[test]
fn decoding_moves_named_fields_out_of_their_map() {
    let record = || {
        let mut map = Map::new();
        map.insert(0u64, bytes().0).unwrap();
        map.insert(1u64, bytes().0).unwrap();
        map.insert(2u64, "an unknown key, ignored").unwrap();
        CBOR::from(map)
    };

    let value = record();
    let (required, optional) = (address_in(&value, &[0]), address_in(&value, &[1]));
    let decoded = BytesRecord::try_from(value).unwrap();
    assert_eq!(decoded.bytes.data().as_ptr(), required, "required field");
    assert_eq!(
        decoded.maybe.as_ref().unwrap().data().as_ptr(),
        optional,
        "optional field"
    );

    let mut payload = Map::new();
    payload.insert(0u64, bytes().0).unwrap();
    let variant = CBOR::from(vec![CBOR::from(1u64), CBOR::from(payload)]);
    let address = address_in(&variant, &[1, 0]);
    match BytesVariant::try_from(variant).unwrap() {
        BytesVariant::Named { bytes, maybe } => {
            assert_eq!(bytes.data().as_ptr(), address, "named variant");
            assert!(maybe.is_none());
        }
        other => panic!("decoded {other:?}"),
    }

    let value = record();
    let address = address_in(&value, &[0]);
    let CBORCase::Map(map) = value.into_case() else {
        unreachable!("the record is a map");
    };
    let copied: ByteString = map.get(0u64).unwrap().unwrap();
    assert_ne!(
        copied.data().as_ptr(),
        address,
        "the control: a borrowed query copies, so the witness can fail"
    );
}

/// Named decoding keeps its refusals: a required field absent, and a field
/// present but of another type, required or optional.
#[test]
fn named_decoding_refuses_missing_and_mistyped_fields() {
    let mut missing = Map::new();
    missing.insert(1u64, bytes().0).unwrap();
    assert!(matches!(
        BytesRecord::try_from(CBOR::from(missing)),
        Err(dcbor::Error::MissingMapKey)
    ));
    let mut mistyped = Map::new();
    mistyped.insert(0u64, 5u64).unwrap();
    assert!(matches!(
        BytesRecord::try_from(CBOR::from(mistyped)),
        Err(dcbor::Error::WrongType)
    ));
    let mut optional = Map::new();
    optional.insert(0u64, bytes().0).unwrap();
    optional.insert(1u64, "not bytes").unwrap();
    assert!(matches!(
        BytesRecord::try_from(CBOR::from(optional)),
        Err(dcbor::Error::WrongType)
    ));
}

// --- Bounded encoding from the same schema ---

use dcbor::CBORBoundedEncodable;
use dcbor::bounded::{Schema, WriteWork, prepare};

#[derive(dcbor::CBORBoundedEncodable)]
enum Collision {
    #[cbor(n = 0)]
    Item {
        #[cbor(n = 0)]
        count: u64,
        #[cbor(n = 1)]
        payload: String,
        #[cbor(n = 2)]
        plan: Option<String>,
    },
}

#[derive(dcbor::CBORBoundedEncodable)]
struct Generic<A, B, P> {
    #[cbor(n = 0)]
    first: [A; 1],
    #[cbor(n = 1)]
    second: B,
    #[cbor(n = 2)]
    third: Option<P>,
}

#[derive(dcbor::CBORBoundedEncodable)]
enum Empty {}

#[test]
fn bounded_derive_accepts_user_names_and_generic_fields() {
    fn bytes(value: &impl Schema) -> Vec<u8> {
        let prepared = prepare(value, &mut Limits::unlimited()).unwrap();
        let mut bytes = vec![0; prepared.len()];
        prepared
            .encode_into(&mut bytes, &mut Limits::unlimited())
            .unwrap();
        bytes
    }
    assert_eq!(
        bytes(&Collision::Item {
            count: 1,
            payload: "x".into(),
            plan: Some("e\u{301}".into()),
        }),
        [0x82, 0, 0xa3, 0, 1, 1, 0x61, b'x', 2, 0x62, 0xc3, 0xa9]
    );
    assert_eq!(
        bytes(&Generic {
            first: [true],
            second: 1u64,
            third: Some(2u64)
        }),
        [0xa3, 0, 0x81, 0xf5, 1, 1, 2, 2]
    );
    fn assert_bounded<T: Schema>() {}
    assert_bounded::<Empty>();
}

/// The preparation and the write of `value`: the bytes are the symbolic
/// encoding's, both decode strictly to one value, the length is exact, and
/// the write reports no more than its bound and allocates nothing.
fn bounded<T: Schema + CBOREncodable>(value: &T) -> Vec<u8> {
    let prepared = prepare(value, &mut Limits::unlimited()).unwrap();
    let mut bytes = vec![0u8; prepared.len()];
    let mut written = Limits::unlimited();
    prepared.encode_into(&mut bytes, &mut written).unwrap();
    let write = prepared
        .write_work::<()>()
        .expect("the write bound of a plan held in memory fits in u64");
    assert!(
        write.covers(&written.used()),
        "{:?} beyond {write:?}",
        written.used()
    );
    assert_eq!(written.requests(), 0, "the write requested allocation");
    assert_eq!(written.live_bytes(), 0);
    let symbolic = value.encode_cbor_data().unwrap();
    assert_eq!(bytes, symbolic);
    assert_eq!(
        CBOR::try_from_data(&bytes).unwrap(),
        CBOR::try_from_data(&symbolic).unwrap()
    );
    bytes
}

/// Keys declared out of order, including keys whose encodings are two
/// bytes wide, and optional fields both ways.
#[derive(Clone, Debug, PartialEq, CBORCodable, CBORBoundedEncodable, CBORBoundedDecodable)]
struct Record {
    #[cbor(n = 300)]
    wide: u64,
    #[cbor(n = 2)]
    label: String,
    #[cbor(n = 24)]
    note: Option<String>,
    #[cbor(n = 0)]
    flag: bool,
    #[cbor(n = 1)]
    payload: ByteString,
    #[cbor(n = 23)]
    signed: i64,
    #[cbor(n = 5)]
    children: Option<Vec<Newtype>>,
    #[cbor(n = 6)]
    kind: Reason,
}

#[derive(Clone, Debug, PartialEq, CBORCodable, CBORBoundedEncodable, CBORBoundedDecodable)]
struct Newtype(Vec<u64>);

#[derive(Clone, Debug, PartialEq, CBORCodable, CBORBoundedEncodable, CBORBoundedDecodable)]
struct Nothing;

#[derive(Clone, Debug, PartialEq, CBORCodable, CBORBoundedEncodable, CBORBoundedDecodable)]
#[repr(C, u8)]
enum Mixed {
    #[cbor(n = 0)]
    Point,
    #[cbor(n = 1)]
    Circle(u64),
    #[cbor(n = 30)]
    Pair(u64, String),
    #[cbor(n = 2)]
    Frame {
        #[cbor(n = 1)]
        height: i64,
        #[cbor(n = 0)]
        width: Option<u64>,
    },
}

#[derive(
    Clone, Copy, Debug, PartialEq, CBORCodable, CBORBoundedEncodable, CBORBoundedDecodable,
)]
#[repr(u8)]
enum Reason {
    #[cbor(n = 0)]
    First,
    #[cbor(n = 1)]
    Second,
    #[cbor(n = 2)]
    Third,
    #[cbor(n = 7)]
    Seventh,
}

#[derive(Clone, Debug, PartialEq, CBORCodable, CBORBoundedEncodable, CBORBoundedDecodable)]
#[cbor(tag = 42)]
struct Labelled {
    #[cbor(n = 0)]
    data: Vec<u8>,
}

fn record(note: Option<&str>, children: Option<Vec<Newtype>>) -> Record {
    Record {
        wide: 70_000,
        label: "e\u{301}tiquette".to_string(),
        note: note.map(str::to_string),
        flag: true,
        payload: ByteString::new([1, 2, 3]),
        signed: -25,
        children,
        kind: Reason::First,
    }
}

/// Maps with optional fields both ways, nested newtypes and a wide signed
/// field, each encoded and constructed back ([`round_trip`]).
#[test]
fn bounded_maps_match_the_symbolic_encoding_with_options_both_ways() {
    for source in [
        record(None, None),
        record(Some("present"), None),
        record(
            Some("x"),
            Some(vec![Newtype(vec![]), Newtype(vec![u64::MAX])]),
        ),
    ] {
        let mut expected = source.clone();
        expected.label = "\u{e9}tiquette".to_string();
        assert_eq!(round_trip(&source), expected);
    }
    round_trip(&Record {
        wide: 1,
        label: String::new(),
        note: Some("present".to_string()),
        flag: false,
        payload: ByteString::new([]),
        signed: i64::MIN,
        children: Some(vec![Newtype(vec![]), Newtype(vec![u64::MAX])]),
        kind: Reason::Seventh,
    });
}

/// Newtypes, every enum shape and unit enums are encoded and constructed
/// back ([`round_trip`]), including the unit struct's null construction.
/// A tagged type encodes untagged; its tagged construction is
/// `bounded_construction_of_a_tagged_type_requires_its_tag`.
#[test]
fn bounded_newtypes_units_enums_and_tags_match_the_symbolic_encoding() {
    round_trip(&Newtype(vec![1, 1000, 1_000_000]));
    assert_eq!(bounded(&Nothing), [0xf6]);
    assert_eq!(round_trip(&Nothing), Nothing);
    round_trip(&Mixed::Point);
    round_trip(&Mixed::Circle(42));
    round_trip(&Mixed::Pair(7, "seven".to_string()));
    round_trip(&Mixed::Frame {
        height: -1,
        width: None,
    });
    round_trip(&Mixed::Frame {
        height: 1,
        width: Some(2),
    });
    for reason in [
        Reason::First,
        Reason::Second,
        Reason::Third,
        Reason::Seventh,
    ] {
        round_trip(&reason);
    }
    let labelled = Labelled { data: vec![1, 2] };
    assert_eq!(
        bounded(&labelled),
        labelled.untagged_cbor().unwrap().to_cbor_data(),
        "the encoding, bounded or not, is the untagged value"
    );
}

/// Unit variants encode as their discriminants' heads, one byte each below
/// 24 and two at 30. A plan without gaps is written in one segment per
/// quantum and the completion, whatever values it holds.
#[test]
fn unit_enums_encode_their_discriminants_heads() {
    let reasons = vec![Reason::Third, Reason::First];
    let prepared = prepare(&reasons, &mut Limits::unlimited()).unwrap();
    assert_eq!(prepared.len(), 3);
    let mut written = Limits::unlimited();
    let mut bytes = [0; 3];
    prepared.encode_into(&mut bytes, &mut written).unwrap();
    assert_eq!(bytes, [0x82, 0x02, 0x00]);
    assert_eq!(written.used(), WriteWork::new(2, 3));
    assert_eq!(bounded(&reasons), bytes);
    assert_eq!(bounded(&vec![Mixed::Point]), [0x81, 0x00]);
}

// --- Bounded construction from the same schema ---

use dcbor::CBORBoundedDecodable;
use dcbor::bounded::Limits;
use dcbor::bounded::decode::decode_typed;

/// `value` encoded on the bounded path ([`bounded`]), then those bytes
/// constructed on both paths: the bounded and symbolic constructions are
/// equal to each other, the symbolic one re-encodes to the
/// same canonical bytes, and dropping the bounded value releases every
/// retained permit. Return the canonical typed value for fixture-specific
/// assertions: normalization can intentionally change the source value.
fn round_trip<T>(value: &T) -> T
where
    T: Schema
        + CBOREncodable
        + TryFrom<CBOR, Error = dcbor::Error>
        + dcbor::bounded::decode::construction::in_place::Transferable<Limits>
        + PartialEq
        + std::fmt::Debug
        + 'static,
{
    let bytes = bounded(value);
    let symbolic = T::try_from(CBOR::try_from_data(bytes.as_slice()).unwrap()).unwrap();
    // The decode is held to its own bound ([`decode_typed`]); these tests
    // are its interpretation of the wire bytes, not its budget.
    let mut limits = Limits::unlimited();
    let built = decode_typed::<T, _>(&bytes, &mut limits).unwrap();
    assert_eq!(
        built.value(),
        &symbolic,
        "bounded and symbolic construction must interpret the same wire bytes",
    );
    assert_eq!(
        symbolic.encode_cbor_data().unwrap(),
        bytes,
        "symbolic reconstruction must preserve the canonical wire representation",
    );
    drop(built);
    assert_eq!(
        limits.live_bytes(),
        0,
        "every permit is released with the value"
    );
    symbolic
}

/// A tagged type is constructed from its tagged form, as `TryFrom<CBOR>`
/// reads it, and refuses another tag and the untagged form.
#[test]
fn bounded_construction_of_a_tagged_type_requires_its_tag() {
    let wrapped = Labelled { data: vec![1, 2] };
    let tagged = wrapped.tagged_cbor_data().unwrap();
    let mut limits = Limits::unlimited();
    let built = decode_typed::<Labelled, _>(&tagged, &mut limits).unwrap();
    assert_eq!(built.value(), &wrapped);
    let untagged = wrapped.untagged_cbor().unwrap().to_cbor_data();
    assert!(decode_typed::<Labelled, _>(&untagged, &mut limits).is_err());
    let other = CBOR::to_tagged_value(99, wrapped.untagged_cbor().unwrap()).to_cbor_data();
    assert!(decode_typed::<Labelled, _>(&other, &mut limits).is_err());
    drop(built);
    assert_eq!(
        limits.live_bytes(),
        0,
        "tagged construction retained permits"
    );
}

/// A required field absent is `MissingMapKey`; a value of another kind is
/// `WrongType`; a discriminant no variant carries is `WrongType`.
#[test]
fn bounded_construction_rejects_what_the_symbolic_conversion_rejects() {
    use dcbor::bounded::decode::DecodeError;
    let mut limits = Limits::unlimited();
    let mut missing = Map::new();
    missing.insert(0u64, true).unwrap();
    let bytes = CBOR::from(missing).to_cbor_data();
    assert!(matches!(
        decode_typed::<Record, _>(&bytes, &mut limits),
        Err(DecodeError::Invalid(dcbor::Error::MissingMapKey))
    ));
    let bytes = CBOR::from(42u64).to_cbor_data();
    assert!(matches!(
        decode_typed::<Record, _>(&bytes, &mut limits),
        Err(DecodeError::Invalid(dcbor::Error::WrongType))
    ));
    let bytes = CBOR::from(5u64).to_cbor_data();
    assert!(matches!(
        decode_typed::<Reason, _>(&bytes, &mut limits),
        Err(DecodeError::Invalid(dcbor::Error::WrongType))
    ));
    assert_eq!(limits.live_bytes(), 0);
}

/// Tuple variants only: a bare discriminant, and arrays of a discriminant
/// and their fields, one of a nested sequence and one holding a text.
#[derive(Clone, Debug, PartialEq, CBORCodable, CBORBoundedEncodable, CBORBoundedDecodable)]
#[repr(C, u8)]
enum Positional {
    #[cbor(n = 0)]
    Bare,
    #[cbor(n = 1)]
    Sequence(Vec<u64>),
    #[cbor(n = 2)]
    Labelled(u64, String),
}

/// A tagged newtype of bytes: one tag level over its field's.
#[derive(Clone, Debug, PartialEq, CBORCodable, CBORBoundedEncodable, CBORBoundedDecodable)]
#[cbor(tag = 7)]
struct TaggedBytes(ByteString);

/// The derive composes each type's wire profile (`InPlace::WIRE`) as its
/// encoding nests its parts: a unit struct is `null`, a scalar; a newtype
/// is its field's; a record accepts unknown keys, any value under them, so
/// it is unrestricted, tagged or not; a unit-only enum is a bare
/// discriminant; a tuple variant is one array level over its discriminant
/// and its fields, the enum the most of its variants', strict text policy
/// where any field takes text; a tag is one level more. A derived newtype
/// over a sequence of integers refuses a document nested past its profile
/// at the profile's depth, everything released.
#[test]
fn the_derive_composes_each_types_wire_profile_from_its_parts() {
    use dcbor::bounded::decode::construction::in_place::InPlace;
    use dcbor::bounded::decode::{DecodeError, Options};
    fn wire<T: InPlace<Limits>>() -> Options {
        T::WIRE
    }
    assert_eq!(wire::<Nothing>(), Options::quick_only(0));
    assert_eq!(wire::<Newtype>(), Options::quick_only(1));
    assert_eq!(wire::<Record>(), Options::UNRESTRICTED);
    assert_eq!(wire::<Labelled>(), Options::UNRESTRICTED);
    assert_eq!(wire::<Reason>(), Options::quick_only(0));
    assert_eq!(wire::<Positional>(), Options::normalizing(2));
    assert_eq!(wire::<TaggedBytes>(), Options::quick_only(1));
    let mut limits = Limits::unlimited();
    let nested = CBOR::from(vec![vec![1u64]]).to_cbor_data();
    assert!(matches!(
        decode_typed::<Newtype, _>(&nested, &mut limits),
        Err(DecodeError::DepthLimit { limit: 1 })
    ));
    assert_eq!(limits.live_bytes(), 0);
    round_trip(&Positional::Bare);
    round_trip(&Positional::Sequence(vec![1, 2]));
    round_trip(&Positional::Labelled(3, "three".to_string()));
    let tagged = TaggedBytes(ByteString::new([1, 2]));
    let built =
        decode_typed::<TaggedBytes, _>(&tagged.tagged_cbor_data().unwrap(), &mut limits).unwrap();
    assert_eq!(built.value(), &tagged);
}

/// A closed record (`#[cbor(closed)]`), holding a closed record and a
/// sequence.
#[derive(Clone, Debug, PartialEq, CBORCodable, CBORBoundedEncodable, CBORBoundedDecodable)]
#[cbor(closed)]
struct Sealed {
    #[cbor(n = 1)]
    count: u64,
    #[cbor(n = 4)]
    note: Option<String>,
    #[cbor(n = 6)]
    inner: SealedInner,
}

#[derive(Clone, Debug, PartialEq, CBORCodable, CBORBoundedEncodable, CBORBoundedDecodable)]
#[cbor(closed)]
struct SealedInner {
    #[cbor(n = 0)]
    values: Vec<u64>,
}

/// A closed enum: its named variant's map is closed, its tuple variant has
/// no keys to refuse.
#[derive(Clone, Debug, PartialEq, CBORCodable, CBORBoundedEncodable, CBORBoundedDecodable)]
#[repr(C, u8)]
#[cbor(closed)]
enum SealedChoice {
    #[cbor(n = 0)]
    Pair(u64, u64),
    #[cbor(n = 1)]
    Named {
        #[cbor(n = 0)]
        value: u64,
    },
}

fn sealed() -> Sealed {
    Sealed {
        count: 3,
        note: None,
        inner: SealedInner { values: vec![1, 2] },
    }
}

/// `value`'s map with `key` added, holding `0`.
fn with_key(value: CBOR, key: CBOR) -> CBOR {
    let CBORCase::Map(mut map) = value.into_case() else {
        panic!("a record encodes as a map");
    };
    map.insert(key, 0u64).unwrap();
    CBOR::from(map)
}

/// Both decoders of a closed record refuse a key no field names, as
/// `UnknownMapKey`: an unsigned key between its fields' and past them, and
/// a text key, at the top and in the closed record it holds, everything
/// released; an optional field left absent is no unknown key. An open
/// record accepts the same keys (`decoding_moves_named_fields_out_of_their_map`).
#[test]
fn a_closed_record_refuses_every_key_no_field_names() {
    use dcbor::bounded::decode::DecodeError;
    round_trip(&sealed());
    round_trip(&Sealed {
        note: Some("n".into()),
        ..sealed()
    });
    let top = sealed().encode_cbor().unwrap();
    // `sealed()`, its inner record holding `key` beside its field.
    let nested = |key: CBOR| {
        let inner = sealed().inner.encode_cbor().unwrap();
        let mut map = Map::new();
        map.insert(1u64, sealed().count).unwrap();
        map.insert(6u64, with_key(inner, key)).unwrap();
        CBOR::from(map)
    };
    let cases = [
        (
            "between the fields",
            with_key(top.clone(), CBOR::from(2u64)),
        ),
        ("past the fields", with_key(top.clone(), CBOR::from(99u64))),
        ("a text key", with_key(top.clone(), CBOR::from("x"))),
        ("nested", nested(CBOR::from(5u64))),
    ];
    for (what, cbor) in cases {
        assert!(
            matches!(
                Sealed::try_from(cbor.clone()),
                Err(dcbor::Error::UnknownMapKey)
            ),
            "{what}: the symbolic decoder"
        );
        let mut limits = Limits::unlimited();
        let refused = decode_typed::<Sealed, _>(&cbor.to_cbor_data(), &mut limits);
        assert!(
            matches!(
                refused,
                Err(DecodeError::Invalid(dcbor::Error::UnknownMapKey))
            ),
            "{what}: the bounded decoder: {:?}",
            refused.map(|value| value.value().clone())
        );
        assert_eq!(limits.live_bytes(), 0, "{what}: storage kept");
    }
    let named = SealedChoice::Named { value: 1 }.encode_cbor().unwrap();
    let CBORCase::Array(items) = named.into_case() else {
        unreachable!("a variant encodes as an array");
    };
    let widened = CBOR::from(vec![
        items[0].clone(),
        with_key(items[1].clone(), CBOR::from(9u64)),
    ]);
    assert!(matches!(
        SealedChoice::try_from(widened.clone()),
        Err(dcbor::Error::UnknownMapKey)
    ));
    assert!(matches!(
        decode_typed::<SealedChoice, _>(&widened.to_cbor_data(), &mut Limits::unlimited()),
        Err(DecodeError::Invalid(dcbor::Error::UnknownMapKey))
    ));
    round_trip(&SealedChoice::Pair(1, 2));
    round_trip(&SealedChoice::Named { value: 1 });
}

/// A closed record's wire profile is its fields', one map level over them,
/// where an open record's is unrestricted: its unknown keys may hold any
/// value. A closed enum's named variant is an array around such a map.
#[test]
fn a_closed_records_wire_profile_is_its_fields() {
    use dcbor::bounded::decode::construction::in_place::InPlace;
    use dcbor::bounded::decode::{DecodeError, Options};
    fn wire<T: InPlace<Limits>>() -> Options {
        T::WIRE
    }
    assert_eq!(wire::<SealedInner>(), Options::quick_only(2));
    assert_eq!(wire::<Sealed>(), Options::normalizing(3));
    assert_eq!(wire::<SealedChoice>(), Options::quick_only(2));
    // Deeper than the profile: refused by the parse at its depth.
    let deep = with_key(
        sealed().encode_cbor().unwrap(),
        CBOR::from(vec![vec![vec![0u64]]]),
    );
    assert!(matches!(
        decode_typed::<Sealed, _>(&deep.to_cbor_data(), &mut Limits::unlimited()),
        Err(DecodeError::DepthLimit { limit: 3 })
    ));
}

/// A float field takes the shared canonical reduction on the bounded path.
#[derive(Clone, Debug, PartialEq, CBORCodable, CBORBoundedEncodable)]
struct Reading {
    #[cbor(n = 0)]
    value: f64,
    #[cbor(n = 1)]
    single: Option<f32>,
}

#[test]
fn bounded_float_fields_match_the_symbolic_encoding() {
    for (value, single) in [
        (1.5, None),
        (2.0, Some(4294967296.0f32)),
        (f64::NAN, Some(f32::INFINITY)),
        (1.1, Some(-0.0)),
    ] {
        bounded(&Reading { value, single });
    }
}
