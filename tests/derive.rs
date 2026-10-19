#![cfg(feature = "derive")]

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
    let cbor: CBOR = p.clone().into();
    let p2: Person = cbor.try_into().unwrap();
    assert_eq!(p, p2);
}

#[test]
fn struct_deterministic() {
    let p = Person {
        name: "Alice".to_string(),
        age: 30,
    };
    let bytes1 = p.to_cbor_data();
    let bytes2 = p.to_cbor_data();
    assert_eq!(bytes1, bytes2);

    // Decode from bytes and re-encode must produce identical bytes
    let decoded = CBOR::try_from_data(&bytes1).unwrap();
    let p3: Person = decoded.try_into().unwrap();
    let bytes3 = p3.to_cbor_data();
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
    let cbor: CBOR = p.clone().into();
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
    let cbor: CBOR = p.clone().into();
    let p2: PersonOptional = cbor.try_into().unwrap();
    assert_eq!(p, p2);
}

// --- Newtype struct ---

#[derive(Clone, Debug, PartialEq, CBOREncodable, CBORDecodable)]
struct Wrapper(String);

#[test]
fn newtype_roundtrip() {
    let w = Wrapper("hello".to_string());
    let cbor: CBOR = w.clone().into();
    let w2: Wrapper = cbor.try_into().unwrap();
    assert_eq!(w, w2);
}

// --- Enum with unit, tuple, and struct variants ---

#[derive(Clone, Debug, PartialEq, CBOREncodable, CBORDecodable)]
enum Shape {
    #[cbor(n = 0)]
    Point,
    #[cbor(n = 1)]
    Circle(u64),
    #[cbor(n = 2)]
    Rectangle {
        #[cbor(n = 0)]
        width: u64,
        #[cbor(n = 1)]
        height: u64,
    },
}

#[test]
fn enum_unit_roundtrip() {
    let s = Shape::Point;
    let cbor: CBOR = s.clone().into();
    let s2: Shape = cbor.try_into().unwrap();
    assert_eq!(s, s2);
}

#[test]
fn enum_tuple_roundtrip() {
    let s = Shape::Circle(42);
    let cbor: CBOR = s.clone().into();
    let s2: Shape = cbor.try_into().unwrap();
    assert_eq!(s, s2);
}

#[test]
fn enum_struct_roundtrip() {
    let s = Shape::Rectangle {
        width: 10,
        height: 20,
    };
    let cbor: CBOR = s.clone().into();
    let s2: Shape = cbor.try_into().unwrap();
    assert_eq!(s, s2);
}

// --- Tagged type ---

#[derive(Clone, Debug, PartialEq, CBOREncodable, CBORDecodable)]
#[cbor(tag = 42)]
struct TaggedData {
    #[cbor(n = 0)]
    payload: Vec<u8>,
}

#[test]
fn tagged_roundtrip() {
    let t = TaggedData {
        payload: vec![1, 2, 3],
    };
    let tagged_cbor = t.tagged_cbor();
    let t2: TaggedData = tagged_cbor.try_into().unwrap();
    assert_eq!(t, t2);
}

#[test]
fn tagged_wrong_tag_rejected() {
    let t = TaggedData {
        payload: vec![1, 2, 3],
    };
    // Encode with correct tag, then re-wrap with wrong tag
    let untagged = t.untagged_cbor();
    let wrong_tagged = CBOR::to_tagged_value(99, untagged);
    let result: dcbor::Result<TaggedData> = wrong_tagged.try_into();
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
    let bytes = p.to_cbor_data();
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
    let result: dcbor::Result<Shape> = cbor.try_into();
    assert!(result.is_err());
}

// --- Bounded encoding from the same schema ---

use dcbor::bounded::{prepare, Allocator, BoundedEncodable, Budget, WriteWork};
use dcbor::CBORBoundedEncodable;

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
    fn bytes(value: &impl BoundedEncodable) -> Vec<u8> {
        let prepared = prepare(value, &mut Tally::default()).unwrap();
        let mut bytes = vec![0; prepared.len() as usize];
        prepared
            .encode_into(&mut bytes, &mut Tally::default())
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
    fn assert_bounded<T: BoundedEncodable>() {}
    assert_bounded::<Empty>();
}

/// A budget that admits everything and records what it is told, checked.
#[derive(Default)]
struct Tally {
    work: WriteWork,
    requested: u64,
}

impl Budget for Tally {
    type Refusal = &'static str;

    fn traverse(&mut self, values: u64, bytes: u64) -> Result<(), &'static str> {
        self.work = self
            .work
            .then::<()>(WriteWork::new(values, bytes))
            .map_err(|_| "overflow")?;
        Ok(())
    }
}

impl Allocator for Tally {
    type Permit = ();

    fn allocate(&mut self, bytes: u64) -> Result<(), &'static str> {
        self.requested = self.requested.checked_add(bytes).ok_or("overflow")?;
        Ok(())
    }
}

/// Both bounded passes of `value`: the bytes are the symbolic encoding's,
/// both decode strictly to one value, the length is exact, and the write
/// reports no more than predicted and allocates nothing.
fn bounded<T: BoundedEncodable + Clone + Into<CBOR>>(value: &T) -> Vec<u8> {
    let prepared = prepare(value, &mut Tally::default()).unwrap();
    let mut bytes = vec![0u8; prepared.len() as usize];
    let mut written = Tally::default();
    prepared.encode_into(&mut bytes, &mut written).unwrap();
    assert!(
        prepared.write_work().covers(&written.work),
        "{:?} beyond {:?}",
        written.work,
        prepared.write_work()
    );
    assert_eq!(written.requested, 0);
    let symbolic = value.clone().into().to_cbor_data();
    assert_eq!(bytes, symbolic);
    assert_eq!(
        CBOR::try_from_data(&bytes).unwrap(),
        CBOR::try_from_data(&symbolic).unwrap()
    );
    bytes
}

/// Keys declared out of order, including keys whose encodings are two
/// bytes wide, and optional fields both ways.
#[derive(Clone, Debug, PartialEq, CBORCodable, CBORBoundedEncodable)]
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
}

#[derive(Clone, Debug, PartialEq, CBORCodable, CBORBoundedEncodable)]
struct Newtype(Vec<u64>);

#[derive(Clone, Debug, PartialEq, CBORCodable, CBORBoundedEncodable)]
struct Nothing;

#[derive(Clone, Debug, PartialEq, CBORCodable, CBORBoundedEncodable)]
enum Mixed {
    #[cbor(n = 0)]
    Point,
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

#[derive(Clone, Copy, Debug, PartialEq, CBORCodable, CBORBoundedEncodable)]
enum Reason {
    #[cbor(n = 0)]
    First,
    #[cbor(n = 1)]
    Second,
    #[cbor(n = 2)]
    Third,
}

#[derive(Clone, Debug, PartialEq, CBORCodable, CBORBoundedEncodable)]
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
    }
}

#[test]
fn bounded_maps_match_the_symbolic_encoding_with_options_both_ways() {
    bounded(&record(None, None));
    bounded(&record(Some("present"), None));
    bounded(&record(
        Some("x"),
        Some(vec![Newtype(vec![]), Newtype(vec![u64::MAX])]),
    ));
}

#[test]
fn bounded_newtypes_units_enums_and_tags_match_the_symbolic_encoding() {
    bounded(&Newtype(vec![1, 1000, 1_000_000]));
    assert_eq!(bounded(&Nothing), [0xf6]);
    bounded(&Mixed::Point);
    bounded(&Mixed::Pair(7, "seven".to_string()));
    bounded(&Mixed::Frame {
        height: -1,
        width: None,
    });
    bounded(&Mixed::Frame {
        height: 1,
        width: Some(2),
    });
    for reason in [Reason::First, Reason::Second, Reason::Third] {
        bounded(&reason);
    }
    let labelled = Labelled { data: vec![1, 2] };
    assert_eq!(
        bounded(&labelled),
        labelled.untagged_cbor().to_cbor_data(),
        "the conversion, bounded or not, is the untagged value"
    );
}

/// An enum of unit variants of one head width has a fixed measure; one
/// whose discriminants need different widths does not.
#[test]
fn unit_enums_of_one_width_have_a_fixed_measure() {
    let fixed = Reason::FIXED.unwrap();
    assert_eq!(fixed.len, 1);
    assert_eq!(fixed.write, WriteWork::new(1, 0));
    assert_eq!(Mixed::FIXED, None);
    let reasons = vec![Reason::Third, Reason::First];
    let mut measuring = Tally::default();
    let prepared = prepare(&reasons, &mut measuring).unwrap();
    assert_eq!(measuring.work.values, 1, "measured from the count");
    assert_eq!(
        prepared.write_work().values,
        3,
        "the array and each element are written"
    );
    let bytes = bounded(&reasons);
    assert_eq!(bytes, [0x82, 0x02, 0x00]);
}

// --- Bounded construction from the same schema ---

use dcbor::bounded::decode::decode_typed;
use dcbor::bounded::Limits;
use dcbor::CBORBoundedDecodable;

#[derive(Clone, Debug, PartialEq, CBORCodable, CBORBoundedEncodable, CBORBoundedDecodable)]
struct Constructed {
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
    children: Option<Vec<Inner>>,
    #[cbor(n = 6)]
    kind: Kind,
}

#[derive(Clone, Debug, PartialEq, CBORCodable, CBORBoundedEncodable, CBORBoundedDecodable)]
struct Inner(Vec<u64>);

#[derive(
    Clone, Copy, Debug, PartialEq, CBORCodable, CBORBoundedEncodable, CBORBoundedDecodable,
)]
enum Kind {
    #[cbor(n = 0)]
    First,
    #[cbor(n = 7)]
    Second,
}

#[derive(Clone, Debug, PartialEq, CBORCodable, CBORBoundedEncodable, CBORBoundedDecodable)]
enum Variants {
    #[cbor(n = 0)]
    Point,
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

#[derive(Clone, Debug, PartialEq, CBORCodable, CBORBoundedEncodable, CBORBoundedDecodable)]
#[cbor(tag = 42)]
struct Wrapped {
    #[cbor(n = 0)]
    data: Vec<u8>,
}

/// Bounded and symbolic construction of the same canonical wire bytes
/// produce equal typed values. Dropping the bounded value releases every
/// retained permit.
fn constructed<T>(value: &T)
where
    T: Clone
        + Into<CBOR>
        + TryFrom<CBOR, Error = dcbor::Error>
        + dcbor::bounded::decode::BoundedDecodable
        + PartialEq
        + std::fmt::Debug,
{
    let bytes = value.clone().into().to_cbor_data();
    let symbolic = T::try_from(CBOR::try_from_data(bytes.as_slice()).unwrap()).unwrap();
    let mut limits = Limits::new(100_000, 1_000_000, 1_000_000);
    let built = decode_typed::<T, _>(&bytes, 16, &mut limits).unwrap();
    assert_eq!(
        built.value(),
        &symbolic,
        "bounded and symbolic construction must interpret the same wire bytes",
    );
    assert_eq!(
        symbolic.into().to_cbor_data(),
        bytes,
        "symbolic reconstruction must preserve the canonical wire representation",
    );
    drop(built);
    assert_eq!(
        limits.live_bytes(),
        0,
        "every permit is released with the value"
    );
}

#[test]
fn bounded_construction_reads_what_the_symbolic_conversion_reads() {
    constructed(&Constructed {
        wide: 70_000,
        label: "e\u{301}tiquette".to_string(),
        note: None,
        flag: true,
        payload: ByteString::new([1, 2, 3]),
        signed: -25,
        children: None,
        kind: Kind::First,
    });
    constructed(&Constructed {
        wide: 1,
        label: String::new(),
        note: Some("present".to_string()),
        flag: false,
        payload: ByteString::new([]),
        signed: i64::MIN,
        children: Some(vec![Inner(vec![]), Inner(vec![u64::MAX])]),
        kind: Kind::Second,
    });
    constructed(&Variants::Point);
    constructed(&Variants::Pair(7, "seven".to_string()));
    constructed(&Variants::Frame {
        height: -1,
        width: None,
    });
    constructed(&Variants::Frame {
        height: 1,
        width: Some(2),
    });
}

/// A tagged type is constructed from its tagged form, as `TryFrom<CBOR>`
/// reads it, and refuses another tag and the untagged form.
#[test]
fn bounded_construction_of_a_tagged_type_requires_its_tag() {
    let wrapped = Wrapped { data: vec![1, 2] };
    let tagged = wrapped.tagged_cbor().to_cbor_data();
    let mut limits = Limits::new(1000, 10_000, 10_000);
    let built = decode_typed::<Wrapped, _>(&tagged, 16, &mut limits).unwrap();
    assert_eq!(built.value(), &wrapped);
    let untagged = wrapped.untagged_cbor().to_cbor_data();
    assert!(decode_typed::<Wrapped, _>(&untagged, 16, &mut limits).is_err());
    let other = CBOR::to_tagged_value(99, wrapped.untagged_cbor()).to_cbor_data();
    assert!(decode_typed::<Wrapped, _>(&other, 16, &mut limits).is_err());
}

/// A required field absent is `MissingMapKey`; a value of another kind is
/// `WrongType`; a discriminant no variant carries is `WrongType`.
#[test]
fn bounded_construction_rejects_what_the_symbolic_conversion_rejects() {
    use dcbor::bounded::decode::DecodeError;
    let mut limits = Limits::new(1000, 10_000, 10_000);
    let mut missing = Map::new();
    missing.insert(0u64, true);
    let bytes = CBOR::from(missing).to_cbor_data();
    assert!(matches!(
        decode_typed::<Constructed, _>(&bytes, 16, &mut limits),
        Err(DecodeError::Invalid(dcbor::Error::MissingMapKey))
    ));
    let bytes = CBOR::from(42u64).to_cbor_data();
    assert!(matches!(
        decode_typed::<Constructed, _>(&bytes, 16, &mut limits),
        Err(DecodeError::Invalid(dcbor::Error::WrongType))
    ));
    let bytes = CBOR::from(5u64).to_cbor_data();
    assert!(matches!(
        decode_typed::<Kind, _>(&bytes, 16, &mut limits),
        Err(DecodeError::Invalid(dcbor::Error::WrongType))
    ));
    assert_eq!(limits.live_bytes(), 0);
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
