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

#[test]
fn newtype_roundtrip() {
    let w = Newtype(vec![1, 1000]);
    let cbor: CBOR = w.clone().into();
    let w2: Newtype = cbor.try_into().unwrap();
    assert_eq!(w, w2);
}

// --- Enum with unit, tuple, and struct variants ---

#[test]
fn enum_unit_roundtrip() {
    let s = Mixed::Point;
    let cbor: CBOR = s.clone().into();
    let s2: Mixed = cbor.try_into().unwrap();
    assert_eq!(s, s2);
}

#[test]
fn enum_tuple_roundtrip() {
    let s = Mixed::Circle(42);
    let cbor: CBOR = s.clone().into();
    let s2: Mixed = cbor.try_into().unwrap();
    assert_eq!(s, s2);
}

#[test]
fn enum_struct_roundtrip() {
    let s = Mixed::Frame {
        width: Some(10),
        height: 20,
    };
    let cbor: CBOR = s.clone().into();
    let s2: Mixed = cbor.try_into().unwrap();
    assert_eq!(s, s2);
}

// --- Tagged type ---

#[test]
fn tagged_roundtrip() {
    let t = Labelled {
        data: vec![1, 2, 3],
    };
    let tagged_cbor = t.tagged_cbor();
    let t2: Labelled = tagged_cbor.try_into().unwrap();
    assert_eq!(t, t2);
}

#[test]
fn tagged_wrong_tag_rejected() {
    let t = Labelled {
        data: vec![1, 2, 3],
    };
    // Encode with correct tag, then re-wrap with wrong tag
    let untagged = t.untagged_cbor();
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
    let result: dcbor::Result<Mixed> = cbor.try_into();
    assert!(result.is_err());
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
fn bounded<T: Schema + Clone + Into<CBOR>>(value: &T) -> Vec<u8> {
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
/// A tagged type converts
/// untagged; its tagged construction is
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
        labelled.untagged_cbor().to_cbor_data(),
        "the conversion, bounded or not, is the untagged value"
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
        + Clone
        + Into<CBOR>
        + TryFrom<CBOR, Error = dcbor::Error>
        + dcbor::bounded::decode::BoundedDecodable
        + PartialEq
        + std::fmt::Debug,
{
    let bytes = bounded(value);
    let symbolic = T::try_from(CBOR::try_from_data(bytes.as_slice()).unwrap()).unwrap();
    let mut limits = Limits::new(100_000, 1_000_000, 1_000_000);
    let built = decode_typed::<T, _>(&bytes, 16, &mut limits).unwrap();
    assert_eq!(
        built.value(),
        &symbolic,
        "bounded and symbolic construction must interpret the same wire bytes",
    );
    assert_eq!(
        symbolic.clone().into().to_cbor_data(),
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
    let tagged = wrapped.tagged_cbor().to_cbor_data();
    let mut limits = Limits::new(1000, 10_000, 10_000);
    let built = decode_typed::<Labelled, _>(&tagged, 16, &mut limits).unwrap();
    assert_eq!(built.value(), &wrapped);
    let untagged = wrapped.untagged_cbor().to_cbor_data();
    assert!(decode_typed::<Labelled, _>(&untagged, 16, &mut limits).is_err());
    let other = CBOR::to_tagged_value(99, wrapped.untagged_cbor()).to_cbor_data();
    assert!(decode_typed::<Labelled, _>(&other, 16, &mut limits).is_err());
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
    let mut limits = Limits::new(1000, 10_000, 10_000);
    let mut missing = Map::new();
    missing.insert(0u64, true);
    let bytes = CBOR::from(missing).to_cbor_data();
    assert!(matches!(
        decode_typed::<Record, _>(&bytes, 16, &mut limits),
        Err(DecodeError::Invalid(dcbor::Error::MissingMapKey))
    ));
    let bytes = CBOR::from(42u64).to_cbor_data();
    assert!(matches!(
        decode_typed::<Record, _>(&bytes, 16, &mut limits),
        Err(DecodeError::Invalid(dcbor::Error::WrongType))
    ));
    let bytes = CBOR::from(5u64).to_cbor_data();
    assert!(matches!(
        decode_typed::<Reason, _>(&bytes, 16, &mut limits),
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
