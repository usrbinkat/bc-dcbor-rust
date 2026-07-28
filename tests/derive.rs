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
