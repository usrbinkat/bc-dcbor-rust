//! Every derived fixture's CDDL corresponds to its decoders: over each
//! fixture's generated domain (`dcbor_cddl_check::mutations`), the symbolic
//! decoder (`TryFrom<CBOR>`) and, where the type derives it, the bounded
//! decoder (`decode_typed`) accept exactly the items the independent CDDL
//! validator admits against the derived document. Evidence class: checked,
//! over the generated domain.
//!
//! The domain, exactly: for each fixture, its samples (below, in
//! `every_finding`), each sample's mutations one level down
//! (`dcbor_cddl_check::mutations`), every replacement drawn from the value
//! classes `dcbor_cddl_check` lists ("The value classes the domain
//! reaches": the simple values, every integer type's range edges and one
//! past them, a float, an infinity, NaN, a text, a byte string, arrays, a
//! map, and two tagged items), each distinct encoding once. What it
//! excludes, and why each exclusion is one CDDL cannot express or one no
//! dCBOR item is, is that crate's "The value classes it excludes".
//!
//! The fixtures cover each schema form the derive emits: required and
//! optional map fields, the keys no field names, a nested derived type, a
//! tag, an enum's unit, tuple and named variants, a newtype, a unit struct,
//! a generic type at two instantiations (alone and side by side in one
//! document), integer ranges at both ends of `i64` and of the unsigned
//! widths, text, byte strings, booleans and a table.
//!
//! Planted controls (`tests/data/controls/cddl-*.patch`), each in the
//! generator or the CDDL forms: a field optional in the decoders rendered
//! required; a key off by one; a tag omitted; the keys no field names
//! forbidden. Each must fail `every_fixtures_cddl_admits_exactly_what_its_
//! decoders_accept` with its named divergence.

use dcbor::bounded::Limits;
use dcbor::bounded::decode::construction::in_place::Transferable;
use dcbor::bounded::decode::decode_typed;
use dcbor::cddl::document;
use dcbor::prelude::*;
use dcbor::{CBORBoundedDecodable, CBORCddl, CBORCodable};
use dcbor_cddl_check::{Decoder, findings, mutations};
use std::collections::BTreeMap;

#[derive(CBORCodable, CBORBoundedDecodable, CBORCddl)]
struct Inner {
    #[cbor(n = 0)]
    flag: bool,
    #[cbor(n = 1)]
    bytes: ByteString,
}

#[derive(CBORCodable, CBORBoundedDecodable, CBORCddl)]
struct Record {
    #[cbor(n = 0)]
    name: String,
    #[cbor(n = 1)]
    count: u8,
    #[cbor(n = 2)]
    note: Option<String>,
    #[cbor(n = 3)]
    inner: Inner,
    #[cbor(n = 5)]
    offset: i64,
}

#[derive(CBORCodable, CBORBoundedDecodable, CBORCddl)]
#[cbor(tag = 40000)]
struct Stamped {
    #[cbor(n = 0)]
    at: u64,
}

#[derive(CBORCodable, CBORBoundedDecodable, CBORCddl)]
#[repr(u8)]
enum Shape {
    #[cbor(n = 0)]
    Point,
    #[cbor(n = 1)]
    Circle(u32),
    #[cbor(n = 2)]
    Rect {
        #[cbor(n = 0)]
        w: u16,
        #[cbor(n = 1)]
        h: Option<u16>,
    },
}

#[derive(CBORCodable, CBORBoundedDecodable, CBORCddl)]
struct Wrapper(Vec<u8>);

#[derive(CBORCodable, CBORBoundedDecodable, CBORCddl)]
struct Unit;

#[derive(CBORCodable, CBORBoundedDecodable, CBORCddl)]
struct Pair<A, B> {
    #[cbor(n = 0)]
    first: A,
    #[cbor(n = 1)]
    second: B,
}

/// Both instantiations of one generic type in one document: one rule each.
#[derive(CBORCodable, CBORBoundedDecodable, CBORCddl)]
struct Pairs {
    #[cbor(n = 0)]
    small: Pair<u8, String>,
    #[cbor(n = 1)]
    listed: Pair<Vec<u8>, bool>,
}

/// A table field: decoded symbolically only (the bounded B-tree binding is
/// the forked collections' alone).
#[derive(CBORCodable, CBORCddl)]
struct Ledger {
    #[cbor(n = 0)]
    totals: BTreeMap<String, u64>,
    #[cbor(n = 1)]
    owner: Option<i8>,
}

/// The symbolic decoder of `T`.
fn symbolic<T>(bytes: &[u8]) -> bool
where
    T: TryFrom<CBOR, Error = dcbor::Error>,
{
    CBOR::try_from_data(bytes).and_then(T::try_from).is_ok()
}

/// The bounded decoder of `T`, unlimited: its acceptance alone is compared.
fn bounded<T: Transferable<Limits> + 'static>(bytes: &[u8]) -> bool {
    decode_typed::<T, _>(bytes, 16, &mut Limits::unlimited()).is_ok()
}

/// The CBOR of a derived value, as its symbolic encoder writes it.
fn encoded(value: impl CBOREncodable) -> CBOR {
    value.encode_cbor().expect("a fixture encodes")
}

fn record(note: Option<&str>) -> Record {
    Record {
        name: "ada".into(),
        count: 255,
        note: note.map(str::to_string),
        inner: Inner {
            flag: true,
            bytes: ByteString::from(vec![0u8, 1]),
        },
        offset: i64::MIN,
    }
}

/// The findings of `fixture`, its `document` against its `decoders` over
/// the domain of its `samples`, added to `all`.
fn check(
    all: &mut Vec<String>,
    fixture: &str,
    document: String,
    samples: Vec<CBOR>,
    decoders: &[Decoder<'_>],
) {
    all.extend(findings(fixture, &document, &mutations(&samples), decoders));
}

/// Every fixture's findings: its document, its domain, its decoders.
fn every_finding() -> Vec<String> {
    let mut all = Vec::new();
    let all_ref = &mut all;
    check(
        all_ref,
        "Record",
        document::<Record>(),
        vec![encoded(record(Some("n"))), encoded(record(None))],
        &[
            ("symbolic", &symbolic::<Record>),
            ("bounded", &bounded::<Record>),
        ],
    );
    check(
        all_ref,
        "Stamped",
        document::<Stamped>(),
        vec![
            Stamped { at: u64::MAX }
                .tagged_cbor()
                .expect("a tagged fixture encodes"),
        ],
        &[
            ("symbolic", &symbolic::<Stamped>),
            ("bounded", &bounded::<Stamped>),
        ],
    );
    check(
        all_ref,
        "Shape",
        document::<Shape>(),
        vec![
            encoded(Shape::Point),
            encoded(Shape::Circle(u32::MAX)),
            encoded(Shape::Rect { w: 3, h: Some(4) }),
            encoded(Shape::Rect { w: 0, h: None }),
        ],
        &[
            ("symbolic", &symbolic::<Shape>),
            ("bounded", &bounded::<Shape>),
        ],
    );
    check(
        all_ref,
        "Wrapper",
        document::<Wrapper>(),
        vec![encoded(Wrapper(vec![0, 255])), encoded(Wrapper(Vec::new()))],
        &[
            ("symbolic", &symbolic::<Wrapper>),
            ("bounded", &bounded::<Wrapper>),
        ],
    );
    check(
        all_ref,
        "Unit",
        document::<Unit>(),
        vec![encoded(Unit)],
        &[
            ("symbolic", &symbolic::<Unit>),
            ("bounded", &bounded::<Unit>),
        ],
    );
    check(
        all_ref,
        "Pair<u8, String>",
        document::<Pair<u8, String>>(),
        vec![encoded(Pair {
            first: 7u8,
            second: "s".to_string(),
        })],
        &[
            ("symbolic", &symbolic::<Pair<u8, String>>),
            ("bounded", &bounded::<Pair<u8, String>>),
        ],
    );
    check(
        all_ref,
        "Pair<Vec<u8>, bool>",
        document::<Pair<Vec<u8>, bool>>(),
        vec![encoded(Pair {
            first: vec![1u8],
            second: false,
        })],
        &[
            ("symbolic", &symbolic::<Pair<Vec<u8>, bool>>),
            ("bounded", &bounded::<Pair<Vec<u8>, bool>>),
        ],
    );
    check(
        all_ref,
        "Pairs",
        document::<Pairs>(),
        vec![encoded(Pairs {
            small: Pair {
                first: 0,
                second: String::new(),
            },
            listed: Pair {
                first: Vec::new(),
                second: true,
            },
        })],
        &[
            ("symbolic", &symbolic::<Pairs>),
            ("bounded", &bounded::<Pairs>),
        ],
    );
    check(
        all_ref,
        "Ledger",
        document::<Ledger>(),
        vec![
            encoded(Ledger {
                totals: BTreeMap::from([("a".to_string(), 1u64), ("b".to_string(), u64::MAX)]),
                owner: Some(i8::MIN),
            }),
            encoded(Ledger {
                totals: BTreeMap::new(),
                owner: None,
            }),
        ],
        &[("symbolic", &symbolic::<Ledger>)],
    );
    all
}

/// The correspondence over every fixture's domain, every finding listed.
#[test]
fn every_fixtures_cddl_admits_exactly_what_its_decoders_accept() {
    let found = every_finding();
    assert!(
        found.is_empty(),
        "{} findings:\n{}",
        found.len(),
        found.join("\n")
    );
}

/// Each form the derive emits, pinned: a change to the generated text is
/// seen here as text, beside its semantic consequence above.
#[test]
fn every_fixtures_document_is_its_schema_in_rfc_8610() {
    let i64_range = "-9223372036854775808..9223372036854775807";
    assert_eq!(
        document::<Record>(),
        format!(
            "dcbor-root = Record\n\
             Record = {{ 0: tstr, 1: 0..255, ? 2: tstr, 3: Inner, 5: {i64_range}, * any => any }}\n\
             Inner = {{ 0: bool, 1: bstr, * any => any }}\n"
        )
    );
    assert_eq!(
        document::<Stamped>(),
        "dcbor-root = Stamped\nStamped = #6.40000({ 0: uint, * any => any })\n"
    );
    assert_eq!(
        document::<Shape>(),
        "dcbor-root = Shape\n\
         Shape = 0 / [1, 0..4294967295] / [2, { 0: 0..65535, ? 1: 0..65535, * any => any }]\n"
    );
    assert_eq!(
        document::<Wrapper>(),
        "dcbor-root = Wrapper\nWrapper = [* 0..255]\n"
    );
    assert_eq!(document::<Unit>(), "dcbor-root = Unit\nUnit = null\n");
    assert_eq!(
        document::<Pairs>(),
        "dcbor-root = Pairs\n\
         Pairs = { 0: Pair, 1: Pair-2, * any => any }\n\
         Pair = { 0: 0..255, 1: tstr, * any => any }\n\
         Pair-2 = { 0: [* 0..255], 1: bool, * any => any }\n"
    );
    assert_eq!(
        document::<Ledger>(),
        "dcbor-root = Ledger\n\
         Ledger = { 0: { * tstr => uint }, ? 1: -128..127, * any => any }\n"
    );
}

/// The check is not vacuous: the domain of a fixture holds items its
/// decoders refuse and the validator refuses, of each kind a control
/// targets, so a planted divergence of any kind has an item to show on.
#[test]
fn the_domain_holds_every_kind_of_mutation_a_control_targets() {
    let domain = mutations(&[
        encoded(record(Some("n"))),
        Stamped { at: 1 }
            .tagged_cbor()
            .expect("a tagged fixture encodes"),
        encoded(Shape::Circle(1)),
    ]);
    let labels: Vec<&str> = domain.iter().map(|item| item.label.as_str()).collect();
    for wanted in [
        "valid",
        "key 2 removed",
        "unknown key 99 added",
        "unknown key \"x\" added",
        "tag 40000 stripped",
        "tag 40000 changed to 40001",
        "discriminant 1 changed to 2",
        "key 3 > key 0 removed",
        "key 1 > replaced by u8::MAX + 1",
        "key 5 > replaced by i64::MAX + 1",
        "element 1 > replaced by u32::MAX + 1",
        "replaced by 1.5",
        "replaced by NaN",
        "replaced by tag 2 around a byte string",
    ] {
        assert!(labels.contains(&wanted), "no `{wanted}` item: {labels:?}");
    }
}
