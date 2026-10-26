//! Public wire contracts for the expanded bounded API. Literal fixtures are
//! authoritative; symbolic comparisons supplement them.
#![cfg_attr(feature = "custom-std-collections", feature(hashmap_bucket_access))]
#[cfg(feature = "custom-std-collections")]
use dcbor::HashMap;
use dcbor::{
    CBOR, CBORCase, Date,
    bounded::{
        decode::{DecodeError, Kind, decode},
        encoding::Shape,
        *,
    },
};
#[cfg(all(feature = "hashbrown", not(feature = "custom-std-collections")))]
use hashbrown::HashMap;
use std::collections::BTreeMap;

fn policy() -> Limits {
    Limits::new(10_000_000, 100_000_000, 10_000_000)
}

/// `value` encodes to `expected`, its published arena holding at least those
/// bytes and at most what [`encode_bound`] retains, and decodes back to them;
/// the decode releases all it held, and the encoding's release the rest.
fn literal<T: Schema + ?Sized>(value: &T, expected: &[u8]) {
    let source: &dyn Schema = &value;
    let shape = Shape::of(source, &mut Limits::unlimited()).expect("the source is walkable");
    let retained = encode_bound::<Reservation, ()>(shape)
        .expect("the bound fits in u64")
        .retained;
    let mut limits = policy();
    let encoded = encode(value, &mut limits).unwrap();
    assert_eq!(encoded.as_ref(), expected);
    let held = limits.live_bytes();
    assert!(
        expected.len() as u64 <= held && held <= retained,
        "{} encoded bytes held in {held}, bounded by {retained}",
        expected.len()
    );
    let document = decode(encoded.as_ref(), 128, &mut limits).unwrap();
    assert_eq!(document.root().encoded(), expected);
    drop(document);
    assert_eq!(limits.live_bytes(), held);
    drop(encoded);
    assert_eq!(limits.live_bytes(), 0);
}

#[test]
fn new_representations_have_literal_wire_contracts() {
    literal(&None::<bool>, &[0xf6]);
    literal(&Some(false), &[0xf4]);
    literal(&Some(None::<bool>), &[0xf6]);
    literal(
        &Tagged {
            tag: 24,
            value: true,
        },
        &[0xd8, 24, 0xf5],
    );
    literal(&Date::from_timestamp(0.5), &[0xc1, 0xf9, 0x38, 0x00]);
    literal(&Date::from_timestamp(-1.0), &[0xc1, 0x20]);
    literal(
        &CBOR::from(CBORCase::Negative(i64::MAX as u64)),
        &hex_literal::hex!("3b7fffffffffffffff"),
    );
    let symbolic = CBOR::from(CBORCase::Array(vec![
        CBOR::from(CBORCase::Text("e\u{301}".into())),
        CBOR::null(),
    ]));
    literal(&symbolic, &[0x82, 0x62, 0xc3, 0xa9, 0xf6]);
    let mut limits = policy();
    assert!(matches!(
        encode(&CBOR::from(CBORCase::Negative(u64::MAX)), &mut limits),
        Err(BoundedError::OutOfRange)
    ));
    assert_eq!(limits.live_bytes(), 0);
}

/// Byte strings and texts at each head width the published vectors use:
/// a one-byte head, a two-byte head of a 32-byte payload, and a three-byte
/// head of a 445-byte text.
#[test]
fn byte_strings_and_texts_have_literal_wire_contracts() {
    use hex_literal::hex;
    literal(
        &dcbor::ByteString::from(hex!("00112233")),
        &hex!("4400112233"),
    );
    literal(
        &dcbor::ByteString::from(hex!(
            "c0a7da14e5847c526244f7e083d26fe33f86d2313ad2b77164233444423a50a7"
        )),
        &hex!("5820c0a7da14e5847c526244f7e083d26fe33f86d2313ad2b77164233444423a50a7"),
    );
    literal("Hello", &hex!("6548656c6c6f"));
    let lorem = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod \
                 tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, \
                 quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo \
                 consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse \
                 cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non \
                 proident, sunt in culpa qui officia deserunt mollit anim id est laborum.";
    assert_eq!(lorem.len(), 0x1bd);
    let mut expected = vec![0x79, 0x01, 0xbd];
    expected.extend_from_slice(lorem.as_bytes());
    literal(lorem, &expected);
}

#[test]
fn maps_sort_encoded_keys_and_refuse_canonical_collisions() {
    // Rust string order differs from bytewise CBOR order (length head first).
    let map = BTreeMap::from([("aa", 1u64), ("b", 2)]);
    let expected = [0xa2, 0x61, b'b', 2, 0x62, b'a', b'a', 1];
    literal(&map, &expected);
    #[cfg(any(feature = "hashbrown", feature = "custom-std-collections"))]
    literal(&HashMap::from([("b", 2u64), ("aa", 1)]), &expected);
    literal(&dcbor::Map::from(map.clone()), &expected);
    literal(&CBOR::from(map), &expected);
    let collision = BTreeMap::from([("\u{e9}", 1u8), ("e\u{301}", 2)]);
    let mut limits = policy();
    assert!(matches!(
        encode(&collision, &mut limits),
        Err(BoundedError::DuplicateKey)
    ));
    assert_eq!(limits.live_bytes(), 0);
    // Exercise both heap-building and extraction on multiple map sizes.
    for n in 0..80 {
        let map: BTreeMap<_, _> = (0..n).map(|k| (format!("key-{k}"), k)).collect();
        literal(&map, &CBOR::from(map.clone()).to_cbor_data());
    }
}

/// Every key hashes to all ones: its home bucket is a table's last.
#[cfg(any(feature = "hashbrown", feature = "custom-std-collections"))]
#[derive(Default)]
struct Last;
#[cfg(any(feature = "hashbrown", feature = "custom-std-collections"))]
impl std::hash::Hasher for Last {
    fn finish(&self) -> u64 {
        u64::MAX
    }
    fn write(&mut self, _: &[u8]) {}
}

/// The vacant buckets before a hash map's last entry are scanned, each
/// window admitted before it is inspected: a large table whose one entry lies
/// in its last bucket is refused under a budget short of that scan, holding
/// nothing. A table of no entries ends at its head, whatever its size: its
/// walk asks for no window, only the map's end.
#[test]
#[cfg(any(feature = "hashbrown", feature = "custom-std-collections"))]
fn sparse_hash_map_iteration_is_admitted() {
    type Hashed = std::hash::BuildHasherDefault<Last>;
    let mut map = HashMap::<u64, u64, Hashed>::with_capacity_and_hasher(100_000, Hashed::default());
    map.insert(7, 7);
    assert_eq!(
        map.get_bucket(map.num_buckets() - 1),
        Some((&7, &7)),
        "the entry lies in the last bucket"
    );
    let mut limits = Limits::new(100, 100, 100);
    assert!(matches!(
        encode(&map, &mut limits),
        Err(BoundedError::Refused(LimitRefusal::Work))
    ));
    assert_eq!(limits.live_bytes(), 0);

    let empty = HashMap::<u64, u64, Hashed>::with_capacity_and_hasher(100_000, Hashed::default());
    let source: &dyn Schema = &empty;
    let shape = Shape::of(source, &mut Limits::unlimited()).expect("the source is walkable");
    assert_eq!(
        shape.dynamic, 1,
        "an empty map's walk asks only for its end"
    );
    let mut limits = policy();
    let encoded = encode(&empty, &mut limits).unwrap();
    assert_eq!(encoded.as_ref(), &[0xa0]);
    drop(encoded);
    assert_eq!(limits.live_bytes(), 0);
}

#[test]
fn symbolic_depth_limit_refuses_before_unbounded_recursion() {
    let mut value = CBOR::from(0);
    for _ in 0..127 {
        value = CBOR::from(CBORCase::Array(vec![value]));
    }
    let mut limits = policy();
    let encoded = encode(&value, &mut limits).unwrap();
    assert_eq!(encoded.as_ref().len(), 128);
    drop(encoded);
    let deeper = CBOR::from(CBORCase::Array(vec![value]));
    assert!(matches!(
        encode(&deeper, &mut limits),
        Err(BoundedError::DepthLimit)
    ));
    assert_eq!(limits.live_bytes(), 0);
}

#[test]
fn borrowed_document_exposes_immediate_children_and_original_payloads() {
    let input = hex_literal::hex!("a20182617842010202c1f93800");
    let mut limits = policy();
    let document = decode(&input, 3, &mut limits).unwrap();
    assert_eq!(document.node_count(), 8);
    assert_eq!(document.root().kind(), Kind::Map(2));
    let nodes: Vec<_> = document.root().children().collect();
    assert_eq!(nodes.len(), 4);
    assert_eq!(nodes[0].kind(), Kind::Unsigned(1));
    assert_eq!(nodes[1].encoded(), &input[2..8]);
    let array: Vec<_> = nodes[1].children().collect();
    assert_eq!(array[0].kind(), Kind::Text("x"));
    let Kind::Bytes(bytes) = array[1].kind() else {
        panic!("byte payload")
    };
    assert_eq!(bytes.as_ptr(), input[6..].as_ptr());
    assert_eq!(nodes[3].kind(), Kind::Tagged(1));
    assert_eq!(nodes[3].children().next().unwrap().kind(), Kind::Float(0.5));
    assert_eq!(nodes[0].children().count(), 0);
    drop(document);
    assert_eq!(limits.live_bytes(), 0);
}

#[test]
fn strict_decoder_rejects_literal_invalid_inputs() {
    for input in [
        &[][..],
        &[0x18, 0],
        &[0x9f, 0xff],
        &[0x61, 0xff],
        &[0x63, b'e', 0xcc, 0x81],
        &[0xf9, 0x3c, 0],
        &[0xf9, 0x80, 0],
        &[0xf9, 0x7e, 1],
        &[0xf8, 20],
        &[0xf7],
        &[0, 0],
        &[0xa2, 1, 0, 1, 0],
        &[0xa2, 2, 0, 1, 0],
        &[0x3b, 0x80, 0, 0, 0, 0, 0, 0, 0],
        &[0x5b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
    ] {
        let mut limits = policy();
        assert!(decode(input, 32, &mut limits).is_err(), "{input:x?}");
        assert_eq!(limits.live_bytes(), 0);
    }
    for input in [&[0xa2, 1, 0, 1, 0][..], &[0xa2, 0x81, 1, 0, 0x81, 1, 0]] {
        assert!(matches!(
            decode(input, 32, &mut policy()),
            Err(DecodeError::Invalid(dcbor::Error::DuplicateMapKey))
        ));
    }
    // A Maybe quick check must still accept genuinely normalized text.
    literal("q\u{301}", &[0x63, b'q', 0xcc, 0x81]);
}

#[test]
fn decoding_deep_inputs_and_drop_are_iterative() {
    let mut bytes = vec![0x81; 10_000];
    bytes.push(0);
    let mut limits = policy();
    assert!(matches!(
        decode(&bytes, 9_999, &mut limits),
        Err(DecodeError::DepthLimit { limit: 9_999 })
    ));
    assert_eq!(limits.live_bytes(), 0);
    let document = decode(&bytes, 10_000, &mut limits).unwrap();
    assert_eq!(document.node_count(), 10_001);
    drop(document);
    assert_eq!(limits.live_bytes(), 0);
    assert!(decode(&[0], 0, &mut limits).is_ok());
    assert!(decode(&[0x80], 0, &mut limits).is_ok());
    assert!(matches!(
        decode(&[0x81, 0], 0, &mut limits),
        Err(DecodeError::DepthLimit { .. })
    ));
}

#[test]
fn bounded_and_symbolic_decoder_acceptance_agree_for_short_inputs() {
    for bits in 0..=u16::MAX {
        let bytes = bits.to_be_bytes();
        for input in [&bytes[..1], &bytes[..]] {
            let mut limits = policy();
            let bounded = decode(input, 4, &mut limits);
            let symbolic = CBOR::try_from_data(input);
            assert_eq!(bounded.is_ok(), symbolic.is_ok(), "{input:x?}");
            if let Ok(document) = bounded {
                assert_eq!(document.root().encoded(), input);
            }
            assert_eq!(limits.live_bytes(), 0);
        }
    }
}

#[cfg(feature = "num-bigint")]
#[test]
fn bignums_have_literal_zero_and_borrow_boundary_encodings() {
    use num_bigint::{BigInt, BigUint};
    literal(&BigUint::from(0u32), &[0xc2, 0x40]);
    literal(&BigInt::from(-1), &[0xc3, 0x41, 0]);
    literal(&BigInt::from(-256), &[0xc3, 0x41, 0xff]);
    literal(&BigInt::from(-257), &[0xc3, 0x42, 1, 0]);
    literal(
        &-(BigInt::from(1) << 64usize),
        &hex_literal::hex!("c348ffffffffffffffff"),
    );
    for bits in [8usize, 16, 31, 32, 33, 63, 64, 65, 127, 128, 129, 1024] {
        let power = BigInt::from(1) << bits;
        for value in [
            &power - 1,
            power.clone(),
            &power + 1,
            -&power - 1,
            -&power,
            -&power + 1,
        ] {
            literal(&value, &CBOR::from(&value).to_cbor_data());
        }
    }
}
