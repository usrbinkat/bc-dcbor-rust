#![cfg(feature = "std")]
//! The decoder's resource bound (`decode::decode_bound`) against what
//! `decode` reports through its allocator callbacks: adversarial shapes at
//! every growth boundary, maximum nesting, nested map keys, normalization
//! fallback, and every prefix of each input (each a malformed input that
//! fails part way). The bound is taken at each input's own length.
use dcbor::{
    ByteString, CBOR, Map,
    bounded::{BoundedError, Limits, decode::*},
};

/// Decode `input` under `max_depth`, and check every reported quantity
/// against the bound at its length, whatever the outcome.
fn covered(input: &[u8], max_depth: usize) -> bool {
    let bound = decode_bound::<()>(input.len() as u64, max_depth).unwrap();
    let mut limits = Limits::unlimited();
    let result = decode(input, max_depth, &mut limits);
    let decoded = result.is_ok();
    if let Ok(document) = &result {
        assert!(
            limits.live_bytes() <= bound.retained,
            "retained {} > {} for {} bytes",
            limits.live_bytes(),
            bound.retained,
            input.len()
        );
        assert!(document.node_count() as u64 <= input.len() as u64);
    }
    drop(result);
    assert_eq!(limits.live_bytes(), 0, "every permit is released");
    assert_eq!(limits.refusals(), 0, "an unlimited policy refused");
    let used = limits.used();
    assert!(
        used.values <= bound.values,
        "values {} > {}",
        used.values,
        bound.values
    );
    assert!(
        used.bytes <= bound.bytes,
        "bytes {} > {}",
        used.bytes,
        bound.bytes
    );
    assert!(
        limits.requested_bytes() <= bound.allocated,
        "allocated {} > {}",
        limits.requested_bytes(),
        bound.allocated
    );
    assert!(
        limits.peak_bytes() <= bound.peak,
        "peak {} > {}",
        limits.peak_bytes(),
        bound.peak
    );
    decoded
}

/// The input, and every proper prefix of it, under every depth limit.
fn covered_with_prefixes(input: &[u8]) {
    for max_depth in [0, 1, 2, 3, 8, 64] {
        covered(input, max_depth);
        for end in 0..input.len() {
            assert!(
                !covered(&input[..end], max_depth),
                "a proper prefix of one item is not one item"
            );
        }
    }
}

/// Nested maps whose keys are themselves maps, `levels` deep: every key
/// byte is compared at each level that contains it.
fn nested_keys(levels: usize) -> CBOR {
    let mut value = CBOR::from(0u64);
    for level in 0..levels {
        let mut map = Map::new();
        map.insert(value.clone(), level as u64);
        map.insert(
            CBOR::from(vec![value.clone(), CBOR::from(level as u64)]),
            1u64,
        );
        value = CBOR::from(map);
    }
    value
}

#[test]
fn the_bound_covers_every_growth_boundary_of_the_arena() {
    for count in [
        0usize, 1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65, 255, 256, 257,
    ] {
        let input = CBOR::from(vec![0u64; count]).to_cbor_data();
        assert!(covered(&input, 1));
        covered_with_prefixes(&input);
    }
    let wide = CBOR::from(vec![0u64; 70_000]).to_cbor_data();
    assert!(covered(&wide, 1));
}

#[test]
fn the_bound_covers_maximum_nesting_and_the_stack() {
    for depth in [1usize, 2, 3, 4, 5, 8, 9, 16, 17, 64] {
        let mut value = CBOR::from(0u64);
        for _ in 0..depth {
            value = CBOR::from(vec![value]);
        }
        let input = value.to_cbor_data();
        assert!(covered(&input, depth), "depth {depth} at its own limit");
        assert!(!covered(&input, depth - 1), "depth {depth} past the limit");
        covered_with_prefixes(&input);
    }
}

#[test]
fn the_bound_covers_nested_map_key_comparisons() {
    for levels in 1..=6 {
        let input = nested_keys(levels).to_cbor_data();
        assert!(covered(&input, 64), "{levels} levels");
        covered_with_prefixes(&input);
    }
}

#[test]
fn the_bound_covers_normalization_fallback_and_its_rejection() {
    let valid = [
        "q\u{316}\u{301}".repeat(64),
        "\u{301}".repeat(100),
        "\u{ac01}".repeat(50),
        "ordinary text".into(),
    ];
    for text in &valid {
        let input = CBOR::from(text.as_str()).to_cbor_data();
        assert!(covered(&input, 0), "{text:?}");
        covered_with_prefixes(&input);
    }
    let many = CBOR::from(vec![CBOR::from("q\u{301}"); 200]).to_cbor_data();
    assert!(covered(&many, 1));
    // Text not in NFC fails after normalization: a canonical-looking head
    // over a decomposed, reorderable payload.
    for text in ["e\u{301}", "a\u{301}\u{316}", "\u{1100}\u{1161}"] {
        let mut input = vec![0x60 | text.len() as u8];
        input.extend_from_slice(text.as_bytes());
        assert!(!covered(&input, 0), "{text:?} is not NFC");
    }
}

#[test]
fn the_bound_covers_records_and_arbitrary_bytes() {
    let mut record = Map::new();
    record.insert(0u64, ByteString::new(vec![0xa5u8; 16]));
    record.insert(1u64, u64::MAX);
    record.insert(2u64, "sha256:00ff");
    record.insert(
        3u64,
        vec![CBOR::from(true), CBOR::null(), CBOR::from(1.5f64)],
    );
    record.insert(4u64, nested_keys(2));
    let input = CBOR::from(record).to_cbor_data();
    assert!(covered(&input, 8));
    covered_with_prefixes(&input);
    let mut state = 0x9e37_79b9_7f4a_7c15u64;
    for length in 0..512usize {
        let bytes: Vec<u8> = (0..length)
            .map(|_| {
                state = state
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                (state >> 56) as u8
            })
            .collect();
        for max_depth in [0, 1, 8, 64] {
            covered(&bytes, max_depth);
        }
    }
}

#[test]
fn an_unrepresentable_bound_is_refused() {
    assert_eq!(
        decode_bound::<()>(u64::MAX, 64),
        Err(BoundedError::Overflow)
    );
    assert_eq!(
        decode_bound::<()>(0, 0).map(|bound| bound.retained),
        Ok(0),
        "an empty input reserves no arena"
    );
}
