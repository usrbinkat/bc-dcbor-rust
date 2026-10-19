#![cfg(feature = "std")]
//! The decoder's resource bound (`decode::decode_bound`) against what
//! `decode` reports through its allocator callbacks: adversarial shapes at
//! every growth boundary, maximum nesting, nested map keys, normalization
//! fallback, and every prefix of each input (each a malformed input that
//! fails part way). The bound is taken at each input's own length.
use dcbor::{
    ByteString, CBOR, Map,
    bounded::{Allocator, BoundedError, Budget, decode::*},
};
use std::{cell::Cell, rc::Rc};

/// Records every report and request, admits everything, and tracks live
/// and peak requested bytes through its permits.
#[derive(Default)]
struct Recorder {
    values: u64,
    bytes: u64,
    requested: u64,
    live: Rc<Cell<u64>>,
    peak: u64,
}

struct Permit {
    bytes: u64,
    live: Rc<Cell<u64>>,
}

impl Drop for Permit {
    fn drop(&mut self) {
        self.live.set(self.live.get() - self.bytes);
    }
}

impl Budget for Recorder {
    type Refusal = ();
    fn traverse(&mut self, values: u64, bytes: u64) -> Result<(), ()> {
        self.values = self.values.checked_add(values).ok_or(())?;
        self.bytes = self.bytes.checked_add(bytes).ok_or(())?;
        Ok(())
    }
}

impl Allocator for Recorder {
    type Permit = Permit;
    fn allocate(&mut self, bytes: u64) -> Result<Permit, ()> {
        self.requested = self.requested.checked_add(bytes).ok_or(())?;
        let live = self.live.get().checked_add(bytes).ok_or(())?;
        self.live.set(live);
        self.peak = self.peak.max(live);
        Ok(Permit {
            bytes,
            live: Rc::clone(&self.live),
        })
    }
}

/// Decode `input` under `max_depth`, and check every reported quantity
/// against the bound at its length, whatever the outcome.
fn covered(input: &[u8], max_depth: usize) -> bool {
    let bound = decode_bound::<()>(input.len() as u64, max_depth).unwrap();
    let mut recorder = Recorder::default();
    let result = decode(input, max_depth, &mut recorder);
    let decoded = result.is_ok();
    if let Ok(document) = &result {
        assert!(
            recorder.live.get() <= bound.retained,
            "retained {} > {} for {} bytes",
            recorder.live.get(),
            bound.retained,
            input.len()
        );
        assert!(document.node_count() as u64 <= input.len() as u64);
    }
    drop(result);
    assert_eq!(recorder.live.get(), 0, "every permit is released");
    assert!(
        recorder.values <= bound.values,
        "values {} > {}",
        recorder.values,
        bound.values
    );
    assert!(
        recorder.bytes <= bound.bytes,
        "bytes {} > {}",
        recorder.bytes,
        bound.bytes
    );
    assert!(
        recorder.requested <= bound.allocated,
        "allocated {} > {}",
        recorder.requested,
        bound.allocated
    );
    assert!(
        recorder.peak <= bound.peak,
        "peak {} > {}",
        recorder.peak,
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
