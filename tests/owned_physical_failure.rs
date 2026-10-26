//! Terminal cleanup of a published tree allocates nothing, whichever of the
//! owner and the value is dropped first. Every physical request of an owned
//! decode failing in turn is the physical stage of the owned decode's
//! matrix (`owned_lifecycle_matrix.rs`).
#[global_allocator]
static HEAP: heap::Heap = heap::Heap;
use dcbor_test_support::heap;

#[cfg(feature = "custom-std-collections")]
#[test]
fn terminal_tree_cleanup_allocates_nothing_in_either_drop_order() {
    use dcbor::ByteString;
    use dcbor::bounded::Limits;
    use dcbor::bounded::decode::Options;
    use dcbor::bounded::decode::construction::TypedValue;
    use dcbor_test_support as support;
    use std::collections::BTreeMap;

    let mut symbolic = dcbor::Map::new();
    for key in 0..12u64 {
        symbolic.insert(key, format!("value-{key}"));
    }
    let wire = dcbor::CBOR::from(symbolic).to_cbor_data();
    for owner_first in [false, true] {
        let mut m = Limits::unlimited().logged().strict();
        let owner = support::scope(&mut m);
        let input = support::copy(&owner, &mut m, &wire);
        let value: TypedValue<'static, ByteString, BTreeMap<u64, String>, Limits> =
            support::decode(&mut m, input, Options::normalizing(8)).unwrap();
        let observation = heap::Observation::begin(None);
        if owner_first {
            drop(owner);
            // The live handle must remain usable after authority retirement.
            assert_eq!(value.value().len(), 12);
            drop(value);
        } else {
            drop(value);
            drop(owner);
        }
        observation.stop();
        assert_eq!(
            observation.snapshot().calls,
            0,
            "terminal cleanup allocated"
        );
        assert_eq!(m.live_bytes(), 0, "drop order owner_first={owner_first}");
    }
}
