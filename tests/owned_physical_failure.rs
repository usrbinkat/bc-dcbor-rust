//! Terminal cleanup of a published tree allocates nothing, whichever of the
//! owner and the value is dropped first. Every physical request of an owned
//! decode failing in turn is the physical stage of the owned decode's
//! matrix (`owned_lifecycle_matrix.rs`).
#[global_allocator]
static HEAP: heap::Heap = heap::Heap;
use dcbor_test_support::heap;

/// The cross-family case on a scope authority whose block fails physically:
/// the block's write admitted under `a` (its release refused), its release
/// under `b` (its request refused), its request granted under `c` and the
/// physical allocation then failing, the authority dropped under no policy.
/// The grant's write, never performed, is forfeited in `a`
/// (`AcquisitionFailed`); the release, bound to `c`'s permit at the grant and
/// performed by its drop, is consumed in `b`; `c` admitted no credit and
/// holds nothing once its permit drops. Each family records exactly its own
/// obligation, and the drop records nothing more. The scope block is the
/// observation's only physical request.
#[test]
fn an_owner_whose_scope_block_fails_physically_settles_each_obligation_in_its_own_family() {
    use dcbor::bounded::decode::construction::DecodeOwner;
    use dcbor::bounded::{BoundedError, Credits, Limits, WriteWork};

    let mut a = Limits::unlimited().refusing(Some(1));
    let mut b = Limits::unlimited().refusing_request(Some(0));
    let mut c = Limits::unlimited();
    let mut owner = DecodeOwner::<'static, Limits>::new();
    assert!(owner.initialize_step(&mut a).is_err());
    let grant = owner.held_credit().expect("the write fits in u64");
    assert!(owner.initialize_step(&mut b).is_err());
    let both = owner
        .held_credit()
        .expect("the write and release fit in u64");
    let release = WriteWork::new(both.values - grant.values, both.bytes - grant.bytes);
    assert_ne!(grant, WriteWork::default());
    assert_ne!(release, WriteWork::default());
    let observation = heap::Observation::begin(Some(0));
    let result = owner.initialize_step(&mut c);
    observation.stop();
    let stats = observation.snapshot();
    assert!(
        matches!(result, Err(BoundedError::Allocation { .. })),
        "the block's physical failure was not reported: {result:?}"
    );
    assert_eq!((stats.calls, stats.denied), (1, 1), "{stats:?}");
    assert_eq!(owner.held_credit(), Some(WriteWork::default()));
    let settled = |family: &Limits, consumed: WriteWork, forfeited: WriteWork| {
        Credits {
            admitted: consumed.checked_then(forfeited).expect("small work"),
            consumed,
            forfeited,
            violated: false,
        } == family.credits()
    };
    assert!(
        settled(&a, WriteWork::default(), grant),
        "a: {:?}",
        a.credits()
    );
    assert!(
        settled(&b, release, WriteWork::default()),
        "b: {:?}",
        b.credits()
    );
    assert_eq!(c.credits(), Credits::default(), "c admitted credit");
    drop(owner);
    assert!(settled(&a, WriteWork::default(), grant), "a after the drop");
    assert!(
        settled(&b, release, WriteWork::default()),
        "b after the drop"
    );
    assert_eq!(a.live_bytes() + b.live_bytes() + c.live_bytes(), 0);
}

#[cfg(feature = "custom-std-collections")]
#[test]
fn terminal_tree_cleanup_allocates_nothing_in_either_drop_order() {
    use dcbor::bounded::decode::Options;
    use dcbor_test_support::{self as support, DropOrder, pipeline::Physical};
    use std::collections::BTreeMap;

    let mut symbolic = dcbor::Map::new();
    for key in 0..12u64 {
        symbolic.insert(key, format!("value-{key}")).unwrap();
    }
    let wire = dcbor::CBOR::from(symbolic).to_cbor_data();
    for order in [DropOrder::ValueFirst, DropOrder::OwnerFirst] {
        support::recorded_run(|run| {
            // Every turn and every retirement runs inside the heap witness:
            // each physical request is matched to an admission, and a
            // retirement, the terminal cleanup's included, that requests
            // physical storage is the run's defect.
            let policy = run.witnessed_policy::<heap::Observation>();
            let heap = <heap::Observation as Physical>::begin(None);
            run.terminal::<BTreeMap<u64, String>, _, _>(
                policy,
                &wire,
                Options::normalizing(8),
                &heap,
                order,
                // The live handle remains usable after the authority's
                // retirement, owner first.
                |value| assert_eq!(value.value().value().len(), 12),
            )?;
            heap.finish();
            run.with_policy(policy, |m| assert_eq!(m.live_bytes(), 0, "{order:?}"));
            Ok(())
        });
    }
}
