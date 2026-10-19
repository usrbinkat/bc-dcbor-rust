use super::support::*;
use dcbor::bounded::resumable::{Fault, Outcome};

#[test]
fn cancellation_at_every_completed_unit_releases_all_capacity() {
    let wire = text_wire("q\u{301}😀");
    let mut baseline = decoder(&wire, &pool());
    drop(finish(&mut baseline));
    let units = baseline.snapshot().completed_units;
    for stop in 0..=units {
        let pool = pool();
        let mut decode = decoder(&wire, &pool);
        for _ in 0..stop {
            match decode.step(&mut budget()) {
                Outcome::Progress => {}
                Outcome::Complete(value) => {
                    drop(value);
                    break;
                }
                other => panic!("{other:?}"),
            }
        }
        drop(decode);
        assert_eq!(pool.live(), 0, "cancellation at {stop}");
    }
}

#[test]
fn completed_output_keeps_its_charge_after_decoder_destruction() {
    let pool = pool();
    let mut decode = decoder(&byte_string(65536), &pool);
    let value = finish(&mut decode);
    drop(decode);
    assert!(pool.live() >= 65536);
    drop(value);
    assert_eq!(pool.live(), 0);
}

#[test]
fn physical_allocation_failure_is_distinct_and_releases_ownership() {
    let wire = byte_string(65536);
    let mut baseline = decoder(&wire, &pool());
    drop(finish(&mut baseline));
    let allocations = baseline.snapshot().physical_allocations;
    assert!(allocations > 0);
    for index in 0..allocations {
        let pool = pool();
        let mut decode = decoder(&wire, &pool);
        decode.fail_physical_allocation_once(index);
        let mut fired = false;
        for _ in 0..wire.len() * 128 + 4096 {
            match decode.step(&mut budget()) {
                Outcome::Progress => {}
                Outcome::AllocationFailed => {
                    fired = true;
                    break;
                }
                other => panic!("allocation {index} was not failed: {other:?}"),
            }
        }
        assert!(fired);
        drop(decode);
        assert_eq!(pool.live(), 0);
    }
}

#[test]
fn shared_capacity_release_unblocks_the_same_continuation() {
    let pool = pool();
    let mut decode = decoder(&byte_string(65536), &pool);
    let held = pool.reserve(pool.available()).unwrap();
    let mut refused = false;
    for _ in 0..64 {
        match decode.step(&mut budget()) {
            Outcome::Progress => {}
            Outcome::Refused(Fault::Capacity) => {
                refused = true;
                break;
            }
            other => panic!("{other:?}"),
        }
    }
    assert!(refused);
    drop(held);
    drop(finish(&mut decode));
    assert_no_replay(decode.events());
    drop(decode);
    assert_eq!(pool.live(), 0);
}

#[test]
fn concurrent_decoders_restore_exact_pool_capacity() {
    let pool = pool();
    let capacity = pool.available();
    std::thread::scope(|scope| {
        for _ in 0..8 {
            let pool = pool.clone();
            scope.spawn(move || {
                let mut decode = decoder(&byte_string(65536), &pool);
                drop(finish(&mut decode));
            });
        }
    });
    assert_eq!(pool.available(), capacity);
    let all = pool.reserve(capacity).unwrap();
    assert!(pool.reserve(1).is_err());
    drop(all);
}
