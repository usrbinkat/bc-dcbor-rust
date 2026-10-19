//! Negative controls for the acceptance assertions themselves.
//! These tests never stand in for execution of the production codec.
use super::support::*;
use dcbor::bounded::resumable::{Event, Operation};

#[test]
fn replay_detector_rejects_empty_instrumentation() {
    assert!(std::panic::catch_unwind(|| assert_no_replay(&[])).is_err());
}

#[test]
fn replay_detector_rejects_overlap_not_only_identical_ranges() {
    let operation = Operation::payload_validation(0);
    let events = [
        Event::Completed {
            operation,
            start: 0,
            end: 64,
        },
        Event::Completed {
            operation,
            start: 63,
            end: 128,
        },
    ];
    assert!(std::panic::catch_unwind(|| assert_no_replay(&events)).is_err());
}

#[test]
fn replay_detector_accepts_disjoint_chunks_and_distinct_semantic_passes() {
    let validate = Operation::payload_validation(0);
    let copy = Operation::payload_copy(0);
    assert_no_replay(&[
        Event::Completed {
            operation: validate,
            start: 0,
            end: 64,
        },
        Event::Completed {
            operation: validate,
            start: 64,
            end: 128,
        },
        Event::Completed {
            operation: copy,
            start: 0,
            end: 128,
        },
    ]);
}

#[test]
fn rejected_split_preserves_both_owner_and_pool() {
    let pool = pool();
    let capacity = pool.available();
    let mut permit = pool.reserve(3).unwrap();
    for requested in [4, u64::MAX] {
        assert!(permit.split(requested).is_err());
        assert_eq!(permit.bytes(), 3);
        assert_eq!(pool.available(), capacity - 3);
    }
    drop(permit);
    assert_eq!(pool.available(), capacity);
}

#[test]
fn failed_capacity_admission_does_not_release_an_existing_owner() {
    let pool = pool();
    let capacity = pool.available();
    let first = pool.reserve(capacity).unwrap();
    for _ in 0..3 {
        assert!(pool.reserve(1).is_err());
        assert_eq!(pool.live(), capacity);
        assert_eq!(pool.available(), 0);
    }
    drop(first);
    assert_eq!(pool.available(), capacity);
}
