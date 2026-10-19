use super::harness::*;
use dcbor::bounded::{BoundedError, decode::storage::Storage};

#[test]
fn growth_admission_refusal_keeps_old_values_and_owner() {
    let mut m = meter();
    let pool = m.pool.clone();
    let mut storage = filled(&mut m);
    let stop = m.calls.len();
    m.fail_at = Some((stop, Refusal::Capacity));
    assert!(matches!(
        storage.reserve_step(&mut m),
        Err(BoundedError::Refused(Refusal::Capacity))
    ));
    assert_eq!(m.refused, Some((stop, Refusal::Capacity)));
    assert_eq!(storage.ready().unwrap(), [10, 20, 30, 40]);
    assert_eq!(pool.live(), 16);
    drop(storage);
    assert_eq!(pool.live(), 0);
}

#[test]
fn relocation_retains_actual_values_until_cancellation_not_just_their_permits() {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    struct Tracked(Arc<AtomicUsize>);
    impl Drop for Tracked {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
    every_case(4, |stop| {
        let dropped = Arc::new(AtomicUsize::new(0));
        let mut m = meter();
        let pool = m.pool.clone();
        let mut storage = Storage::new();
        for _ in 0..4 {
            assert!(storage.reserve_step(&mut m).unwrap());
            assert!(storage.push_reserved(Tracked(dropped.clone())).is_ok());
        }
        assert!(!storage.reserve_step(&mut m).unwrap());
        for _ in 0..stop {
            assert!(!storage.reserve_step(&mut m).unwrap());
        }
        let call = m.calls.len();
        m.fail_at = Some((call, Refusal::Work));
        assert!(matches!(
            storage.reserve_step(&mut m),
            Err(BoundedError::Refused(Refusal::Work))
        ));
        assert_eq!(m.refused, Some((call, Refusal::Work)));
        assert_eq!(storage.len(), 4);
        assert_eq!(storage.relocated(), stop);
        assert_eq!(
            dropped.load(Ordering::SeqCst),
            0,
            "completed values were destroyed during suspension"
        );
        assert!(pool.live() > 0);
        drop(storage);
        assert_eq!(dropped.load(Ordering::SeqCst), 4);
        assert_eq!(pool.live(), 0);
    });
}

fn filled(meter: &mut Meter) -> Storage<u32, Permit> {
    let mut storage = Storage::new();
    for value in [10, 20, 30, 40] {
        assert!(storage.reserve_step(meter).unwrap());
        storage.push_reserved(value).unwrap();
    }
    storage
}

#[test]
fn production_storage_retains_values_offsets_and_both_permits_during_growth() {
    every_case(4, |stop| {
        let mut m = meter();
        let pool = m.pool.clone();
        let mut storage = filled(&mut m);
        assert_eq!(pool.live(), 16);
        assert!(!storage.reserve_step(&mut m).unwrap());
        assert_eq!(pool.live(), 48, "old and new allocations overlap");
        assert_eq!(storage.len(), 4);
        assert!(storage.ready().is_none());
        for position in 0..4 {
            assert_eq!(storage.relocated(), position);
            if position == stop {
                let call = m.calls.len();
                m.fail_at = Some((call, Refusal::Work));
                assert!(matches!(
                    storage.reserve_step(&mut m),
                    Err(BoundedError::Refused(Refusal::Work))
                ));
                assert_eq!(m.refused, Some((call, Refusal::Work)));
                assert_eq!(storage.relocated(), position);
                assert_eq!(storage.len(), 4);
                assert_eq!(pool.live(), 48);
                m.fail_at = None;
                m.refused = None;
            }
            assert_eq!(storage.reserve_step(&mut m).unwrap(), position == 3);
        }
        assert_eq!(storage.ready().unwrap(), [10, 20, 30, 40]);
        assert_eq!(
            (m.values, m.bytes),
            (4, 16),
            "no relocated element was replayed"
        );
        m.assert_units(3, 64);
        assert_eq!(
            pool.live(),
            32,
            "old permit releases only after the last move"
        );
        storage.push_reserved(50).unwrap();
        let owned = match storage.into_owned() {
            Ok(value) => value,
            Err(_) => panic!("growth not complete"),
        };
        drop(m);
        assert_eq!(pool.live(), 32);
        assert_eq!(owned.as_slice(), [10, 20, 30, 40, 50]);
        drop(owned);
        assert_eq!(pool.live(), 0);
    });
}

#[test]
fn production_storage_cancels_at_every_partial_relocation() {
    every_case(4, |stop| {
        let mut m = meter();
        let pool = m.pool.clone();
        let mut storage = filled(&mut m);
        assert!(!storage.reserve_step(&mut m).unwrap());
        for _ in 0..stop {
            assert!(!storage.reserve_step(&mut m).unwrap());
        }
        let call = m.calls.len();
        m.fail_at = Some((call, Refusal::Work));
        assert!(matches!(
            storage.reserve_step(&mut m),
            Err(BoundedError::Refused(Refusal::Work))
        ));
        assert_eq!(m.refused, Some((call, Refusal::Work)));
        assert_eq!(storage.relocated(), stop);
        assert_eq!(pool.live(), 48);
        drop(storage);
        assert_eq!(pool.live(), 0);
    });
}

#[test]
fn draining_interrupted_relocation_keeps_both_allocations_charged() {
    every_case(4, |moved| {
        every_case(4, |stop| {
            let mut m = meter();
            let mut storage = filled(&mut m);
            assert!(!storage.reserve_step(&mut m).unwrap());
            for _ in 0..moved {
                assert!(!storage.reserve_step(&mut m).unwrap());
            }
            let before = (m.values, m.bytes);
            let mut values = Vec::new();
            for index in 0..4 {
                if index == stop {
                    let call = m.calls.len();
                    m.fail_at = Some((call, Refusal::Work));
                    assert!(matches!(
                        storage.drain_step(&mut m),
                        Err(BoundedError::Refused(Refusal::Work))
                    ));
                    assert_eq!(m.refused, Some((call, Refusal::Work)));
                    assert_eq!(storage.len(), 4 - index);
                    assert_eq!(m.pool.live(), 48);
                    m.fail_at = None;
                    m.refused = None;
                }
                m.limit_values = m.values + 3;
                m.limit_bytes = m.bytes + 64;
                values.push(storage.drain_step(&mut m).unwrap().unwrap());
                assert_eq!(storage.len(), 3 - index);
                assert_eq!(m.pool.live(), 48);
            }
            values.sort();
            assert_eq!(values, [10, 20, 30, 40]);
            assert!(storage.drain_step(&mut m).unwrap().is_none());
            assert_eq!((m.values - before.0, m.bytes - before.1), (4, 16));
            drop(storage);
            assert_eq!(m.pool.live(), 0);
        });
    });
}

#[test]
fn empty_storage_releases_old_then_new_allocation_across_refusal() {
    let mut m = meter();
    let mut storage = filled(&mut m);
    assert!(!storage.reserve_step(&mut m).unwrap());
    assert!(matches!(
        storage.release_step(&mut m),
        Err(BoundedError::PlanMismatch)
    ));
    assert_eq!(m.pool.live(), 48);
    while storage.drain_step(&mut m).unwrap().is_some() {}
    for (remaining, done) in [(32, false), (0, true)] {
        let before = m.pool.live();
        let stop = m.calls.len();
        m.fail_at = Some((stop, Refusal::Work));
        assert!(matches!(
            storage.release_step(&mut m),
            Err(BoundedError::Refused(Refusal::Work))
        ));
        assert_eq!(m.refused, Some((stop, Refusal::Work)));
        assert_eq!(m.pool.live(), before);
        m.fail_at = None;
        m.refused = None;
        assert_eq!(storage.release_step(&mut m).unwrap(), done);
        assert_eq!(m.pool.live(), remaining);
    }
    let calls = m.calls.len();
    assert!(storage.release_step(&mut m).unwrap());
    assert_eq!(m.calls.len(), calls);
    drop(storage);
    assert_eq!(m.pool.live(), 0);
}
