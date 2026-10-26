use super::harness::*;
use super::support::{Fault, pipeline::Refusal, refusal_matrix, refuse, rigor::rigor};
use dcbor::bounded::{BoundedError, Call, Failure, WriteWork, decode::storage::Storage};

/// The bytes a growth's staging block holds while it is staged: an arena
/// of `u32` with its permit, and the block's own permit.
const BLOCK: u64 = 64;

/// The units a growth of an arena of `len` elements takes before it grants
/// a slot (`Storage::grow_step`): staging, the grown allocation,
/// publication, one relocation per element, the settlement and the vacated
/// block's release; then the grant.
fn growth_units(len: usize) -> usize {
    len + 6
}

/// The units cleaning an arena of `len` elements takes
/// (`Storage::reclaim_step`): a staged growth's release, one drain per
/// element, the allocation's release, then the completing transition.
fn cleanup_units(len: usize) -> usize {
    len + 3
}

/// One reservation step to completion: every growth and relocation unit
/// taken, then the free slot filled with `value`. The storage reports
/// itself empty exactly when it holds nothing, before the push and not
/// after it. The grant observes the settled arena before the push: as many
/// elements as the storage held, empty exactly when it held none, and at
/// least one free slot.
fn push<T>(storage: &mut Storage<T, Reservation>, value: T, meter: &mut Limits) {
    let held = storage.len();
    assert_eq!(
        storage.is_empty(),
        held == 0,
        "the storage misreports emptiness of an arena of {held}"
    );
    for _ in 0..growth_units(held) {
        if let Some(spare) = storage.reserve_step(usize::MAX, meter).unwrap() {
            assert_eq!(spare.len(), held, "the grant miscounts the arena");
            assert_eq!(
                spare.is_empty(),
                held == 0,
                "the grant misreports emptiness of an arena of {held}"
            );
            assert!(spare.room() >= 1, "a grant without a free slot");
            spare.push(value);
            assert!(
                !storage.is_empty(),
                "a storage holding a push reports empty"
            );
            return;
        }
    }
    panic!("a push exceeded one growth's units");
}

/// An arena of `u32` holding ten through forty, its capacity of four full.
fn filled(meter: &mut Limits) -> Storage<u32, Reservation> {
    let mut storage = Storage::new();
    for value in [10, 20, 30, 40] {
        push(&mut storage, value, meter);
    }
    storage
}

/// Stage the growth of a full arena of four `u32`: the block staged, the
/// grown allocation requested, the relocation published. Each is one unit
/// that grants no slot.
fn begin_relocation(storage: &mut Storage<u32, Reservation>, meter: &mut Limits) {
    use dcbor::bounded::decode::construction::reclamation::Admitted;
    use dcbor::bounded::decode::storage::StorageStage;
    for stage in [
        StorageStage::Staged(Admitted::Nothing),
        StorageStage::Ready,
        StorageStage::Relocating,
    ] {
        assert!(storage.reserve_step(usize::MAX, meter).unwrap().is_none());
        let before = (meter.used(), meter.attempts(), meter.live_bytes());
        let position = storage.position();
        assert_eq!(storage.position(), position);
        assert_eq!((meter.used(), meter.attempts(), meter.live_bytes()), before);
        assert_eq!(position.stage, stage);
        assert!(position.has_current_permit);
        match stage {
            StorageStage::Staged(_) => {
                assert_eq!(position.staged_reserved_capacity, 0);
                assert_eq!(position.staged_physical_capacity, 0);
                assert!(!position.has_staged_permit);
                assert!(!position.has_relocating_permit);
                assert_eq!(meter.live_bytes(), 16 + BLOCK);
            }
            StorageStage::Ready => {
                assert_eq!(position.reserved_capacity, 4);
                assert_eq!(position.staged_reserved_capacity, 8);
                assert_eq!(position.staged_physical_capacity, 8);
                assert!(position.has_staged_permit);
                assert!(!position.has_relocating_permit);
                assert_eq!(meter.live_bytes(), 16 + 32 + BLOCK);
            }
            StorageStage::Relocating => {
                assert_eq!(position.reserved_capacity, 8);
                assert_eq!(position.relocating_remaining, 4);
                assert_eq!(position.staged_reserved_capacity, 0);
                assert!(!position.has_staged_permit);
                assert!(position.has_relocating_permit);
                assert_eq!(meter.live_bytes(), 16 + 32 + BLOCK);
            }
            _ => unreachable!("the three growth transitions above"),
        }
    }
}

#[test]
fn growth_admission_refusal_keeps_old_values_and_owner() {
    let mut m = meter();
    let pool = m.share();
    let mut storage = filled(&mut m);
    let stop = m.attempts();
    refuse(&mut m, Refusal::For(stop, LimitRefusal::Storage));
    assert!(matches!(
        storage.reserve_step(usize::MAX, &mut m),
        Err(BoundedError::Refused(LimitRefusal::Storage))
    ));
    assert_eq!(m.first_refusal(), Some((stop, LimitRefusal::Storage)));
    assert_eq!(
        storage.settled().map(|arena| arena.as_slice()),
        Some([10, 20, 30, 40].as_slice())
    );
    assert_eq!(pool.live_bytes(), 16);
    drop(storage);
    assert_eq!(pool.live_bytes(), 0);
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
    // Each of the four relocation positions: a bounded control-state
    // domain, enumerated whole.
    every_fixture(4, |stop| {
        let dropped = Arc::new(AtomicUsize::new(0));
        let mut m = meter();
        let pool = m.share();
        let mut storage = Storage::new();
        for _ in 0..4 {
            push(&mut storage, Tracked(dropped.clone()), &mut m);
        }
        for _ in 0..3 {
            assert!(storage.reserve_step(usize::MAX, &mut m).unwrap().is_none());
        }
        for _ in 0..stop {
            assert!(storage.reserve_step(usize::MAX, &mut m).unwrap().is_none());
        }
        let call = m.attempts();
        refuse(&mut m, Refusal::For(call, LimitRefusal::Work));
        assert!(matches!(
            storage.reserve_step(usize::MAX, &mut m),
            Err(BoundedError::Refused(LimitRefusal::Work))
        ));
        assert_eq!(m.first_refusal(), Some((call, LimitRefusal::Work)));
        assert_eq!(storage.len(), 4);
        assert_eq!(storage.relocated(), stop);
        assert_eq!(
            dropped.load(Ordering::SeqCst),
            0,
            "completed values were destroyed during suspension"
        );
        assert!(pool.live_bytes() > 0);
        drop(storage);
        assert_eq!(dropped.load(Ordering::SeqCst), 4);
        assert_eq!(pool.live_bytes(), 0);
    });
}

#[test]
fn production_storage_retains_values_offsets_and_both_permits_during_growth() {
    // Each of the four relocation positions, enumerated whole.
    every_fixture(4, |stop| {
        let mut m = meter();
        let pool = m.share();
        let mut storage = filled(&mut m);
        assert_eq!(pool.live_bytes(), 16);
        // The block is staged beside the arena, then the grown allocation
        // requested into it, then the relocation published: old, grown and
        // block held at once.
        begin_relocation(&mut storage, &mut m);
        assert_eq!(
            pool.live_bytes(),
            16 + 32 + BLOCK,
            "old, grown and block overlap"
        );
        assert_eq!(storage.len(), 4);
        assert!(storage.settled().is_none());
        let before = m.used();
        for position in 0..4 {
            assert_eq!(storage.relocated(), position);
            // The newest element stays the old allocation's last while any
            // element remains there to move.
            assert_eq!(
                storage.last(),
                Some(&40),
                "the newest element at relocation position {position}"
            );
            if position == stop {
                let call = m.attempts();
                refuse(&mut m, Refusal::For(call, LimitRefusal::Work));
                assert!(matches!(
                    storage.reserve_step(usize::MAX, &mut m),
                    Err(BoundedError::Refused(LimitRefusal::Work))
                ));
                assert_eq!(m.first_refusal(), Some((call, LimitRefusal::Work)));
                assert_eq!(storage.relocated(), position);
                assert_eq!(storage.len(), 4);
                assert_eq!(pool.live_bytes(), 16 + 32 + BLOCK);
                m.fail_call(None);
                m.clear_refusal();
            }
            assert!(storage.reserve_step(usize::MAX, &mut m).unwrap().is_none());
        }
        let after = m.used();
        assert_eq!(
            WriteWork::new(after.values - before.values, after.bytes - before.bytes),
            WriteWork::new(4, 16),
            "no relocated element was replayed"
        );
        m.assert_units(TURN);
        assert_eq!(
            pool.live_bytes(),
            32 + BLOCK,
            "the old permit releases after the last move, its release prepaid"
        );
        assert!(!storage.position().has_relocating_permit);
        assert_eq!(storage.last(), Some(&40), "the newest element, relocated");
        // The relocated arena settles in place, then its vacated block is
        // freed: a release its staging paid for.
        assert!(storage.reserve_step(usize::MAX, &mut m).unwrap().is_none());
        assert_eq!(
            storage.settled().map(|arena| arena.as_slice()),
            Some([10, 20, 30, 40].as_slice())
        );
        let calls = m.attempts();
        assert!(storage.reserve_step(usize::MAX, &mut m).unwrap().is_none());
        assert_eq!(m.attempts(), calls, "a prepaid release admits nothing");
        assert_eq!(pool.live_bytes(), 32);
        push(&mut storage, 50, &mut m);
        assert_eq!(storage.last(), Some(&50), "the newest element, settled");
        let owned = core::mem::take(storage.settle_step(&mut m).unwrap().unwrap());
        drop(m);
        assert_eq!(pool.live_bytes(), 32);
        assert_eq!(owned.as_slice(), [10, 20, 30, 40, 50]);
        drop(owned);
        assert_eq!(pool.live_bytes(), 0);
    });
}

#[test]
fn production_storage_cancels_at_every_partial_relocation() {
    // Each of the four relocation positions, enumerated whole.
    every_fixture(4, |stop| {
        let mut m = meter();
        let pool = m.share();
        let mut storage = filled(&mut m);
        begin_relocation(&mut storage, &mut m);
        for _ in 0..stop {
            assert!(storage.reserve_step(usize::MAX, &mut m).unwrap().is_none());
        }
        let call = m.attempts();
        refuse(&mut m, Refusal::For(call, LimitRefusal::Work));
        assert!(matches!(
            storage.reserve_step(usize::MAX, &mut m),
            Err(BoundedError::Refused(LimitRefusal::Work))
        ));
        assert_eq!(m.first_refusal(), Some((call, LimitRefusal::Work)));
        assert_eq!(storage.relocated(), stop);
        assert_eq!(pool.live_bytes(), 16 + 32 + BLOCK);
        drop(storage);
        assert_eq!(pool.live_bytes(), 0);
    });
}

#[test]
fn draining_interrupted_relocation_keeps_every_allocation_charged() {
    // Every relocation position the drain starts from, and every drained
    // element refused: two bounded domains of four, enumerated whole.
    every_fixture(4, |moved| {
        every_fixture(4, |stop| {
            let mut m = meter();
            let mut storage = filled(&mut m);
            begin_relocation(&mut storage, &mut m);
            for _ in 0..moved {
                assert!(storage.reserve_step(usize::MAX, &mut m).unwrap().is_none());
            }
            let before = m.used();
            for index in 0..4 {
                if index == stop {
                    let call = m.attempts();
                    refuse(&mut m, Refusal::For(call, LimitRefusal::Work));
                    assert!(matches!(
                        storage.reclaim_step(&mut m),
                        Err(BoundedError::Refused(LimitRefusal::Work))
                    ));
                    assert_eq!(m.first_refusal(), Some((call, LimitRefusal::Work)));
                    assert_eq!(storage.len(), 4 - index);
                    m.fail_call(None);
                    m.clear_refusal();
                }
                m.fresh();
                let held = m.live_bytes();
                assert!(!storage.reclaim_step(&mut m).unwrap());
                assert_eq!(storage.len(), 3 - index);
                // Relocating or relocated, emptiness counts both
                // allocations' elements.
                assert_eq!(
                    storage.is_empty(),
                    index == 3,
                    "an interrupted relocation misreports emptiness after drain {index}"
                );
                // The grown allocation and its block stay held while any
                // element does; the old one is released once it empties.
                assert!(m.live_bytes() >= 32 + BLOCK && m.live_bytes() <= held);
            }
            let after = m.used();
            assert_eq!(
                WriteWork::new(after.values - before.values, after.bytes - before.bytes),
                WriteWork::new(4, 16),
                "one admitted unit per drained element"
            );
            let mut done = false;
            for _ in 0..cleanup_units(storage.len()) {
                m.fresh();
                if storage.reclaim_step(&mut m).unwrap() {
                    done = true;
                    break;
                }
            }
            assert!(done, "the drained arena's cleanup exceeded its units");
            assert_eq!(m.live_bytes(), 0);
        });
    });
}

/// Custody across a whole growth, under the fault matrix: the staging
/// block's write, release and allocation, the grown allocation's, the
/// publication, each relocation and the settlement. Each refusal leaves the
/// storage's position and live bytes unchanged, the growth resumes to the
/// same arena with every allocation owned exactly once throughout (the
/// staged block, the grown allocation and the vacated block, each released
/// once), and a cancellation at any admission, the storage dropped there,
/// releases everything.
#[test]
fn a_growth_refused_at_every_admission_keeps_custody_and_resumes() {
    refusal_matrix("a growth of a full arena", rigor(), |fault: Fault| {
        let mut m = meter();
        let pool = m.share();
        let mut storage = filled(&mut m);
        // The growth alone is under test: the fill is setup.
        m.measure();
        refuse(&mut m, fault.refusal);
        // Staging and grown-allocation acquisition each retain two work
        // admissions before allocation. Splitting them at quantum exhaustion
        // adds at most two turns to the structural growth bound. A single
        // injected refusal can consume another turn without advancing growth;
        // the refuse-each schedule uses the shared expanded allowance.
        let ordinary = growth_units(storage.len()) + 2;
        let turns = match fault.refusal {
            Refusal::At(_) | Refusal::For(_, _) => ordinary + 1,
            Refusal::None | Refusal::Each => super::support::allowed(&m, ordinary),
        };
        for _ in 0..turns {
            m.turn();
            let (position, live) = (storage.position(), pool.live_bytes());
            let attempts = m.attempts();
            match storage.reserve_step(usize::MAX, &mut m) {
                Ok(Some(spare)) => {
                    spare.push(50);
                    assert_eq!(
                        storage.settled().map(|arena| arena.as_slice()),
                        Some([10, 20, 30, 40, 50].as_slice())
                    );
                    assert_eq!(pool.live_bytes(), 32, "only the grown allocation is held");
                    let calls = super::support::RefusalRun::of(&m);
                    drop(storage);
                    assert_eq!(pool.live_bytes(), 0);
                    return calls;
                }
                Ok(None) => {}
                Err(error) if error.refused() => {
                    // A step whose only attempt was refused moves nothing; one
                    // that admitted units before its refusal keeps them, as its
                    // stage records. Neither acquires nor releases storage.
                    if m.attempts() - attempts == 1 {
                        assert_eq!(storage.position(), position, "a refusal moved the storage");
                    }
                    assert_eq!(pool.live_bytes(), live, "a refusal changed what is held");
                    if fault.cancel && m.injected_refusals() > 0 {
                        let calls = super::support::RefusalRun::of(&m);
                        drop(storage);
                        assert_eq!(pool.live_bytes(), 0, "cancellation kept an allocation");
                        return calls;
                    }
                }
                Err(error) => panic!("growth failed: {error:?}"),
            }
        }
        panic!("the growth exceeded its units");
    });
}

/// The termination measure: every step of a whole growth, from staging to
/// the vacated block's release, and every step of the cleanup after it,
/// either admits work or releases an allocation its acquisition paid for,
/// so the admissions still allowed plus the allocations still held fall at
/// every step.
#[test]
fn every_growth_and_cleanup_step_lowers_the_termination_measure() {
    let mut m = meter();
    let mut storage = filled(&mut m);
    let lowered = |m: &Limits, attempts: usize, live: u64, step: &str| {
        assert!(
            m.attempts() > attempts || m.live_bytes() < live,
            "{step}: neither admitted work nor released an allocation"
        );
    };
    let mut steps = 0;
    for _ in 0..growth_units(storage.len()) {
        let (attempts, live) = (m.attempts(), m.live_bytes());
        match storage.reserve_step(usize::MAX, &mut m).unwrap() {
            // A granted slot is the growth's end, not one of its steps.
            Some(spare) => {
                spare.push(50);
                break;
            }
            None => lowered(&m, attempts, live, &format!("growth step {steps}")),
        }
        steps += 1;
    }
    // Staging, the grown allocation, publication, four relocations, the
    // settlement and the vacated block's release.
    assert_eq!(steps, 3 + 4 + 2);
    let mut done = false;
    for _ in 0..cleanup_units(storage.len()) {
        let (attempts, live) = (m.attempts(), m.live_bytes());
        done = storage.reclaim_step(&mut m).unwrap();
        lowered(&m, attempts, live, &format!("cleanup step {steps}"));
        steps += 1;
        if done {
            break;
        }
    }
    assert!(done, "cleanup exceeded its units");
    assert_eq!(m.live_bytes(), 0);
}

/// A cancellation's forfeit: an acquisition whose allocation is refused
/// keeps exactly its two admitted units, the block's write and its
/// release, repeats neither when it resumes, and forfeits exactly those
/// two, no more, when it is cancelled instead.
#[test]
fn a_refused_acquisition_keeps_and_forfeits_one_write_and_one_release() {
    for resumed in [true, false] {
        let mut m = meter();
        let mut storage = filled(&mut m);
        let start = m.admitted().len();
        // The staging block's write, its release, then its allocation,
        // refused.
        let refused = m.attempts() + 2;
        refuse(&mut m, Refusal::For(refused, LimitRefusal::Storage));
        assert!(matches!(
            storage.reserve_step(usize::MAX, &mut m),
            Err(BoundedError::Refused(LimitRefusal::Storage))
        ));
        assert_eq!(
            &m.admitted()[start..],
            [
                Call::Work {
                    values: 1,
                    bytes: BLOCK
                },
                Call::Work {
                    values: 1,
                    bytes: 16
                }
            ],
            "the block's write and its release, admitted before its allocation"
        );
        assert_eq!(
            m.live_bytes(),
            16,
            "nothing allocated for the refused block"
        );
        m.fail_call(None);
        m.clear_refusal();
        let kept = m.admitted().len();
        if resumed {
            assert!(storage.reserve_step(usize::MAX, &mut m).unwrap().is_none());
            assert_eq!(
                &m.admitted()[kept..],
                [Call::Allocate(BLOCK)],
                "a resumed acquisition repeats no admitted unit"
            );
        } else {
            // Cancelled: the retained admissions are dropped with the
            // growth, never repeated or refunded.
            let position = storage.position();
            let paid = m.used();
            let held = m.live_bytes();
            let refusal = m.attempts();
            m.refuse_next();
            assert!(matches!(
                storage.reclaim_step(&mut m),
                Err(BoundedError::Refused(LimitRefusal::Scheduled(at))) if at == refusal
            ));
            assert_eq!(
                m.first_refusal(),
                Some((refusal, LimitRefusal::Scheduled(refusal)))
            );
            assert_eq!(
                storage.position(),
                position,
                "refused cleanup forfeited retained admissions"
            );
            assert_eq!(m.used(), paid);
            assert_eq!(m.live_bytes(), held);
            m.clear_refusal();
            let mut done = false;
            for _ in 0..cleanup_units(storage.len()) {
                m.fresh();
                done = storage.reclaim_step(&mut m).unwrap();
                if done {
                    break;
                }
            }
            assert!(done, "the cancelled growth's cleanup exceeded its units");
            let cleanup = &m.admitted()[kept..];
            assert!(
                !cleanup.iter().any(|call| matches!(call, Call::Allocate(_))),
                "a cancelled acquisition allocated: {cleanup:?}"
            );
            for forfeited in &m.admitted()[start..kept] {
                assert!(
                    !cleanup.contains(forfeited),
                    "a forfeited unit was admitted again: {cleanup:?}"
                );
            }
        }
        drop(storage);
        assert_eq!(m.live_bytes(), 0);
    }
}

#[test]
fn cleanup_refusals_keep_the_storage_and_prepaid_releases_admit_nothing() {
    let mut m = meter();
    let mut storage = filled(&mut m);
    begin_relocation(&mut storage, &mut m);
    assert_eq!(m.live_bytes(), 16 + 32 + BLOCK);
    let mut done = false;
    // Each unit is refused once before it runs, both within one iteration;
    // relocation units run while it drains.
    for _ in 0..growth_units(storage.len()) + cleanup_units(storage.len()) {
        if done {
            break;
        }
        let (position, live) = (storage.position(), m.live_bytes());
        let attempts = m.attempts();
        refuse(&mut m, Refusal::For(attempts, LimitRefusal::Work));
        match storage.reclaim_step(&mut m) {
            Err(BoundedError::Refused(LimitRefusal::Work)) => {
                assert_eq!(m.first_refusal(), Some((attempts, LimitRefusal::Work)));
                assert_eq!(storage.position(), position, "a refusal moved the storage");
                assert_eq!(m.live_bytes(), live, "a refusal released storage");
                m.fail_call(None);
                m.clear_refusal();
                m.fresh();
                done = storage.reclaim_step(&mut m).unwrap();
            }
            // A step that released what an acquisition paid for admits
            // nothing, so the scheduled refusal stays unreached.
            Ok(finished) => {
                assert_eq!(m.attempts(), attempts, "a prepaid release admitted work");
                m.fail_call(None);
                done = finished;
            }
            Err(error) => panic!("cleanup failed: {error:?}"),
        }
    }
    assert!(
        done,
        "the interrupted relocation's cleanup exceeded its units"
    );
    assert_eq!(m.live_bytes(), 0);
    let calls = m.calls().len();
    m.fresh();
    assert!(storage.reclaim_step(&mut m).unwrap());
    assert_eq!(
        m.calls().len(),
        calls + 1,
        "a released arena admits its transition"
    );
    drop(storage);
    assert_eq!(m.live_bytes(), 0);
}
