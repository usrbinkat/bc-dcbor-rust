//! Models of the decode scope's atomic protocol: retirement onto the
//! intrusive queue, the stepping flag, the retained removal admission, the
//! scope's reference count and the last reference's terminal drain, run under
//! a model checker's threads and atomics ([`crate::sync`]), against the
//! shipped protocol and accounting: every contract quantity is the
//! production representation's in these builds too.
//!
//! Each scenario is one body both checkers run, and each (scenario, worker
//! count) is a test of its own, so a gate row is one process: a checker that
//! abandons a failed execution leaves nothing behind for another model.
//!
//! - loom (`cfg(loom)`): every interleaving of one to four workers beside
//!   the main thread (loom's thread limit is five, the main thread
//!   included), with no preemption bound, and the outcomes the acquire and
//!   release orderings permit; the queued record's custody is a tracked cell
//!   ([`crate::sync::LoomCell`]), so a publication that does not order its
//!   write before the stepper's read fails the model.
//! - shuttle (`cfg(all(shuttle, not(loom)))`): every schedule of five
//!   workers, the first count loom cannot reach, by shuttle's exhaustive
//!   depth-first scheduler, each schedule replayed and required to reach the
//!   same runnable tasks at every step. shuttle treats every ordering as
//!   `SeqCst`, so its guarantee is exhaustive under sequential consistency.
//!
//! Every model is configured by the one runner (`tests/support/model.rs`),
//! its bound recorded and derived by the gate (`tests/gate`). Each
//! scenario's oracle is the scope's own accounting, admission-level facts
//! valid in every build: a record released twice panics in the permit's
//! release (`Reservation::drop`), a record never released leaves live bytes,
//! every step of a drain leaves live bytes and outstanding records no higher
//! than before it (`Draining`, FF-13's data invariants, checked in every
//! interleaving), and every scenario ends with no live byte. Physical allocation is checked
//! natively and under Miri: inside a model the global heap observer cannot
//! tell the checker's allocations from the library's, and the library's
//! `Allocator` grants permits only, no memory (`src/bounded.rs`), so no
//! allocator handed to the scope could. The storage counters' `Arc` is
//! `alloc`'s, not loom's (a permit holding loom's would exceed
//! `PERMIT_BYTES`), so loom's own leak check does not see it; the live-byte
//! count does.

extern crate alloc;

use alloc::{sync::Arc, vec::Vec};

#[cfg(loom)]
use loom::thread;
#[cfg(all(shuttle, not(loom)))]
use shuttle::thread;

use crate::bounded::Limits;
use crate::bounded::decode::construction::reclamation::{
    Acquisition, DecodeOwner, OwnedRecord, Reclaimed,
};

type Owner = DecodeOwner<'static, Limits>;
type Record = OwnedRecord<'static, u64, Limits>;

/// The test target the models' bounds are recorded under.
const TARGET: &str = "lib";

/// The model a test of this module is, as the bounds record names it: its
/// path within the crate, `module` the test's module path.
fn model(module: &'static str) -> &'static str {
    module
        .strip_prefix("dcbor::")
        .unwrap_or_else(|| panic!("{module} is a path of this crate"))
}

fn initialized(m: &mut Limits) -> Owner {
    let mut owner = Owner::new();
    owner
        .initialize_step(m)
        .expect("an unlimited policy admits the scope");
    owner
}

fn allocated(owner: &Owner, m: &mut Limits) -> Record {
    owner
        .allocate_step::<u64>(m, &mut Acquisition::new())
        .expect("an unlimited policy admits a record")
}

/// The data invariants of a draining scope, checked at every step of every
/// interleaving (FF-13): once no record is allocated any more, what the
/// storage holds and what the scope counts outstanding never rise, whichever
/// thread steps, retires or links; an interleaving that grows either has
/// acquired, or recounted, what a drain only releases.
struct Draining {
    live: u64,
    outstanding: usize,
}

impl Draining {
    fn new(owner: &Owner, m: &Limits) -> Self {
        Self {
            live: m.live_bytes(),
            outstanding: owner.outstanding(),
        }
    }

    /// The invariants after one step: neither quantity rose.
    fn step(&mut self, owner: &Owner, m: &Limits, at: &str) {
        let (live, outstanding) = (m.live_bytes(), owner.outstanding());
        assert!(
            live <= self.live,
            "{at}: live bytes rose from {} to {live} while the scope drained",
            self.live
        );
        assert!(
            outstanding <= self.outstanding,
            "{at}: outstanding records rose from {} to {outstanding} while the scope drained",
            self.outstanding
        );
        (self.live, self.outstanding) = (live, outstanding);
    }
}

/// Shut the scope down, yielding to the model's other threads whenever
/// nothing can advance until one of them retires or links a record; the
/// draining invariants checked at every step ([`Draining`]).
fn shut_down(owner: &mut Owner, m: &mut Limits) {
    let mut draining = Draining::new(owner, m);
    loop {
        let reclaimed = owner
            .shutdown_step(m)
            .expect("an unlimited policy admits every cleanup unit");
        draining.step(owner, m, "the authority's shutdown");
        match reclaimed {
            Reclaimed::Done => return,
            Reclaimed::Progress => {}
            Reclaimed::Waiting => thread::yield_now(),
        }
    }
}

fn released(m: &Limits, scenario: &str) {
    assert_eq!(
        m.live_bytes(),
        0,
        "{scenario}: a record or the scope outlived the drain"
    );
}

/// Workers retire their records while the authority shuts the scope down:
/// shutdown completes only after every record is pushed, linked, removed
/// and released once, and every worker's scope reference is returned.
fn retirements_race_shutdown(workers: usize) {
    let mut m = Limits::unlimited();
    let mut owner = initialized(&mut m);
    let retiring: Vec<_> = (0..workers)
        .map(|_| {
            let record = allocated(&owner, &mut m);
            thread::spawn(move || drop(record))
        })
        .collect();
    shut_down(&mut owner, &mut m);
    for worker in retiring {
        worker.join().expect("a retiring worker panicked");
    }
    released(&m, "retirements racing shutdown");
}

/// Workers retire their records and step the shared queue, each with its own
/// policy over the same storage: one steps at a time, a concurrent caller
/// performs and admits nothing, a removal raced by a retiring thread keeps
/// its admission, and the authority drains what the workers left.
fn contended_queue_step(workers: usize) {
    let mut m = Limits::unlimited();
    let owner = initialized(&mut m);
    let records: Vec<_> = (0..workers).map(|_| allocated(&owner, &mut m)).collect();
    let owner = Arc::new(owner);
    let stepping: Vec<_> = records
        .into_iter()
        .map(|record| {
            let owner = Arc::clone(&owner);
            let mut local = m.share();
            thread::spawn(move || {
                drop(record);
                let mut draining = Draining::new(&owner, &local);
                loop {
                    let reclaimed = owner
                        .step(&mut local)
                        .expect("an unlimited policy admits every cleanup unit");
                    draining.step(&owner, &local, "a stepping worker");
                    if reclaimed != Reclaimed::Progress {
                        break;
                    }
                }
            })
        })
        .collect();
    for worker in stepping {
        worker.join().expect("a stepping worker panicked");
    }
    let mut owner = Arc::try_unwrap(owner)
        .ok()
        .expect("every worker's reference to the authority was dropped at its join");
    shut_down(&mut owner, &mut m);
    released(&m, "contended queue step");
}

/// The authority is dropped while workers still hold records: the scope is
/// abandoned, each retirement continues its terminal drain, and the last
/// reference released drains what remains and frees the scope.
fn last_worker_reclaims(workers: usize) {
    let mut m = Limits::unlimited();
    let owner = initialized(&mut m);
    let retiring: Vec<_> = (0..workers)
        .map(|_| {
            let record = allocated(&owner, &mut m);
            thread::spawn(move || drop(record))
        })
        .collect();
    drop(owner);
    for worker in retiring {
        worker.join().expect("a retiring worker panicked");
    }
    released(&m, "last worker reclaims");
}

/// A record carried across `hops` workers, the last of which retires it
/// while the authority shuts the scope down, or retired on the main thread
/// itself when `hops` is zero; the policy that drained it. Spawns `hops`
/// threads in all.
fn drained(hops: usize) -> Limits {
    let mut m = Limits::unlimited().logged();
    let mut owner = initialized(&mut m);
    let record = allocated(&owner, &mut m);
    m.measure();
    let retiring = if hops == 0 {
        drop(record);
        None
    } else {
        let mut carried = record;
        for _ in 1..hops {
            carried = thread::spawn(move || carried)
                .join()
                .expect("a carrying worker panicked");
        }
        Some(thread::spawn(move || drop(carried)))
    };
    shut_down(&mut owner, &mut m);
    if let Some(worker) = retiring {
        worker.join().expect("the retiring worker panicked");
    }
    released(&m, "worker transfer");
    m
}

/// A record handed between workers is drained with exactly the admissions a
/// record retired on the authority's own thread takes: moving a handle
/// replays nothing. Waiting steps admit nothing and a removal raced by the
/// retirement keeps its admission, so the admitted sequence is the same in
/// every interleaving.
fn worker_transfer(workers: usize) {
    let threaded = drained(workers);
    let local = drained(0);
    assert_eq!(
        threaded.admitted(),
        local.admitted(),
        "a transferred record's drain admitted differently from a local one's"
    );
}

/// The I3 witness under the build's atomics: a scope and a record admit
/// their production representation, though the checker's atomics are what
/// is stored. One thread.
fn production_representation() {
    crate::bounded::decode::construction::reclamation::admits_its_production_representation();
}

#[cfg(loom)]
mod loom_models {
    /// Every interleaving of `scenario` with `workers` workers beside the
    /// main thread, as the model `module`.
    fn exhaustive(module: &'static str, scenario: fn(usize), workers: usize) {
        dcbor_test_support::model::loom(
            super::TARGET,
            super::model(module),
            workers + 1,
            move || scenario(workers),
        );
    }

    /// One test per worker count of `$scenario`, each its own model.
    macro_rules! scenario {
        ($scenario:ident: $($test:ident = $workers:literal),+) => {
            mod $scenario {
                $(
                    #[test]
                    fn $test() {
                        super::exhaustive(
                            concat!(module_path!(), "::", stringify!($test)),
                            crate::sync::models::$scenario,
                            $workers,
                        );
                    }
                )+
            }
        };
    }

    scenario!(retirements_race_shutdown: workers_1 = 1, workers_2 = 2, workers_3 = 3, workers_4 = 4);
    scenario!(contended_queue_step: workers_1 = 1, workers_2 = 2, workers_3 = 3, workers_4 = 4);
    scenario!(last_worker_reclaims: workers_1 = 1, workers_2 = 2, workers_3 = 3, workers_4 = 4);
    scenario!(worker_transfer: workers_1 = 1, workers_2 = 2, workers_3 = 3, workers_4 = 4);

    /// I3 under loom's atomics: one thread.
    #[test]
    fn production_representation() {
        dcbor_test_support::model::loom(
            super::TARGET,
            super::model(concat!(module_path!(), "::production_representation")),
            1,
            super::production_representation,
        );
    }
}

#[cfg(all(shuttle, not(loom)))]
mod shuttle_models {
    /// Every schedule of `scenario` with `workers` workers beside the main
    /// thread, as the model `module`.
    fn exhaustive(module: &'static str, scenario: fn(usize), workers: usize) {
        dcbor_test_support::model::shuttle(super::TARGET, super::model(module), move || {
            scenario(workers)
        });
    }

    /// The test of `$scenario` at five workers, the first count loom cannot
    /// reach.
    macro_rules! scenario {
        ($scenario:ident) => {
            mod $scenario {
                #[test]
                fn workers_5() {
                    super::exhaustive(
                        concat!(module_path!(), "::workers_5"),
                        crate::sync::models::$scenario,
                        5,
                    );
                }
            }
        };
    }

    scenario!(retirements_race_shutdown);
    scenario!(contended_queue_step);
    scenario!(last_worker_reclaims);
    scenario!(worker_transfer);

    /// I3 under shuttle's atomics: one task.
    #[test]
    fn production_representation() {
        dcbor_test_support::model::shuttle(
            super::TARGET,
            super::model(concat!(module_path!(), "::production_representation")),
            super::production_representation,
        );
    }
}
