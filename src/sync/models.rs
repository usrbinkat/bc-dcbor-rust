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

use crate::bounded::decode::construction::reclamation::{
    Acquisition, DecodeOwner, OwnedRecord, Reclaimed,
};
use crate::bounded::{Call, Capacity, Limits, Session, Step};

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

/// Workers reclaim records of an abandoned scope in place, concurrently:
/// each record's cleanup defers its scope reference into its own step's
/// worklist ([`OwnedRecord::reclaim_step`]), and each step processes its list
/// after returning, so one worker's deferral races another's processing of
/// the same scope (an `n - 1` batch, the compare-exchange from 1 to 0, a
/// deferral listing the scope again after it), and the release a processing
/// performs runs the scope's terminal drain. The oracles, in every
/// interleaving: a drain begun inside another aborts (the nesting oracle of
/// `drain_terminally`, per model thread), so drains never nest; a deferred
/// release lost leaves the scope block's permit held and a release performed
/// twice frees the block twice, so `released`'s zero live bytes requires
/// exactly one free, after the last counted reference; and every record is
/// reclaimed, so nothing remains outstanding. Planted control
/// `tests/data/controls/deferral-clear-unchecked.patch` (the 1-to-0
/// compare-exchange replaced by a store, losing a deferral made between the
/// load and the store) fails "deferral racing processing".
fn deferral_races_processing(workers: usize) {
    let mut m = Limits::unlimited();
    let owner = initialized(&mut m);
    let reclaiming: Vec<_> = (0..workers)
        .map(|_| {
            let record = allocated(&owner, &mut m);
            let mut local = m.share();
            thread::spawn(move || {
                let mut slot = Some(record);
                while Record::reclaim_step(&mut slot, &mut local)
                    .expect("an unlimited policy admits every cleanup unit")
                    != Reclaimed::Done
                {}
            })
        })
        .collect();
    drop(owner);
    for worker in reclaiming {
        worker.join().expect("a reclaiming worker panicked");
    }
    released(&m, "deferral racing processing");
}

/// Workers retire into a scope another thread is stepping: each cancels an
/// input acquisition once its record is allocated, whose cleanup defers the
/// record's and the acquisition's scope references into its step's worklist
/// and processes them at that step's end, then retires a record of its own
/// into the queue, while the stepping thread removes and reclaims queued
/// records and the authority's thread shuts the scope down after. The
/// oracles: the nesting oracle in every interleaving, a release performed
/// twice or lost through the permits' accounting, and `released`'s zero
/// live bytes with nothing outstanding.
fn retirement_into_a_stepped_scope(workers: usize) {
    let mut m = Limits::unlimited();
    let owner = initialized(&mut m);
    let records: Vec<_> = (0..workers).map(|_| allocated(&owner, &mut m)).collect();
    let owner = Arc::new(owner);
    let stepper = {
        let owner = Arc::clone(&owner);
        let mut local = m.share();
        thread::spawn(move || {
            loop {
                match owner
                    .step(&mut local)
                    .expect("an unlimited policy admits every cleanup unit")
                {
                    Reclaimed::Done => return,
                    Reclaimed::Progress => {}
                    Reclaimed::Waiting => thread::yield_now(),
                }
            }
        })
    };
    let retiring: Vec<_> = records
        .into_iter()
        .map(|record| {
            let owner = Arc::clone(&owner);
            let mut local = m.share();
            thread::spawn(move || {
                let mut copy = owner.copy_input(&[]);
                while !copy.position().allocated {
                    copy.step(&mut local)
                        .expect("an unlimited policy admits the input's record");
                }
                copy.cancel();
                while !matches!(
                    copy.step(&mut local)
                        .expect("an unlimited policy admits every cleanup unit"),
                    Step::Finished
                ) {}
                drop(copy);
                drop(record);
            })
        })
        .collect();
    for worker in retiring {
        worker.join().expect("a retiring worker panicked");
    }
    stepper.join().expect("the stepping thread panicked");
    let mut owner = Arc::try_unwrap(owner)
        .ok()
        .expect("every thread's reference to the authority was dropped at its join");
    assert_eq!(
        owner.outstanding(),
        0,
        "a record outlived the stepped drain"
    );
    shut_down(&mut owner, &mut m);
    released(&m, "retirement into a stepped scope");
}

/// The recording capacity of one drained scope, derived from what the
/// scenario performs under one unlimited recorded policy, nothing refused,
/// by the session's publication rules: each admission through the route
/// publishes its call and its credit (two), an owner minted and an
/// acquisition bound one each, a grant its call and its physical effect
/// (two), a held obligation's spend one, and a permit's drop its release.
///
/// - The scope's acquisition (`DecodeOwner::initialize_step`,
///   `stable::acquire`): its owner minted, its acquisition bound, its write
///   and its release admitted held (four), the block granted and reserved
///   (two), both obligations spent at the grant (two); then its terminal
///   dispatch written in one admitted unit (two): 12.
/// - The record's (`allocate_step`): the same ten for its acquisition, its
///   token's owner minted at its first entry, then its owner stage in one
///   admitted unit (`OWNER`, two): 12.
/// - Retirement publishes nothing (the queue push admits nothing); a
///   waiting step admits nothing, a removal admitted before a wait being
///   retained, never admitted again.
/// - The drain (`Reclaimer::step`): the removal unit (`REMOVAL`, two); the
///   `u64` record's one cleanup unit (its `remaining` is 1, two); its block
///   freed, its permit's release (one); then the scope block freed by the
///   authority's last shutdown step, its release (one): 6.
///
/// 30 observations and 2 permit records, the scope block's and the
/// record's, none split. An observation beyond either invalidates the
/// session, so a derivation short of what production publishes fails the
/// scenario at its finish, naming the recording, never passing short.
const DRAINED: Capacity = Capacity {
    permits: 2,
    events: 30,
};

/// A record carried across `hops` workers, the last of which retires it
/// while the authority shuts the scope down, or retired on the main thread
/// itself when `hops` is zero; the calls the draining policy admitted after
/// the record was allocated. The policy is a family of its own recording
/// session ([`Limits::recorded_unlimited`]), made inside this model
/// execution and recording from the scope's initialization through the
/// drain: `measure` scopes only the policy's own admission history, never
/// the session's stream. The policy, the scope and the record are dropped
/// and the session finished whole, then its entire stream is refined by the
/// one checker, acceptance required (`dcbor_test_support::refine_words`):
/// every permit's lifecycle, every obligation's settlement into its origin,
/// every acquisition's owner and every physical outcome. The checker links
/// its own build of this crate, so the stream crosses as each observation's
/// whole storage form ([`crate::bounded::Observed::to_words`]). Spawns `hops` threads in
/// all.
fn drained(hops: usize) -> Vec<Call> {
    let session = Session::new(DRAINED);
    let mut m = Limits::recorded_unlimited(&session);
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
    let admitted = m.admitted_calls();
    drop((owner, m));
    let observed = session.finish().unwrap_or_else(|incomplete| {
        panic!("worker transfer: the drain's recording is incomplete: {incomplete:?}")
    });
    let words: Vec<_> = observed
        .iter()
        .enumerate()
        .map(|(index, observation)| {
            observation.to_words().unwrap_or_else(|| {
                panic!("worker transfer: observation {index} has no storage form: {observation:?}")
            })
        })
        .collect();
    dcbor_test_support::refine_words(&words);
    admitted
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
        threaded, local,
        "a transferred record's drain admitted differently from a local one's"
    );
}

/// The I3 witness under the build's atomics: a scope and a record admit
/// their production representation, though the checker's atomics are what
/// is stored. One thread. The witness concludes its recording session inside
/// the model, as [`drained`] does: the session's finish loads the checker's
/// atomics, which moves only this model's step bound, measured and recorded,
/// never a contract quantity.
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
    scenario!(deferral_races_processing: workers_1 = 1, workers_2 = 2, workers_3 = 3, workers_4 = 4);
    // The stepping thread beside the workers: three workers reach loom's
    // five threads.
    scenario!(retirement_into_a_stepped_scope: workers_1 = 1, workers_2 = 2, workers_3 = 3);

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
    scenario!(deferral_races_processing);
    scenario!(retirement_into_a_stepped_scope);

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
