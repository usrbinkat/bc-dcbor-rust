//! A shared decode scope: every thread holding `&DecodeOwner` may allocate
//! records and step queued cleanup at once. One stepper runs at a time; a
//! contended step performs and admits nothing and reports `Waiting`, while
//! allocation proceeds beside the stepper.
#![cfg(feature = "std")]

use dcbor::bounded::decode::construction::{Acquisition, DecodeOwner, Reclaimed};
use dcbor::bounded::{
    Allocator, Budget, Effect, Hold, Identity, LimitRefusal, Limits, Owner, Performer, Releasing,
    Reservation, TerminalAllocator, WriteWork, boundary,
};
use std::sync::{Arc, Barrier};

/// Steps a shutdown may take before it is a defect: two records, each one
/// removal, one cleanup unit and one release, then the scope's release.
const SHUTDOWN_STEPS: usize = 16;

/// A scope's authority dropped while a published value lives: the scope is
/// abandoned, not freed ([`support::Retirement::Abandoned`]), and the value,
/// whose handle now reports the scope block as shared custody, is read on a
/// worker thread; its final handle is then moved to a retirement worker,
/// where destruction drains the abandoned scope terminally
/// ([`support::Retirement::LastReference`]). The joined retirement leaves
/// nothing live.
#[test]
fn last_worker_handle_reclaims_an_abandoned_scope() {
    use dcbor_test_support::{
        self as support, CustodyBatch, DropOrder, Retirement, pipeline::Unwitnessed,
    };
    support::recorded_run(|run| {
        let policy = run.policy(u64::MAX);
        run.terminal::<String, _, _>(
            policy,
            &[0x62, b'o', b'k'],
            &Unwitnessed,
            DropOrder::OwnerFirst,
            |value| {
                std::thread::scope(|threads| {
                    let published = value.value();
                    threads
                        .spawn(|| assert_eq!(published.value(), "ok"))
                        .join()
                        .expect("the worker read the abandoned scope's value")
                });
                value.transfer(
                    |value| {
                        let mut batch = CustodyBatch::with_capacity(1);
                        batch.retain(value);
                        batch
                    },
                    Retirement::LastReference,
                    |batch| batch.retire_concurrently(),
                );
            },
        )?;
        run.with_policy(policy, |m| assert_eq!(m.live_bytes(), 0));
        Ok(())
    });
}

/// A policy that holds its first admission, foreground or cleanup, at a
/// rendezvous: it signals `entered`, then waits for `released`. The first
/// admission of a queue step is the removal of the front record, a cleanup
/// admission made while the step holds the queue's stepping flag, so the
/// holder is parked inside `step`. Everything else, every observation,
/// identity, credit origin and settlement, is its inner policy's, forwarded
/// unchanged.
struct Gate {
    inner: Limits,
    gate: Option<(Arc<Barrier>, Arc<Barrier>)>,
}

impl Gate {
    /// Park at the rendezvous once, before the first admission of either
    /// account.
    fn park(&mut self) {
        if let Some((entered, released)) = self.gate.take() {
            entered.wait();
            released.wait();
        }
    }
}

impl Budget for Gate {
    type Refusal = LimitRefusal;

    #[expect(
        clippy::disallowed_methods,
        reason = "a third-party policy forwards an admission already made through the route"
    )]
    fn traverse(&mut self, values: u64, bytes: u64) -> Result<(), LimitRefusal> {
        self.park();
        self.inner.traverse(values, bytes)
    }

    // Each forwarded through the trait by path: `Limits` has inherent
    // readers whose names a method call would resolve to first.
    fn boundary(&mut self, boundary: boundary::Boundary) {
        Budget::boundary(&mut self.inner, boundary);
    }

    type Origin = <Limits as Budget>::Origin;

    fn origin(&self) -> Self::Origin {
        Budget::origin(&self.inner)
    }

    fn admitted(&mut self, work: WriteWork) {
        Budget::admitted(&mut self.inner, work);
    }

    fn identify(&mut self) -> Result<Identity, LimitRefusal> {
        Budget::identify(&mut self.inner)
    }

    fn held(&mut self, work: WriteWork, hold: Hold) {
        Budget::held(&mut self.inner, work, hold);
    }

    fn effect(&mut self, effect: Effect) {
        Budget::effect(&mut self.inner, effect);
    }

    fn owner(&mut self) -> Result<Owner, LimitRefusal> {
        Budget::owner(&mut self.inner)
    }

    fn acquisition(
        &mut self,
        owner: &Owner,
    ) -> Result<dcbor::bounded::Acquisition<Self::Origin>, LimitRefusal> {
        Budget::acquisition(&mut self.inner, owner)
    }

    fn validate_owner(&mut self, owner: &Owner) -> Result<(), LimitRefusal> {
        Budget::validate_owner(&mut self.inner, owner)
    }

    fn performer(&self) -> Performer {
        Budget::performer(&self.inner)
    }
}

impl Releasing for Gate {
    type Permit = Reservation;

    #[expect(
        clippy::disallowed_methods,
        reason = "a third-party policy forwards a cleanup admission already made through the route"
    )]
    fn reclaim(&mut self, values: u64, bytes: u64) -> Result<(), LimitRefusal> {
        self.park();
        Releasing::reclaim(&mut self.inner, values, bytes)
    }

    fn permit_identity(permit: &Reservation) -> Identity {
        <Limits as Releasing>::permit_identity(permit)
    }

    fn custody(permit: &Reservation, owner: Identity, stage: dcbor::bounded::RecordStage) {
        <Limits as Releasing>::custody(permit, owner, stage)
    }
}

impl Allocator for Gate {
    fn allocate(&mut self, bytes: u64) -> Result<Reservation, LimitRefusal> {
        Allocator::allocate(&mut self.inner, bytes)
    }
}

// SAFETY: terminal cleanup delegates to Limits' terminal policy and never
// enters a barrier: the terminal gate is empty.
unsafe impl TerminalAllocator for Gate {
    fn terminal(permit: &Reservation) -> Self {
        Self {
            inner: Limits::terminal(permit),
            gate: None,
        }
    }
}

/// While one thread steps the queue, parked inside its own admission, a
/// second thread's step reports `Waiting` and admits nothing, and its
/// allocation of a new record succeeds. The parked step then completes the
/// removal it was admitting, and shutdown releases every record and the
/// scope.
#[test]
fn a_contended_step_waits_while_allocation_proceeds() {
    let mut setup = Gate {
        inner: Limits::unlimited(),
        gate: None,
    };
    let mut owner = DecodeOwner::<'static, Gate>::new();
    owner.initialize_step(&mut setup).unwrap();
    // One queued record, so the gated step has a removal to admit.
    let record = owner
        .allocate_step::<u64>(&mut setup, &mut Acquisition::new())
        .unwrap();
    drop(record);
    assert_eq!(owner.outstanding(), 1);
    let entered = Arc::new(Barrier::new(2));
    let released = Arc::new(Barrier::new(2));
    let mut stepper = Gate {
        inner: setup.inner.share(),
        gate: Some((entered.clone(), released.clone())),
    };
    let mut other = Gate {
        inner: setup.inner.share(),
        gate: None,
    };
    std::thread::scope(|scope| {
        let shared = &owner;
        let parked = scope.spawn(move || shared.step(&mut stepper));
        entered.wait();
        // The stepper holds the stepping flag, parked inside its admission.
        let attempts = other.inner.attempts();
        assert_eq!(shared.step(&mut other).unwrap(), Reclaimed::Waiting);
        assert_eq!(
            other.inner.attempts(),
            attempts,
            "a contended step admitted work"
        );
        // Allocation does not wait for the stepper.
        let record = shared
            .allocate_step::<u64>(&mut other, &mut Acquisition::new())
            .unwrap();
        assert_eq!(shared.outstanding(), 2);
        drop(record);
        released.wait();
        assert_eq!(parked.join().unwrap().unwrap(), Reclaimed::Progress);
    });
    for _ in 0..SHUTDOWN_STEPS {
        if owner.shutdown_step(&mut setup).unwrap() == Reclaimed::Done {
            assert_eq!(owner.outstanding(), 0);
            assert_eq!(setup.inner.live_bytes(), 0);
            return;
        }
    }
    panic!("shutdown exceeded {SHUTDOWN_STEPS} steps");
}
