//! A shared decode scope: every thread holding `&DecodeOwner` may allocate
//! records and step queued cleanup at once. One stepper runs at a time; a
//! contended step performs and admits nothing and reports `Waiting`, while
//! allocation proceeds beside the stepper.
#![cfg(feature = "std")]

use dcbor::bounded::decode::construction::{Acquisition, DecodeOwner, Reclaimed};
use dcbor::bounded::{Allocator, Budget, LimitRefusal, Limits, Reservation};
use std::sync::{Arc, Barrier};

/// Steps a shutdown may take before it is a defect: two records, each one
/// removal, one cleanup unit and one release, then the scope's release.
const SHUTDOWN_STEPS: usize = 16;

#[test]
fn last_worker_handle_reclaims_an_abandoned_scope() {
    let mut m = Limits::unlimited();
    let owner = dcbor_test_support::scope(&mut m);
    let input = dcbor_test_support::copy(&owner, &mut m, &[0x62, b'o', b'k']);
    let value = dcbor_test_support::decode::<_, String>(
        &mut m,
        input,
        dcbor::bounded::decode::Options::normalizing(8),
    )
    .unwrap();
    let ready = Arc::new(Barrier::new(2));
    let worker_ready = ready.clone();
    let worker = std::thread::spawn(move || {
        worker_ready.wait();
        assert_eq!(value.value(), "ok");
        drop(value);
    });
    drop(owner);
    ready.wait();
    worker.join().unwrap();
    assert_eq!(m.live_bytes(), 0);
}

/// A policy that holds its first admission at a rendezvous: it signals
/// `entered`, then waits for `released`. The first admission of a queue step
/// is the removal of the front record, made while the step holds the
/// queue's stepping flag, so the holder is parked inside `step`.
struct Gate {
    inner: Limits,
    gate: Option<(Arc<Barrier>, Arc<Barrier>)>,
}

impl Budget for Gate {
    type Refusal = LimitRefusal;

    #[expect(
        clippy::disallowed_methods,
        reason = "a third-party policy forwards an admission already made through the route"
    )]
    fn traverse(&mut self, values: u64, bytes: u64) -> Result<(), LimitRefusal> {
        if let Some((entered, released)) = self.gate.take() {
            entered.wait();
            released.wait();
        }
        self.inner.traverse(values, bytes)
    }
}

impl Allocator for Gate {
    type Permit = Reservation;

    fn allocate(&mut self, bytes: u64) -> Result<Reservation, LimitRefusal> {
        self.inner.allocate(bytes)
    }
}

// SAFETY: terminal cleanup delegates to Limits and never enters a barrier.
unsafe impl dcbor::bounded::TerminalAllocator for Gate {
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
