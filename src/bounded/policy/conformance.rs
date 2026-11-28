//! The accounting contract, instantiated for every shipping policy.
use super::*;
use crate::bounded::TerminalAllocator;
use crate::bounded::governance::{Governor, OperationBudget};

/// Construction, scheduling and observations beyond the admission contract.
/// Implementations normalize setup to an unscheduled, empty policy.
trait Conforming: TerminalAllocator + Budget<Refusal = LimitRefusal> {
    fn under(ceilings: Ceilings) -> Self;
    fn unlimited() -> Self {
        Self::under(Ceilings::UNLIMITED)
    }
    fn without_turns(&mut self);
    fn turn_with(&mut self, allowance: WriteWork);
    fn exhaust(&mut self);
    fn used(&self) -> WriteWork;
    fn cleanup_used(&self) -> WriteWork;
    fn remaining(&self) -> WriteWork;
    fn live_bytes(&self) -> u64;
    fn peak_bytes(&self) -> u64;
    fn requested_bytes(&self) -> u64;
    fn permit_bytes(permit: &Self::Permit) -> u64;
    /// A grant refused after this policy has reserved live storage:
    /// exhausted recording for Limits, occupied group storage for governance.
    fn reservation_pressure() -> (Self, Self::Permit, LimitRefusal);
    fn turn(&mut self) {
        self.turn_with(TURN);
    }
}

impl Conforming for Limits {
    fn under(ceilings: Ceilings) -> Self {
        Self::with_counters(ceilings, Arc::new(Counters::default()))
    }
    fn without_turns(&mut self) {
        self.open();
    }
    fn turn_with(&mut self, allowance: WriteWork) {
        self.turn_with(allowance);
    }
    fn exhaust(&mut self) {
        self.exhaust();
    }
    fn used(&self) -> WriteWork {
        self.used()
    }
    fn cleanup_used(&self) -> WriteWork {
        self.cleanup_used()
    }
    fn remaining(&self) -> WriteWork {
        self.remaining()
    }
    fn live_bytes(&self) -> u64 {
        self.live_bytes()
    }
    fn peak_bytes(&self) -> u64 {
        self.peak_bytes()
    }
    fn requested_bytes(&self) -> u64 {
        self.requested_bytes()
    }
    fn permit_bytes(permit: &Self::Permit) -> u64 {
        permit.bytes()
    }
    fn reservation_pressure() -> (Self, Self::Permit, LimitRefusal) {
        let session = Session::new(record::Capacity {
            permits: 1,
            events: record::Capacity::DEFAULT.events,
        });
        let mut policy = Self::recorded(u64::MAX, u64::MAX, 8, &session);
        let held = policy.allocate(2).unwrap();
        (policy, held, LimitRefusal::Unrecorded)
    }
}

impl Conforming for OperationBudget {
    fn under(ceilings: Ceilings) -> Self {
        let mut policy = Governor::new(Ceilings::UNLIMITED).operation(ceilings);
        policy.unscheduled();
        policy
    }
    fn without_turns(&mut self) {
        self.unscheduled();
    }
    fn turn_with(&mut self, allowance: WriteWork) {
        self.turn_with(allowance);
    }
    fn exhaust(&mut self) {
        self.exhaust();
    }
    fn used(&self) -> WriteWork {
        self.used()
    }
    fn cleanup_used(&self) -> WriteWork {
        self.cleanup_used()
    }
    fn remaining(&self) -> WriteWork {
        self.remaining()
    }
    fn live_bytes(&self) -> u64 {
        self.live_bytes()
    }
    fn peak_bytes(&self) -> u64 {
        self.peak_bytes()
    }
    fn requested_bytes(&self) -> u64 {
        self.requested_bytes()
    }
    fn permit_bytes(permit: &Self::Permit) -> u64 {
        permit.bytes()
    }
    fn reservation_pressure() -> (Self, Self::Permit, LimitRefusal) {
        let governor = Governor::new(Ceilings {
            live: 4,
            ..Ceilings::UNLIMITED
        });
        let held = governor.operation(Ceilings::UNLIMITED).allocate(2).unwrap();
        (
            governor.operation(Ceilings::UNLIMITED),
            held,
            LimitRefusal::Storage,
        )
    }
}

const ONE: WriteWork = WriteWork::new(1, 0);

fn storage<P: Conforming>(p: &P) -> (u64, u64, u64) {
    (p.live_bytes(), p.peak_bytes(), p.requested_bytes())
}

fn work<P: Conforming>(p: &P) -> (WriteWork, WriteWork, WriteWork) {
    (p.used(), p.cleanup_used(), p.remaining())
}

#[expect(
    clippy::disallowed_methods,
    reason = "direct policy contract admissions"
)]
fn turns_never_raise_lifetime_authorization<P: Conforming>() {
    let mut p = P::under(Ceilings {
        work: WriteWork::new(5, u64::MAX),
        ..Ceilings::UNLIMITED
    });
    let mut admitted = 0;
    for _ in 0..10 {
        p.turn();
        while p.traverse(1, 0).is_ok() {
            admitted += 1;
        }
    }
    assert_eq!(admitted, 5, "turns raised the lifetime allowance");
    assert_eq!(p.used(), WriteWork::new(5, 0));
    p.turn();
    assert_eq!(p.traverse(1, 0), Err(LimitRefusal::Work));
    assert_eq!(p.remaining(), WriteWork::new(0, TURN.bytes));
    p.traverse(0, TURN.bytes).unwrap();
    assert_eq!(p.remaining(), WriteWork::default());
}

#[expect(
    clippy::disallowed_methods,
    reason = "direct policy contract admissions"
)]
fn a_refused_admission_commits_nothing<P: Conforming>() {
    let mut p = P::under(Ceilings {
        work: WriteWork::new(10, u64::MAX),
        requested: 10,
        live: 8,
    });
    p.turn_with(WriteWork::new(2, 64));
    p.traverse(2, 0).unwrap();
    let before = work(&p);
    for (values, refusal) in [
        (1, LimitRefusal::Turn),
        (TURN.values + 1, LimitRefusal::QuantumTooSmall),
    ] {
        assert_eq!(p.traverse(values, 0), Err(refusal));
        assert_eq!(work(&p), before, "a refused unit committed");
    }
    for _ in 0..2 {
        p.turn();
        p.traverse(TURN.values, 0).unwrap();
    }
    p.turn();
    let before = work(&p);
    assert_eq!(p.traverse(TURN.values, 0), Err(LimitRefusal::Work));
    assert_eq!(work(&p), before, "a refused unit committed");

    let held = p.allocate(6).unwrap();
    assert_eq!(P::permit_bytes(&held), 6);
    let before = storage(&p);
    for (bytes, refusal) in [
        (9, LimitRefusal::TooLarge),
        (3, LimitRefusal::Storage),
        (5, LimitRefusal::Requested),
    ] {
        assert_eq!(p.allocate(bytes).err(), Some(refusal));
        assert_eq!(storage(&p), before, "a refused request committed");
    }
    drop(held);
    assert_eq!(storage(&p), (0, 6, 6));
}

#[expect(
    clippy::disallowed_methods,
    reason = "direct policy contract admissions"
)]
fn the_quantum_bounds_a_unit_and_the_allowance_bounds_a_turn<P: Conforming>() {
    let mut p = P::unlimited();
    p.turn();
    assert_eq!(
        p.traverse(TURN.values + 1, 0),
        Err(LimitRefusal::QuantumTooSmall)
    );
    assert_eq!(
        p.traverse(0, TURN.bytes + 1),
        Err(LimitRefusal::QuantumTooSmall)
    );
    p.turn_with(WriteWork::default());
    assert_eq!(p.traverse(1, 0), Err(LimitRefusal::Turn));
    p.turn_with(ONE);
    p.traverse(1, 0).unwrap();
    assert_eq!(p.traverse(1, 0), Err(LimitRefusal::Turn));
    p.turn_with(Ceilings::UNLIMITED.work);
    assert_eq!(p.remaining(), TURN, "a grant beyond the quantum");
    p.exhaust();
    assert_eq!(p.remaining(), WriteWork::default());
    assert_eq!(p.traverse(1, 0), Err(LimitRefusal::Turn));
    p.without_turns();
    p.traverse(TURN.values + 1, TURN.bytes + 1).unwrap();
}

#[expect(
    clippy::disallowed_methods,
    reason = "direct policy contract admissions"
)]
fn lifetime_exhaustion_precedes_the_turn_and_the_quantum<P: Conforming>() {
    for unit in [ONE, WriteWork::new(0, 1)] {
        let mut p = P::under(Ceilings {
            work: unit,
            ..Ceilings::UNLIMITED
        });
        p.turn_with(unit);
        p.traverse(unit.values, unit.bytes).unwrap();
        assert_eq!(p.traverse(unit.values, unit.bytes), Err(LimitRefusal::Work));
        assert_eq!(
            p.traverse(TURN.values + 1, TURN.bytes + 1),
            Err(LimitRefusal::Work)
        );
    }
}

#[expect(
    clippy::disallowed_methods,
    reason = "direct policy contract admissions"
)]
fn cleanup_is_never_refused_for_the_foreground<P: Conforming>() {
    let mut p = P::under(Ceilings {
        work: ONE,
        ..Ceilings::UNLIMITED
    });
    p.traverse(1, 0).unwrap();
    assert_eq!(p.traverse(1, 0), Err(LimitRefusal::Work));
    assert_eq!(
        p.reclaim(1, 8),
        Ok(()),
        "cleanup was refused for the lifetime allowance"
    );
    assert_eq!(p.used(), WriteWork::new(2, 8));
    assert_eq!(p.cleanup_used(), WriteWork::new(1, 8));
    assert_eq!(
        p.remaining(),
        WriteWork::default(),
        "cleanup was taken from the foreground's remainder"
    );
}

#[expect(
    clippy::disallowed_methods,
    reason = "direct policy contract admissions"
)]
fn cleanup_spends_the_turn_and_is_held_to_the_quantum<P: Conforming>() {
    let mut p = P::unlimited();
    p.turn();
    let before = work(&p);
    for unit in [
        WriteWork::new(TURN.values + 1, 0),
        WriteWork::new(0, TURN.bytes + 1),
    ] {
        assert_eq!(
            p.reclaim(unit.values, unit.bytes),
            Err(LimitRefusal::QuantumTooSmall)
        );
        assert_eq!(work(&p), before, "a refused cleanup unit committed");
    }
    p.turn_with(ONE);
    p.reclaim(1, 0).unwrap();
    let before = work(&p);
    assert_eq!(p.reclaim(1, 0), Err(LimitRefusal::Turn));
    assert_eq!(work(&p), before, "a refused cleanup unit committed");
    assert_eq!(p.traverse(1, 0), Err(LimitRefusal::Turn));
    p.turn_with(ONE);
    p.traverse(1, 0).unwrap();
    let before = work(&p);
    assert_eq!(p.reclaim(1, 0), Err(LimitRefusal::Turn));
    assert_eq!(work(&p), before, "a refused cleanup unit committed");
    assert_eq!(p.cleanup_used(), ONE);
    assert_eq!(p.used(), WriteWork::new(2, 0));
}

fn a_unit_under_the_cleanup_capability_is_charged_as_cleanup<P: Conforming>() {
    use crate::bounded::decode::construction::reclamation::Cleanup;
    use crate::bounded::{Caller, Unit};
    let unit = Unit::new(Caller, 1, 8);
    let mut p = P::under(Ceilings {
        work: WriteWork::default(),
        ..Ceilings::UNLIMITED
    });
    assert!(
        unit.admit(&mut Cleanup::new(&mut p)).is_ok(),
        "cleanup was charged to the foreground"
    );
    assert_eq!(p.cleanup_used(), WriteWork::new(1, 8));
    assert!(unit.admit(&mut p).is_err());
    assert_eq!(p.used(), p.cleanup_used());
}

#[expect(
    clippy::disallowed_methods,
    reason = "direct policy contract admissions"
)]
fn a_terminal_policy_never_refuses_work_and_never_allocates<P: Conforming>() {
    let mut origin = P::under(Ceilings {
        work: WriteWork::default(),
        live: 4,
        requested: 4,
    });
    let permit = origin.allocate(4).unwrap();
    let mut terminal = P::terminal(&permit);
    terminal.exhaust();
    for _ in 0..2 {
        assert_eq!(terminal.traverse(u64::MAX, u64::MAX), Ok(()));
        assert_eq!(terminal.reclaim(u64::MAX, u64::MAX), Ok(()));
    }
    for bytes in [0, 1, u64::MAX] {
        assert_eq!(terminal.allocate(bytes).err(), Some(LimitRefusal::Storage));
        assert_eq!(storage(&origin), (4, 4, 4));
    }
    drop(permit);
    assert_eq!(
        storage(&origin),
        (0, 4, 4),
        "a permit released outside its origin"
    );
    assert_eq!(
        terminal.traverse(1, 1),
        Ok(()),
        "terminal borrowed its permit"
    );
    drop(origin);
    assert_eq!(
        terminal.reclaim(1, 1),
        Ok(()),
        "terminal borrowed its origin"
    );
}

fn a_permit_releases_live_bytes_but_not_the_peak<P: Conforming>() {
    let mut p = P::unlimited();
    let first = p.allocate(3).unwrap();
    let second = p.allocate(5).unwrap();
    assert_eq!((P::permit_bytes(&first), P::permit_bytes(&second)), (3, 5));
    assert_eq!(storage(&p), (8, 8, 8));
    drop(first);
    assert_eq!(storage(&p), (5, 8, 8));
    drop(second);
    assert_eq!(storage(&p), (0, 8, 8));
}

fn a_later_refusal_returns_the_reservation<P: Conforming>() {
    let (mut p, held, refusal) = P::reservation_pressure();
    let before = storage(&p);
    assert_eq!(p.allocate(4).err(), Some(refusal));
    assert_eq!(
        p.live_bytes(),
        before.0,
        "a later refusal kept the reservation"
    );
    assert_eq!(p.peak_bytes(), before.1, "a later refusal raised a peak");
    assert_eq!(p.requested_bytes(), before.2, "a refused request committed");
    drop(held);
    assert_eq!(p.live_bytes(), 0);
}

#[expect(
    clippy::disallowed_methods,
    reason = "the accounting contract is driven by direct admissions"
)]
fn cleanup_never_refuses_for_its_own_total<P: Conforming>() {
    // Exercise each component independently, then both together.
    for full in [
        WriteWork::new(u64::MAX, 0),
        WriteWork::new(0, u64::MAX),
        WriteWork::new(u64::MAX, u64::MAX),
    ] {
        let unit = WriteWork::new(u64::from(full.values != 0), u64::from(full.bytes != 0));
        let mut p = P::unlimited();
        p.without_turns();
        assert_eq!(p.reclaim(full.values, full.bytes), Ok(()));
        assert_eq!(
            p.reclaim(unit.values, unit.bytes),
            Ok(()),
            "a cleanup unit was refused for its total"
        );
        assert_eq!(p.cleanup_used(), full);
        assert_eq!(
            p.traverse(unit.values, unit.bytes),
            Ok(()),
            "saturated cleanup blocked the foreground"
        );
        assert_eq!(p.used(), full);

        let mut p = P::under(Ceilings {
            work: unit,
            ..Ceilings::UNLIMITED
        });
        assert_eq!(p.traverse(unit.values, unit.bytes), Ok(()));
        assert_eq!(p.reclaim(full.values, full.bytes), Ok(()));
        assert_eq!(p.reclaim(unit.values, unit.bytes), Ok(()));
        assert_eq!(p.remaining(), WriteWork::default());
        assert_eq!(
            p.traverse(unit.values, unit.bytes),
            Err(LimitRefusal::Work),
            "saturated cleanup erased foreground authorization"
        );
        assert_eq!(p.cleanup_used(), full);
        assert_eq!(p.used(), full);
    }
}

macro_rules! conformance {
    (@tests $name:ident: $policy:ty; $($test:ident),+ $(,)?) => {
        paste::paste! {
            $(
                #[test]
                fn [<$name _ $test>]() {
                    $test::<$policy>();
                }
            )+
        }
    };
    ($($name:ident: $policy:ty);+ $(;)?) => {
        $(
            conformance!(@tests $name: $policy;
                cleanup_never_refuses_for_its_own_total,
                turns_never_raise_lifetime_authorization,
                a_refused_admission_commits_nothing,
                the_quantum_bounds_a_unit_and_the_allowance_bounds_a_turn,
                lifetime_exhaustion_precedes_the_turn_and_the_quantum,
                cleanup_is_never_refused_for_the_foreground,
                cleanup_spends_the_turn_and_is_held_to_the_quantum,
                a_unit_under_the_cleanup_capability_is_charged_as_cleanup,
                a_terminal_policy_never_refuses_work_and_never_allocates,
                a_permit_releases_live_bytes_but_not_the_peak,
                a_later_refusal_returns_the_reservation,
            );
        )+
    };
}

conformance!(limits: Limits; governed: OperationBudget);
