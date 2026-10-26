use super::bindings::decoder;
use super::harness::*;
use super::support::rigor::rigor;
use super::support::{
    Fault, allowed, contracted, drive_faulted, drive_within, reason_matrix, refusal_matrix, refuse,
    suspend_within,
};
use dcbor::bounded::{Failure, WriteWork};

#[test]
fn expired_before_first_admission_executes_no_work_and_allocates_nothing() {
    let wire = [0x81, 0x01];
    let mut m = meter();
    m.deadline(Some(0));
    let pool = m.share();
    let mut operation = decoder(&wire);
    let refused = contracted(&mut m, &mut operation)
        .err()
        .expect("deadline was ignored");
    assert!(refused.refused());
    assert_eq!(m.first_refusal(), Some((0, LimitRefusal::Deadline)));
    assert_eq!(m.used(), WriteWork::default());
    assert_eq!(pool.live_bytes(), 0);
    drop(operation);
    assert_eq!(pool.live_bytes(), 0);
}

/// A decode of `wire` whose deadline expires at call `stop`: the expiration
/// is observed there, at the clock it names; once the deadline is lifted the
/// same operation resumes to the literal document, attempting the
/// unobstructed run's calls with only the expired one repeated. Returns the
/// calls attempted.
fn expire_at(wire: &[u8], baseline: &Limits, stop: usize) -> Vec<Call> {
    let mut m = meter();
    m.deadline(Some(u64::try_from(stop).expect("a call index fits in u64")));
    let pool = m.share();
    let mut operation = decoder(wire);
    assert_eq!(
        suspend_within(
            &mut m,
            &mut operation,
            LimitRefusal::Deadline,
            decode_turns(wire.len()),
            super::support::TurnSchedule::Fresh,
        ),
        stop
    );
    assert_eq!(
        m.clock(),
        u64::try_from(stop).expect("a call index fits in u64") + 1
    );
    assert_eq!(m.calls(), &baseline.calls()[..=stop]);
    let paid = m.used();
    m.deadline(None);
    let document = drive_within(&mut m, &mut operation, decode_turns(wire.len()))
        .expect("deadline recovery failed");
    let after = m.used();
    assert!(after.values >= paid.values && after.bytes >= paid.bytes);
    assert_eq!(after, baseline.used());
    m.assert_units(TURN);
    assert_eq!(document.root().encoded(), wire);
    drop(operation);
    assert!(pool.live_bytes() > 0);
    drop(document);
    assert_eq!(pool.live_bytes(), 0);
    m.admitted().to_vec()
}

#[test]
fn expiration_between_admissions_preserves_paid_work_and_can_resume() {
    let wire = [0x82, 0x01, 0x02];
    // The engine sees an expired deadline as a refusal like any other: the
    // refusal matrix covers every admission.
    refusal_matrix("decoder of a flat array", rigor(), |fault: Fault| {
        let mut m = meter();
        refuse(&mut m, fault.refusal);
        let pool = m.share();
        let mut operation = decoder(&wire);
        let turns = allowed(&m, decode_turns(wire.len()));
        let document = drive_faulted(&mut m, &mut operation, turns, fault.cancel)
            .expect("a canonical array decodes");
        drop(operation);
        drop(document);
        assert_eq!(pool.live_bytes(), 0);
        super::support::RefusalRun::of(&m)
    });
    let mut baseline = meter();
    drop(drive_within(&mut baseline, &mut decoder(&wire), decode_turns(wire.len())).unwrap());
    // An expiration between admissions: at the decode's last, which every
    // earlier admission precedes. The exhaustive layer expires the deadline
    // at every admission and requires each to attempt exactly what the
    // refusal of that call attempts: the evidence that the engine treats an
    // expiration as any refusal.
    reason_matrix(
        "deadline expirations of a flat array decode",
        rigor(),
        baseline.calls(),
        &[LimitRefusal::Deadline],
        |stop, _| {
            assert_eq!(
                expire_at(&wire, &baseline, stop),
                baseline.admitted(),
                "deadline recovery at call {stop} replayed paid work"
            );
        },
    );
}
