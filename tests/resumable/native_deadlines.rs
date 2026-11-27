use super::bindings::decoder;
use super::harness::*;
use super::support::rigor::rigor;
use super::support::{
    Fault, Finding, Retirement, TurnSchedule, pipeline::Unwitnessed, reason_matrix, refusal_matrix,
};
use dcbor::bounded::WriteWork;

#[test]
fn expired_before_first_admission_executes_no_work_and_allocates_nothing() {
    let wire = [0x81, 0x01];
    suite(|run, policy| {
        run.with_policy(policy, |m| m.expire_at_call(Some(0)));
        run.holding(
            decoder(&wire),
            Retirement::Released,
            &Unwitnessed,
            |operation| {
                assert_eq!(
                    operation.suspend(
                        policy,
                        LimitRefusal::Deadline,
                        1,
                        TurnSchedule::Retained,
                        Retirement::Released
                    )?,
                    0
                );
                operation.with_policy(policy, |_, m| {
                    assert_eq!(m.first_refusal(), Some((0, LimitRefusal::Deadline)));
                    assert_eq!(m.used(), WriteWork::default());
                    assert_eq!(m.live_bytes(), 0);
                });
                Ok::<_, Finding>(())
            },
        )?;
        run.with_policy(policy, |m| assert_eq!(m.live_bytes(), 0));
        Ok(())
    });
}

/// The unobstructed decode of a wire, as detached data: the calls it
/// attempted, those admitted, and the work it used.
struct Baseline {
    calls: Vec<Call>,
    admitted: Vec<Call>,
    used: WriteWork,
}

/// A decode of `wire` whose deadline expires at call `stop`. The expiry
/// refuses foreground calls alone, so the call it refuses is the first
/// foreground call of the unobstructed run at or after `stop`: a cleanup
/// unit at `stop` is admitted as in that run. The expiration is observed at
/// the refused call, at the clock it names; once the deadline is lifted the
/// same operation resumes to the literal document, attempting the
/// unobstructed run's calls with only the expired one repeated. With no
/// foreground call at or after `stop` the expiry refuses nothing and the
/// decode completes as the unobstructed run does. Returns the calls admitted
/// and the boundary valuations the decode reached.
fn expire_at(
    wire: &[u8],
    baseline: &Baseline,
    stop: usize,
) -> (Vec<Call>, dcbor::bounded::boundary::Reached) {
    let refused = (stop..baseline.calls.len()).find(|&at| baseline.calls[at].is_foreground());
    suite(|run, policy| {
        run.with_policy(policy, |m| {
            m.expire_at_call(Some(u64::try_from(stop).expect("a call index fits in u64")));
        });
        run.holding(
            decoder(wire),
            Retirement::Released,
            &Unwitnessed,
            |operation| {
                if let Some(refused) = refused {
                    assert_eq!(
                        operation.suspend(
                            policy,
                            LimitRefusal::Deadline,
                            decode_turns(wire.len()),
                            TurnSchedule::Fresh,
                            Retirement::Released,
                        )?,
                        refused,
                        "an expiry at call {stop} refused another call than the first \
                         foreground one after it"
                    );
                }
                let paid = operation.with_policy(policy, |_, m| {
                    if let Some(refused) = refused {
                        assert_eq!(
                            m.clock(),
                            u64::try_from(refused).expect("a call index fits in u64") + 1
                        );
                        assert_eq!(m.calls(), &baseline.calls[..=refused]);
                    }
                    let paid = m.used();
                    m.expire_at_call(None);
                    paid
                });
                operation.drive_faulted(
                    policy,
                    decode_turns(wire.len()),
                    Retirement::Released,
                    Fault::NONE,
                    |_, _| {},
                    |document| {
                        document.with_policy(policy, |document, m| {
                            let after = m.used();
                            assert!(after.values >= paid.values && after.bytes >= paid.bytes);
                            assert_eq!(after, baseline.used);
                            m.assert_units(TURN);
                            assert_eq!(document.root().encoded(), wire);
                            assert!(m.live_bytes() > 0);
                        });
                    },
                )?;
                Ok::<_, Finding>(())
            },
        )?;
        Ok(run.with_policy(policy, |m| {
            assert_eq!(m.live_bytes(), 0);
            (m.admitted_calls(), m.reached())
        }))
    })
}

#[test]
fn expiration_between_admissions_preserves_paid_work_and_can_resume() {
    let wire = [0x82, 0x01, 0x02];
    // The engine sees an expired deadline as a refusal like any other: the
    // refusal matrix covers every admission.
    refusal_matrix("decoder of a flat array", rigor(), |fault: Fault| {
        retained_case(decoder(&wire), decode_turns(wire.len()), fault, |_, _| {})
    });
    let mut used = WriteWork::default();
    let calls = retained_case(
        decoder(&wire),
        decode_turns(wire.len()),
        Fault::NONE,
        |_, m| {
            used = m.used();
        },
    );
    let baseline = Baseline {
        calls: calls.calls().to_vec(),
        admitted: calls.admitted().to_vec(),
        used,
    };
    // An expiration between admissions: at the decode's last, which every
    // earlier admission precedes. The exhaustive layer expires the deadline
    // at every admission, a cleanup unit's included, and requires each to
    // attempt exactly what the refusal of the first foreground call at or
    // after it attempts: the evidence that the engine treats an expiration
    // as any refusal, and that cleanup is never refused for it.
    reason_matrix(
        "deadline expirations of a flat array decode",
        rigor(),
        &baseline.calls,
        &[LimitRefusal::Deadline],
        |stop, _| {
            let (admitted, reached) = expire_at(&wire, &baseline, stop);
            assert_eq!(
                admitted, baseline.admitted,
                "deadline recovery at call {stop} replayed paid work"
            );
            reached
        },
    );
}
