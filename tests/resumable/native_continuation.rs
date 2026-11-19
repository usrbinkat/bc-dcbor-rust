use super::bindings::{decoder, string_decoder, text_encoder};
use super::harness::*;
use super::support::{
    CustodyBatch, Fault, Finding, Lent, Retirement, TurnSchedule, pipeline::Unwitnessed,
    refusal_matrix, rigor::rigor,
};
use dcbor::bounded::decode::Kind;

#[test]
fn decoder_resumes_same_operation_before_and_after_header_without_replay() {
    let wire = [
        0x58, 0x18, b'a', b'b', b'c', b'd', b'e', b'f', b'g', b'h', b'i', b'j', b'k', b'l', b'm',
        b'n', b'o', b'p', b'q', b'r', b's', b't', b'u', b'v', b'w', b'x',
    ];
    refusal_matrix("decoder over a byte string", rigor(), |fault: Fault| {
        retained_case(
            decoder(&wire),
            decode_turns(wire.len()),
            fault,
            |document, _| {
                assert_eq!(document.root().kind(), Kind::Bytes(&wire[2..]));
                assert_eq!(document.root().encoded(), wire);
            },
        )
    });
}

#[test]
fn text_normalization_resumes_each_real_refusal_and_preserves_literal_result() {
    let source = "a\u{301}";
    refusal_matrix(
        "text encoder of a composing pair",
        rigor(),
        |fault: Fault| {
            retained_case(
                text_encoder(source),
                normalize_turns(source),
                fault,
                |value, m| {
                    assert_eq!(value.as_ref(), &[0x62, 0xc3, 0xa1]);
                    assert!(m.live_bytes() >= 3);
                },
            )
        },
    );
}

#[test]
fn typed_construction_resumes_and_transfers_output_ownership() {
    let wire = [0x62, 0xc3, 0xa9];
    refusal_matrix(
        "string decoder of composed text",
        rigor(),
        |fault: Fault| {
            retained_case(
                string_decoder(&wire),
                string_turns(wire.len()),
                fault,
                |value, m| {
                    assert_eq!(value.value(), "\u{e9}");
                    assert!(m.live_bytes() >= 2);
                    assert_eq!(value.value(), "\u{e9}");
                },
            )
        },
    );
}

#[test]
fn externally_released_capacity_resumes_same_decode_not_a_second_attempt() {
    let wire = [0x81, 0x01];
    let turns = decode_turns(wire.len());
    super::support::recorded_run(|run| {
        // The unobstructed decode, under a family of its own, held by the run.
        let unobstructed = run.policy(POOL);
        run.holding(
            decoder(&wire),
            Retirement::Released,
            &Unwitnessed,
            |baseline| baseline.drive(unobstructed, turns, Retirement::Released, |_| ()),
        )?;
        let baseline = run.with_policy(unobstructed, |baseline| {
            (baseline.admitted_calls(), baseline.used())
        });
        let blocking = run.policy(4096);
        // The decode's policy: a share of the blocked pool, its own trace over
        // the pool's storage.
        let shared = run.shared_policy(blocking);
        let (owner, blocked) = run.with_policy(blocking, |pool| {
            let owner = pool.owner().expect("a recorded owner");
            // Another tenant holding the pool's whole 4096 bytes.
            let blocked = occupy::<1024>(pool, &owner);
            assert_eq!(pool.live_bytes(), 4096);
            (owner, blocked)
        });
        let mut tenants = CustodyBatch::with_capacity(1);
        tenants.retain(blocked);
        run.holding(tenants, Retirement::Released, &Unwitnessed, |tenants| {
            tenants.lending(Retirement::Exhausted, Lent::new, |lent| {
                let tenants = lent.value().get();
                lent.holding(decoder(&wire), Retirement::Released, |operation| {
                    let stop = operation.suspend(
                        shared,
                        LimitRefusal::Storage,
                        turns,
                        TurnSchedule::Retained,
                        Retirement::Released,
                    )?;
                    let paid = operation.with_policy(shared, |_, m| {
                        assert_eq!(m.first_refusal(), Some((stop, LimitRefusal::Storage)));
                        m.used()
                    });
                    operation.with_policy(blocking, |_, pool| assert_eq!(pool.live_bytes(), 4096));
                    // The tenant released by another thread: the capacity the
                    // suspended decode waits for.
                    operation.drawn(tenants, 0, Retirement::Released, |tenant| {
                        tenant.transfer(
                            |tenant| {
                                let mut batch = CustodyBatch::with_capacity(1);
                                batch.retain(tenant);
                                batch
                            },
                            Retirement::Released,
                            |batch| batch.retire_concurrently(),
                        );
                    });
                    operation.with_policy(blocking, |_, pool| assert_eq!(pool.live_bytes(), 0));
                    operation.drive(shared, turns, Retirement::Released, |document| {
                        document.with_policy(shared, |document, m| {
                            let after = m.used();
                            assert!(after.values >= paid.values && after.bytes >= paid.bytes);
                            assert_eq!(
                                m.admitted_calls(),
                                baseline.0,
                                "completed work was replayed"
                            );
                            assert_eq!(m.used(), baseline.1);
                            assert_eq!(document.root().encoded(), wire);
                            m.assert_units(TURN);
                        });
                    })?;
                    Ok::<_, Finding>(())
                })
            })
        })?;
        run.with_policy(blocking, |pool| {
            assert_eq!(pool.live_bytes(), 0);
            // The whole capacity is free again, and no more than it.
            let all = occupy::<1024>(pool, &owner);
            refuses_more(pool, &owner);
            drop(all);
        });
        drop(owner);
        Ok(())
    });
}

#[test]
fn decode_publishes_once_and_then_only_reports_finished() {
    let wire = [0x81, 0x01];
    suite(|run, policy| {
        run.holding(
            decoder(&wire),
            Retirement::Released,
            &Unwitnessed,
            |operation| {
                operation.drive(
                    policy,
                    decode_turns(wire.len()),
                    Retirement::Released,
                    |document| {
                        assert_eq!(document.value().root().encoded(), wire);
                    },
                )?;
                Ok::<_, Finding>(())
            },
        )
    });
}
