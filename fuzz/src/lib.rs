//! Bounded-size property runners. Specification fixtures remain authoritative;
//! symbolic comparison here supplements value, length and resource assertions.
use dcbor::bounded::*;
use dcbor_test_support as support;
mod maps;
mod schema;
pub use schema::exercise_schema_schedule;

/// Recorded 2M-value, 32M-byte work allowance, 4M live bytes, and one refusal.
fn policy(run: &mut support::RecordedRun, refuse_at: Option<usize>) -> support::PolicyId {
    let policy = run.budget(WriteWork::new(2_000_000, 32_000_000), 4_000_000);
    run.with_policy(policy, |m| {
        m.fail_call(refuse_at.map(|at| (at, LimitRefusal::Scheduled(at))));
    });
    policy
}

/// The policy limits a run under [`policy`] can reach: its lifetime work,
/// its live storage, and a request beyond the whole ceiling. It runs no
/// turns and lowers no requested-bytes ceiling.
fn limit(refusal: LimitRefusal) -> bool {
    matches!(
        refusal,
        LimitRefusal::Work | LimitRefusal::Storage | LimitRefusal::TooLarge
    )
}

/// A refusal is either the scheduled one, at exactly the scheduled call, or a
/// policy limit ([`limit`]). Anything else is an encoder invariant failure.
fn expected_failure(error: BoundedError<LimitRefusal>, policy: &Limits, scheduled: Option<usize>) {
    match error {
        BoundedError::Refused(LimitRefusal::Scheduled(at)) => {
            assert_eq!(Some(at), scheduled);
            assert_eq!(at, policy.attempts() - 1);
        }
        BoundedError::Refused(refusal) if limit(refusal) => {}
        other => panic!("encoding invariant failed: {other:?}"),
    }
}

/// Prepare `value`, write its plan into owned output its writing policy
/// grants ([`Prepared::encode_owned`]), possibly refused and then retried, and
/// publish the plan in place ([`Prepared::publish`]): every output is
/// `expected`, within the write bound, and published only once complete;
/// every reservation is released with its owner.
pub fn exercise<T: Schema + ?Sized>(value: &T, expected: &[u8], refusal: Option<usize>) {
    // Select the phase independently. Reusing one refusal index in both
    // passes can stop preparation before the write refusal is ever reached.
    let preparation_refusal = refusal
        .filter(|index| index % 2 == 0)
        .map(|index| index / 2);
    let write_refusal = refusal
        .filter(|index| index % 2 != 0)
        .map(|index| index / 2);
    support::recorded_run(|run| {
        let allocator = policy(run, preparation_refusal);
        let writing = policy(run, write_refusal);
        let retry = policy(run, None);
        let publishing = policy(run, None);
        let result = run.with_policy(allocator, |m| prepare(value, m));
        match result {
            Err(error) => run.with_policy(allocator, |m| {
                expected_failure(error, m, preparation_refusal)
            }),
            Ok(prepared) => run.holding(
                prepared,
                support::Retirement::Released,
                &support::pipeline::Unwitnessed,
                |prepared| {
                    assert_eq!(prepared.value().len(), expected.len());
                    let len = u64::try_from(prepared.value().len()).unwrap();
                    let write = prepared.value().write_work::<()>().unwrap();
                    let owned = encoding::owned_emit_bound::<Reservation, ()>(len).unwrap();
                    // The writing policy admits the output's release, grants its
                    // storage, exactly the encoding's length, then admits its write;
                    // the injected schedule may refuse any of them.
                    let encoded =
                        prepared.with_policy(writing, |prepared, m| prepared.encode_owned(m));
                    match encoded {
                        Ok(encoded) => {
                            prepared.holding(encoded, support::Retirement::Released, |encoded| {
                                encoded.with_policy(writing, |encoded, budget| {
                                    assert_eq!(encoded.as_ref(), expected);
                                    assert!(owned.work().covers(&budget.used()));
                                    assert!(budget.requested_bytes() <= owned.allocated);
                                    assert_eq!(budget.live_bytes(), len);
                                    assert_eq!(
                                        dcbor::CBOR::try_from_data(encoded.as_ref())
                                            .unwrap()
                                            .to_cbor_data(),
                                        expected
                                    );
                                });
                            })
                        }
                        Err(error) => prepared
                            .with_policy(writing, |_, m| expected_failure(error, m, write_refusal)),
                    }
                    prepared.with_policy(writing, |_, m| assert_eq!(m.live_bytes(), 0));
                    // Each write starts with a fresh writer, including after a
                    // refusal. Retry must be canonical and within the write bound.
                    let encoded = prepared
                        .with_policy(retry, |prepared, m| prepared.encode_owned(m).unwrap());
                    prepared.holding(encoded, support::Retirement::Released, |encoded| {
                        encoded.with_policy(retry, |encoded, retry| {
                            assert_eq!(encoded.as_ref(), expected);
                            assert!(owned.work().covers(&retry.used()));
                            assert_eq!(retry.requested_bytes(), len);
                            assert_eq!(owned.allocated, len);
                        })
                    });
                    prepared.with_policy(retry, |_, m| assert_eq!(m.live_bytes(), 0));
                    // The plan's own arena published in place as the encoding.
                    prepared.publish(publishing, |published| {
                        published.with_policy(publishing, |published, publishing| {
                            assert_eq!(published.as_ref(), expected);
                            assert!(write.covers(&publishing.used()));
                        });
                        published.with_policy(allocator, |_, m| assert!(m.live_bytes() >= len));
                    })?;
                    Ok::<_, support::Finding>(())
                },
            )?,
        }
        run.with_policy(allocator, |m| assert_eq!(m.live_bytes(), 0));
        Ok(())
    });
}

pub fn exercise_decode(input: &[u8], refusal: Option<usize>) {
    use dcbor::bounded::decode::{DecodeError, decode};
    support::recorded_run(|run| {
        let policy = policy(run, refusal);
        let decoded = run.with_policy(policy, |m| decode(input, 32, m));
        match decoded {
            Ok(document) => run.holding(
                document,
                support::Retirement::Released,
                &support::pipeline::Unwitnessed,
                |document| {
                    let document = document.value();
                    assert_eq!(document.root().encoded(), input);
                    // Only successful bounded validation reaches the recursive oracle:
                    // its depth is now known and its text is canonical.
                    let symbolic = dcbor::CBOR::try_from_data(input).unwrap();
                    assert_eq!(symbolic.to_cbor_data(), input);
                    assert!(document.node_count() <= input.len());
                },
            ),
            Err(DecodeError::Resource(error)) => {
                run.with_policy(policy, |m| expected_failure(error, m, refusal))
            }
            Err(DecodeError::Invalid(_) | DecodeError::DepthLimit { .. }) => {}
            Err(DecodeError::UnprovenText) => {
                panic!("normalizing policy returned QuickOnly refusal")
            }
        }
        run.with_policy(policy, |m| assert_eq!(m.live_bytes(), 0));
        Ok(())
    });
}

/// Arbitrary malformed inputs, every proper prefix of a bounded sample, and a
/// selected actual refusal. The recursive oracle only sees validated depth.
pub fn exercise_decode_schedule(data: &[u8]) {
    let Some((&schedule, input)) = data.split_first() else {
        return;
    };
    let input = &input[..input.len().min(4096)];
    retained_schedule(input, schedule as usize);
    for end in 0..input.len().min(64) {
        retained_schedule(&input[..end], schedule as usize + end);
    }
    if !input.is_empty() {
        let mut mutation = input.to_vec();
        let at = schedule as usize % mutation.len();
        mutation[at] ^= 1 << (schedule % 8);
        retained_schedule(&mutation, schedule as usize);
    }
}

fn retained_schedule(input: &[u8], schedule: usize) {
    use dcbor::bounded::decode::{DecodeError, Options, cursor::Decoder};
    /// The terminal outcome of one retained decode: published, invalid,
    /// beyond the depth limit, refused by a policy limit, or cancelled.
    #[derive(Debug, PartialEq, Eq)]
    enum Terminal {
        Published,
        Invalid,
        Depth,
        Limit,
        Cancelled,
    }
    fn run(input: &[u8], stop: Option<usize>, cancel: bool) -> (usize, WriteWork, Terminal) {
        support::recorded_run(|run| {
            let policy = run.policy(4_000_000);
            let outcome = run.holding(
                Decoder::new(input, Options::normalizing(32)),
                support::Retirement::Released,
                &support::pipeline::Unwitnessed,
                |operation| {
                    operation.drive_faulted(
                        policy,
                        support::decode_turns(input.len()),
                        support::Retirement::Released,
                        support::Fault {
                            refusal: stop.map_or(
                                support::pipeline::Refusal::None,
                                support::pipeline::Refusal::At,
                            ),
                            cancel,
                        },
                        |_, _| {},
                        |document| {
                            assert_eq!(document.value().root().encoded(), input);
                            let expected = dcbor::CBOR::try_from_data(input).unwrap();
                            assert_eq!(expected.to_cbor_data(), input);
                        },
                    )
                },
            );
            let terminal = match outcome {
                Ok(Some(())) => Terminal::Published,
                Ok(None) => Terminal::Cancelled,
                Err(support::Stopped::Operation(DecodeError::Invalid(_))) => Terminal::Invalid,
                Err(support::Stopped::Operation(DecodeError::DepthLimit { .. })) => Terminal::Depth,
                Err(support::Stopped::Operation(DecodeError::Resource(BoundedError::Refused(
                    refusal,
                )))) if limit(refusal) => Terminal::Limit,
                Err(stop) => return Err(support::Finding::from(stop)),
            };
            Ok(run.with_policy(policy, |m| {
                assert_eq!(m.injected_refusals(), usize::from(stop.is_some()));
                if let Some(at) = stop {
                    assert!(
                        m.refused_calls()
                            .contains(&(at, LimitRefusal::Scheduled(at), true))
                    );
                }
                assert_eq!(m.live_bytes(), 0);
                (m.attempts(), m.used(), terminal)
            }))
        })
    }
    let baseline = run(input, None, false);
    assert!(baseline.0 > 0);
    let stop = schedule % baseline.0;
    let resumed = run(input, Some(stop), false);
    assert_eq!(resumed.0, baseline.0 + 1);
    assert_eq!(
        resumed.1, baseline.1,
        "completed work replayed after refusal"
    );
    assert_eq!(resumed.2, baseline.2);
    run(input, Some(stop), true);
}
