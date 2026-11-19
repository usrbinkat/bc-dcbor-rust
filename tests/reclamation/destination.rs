use super::*;

/// Construct `["a", "b"]` from `wire`, cancelling the construction after
/// `stop` turns: cancellation releases nothing synchronously, and its own
/// cleanup takes every unit refused once before it is admitted
/// ([`support::pipeline::Refusal::Each`]), each refused step checked to
/// leave the construction where it was and the holding stack checkpointed
/// after every turn, within the decode's bound. The turns construction took
/// to publish, when it published within `stop`, and the boundary valuations
/// the run reached. One recorded run, its finalizer refining the stream.
fn cancelled(wire: &[u8], stop: usize) -> (Option<usize>, dcbor::bounded::boundary::Reached) {
    let bound = support::typed_turns::<Vec<String>>(wire.len());
    support::recorded_run(|run| {
        let policy = run.policy(u64::MAX);
        let published = run.scoped(policy, &Unwitnessed, |owner| {
            owner.copied(policy, wire, |input| {
                input.parse(policy, Options::normalizing(8), |document| {
                    document.transfer(
                        Construction::<_, Vec<String>, Limits>::construct,
                        Retirement::Stopped,
                        |construction| {
                            let mut turns = 0;
                            let published = construction.controlled(
                                policy,
                                bound,
                                Retirement::Published,
                                true,
                                |_, _, at| {
                                    turns = at + 1;
                                    at == stop
                                },
                                |value| assert_eq!(value.value().value(), &["a", "b"]),
                            )?;
                            if published.is_some() {
                                return Ok::<_, Finding>(Some(turns));
                            }
                            construction.with_policy(policy, |construction, m| {
                                let held = m.live_bytes();
                                construction.cancel();
                                assert_eq!(
                                    m.live_bytes(),
                                    held,
                                    "cancellation released synchronously"
                                );
                                support::refuse(m, support::pipeline::Refusal::Each);
                            });
                            construction.finish(policy, bound, Retirement::Published)?;
                            construction.with_policy(policy, |_, m| {
                                m.fail_call(None);
                                m.clear_refusal();
                            });
                            Ok(None)
                        },
                    )
                })
            })??
        })?;
        run.with_policy(policy, |m| {
            assert_eq!(m.live_bytes(), 0);
            Ok((published, m.reached()))
        })
    })
}

/// The construction cancelled after every number of turns through its
/// publication ([`support::stop_matrix`]): publication is reached within the
/// decode's bound, and exactly the stop at it publishes.
#[test]
fn cancelled_construction_reclaims_at_every_boundary() {
    let wire = [0x82, 0x61, b'a', 0x61, b'b'];
    let boundaries = cancelled(&wire, usize::MAX)
        .0
        .expect("construction never reached publication");
    support::stop_matrix("cancelled construction of two texts", boundaries, |stop| {
        let (published, reached) = cancelled(&wire, stop);
        assert_eq!(
            published.is_some(),
            stop == boundaries,
            "a stop after {stop} turns"
        );
        reached
    });
}

/// A construction whose scope closed while its document was live fails at
/// its first step with the scope's refusal of a new record, not a
/// retryable refusal, and is not replayed: its own cleanup runs to
/// `Finished`, and the scope then drains to nothing. The document is held
/// beside the scope, outside it, so the scope is shut down exclusively
/// while the document lives.
#[test]
fn terminal_allocation_error_is_not_replayed() {
    type Document =
        dcbor::bounded::decode::construction::OwnedDocument<'static, ByteString, Limits>;
    support::recorded_run(|run| {
        let policy = run.policy(u64::MAX);
        run.holding(
            CustodyBatch::<Document>::slots(1),
            Retirement::Exhausted,
            &Unwitnessed,
            |documents| {
                documents.lending(Retirement::Exhausted, Lent::new, |lent| {
                    let documents = lent.value().get();
                    lent.holding(DecodeOwner::new(), Retirement::Scope, |owner| {
                        owner.initialize(policy)?;
                        owner.copied(policy, &[7], |input| {
                            input.parse(policy, Options::normalizing(8), |document| {
                                document.deposit(documents, 0)
                            })
                        })??;
                        // Close the scope: the live document keeps it from
                        // completing.
                        let closing = owner.with_policy(policy, |owner, m| {
                            m.fresh();
                            owner.shutdown_step(m)
                        });
                        assert_eq!(
                            closing.map_err(support::failed("the closing shutdown step"))?,
                            Reclaimed::Waiting
                        );
                        let turns = support::typed_turns::<u64>(1);
                        owner.drawn(documents, 0, Retirement::Published, |document| {
                            document.transfer(
                                Construction::<_, u64, Limits>::construct,
                                Retirement::Stopped,
                                |construction| {
                                    match construction.drive(
                                        policy,
                                        turns,
                                        Retirement::Published,
                                        |_| (),
                                    ) {
                                        Err(Stopped::Operation(DecodeError::Resource(
                                            BoundedError::PlanMismatch,
                                        ))) => {}
                                        other => {
                                            return Err(Finding::Driver(format!(
                                                "a construction in a closed scope reached \
                                                 {other:?}"
                                            )));
                                        }
                                    }
                                    construction.finish(policy, turns, Retirement::Published)?;
                                    Ok(())
                                },
                            )
                        })?;
                        owner.drain(policy)
                    })
                })
            },
        )?;
        run.with_policy(policy, |m| assert_eq!(m.live_bytes(), 0));
        Ok(())
    });
}
