use super::bindings::decoder;
use super::harness::*;
use super::support::{
    Fault, Finding, Retirement, TurnSchedule, contracted, label,
    pipeline::{Refusal, Unwitnessed},
    refuse,
};
use dcbor::bounded::Step;
use dcbor::bounded::decode::{
    Kind,
    cursor::{Phase, Position},
};

fn map_wire() -> Vec<u8> {
    // Byte-string keys distinguish comparison admission from text validation.
    let mut wire = vec![0xa2];
    for last in *b"ab" {
        wire.extend_from_slice(&[0x59, 0x01, 0x00]);
        wire.extend(std::iter::repeat_n(b'a', 255));
        wire.push(last);
        wire.push(0x01);
    }
    wire
}

/// The unobstructed reference decode, as detached data: the attempt at
/// which the selected boundary was reached, the calls, the work used and the
/// shared refusal oracle's view of the run.
struct Reference {
    selected: (usize, Position),
    calls: Vec<Call>,
    used: dcbor::bounded::WriteWork,
    run: super::support::RefusalRun,
}

fn script(wire: &[u8], select: impl Fn(Position) -> bool) {
    super::support::recorded_run(|run| {
        // The unobstructed reference decode, held by the run, its every step
        // contract-checked and the selected boundary noted on the way.
        let reference = run.policy(POOL);
        let selected = run.holding(
            decoder(wire),
            Retirement::Released,
            &Unwitnessed,
            |decoding| {
                let (selected, document) =
                    decoding.with_policy(reference, |decoding, baseline| {
                        let mut selected = None;
                        for _ in 0..decode_turns(wire.len()) {
                            let position = decoding.position();
                            if selected.is_none() && select(position) {
                                selected = Some((baseline.attempts(), position));
                            }
                            match contracted(baseline, decoding) {
                                Ok(Step::Progress) => {}
                                Ok(Step::Complete(document)) => return Ok((selected, document)),
                                other => {
                                    return Err(Finding::Driver(format!(
                                        "reference at {position:?}: {}",
                                        label(&other)
                                    )));
                                }
                            }
                        }
                        Err(Finding::Driver(
                            "reference decode did not complete".to_owned(),
                        ))
                    })?;
                decoding.retirement(Retirement::Exhausted);
                decoding.holding(document, Retirement::Released, |document| {
                    assert_eq!(document.value().root().encoded(), wire);
                });
                Ok::<_, Finding>(selected)
            },
        )?;
        let baseline = run.with_policy(reference, |baseline| Reference {
            selected: selected.expect("requested execution boundary was not reached"),
            calls: baseline.calls(),
            used: baseline.used(),
            run: super::support::RefusalRun::of(baseline),
        });
        let (stop, target) = baseline.selected;
        assert!(stop < baseline.calls.len());
        // The same decode suspended at the selected boundary, then resumed to
        // publication, held by the run; the document outlives the decoder.
        let resuming = run.policy(POOL);
        run.holding(
            decoder(wire),
            Retirement::Released,
            &Unwitnessed,
            |operation| {
                operation.with_policy(resuming, |_, m| {
                    refuse(m, Refusal::For(stop, LimitRefusal::Work));
                });
                let suspended = operation.suspend(
                    resuming,
                    LimitRefusal::Work,
                    decode_turns(wire.len()),
                    TurnSchedule::Retained,
                    Retirement::Released,
                )?;
                assert_eq!(suspended, stop);
                let (prefix, paid) = operation.with_policy(resuming, |operation, m| {
                    assert_eq!(operation.position(), target);
                    assert_eq!(m.calls(), &baseline.calls[..=stop]);
                    // Preserve the admitted prefix as the independent
                    // no-replay oracle.
                    let prefix = m.calls()[..stop].to_vec();
                    let paid = m.used();
                    m.fail_call(None);
                    (prefix, paid)
                });
                operation.drive_faulted(
                    resuming,
                    decode_turns(wire.len()),
                    Retirement::Released,
                    Fault::NONE,
                    |_, _| {},
                    |output| {
                        output.with_policy(resuming, |output, m| {
                            assert_eq!(&m.calls()[..stop], prefix);
                            let after = m.used();
                            assert!(after.values >= paid.values && after.bytes >= paid.bytes);
                            // Suspension retains the original allowance;
                            // resumption uses fresh turns. The shared oracle
                            // preserves the exact prefix and all admitted
                            // work, accounting separately for later quantum
                            // exhaustion.
                            super::support::RefusalRun::of(m).resumed(
                                &baseline.run,
                                stop,
                                LimitRefusal::Work,
                            );
                            assert_eq!(after, baseline.used);
                            m.assert_units(TURN);
                            // The decoder is retired; the document keeps its
                            // arena.
                            assert!(m.live_bytes() > 0, "document must retain its arena");
                            assert_eq!(output.root().encoded(), wire);
                        });
                    },
                )?;
                Ok::<_, Finding>(())
            },
        )?;
        run.with_policy(resuming, |m| assert_eq!(m.live_bytes(), 0));
        Ok(())
    });
}

#[test]
fn before_header_has_no_consumed_work_and_same_cursor_completes() {
    script(&[0x81, 0x18, 0x18], |p| {
        p.phase == Phase::Header && p.header_bytes == 0 && p.input == 0
    });
}

#[test]
fn after_header_retains_validation_and_same_cursor_completes() {
    script(&[0x43, b'a', b'b', b'c'], |p| {
        p.phase == Phase::Interpret && p.header_bytes == 1 && p.input == 1
    });
}

#[test]
fn second_payload_preserves_previous_child_and_same_cursor_completes() {
    script(
        &[0x82, 0x63, b'a', b'b', b'c', 0x63, b'd', b'e', b'f'],
        |p| p.phase == Phase::Utf8 && p.completed_children == 1 && p.payload_validated == 1,
    );
}

#[test]
fn key_comparison_refusal_resumes_without_revalidating_prior_keys() {
    script(&map_wire(), |p| {
        p.phase == Phase::Compare && p.compared_bytes == 64
    });
}

#[test]
fn container_completion_refusal_does_not_complete_children_twice() {
    script(&[0x82, 0x01, 0x02], |p| {
        p.phase == Phase::Attach && p.completed_children == 1
    });
}

#[test]
fn long_prefix_keys_out_of_order_or_equal_are_rejected_after_bounded_comparison() {
    let key = |last: u8| {
        let mut key = vec![0x59, 0x01, 0x00];
        key.extend(std::iter::repeat_n(b'a', 255));
        key.push(last);
        key
    };
    let map = |first: &[u8], second: &[u8]| {
        let mut wire = vec![0xa2];
        wire.extend_from_slice(first);
        wire.push(0x00);
        wire.extend_from_slice(second);
        wire.push(0x01);
        wire
    };
    // The keys differ only in their last byte, or not at all: ordering is
    // decided only after the whole shared prefix is compared.
    for wire in [map(&key(b'b'), &key(b'a')), map(&key(b'a'), &key(b'a'))] {
        rejected_case(decoder(&wire), decode_turns(wire.len()), |_, _| Ok(()));
    }
}

#[test]
fn key_comparison_quantum_is_checked_separately_from_payload_scans() {
    let wire = map_wire();
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
                    |doc| {
                        assert_eq!(doc.value().root().kind(), Kind::Map(2));
                        assert_eq!(doc.value().root().encoded(), wire);
                        // Byte-string validation charges zero values. Comparisons
                        // charge visits.
                        let oversized: Vec<_> = doc.with_policy(policy, |_, m| {
                            m.calls()
                                .into_iter()
                                .filter(|c| {
                                    c.work()
                                        .is_some_and(|work| work.values > 0 && work.bytes > 64)
                                })
                                .collect()
                        });
                        assert!(oversized.is_empty(), "unbounded comparison: {oversized:?}");
                    },
                )
            },
        )?;
        run.with_policy(policy, |m| assert_eq!(m.live_bytes(), 0));
        Ok(())
    });
}

#[test]
fn arena_growth_quantum_is_checked_without_text_or_payload_processing() {
    let mut wire = vec![0x99, 0x10, 0x00];
    wire.extend(std::iter::repeat_n(0x01, 4096));
    let mut budgets = budgets("arena-growth", &["integers/4096/decode"]);
    budgets.run("integers/4096/decode", |run| {
        let policy = run.policy(POOL);
        run.holding(
            decoder(&wire),
            Retirement::Released,
            &Unwitnessed,
            |operation| {
                operation.drive(
                    policy,
                    decode_turns(wire.len()),
                    Retirement::Released,
                    |doc| {
                        assert_eq!(doc.value().node_count(), 4097);
                        assert!(
                            doc.value()
                                .root()
                                .children()
                                .all(|node| node.kind() == Kind::Unsigned(1))
                        );
                        doc.with_policy(policy, |_, m| {
                            assert!(
                                m.calls()
                                    .iter()
                                    .all(|c| !c.work().is_some_and(|work| work.bytes > 64)),
                                "growth relocation exceeds quantum: {:?}",
                                m.calls()
                            );
                        });
                    },
                )
            },
        )?;
        run.with_policy(policy, |m| assert_eq!(m.live_bytes(), 0));
        Ok::<_, Finding>(())
    });
    budgets.finish();
}

// Prior art: tokio-util/tests/length_delimited.rs, read_multi_frame_multi_packet:
// three ordered outputs, each completed once across scripted boundaries.
const CHILDREN: &[u8] = &[
    0x83, 0x63, b'a', b'b', b'c', 0x63, b'1', b'2', b'3', 0x65, b'h', b'e', b'l', b'l', b'o',
];

#[test]
fn every_child_completion_refusal_completes_each_child_once() {
    for child in 0..3 {
        script(CHILDREN, |p| {
            p.phase == Phase::Attach && p.completed_children == child
        });
    }
}

#[test]
fn a_trailing_item_is_rejected_after_a_refusal_at_every_child_completion() {
    let mut wire = CHILDREN.to_vec();
    wire.push(0x00);
    for child in 0..3 {
        rejected_case(
            decoder(&wire),
            decode_turns(wire.len()),
            |operation, policy| {
                let reached = operation.controlled(
                    policy,
                    decode_turns(wire.len()),
                    Retirement::Released,
                    true,
                    |_, operation, _| {
                        let position = operation.position();
                        position.phase == Phase::Attach && position.completed_children == child
                    },
                    |_| (),
                )?;
                assert!(reached.is_none(), "child {child} never completed");
                let position = operation.value().position();
                operation.refused(policy, 3, Retirement::Released)?;
                assert_eq!(operation.value().position(), position);
                Ok(())
            },
        );
    }
}

#[test]
fn late_invalid_trailing_item_is_never_published_after_a_refusal() {
    let wire = [0x82, 0x01, 0x02, 0x00];
    rejected_case(
        decoder(&wire),
        decode_turns(wire.len()),
        |operation, policy| {
            operation.with_policy(policy, |_, m| {
                refuse(m, Refusal::For(0, LimitRefusal::Work))
            });
            let suspended = operation.suspend(
                policy,
                LimitRefusal::Work,
                decode_turns(wire.len()),
                TurnSchedule::Retained,
                Retirement::Released,
            )?;
            assert_eq!(suspended, 0);
            operation.with_policy(policy, |_, m| m.fail_call(None));
            Ok(())
        },
    );
}
