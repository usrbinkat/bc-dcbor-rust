use super::bindings::{string_decoder, text_encoder};
use super::harness::*;
use super::support::{
    Fault, Finding, RefusalRun, Retirement, pipeline::Unwitnessed, recorded_run, refusal_matrix,
    rigor::rigor,
};
use dcbor::bounded::text_cursor::pipeline::TextPreparation;

const SOURCE: &str = "a\u{301}";
const EXPECTED: &[u8] = &[0x62, 0xc3, 0xa1];

/// Every refusal of preparing [`SOURCE`] resumed to a plan that owns its
/// storage beyond the preparation and emits the literal encoding, and a
/// cancellation at every call releasing the preparation's scratch.
#[test]
fn preparation_refusal_and_cancellation_preserve_literal_result_and_plan_ownership() {
    retained_case(
        TextPreparation::new(SOURCE),
        normalize_turns(SOURCE),
        Fault::NONE,
        |plan, _| {
            assert_eq!(plan.len(), EXPECTED.len() as u64);
        },
    );
    refusal_matrix("text preparation", rigor(), |fault: Fault| {
        recorded_run(|run| {
            let preparing = run.policy(POOL);
            let emitting = run.policy(POOL);
            run.holding(
                TextPreparation::new(SOURCE),
                Retirement::Released,
                &Unwitnessed,
                |operation| {
                    let retained = std::cell::Cell::new(0);
                    operation
                        .drive_faulted(
                            preparing,
                            normalize_turns(SOURCE),
                            Retirement::Released,
                            fault,
                            |m, _| retained.set(m.live_bytes()),
                            |plan| {
                                let retained = retained.get();
                                plan.with_policy(preparing, |_, m| {
                                    m.assert_units(TURN);
                                    assert!(retained > 0);
                                    assert_eq!(m.live_bytes(), retained);
                                });
                                let mut bytes = [0xee; 3];
                                plan.lending(
                                    Retirement::Released,
                                    |plan| plan.writer(&mut bytes),
                                    |writer| {
                                        writer.drive(
                                            emitting,
                                            text_emit_turns(EXPECTED.len()),
                                            Retirement::Released,
                                            |output| {
                                                output.with_policy(emitting, |_, m| {
                                                    m.assert_units(TURN)
                                                });
                                            },
                                        )
                                    },
                                )?;
                                assert_eq!(bytes, EXPECTED);
                                plan.with_policy(preparing, |_, m| {
                                    assert_eq!(m.live_bytes(), retained)
                                });
                                Ok::<_, Finding>(())
                            },
                        )?
                        .transpose()?;
                    Ok::<_, Finding>(())
                },
            )?;
            run.with_policy(preparing, |m| {
                assert_eq!(m.live_bytes(), 0, "retirement kept scratch or plan storage");
                Ok(RefusalRun::of(m))
            })
        })
    });
}

/// Every refusal of emitting the plan resumed into the same guarded
/// destination without replaying its prefix, and a cancellation at every
/// call leaving exactly the literal prefix emitted so far, the guards intact
/// and the plan's storage held. Each run prepares its plan under a family of
/// its own and emits it under another, so the run holds every custody it
/// makes.
#[test]
fn emission_refusal_and_cancellation_preserve_destination_prefix_and_plan() {
    refusal_matrix("text emission", rigor(), |fault: Fault| {
        recorded_run(|run| {
            let allocator = run.policy(POOL);
            let emitting = run.policy(POOL);
            run.holding(
                TextPreparation::new(SOURCE),
                Retirement::Released,
                &Unwitnessed,
                |preparation| {
                    preparation.drive(
                        allocator,
                        normalize_turns(SOURCE),
                        Retirement::Released,
                        |plan| {
                            let retained = plan.with_policy(allocator, |_, a| a.live_bytes());
                            let mut guarded = [0xee; 5];
                            let emitted = plan
                                .lending(
                                    Retirement::Released,
                                    |plan| plan.writer(&mut guarded[1..4]),
                                    |operation| {
                                        operation.drive_faulted(
                                            emitting,
                                            text_emit_turns(EXPECTED.len()),
                                            Retirement::Released,
                                            fault,
                                            |_, _| {},
                                            |output| {
                                                output.with_policy(emitting, |_, m| {
                                                    m.assert_units(TURN)
                                                })
                                            },
                                        )
                                    },
                                )?
                                .is_some();
                            assert_eq!(
                                plan.with_policy(allocator, |_, a| a.live_bytes()),
                                retained,
                                "emission changed the plan"
                            );
                            // The writer's borrow of `guarded` has ended; it has no destructor.
                            assert_eq!(
                                (guarded[0], guarded[4]),
                                (0xee, 0xee),
                                "a guard was written"
                            );
                            let written = guarded[1..4]
                                .iter()
                                .take_while(|byte| **byte != 0xee)
                                .count();
                            assert_eq!(&guarded[1..1 + written], &EXPECTED[..written]);
                            assert!(guarded[1 + written..4].iter().all(|byte| *byte == 0xee));
                            if emitted {
                                assert_eq!(
                                    written,
                                    EXPECTED.len(),
                                    "a completed emission is partial"
                                );
                            }
                            Ok::<_, Finding>(())
                        },
                    )?
                },
            )?;
            assert_eq!(run.with_policy(allocator, |a| a.live_bytes()), 0);
            Ok(run.with_policy(emitting, |m| RefusalRun::of(m)))
        })
    });
}

/// Every refusal of encoding [`SOURCE`], resumed or cancelled, beside an
/// independent output of the same pool: the output's storage is untouched
/// by the second encoding's suspension, resumption or cancellation.
#[test]
fn every_encoding_refusal_leaves_an_independent_output_untouched() {
    refusal_matrix("text encoding beside an output", rigor(), |fault: Fault| {
        suite(|run, policy| {
            let first = run.shared_policy(policy);
            let second = run.shared_policy(policy);
            run.holding(
                text_encoder(SOURCE),
                Retirement::Released,
                &Unwitnessed,
                |operation| {
                    operation
                        .drive_faulted(
                            first,
                            normalize_turns(SOURCE),
                            Retirement::Released,
                            Fault::NONE,
                            |_, _| {},
                            |output| {
                                let retained =
                                    output.with_policy(policy, |_, pool| pool.live_bytes());
                                assert!(retained >= EXPECTED.len() as u64);
                                output.holding(
                                    text_encoder(SOURCE),
                                    Retirement::Released,
                                    |operation| {
                                        operation.drive_faulted(
                                            second,
                                            normalize_turns(SOURCE),
                                            Retirement::Released,
                                            fault,
                                            |m, _| assert!(m.live_bytes() >= retained),
                                            |second| {
                                                assert_eq!(second.value().as_ref(), EXPECTED);
                                            },
                                        )
                                    },
                                )?;
                                assert_eq!(
                                    output.with_policy(policy, |_, pool| pool.live_bytes()),
                                    retained,
                                    "the independent output changed"
                                );
                                assert_eq!(output.value().as_ref(), EXPECTED);
                                Ok::<_, Finding>(())
                            },
                        )?
                        .transpose()?;
                    Ok::<_, Finding>(())
                },
            )?;
            run.with_policy(policy, |pool| assert_eq!(pool.live_bytes(), 0));
            Ok(run.with_policy(second, |m| RefusalRun::of(m)))
        })
    });
}

// Ownership transitions and exact final reacquisition follow merge/split and
// stress_test in tokio/tests/sync_semaphore_owned.rs. Workers use real dCBOR
// calls and independently observed suspension; no worker simulates a result.
#[test]
fn concurrent_suspended_constructors_recover_exact_shared_capacity() {
    // The pool: four elements of eight mebibytes of one tenant.
    const EIGHTH: usize = 8 * 1024 * 1024;
    recorded_run(|run| {
        let unobstructed = run.policy(POOL);
        run.holding(
            string_decoder(EXPECTED),
            Retirement::Released,
            &Unwitnessed,
            |decoder| {
                decoder.drive(
                    unobstructed,
                    string_turns(EXPECTED.len()),
                    Retirement::Released,
                    |output| assert_eq!(output.value().value(), "\u{e1}"),
                )
            },
        )?;
        let (baseline, used) = run.with_policy(unobstructed, |baseline| {
            (RefusalRun::of(baseline), baseline.used())
        });
        let boundaries = baseline.calls().len();
        // Every refused call is suspended and resumed the same number of
        // times, in rounds over all of them, about a thousand continuations
        // in all; the cases are dealt to the workers in turn.
        const WORKERS: usize = 8;
        const CONTINUATIONS: usize = 1000;
        let rounds = CONTINUATIONS.div_ceil(boundaries);
        let cases: Vec<Option<usize>> = (0..rounds)
            .flat_map(|_| (0..boundaries).map(Some))
            .collect();
        concurrent_string_decodes::<EIGHTH>(run, WORKERS, EXPECTED, &cases, "\u{e1}", |m, stop| {
            let stop = stop.expect("every continuation refuses one call");
            RefusalRun::of(m).resumed(&baseline, stop, LimitRefusal::Work);
            assert_eq!(m.used(), used);
            m.assert_units(TURN);
        })
    });
}
