use super::bindings::text_encoder;
use super::harness::*;
use super::support::{
    Fault, Finding, Retirement, Stepped, allowed, contracted, expect_progress, ordinary_exhaustion,
    pipeline::{Refusal, Unwitnessed},
    refusal_matrix, refuse,
    rigor::rigor,
};
use dcbor::bounded::{BoundedError, Failure};

#[test]
fn actual_normalizer_progress_and_emitted_prefix_survive_every_cancellation_point() {
    let source = "a\u{300}\u{305}\u{315}\u{5ae}b";
    let expected = [0x69, 0xc3, 0xa0, 0xd6, 0xae, 0xcc, 0x85, 0xcc, 0x95, b'b'];
    // The unrefused encoding's state after each progress step, as detached
    // data from a recorded run of its own, the encoder and its output held
    // by the run.
    let states = suite(|run, policy| {
        run.holding(
            text_encoder(source),
            Retirement::Released,
            &Unwitnessed,
            |reference| {
                let mut states = Vec::new();
                for at in 0..normalize_turns(source) {
                    let before = reference.value().position();
                    match reference.step(
                        policy,
                        at,
                        Retirement::Released,
                        |_, _| {},
                        |output| {
                            assert_eq!(output.value().as_ref(), expected);
                            output.with_policy(policy, |_, baseline| baseline.assert_units(TURN));
                        },
                    )? {
                        Stepped::Progress => {
                            reference.with_policy(policy, |reference, baseline| {
                                assert_ne!(
                                    reference.position(),
                                    before,
                                    "charges alone must not count as useful execution progress"
                                );
                                assert!(expected.starts_with(reference.emitted_prefix()));
                                states.push((reference.position(), baseline.live_bytes()));
                            });
                        }
                        Stepped::Published(()) => return Ok(states),
                        Stepped::Failed(error)
                            if reference
                                .with_policy(policy, |_, m| ordinary_exhaustion(m, &error)) => {}
                        other => {
                            return Err(Finding::Driver(format!(
                                "unexpected normalization outcome {other:?}"
                            )));
                        }
                    }
                }
                Err(Finding::Driver("normalization did not complete".to_owned()))
            },
        )
    });
    assert!(!states.is_empty());
    // Every admission refused from the state the unrefused encoding reaches
    // there, the refused step moving nothing (`contracted`), and a
    // cancellation at every admission releasing everything the encoder held.
    // After each step that makes progress, the encoder is at the position,
    // holding the storage, the unrefused encoding reached after as many
    // steps: refusals change when steps happen, never what they do.
    refusal_matrix(
        "text encoder of a reordered run",
        rigor(),
        |fault: Fault| {
            suite(|run, policy| {
                run.holding(
                    text_encoder(source),
                    Retirement::Released,
                    &Unwitnessed,
                    |operation| {
                        let turns = operation.with_policy(policy, |_, m| {
                            refuse(m, fault.refusal);
                            allowed(m, normalize_turns(source))
                        });
                        let mut steps = 0;
                        for at in 0..turns {
                            match operation.step(
                                policy,
                                at,
                                Retirement::Released,
                                |_, _| {},
                                |output| {
                                    assert_eq!(
                                        steps,
                                        states.len(),
                                        "completion came at another step"
                                    );
                                    assert_eq!(output.value().as_ref(), expected);
                                },
                            )? {
                                Stepped::Progress => {
                                    operation.with_policy(policy, |operation, m| {
                                        assert_eq!(
                                            (operation.position(), m.live_bytes()),
                                            states[steps],
                                            "progress step {steps} reached another state"
                                        );
                                        assert!(expected.starts_with(operation.emitted_prefix()));
                                    });
                                    steps += 1;
                                }
                                Stepped::Published(()) => return Ok(()),
                                Stepped::Failed(error) if error.refused() => {
                                    if fault.cancel
                                        && operation
                                            .with_policy(policy, |_, m| m.injected_refusals())
                                            > 0
                                    {
                                        assert!(
                                            expected
                                                .starts_with(operation.value().emitted_prefix())
                                        );
                                        return Ok(());
                                    }
                                }
                                other => {
                                    return Err(Finding::Driver(format!(
                                        "unexpected normalization outcome {other:?}"
                                    )));
                                }
                            }
                        }
                        Err(Finding::Driver(
                            "the encoding exceeded its bound".to_owned(),
                        ))
                    },
                )?;
                Ok(run.with_policy(policy, |m| {
                    assert_eq!(m.live_bytes(), 0);
                    super::support::RefusalRun::of(m)
                }))
            })
        },
    );
}

#[test]
fn text_resume_retains_actual_offsets_and_owned_output_after_decoder_drop() {
    let source = "\u{1e0b}\u{323}";
    let expected = [0x65, 0xe1, 0xb8, 0x8d, 0xcc, 0x87];
    suite(|run, policy| {
        run.holding(
            text_encoder(source),
            Retirement::Released,
            &Unwitnessed,
            |operation| {
                operation.with_policy(policy, |operation, m| {
                    expect_progress(contracted(m, operation))?;
                    let before = operation.position();
                    assert_eq!(before.source_bytes, 3);
                    let call = m.attempts();
                    refuse(m, Refusal::For(call, LimitRefusal::Storage));
                    assert!(matches!(
                        contracted(m, operation),
                        Err(BoundedError::Refused(LimitRefusal::Storage))
                    ));
                    assert_eq!(m.first_refusal(), Some((call, LimitRefusal::Storage)));
                    assert_eq!(operation.position(), before);
                    m.fail_call(None);
                    Ok::<_, Finding>(())
                })?;
                // The source bytes the encoder reports after each turn, read
                // while it is still held; the last is its position at
                // publication.
                let mut read = 0;
                operation.drive_faulted(
                    policy,
                    normalize_turns(source),
                    Retirement::Released,
                    Fault::NONE,
                    |_, operation| read = operation.position().source_bytes,
                    // The encoder is retired before the output is consumed:
                    // the output outlives it, holding exactly its bytes.
                    |output| {
                        output.with_policy(policy, |output, m| {
                            assert_eq!(output.as_ref(), expected);
                            assert_eq!(m.live_bytes(), expected.len() as u64);
                        });
                    },
                )?;
                assert_eq!(read, source.len());
                Ok::<_, Finding>(())
            },
        )?;
        run.with_policy(policy, |m| assert_eq!(m.live_bytes(), 0));
        Ok(())
    });
}
