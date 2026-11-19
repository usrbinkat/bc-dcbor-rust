use super::bindings::{decoder, text_encoder};
use super::harness::*;
use super::support::{
    Finding, Holding, PolicyId, RecordedRun, Retirement, Stepped, Terminal, pipeline::Unwitnessed,
};
use dcbor::bounded::{Class, Custodial, Failure, Resumable};
use std::time::{Duration, Instant};

// An acceptance ceiling for the measured call on the qualification host, not
// a worst-case execution-time proof. The trace includes the maximum duration
// and completed step count. No sleep, allowance accumulation, or retry occurs.
const STEP_LATENCY: Duration = Duration::from_millis(10);

/// Set by the host qualification gate (`run_tests.sh`) alone: only then does
/// the wall-clock ceiling decide the outcome. Elsewhere, under mutation runs
/// above all, a step's duration depends on the host's load, not on the code,
/// so it is measured and reported but never asserted; the deterministic
/// assertions (completion, suspension, the trace, ownership, the output)
/// hold in every run.
const QUALIFICATION: &str = "DCBOR_LATENCY_QUALIFICATION";

/// Measure checked turns while shared holdings retain every publication
/// across timing assertions, terminal probing, and output inspection.
fn measured_completion<O>(
    operation: &mut Holding<'_, '_, O, Unwitnessed>,
    policy: PolicyId,
    steps: usize,
    check: impl FnOnce(&mut O::Output, &mut Limits),
) -> Result<(), Finding>
where
    O: Resumable<Limits> + Custodial<Reservation> + Terminal,
    O::Output: Custodial<Reservation>,
    O::Error: std::fmt::Debug,
    O::Position: std::fmt::Debug,
{
    let qualifying = std::env::var_os(QUALIFICATION).is_some();
    let mut maximum = Duration::ZERO;
    let mut suspended = false;
    let mut check = Some(check);
    for step in 0..steps {
        let before = operation.with_policy(policy, |_, m| m.used());
        let started = Instant::now();
        let outcome = operation.step(
            policy,
            step,
            Retirement::Released,
            |_, _| {
                let elapsed = started.elapsed();
                maximum = maximum.max(elapsed);
                assert!(
                    !qualifying || elapsed <= STEP_LATENCY,
                    "step {step}: elapsed={elapsed:?}, maximum={maximum:?}"
                );
            },
            |output| {
                assert!(
                    suspended,
                    "large fixture did not exercise multiple scheduler turns"
                );
                output.with_policy(policy, |output, m| {
                    m.assert_units(TURN);
                    check
                        .take()
                        .expect("one publication consumes its inspector")(
                        output, m
                    );
                });
            },
        )?;
        match outcome {
            Stepped::Published(()) => return Ok(()),
            Stepped::Progress => suspended = true,
            Stepped::Failed(error) if error.class() == Class::Refused(&LimitRefusal::Work) => {
                operation.with_policy(policy, |_, m| {
                    assert_eq!(
                        m.first_refusal().map(|(_, reason)| reason),
                        Some(LimitRefusal::Work)
                    );
                    assert_ne!(m.used(), before, "fixed quantum cannot admit the next unit");
                });
                suspended = true;
            }
            other => {
                return operation.with_policy(policy, |_, m| {
                    Err(Finding::Driver(format!(
                        "step {step}: {other:?}; maximum={maximum:?}; calls={:?}",
                        m.calls()
                    )))
                });
            }
        }
    }
    Err(Finding::Driver(format!(
        "no useful completion in {steps} steps; maximum={maximum:?}"
    )))
}

/// `operation`, held by `run`, through the timed schedule to its publication
/// ([`measured_completion`]), inspected after shared terminal probing and
/// publisher retirement.
fn timed<O>(
    run: &mut RecordedRun,
    policy: PolicyId,
    operation: O,
    steps: usize,
    check: impl FnOnce(&mut O::Output, &mut Limits),
) -> Result<(), Finding>
where
    O: Resumable<Limits> + Custodial<Reservation> + Terminal,
    O::Output: Custodial<Reservation>,
    O::Error: std::fmt::Debug,
    O::Position: std::fmt::Debug,
{
    run.holding(operation, Retirement::Released, &Unwitnessed, |operation| {
        measured_completion(operation, policy, steps, check)
    })?;
    run.with_policy(policy, |m| assert_eq!(m.live_bytes(), 0));
    Ok(())
}

#[test]
fn large_payload_decode_meets_measured_step_ceiling_and_ownership_contract() {
    let text = "x".repeat(65536);
    let wire = text_wire(&text);
    let mut budgets = budgets("payload-latency", &["text/65536/timed"]);
    budget_suite(&mut budgets, "text/65536/timed", POOL, |run, policy| {
        timed(run, policy, decoder(&wire), wire.len() * 4, |output, m| {
            // The decoder is retired; the document holds its arena.
            assert!(m.live_bytes() > 0);
            assert_eq!(output.root().encoded(), wire);
        })
    });
    budgets.finish();
}

#[test]
fn normalization_meets_measured_step_ceiling_and_literal_canonical_oracle() {
    let source = format!("q{}", "\u{301}\u{316}".repeat(256));
    let canonical = format!("q{}{}", "\u{316}".repeat(256), "\u{301}".repeat(256));
    let expected = text_wire(&canonical);
    suite(|run, policy| {
        timed(
            run,
            policy,
            text_encoder(&source),
            source.len() * source.len(),
            |output, m| {
                // The encoder is retired; the encoding holds its bytes.
                assert!(m.live_bytes() >= expected.len() as u64);
                assert_eq!(output.as_ref(), expected);
            },
        )
    });
}
