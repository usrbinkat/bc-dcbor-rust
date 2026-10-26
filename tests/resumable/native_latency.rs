use super::bindings::{decoder, text_encoder};
use super::harness::*;
use super::support::{checked, contracted, exhausted, label};
use dcbor::bounded::{Class, Failure, Resumable, Step};
use std::time::{Duration, Instant};

// An acceptance ceiling for the measured call on the qualification host, not
// a worst-case execution-time proof. The trace includes the maximum duration
// and completed step count. No sleep, allowance accumulation, or retry occurs.
const STEP_LATENCY: Duration = Duration::from_millis(10);

/// Drive `operation` through timed shared checked turns to its output.
fn measured_completion<O: Resumable<Limits>>(
    m: &mut Limits,
    operation: &mut O,
    steps: usize,
) -> O::Output
where
    O::Error: std::fmt::Debug,
{
    let mut maximum = Duration::ZERO;
    let mut suspended = false;
    for step in 0..steps {
        let before = m.used();
        let started = Instant::now();
        let outcome = checked(m, |m| contracted(m, operation));
        let elapsed = started.elapsed();
        maximum = maximum.max(elapsed);
        assert!(
            elapsed <= STEP_LATENCY,
            "step {step}: elapsed={elapsed:?}, maximum={maximum:?}, outcome={}",
            label(&outcome)
        );
        let after = m.used();
        match outcome {
            Ok(Step::Complete(output)) => {
                assert!(
                    suspended,
                    "large fixture did not exercise multiple scheduler turns"
                );
                exhausted(m, operation);
                m.assert_units(TURN);
                return output;
            }
            Ok(Step::Progress) => suspended = true,
            Err(error) if error.class() == Class::Refused(&LimitRefusal::Work) => {
                assert_eq!(
                    m.first_refusal().map(|(_, reason)| reason),
                    Some(LimitRefusal::Work)
                );
                assert_ne!(after, before, "fixed quantum cannot admit the next unit");
                suspended = true;
            }
            other => panic!(
                "step {step}: {}; maximum={maximum:?}; calls={:?}",
                label(&other),
                m.calls()
            ),
        }
    }
    panic!("no useful completion in {steps} steps; maximum={maximum:?}");
}

#[test]
fn large_payload_decode_meets_measured_step_ceiling_and_ownership_contract() {
    let text = "x".repeat(65536);
    let wire = text_wire(&text);
    let mut m = meter();
    let pool = m.share();
    let mut operation = decoder(&wire);
    let output = measured_completion(&mut m, &mut operation, wire.len() * 4);
    assert_eq!(output.root().encoded(), wire);
    drop(operation);
    assert!(pool.live_bytes() > 0);
    assert_eq!(output.root().encoded(), wire);
    drop(output);
    assert_eq!(pool.live_bytes(), 0);
}

#[test]
fn normalization_meets_measured_step_ceiling_and_literal_canonical_oracle() {
    let source = format!("q{}", "\u{301}\u{316}".repeat(256));
    let canonical = format!("q{}{}", "\u{316}".repeat(256), "\u{301}".repeat(256));
    let expected = text_wire(&canonical);
    let mut m = meter();
    let pool = m.share();
    let mut operation = text_encoder(&source);
    let output = measured_completion(&mut m, &mut operation, source.len() * source.len());
    assert_eq!(output.as_ref(), expected);
    drop(operation);
    assert!(pool.live_bytes() >= expected.len() as u64);
    assert_eq!(output.as_ref(), expected);
    drop(output);
    assert_eq!(pool.live_bytes(), 0);
}
