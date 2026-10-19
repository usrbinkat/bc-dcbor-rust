use super::bindings::{decode_driver, text_driver};
use super::driver::{Driver, Operation, Step};
use super::harness::*;
use std::time::{Duration, Instant};

// An acceptance ceiling for the measured call on the qualification host, not
// a worst-case execution-time proof. The trace includes the maximum duration
// and completed step count. No sleep, allowance accumulation, or retry occurs.
const STEP_LATENCY: Duration = Duration::from_millis(10);

fn measured_completion<F, T>(operation: &mut Driver<F, T>, steps: usize)
where
    F: Operation<T>,
{
    let mut maximum = Duration::ZERO;
    let mut suspended = false;
    for step in 0..steps {
        let before = (operation.meter.values, operation.meter.bytes);
        operation.meter.limit_values = before.0.checked_add(3).unwrap();
        operation.meter.limit_bytes = before.1.checked_add(64).unwrap();
        operation.meter.refused = None;
        let started = Instant::now();
        let outcome = operation.step();
        let elapsed = started.elapsed();
        maximum = maximum.max(elapsed);
        assert!(
            elapsed <= STEP_LATENCY,
            "step {step}: elapsed={elapsed:?}, maximum={maximum:?}, outcome={outcome:?}"
        );
        let after = (operation.meter.values, operation.meter.bytes);
        assert!(after.0 >= before.0 && after.1 >= before.1);
        assert!(after.0 - before.0 <= 3 && after.1 - before.1 <= 64);
        match outcome {
            Ok(Step::Complete) => {
                assert!(
                    suspended,
                    "large fixture did not exercise multiple scheduler turns"
                );
                assert!(operation.output.is_some());
                assert_eq!(operation.invocations, 1);
                operation.meter.assert_units(3, 64);
                return;
            }
            Ok(Step::Progress) => {
                suspended = true;
                assert!(operation.output.is_none());
                assert_ne!(after, before, "empty progress step {step}");
            }
            Ok(Step::Refused(Refusal::Work)) => {
                assert_eq!(
                    operation.meter.refused.map(|(_, reason)| reason),
                    Some(Refusal::Work)
                );
                assert!(operation.output.is_none());
                assert_ne!(after, before, "fixed quantum cannot admit the next unit");
                suspended = true;
            }
            other => panic!(
                "step {step}: {other:?}; maximum={maximum:?}; calls={:?}",
                operation.meter.calls
            ),
        }
    }
    panic!("no useful completion in {steps} steps; maximum={maximum:?}");
}

#[test]
fn large_payload_decode_meets_measured_step_ceiling_and_ownership_contract() {
    let text = "x".repeat(65536);
    let wire = text_wire(&text);
    let m = meter();
    let pool = m.pool.clone();
    let mut operation = decode_driver(&wire, m);
    measured_completion(&mut operation, wire.len() * 4);
    assert_eq!(operation.output.as_ref().unwrap().root().encoded(), wire);
    let output = operation.output.take().unwrap();
    assert_eq!(operation.step().unwrap(), Step::Finished);
    drop(operation);
    assert!(pool.live() > 0);
    assert_eq!(output.root().encoded(), wire);
    drop(output);
    assert_eq!(pool.live(), 0);
}

#[test]
fn normalization_meets_measured_step_ceiling_and_literal_canonical_oracle() {
    let source = format!("q{}", "\u{301}\u{316}".repeat(256));
    let canonical = format!("q{}{}", "\u{316}".repeat(256), "\u{301}".repeat(256));
    let expected = text_wire(&canonical);
    let m = meter();
    let pool = m.pool.clone();
    let mut operation = text_driver(&source, m);
    measured_completion(&mut operation, source.len() * source.len());
    assert_eq!(operation.output.as_ref().unwrap().as_ref(), expected);
    let output = operation.output.take().unwrap();
    assert_eq!(operation.step().unwrap(), Step::Finished);
    drop(operation);
    assert!(pool.live() >= expected.len() as u64);
    assert_eq!(output.as_ref(), expected);
    drop(output);
    assert_eq!(pool.live(), 0);
}
