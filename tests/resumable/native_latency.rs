use super::bindings::{decoder, text_encoder};
use super::harness::*;
use super::support::{
    Finding, PolicyId, RecordedRun, Retirement, exhausted, label, panic_report,
    pipeline::Unwitnessed, scheduled,
};
use dcbor::bounded::{Class, Custodial, Failure, Resumable, Step};
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

/// Drive `operation` through timed shared checked turns to its output
/// ([`scheduled`]), the recording's integrity read inside each timed turn;
/// or, for a lost recording, any other outcome than progress, a work
/// refusal or publication, or for `steps` spent without one, the run's
/// finding. The output is returned the moment it is published, with whether
/// the schedule suspended before it, so its holder takes it before any
/// check runs.
fn measured_completion<O: Resumable<Limits>>(
    m: &mut Limits,
    operation: &mut O,
    steps: usize,
) -> Result<(O::Output, bool), Finding>
where
    O::Error: std::fmt::Debug,
    O::Position: std::fmt::Debug,
{
    let qualifying = std::env::var_os(QUALIFICATION).is_some();
    let mut maximum = Duration::ZERO;
    let mut suspended = false;
    for step in 0..steps {
        let before = m.used();
        let started = Instant::now();
        let outcome = scheduled(m, operation, step)?;
        let elapsed = started.elapsed();
        maximum = maximum.max(elapsed);
        assert!(
            !qualifying || elapsed <= STEP_LATENCY,
            "step {step}: elapsed={elapsed:?}, maximum={maximum:?}, outcome={}",
            label(&outcome)
        );
        let after = m.used();
        match outcome {
            Ok(Step::Complete(output)) => return Ok((output, suspended)),
            Ok(Step::Progress) => suspended = true,
            Err(error) if error.class() == Class::Refused(&LimitRefusal::Work) => {
                assert_eq!(
                    m.first_refusal().map(|(_, reason)| reason),
                    Some(LimitRefusal::Work)
                );
                assert_ne!(after, before, "fixed quantum cannot admit the next unit");
                suspended = true;
            }
            other => {
                return Err(Finding::Driver(format!(
                    "step {step}: {}; maximum={maximum:?}; calls={:?}",
                    label(&other),
                    m.calls()
                )));
            }
        }
    }
    Err(Finding::Driver(format!(
        "no useful completion in {steps} steps; maximum={maximum:?}"
    )))
}

/// `operation`, held by `run`, through the timed schedule to its publication
/// ([`measured_completion`]); then its terminal probe ([`exhausted`]) on the
/// held operation, a probe failure the run's finding with the output still
/// held; then the output handed over from its exhausted publisher
/// ([`Holding::hand_over`]) and checked by `check` while it outlives the
/// operation. Afterwards the run holds nothing.
fn timed<O>(
    run: &mut RecordedRun,
    policy: PolicyId,
    operation: O,
    steps: usize,
    check: impl FnOnce(&mut O::Output, &mut Limits),
) -> Result<(), Finding>
where
    O: Resumable<Limits> + Custodial<Reservation>,
    O::Output: Custodial<Reservation>,
    O::Error: std::fmt::Debug,
    O::Position: std::fmt::Debug,
{
    run.holding(operation, Retirement::Released, &Unwitnessed, |operation| {
        let (output, suspended) =
            operation.with_policy(policy, |operation, m| measured_completion(m, operation, steps))?;
        let probed = operation.with_policy(policy, |operation, m| {
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                exhausted(m, operation);
                m.assert_units(TURN);
            }))
        });
        operation.hand_over(Retirement::Exhausted, output, Retirement::Released, |output| {
            if let Err(payload) = probed {
                return Err(Finding::Defect(format!(
                    "the published operation's terminal probe failed: {}",
                    panic_report(payload.as_ref())
                )));
            }
            assert!(
                suspended,
                "large fixture did not exercise multiple scheduler turns"
            );
            output.with_policy(policy, |output, m| check(output, m));
            Ok(())
        })
    })?;
    run.with_policy(policy, |m| assert_eq!(m.live_bytes(), 0));
    Ok(())
}

#[test]
fn large_payload_decode_meets_measured_step_ceiling_and_ownership_contract() {
    let text = "x".repeat(65536);
    let wire = text_wire(&text);
    // A 64 KiB text decoded in units of a quantum: 131,121 observations and
    // 2 permit records, measured.
    let recording = super::support::measured(131_121, 2);
    suite_with(POOL, recording, |run, policy| {
        timed(run, policy, decoder(&wire), wire.len() * 4, |output, m| {
            // The decoder is retired; the document holds its arena.
            assert!(m.live_bytes() > 0);
            assert_eq!(output.root().encoded(), wire);
        })
    });
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
