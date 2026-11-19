use super::harness::*;
use super::heap::Observation;
use super::support::{
    Fault, Finding, Retirement, Stopped, physical_matrix, pipeline::Physical, recorded_run,
};
use dcbor::bounded::BoundedError;
use dcbor::bounded::text_cursor::pipeline::TextPreparation;

#[test]
fn preparation_physical_failures_preserve_independent_plan_ownership() {
    let source = "q\u{301}\u{316}".repeat(32);
    let bound = normalize_turns(&source);
    let run = |fail_at| {
        recorded_run(|run| {
            // Both policies' recording storage is made before observation
            // starts; the preparation's is observed, the emission's is not.
            let preparing = run.observed_policy(POOL);
            let emitting = run.policy(POOL);
            let observer = <Observation as Physical>::begin(fail_at);
            let (failed, stats, reached) = run.holding(
                TextPreparation::new(&source),
                Retirement::Released,
                &observer,
                |preparation| {
                    match preparation.drive(
                        preparing,
                        bound,
                        Retirement::Released,
                        |plan| {
                            // The preparation is retired before the surviving
                            // plan is lent to its writer.
                            let stats = observer.snapshot();
                            let reached = plan.with_policy(preparing, |_, meter| {
                                assert!(meter.live_bytes() > 0);
                                assert!(stats.live <= meter.live_bytes() as usize);
                                assert!(stats.peak <= meter.peak_bytes() as usize);
                                meter.reached()
                            });
                            let expected = text_wire(&"q\u{316}\u{301}".repeat(32));
                            emit_held(plan, preparing, emitting, &expected, Fault::NONE)?;
                            let emitted =
                                plan.with_policy(emitting, |_, emission| emission.reached());
                            Ok::<_, Finding>((false, stats, reached.union(emitted)))
                        },
                    ) {
                        Ok(result) => result,
                        Err(Stopped::Operation(BoundedError::Allocation { .. })) => {
                            preparation.finish(preparing, bound, Retirement::Released)?;
                            let stats = observer.snapshot();
                            preparation.with_policy(preparing, |_, meter| {
                                assert_eq!(
                                    meter.live_bytes(),
                                    0,
                                    "failed preparation retained storage",
                                );
                                assert!(stats.live <= meter.live_bytes() as usize);
                                assert!(stats.peak <= meter.peak_bytes() as usize);
                                Ok((true, stats, meter.reached()))
                            })
                        }
                        Err(stop) => Err(stop.into()),
                    }
                },
            )?;
            assert_eq!(stats.denied, usize::from(fail_at.is_some()));
            assert_eq!(failed, fail_at.is_some());
            assert!(!stats.overflow);
            assert_eq!(stats.unadmitted, 0);
            observer.finish();
            assert_eq!(observer.snapshot().live, 0);
            assert_eq!(run.with_policy(preparing, |meter| meter.live_bytes()), 0);
            Ok((stats.calls, reached))
        })
    };
    physical_matrix("text preparation physically", run);
}
