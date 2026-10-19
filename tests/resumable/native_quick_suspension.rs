use super::driver::{Driver, Event, Operation, Step, finish, finish_invalid};
use super::harness::*;
use dcbor::bounded::BoundedError;
use dcbor::bounded::decode::{
    DecodeError, Document, Options,
    cursor::{DecodeStep, Decoder},
};

struct QuickOperation<'a> {
    decoder: Decoder<'a, Permit>,
    unproven: bool,
}

impl<'a> Operation<Document<'a, Permit>> for QuickOperation<'a> {
    fn advance(&mut self, meter: &mut Meter) -> Result<Event<Document<'a, Permit>>, &'static str> {
        Ok(match self.decoder.step(meter) {
            Ok(DecodeStep::Progress) => Event::Progress,
            Ok(DecodeStep::Complete(document)) => Event::Complete(document),
            Ok(DecodeStep::Finished) => Event::Finished,
            Err(DecodeError::UnprovenText) => {
                self.unproven = true;
                Event::Invalid
            }
            Err(DecodeError::Resource(BoundedError::Refused(reason))) => Event::Refused(reason),
            Err(_) => return Err("unexpected QuickOnly error"),
        })
    }
}

fn quick_driver(input: &[u8], meter: Meter) -> Driver<QuickOperation<'_>, Document<'_, Permit>> {
    Driver::from_operation(
        QuickOperation {
            decoder: Decoder::new(input, Options::quick_only(8)),
            unproven: false,
        },
        meter,
    )
}

#[test]
fn quick_only_policy_survives_every_refusal_without_silent_normalization() {
    let fixtures = [
        ("ASCII", true),
        ("é", true),
        ("q\u{301}", false),
        ("e\u{301}", false),
    ];
    every_case(fixtures.len(), |fixture| {
        let (text, accepted) = fixtures[fixture];
        let wire = text_wire(text);
        let mut reference = quick_driver(&wire, meter());
        if accepted {
            finish(&mut reference, 4096);
            assert_eq!(reference.output.as_ref().unwrap().root().encoded(), wire);
        } else {
            finish_invalid(&mut reference, 4096);
            assert!(reference.operation().unproven);
        }
        drop(reference.output.take());
        let baseline = reference.meter;
        assert_eq!(baseline.pool.live(), 0);
        every_case(baseline.calls.len(), |stop| {
            let mut m = meter();
            m.fail_at = Some((stop, Refusal::Work));
            let pool = m.pool.clone();
            let mut operation = quick_driver(&wire, m);
            let mut suspended = false;
            for _ in 0..4096 {
                let before = operation.operation().decoder.position();
                match operation.step().unwrap() {
                    Step::Progress => assert!(operation.output.is_none()),
                    Step::Refused(Refusal::Work) => {
                        assert_eq!(operation.operation().decoder.position(), before);
                        suspended = true;
                        break;
                    }
                    other => panic!("missing QuickOnly suspension at {before:?}: {other:?}"),
                }
            }
            assert!(suspended);
            assert_eq!(operation.meter.refused, Some((stop, Refusal::Work)));
            assert!(
                !operation.operation().unproven,
                "policy outcome occurred before targeted suspension"
            );
            assert!(operation.output.is_none());
            operation.meter.fail_at = None;
            if accepted {
                finish(&mut operation, 4096);
                assert_eq!(operation.output.as_ref().unwrap().root().encoded(), wire);
            } else {
                let mut invalid = false;
                for _ in 0..4096 {
                    let before = (operation.meter.values, operation.meter.bytes);
                    operation.meter.limit_values = before.0.checked_add(3).unwrap();
                    operation.meter.limit_bytes = before.1.checked_add(64).unwrap();
                    operation.meter.refused = None;
                    let outcome = operation
                        .step()
                        .expect("missing retained QuickOnly operation");
                    let after = (operation.meter.values, operation.meter.bytes);
                    assert!(after.0 >= before.0 && after.1 >= before.1);
                    assert!(after.0 - before.0 <= 3 && after.1 - before.1 <= 64);
                    assert!(operation.output.is_none());
                    match outcome {
                        Step::Invalid => {
                            invalid = true;
                            break;
                        }
                        Step::Progress => assert_ne!(before, after),
                        other => panic!("unexpected QuickOnly outcome {other:?}"),
                    }
                }
                assert!(invalid);
                assert!(
                    operation.operation().unproven,
                    "lost the specific QuickOnly rejection"
                );
            }
            let mut trace = baseline.calls.clone();
            trace.insert(stop, baseline.calls[stop]);
            assert_eq!(
                operation.meter.calls, trace,
                "QuickOnly replayed completed work"
            );
            assert_eq!(
                (operation.meter.values, operation.meter.bytes),
                (baseline.values, baseline.bytes)
            );
            assert_eq!(operation.invocations, 1);
            operation.meter.assert_units(3, 64);
            assert_eq!(operation.step().unwrap(), Step::Finished);
            let output = operation.output.take();
            drop(operation);
            if let Some(document) = output {
                assert!(pool.live() > 0);
                assert_eq!(document.root().encoded(), wire);
                drop(document);
            }
            assert_eq!(pool.live(), 0);
        });
    });
}
