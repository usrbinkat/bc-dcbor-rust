use super::bindings::{decode_driver, string_driver, text_driver};
use super::driver::{Driver, Operation, Step, finish};
use super::harness::*;

/// Refuse every callback, successively, on ONE operation. At each turn only
/// the previously refused callback may succeed before the next refusal.
/// Separate one-refusal runs cannot prove this retained-state contract.
fn successive<F, T>(operation: &mut Driver<F, T>, baseline: &Meter)
where
    F: Operation<T>,
{
    let mut expected = Vec::new();
    let mut paid = (0, 0);
    for (index, call) in baseline.calls.iter().copied().enumerate() {
        let reason = match call {
            Call::Allocate(_) => Refusal::Capacity,
            Call::Work { .. } => Refusal::Work,
        };
        let target = if index == 0 {
            0
        } else {
            operation.meter.calls.len() + 1
        };
        operation.meter.fail_at = Some((target, reason));
        operation.meter.refused = None;
        operation.meter.limit_values = paid.0 + 3;
        operation.meter.limit_bytes = paid.1 + 64;
        if index > 0 {
            expected.push(baseline.calls[index - 1]);
        }
        expected.push(call);
        let mut observed = false;
        for _ in 0..4 {
            match operation.step().unwrap() {
                Step::Progress => assert!(operation.output.is_none()),
                Step::Refused(actual) => {
                    assert_eq!(actual, reason, "boundary {index}");
                    observed = true;
                    break;
                }
                other => panic!("boundary {index}: expected suspension, got {other:?}"),
            }
        }
        assert!(
            observed,
            "boundary {index}: no refusal; trace {:?}",
            operation.meter.calls
        );
        assert_eq!(operation.meter.refused, Some((target, reason)));
        assert_eq!(operation.meter.calls, expected);
        assert!(
            operation.output.is_none(),
            "published before all boundaries completed"
        );
        let next = (operation.meter.values, operation.meter.bytes);
        assert!(next.0 >= paid.0 && next.1 >= paid.1);
        assert!(next.0 - paid.0 <= 3 && next.1 - paid.1 <= 64);
        paid = next;
    }
    operation.meter.fail_at = None;
    operation.meter.refused = None;
    operation.meter.limit_values = paid.0 + 3;
    operation.meter.limit_bytes = paid.1 + 64;
    assert_eq!(operation.step(), Ok(Step::Complete));
    expected.push(*baseline.calls.last().expect("nonempty admission trace"));
    assert_eq!(operation.meter.calls, expected);
    assert_eq!(
        (operation.meter.values, operation.meter.bytes),
        (baseline.values, baseline.bytes)
    );
    operation.meter.assert_units(3, 64);
    assert_eq!(operation.invocations, 1);
    assert_eq!(operation.step(), Ok(Step::Finished));
}

#[test]
fn decoder_survives_successive_refusals_on_one_retained_operation() {
    let wire = [0x82, 0x01, 0x62, 0xc3, 0xa9];
    let mut reference = decode_driver(&wire, meter());
    finish(&mut reference, 4096);
    drop(reference.output.take());
    let baseline = reference.meter;
    let m = meter();
    let pool = m.pool.clone();
    let mut operation = decode_driver(&wire, m);
    successive(&mut operation, &baseline);
    let document = operation.output.take().unwrap();
    assert_eq!(document.root().encoded(), wire);
    drop(operation);
    assert!(pool.live() > 0);
    assert_eq!(document.root().encoded(), wire);
    drop(document);
    assert_eq!(pool.live(), 0);
}

#[test]
fn typed_fields_survive_successive_refusals_with_output_ownership() {
    let wire = [0x62, 0xc3, 0xa9];
    let mut reference = string_driver(&wire, meter());
    finish(&mut reference, 4096);
    drop(reference.output.take());
    let baseline = reference.meter;
    let m = meter();
    let pool = m.pool.clone();
    let mut operation = string_driver(&wire, m);
    successive(&mut operation, &baseline);
    let value = operation.output.take().unwrap();
    assert_eq!(value.value(), "é");
    drop(operation);
    assert!(pool.live() >= 2);
    assert_eq!(value.value(), "é");
    drop(value);
    assert_eq!(pool.live(), 0);
}

#[test]
fn normalization_and_emission_survive_successive_refusals_without_replay() {
    let source = "a\u{301}";
    let mut reference = text_driver(source, meter());
    finish(&mut reference, 4096);
    drop(reference.output.take());
    let baseline = reference.meter;
    let m = meter();
    let pool = m.pool.clone();
    let mut operation = text_driver(source, m);
    successive(&mut operation, &baseline);
    let output = operation.output.take().unwrap();
    assert_eq!(output.as_ref(), &[0x62, 0xc3, 0xa1]);
    drop(operation);
    assert!(pool.live() >= 3);
    assert_eq!(output.as_ref(), &[0x62, 0xc3, 0xa1]);
    drop(output);
    assert_eq!(pool.live(), 0);
}
