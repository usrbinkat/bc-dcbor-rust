use super::bindings::{decode_driver, string_driver, text_driver};
use super::driver::{Step, finish, resume};
use super::harness::*;
use dcbor::bounded::decode::Kind;

fn assert_no_replay(actual: &Meter, baseline: &Meter, stop: usize) {
    let mut expected = baseline.calls.clone();
    expected.insert(stop, baseline.calls[stop]);
    assert_eq!(actual.calls, expected, "completed work was replayed");
    assert_eq!(
        (actual.values, actual.bytes),
        (baseline.values, baseline.bytes)
    );
}

#[test]
fn decoder_resumes_same_operation_before_and_after_header_without_replay() {
    let wire = [
        0x58, 0x18, b'a', b'b', b'c', b'd', b'e', b'f', b'g', b'h', b'i', b'j', b'k', b'l', b'm',
        b'n', b'o', b'p', b'q', b'r', b's', b't', b'u', b'v', b'w', b'x',
    ];
    let mut reference = decode_driver(&wire, meter());
    finish(&mut reference, 4096);
    drop(reference.output.take());
    let baseline = reference.meter;
    every_case(baseline.calls.len(), |stop| {
        let mut m = meter();
        m.fail_at = Some((stop, Refusal::Work));
        let pool = m.pool.clone();
        let mut operation = decode_driver(&wire, m);
        resume(&mut operation, Refusal::Work);
        assert_no_replay(&operation.meter, &baseline, stop);
        assert_eq!(
            operation.output.as_ref().unwrap().root().kind(),
            Kind::Bytes(&wire[2..])
        );
        assert_eq!(operation.output.as_ref().unwrap().root().encoded(), wire);
        operation.meter.assert_units(3, 64);
        assert_eq!(operation.step().unwrap(), Step::Finished);
        drop(operation);
        assert_eq!(pool.live(), 0);
    });
}

#[test]
fn text_normalization_resumes_each_real_refusal_and_preserves_literal_result() {
    let source = "a\u{301}";
    let mut reference = text_driver(source, meter());
    finish(&mut reference, 4096);
    drop(reference.output.take());
    let baseline = reference.meter;
    every_case(baseline.calls.len(), |stop| {
        let mut m = meter();
        m.fail_at = Some((stop, Refusal::Work));
        let pool = m.pool.clone();
        let mut operation = text_driver(source, m);
        resume(&mut operation, Refusal::Work);
        assert_no_replay(&operation.meter, &baseline, stop);
        assert_eq!(
            operation.output.as_ref().unwrap().as_ref(),
            &[0x62, 0xc3, 0xa1]
        );
        operation.meter.assert_units(3, 64);
        let value = operation.output.take().unwrap();
        drop(operation);
        assert!(pool.live() >= 3);
        drop(value);
        assert_eq!(pool.live(), 0);
    });
}

#[test]
fn typed_construction_resumes_and_transfers_output_ownership() {
    let wire = [0x62, 0xc3, 0xa9];
    let mut reference = string_driver(&wire, meter());
    finish(&mut reference, 4096);
    drop(reference.output.take());
    let baseline = reference.meter;
    every_case(baseline.calls.len(), |stop| {
        let mut m = meter();
        m.fail_at = Some((stop, Refusal::Work));
        let pool = m.pool.clone();
        let mut operation = string_driver(&wire, m);
        resume(&mut operation, Refusal::Work);
        assert_no_replay(&operation.meter, &baseline, stop);
        assert_eq!(operation.output.as_ref().unwrap().value(), "é");
        operation.meter.assert_units(3, 64);
        let value = operation.output.take().unwrap();
        drop(operation);
        assert!(pool.live() >= 2);
        assert_eq!(value.value(), "é");
        drop(value);
        assert_eq!(pool.live(), 0);
    });
}

#[test]
fn externally_released_capacity_resumes_same_decode_not_a_second_attempt() {
    let pool = Pool::new(4096);
    let blocked = pool.reserve(4096).unwrap();
    let wire = [0x81, 0x01];
    let mut operation = decode_driver(&wire, Meter::new(pool.clone()));
    let mut suspended = false;
    for _ in 0..4096 {
        match operation.step().unwrap() {
            Step::Progress => assert!(operation.output.is_none()),
            Step::Refused(Refusal::Capacity) => {
                suspended = true;
                break;
            }
            other => panic!("expected capacity suspension, got {other:?}"),
        }
    }
    assert!(suspended, "capacity boundary was never reached");
    let (stop, reason) = operation
        .meter
        .refused
        .expect("capacity refusal was not observed");
    assert_eq!(reason, Refusal::Capacity);
    let paid = (operation.meter.values, operation.meter.bytes);
    assert!(operation.output.is_none());
    assert_eq!(pool.live(), 4096);
    std::thread::spawn(move || drop(blocked)).join().unwrap();
    assert_eq!(pool.live(), 0);
    finish(&mut operation, 4096);
    assert_eq!(operation.invocations, 1);
    assert!(operation.meter.values >= paid.0 && operation.meter.bytes >= paid.1);
    let mut reference = decode_driver(&wire, meter());
    finish(&mut reference, 4096);
    drop(reference.output.take());
    let baseline = reference.meter;
    assert_no_replay(&operation.meter, &baseline, stop);
    assert_eq!(operation.output.as_ref().unwrap().root().encoded(), wire);
    operation.meter.assert_units(3, 64);
    drop(operation);
    assert_eq!(pool.live(), 0);
    let all = pool.reserve(4096).unwrap();
    assert!(pool.reserve(1).is_err());
    drop(all);
}

#[test]
fn driver_control_executes_real_decode_once_and_never_republishes() {
    let wire = [0x81, 0x01];
    let mut operation = decode_driver(&wire, meter());
    finish(&mut operation, 4096);
    assert_eq!(operation.output.as_ref().unwrap().root().encoded(), wire);
    assert_eq!(operation.step().unwrap(), Step::Finished);
    assert_eq!(operation.invocations, 1);
}
