use super::bindings::decode_driver;
use super::driver::{Step, finish_invalid};
use super::harness::*;

fn invalid_baseline(wire: &[u8]) -> Meter {
    let mut operation = decode_driver(wire, meter());
    finish_invalid(&mut operation, wire.len() * 128 + 4096);
    operation.meter.assert_units(3, 64);
    operation.meter
}

fn suspend<'a>(
    driver: &mut super::driver::Driver<
        dcbor::bounded::decode::cursor::Decoder<'a, Permit>,
        dcbor::bounded::decode::Document<'a, Permit>,
    >,
    stop: usize,
    reason: Refusal,
) {
    let mut observed = false;
    for _ in 0..stop + 4096 {
        let mut before = driver.operation().position();
        let first_call = driver.meter.calls.len();
        match driver.step().unwrap() {
            Step::Progress => assert!(driver.output.is_none()),
            Step::Refused(actual) => {
                assert_eq!(actual, reason);
                assert_eq!(driver.meter.refused, Some((stop, reason)));
                // A turn can acquire replacement storage or move its last
                // element before refusing the following append. Account for
                // exactly those successful admissions, never the refused one.
                use dcbor::bounded::decode::cursor::Phase;
                let relocation = match before.phase {
                    Phase::Entry => Some(&mut before.arena_relocated),
                    Phase::Frame => Some(&mut before.stack_relocated),
                    _ => None,
                };
                if let Some(position) = relocation {
                    for call in &driver.meter.calls[first_call..stop] {
                        match call {
                            Call::Allocate(_) => *position = 0,
                            Call::Work { values: 1, bytes } if *bytes > 0 => *position += 1,
                            other => panic!("unexpected work before relocation refusal: {other:?}"),
                        }
                    }
                }
                assert_eq!(driver.operation().position(), before);
                observed = true;
                break;
            }
            other => panic!("target stop {stop} not reached at {before:?}: {other:?}"),
        }
    }
    assert!(
        observed,
        "target stop {stop} not observed at {:?}",
        driver.operation().position()
    );
    driver.meter.assert_units(3, 64);
}

// Literal invalid encodings, independent of either production encoder.
const INVALID: &[&[u8]] = &[
    &[0x19, 0x01],                   // incomplete head
    &[0x43, 0x01, 0x02],             // incomplete payload
    &[0x82, 0x01],                   // incomplete container
    &[0x18, 0x00],                   // nonminimal integer
    &[0x62, 0xc0, 0x80],             // overlong UTF-8
    &[0x63, 0x65, 0xcc, 0x81],       // non-NFC text
    &[0xa2, 0x01, 0x00, 0x00, 0x00], // reversed keys
    &[0xa2, 0x00, 0x01, 0x00, 0x02], // duplicate keys
    &[0x81, 0x01, 0x00],             // trailing item
    &[0x9f, 0x01, 0xff],             // indefinite container
];

#[test]
fn malformed_inputs_cancel_cleanly_at_every_observed_refusal() {
    every_case(INVALID.len(), |fixture| {
        let wire = INVALID[fixture];
        let baseline = invalid_baseline(wire);
        assert!(baseline.refused.is_none());
        assert_eq!(baseline.pool.live(), 0);
        every_case(baseline.calls.len() * 3, |schedule| {
            let stop = schedule / 3;
            let reason = [Refusal::Work, Refusal::Capacity, Refusal::Deadline][schedule % 3];
            let mut m = meter();
            m.fail_at = Some((stop, reason));
            let pool = m.pool.clone();
            let mut driver = decode_driver(wire, m);
            suspend(&mut driver, stop, reason);
            assert_eq!(driver.meter.refused, Some((stop, reason)));
            assert_eq!(driver.meter.calls, baseline.calls[..=stop]);
            assert!(driver.output.is_none());
            drop(driver);
            assert_eq!(pool.live(), 0);
        });
    });
}

// Prior art: tokio-util/tests/length_delimited.rs,
// read_incomplete_head_multi and read_incomplete_payload: suspension must not
// turn an incomplete item into success or consume its terminal error.
#[test]
fn malformed_inputs_resume_to_invalid_without_publishing_at_every_boundary() {
    every_case(INVALID.len(), |fixture| {
        let wire = INVALID[fixture];
        let baseline = invalid_baseline(wire);
        every_case(baseline.calls.len(), |stop| {
            let mut m = meter();
            m.fail_at = Some((stop, Refusal::Work));
            let pool = m.pool.clone();
            let mut driver = decode_driver(wire, m);
            suspend(&mut driver, stop, Refusal::Work);
            assert_eq!(driver.meter.refused, Some((stop, Refusal::Work)));
            driver.meter.fail_at = None;
            finish_invalid(&mut driver, wire.len() * 128 + 4096);
            let mut trace = baseline.calls.clone();
            trace.insert(stop, baseline.calls[stop]);
            assert_eq!(
                driver.meter.calls, trace,
                "invalid-input recovery replayed completed work"
            );
            assert_eq!(
                (driver.meter.values, driver.meter.bytes),
                (baseline.values, baseline.bytes)
            );
            assert_eq!(driver.invocations, 1);
            assert_eq!(driver.step().unwrap(), Step::Finished);
            drop(driver);
            assert_eq!(pool.live(), 0);
        });
    });
}

#[test]
fn every_truncation_of_nested_literal_input_resumes_to_error_without_replay() {
    let complete = [
        0x82, 0x82, 0x01, 0x62, 0xc3, 0xa9, 0xa1, 0x00, 0x43, 1, 2, 3,
    ];
    every_case(complete.len(), |end| {
        let wire = &complete[..end];
        let baseline = invalid_baseline(wire);
        assert!(baseline.refused.is_none());
        every_case(baseline.calls.len(), |stop| {
            let mut m = meter();
            m.fail_at = Some((stop, Refusal::Work));
            let pool = m.pool.clone();
            let mut operation = decode_driver(wire, m);
            suspend(&mut operation, stop, Refusal::Work);
            assert_eq!(operation.meter.refused, Some((stop, Refusal::Work)));
            assert!(operation.output.is_none());
            operation.meter.fail_at = None;
            finish_invalid(&mut operation, complete.len() * 128 + 4096);
            let mut trace = baseline.calls.clone();
            trace.insert(stop, baseline.calls[stop]);
            assert_eq!(operation.meter.calls, trace);
            assert_eq!(
                (operation.meter.values, operation.meter.bytes),
                (baseline.values, baseline.bytes)
            );
            drop(operation);
            assert_eq!(pool.live(), 0);
        });
    });
}
