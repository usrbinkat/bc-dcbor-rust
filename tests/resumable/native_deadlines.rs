use super::bindings::decode_driver;
use super::driver::{Step, finish};
use super::harness::*;

#[test]
fn expired_before_first_admission_executes_no_work_and_allocates_nothing() {
    let wire = [0x81, 0x01];
    let mut m = meter();
    m.deadline = Some(0);
    let pool = m.pool.clone();
    let mut driver = decode_driver(&wire, m);
    assert_eq!(driver.step().unwrap(), Step::Refused(Refusal::Deadline));
    assert_eq!(driver.meter.refused, Some((0, Refusal::Deadline)));
    assert_eq!((driver.meter.values, driver.meter.bytes), (0, 0));
    assert!(driver.output.is_none());
    assert_eq!(pool.live(), 0);
    drop(driver);
    assert_eq!(pool.live(), 0);
}

#[test]
fn expiration_between_admissions_preserves_paid_work_and_can_resume() {
    let wire = [0x82, 0x01, 0x02];
    let mut reference = decode_driver(&wire, meter());
    finish(&mut reference, 4096);
    drop(reference.output.take());
    let baseline = reference.meter;
    every_case(baseline.calls.len(), |stop| {
        let mut m = meter();
        m.deadline = Some(u64::try_from(stop).unwrap());
        let pool = m.pool.clone();
        let mut driver = decode_driver(&wire, m);
        let mut suspended = false;
        for _ in 0..4096 {
            let before = driver.operation().position();
            match driver.step().unwrap() {
                Step::Progress => assert!(driver.output.is_none()),
                Step::Refused(Refusal::Deadline) => {
                    assert_eq!(driver.operation().position(), before);
                    suspended = true;
                    break;
                }
                other => panic!("deadline {stop} not observed at {before:?}: {other:?}"),
            }
        }
        assert!(suspended);
        assert_eq!(driver.meter.refused, Some((stop, Refusal::Deadline)));
        assert_eq!(driver.meter.clock, u64::try_from(stop).unwrap() + 1);
        assert_eq!(driver.meter.calls, baseline.calls[..=stop]);
        let paid = (driver.meter.values, driver.meter.bytes);
        assert!(driver.output.is_none());
        driver.meter.deadline = None;
        finish(&mut driver, 4096);
        assert_eq!(driver.invocations, 1);
        let mut trace = baseline.calls.clone();
        trace.insert(stop, baseline.calls[stop]);
        assert_eq!(
            driver.meter.calls, trace,
            "deadline recovery replayed paid work"
        );
        assert!(driver.meter.values >= paid.0 && driver.meter.bytes >= paid.1);
        assert_eq!(
            (driver.meter.values, driver.meter.bytes),
            (baseline.values, baseline.bytes)
        );
        driver.meter.assert_units(3, 64);
        assert_eq!(driver.output.as_ref().unwrap().root().encoded(), wire);
        let output = driver.output.take().unwrap();
        drop(driver);
        assert!(pool.live() > 0);
        drop(output);
        assert_eq!(pool.live(), 0);
    });
}
