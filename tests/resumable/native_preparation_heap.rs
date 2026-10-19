use super::harness::*;
use super::heap::Observation;
use dcbor::bounded::BoundedError;
use dcbor::bounded::text_cursor::pipeline::{PrepareStep, TextPreparation};

#[test]
fn preparation_physical_failures_preserve_independent_plan_ownership() {
    let source = "q\u{301}\u{316}".repeat(32);
    let run = |fail_at| {
        let mut meter = meter();
        // Test-owned trace storage is allocated before observation starts.
        meter.calls.reserve(16384);
        let observer = Observation::begin(fail_at);
        let mut preparation = TextPreparation::new(&source);
        let mut output = None;
        let mut failed = false;
        let mut complete = false;
        for _ in 0..16384 {
            let before = (meter.values, meter.bytes);
            meter.limit_values = before.0 + 3;
            meter.limit_bytes = before.1 + 64;
            let result = preparation.step(&mut meter);
            assert!(meter.values - before.0 <= 3 && meter.bytes - before.1 <= 64);
            match result {
                Ok(PrepareStep::Progress) => assert_ne!((meter.values, meter.bytes), before),
                Ok(PrepareStep::Complete(plan)) => {
                    output = Some(plan);
                    complete = true;
                    break;
                }
                Err(BoundedError::Allocation { .. }) => {
                    failed = true;
                    break;
                }
                _ => panic!("unexpected preparation outcome"),
            }
        }
        observer.stop();
        assert!(complete || failed, "preparation did not terminate");
        let stats = observer.snapshot();
        assert_eq!(stats.denied, fail_at.is_some());
        assert_eq!(failed, fail_at.is_some());
        assert!(!stats.overflow);
        assert_eq!(stats.unadmitted, 0);
        assert!(stats.live <= meter.pool.live() as usize);
        assert!(stats.peak <= meter.pool.peak() as usize);
        drop(preparation);
        if let Some(plan) = output {
            assert!(meter.pool.live() > 0);
            let expected = text_wire(&"q\u{316}\u{301}".repeat(32));
            let mut bytes = vec![0xee; plan.len() as usize];
            let mut writer = super::driver::Driver::from_operation(
                plan.writer(&mut bytes),
                super::harness::meter(),
            );
            super::driver::finish(&mut writer, expected.len() + 16);
            assert!(
                !writer
                    .meter
                    .calls
                    .iter()
                    .any(|call| matches!(call, Call::Allocate(_)))
            );
            drop(writer);
            assert_eq!(bytes, expected);
            drop(plan);
        }
        assert_eq!(observer.snapshot().live, 0);
        assert_eq!(meter.pool.live(), 0);
        stats.calls
    };
    let calls = run(None);
    assert!(calls > 0);
    every_case(calls, |index| {
        run(Some(index));
    });
}
