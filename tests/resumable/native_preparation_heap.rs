use super::harness::*;
use super::heap::Observation;
use super::support::{drive_within, finish_within, physical_matrix};
use dcbor::bounded::BoundedError;
use dcbor::bounded::text_cursor::pipeline::TextPreparation;

#[test]
fn preparation_physical_failures_preserve_independent_plan_ownership() {
    let source = "q\u{301}\u{316}".repeat(32);
    let bound = normalize_turns(&source);
    let run = |fail_at| {
        // The policy's call log is reserved before observation starts.
        let mut meter = meter();
        let observer = Observation::begin(fail_at);
        let mut preparation = TextPreparation::new(&source);
        let (output, failed) = match drive_within(&mut meter, &mut preparation, bound) {
            Ok(plan) => (Some(plan), false),
            Err(BoundedError::Allocation { .. }) => {
                // The normalizer's own cleanup releases its scratch,
                // observed, before the preparation is dropped.
                finish_within(&mut meter, &mut preparation, bound);
                assert_eq!(meter.live_bytes(), 0, "failed preparation retained storage");
                (None, true)
            }
            Err(error) => panic!("unexpected preparation outcome: {error:?}"),
        };
        observer.stop();
        assert!(output.is_some() || failed, "preparation did not terminate");
        let stats = observer.snapshot();
        assert_eq!(stats.denied, usize::from(fail_at.is_some()));
        assert_eq!(failed, fail_at.is_some());
        assert!(!stats.overflow);
        assert_eq!(stats.unadmitted, 0);
        assert!(stats.live <= meter.live_bytes() as usize);
        assert!(stats.peak <= meter.peak_bytes() as usize);
        drop(preparation);
        if let Some(plan) = output {
            assert!(meter.live_bytes() > 0);
            let expected = text_wire(&"q\u{316}\u{301}".repeat(32));
            let mut bytes = vec![0xee; plan.len() as usize];
            let mut emission = super::harness::meter();
            drive_within(
                &mut emission,
                &mut plan.writer(&mut bytes),
                text_emit_turns(expected.len()),
            )
            .expect("emission failed");
            assert_eq!(emission.requests(), 0, "emission requested allocation");
            assert_eq!(bytes, expected);
            drop(plan);
        }
        assert_eq!(observer.snapshot().live, 0);
        assert_eq!(meter.live_bytes(), 0);
        stats.calls
    };
    physical_matrix("text preparation physically", run);
}
