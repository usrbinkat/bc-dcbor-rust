use super::bindings::text_driver;
use super::driver::{Step, finish};
use super::harness::*;

#[test]
fn actual_normalizer_progress_and_emitted_prefix_survive_every_cancellation_point() {
    let source = "a\u{300}\u{305}\u{315}\u{5ae}b";
    let expected = [0x69, 0xc3, 0xa0, 0xd6, 0xae, 0xcc, 0x85, 0xcc, 0x95, b'b'];
    let mut baseline = text_driver(source, meter());
    let mut states = Vec::new();
    let mut completed = false;
    for _ in 0..4096 {
        let before = baseline.operation().position();
        match baseline.step().unwrap() {
            Step::Progress => {
                assert_ne!(
                    baseline.operation().position(),
                    before,
                    "charges alone must not count as useful execution progress"
                );
                assert!(expected.starts_with(baseline.operation().emitted_prefix()));
                states.push((baseline.operation().position(), baseline.meter.pool.live()));
            }
            Step::Complete => {
                completed = true;
                break;
            }
            other => panic!("unexpected normalization outcome {other:?}"),
        }
    }
    assert!(completed);
    assert_eq!(baseline.output.as_ref().unwrap().as_ref(), expected);
    baseline.meter.assert_units(3, 64);
    every_case(states.len(), |stop| {
        let m = meter();
        let pool = m.pool.clone();
        let mut operation = text_driver(source, m);
        for _ in 0..=stop {
            assert_eq!(operation.step(), Ok(Step::Progress));
        }
        assert_eq!(operation.operation().position(), states[stop].0);
        assert_eq!(pool.live(), states[stop].1);
        let prefix = operation.operation().emitted_prefix().to_vec();
        assert!(expected.starts_with(&prefix));
        let call = operation.meter.calls.len();
        operation.meter.fail_at = Some((call, Refusal::Work));
        assert_eq!(operation.step(), Ok(Step::Refused(Refusal::Work)));
        assert_eq!(operation.meter.refused, Some((call, Refusal::Work)));
        assert_eq!(operation.operation().position(), states[stop].0);
        assert_eq!(operation.operation().emitted_prefix(), prefix);
        assert!(operation.output.is_none());
        drop(operation);
        assert_eq!(pool.live(), 0);
    });
}

#[test]
fn text_resume_retains_actual_offsets_and_owned_output_after_decoder_drop() {
    let source = "\u{1e0b}\u{323}";
    let expected = [0x65, 0xe1, 0xb8, 0x8d, 0xcc, 0x87];
    let m = meter();
    let pool = m.pool.clone();
    let mut operation = text_driver(source, m);
    assert_eq!(operation.step(), Ok(Step::Progress));
    let before = operation.operation().position();
    assert_eq!(before.source_bytes, 3);
    let call = operation.meter.calls.len();
    operation.meter.fail_at = Some((call, Refusal::Capacity));
    assert_eq!(operation.step(), Ok(Step::Refused(Refusal::Capacity)));
    assert_eq!(operation.meter.refused, Some((call, Refusal::Capacity)));
    assert_eq!(operation.operation().position(), before);
    operation.meter.fail_at = None;
    finish(&mut operation, 4096);
    assert_eq!(operation.output.as_ref().unwrap().as_ref(), expected);
    assert_eq!(operation.operation().position().source_bytes, source.len());
    let output = operation.output.take().unwrap();
    drop(operation);
    assert_eq!(pool.live(), expected.len() as u64);
    assert_eq!(output.as_ref(), expected);
    drop(output);
    assert_eq!(pool.live(), 0);
}
