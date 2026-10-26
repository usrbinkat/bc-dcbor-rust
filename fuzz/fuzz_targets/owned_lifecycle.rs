#![no_main]
use dcbor::bounded::decode::Options;
use dcbor::bounded::LimitRefusal;
use dcbor_test_support::classes::Classes;
use dcbor_test_support::{heap, pipeline};
use libfuzzer_sys::fuzz_target;

// Physical requests are observed, and failed on schedule, only through this
// allocator; outside an observation it forwards to the system allocator.
#[global_allocator]
static HEAP: heap::Heap = heap::Heap;

/// Inputs the owned pipeline observes: every live allocation of a plan fits
/// the observer's fixed bookkeeping.
const PIPELINE_INPUT: usize = 1024;

fuzz_target!(|data: &[u8]| {
    if data.len() < 4 {
        return;
    }
    let schedule = u16::from_le_bytes([data[0], data[1]]) as usize;
    let wire = &data[4..];
    let options = if data[2] & 1 == 0 {
        Options::normalizing(16)
    } else {
        Options::quick_only(16)
    };
    use pipeline::{Refusal, Schedule, Stop};
    // The owned decode of a custom input under one schedule, with the value
    // it published.
    let decoded = |schedule: &Schedule| {
        let mut value = None;
        let report =
            pipeline::decode::<String>(wire, options, schedule, &Classes::none(), |published| {
                value = Some(published.clone())
            });
        (report, value)
    };
    let (baseline, value) = decoded(&Schedule::BASELINE);
    if data[2] & 1 == 0 {
        let oracle = dcbor::CBOR::try_from_data(wire)
            .ok()
            .and_then(|value| String::try_from(value).ok());
        assert_eq!(value, oracle);
    }
    let refusal = schedule % baseline.attempts.max(1);
    let (resumed, resumed_value) = decoded(&Schedule {
        refusal: Refusal::At(refusal),
        ..Schedule::BASELINE
    });
    assert_eq!(resumed.refused, 1);
    assert_eq!(resumed_value, value);
    assert_eq!(resumed.invalid, baseline.invalid);
    assert_eq!(resumed.failed, baseline.failed);
    resumed.accounting.resumed(
        &baseline.accounting,
        refusal,
        LimitRefusal::Scheduled(refusal),
    );
    if !baseline.boundaries.is_empty() {
        let boundary = &baseline.boundaries[schedule % baseline.boundaries.len()];
        let (cancelled, cancelled_value) = decoded(&Schedule {
            stop: Some((boundary.phase, boundary.turn, Stop::Cancel)),
            ..Schedule::BASELINE
        });
        assert!(cancelled.stopped && cancelled_value.is_none());
    }
    if wire.len() <= PIPELINE_INPUT {
        let stop = if data[3] & 1 == 0 {
            pipeline::Stop::Retire
        } else {
            pipeline::Stop::Cancel
        };
        owned_pipeline(wire, schedule, stop);
    }
});

/// The owned pipeline over `wire`: decoded text is prepared and emitted
/// owned, equal to the input, exactly when the input is canonical text. One
/// admission selected by `schedule` is refused and resumed without replay;
/// one physical request fails with exact recovery; at one observed boundary
/// the consumer retires what it holds or cancels the operation in progress,
/// as `stop` selects. libFuzzer's panic hook aborts before any unwind, so
/// consumer unwinding is qualified by the deterministic pipeline matrix.
fn owned_pipeline(wire: &[u8], schedule: usize, stop: pipeline::Stop) {
    use pipeline::{Refusal, Schedule};
    // One schedule per kind of fault, selected by the input: no stop is
    // grouped with another, so no boundary is classed.
    let classes = &Classes::none();
    let baseline = pipeline::encode::<String>(wire, &Schedule::BASELINE, classes);
    let canonical = dcbor::CBOR::try_from_data(wire)
        .ok()
        .and_then(|value| String::try_from(value).ok())
        .is_some();
    assert_eq!(baseline.complete, canonical);
    assert_eq!(baseline.invalid, !canonical);
    let refusal = schedule % baseline.attempts.max(1);
    let resumed = pipeline::encode::<String>(
        wire,
        &Schedule {
            refusal: Refusal::At(refusal),
            ..Schedule::BASELINE
        },
        classes,
    );
    assert_eq!(resumed.refused, 1);
    assert_eq!(resumed.complete, baseline.complete);
    assert_eq!(resumed.invalid, baseline.invalid);
    resumed.accounting.resumed(
        &baseline.accounting,
        refusal,
        LimitRefusal::Scheduled(refusal),
    );
    if baseline.physical > 0 {
        let physical = schedule % baseline.physical;
        let failed = pipeline::encode::<String>(
            wire,
            &Schedule {
                physical: Some(physical),
                ..Schedule::BASELINE
            },
            classes,
        );
        assert_eq!(failed.denied, 1, "unobserved physical failure {physical}");
        assert!(failed.failed, "physical failure {physical} misclassified");
        assert!(!failed.complete);
    }
    let boundary = &baseline.boundaries[schedule % baseline.boundaries.len()];
    let (phase, turn) = (boundary.phase, boundary.turn);
    let stopped = pipeline::encode::<String>(
        wire,
        &Schedule {
            stop: Some((phase, turn, stop)),
            ..Schedule::BASELINE
        },
        classes,
    );
    assert!(
        stopped.stopped,
        "{stop:?} at {phase:?} {turn} was not reached"
    );
    assert!(
        !stopped.complete,
        "published after {stop:?} at {phase:?} {turn}"
    );
}
