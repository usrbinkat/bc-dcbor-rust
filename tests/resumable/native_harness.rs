//! The suite's policy, its fixture runner, and its preparation drivers. The
//! preparation and physical matrices are the support crate's single-operation
//! matrices ([`super::support::refusal_matrix`],
//! [`super::support::physical_matrix`]) over a preparation run; they are
//! compiled exactly where a registered group calls them: the map and schema
//! groups, under `derive`, `hashbrown` or the standard library's collections.
#[cfg(any(feature = "derive", feature = "hashbrown"))]
use super::heap::Observation;
#[cfg(any(feature = "derive", feature = "hashbrown"))]
use super::support::{
    Fault, allowed, drive_faulted, drive_faulted_observed, exhausted, physical_matrix,
    refusal_matrix, refuse, rigor::rigor,
};
use super::support::{drive_within, prepare_turns, shape};
#[cfg(any(feature = "derive", feature = "hashbrown"))]
use dcbor::bounded::BoundedError;
use dcbor::bounded::encoding::{Preparation, Prepared, Schema};
pub use dcbor::bounded::{Call, LimitRefusal, Limits, Reservation, TURN};

#[cfg(any(
    feature = "derive",
    feature = "hashbrown",
    feature = "custom-std-collections"
))]
pub use super::support::emit_turns;
pub use super::support::{
    decode_turns, normalize_turns, string_turns, text_emit_turns, typed_turns,
};

/// The resumable suite's policy: a 32 MiB pool, logged and strict calls, and
/// admitted allocations reported to the heap observer.
pub fn meter() -> Limits {
    meter_with(32 * 1024 * 1024)
}

/// The suite policy over `capacity` live bytes.
pub fn meter_with(capacity: u64) -> Limits {
    super::support::observed_with_capacity(capacity)
}

/// Run every one of `count` fixtures or stress repetitions, never a
/// selection of them, even while some fail: catching an assertion does not
/// pass the test, and all failures are reported at the end, so the first
/// failing fixture cannot hide later ones. Fault schedules are not fixtures:
/// they run through the support crate's matrices.
pub fn every_fixture(count: usize, mut case: impl FnMut(usize)) {
    assert!(count > 0, "no fixture");
    let mut failures = Vec::new();
    for index in 0..count {
        if let Err(error) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| case(index))) {
            let message = error
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| error.downcast_ref::<&str>().map(|s| (*s).to_owned()))
                .unwrap_or_else(|| "non-string panic".to_owned());
            failures.push((index, message));
        }
    }
    assert!(
        failures.is_empty(),
        "{} of {count} fixtures failed: {failures:#?}",
        failures.len()
    );
}

/// Emit `plan` into a guarded destination of `expected`'s length within an
/// input-derived bound of turns. Requires the literal bytes, no write outside
/// the destination, no allocation request, and a finished writer that admits
/// nothing further.
#[cfg(any(
    feature = "derive",
    feature = "hashbrown",
    feature = "custom-std-collections"
))]
pub fn emit(plan: &Prepared<Reservation>, expected: &[u8], m: &mut Limits) {
    assert_eq!(plan.len(), expected.len());
    let mut bytes = vec![0xee; expected.len() + 2];
    let requests = m.requests();
    {
        let mut writer = plan.writer(&mut bytes[1..=expected.len()]);
        drive_within(m, &mut writer, emit_turns(expected.len())).expect("emission failed");
        assert_eq!(writer.emitted_prefix(), expected);
    }
    assert_eq!(
        (bytes[0], bytes[expected.len() + 1]),
        (0xee, 0xee),
        "emission wrote outside its destination"
    );
    assert_eq!(m.requests(), requests, "emission requested allocation");
}

/// `source` prepared under fresh checked turns within its shape's bound,
/// with the policy holding its reservations.
pub fn prepared(source: &dyn Schema) -> (Prepared<Reservation>, Limits) {
    let mut m = meter();
    let plan = drive_within(
        &mut m,
        &mut Preparation::new(source),
        prepare_turns(shape(source)),
    )
    .expect("preparation failed");
    (plan, m)
}

/// What preparing a source must reach: its literal encoding, or the terminal
/// rejection of an invalid source.
#[cfg(any(feature = "derive", feature = "hashbrown"))]
pub type Expected<'e> = Result<&'e [u8], BoundedError<LimitRefusal>>;

/// Prepare `source` under fresh checked turns within its shape's bound,
/// injecting `fault`: a refused step is resumed in the next turn, or, when
/// the fault cancels, the preparation is dropped at its refusal. An expected
/// encoding is emitted under its own policy; an expected rejection ends the
/// preparation, which then admits nothing. Every reservation is released.
/// Returns the calls the preparation attempted.
#[cfg(any(feature = "derive", feature = "hashbrown"))]
pub fn prepare_run(
    source: &dyn Schema,
    expected: &Expected<'_>,
    fault: Fault,
    bound: dcbor::bounded::encoding::Shape,
) -> super::support::RefusalRun {
    let mut m = meter();
    refuse(&mut m, fault.refusal);
    let mut operation = Preparation::new(source);
    let turns = allowed(&m, prepare_turns(bound));
    let output = match drive_faulted(&mut m, &mut operation, turns, fault.cancel) {
        Ok(output) => {
            assert!(
                output.is_none() || expected.is_ok(),
                "a rejected source was published"
            );
            output
        }
        Err(error) => {
            assert_eq!(
                expected.as_ref().err(),
                Some(&error),
                "unexpected rejection at {:?}",
                operation.position()
            );
            exhausted(&mut m, &mut operation);
            None
        }
    };
    drop(operation);
    if let Some(plan) = output {
        assert!(m.live_bytes() > 0);
        let bytes = expected
            .as_ref()
            .copied()
            .expect("a published plan's source was expected to publish");
        emit(&plan, bytes, &mut meter());
        drop(plan);
    }
    assert_eq!(m.live_bytes(), 0);
    super::support::RefusalRun::of(&m)
}

/// The fault matrix of preparing `source` ([`refusal_matrix`]): every
/// refusal resumed without replay, and a cancellation at every call, which
/// ends the trace there. Named by the source shape and declared outcome;
/// libtest supplies the surrounding semantic test identity.
#[cfg(any(feature = "derive", feature = "hashbrown"))]
pub fn prepare_matrix(source: &dyn Schema, expected: Expected<'_>) {
    prepare_matrix_bounded(source, expected, shape(source));
}

/// A fixture-supplied structural upper bound for sources rejected by the
/// shape walk itself. The actual preparation must still reach the exact
/// declared error under every shared refusal and cancellation schedule.
#[cfg(any(feature = "derive", feature = "hashbrown"))]
pub fn prepare_matrix_bounded(
    source: &dyn Schema,
    expected: Expected<'_>,
    bound: dcbor::bounded::encoding::Shape,
) {
    let name = format!("prepare {bound:?}, expected {expected:?}");
    refusal_matrix(&name, rigor(), |fault| {
        prepare_run(source, &expected, fault, bound)
    });
}

/// Prepare `source` under the heap observer, failing physical request
/// `failure`. Observed storage stays within reservations, every request was
/// admitted, and failure or completion releases every byte and reservation.
/// Returns the physical requests made.
#[cfg(any(feature = "derive", feature = "hashbrown"))]
pub fn prepare_physically(source: &dyn Schema, failure: Option<usize>) -> usize {
    let turns = prepare_turns(shape(source));
    let mut m = meter();
    let observation = Observation::begin(failure);
    let mut operation = Preparation::new(source);
    let result = drive_faulted_observed(&mut m, &mut operation, turns, false, |m, _, _| {
        assert!(observation.snapshot().live <= m.live_bytes() as usize)
    });
    let (output, failed) = match result {
        Ok(Some(plan)) => (Some(plan), false),
        Err(BoundedError::Allocation { .. }) => {
            exhausted(&mut m, &mut operation);
            (None, true)
        }
        Ok(None) => unreachable!("physical failures never request cancellation"),
        Err(error) => panic!("unexpected allocation matrix outcome {error:?}"),
    };
    observation.stop();
    assert!(failed || output.is_some());
    assert_eq!(failed, failure.is_some());
    let stats = observation.snapshot();
    assert_eq!(stats.denied, usize::from(failure.is_some()));
    assert_eq!(stats.unadmitted, 0);
    assert!(!stats.overflow);
    assert!(stats.peak <= m.peak_bytes() as usize);
    drop(operation);
    if output.is_some() {
        assert!(m.live_bytes() > 0);
    }
    drop(output);
    assert_eq!(m.live_bytes(), 0);
    assert_eq!(observation.snapshot().live, 0);
    stats.calls
}

/// Every physical allocation of preparing `source`, failed in a run of its
/// own ([`physical_matrix`]). Named by the source shape within its test.
#[cfg(any(feature = "derive", feature = "hashbrown"))]
pub fn prepare_physical_matrix(source: &dyn Schema) {
    let name = format!("prepare {:?}", shape(source));
    physical_matrix(&name, |failure| prepare_physically(source, failure));
}

pub fn text_wire(text: &str) -> Vec<u8> {
    let n = text.len();
    let mut wire = match n {
        0..24 => vec![0x60 | n as u8],
        24..256 => vec![0x78, n as u8],
        256..65536 => vec![0x79, (n >> 8) as u8, n as u8],
        _ => {
            let mut v = vec![0x7a];
            v.extend(u32::try_from(n).unwrap().to_be_bytes());
            v
        }
    };
    wire.extend(text.as_bytes());
    wire
}
