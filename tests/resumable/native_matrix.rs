use super::bindings::decode_driver;
use super::driver::{Step, finish, finish_invalid};
use super::harness::*;
use dcbor::bounded::decode::{
    Kind,
    cursor::{Phase, Position},
};

fn map_wire() -> Vec<u8> {
    // Byte-string keys distinguish comparison admission from text validation.
    let mut wire = vec![0xa2];
    for last in *b"ab" {
        wire.extend_from_slice(&[0x59, 0x01, 0x00]);
        wire.extend(std::iter::repeat_n(b'a', 255));
        wire.push(last);
        wire.push(0x01);
    }
    wire
}

fn script(wire: &[u8], select: impl Fn(Position) -> bool) {
    let mut reference = decode_driver(wire, meter());
    let mut selected = None;
    let mut completed = false;
    for _ in 0..wire.len() * 128 + 4096 {
        let position = reference.operation().position();
        if selected.is_none() && select(position) {
            selected = Some((reference.meter.calls.len(), position));
        }
        match reference.step().unwrap() {
            Step::Progress => {}
            Step::Complete => {
                completed = true;
                break;
            }
            other => panic!("reference at {position:?}: {other:?}"),
        }
    }
    assert!(completed);
    let (stop, target) = selected.expect("requested execution boundary was not reached");
    assert_eq!(reference.output.as_ref().unwrap().root().encoded(), wire);
    drop(reference.output.take());
    let baseline = reference.meter;
    assert!(stop < baseline.calls.len());
    let mut m = meter();
    m.fail_at = Some((stop, Refusal::Work));
    let pool = m.pool.clone();
    let mut driver = decode_driver(wire, m);
    let mut observed = false;
    for _ in 0..wire.len() * 128 + 4096 {
        match driver.step().unwrap() {
            Step::Progress => assert!(driver.output.is_none()),
            Step::Refused(Refusal::Work) => {
                observed = true;
                break;
            }
            other => panic!("target {target:?}: {other:?}"),
        }
    }
    assert!(observed);
    assert_eq!(driver.operation().position(), target);
    assert_eq!(driver.meter.refused, Some((stop, Refusal::Work)));
    assert_eq!(driver.meter.calls, baseline.calls[..=stop]);
    assert!(driver.output.is_none());
    // Preserve the admitted prefix as the independent no-replay oracle.
    let prefix = driver.meter.calls[..stop].to_vec();
    let paid = (driver.meter.values, driver.meter.bytes);
    driver.meter.fail_at = None;
    finish(&mut driver, wire.len() * 128 + 4096);
    assert_eq!(driver.invocations, 1);
    assert_eq!(&driver.meter.calls[..stop], prefix);
    assert!(driver.meter.values >= paid.0 && driver.meter.bytes >= paid.1);
    let output = driver.output.take().unwrap();
    assert_eq!(output.root().encoded(), wire);
    // Only the failed callback may be retried. Completed callbacks must not
    // appear again before the remaining uninterrupted reference sequence.
    let mut expected_trace = baseline.calls.clone();
    expected_trace.insert(stop, baseline.calls[stop]);
    assert_eq!(
        driver.meter.calls, expected_trace,
        "completed work replayed"
    );
    assert_eq!(
        (driver.meter.values, driver.meter.bytes),
        (baseline.values, baseline.bytes)
    );
    driver.meter.assert_units(3, 64);
    assert_eq!(driver.step().unwrap(), Step::Finished);
    drop(driver);
    assert!(pool.live() > 0, "document must retain its arena");
    assert_eq!(output.root().encoded(), wire);
    drop(output);
    assert_eq!(pool.live(), 0);
}

#[test]
fn before_header_has_no_consumed_work_and_same_cursor_completes() {
    script(&[0x81, 0x18, 0x18], |p| {
        p.phase == Phase::Header && p.header_bytes == 0 && p.input == 0
    });
}

#[test]
fn after_header_retains_validation_and_same_cursor_completes() {
    script(&[0x43, b'a', b'b', b'c'], |p| {
        p.phase == Phase::Interpret && p.header_bytes == 1 && p.input == 1
    });
}

#[test]
fn second_payload_preserves_previous_child_and_same_cursor_completes() {
    script(
        &[0x82, 0x63, b'a', b'b', b'c', 0x63, b'd', b'e', b'f'],
        |p| p.phase == Phase::Utf8 && p.completed_children == 1 && p.payload_validated == 1,
    );
}

#[test]
fn key_comparison_refusal_resumes_without_revalidating_prior_keys() {
    script(&map_wire(), |p| {
        p.phase == Phase::Compare && p.compared_bytes == 64
    });
}

#[test]
fn container_completion_refusal_does_not_complete_children_twice() {
    script(&[0x82, 0x01, 0x02], |p| {
        p.phase == Phase::Attach && p.completed_children == 1
    });
}

#[test]
fn key_comparison_quantum_is_checked_separately_from_payload_scans() {
    let wire = map_wire();
    let mut operation = decode_driver(&wire, meter());
    finish(&mut operation, wire.len() * 128 + 4096);
    let doc = operation.output.take().unwrap();
    let m = operation.meter;
    assert_eq!(doc.root().kind(), Kind::Map(2));
    assert_eq!(doc.root().encoded(), wire);
    // Byte-string validation charges zero values. Comparisons charge visits.
    let oversized: Vec<_> = m
        .calls
        .iter()
        .filter(|c| matches!(c, Call::Work { values, bytes } if *values > 0 && *bytes > 64))
        .collect();
    drop(doc);
    assert_eq!(m.pool.live(), 0);
    assert!(oversized.is_empty(), "unbounded comparison: {oversized:?}");
}

#[test]
fn arena_growth_quantum_is_checked_without_text_or_payload_processing() {
    let mut wire = vec![0x99, 0x10, 0x00];
    wire.extend(std::iter::repeat_n(0x01, 4096));
    let mut operation = decode_driver(&wire, meter());
    finish(&mut operation, wire.len() * 128 + 4096);
    let doc = operation.output.take().unwrap();
    let m = operation.meter;
    assert_eq!(doc.node_count(), 4097);
    assert!(
        doc.root()
            .children()
            .all(|node| node.kind() == Kind::Unsigned(1))
    );
    let calls = m.calls.clone();
    drop(doc);
    assert_eq!(m.pool.live(), 0);
    assert!(
        calls
            .iter()
            .all(|c| !matches!(c, Call::Work { bytes, .. } if *bytes > 64)),
        "growth relocation exceeds quantum: {calls:?}"
    );
}

#[test]
fn late_invalid_trailing_item_is_never_published_after_a_refusal() {
    let wire = [0x82, 0x01, 0x02, 0x00];
    let mut m = meter();
    m.fail_at = Some((0, Refusal::Work));
    let pool = m.pool.clone();
    let mut driver = decode_driver(&wire, m);
    assert_eq!(driver.step().unwrap(), Step::Refused(Refusal::Work));
    assert_eq!(driver.meter.refused, Some((0, Refusal::Work)));
    assert!(driver.output.is_none());
    driver.meter.fail_at = None;
    finish_invalid(&mut driver, wire.len() * 128 + 4096);
    assert!(driver.output.is_none());
    assert_eq!(driver.invocations, 1);
    assert_eq!(driver.step().unwrap(), Step::Finished);
    drop(driver);
    assert_eq!(pool.live(), 0);
}
