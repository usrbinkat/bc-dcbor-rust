use super::bindings::text_driver;
use super::driver::{Step, finish, resume, resume_with_limit};
use super::harness::*;
use dcbor::bounded::decode::{Kind, decode};

fn fixture(source: &str, expected: &[u8]) {
    let canonical = std::str::from_utf8(&expected[1..]).unwrap();
    let mut reference = text_driver(source, meter());
    finish(&mut reference, source.len() * source.len() * 8 + 4096);
    let encoded = reference.output.take().unwrap();
    assert_eq!(encoded.as_ref(), expected);
    drop(encoded);
    let baseline = reference.meter;
    assert_eq!(baseline.pool.live(), 0);
    // Every callback, both refusal classes, then independent decoder oracles.
    every_case(baseline.calls.len() * 2, |schedule| {
        let index = schedule / 2;
        let reason = if schedule % 2 == 0 {
            Refusal::Work
        } else {
            Refusal::Capacity
        };
        let mut m = meter();
        m.fail_at = Some((index, reason));
        let pool = m.pool.clone();
        let mut operation = text_driver(source, m);
        resume(&mut operation, reason);
        assert_eq!(operation.output.as_ref().unwrap().as_ref(), expected);
        let mut trace = baseline.calls.clone();
        trace.insert(index, baseline.calls[index]);
        assert_eq!(
            operation.meter.calls, trace,
            "completed normalization was replayed"
        );
        assert_eq!(
            (operation.meter.values, operation.meter.bytes),
            (baseline.values, baseline.bytes)
        );
        operation.meter.assert_units(3, 64);
        let output = operation.output.take().unwrap();
        assert_eq!(operation.step().unwrap(), Step::Finished);
        drop(operation);
        assert!(pool.live() >= expected.len() as u64);
        assert_eq!(output.as_ref(), expected);
        drop(output);
        assert_eq!(pool.live(), 0);
    });
    let mut m = meter();
    let parsed = decode(expected, 8, &mut m).unwrap();
    assert_eq!(parsed.root().kind(), Kind::Text(canonical));
    drop(parsed);
    assert_eq!(m.pool.live(), 0);
    if source != canonical {
        assert!(decode(&text_wire(source), 8, &mut meter()).is_err());
    }
}

#[test]
fn composition_is_correct_after_every_suspension() {
    fixture("a\u{301}", &[0x62, 0xc3, 0xa1]);
}

#[test]
fn leading_combining_mark_is_preserved_after_every_suspension() {
    fixture("\u{301}a", &[0x63, 0xcc, 0x81, b'a']);
}

#[test]
fn decomposition_and_recomposition_survive_every_suspension() {
    fixture("\u{1e0b}\u{323}", &[0x65, 0xe1, 0xb8, 0x8d, 0xcc, 0x87]);
}

#[test]
fn stable_combining_order_survives_every_suspension() {
    fixture(
        "a\u{300}\u{305}\u{315}\u{5ae}b",
        &[0x69, 0xc3, 0xa0, 0xd6, 0xae, 0xcc, 0x85, 0xcc, 0x95, b'b'],
    );
}

#[test]
fn two_part_hangul_survives_every_suspension() {
    fixture("\u{1100}\u{1162}", &[0x63, 0xea, 0xb0, 0x9c]);
}

#[test]
fn three_part_hangul_survives_every_suspension() {
    fixture("\u{1111}\u{1171}\u{11b6}", &[0x63, 0xed, 0x93, 0x9b]);
}

#[test]
fn long_combining_run_requires_retained_progress_not_whole_run_admission() {
    let source = format!("q{}", "\u{301}\u{316}".repeat(4096));
    let normal = format!("q{}{}", "\u{316}".repeat(4096), "\u{301}".repeat(4096));
    let expected = text_wire(&normal);
    let mut m = meter();
    m.limit_values = 3;
    m.limit_bytes = 64;
    let pool = m.pool.clone();
    let mut operation = text_driver(&source, m);
    // Each merge level reads and writes each mark once, with constant
    // bookkeeping per pair. Require O(n log n) total turns at the same 3/64
    // quantum; adjacent-swap insertion ordering cannot satisfy this bound.
    let marks = 8192usize;
    let turns = 8 * marks * (marks.ilog2() as usize + 1) + source.len() * 16;
    resume_with_limit(&mut operation, Refusal::Work, turns);
    assert_eq!(operation.output.as_ref().unwrap().as_ref(), expected);
    operation.meter.assert_units(3, 64);
    let output = operation.output.take().unwrap();
    drop(operation);
    assert!(pool.live() >= expected.len() as u64);
    drop(output);
    assert_eq!(pool.live(), 0);
}
