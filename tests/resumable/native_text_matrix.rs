use super::bindings::text_encoder;
use super::harness::*;
use super::support::rigor::rigor;
use super::support::{
    Fault, allowed, drive_faulted, drive_within, fail_within, finish_within, pipeline::Refusal,
    reason_matrix, refusal_matrix, refuse, resume_within,
};
use dcbor::bounded::WriteWork;
use dcbor::bounded::decode::{DecodeError, Kind, Options, cursor::Decoder, decode};

/// Encode `source` under `fault`: resumed to the literal `expected` bytes,
/// which the encoder's output holds beyond the encoder's own life, or
/// cancelled at its refusal, releasing everything. Returns the calls
/// attempted.
fn encode_run(source: &str, expected: &[u8], fault: Fault) -> super::support::RefusalRun {
    let mut m = meter();
    refuse(&mut m, fault.refusal);
    let pool = m.share();
    let mut operation = text_encoder(source);
    let turns = allowed(&m, normalize_turns(source));
    let output =
        drive_faulted(&mut m, &mut operation, turns, fault.cancel).expect("a text normalizes");
    drop(operation);
    if let Some(output) = output {
        assert_eq!(output.as_ref(), expected);
        m.assert_units(TURN);
        assert!(pool.live_bytes() >= expected.len() as u64);
        assert_eq!(output.as_ref(), expected);
        drop(output);
    }
    assert_eq!(pool.live_bytes(), 0);
    super::support::RefusalRun::of(&m)
}

fn fixture(source: &str, expected: &[u8]) {
    let canonical = std::str::from_utf8(&expected[1..]).unwrap();
    // Every callback refused, resumed and cancelled.
    let baseline = refusal_matrix(
        &format!("text encoder of {source:?}"),
        rigor(),
        |fault: Fault| encode_run(source, expected, fault),
    );
    // A storage refusal is a refusal like any other to the encoder: the
    // fast layer refuses for storage at the encoding's last call, the
    // exhaustive layer at every call, each resumed with only that call
    // repeated.
    reason_matrix(
        &format!("text encoder of {source:?}: storage refusals"),
        rigor(),
        baseline.calls(),
        &[LimitRefusal::Storage],
        |stop, reason| {
            encode_run(
                source,
                expected,
                Fault {
                    refusal: Refusal::For(stop, reason),
                    cancel: false,
                },
            )
            .resumed(&baseline, stop, reason);
        },
    );
    // Independent decoder oracles.
    let mut m = meter();
    let parsed = decode(expected, 8, &mut m).unwrap();
    assert_eq!(parsed.root().kind(), Kind::Text(canonical));
    drop(parsed);
    assert_eq!(m.live_bytes(), 0);
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

/// A run whose classes differ in both four-bit digits, 230 (0xE6), 220
/// (0xDC), 202 (0xCA), 1 (0x01), 216 (0xD8) and 230 again: the low pass
/// alone leaves it out of order, both passes order it, and the two class-230
/// marks keep their source order. U+0301 then composes with the starter;
/// U+0300, after it, does not. Refused at every admission, the retained
/// counter table, pass and scatter offset reproduce the same bytes and
/// replay no admitted unit.
#[test]
fn radix_ordering_over_both_class_digits_survives_every_suspension() {
    fixture(
        "a\u{301}\u{316}\u{327}\u{334}\u{31b}\u{300}b",
        &[
            0x6d, 0xc3, 0xa1, 0xcc, 0xb4, 0xcc, 0xa7, 0xcc, 0x9b, 0xcc, 0x96, 0xcc, 0x80, b'b',
        ],
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
    // One quantum before the first refusal; every later turn is one quantum.
    m.set_limit(WriteWork::new(TURN.values, TURN.bytes));
    let pool = m.share();
    let mut operation = text_encoder(&source);
    let (_, output) = resume_within(
        &mut m,
        &mut operation,
        LimitRefusal::Work,
        normalize_turns(&source),
    );
    assert_eq!(output.as_ref(), expected);
    m.assert_units(TURN);
    drop(operation);
    assert!(pool.live_bytes() >= expected.len() as u64);
    drop(output);
    assert_eq!(pool.live_bytes(), 0);
}

#[test]
fn long_valid_combining_sequence_is_accepted_and_one_late_disordered_mark_rejects_it() {
    // q composes with no mark, and every mark has the same combining class:
    // the text is NFC however long the run.
    let valid = format!("q{}", "\u{301}".repeat(100_000));
    let wire = text_wire(&valid);
    let mut m = meter();
    let mut operation = Decoder::new(&wire, Options::normalizing(8));
    // The retained parse bound includes proving the text's normalization.
    let document = drive_within(&mut m, &mut operation, decode_turns(wire.len()))
        .expect("canonical text rejected");
    assert_eq!(document.root().kind(), Kind::Text(&valid));
    m.assert_units(TURN);
    drop(operation);
    drop(document);
    assert_eq!(m.live_bytes(), 0);
    // A class-220 mark after the class-230 run is out of canonical order; it
    // is found only after the whole run has been validated.
    let disordered = format!("{valid}\u{316}");
    let wire = text_wire(&disordered);
    let mut m = meter();
    let mut operation = Decoder::new(&wire, Options::normalizing(8));
    let error = fail_within(&mut m, &mut operation, decode_turns(wire.len()));
    assert!(matches!(error, DecodeError::Invalid(_)), "{error:?}");
    finish_within(&mut m, &mut operation, decode_turns(wire.len()));
    m.assert_units(TURN);
    drop(operation);
    assert_eq!(m.live_bytes(), 0);
}
