use super::bindings::{decoder, string_decoder, text_encoder};
use super::harness::*;
use super::support::{RefusalRun, allowed, drive_within, pipeline::Refusal, refuse};
use dcbor::bounded::Resumable;

/// Refuse every callback, successively, on ONE operation. At each turn only
/// the previously refused callback may succeed before the next refusal.
/// Separate one-refusal runs cannot prove this retained-state contract.
/// Returns the output.
fn successive<O: Resumable<Limits>>(
    m: &mut Limits,
    operation: &mut O,
    baseline: &Limits,
    turns: usize,
) -> O::Output
where
    O::Error: std::fmt::Debug,
{
    // Reason classification is exercised by reason_matrix; successive
    // suspension uses the authoritative one-pass schedule and replay oracle.
    refuse(m, Refusal::Each);
    let turns = allowed(m, turns);
    let output = drive_within(m, operation, turns).expect("successive refusal failed");
    RefusalRun::of(m).each(&RefusalRun::of(baseline));
    assert_eq!(m.used(), baseline.used());
    m.assert_units(TURN);
    output
}

#[test]
fn decoder_survives_successive_refusals_on_one_retained_operation() {
    let wire = [0x82, 0x01, 0x62, 0xc3, 0xa9];
    let mut baseline = meter();
    drop(drive_within(&mut baseline, &mut decoder(&wire), decode_turns(wire.len())).unwrap());
    let mut m = meter();
    let pool = m.share();
    let mut operation = decoder(&wire);
    let document = successive(&mut m, &mut operation, &baseline, decode_turns(wire.len()));
    assert_eq!(document.root().encoded(), wire);
    drop(operation);
    assert!(pool.live_bytes() > 0);
    assert_eq!(document.root().encoded(), wire);
    drop(document);
    assert_eq!(pool.live_bytes(), 0);
}

#[test]
fn typed_fields_survive_successive_refusals_with_output_ownership() {
    let wire = [0x62, 0xc3, 0xa9];
    let mut baseline = meter();
    drop(
        drive_within(
            &mut baseline,
            &mut string_decoder(&wire),
            string_turns(wire.len()),
        )
        .unwrap(),
    );
    let mut m = meter();
    let pool = m.share();
    let mut operation = string_decoder(&wire);
    let value = successive(&mut m, &mut operation, &baseline, string_turns(wire.len()));
    assert_eq!(value.value(), "\u{e9}");
    drop(operation);
    assert!(pool.live_bytes() >= 2);
    assert_eq!(value.value(), "\u{e9}");
    drop(value);
    assert_eq!(pool.live_bytes(), 0);
}

#[test]
fn normalization_and_emission_survive_successive_refusals_without_replay() {
    let source = "a\u{301}";
    let mut baseline = meter();
    drop(
        drive_within(
            &mut baseline,
            &mut text_encoder(source),
            normalize_turns(source),
        )
        .unwrap(),
    );
    let mut m = meter();
    let pool = m.share();
    let mut operation = text_encoder(source);
    let output = successive(&mut m, &mut operation, &baseline, normalize_turns(source));
    assert_eq!(output.as_ref(), &[0x62, 0xc3, 0xa1]);
    drop(operation);
    assert!(pool.live_bytes() >= 3);
    assert_eq!(output.as_ref(), &[0x62, 0xc3, 0xa1]);
    drop(output);
    assert_eq!(pool.live_bytes(), 0);
}
