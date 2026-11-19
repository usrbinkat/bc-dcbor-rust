use super::bindings::{decoder, string_decoder, text_encoder};
use super::harness::*;
use super::support::{Fault, RefusalRun, Terminal, pipeline::Refusal};
use dcbor::bounded::{Custodial, Resumable, WriteWork};

/// The unobstructed run of an operation, as detached data: the shared
/// refusal oracle's view of it and the work it used.
struct Baseline {
    run: RefusalRun,
    used: WriteWork,
}

/// The shared retained scenario's unobstructed accounting, detached after
/// both the operation and its output retire.
fn baseline<O>(operation: O, turns: usize) -> Baseline
where
    O: Resumable<Limits> + Custodial<Reservation> + Terminal,
    O::Output: Custodial<Reservation>,
    O::Error: std::fmt::Debug,
{
    let mut used = WriteWork::default();
    let run = retained_case(operation, turns, Fault::NONE, |_, m| used = m.used());
    Baseline { run, used }
}

/// Refuse every callback, successively, on ONE operation. At each turn only
/// the previously refused callback may succeed before the next refusal.
/// Separate one-refusal runs cannot prove this retained-state contract.
/// Check the output after its operation retires, then compare the completed
/// run's admissions with the unobstructed recording.
fn successive<O>(
    operation: O,
    baseline: &Baseline,
    turns: usize,
    check: impl FnOnce(&mut O::Output, &Limits),
) where
    O: Resumable<Limits> + Custodial<Reservation> + Terminal,
    O::Output: Custodial<Reservation>,
    O::Error: std::fmt::Debug,
{
    // Reason classification is exercised by reason_matrix; successive
    // suspension uses the authoritative one-pass schedule and replay oracle.
    let run = retained_case(
        operation,
        turns,
        Fault {
            refusal: Refusal::Each,
            cancel: false,
        },
        |output, m| {
            assert_eq!(m.used(), baseline.used);
            check(output, m);
        },
    );
    run.each(&baseline.run);
}

#[test]
fn decoder_survives_successive_refusals_on_one_retained_operation() {
    let wire = [0x82, 0x01, 0x62, 0xc3, 0xa9];
    let baseline = baseline(decoder(&wire), decode_turns(wire.len()));
    successive(
        decoder(&wire),
        &baseline,
        decode_turns(wire.len()),
        |document, m| {
            assert!(m.live_bytes() > 0);
            assert_eq!(document.root().encoded(), wire);
        },
    );
}

#[test]
fn typed_fields_survive_successive_refusals_with_output_ownership() {
    let wire = [0x62, 0xc3, 0xa9];
    let baseline = baseline(string_decoder(&wire), string_turns(wire.len()));
    successive(
        string_decoder(&wire),
        &baseline,
        string_turns(wire.len()),
        |value, m| {
            assert!(m.live_bytes() >= 2);
            assert_eq!(value.value(), "\u{e9}");
        },
    );
}

#[test]
fn normalization_and_emission_survive_successive_refusals_without_replay() {
    let source = "a\u{301}";
    let baseline = baseline(text_encoder(source), normalize_turns(source));
    successive(
        text_encoder(source),
        &baseline,
        normalize_turns(source),
        |output, m| {
            assert!(m.live_bytes() >= 3);
            assert_eq!(output.as_ref(), &[0x62, 0xc3, 0xa1]);
        },
    );
}
