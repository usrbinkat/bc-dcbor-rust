use super::harness::*;
use super::support::{
    Fault, allowed, drive_faulted, drive_within, finish_within, refusal_matrix, refuse,
    rigor::rigor,
};
use dcbor::bounded::decode::{DecodeError, Options, cursor::Decoder};
use unicode_normalization::{IsNormalized, is_nfc_quick};

fn quick(input: &[u8]) -> Decoder<'_, Reservation> {
    Decoder::new(input, Options::quick_only(8))
}

/// For each fixture, every refusal of a QuickOnly decode resumed to the same
/// outcome, the literal document or the specific QuickOnly rejection, never
/// a silent normalization; and a cancellation at every call releasing what
/// the decode held. A rejected decode's own cleanup runs under a shared
/// policy, outside the measured trace.
#[test]
fn quick_only_policy_survives_every_refusal_without_silent_normalization() {
    let fixtures = [
        ("ASCII", true),
        ("\u{e9}", true),
        ("q\u{301}", false),
        ("e\u{301}", false),
    ];
    every_fixture(fixtures.len(), |fixture| {
        let (text, accepted) = fixtures[fixture];
        let wire = text_wire(text);
        refusal_matrix(
            &format!("QuickOnly decode of {text:?}"),
            rigor(),
            |fault: Fault| {
                let mut m = meter();
                refuse(&mut m, fault.refusal);
                let pool = m.share();
                let mut operation = quick(&wire);
                let turns = allowed(&m, decode_turns(wire.len()));
                match drive_faulted(&mut m, &mut operation, turns, fault.cancel) {
                    Ok(Some(document)) => {
                        assert!(accepted, "unproven text accepted");
                        assert_eq!(document.root().encoded(), wire);
                        m.assert_units(TURN);
                        drop(operation);
                        assert!(pool.live_bytes() > 0);
                        drop(document);
                    }
                    Ok(None) => {
                        assert!(fault.cancel, "unscheduled cancellation");
                        drop(operation);
                    }
                    Err(error) => {
                        assert!(!accepted, "proven text refused: {error:?}");
                        assert!(
                            matches!(error, DecodeError::UnprovenText),
                            "lost the specific QuickOnly rejection: {error:?}"
                        );
                        m.assert_units(TURN);
                        finish_within(&mut m.share(), &mut operation, decode_turns(wire.len()));
                        drop(operation);
                    }
                }
                assert_eq!(pool.live_bytes(), 0);
                super::support::RefusalRun::of(&m)
            },
        );
    });
}

/// Payload validation proceeds in quanta of at most 64 bytes. An ASCII prefix
/// of every length from 56 through 72 places each byte of every scalar, and
/// every boundary between a base and its marks, on each side of the first
/// quantum's end. The QuickOnly verdict must equal upstream's for the whole
/// text wherever the boundary falls.
#[test]
fn quick_check_agrees_with_upstream_wherever_a_scalar_meets_a_quantum_boundary() {
    let texts = [
        "\u{e9}",
        "\u{1f600}",
        "\u{ac1c}",
        "q\u{301}a",
        "a\u{301}",
        "\u{301}a",
        "q\u{301}\u{316}",
        "\u{1100}\u{1161}\u{11a8}",
        "\u{e9}\u{1f600}q\u{301}",
    ];
    every_fixture(texts.len(), |fixture| {
        let text = texts[fixture];
        for prefix in 56..=72 {
            let source = format!("{}{text}", "x".repeat(prefix));
            let proven = is_nfc_quick(source.chars()) == IsNormalized::Yes;
            let wire = text_wire(&source);
            let mut m = meter();
            let mut operation = quick(&wire);
            let bound = decode_turns(wire.len());
            match drive_within(&mut m, &mut operation, bound) {
                Ok(document) => {
                    assert!(proven, "unproven text accepted: prefix={prefix} {text:?}");
                    assert_eq!(document.root().encoded(), wire);
                    drop(document);
                }
                Err(error) => {
                    assert!(
                        matches!(error, DecodeError::UnprovenText),
                        "prefix={prefix} {text:?}: {error:?}"
                    );
                    assert!(!proven, "proven text refused: prefix={prefix} {text:?}");
                    finish_within(&mut m, &mut operation, bound);
                }
            }
            m.assert_units(TURN);
            drop(operation);
            assert_eq!(m.live_bytes(), 0);
        }
    });
}
