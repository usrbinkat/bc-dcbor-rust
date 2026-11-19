use super::harness::*;
use super::support::{
    Fault, Finding, RefusalRun, Retirement, Stopped, pipeline::Unwitnessed, recorded_run,
    refusal_matrix, rigor::rigor,
};
use dcbor::bounded::Family;
use dcbor::bounded::decode::{DecodeError, Options, cursor::Decoder};
use unicode_normalization::{IsNormalized, is_nfc_quick};

fn quick(input: &[u8]) -> Decoder<'_, Reservation, Family> {
    Decoder::new(input, Options::quick_only(8))
}

/// The same retained decode and cleanup scenario serves literal verdicts
/// and upstream comparisons, including publication surviving its decoder.
fn quick_run(wire: &[u8], accepted: bool, fault: Fault, case: &str) -> RefusalRun {
    recorded_run(|run| {
        let policy = run.observed_policy(POOL);
        let cleanup = run.shared_policy(policy);
        let bound = decode_turns(wire.len());
        run.holding(
            quick(wire),
            Retirement::Released,
            &Unwitnessed,
            |operation| {
                match operation.drive_faulted(
                    policy,
                    bound,
                    Retirement::Released,
                    fault,
                    |_, _| {},
                    |document| {
                        assert!(accepted, "{case}: unproven text accepted");
                        assert_eq!(document.value().root().encoded(), wire, "{case}");
                        document.with_policy(policy, |_, m| {
                            m.assert_units(TURN);
                            assert!(m.live_bytes() > 0);
                        });
                    },
                ) {
                    Ok(Some(())) => {}
                    Ok(None) => assert!(fault.cancel, "{case}: unscheduled cancellation"),
                    Err(Stopped::Operation(error)) => {
                        assert!(!accepted, "{case}: proven text refused: {error:?}");
                        assert!(
                            matches!(error, DecodeError::UnprovenText),
                            "{case}: lost the specific QuickOnly rejection: {error:?}"
                        );
                        operation.with_policy(policy, |_, m| m.assert_units(TURN));
                        operation.finish(cleanup, bound, Retirement::Released)?;
                    }
                    Err(stop) => return Err(Finding::from(stop)),
                }
                Ok(())
            },
        )?;
        Ok(run.with_policy(policy, |m| {
            assert_eq!(m.live_bytes(), 0);
            RefusalRun::of(m)
        }))
    })
}

/// For each fixture, every refusal of a QuickOnly decode resumed to the same
/// outcome, the literal document or the specific QuickOnly rejection, never
/// a silent normalization; and a cancellation at every call releasing what
/// the decode held. A rejected decode's own cleanup runs under a shared
/// policy, outside the measured trace.
#[test]
fn quick_only_policy_survives_every_refusal_without_silent_normalization()
-> Result<(), Vec<Finding>> {
    let fixtures = [
        ("ASCII", true),
        ("\u{e9}", true),
        ("q\u{301}", false),
        ("e\u{301}", false),
    ];
    every_fixture(fixtures.len(), |fixture| {
        let (text, accepted) = fixtures[fixture];
        let wire = text_wire(text);
        refusal_matrix(&format!("QuickOnly decode of {text:?}"), rigor(), |fault| {
            quick_run(&wire, accepted, fault, text)
        });
        Ok(())
    })
}

/// Payload validation proceeds in quanta of at most 64 bytes. An ASCII prefix
/// of every length from 56 through 72 places each byte of every scalar, and
/// every boundary between a base and its marks, on each side of the first
/// quantum's end. The QuickOnly verdict must equal upstream's for the whole
/// text wherever the boundary falls.
#[test]
fn quick_check_agrees_with_upstream_wherever_a_scalar_meets_a_quantum_boundary()
-> Result<(), Vec<Finding>> {
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
            quick_run(
                &wire,
                proven,
                Fault::NONE,
                &format!("prefix={prefix} {text:?}"),
            );
        }
        Ok(())
    })
}
