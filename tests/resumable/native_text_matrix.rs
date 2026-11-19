use super::bindings::text_encoder;
use super::harness::*;
use super::support::rigor::{Rigor, rigor};
use super::support::{
    Fault, Finding, Retirement, Stopped, TurnSchedule,
    pipeline::{Refusal, Unwitnessed},
    reason_matrix, refusal_matrix,
};
use dcbor::bounded::WriteWork;
use dcbor::bounded::decode::{DecodeError, Kind, Options, cursor::Decoder, decode};

/// Encode `source` under `fault`: resumed to the literal `expected` bytes,
/// which the encoder's output holds beyond the encoder's own life, or
/// cancelled at its refusal, releasing everything. Returns the calls
/// attempted.
fn encode_run(source: &str, expected: &[u8], fault: Fault) -> super::support::RefusalRun {
    retained_case(
        text_encoder(source),
        normalize_turns(source),
        fault,
        |output, m| {
            assert_eq!(output.as_ref(), expected);
            assert!(m.live_bytes() >= expected.len() as u64);
            assert_eq!(output.as_ref(), expected);
        },
    )
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
            let run = encode_run(
                source,
                expected,
                Fault {
                    refusal: Refusal::For(stop, reason),
                    cancel: false,
                },
            );
            run.resumed(&baseline, stop, reason);
            run.reached()
        },
    );
    // Independent decoder oracles: the synchronous decode's document held by
    // the run and retired, releasing its storage.
    suite(|run, policy| {
        let parsed = run
            .with_policy(policy, |m| decode(expected, 8, m))
            .map_err(|error| {
                Finding::Driver(format!("the expected encoding did not decode: {error:?}"))
            })?;
        run.holding(parsed, Retirement::Released, &Unwitnessed, |parsed| {
            assert_eq!(parsed.value().root().kind(), Kind::Text(canonical));
        });
        run.with_policy(policy, |m| assert_eq!(m.live_bytes(), 0));
        Ok(())
    });
    if source != canonical {
        let wire = text_wire(source);
        suite(|run, policy| {
            let rejected = run.with_policy(policy, |m| decode(&wire, 8, m));
            match rejected {
                Err(_) => Ok(()),
                Ok(document) => {
                    run.holding(document, Retirement::Released, &Unwitnessed, |_| ());
                    Err(Finding::Defect(format!(
                        "the non-canonical text {source:?} decoded"
                    )))
                }
            }
        });
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
    // A combining run of 8,193 scalars normalized and encoded a quantum per
    // turn: 279,243 observations and 53 permit records, measured.
    let recording = super::support::measured(279_243, 53);
    suite_with(POOL, recording, |run, policy| {
        // One quantum before the first refusal; every later turn is one
        // quantum.
        run.with_policy(policy, |m| {
            m.set_limit(WriteWork::new(TURN.values, TURN.bytes))
        });
        run.holding(
            text_encoder(&source),
            Retirement::Released,
            &Unwitnessed,
            |operation| {
                operation.suspend(
                    policy,
                    LimitRefusal::Work,
                    normalize_turns(&source),
                    TurnSchedule::Retained,
                    Retirement::Released,
                )?;
                // The encoder retired before its output is consumed: the
                // output holds its bytes beyond the encoder's life.
                operation.drive_faulted(
                    policy,
                    normalize_turns(&source),
                    Retirement::Released,
                    Fault::NONE,
                    |_, _| {},
                    |output| {
                        output.with_policy(policy, |output, m| {
                            assert_eq!(output.as_ref(), expected);
                            m.assert_units(TURN);
                            assert!(m.live_bytes() >= expected.len() as u64);
                        });
                    },
                )?;
                Ok::<_, Finding>(())
            },
        )?;
        run.with_policy(policy, |m| assert_eq!(m.live_bytes(), 0));
        Ok(())
    });
}

#[test]
fn long_valid_combining_sequence_is_accepted_and_one_late_disordered_mark_rejects_it() {
    // The fast witness crosses several byte quanta; the exhaustive witness
    // stresses the same acceptance and late-disorder paths at 100,000 marks.
    let marks = match rigor() {
        Rigor::Fast => 128,
        Rigor::Exhaustive => 100_000,
    };
    let measuring = match std::env::var("DCBOR_MEASURE_RECORDING") {
        Err(std::env::VarError::NotPresent) => false,
        Ok(value) if value == "1" => true,
        other => panic!("DCBOR_MEASURE_RECORDING must be 1 or unset: {other:?}"),
    };
    let capacity = |events, permits| {
        if measuring {
            dcbor::bounded::Capacity {
                events: 1 << 23,
                permits: super::support::CAPACITY.permits,
            }
        } else {
            match rigor() {
                Rigor::Fast => super::support::CAPACITY,
                Rigor::Exhaustive => super::support::measured(events, permits),
            }
        }
    };
    let inspect = move |run: &mut super::support::RecordedRun, name: &'static str| {
        if measuring {
            run.inspect_evidence(move |observed, _| {
                use dcbor::bounded::{Answer, Call, Event};
                let permits = observed
                    .iter()
                    .filter(|observation| {
                        matches!(
                            observation.event,
                            Event::Call(Call::Allocate(_), Answer::Granted(_))
                                | Event::Split { .. }
                        )
                    })
                    .count();
                eprintln!(
                    "long combining {name}, {marks} marks: {} events, {permits} permits",
                    observed.len()
                );
            });
        }
    };
    // q composes with no mark, and every mark has the same combining class:
    // the text is NFC however long the run.
    let valid = format!("q{}", "\u{301}".repeat(marks));
    let wire = text_wire(&valid);
    suite_with(POOL, capacity(3_331_604, 67), |run, policy| {
        inspect(run, "valid");
        run.holding(
            Decoder::new(&wire, Options::normalizing(8)),
            Retirement::Released,
            &Unwitnessed,
            |operation| {
                // The retained parse bound includes proving the text's
                // normalization.
                operation.drive(
                    policy,
                    decode_turns(wire.len()),
                    Retirement::Released,
                    |document| {
                        assert_eq!(document.value().root().kind(), Kind::Text(&valid));
                        document.with_policy(policy, |_, m| m.assert_units(TURN));
                    },
                )
            },
        )?;
        run.with_policy(policy, |m| assert_eq!(m.live_bytes(), 0));
        Ok(())
    });
    // A class-220 mark after the class-230 run is out of canonical order; it
    // is found only after the whole run has been validated, then the decoder
    // steps its own cleanup to its end.
    let disordered = format!("{valid}\u{316}");
    let wire = text_wire(&disordered);
    suite_with(POOL, capacity(200_026, 0), |run, policy| {
        inspect(run, "disordered");
        run.holding(
            Decoder::new(&wire, Options::normalizing(8)),
            Retirement::Released,
            &Unwitnessed,
            |operation| {
                match operation.drive(
                    policy,
                    decode_turns(wire.len()),
                    Retirement::Released,
                    |_| (),
                ) {
                    Err(Stopped::Operation(DecodeError::Invalid(_))) => {}
                    Err(stop) => return Err(Finding::from(stop)),
                    Ok(()) => {
                        return Err(Finding::Defect(
                            "a disordered combining run decoded".to_owned(),
                        ));
                    }
                }
                operation.finish(policy, decode_turns(wire.len()), Retirement::Released)?;
                Ok(())
            },
        )?;
        run.with_policy(policy, |m| m.assert_units(TURN));
        run.with_policy(policy, |m| assert_eq!(m.live_bytes(), 0));
        Ok(())
    });
    assert!(!measuring, "recording measurement is not qualification");
}
