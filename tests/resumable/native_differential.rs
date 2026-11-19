use super::harness::*;
use super::support::{
    Fault, Finding, Retirement, Stopped, TurnSchedule, contracted, label, pipeline::Unwitnessed,
};
use dcbor::bounded::decode::{
    DecodeError, Options,
    cursor::{Decoder, retained_decode_bound},
    decode_bound,
};
use dcbor::{
    CBOR,
    bounded::{BoundedError, Family, Step, WriteWork},
};

fn check(bytes: &[u8]) {
    let expected = CBOR::try_from_data(bytes);
    suite(|run, policy| {
        let cleanup = run.shared_policy(policy);
        let mut position = None;
        let retained = run.holding(
            Decoder::new(bytes, Options::normalizing(64)),
            Retirement::Released,
            &Unwitnessed,
            |decoder| {
                let retained = match decoder.drive_observed(
                    policy,
                    decode_turns(bytes.len()),
                    Retirement::Released,
                    |_, decoder| position = Some(decoder.position()),
                    |document| {
                        assert!(expected.is_ok(), "wire={bytes:x?}");
                        assert_eq!(document.value().root().encoded(), bytes);
                        document.with_policy(policy, |_, m| m.live_bytes())
                    },
                ) {
                    Ok(retained) => Some(retained),
                    Err(Stopped::Operation(DecodeError::Invalid(_))) => {
                        assert!(expected.is_err(), "wire={bytes:x?}");
                        None
                    }
                    Err(Stopped::Operation(error)) => {
                        return Err(Finding::Driver(format!(
                            "unexpected differential outcome {error:?} at {position:?}: wire={bytes:x?}",
                        )));
                    }
                    Err(stop) => return Err(Finding::from(stop)),
                };
                // Terminal errors retain custody for the parser's admitted cleanup.
                if retained.is_none() {
                    decoder.finish(cleanup, decode_turns(bytes.len()), Retirement::Released)?;
                }
                Ok::<_, Finding>(retained)
            },
        )?;
        // The retained parser's own bound, not the synchronous decoder's.
        let bound = retained_decode_bound::<Reservation, Family, LimitRefusal>(
            bytes.len() as u64,
            Options::normalizing(64),
        )
        .unwrap();
        run.with_policy(cleanup, |cleanup| {
            cleanup.assert_units(TURN);
            assert_eq!(
                cleanup.live_bytes(),
                0,
                "terminal error retained storage after cleanup"
            );
        });
        run.with_policy(policy, |m| {
            let used = m.used();
            assert!(used.values <= bound.values && used.bytes <= bound.bytes);
            let allocated: u64 = m
                .calls()
                .iter()
                .filter_map(|call| match call {
                    Call::Allocate(bytes) => Some(*bytes),
                    _ => None,
                })
                .sum();
            assert!(allocated <= bound.allocated);
            assert_eq!(allocated, m.requested_bytes());
            assert!(m.peak_bytes() <= bound.peak);
            let live = retained.unwrap_or_else(|| m.live_bytes());
            assert!(
                live <= bound.retained,
                "retained capacity exceeded: wire={bytes:02x?}, accepted={}, parser={position:?}, live={}, peak={}, bound={bound:?}, admissions={:?}\n{:?}",
                retained.is_some(),
                live,
                m.peak_bytes(),
                m.calls(),
                m.trace()
            );
            m.assert_units(TURN);
            assert_eq!(m.live_bytes(), 0);
        });
        Ok(())
    });
}

/// Every single byte, and every truncation and single-bit mutation of each
/// literal, agrees with the symbolic decoder: each wire a fixture of its
/// own, all run and every failure reported ([`every_fixture`]).
#[test]
fn every_single_byte_and_mutated_literal_agrees_with_independent_symbolic_decoder()
-> Result<(), Vec<Finding>> {
    let literals: &[&[u8]] = &[
        &[0xa2, 0x00, 0x82, 0x01, 0x02, 0x01, 0x62, 0xc3, 0xa9],
        &[0x82, 0xf5, 0xf6],
        &[0xd8, 0x2a, 0x01],
        &[0x19, 0x01, 0x00],
        &[0x63, 0xed, 0x93, 0x9b],
    ];
    let mut wires: Vec<Vec<u8>> = (0..=255u8).map(|byte| vec![byte]).collect();
    for literal in literals {
        for end in 0..=literal.len() {
            wires.push(literal[..end].to_vec());
        }
        for at in 0..literal.len() {
            for bit in 0..8 {
                let mut mutation = literal.to_vec();
                mutation[at] ^= 1 << bit;
                wires.push(mutation);
            }
        }
    }
    every_fixture(wires.len(), |index| {
        check(&wires[index]);
        Ok(())
    })
}

/// Generated nested byte strings, each also with one corrupted byte, agree
/// with the symbolic decoder within the retained parse's bounds: each wire a
/// fixture of its own, all run and every failure reported
/// ([`every_fixture`]). A wire's nesting depth, 0 through 31, is its one
/// structural variable: the exhaustive layer runs all 2048 generated, the
/// fast layer the first generated at each depth, each beside its corruption
/// ([`super::support::rigor`]).
#[test]
fn deterministic_generated_nested_inputs_keep_semantics_and_resource_bounds()
-> Result<(), Vec<Finding>> {
    use super::support::rigor::{Rigor, rigor};
    let exhaustive = rigor() == Rigor::Exhaustive;
    let mut state = 0x7a31_ef02_45cd_918bu64;
    let mut wires = Vec::with_capacity(2 * 2048);
    let mut depths = [false; 32];
    for _ in 0..2048 {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let depth = (state % 32) as usize;
        if !exhaustive && core::mem::replace(&mut depths[depth], true) {
            continue;
        }
        let mut wire = vec![0x81; depth];
        wire.extend_from_slice(&[
            0x44,
            (state >> 8) as u8,
            (state >> 16) as u8,
            (state >> 24) as u8,
            (state >> 32) as u8,
        ]);
        let mut corrupted = wire.clone();
        let at = (state as usize) % corrupted.len();
        corrupted[at] ^= (state >> 40) as u8;
        wires.push(wire);
        wires.push(corrupted);
    }
    assert!(
        exhaustive || depths.iter().all(|&reached| reached),
        "the generator reached every depth"
    );
    every_fixture(wires.len(), |index| {
        check(&wires[index]);
        Ok(())
    })
}

#[test]
fn overflowing_decode_bounds_are_typed_errors_not_saturated_allowances() {
    for length in [u64::MAX, u64::MAX - 1, u64::MAX / 2] {
        assert!(matches!(
            decode_bound::<LimitRefusal>(length, 64),
            Err(BoundedError::Overflow)
        ));
        assert!(matches!(
            retained_decode_bound::<Reservation, Family, LimitRefusal>(
                length,
                Options::normalizing(64),
            ),
            Err(BoundedError::Overflow)
        ));
    }
}

/// Fresh allowances never accumulate: each turn grants zero work, a random
/// part of one quantum, or one whole quantum past what was admitted. A step
/// refused part way keeps what it admitted and resumes there, so every
/// schedule admits exactly the unobstructed decode's calls, in order.
#[test]
fn randomized_turn_allowances_never_change_canonical_results_or_replay_work()
-> Result<(), Vec<Finding>> {
    let wire = [0x83, 0x18, 0x18, 0x62, 0xc3, 0xa9, 0x42, 0x00, 0xff];
    let turns = decode_turns(wire.len());
    let baseline = retained_case(
        Decoder::new(&wire, Options::normalizing(64)),
        turns,
        Fault::NONE,
        |document, _| assert_eq!(document.root().encoded(), wire),
    )
    .into_admitted();
    every_fixture(64, |seed| {
        suite(|run, policy| {
            run.holding(
                Decoder::new(&wire, Options::normalizing(64)),
                Retirement::Released,
                &Unwitnessed,
                |decoder| {
                    let mut random = seed as u64 + 1;
                    // Every third turn grants a whole quantum, so the schedule completes
                    // within three times the unobstructed bound.
                    for turn in 0..3 * turns {
                        random = random
                            .wrapping_mul(6364136223846793005)
                            .wrapping_add(1442695040888963407);
                        let allowance = match turn % 3 {
                            0 => WriteWork::new(0, 0),
                            1 => WriteWork::new(
                                1 + (random >> 33) % TURN.values,
                                1 + (random >> 17) % TURN.bytes,
                            ),
                            _ => TURN,
                        };
                        let outcome = decoder.with_policy(policy, |decoder, m| {
                            m.clear_refusal();
                            let used = m.used();
                            m.set_limit(WriteWork::new(
                                used.values + allowance.values,
                                used.bytes + allowance.bytes,
                            ));
                            contracted(m, decoder)
                        });
                        match outcome {
                            Ok(Step::Progress) => {
                                decoder.with_policy(policy, |_, m| {
                                    assert_eq!(m.evidence(), Ok(()), "seed {seed}, turn {turn}");
                                });
                                decoder.checkpoint();
                            }
                            Ok(Step::Complete(published)) => {
                                decoder.holding(published, Retirement::Released, |document| {
                                    document.checkpoint();
                                    assert_eq!(document.value().root().encoded(), wire);
                                    document.with_policy(policy, |_, m| {
                                assert_eq!(m.evidence(), Ok(()), "seed {seed}, turn {turn}");
                                assert_eq!(
                                    m.admitted_calls(),
                                    baseline,
                                    "seed {seed}: an allowance schedule replayed admitted work"
                                );
                                m.assert_units(TURN);
                            });
                                });
                                return Ok(());
                            }
                            Err(DecodeError::Resource(BoundedError::Refused(
                                LimitRefusal::Work,
                            ))) => {
                                decoder.with_policy(policy, |_, m| {
                                    assert_eq!(m.evidence(), Ok(()), "seed {seed}, turn {turn}");
                                });
                                decoder.checkpoint();
                            }
                            other => {
                                return Err(Finding::Driver(format!(
                                    "seed {seed}, turn {turn}: unexpected outcome {} at {:?}",
                                    label(&other),
                                    decoder.value().position()
                                )));
                            }
                        }
                    }
                    Err(Finding::Driver(format!(
                        "seed {seed}: the schedule exceeded its bound"
                    )))
                },
            )?;
            run.with_policy(policy, |m| assert_eq!(m.live_bytes(), 0));
            Ok(())
        });
        Ok(())
    })
}

#[test]
fn generated_valid_inputs_complete_after_small_budget_refusal_without_replay()
-> Result<(), Vec<Finding>> {
    every_fixture(64, |seed| {
        let mut wire = vec![0x81; seed % 16];
        wire.extend_from_slice(&[0x43, seed as u8, 0, 255]);
        suite(|run, policy| {
            run.with_policy(policy, |m| m.set_limit(WriteWork::new(3, 16)));
            run.holding(
                Decoder::new(&wire, Options::normalizing(64)),
                Retirement::Released,
                &Unwitnessed,
                |decoder| {
                    // Within the retained parse's own bound, under the small
                    // allowance set above, kept across steps until it refuses.
                    decoder.suspend(
                        policy,
                        LimitRefusal::Work,
                        decode_turns(wire.len()),
                        TurnSchedule::Retained,
                        Retirement::Released,
                    )?;
                    decoder.drive_faulted(
                        policy,
                        decode_turns(wire.len()),
                        Retirement::Released,
                        Fault::NONE,
                        |_, _| {},
                        |document| {
                            assert_eq!(document.value().root().encoded(), wire);
                            document.with_policy(policy, |_, m| assert!(m.live_bytes() > 0));
                        },
                    )?;
                    Ok::<_, Finding>(())
                },
            )?;
            run.with_policy(policy, |m| assert_eq!(m.live_bytes(), 0));
            Ok(())
        });
        Ok(())
    })
}
