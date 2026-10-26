use super::harness::*;
use super::support::{TurnSchedule, contracted, drive_within, finish_within, suspend_within};
use dcbor::bounded::decode::{
    DecodeError, Options,
    cursor::{Decoder, retained_decode_bound},
    decode_bound,
};
use dcbor::{
    CBOR,
    bounded::{BoundedError, Step, WriteWork},
};

fn check(bytes: &[u8]) {
    let expected = CBOR::try_from_data(bytes);
    let mut m = meter();
    let mut decoder = Decoder::new(bytes, Options::normalizing(64));
    let mut result = None;
    let mut terminal = false;
    for _ in 0..decode_turns(bytes.len()) {
        match contracted(&mut m, &mut decoder) {
            Ok(Step::Progress) => {}
            Ok(Step::Complete(document)) => {
                result = Some(document);
                terminal = true;
                break;
            }
            Err(DecodeError::Invalid(_)) => {
                terminal = true;
                break;
            }
            _ => panic!(
                "unexpected differential outcome at {:?}: wire={bytes:x?}",
                decoder.position()
            ),
        }
    }
    assert!(
        terminal,
        "no terminal outcome at {:?}: wire={bytes:x?}",
        decoder.position()
    );
    assert_eq!(result.is_some(), expected.is_ok(), "wire={bytes:x?}");
    if let Some(document) = &result {
        assert_eq!(document.root().encoded(), bytes);
    }
    // The retained parser's own bound, not the synchronous decoder's.
    let bound = retained_decode_bound::<Reservation, LimitRefusal>(
        bytes.len() as u64,
        Options::normalizing(64),
    )
    .unwrap();
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
    // A terminal parse error retains custody for admitted cleanup, which the
    // decoder's own steps perform. The retained bound describes the published
    // document, not a suspended cleanup.
    if result.is_none() {
        let mut cleanup = m.share();
        finish_within(&mut cleanup, &mut decoder, decode_turns(bytes.len()));
        cleanup.assert_units(TURN);
        assert_eq!(
            cleanup.live_bytes(),
            0,
            "terminal error retained storage after cleanup"
        );
    }
    assert!(
        m.live_bytes() <= bound.retained,
        "retained capacity exceeded: wire={bytes:02x?}, accepted={}, parser={:?}, live={}, peak={}, bound={bound:?}, admissions={:?}\n{:?}",
        result.is_some(),
        decoder.position(),
        m.live_bytes(),
        m.peak_bytes(),
        m.calls(),
        m.trace()
    );
    m.assert_units(TURN);
    drop(decoder);
    drop(result);
    assert_eq!(m.live_bytes(), 0);
}

/// Every single byte, and every truncation and single-bit mutation of each
/// literal, agrees with the symbolic decoder: each wire a fixture of its
/// own, all run and every failure reported ([`every_fixture`]).
#[test]
fn every_single_byte_and_mutated_literal_agrees_with_independent_symbolic_decoder() {
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
    every_fixture(wires.len(), |index| check(&wires[index]));
}

/// 2048 generated nested byte strings, each also with one corrupted byte,
/// agree with the symbolic decoder within the retained parse's bounds: each
/// wire a fixture of its own, all run and every failure reported
/// ([`every_fixture`]).
#[test]
fn deterministic_generated_nested_inputs_keep_semantics_and_resource_bounds() {
    let mut state = 0x7a31_ef02_45cd_918bu64;
    let mut wires = Vec::with_capacity(2 * 2048);
    for _ in 0..2048 {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let depth = (state % 32) as usize;
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
    every_fixture(wires.len(), |index| check(&wires[index]));
}

#[test]
fn overflowing_decode_bounds_are_typed_errors_not_saturated_allowances() {
    for length in [u64::MAX, u64::MAX - 1, u64::MAX / 2] {
        assert!(matches!(
            decode_bound::<LimitRefusal>(length, 64),
            Err(BoundedError::Overflow)
        ));
        assert!(matches!(
            retained_decode_bound::<Reservation, LimitRefusal>(length, Options::normalizing(64)),
            Err(BoundedError::Overflow)
        ));
    }
}

/// Fresh allowances never accumulate: each turn grants zero work, a random
/// part of one quantum, or one whole quantum past what was admitted. A step
/// refused part way keeps what it admitted and resumes there, so every
/// schedule admits exactly the unobstructed decode's calls, in order.
#[test]
fn randomized_turn_allowances_never_change_canonical_results_or_replay_work() {
    let wire = [0x83, 0x18, 0x18, 0x62, 0xc3, 0xa9, 0x42, 0x00, 0xff];
    let turns = decode_turns(wire.len());
    let baseline = {
        let mut m = meter();
        let mut decoder = Decoder::new(&wire, Options::normalizing(64));
        let document = drive_within(&mut m, &mut decoder, turns).expect("baseline failed");
        assert_eq!(document.root().encoded(), wire);
        drop(document);
        m.admitted().to_vec()
    };
    every_fixture(64, |seed| {
        let mut m = meter();
        let mut decoder = Decoder::new(&wire, Options::normalizing(64));
        let mut random = seed as u64 + 1;
        let mut document = None;
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
            m.clear_refusal();
            let used = m.used();
            m.set_limit(WriteWork::new(
                used.values + allowance.values,
                used.bytes + allowance.bytes,
            ));
            match contracted(&mut m, &mut decoder) {
                Ok(Step::Progress) => {}
                Ok(Step::Complete(published)) => {
                    document = Some(published);
                    break;
                }
                Err(DecodeError::Resource(BoundedError::Refused(LimitRefusal::Work))) => {}
                _ => panic!(
                    "seed {seed}, turn {turn}: unexpected outcome at {:?}",
                    decoder.position()
                ),
            }
        }
        let document = document.expect("schedule exceeded its bound");
        assert_eq!(document.root().encoded(), wire);
        assert_eq!(
            m.admitted(),
            baseline,
            "seed {seed}: an allowance schedule replayed admitted work"
        );
        m.assert_units(TURN);
        drop(decoder);
        drop(document);
        assert_eq!(m.live_bytes(), 0);
    });
}

#[test]
fn generated_valid_inputs_complete_after_small_budget_refusal_without_replay() {
    every_fixture(64, |seed| {
        let mut wire = vec![0x81; seed % 16];
        wire.extend_from_slice(&[0x43, seed as u8, 0, 255]);
        let mut m = meter();
        m.set_limit(WriteWork::new(3, 16));
        let pool = m.share();
        let mut decoder = Decoder::new(&wire, Options::normalizing(64));
        // Within the retained parse's own bound, under the small allowance
        // set above, kept across steps until it refuses.
        suspend_within(
            &mut m,
            &mut decoder,
            LimitRefusal::Work,
            decode_turns(wire.len()),
            TurnSchedule::Retained,
        );
        let document = drive_within(&mut m, &mut decoder, decode_turns(wire.len()))
            .expect("valid input failed after refusal");
        assert_eq!(document.root().encoded(), wire);
        drop(decoder);
        assert!(pool.live_bytes() > 0);
        drop(document);
        assert_eq!(pool.live_bytes(), 0);
    });
}
