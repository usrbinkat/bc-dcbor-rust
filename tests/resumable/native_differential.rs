use super::driver::{Driver, Step, finish};
use super::harness::*;
use dcbor::bounded::decode::{
    Options,
    cursor::{DecodeStep, Decoder},
    decode_bound,
};
use dcbor::{CBOR, bounded::BoundedError};

fn check(bytes: &[u8]) {
    let expected = CBOR::try_from_data(bytes);
    let mut m = meter();
    let mut decoder = Decoder::new(bytes, Options::normalizing(64));
    let mut result = None;
    let mut terminal = false;
    for _ in 0..bytes
        .len()
        .saturating_mul(bytes.len())
        .saturating_mul(128)
        .saturating_add(4096)
    {
        match decoder.step(&mut m) {
            Ok(DecodeStep::Progress) => {}
            Ok(DecodeStep::Complete(document)) => {
                result = Some(document);
                terminal = true;
                break;
            }
            Err(dcbor::bounded::decode::DecodeError::Invalid(_)) => {
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
    let bound = decode_bound::<Refusal>(bytes.len() as u64, 64).unwrap();
    assert!(m.values <= bound.values && m.bytes <= bound.bytes);
    let allocated: u64 = m
        .calls
        .iter()
        .filter_map(|call| match call {
            Call::Allocate(bytes) => Some(*bytes),
            _ => None,
        })
        .sum();
    assert!(allocated <= bound.allocated);
    assert!(m.pool.peak() <= bound.peak);
    // A terminal parse error now retains custody for admitted cleanup. The
    // retained bound describes the published document, not a suspended cleanup.
    // Exercise the real cleanup boundary with independently fresh allowances.
    if result.is_none() {
        let mut cleanup = Meter::new(m.pool.clone());
        let mut cleaned = false;
        for _ in 0..bytes.len().saturating_mul(128).saturating_add(4096) {
            cleanup.limit_values = cleanup.values + 3;
            cleanup.limit_bytes = cleanup.bytes + 64;
            cleanup.refused = None;
            match decoder.reclaim_step(&mut cleanup) {
                Ok(true) => {
                    cleaned = true;
                    break;
                }
                Ok(false) | Err(BoundedError::Refused(_)) => {}
                other => panic!(
                    "cleanup failed: {other:?}, wire={bytes:02x?}, parser={:?}",
                    decoder.position()
                ),
            }
        }
        assert!(cleaned, "cleanup exceeded finite bound: wire={bytes:02x?}");
        cleanup.assert_units(3, 64);
        assert_eq!(
            cleanup.pool.live(),
            0,
            "terminal error retained storage after cleanup"
        );
    }
    assert!(
        m.pool.live() <= bound.retained,
        "retained capacity exceeded: wire={bytes:02x?}, accepted={}, parser={:?}, live={}, peak={}, bound={bound:?}, admissions={:?}\n{:?}",
        result.is_some(),
        decoder.position(),
        m.pool.live(),
        m.pool.peak(),
        m.calls,
        m.trace
    );
    m.assert_units(3, 64);
    drop(decoder);
    drop(result);
    assert_eq!(m.pool.live(), 0);
}

#[test]
fn every_single_byte_and_mutated_literal_agrees_with_independent_symbolic_decoder() {
    for byte in 0..=255 {
        check(&[byte]);
    }
    let fixtures: &[&[u8]] = &[
        &[0xa2, 0x00, 0x82, 0x01, 0x02, 0x01, 0x62, 0xc3, 0xa9],
        &[0x82, 0xf5, 0xf6],
        &[0xd8, 0x2a, 0x01],
        &[0x19, 0x01, 0x00],
        &[0x63, 0xed, 0x93, 0x9b],
    ];
    for fixture in fixtures {
        for end in 0..=fixture.len() {
            check(&fixture[..end]);
        }
        for at in 0..fixture.len() {
            for bit in 0..8 {
                let mut mutation = fixture.to_vec();
                mutation[at] ^= 1 << bit;
                check(&mutation);
            }
        }
    }
}

#[test]
fn deterministic_generated_nested_inputs_keep_semantics_and_resource_bounds() {
    let mut state = 0x7a31_ef02_45cd_918bu64;
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
        check(&wire);
        let at = (state as usize) % wire.len();
        wire[at] ^= (state >> 40) as u8;
        check(&wire);
    }
}

#[test]
fn overflowing_decode_bounds_are_typed_errors_not_saturated_allowances() {
    for length in [u64::MAX, u64::MAX - 1, u64::MAX / 2] {
        assert!(matches!(
            decode_bound::<Refusal>(length, 64),
            Err(BoundedError::Overflow)
        ));
    }
}

#[test]
fn generated_valid_inputs_complete_after_small_budget_refusal_without_replay() {
    every_case(64, |seed| {
        let mut wire = vec![0x81; seed % 16];
        wire.extend_from_slice(&[0x43, seed as u8, 0, 255]);
        let mut m = meter();
        m.limit_values = 3;
        m.limit_bytes = 16;
        let pool = m.pool.clone();
        let mut driver = Driver::from_operation(Decoder::new(&wire, Options::normalizing(64)), m);
        let mut suspended = false;
        for _ in 0..4096 {
            let before = driver.operation().position();
            match driver.step().unwrap() {
                Step::Progress => assert!(driver.output.is_none()),
                Step::Refused(Refusal::Work) => {
                    assert_eq!(driver.operation().position(), before);
                    assert_eq!(
                        driver.meter.refused.map(|(_, reason)| reason),
                        Some(Refusal::Work)
                    );
                    suspended = true;
                    break;
                }
                other => panic!("seed={seed}: {other:?}"),
            }
        }
        assert!(suspended);
        finish(&mut driver, wire.len() * 128 + 4096);
        assert_eq!(driver.invocations, 1);
        assert_eq!(driver.output.as_ref().unwrap().root().encoded(), wire);
        let output = driver.output.take().unwrap();
        drop(driver);
        assert!(pool.live() > 0);
        drop(output);
        assert_eq!(pool.live(), 0);
    });
}
