use super::bindings::{decoder, string_decoder, text_encoder};
use super::harness::*;
use super::support::{
    Fault, TurnSchedule, allowed, drive_faulted, drive_within, exhausted, refusal_matrix, refuse,
    rigor::rigor, suspend_within,
};
use dcbor::bounded::Allocator;
use dcbor::bounded::decode::Kind;

#[test]
fn decoder_resumes_same_operation_before_and_after_header_without_replay() {
    let wire = [
        0x58, 0x18, b'a', b'b', b'c', b'd', b'e', b'f', b'g', b'h', b'i', b'j', b'k', b'l', b'm',
        b'n', b'o', b'p', b'q', b'r', b's', b't', b'u', b'v', b'w', b'x',
    ];
    refusal_matrix("decoder over a byte string", rigor(), |fault: Fault| {
        let mut m = meter();
        refuse(&mut m, fault.refusal);
        let pool = m.share();
        let mut operation = decoder(&wire);
        let turns = allowed(&m, decode_turns(wire.len()));
        let document = drive_faulted(&mut m, &mut operation, turns, fault.cancel)
            .expect("a canonical byte string decodes");
        if let Some(document) = &document {
            assert_eq!(document.root().kind(), Kind::Bytes(&wire[2..]));
            assert_eq!(document.root().encoded(), wire);
            m.assert_units(TURN);
        }
        drop(operation);
        drop(document);
        assert_eq!(pool.live_bytes(), 0);
        super::support::RefusalRun::of(&m)
    });
}

#[test]
fn text_normalization_resumes_each_real_refusal_and_preserves_literal_result() {
    let source = "a\u{301}";
    refusal_matrix(
        "text encoder of a composing pair",
        rigor(),
        |fault: Fault| {
            let mut m = meter();
            refuse(&mut m, fault.refusal);
            let pool = m.share();
            let mut operation = text_encoder(source);
            let turns = allowed(&m, normalize_turns(source));
            let value = drive_faulted(&mut m, &mut operation, turns, fault.cancel)
                .expect("a composing pair normalizes");
            drop(operation);
            if let Some(value) = &value {
                assert_eq!(value.as_ref(), &[0x62, 0xc3, 0xa1]);
                m.assert_units(TURN);
                assert!(pool.live_bytes() >= 3);
            }
            drop(value);
            assert_eq!(pool.live_bytes(), 0);
            super::support::RefusalRun::of(&m)
        },
    );
}

#[test]
fn typed_construction_resumes_and_transfers_output_ownership() {
    let wire = [0x62, 0xc3, 0xa9];
    refusal_matrix(
        "string decoder of composed text",
        rigor(),
        |fault: Fault| {
            let mut m = meter();
            refuse(&mut m, fault.refusal);
            let pool = m.share();
            let mut operation = string_decoder(&wire);
            let turns = allowed(&m, string_turns(wire.len()));
            let value = drive_faulted(&mut m, &mut operation, turns, fault.cancel)
                .expect("canonical text decodes");
            drop(operation);
            if let Some(value) = &value {
                assert_eq!(value.value(), "\u{e9}");
                m.assert_units(TURN);
                assert!(pool.live_bytes() >= 2);
                assert_eq!(value.value(), "\u{e9}");
            }
            drop(value);
            assert_eq!(pool.live_bytes(), 0);
            super::support::RefusalRun::of(&m)
        },
    );
}

#[test]
fn externally_released_capacity_resumes_same_decode_not_a_second_attempt() {
    let mut pool = meter_with(4096);
    let blocked = pool.allocate(4096).unwrap();
    let wire = [0x81, 0x01];
    let mut m = pool.share();
    let mut operation = decoder(&wire);
    let turns = decode_turns(wire.len());
    let stop = suspend_within(
        &mut m,
        &mut operation,
        LimitRefusal::Storage,
        turns,
        TurnSchedule::Retained,
    );
    assert_eq!(m.first_refusal(), Some((stop, LimitRefusal::Storage)));
    let paid = m.used();
    assert_eq!(pool.live_bytes(), 4096);
    std::thread::spawn(move || drop(blocked)).join().unwrap();
    assert_eq!(pool.live_bytes(), 0);
    let document =
        drive_within(&mut m, &mut operation, turns).expect("released capacity did not resume");
    let after = m.used();
    assert!(after.values >= paid.values && after.bytes >= paid.bytes);
    let mut baseline = meter();
    drop(drive_within(&mut baseline, &mut decoder(&wire), turns).unwrap());
    assert_eq!(
        m.admitted(),
        baseline.admitted(),
        "completed work was replayed"
    );
    assert_eq!(m.used(), baseline.used());
    assert_eq!(document.root().encoded(), wire);
    m.assert_units(TURN);
    drop(operation);
    drop(document);
    assert_eq!(pool.live_bytes(), 0);
    let all = pool.allocate(4096).unwrap();
    assert!(pool.allocate(1).is_err());
    drop(all);
}

#[test]
fn decode_publishes_once_and_then_only_reports_finished() {
    let wire = [0x81, 0x01];
    let mut m = meter();
    let mut operation = decoder(&wire);
    let document = drive_within(&mut m, &mut operation, decode_turns(wire.len())).unwrap();
    assert_eq!(document.root().encoded(), wire);
    exhausted(&mut m, &mut operation);
    exhausted(&mut m, &mut operation);
}
