use super::bindings::decoder;
use super::harness::*;
use super::support::rigor::rigor;
use super::support::{
    Fault, allowed, drive_faulted, finish_within, pipeline::Refusal, reason_matrix, refusal_matrix,
    refuse,
};
use dcbor::bounded::decode::DecodeError;

// Literal invalid encodings, independent of either production encoder.
const INVALID: &[&[u8]] = &[
    &[0x19, 0x01],             // incomplete head
    &[0x43, 0x01, 0x02],       // incomplete payload
    &[0x82, 0x01],             // incomplete container
    &[0x18, 0x00],             // nonminimal integer
    &[0x62, 0xc0, 0x80],       // overlong UTF-8
    &[0x61, 0xff],             // byte that never occurs in UTF-8
    &[0x63, 0xed, 0xa0, 0x80], // UTF-8 encoded surrogate
    &[0x63, 0x65, 0xcc, 0x81], // non-NFC text
    // A declared length beyond the input, never reserved or scanned.
    &[0x5b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
    &[0x9f, 0xff],                   // empty indefinite container
    &[0xa2, 0x01, 0x00, 0x00, 0x00], // reversed keys
    &[0xa2, 0x00, 0x01, 0x00, 0x02], // duplicate keys
    &[0x81, 0x01, 0x00],             // trailing item
    &[0x9f, 0x01, 0xff],             // indefinite container
];

/// The fault matrix of decoding invalid `wire`, named `name`
/// ([`refusal_matrix`]): every refusal resumed to the terminal validation
/// error, never a publication, its cleanup run under a shared policy outside
/// the measured trace; and a cancellation at every call through the same
/// checked driver. Then the refusal's reason ([`reasons`]). Everything held
/// is released on every path.
fn invalid_matrix(name: &str, wire: &[u8]) {
    let baseline = refusal_matrix(name, rigor(), |fault: Fault| {
        let mut m = meter();
        refuse(&mut m, fault.refusal);
        let pool = m.share();
        let mut operation = decoder(wire);
        let turns = allowed(&m, decode_turns(wire.len()));
        match drive_faulted(&mut m, &mut operation, turns, fault.cancel) {
            Ok(Some(_)) => panic!("{name}: invalid input published"),
            Ok(None) => assert!(fault.cancel),
            Err(error) => {
                assert!(matches!(error, DecodeError::Invalid(_)), "{error:?}");
                m.assert_units(TURN);
                finish_within(&mut m.share(), &mut operation, decode_turns(wire.len()));
            }
        }
        drop(operation);
        assert_eq!(pool.live_bytes(), 0);
        super::support::RefusalRun::of(&m)
    });
    reasons(name, wire, baseline.calls());
}

/// The engine treats a refusal the same whatever its reason; only its
/// classification names the reason. A storage refusal and a deadline, each
/// observed at the selected call with its own reason, end the trace there
/// as a scheduled refusal does, and the cancelled decode releases
/// everything. The fast layer refuses for each reason at the decode's last
/// call; the exhaustive layer at every call, the evidence for the claim.
fn reasons(name: &str, wire: &[u8], baseline: &[Call]) {
    const REASONS: [LimitRefusal; 2] = [LimitRefusal::Storage, LimitRefusal::Deadline];
    reason_matrix(name, rigor(), baseline, &REASONS, |stop, reason| {
        let mut m = meter();
        refuse(&mut m, Refusal::For(stop, reason));
        let pool = m.share();
        let mut operation = decoder(wire);
        let result = drive_faulted(&mut m, &mut operation, decode_turns(wire.len()), true)
            .expect("selected refusal must precede invalid-input rejection");
        assert!(result.is_none(), "invalid input published");
        assert_eq!(m.first_refusal(), Some((stop, reason)));
        assert_eq!(m.injected_refusals(), 1);
        assert_eq!(m.calls(), &baseline[..=stop], "{reason:?} at call {stop}");
        drop(operation);
        assert_eq!(pool.live_bytes(), 0);
    });
}

// Prior art: tokio-util/tests/length_delimited.rs,
// read_incomplete_head_multi and read_incomplete_payload: suspension must not
// turn an incomplete item into success or consume its terminal error.
#[test]
fn malformed_inputs_stay_invalid_and_cancel_cleanly_at_every_refusal() {
    every_fixture(INVALID.len(), |fixture| {
        let wire = INVALID[fixture];
        invalid_matrix(&format!("malformed {wire:02x?}"), wire);
    });
}

#[test]
fn every_truncation_of_nested_literal_input_resumes_to_error_without_replay() {
    let complete = [
        0x82, 0x82, 0x01, 0x62, 0xc3, 0xa9, 0xa1, 0x00, 0x43, 1, 2, 3,
    ];
    every_fixture(complete.len(), |end| {
        invalid_matrix(&format!("truncated at {end}"), &complete[..end]);
    });
}
