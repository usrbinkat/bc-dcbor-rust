use super::bindings::decoder;
use super::harness::*;
use super::support::rigor::rigor;
use super::support::{
    Fault, Finding, Retirement, Stopped,
    pipeline::{Refusal, Unwitnessed},
    reason_matrix, recorded_run, refusal_matrix,
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
        recorded_run(|run| {
            let policy = run.observed_policy(POOL);
            let cleanup = run.shared_policy(policy);
            run.holding(
                decoder(wire),
                Retirement::Released,
                &Unwitnessed,
                |operation| {
                    match operation.drive_faulted(
                        policy,
                        decode_turns(wire.len()),
                        Retirement::Released,
                        fault,
                        |_, _| {},
                        |_| panic!("{name}: invalid input published"),
                    ) {
                        Ok(Some(())) => unreachable!("publication fails inside its holding"),
                        Ok(None) => assert!(fault.cancel),
                        Err(Stopped::Operation(error)) => {
                            assert!(matches!(error, DecodeError::Invalid(_)), "{error:?}");
                            operation.with_policy(policy, |_, m| m.assert_units(TURN));
                            operation.finish(
                                cleanup,
                                decode_turns(wire.len()),
                                Retirement::Released,
                            )?;
                        }
                        Err(stop) => return Err(Finding::from(stop)),
                    }
                    Ok(())
                },
            )?;
            Ok(run.with_policy(policy, |m| {
                assert_eq!(m.live_bytes(), 0);
                super::support::RefusalRun::of(m)
            }))
        })
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
        recorded_run(|run| {
            let policy = run.observed_policy(POOL);
            run.holding(
                decoder(wire),
                Retirement::Released,
                &Unwitnessed,
                |operation| {
                    operation.drive_faulted(
                        policy,
                        decode_turns(wire.len()),
                        Retirement::Released,
                        Fault {
                            refusal: Refusal::For(stop, reason),
                            cancel: true,
                        },
                        |_, _| {},
                        |_| panic!("invalid input published"),
                    )?;
                    Ok::<_, Finding>(())
                },
            )?;
            Ok(run.with_policy(policy, |m| {
                assert_eq!(m.first_refusal(), Some((stop, reason)));
                assert_eq!(m.injected_refusals(), 1);
                assert_eq!(m.calls(), &baseline[..=stop], "{reason:?} at call {stop}");
                assert_eq!(m.live_bytes(), 0);
                m.reached()
            }))
        })
    });
}

// Prior art: tokio-util/tests/length_delimited.rs,
// read_incomplete_head_multi and read_incomplete_payload: suspension must not
// turn an incomplete item into success or consume its terminal error.
#[test]
fn malformed_inputs_stay_invalid_and_cancel_cleanly_at_every_refusal() -> Result<(), Vec<Finding>> {
    every_fixture(INVALID.len(), |fixture| {
        let wire = INVALID[fixture];
        invalid_matrix(&format!("malformed {wire:02x?}"), wire);
        Ok(())
    })
}

#[test]
fn every_truncation_of_nested_literal_input_resumes_to_error_without_replay()
-> Result<(), Vec<Finding>> {
    let complete = [
        0x82, 0x82, 0x01, 0x62, 0xc3, 0xa9, 0xa1, 0x00, 0x43, 1, 2, 3,
    ];
    every_fixture(complete.len(), |end| {
        invalid_matrix(&format!("truncated at {end}"), &complete[..end]);
        Ok(())
    })
}
