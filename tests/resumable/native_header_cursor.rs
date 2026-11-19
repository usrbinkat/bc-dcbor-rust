use super::harness::*;
use super::support::{
    Fault, Finding, Retirement, exhausted, pipeline::Unwitnessed, recorded_run, refusal_matrix,
    refuse, rigor::rigor, scheduled,
};
use dcbor::bounded::decode::{DecodeError, header::HeaderCursor};
use dcbor::bounded::{Failure, Step, WriteWork};

/// What stepping a header cursor reached: a head's argument and encoded
/// length, its rejection, or a cancellation.
enum Read {
    Header { argument: u64, length: usize },
    Invalid,
    Cancelled,
}

/// Step a header cursor over `wire` under `fault`, one turn per step, with
/// its exact per-turn oracles: the bytes acquired and the next unit's work
/// bound, within a quantum, are unchanged by a refused step and advance by
/// exactly one byte otherwise. A refused step is retried in the next turn,
/// or, when the fault cancels, the cursor is dropped there; it owns nothing.
/// Returns what it reached and the calls attempted.
fn read_header(wire: &[u8], fault: Fault) -> (Read, super::support::RefusalRun) {
    recorded_run(|run| {
        let policy = run.observed_policy(POOL);
        run.holding(
            HeaderCursor::new(wire),
            Retirement::Released,
            &Unwitnessed,
            |held| {
                held.with_policy(policy, |cursor, m| {
                    refuse(m, fault.refusal);
                    // Each byte and the validation, each possibly refused once.
                    for at in 0..2 * (wire.len() + 1) + 1 {
                        let acquired = cursor.acquired();
                        let bound = cursor.next_work();
                        if let Some(bound) = bound {
                            assert!(TURN.covers(&bound));
                        }
                        match scheduled(m, cursor, at)? {
                            Ok(Step::Progress) => assert_eq!(cursor.acquired(), acquired + 1),
                            Ok(Step::Complete(header)) => {
                                assert_eq!(cursor.next_work(), None);
                                exhausted(m, cursor);
                                assert_eq!(m.live_bytes(), 0);
                                let read = Read::Header {
                                    argument: header.argument,
                                    length: header.length,
                                };
                                return Ok((read, super::support::RefusalRun::of(m)));
                            }
                            Err(error) if error.refused() => {
                                assert_eq!(
                                    cursor.acquired(),
                                    acquired,
                                    "a refused step acquired a byte"
                                );
                                assert_eq!(
                                    cursor.next_work(),
                                    bound,
                                    "a refused step moved the cursor"
                                );
                                if fault.cancel && m.injected_refusals() > 0 {
                                    return Ok((
                                        Read::Cancelled,
                                        super::support::RefusalRun::of(m),
                                    ));
                                }
                            }
                            Err(DecodeError::Invalid(_)) => {
                                assert_eq!(cursor.acquired(), wire.len());
                                exhausted(m, cursor);
                                m.assert_units(TURN);
                                assert_eq!(m.live_bytes(), 0);
                                return Ok((Read::Invalid, super::support::RefusalRun::of(m)));
                            }
                            other => {
                                return Err(Finding::Driver(format!(
                                    "unexpected header outcome {other:?}"
                                )));
                            }
                        }
                    }
                    Err(Finding::Driver(format!(
                        "the header cursor exceeded its bound over {wire:02x?}"
                    )))
                })
            },
        )
    })
}

// RocksDB db/log_test.cc NonBlockingReadFullRecord and TailLog_PartialHeader:
// exercise the retained reader, positively observe the interruption, then
// require literal completion. Here complete input stays immutably borrowed.
#[test]
fn production_header_cursor_retains_each_byte_before_and_after_refusal() {
    let wire = [0x1b, 0, 0, 0, 1, 0, 0, 0, 0];
    let baseline = refusal_matrix("header cursor of a wide head", rigor(), |fault: Fault| {
        let (read, calls) = read_header(&wire, fault);
        match read {
            Read::Header { argument, length } => {
                assert_eq!(argument, 4_294_967_296);
                assert_eq!(length, 9);
            }
            Read::Cancelled => assert!(fault.cancel),
            Read::Invalid => panic!("a canonical head was rejected"),
        }
        calls
    });
    // Each of the nine bytes and the head's validation is one unit, of one
    // value each and eighteen bytes together.
    assert_eq!(baseline.calls().len(), 10);
    recorded_run(|run| {
        let policy = run.observed_policy(POOL);
        run.holding(
            HeaderCursor::new(&wire),
            Retirement::Released,
            &Unwitnessed,
            |held| {
                held.with_policy(policy, |cursor, m| {
                    for at in 0..baseline.calls().len() {
                        if let Err(error) = scheduled(m, cursor, at)? {
                            return Err(Finding::Driver(format!(
                                "a canonical head was not read: {error:?}"
                            )));
                        }
                    }
                    assert_eq!(m.used(), WriteWork::new(10, 18));
                    assert_eq!(cursor.next_work(), None);
                    Ok(())
                })
            },
        )
    });
}

#[test]
fn retained_header_rejects_truncation_after_observed_refusal() -> Result<(), Vec<Finding>> {
    let complete = [0x1b, 0, 0, 0, 1, 0, 0, 0, 0];
    every_fixture(complete.len(), |end| {
        refusal_matrix(
            &format!("header cursor truncated at {end}"),
            rigor(),
            |fault: Fault| {
                let (read, calls) = read_header(&complete[..end], fault);
                match read {
                    Read::Invalid => {}
                    Read::Cancelled => assert!(fault.cancel),
                    Read::Header { .. } => panic!("a truncated head published"),
                }
                calls
            },
        );
        Ok(())
    })
}

#[test]
fn retained_header_never_publishes_nonminimal_or_reserved_encodings() -> Result<(), Vec<Finding>> {
    let invalid: &[&[u8]] = &[
        &[0x18, 0x17],
        &[0x19, 0, 0xff],
        &[0x1a, 0, 0, 0xff, 0xff],
        &[0x1b, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff],
        &[0x1c],
        &[0x1d],
        &[0x1e],
        &[0x1f],
    ];
    every_fixture(invalid.len(), |fixture| {
        let wire = invalid[fixture];
        let baseline = refusal_matrix(
            &format!("header cursor of {wire:02x?}"),
            rigor(),
            |fault: Fault| {
                let (read, calls) = read_header(wire, fault);
                match read {
                    Read::Invalid => {}
                    Read::Cancelled => assert!(fault.cancel),
                    Read::Header { .. } => panic!("{wire:02x?} published"),
                }
                calls
            },
        );
        // Each byte and the rejecting validation.
        assert_eq!(baseline.calls().len(), wire.len() + 1);
        Ok(())
    })
}
