//! The crate's aborts, witnessed from outside the process. An abort ends the
//! process, so each witness re-runs this test binary on one scenario alone
//! and requires it to be killed by `SIGABRT`: never to exit, to panic once
//! and unwind, or to return. Every abort is `abort` in the decode scope
//! (`std::process::abort` with `std`, a panic while panicking without),
//! reached directly or through its abort-on-unwind guard. This target is
//! compiled with and without `std`, so each build witnesses its own abort
//! path.
//!
//! - A record that cleans up beyond the count it declared is a defect the
//!   scope refuses; when the authority is dropped, the terminal drain meets
//!   that refusal and, by contract, aborts.
//! - A release observer that panics would unwind out of the cleanup step
//!   releasing a permit, leaving that step's state recording what it no
//!   longer holds; the release aborts instead.

use dcbor::bounded::decode::construction::{Acquisition, DecodeOwner};
use dcbor::bounded::{Allocator, Limits};
use dcbor_test_support as support;

/// The defective-record scenario's test name.
const DEFECTIVE_RECORD: &str = "a_defective_record_left_to_the_terminal_drain";

/// The panicking-observer scenario's test name.
const PANICKING_OBSERVER: &str = "a_release_observer_that_panics";

/// The defective scenario: a queued record declaring one cleanup call but
/// taking three ([`support::Understated`]), its scope retired by the run's
/// holding. The terminal drain removes the record, spends its one declared
/// call, and is refused the next as a defect, which aborts. Returning from
/// this test is the failure the witness detects.
#[test]
#[ignore = "run only as the abort witness's child: it ends its own process"]
fn a_defective_record_left_to_the_terminal_drain() {
    // The record retires to the queue as a published handle; the scope's
    // retirement is its authority's terminal destruction, whose drain meets
    // the understated count and aborts before the run can finalize.
    support::recorded_run(|run| {
        let policy = run.policy(u64::MAX);
        run.holding(
            DecodeOwner::new(),
            support::Retirement::Scope,
            &support::pipeline::Unwitnessed,
            |owner| {
                owner.initialize(policy)?;
                owner.lending(support::Retirement::Exhausted, support::Lent::new, |view| {
                    let scope = view.value().get();
                    view.holding(
                        Acquisition::<support::Understated, Limits>::new(),
                        support::Retirement::Stopped,
                        |acquisition| {
                            acquisition.acquire(policy, scope, |record| {
                                support::understate(record.value(), 2)
                            })
                        },
                    )
                })?;
                Ok::<_, support::Finding>(())
            },
        )
    });
}

/// A release observer that breaks its contract by panicking.
fn panicking_observer(_: u64) {
    panic!("a release observer panicked");
}

/// The panicking-observer scenario: a reservation released under a policy
/// whose release observer panics. The release aborts; an unwind out of it,
/// which a caught panic would let a cleanup step resume half done, is the
/// failure the witness detects, as is returning.
#[test]
#[ignore = "run only as the abort witness's child: it ends its own process"]
fn a_release_observer_that_panics() {
    let mut m = Limits::unlimited().observe_releases(panicking_observer);
    let permit = m.allocate(8).expect("an unlimited policy admits");
    drop(permit);
}

/// The SIGABRT signal number on the Unix hosts this suite runs on.
#[cfg(unix)]
const SIGABRT: i32 = 6;

/// Run `child`, a scenario of this binary, alone in a child process, and
/// require it to be killed by `SIGABRT`.
#[cfg(unix)]
fn aborts(child: &str) {
    use std::os::unix::process::ExitStatusExt;
    let output = std::process::Command::new(std::env::current_exe().expect("this test binary"))
        .args([
            "--ignored",
            "--exact",
            child,
            "--test-threads=1",
            "--nocapture",
        ])
        .output()
        .expect("the child scenario runs");
    assert_eq!(
        output.status.signal(),
        Some(SIGABRT),
        "{child} did not abort: {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

/// The defective record, left to the terminal drain, aborts the process.
#[cfg(unix)]
#[test]
fn a_defect_in_the_terminal_drain_aborts_the_process() {
    aborts(DEFECTIVE_RECORD);
}

/// A release observer that panics aborts the process instead of unwinding
/// out of the release.
#[cfg(unix)]
#[test]
fn a_panicking_release_observer_aborts_the_process() {
    aborts(PANICKING_OBSERVER);
}
