//! Kani harness of the header cursor's whole-operation bound (register item
//! 4), written and unverified until the gate runs it: [`header_bound`]
//! covers every admission a [`HeaderCursor`] makes to its outcome, and the
//! cursor reaches it within the bound's steps and the one refused call, under
//! a policy refusal at any one admission attempt.
//!
//! Domain, stated: every input of 0 to [`MAX_HEAD_LEN`] bytes, every byte
//! any value: every head, valid or not, and every input that ends inside
//! one; and one refusal at any one attempt: none, or the admission at any attempt
//! index (`u64`, an index past the run's last refusing nothing). A refusal
//! keeps the cursor's bytes and offset (`HeaderCursor`'s contract,
//! header.rs:39), so the harness steps on after it. The cursor allocates
//! nothing, so no request is refused. The cursor acquires at most nine bytes
//! and validates once, so its loop runs at most ten times and the one
//! refused call: eleven, `kani::unwind(12)`.
//!
//! The domain is checked one input length at a time: each instance fixes
//! the length and leaves every byte any value, so [`header_bound`] is
//! computed for a constant and the loop's trip count is the cursor's own;
//! the union of the instances, every length through [`MAX_HEAD_LEN`], is
//! the domain. The property is one body, [`check`]. Compiled only under
//! `cfg(kani)`.

use super::super::super::proof_budget::Counting;
use super::{BoundedError, DecodeError, HeaderCursor, MAX_HEAD_LEN, Step, header_bound};

/// None, or any index.
fn any_index() -> Option<u64> {
    if kani::any() { Some(kani::any()) } else { None }
}

/// Every input of `LEN` bytes is acquired and validated within
/// [`header_bound`]'s steps and the one refused call, to a head or to its
/// refusal as invalid input, admitting no more work than the bound; a
/// refused step changes nothing the cursor holds.
fn check<const LEN: usize>() {
    const { assert!(LEN <= MAX_HEAD_LEN, "an instance is within a head's bytes") };
    let bytes: [u8; LEN] = kani::any();
    let input = &bytes[..];
    let bound = header_bound(LEN as u64);
    let steps = bound.steps::<()>().expect("a head's steps fit");
    let mut cursor = HeaderCursor::new(input);
    let mut budget = Counting::scheduled(any_index(), None);
    // The cursor is stepped to its outcome, each call counted; the loop's
    // unwinding assertion establishes that every run reaches it within the
    // harness's unwind. Findings recorded in the loop and asserted after it,
    // so every run reaches the same tail.
    let mut calls = 0u64;
    let mut changed_on_refusal = false;
    let mut finished_early = false;
    loop {
        calls += 1;
        let before = cursor.position();
        match cursor.step(&mut budget) {
            Ok(Step::Progress) => {}
            Err(DecodeError::Resource(BoundedError::Refused(()))) => {
                changed_on_refusal |= cursor.position() != before;
            }
            // A head, or its refusal as invalid input: the outcome.
            Ok(Step::Complete(_)) | Err(_) => break,
            Ok(Step::Finished) => {
                finished_early = true;
                break;
            }
        }
    }
    assert!(
        !changed_on_refusal,
        "a refused step changes nothing the cursor holds"
    );
    assert!(!finished_early, "the cursor finished before its outcome");
    assert!(
        u128::from(calls) <= u128::from(steps) + 1,
        "the cursor reaches its outcome within its bound's steps and the one refused call"
    );
    assert!(
        bound.work().covers(&budget.admitted),
        "the cursor admits no more than its bound"
    );
}

// The instances, declared in tests/data/proofs/instances.rs and generated
// by build.rs: every input length through MAX_HEAD_LEN.
include!(concat!(env!("OUT_DIR"), "/proof_instances/header.rs"));
