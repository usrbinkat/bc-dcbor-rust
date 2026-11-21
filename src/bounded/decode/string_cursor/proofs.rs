//! Kani harness of the string decode's whole-operation bound (register item
//! 4), written and unverified until the gate runs it: [`string_bound`]
//! covers what a [`StringDecoder`] (the retained parse, the inspection, the
//! string's release, allocation and copies, and publication) admits,
//! requests, holds at once and retains, to its outcome, unrefused and under
//! a policy refusal at any one admission attempt or allocation request, for
//! every input of the domain. A refusal is not terminal (`StringDecoder::step`
//! ends the decode only on another error): the harness steps on after it,
//! and the refused step changes nothing the decode reports
//! ([`StringDecoder::position`]). Policy refusal at every attempt and
//! request is covered; physical reservation failure is not:
//! `String::try_reserve_exact` under Kani's allocator never fails.
//!
//! Domain, stated: every input of at most [`INPUT`] bytes, every byte any
//! value (texts of up to three payload bytes, every other major type the
//! wrong type, malformed and truncated inputs), every nesting limit up to
//! [`DEPTH`], under both text policies, and one refusal at any one attempt
//! and one at any one request (each index any `u64` or none, an index past
//! the run's last refusing nothing). Both may refuse in one run: each is
//! resumed. A refused request is retried, so the attempted requests may
//! exceed the granted ones by that one request; granted bytes are checked
//! against the bound's `allocated` (`ResourceBound::allocated`,
//! `bounded.rs`:2151-2152), every attempted request's bytes against
//! `allocated` and one request more, at most the bound's `peak`, since a
//! granted request's bytes are held at once (`ResourceBound::peak`,
//! :2153-2155). The parse's own bound is `cursor::retained_decode_bound`, a
//! term of this one.
//!
//! # Unwind
//!
//! The driver steps the decode to its outcome and counts its calls; the
//! count is asserted within [`crate::bounded::ResourceBound::steps`], the
//! sum of admitted values and allocated bytes, and the two refused calls.
//! Values alone do not bound the calls: a step can make an allocation
//! request without admitting a value. The loop's limit is not derived from
//! the bound, so the observation stays independent of it.
//!
//! `kani::unwind(378)` is the verification limit of every instance, not a
//! derivation from the bound's values. Its enabled unwinding assertions must
//! establish that every reachable loop, the driver and cleanup included,
//! fits this limit over the instance's domain; a reachable iteration beyond
//! it fails verification. The instances are declared once, with their
//! unwinds and stubs, in `tests/data/proofs/instances.rs`.
//!
//! # The `half` conversion
//!
//! A two-byte float head within [`INPUT`] bytes reaches the retained parse's
//! binary16 adapters (`crate::float::widened` and `crate::float::narrowed`
//! through `validate_canonical_f16`, cursor.rs:750-753),
//! whose `half` dispatch is x86 inline assembly and F16C intrinsics Kani
//! does not model. Both are stubbed with their exactness contracts
//! (`float/proofs.rs` `from_f64_contract`, `to_f64_contract`), as in
//! `decode/proofs.rs`; the contracts are checked exhaustively over every
//! binary16 pattern, natively and under Miri (`float.rs` tests). Compiled
//! only under `cfg(kani)`.

use super::super::super::proof_budget::{Counting, Permit};
use super::{BoundedError, DecodeError, Options, Step, StringDecoder, TextPolicy, string_bound};
use TextPolicy::{Normalize, QuickOnly};

/// The longest input of the domain.
const INPUT: usize = 4;

/// The deepest nesting limit of the domain.
const DEPTH: usize = 2;

/// None, or any index.
fn any_index() -> Option<u64> {
    if kani::any() { Some(kani::any()) } else { None }
}

/// Every input of `LEN` bytes, under nesting limit `max_depth` and the text
/// policy `text`, and under one refusal at any one attempt and one at any
/// one request, reaches its outcome (a published string or a terminal error)
/// within its bound's steps and the two refused calls; the work admitted,
/// the bytes granted, the most held at once and what the published string
/// retains are each at most the bound's, and the bytes requested at most the
/// bound's and one request more; a refused step changes nothing the decode
/// reports; nothing is held once the decode and its string drop. The domain
/// is checked one length, nesting limit and policy at a time, so
/// [`string_bound`] is computed for constants; the union of the instances
/// is the domain stated above.
fn check<const LEN: usize>(max_depth: usize, text: TextPolicy) {
    const { assert!(LEN <= INPUT, "an instance is within the domain's inputs") };
    assert!(
        max_depth <= DEPTH,
        "an instance is within the domain's nesting limits"
    );
    let bytes: [u8; LEN] = kani::any();
    let options = Options { max_depth, text };
    let input = &bytes[..];
    let bound =
        string_bound::<Permit, (), ()>(LEN as u64, options).expect("the domain's bound fits");
    let steps = bound.steps::<()>().expect("the domain's steps fit");
    let mut policy = Counting::scheduled(any_index(), any_index());
    let mut decoder = StringDecoder::<Permit, ()>::new(input, options);
    let mut string = None;
    // The decode is stepped to its outcome, each call counted; the loop's
    // unwinding assertion establishes that every run reaches it within the
    // harness's unwind. Findings recorded in the loop and asserted after the
    // cleanup tail, so every run drops what it holds before any assertion.
    let mut calls = 0u64;
    let mut changed_on_refusal = false;
    let mut finished_early = false;
    loop {
        calls += 1;
        let before = decoder.position();
        match decoder.step(&mut policy) {
            Ok(Step::Progress) => {}
            Err(DecodeError::Resource(BoundedError::Refused(()))) => {
                changed_on_refusal |= decoder.position() != before;
            }
            Ok(Step::Complete(published)) => {
                string = Some(published);
                break;
            }
            Ok(Step::Finished) => {
                finished_early = true;
                break;
            }
            // A terminal error: the outcome.
            Err(_) => break,
        }
    }
    let retained = policy.live();
    drop(string);
    drop(decoder);
    assert!(
        policy.live() == 0,
        "nothing is held once the decode and its string drop"
    );
    assert!(
        !changed_on_refusal,
        "a refused step changes nothing the decode reports"
    );
    assert!(!finished_early, "the decode finished before its outcome");
    assert!(
        u128::from(calls) <= u128::from(steps) + 2,
        "the string decode reaches its outcome within its bound's steps and the two refused calls"
    );
    assert!(
        bound.work().covers(&policy.admitted),
        "the string decode admits no more work than its bound"
    );
    assert!(
        policy.granted <= bound.allocated,
        "the string decode requests no more than its bound"
    );
    assert!(
        u128::from(policy.requested) <= u128::from(bound.allocated) + u128::from(bound.peak),
        "the string decode's attempted requests, a refused one retried, are within its bound and one request more"
    );
    assert!(
        policy.peak <= bound.peak,
        "the string decode holds no more at once than its bound"
    );
    assert!(
        retained <= bound.retained,
        "the string decode's string retains no more than its bound"
    );
}

// The instances, declared in tests/data/proofs/instances.rs and generated
// by build.rs: every input length through INPUT, every nesting limit
// through DEPTH, both text policies.
include!(concat!(env!("OUT_DIR"), "/proof_instances/string.rs"));
