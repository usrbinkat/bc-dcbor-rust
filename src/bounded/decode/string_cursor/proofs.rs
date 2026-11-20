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
//! The driver uses [`crate::bounded::ResourceBound::steps`], the sum of
//! admitted values and allocated bytes, plus the two refused calls. Values
//! alone do not bound this loop: a step can make an allocation request
//! without admitting a value. The driver stops at its outcome, which can
//! precede that conservative limit.
//!
//! `kani::unwind(378)` is a separate verification limit, not a derivation
//! from the bound's values. Its enabled unwinding assertions must establish
//! that every reachable loop, including the driver and cleanup, fits this
//! limit over the whole domain. A reachable iteration beyond it fails
//! verification; the harness does not assume early completion.
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

use super::super::super::proof_budget::{Counting, Permit, decode_bound_at};
use super::{BoundedError, DecodeError, Options, Step, StringDecoder, TextPolicy, string_bound};

/// The longest input of the domain.
const INPUT: usize = 4;

/// The deepest nesting limit of the domain.
const DEPTH: usize = 2;

/// None, or any index.
fn any_index() -> Option<u64> {
    if kani::any() { Some(kani::any()) } else { None }
}

/// Every input of the domain, under one refusal at any one attempt and one
/// at any one request, reaches its outcome (a published string or a
/// terminal error) within its bound's steps and the two refused calls; the
/// work admitted, the bytes granted, the most held at once and what the
/// published string retains are each at most the bound's, and the bytes
/// requested at most the bound's and one request more; a refused step
/// changes nothing the decode reports; nothing is held once the decode and
/// its string drop.
#[kani::proof]
#[kani::unwind(378)]
#[kani::stub(crate::float::narrowed, crate::float::proofs::from_f64_contract)]
#[kani::stub(crate::float::widened, crate::float::proofs::to_f64_contract)]
fn the_string_bound_covers_every_input() {
    let bytes: [u8; INPUT] = kani::any();
    let length: usize = kani::any();
    kani::assume(length <= INPUT);
    let max_depth: usize = kani::any();
    kani::assume(max_depth <= DEPTH);
    let options = Options {
        max_depth,
        text: if kani::any() {
            TextPolicy::Normalize
        } else {
            TextPolicy::QuickOnly
        },
    };
    let input = &bytes[..length];
    let bound = decode_bound_at(length, options, INPUT, DEPTH, |size, case| {
        string_bound::<Permit, (), ()>(size, case).expect("the domain's bound fits")
    });
    let steps = bound.steps::<()>().expect("the domain's steps fit");
    let mut policy = Counting::scheduled(any_index(), any_index());
    let mut decoder = StringDecoder::<Permit, ()>::new(input, options);
    let mut ended = false;
    let mut string = None;
    // Findings recorded in the loop and asserted after the cleanup tail, so
    // every run drops what it holds before any assertion.
    let mut changed_on_refusal = false;
    let mut finished_early = false;
    for _ in 0..steps + 2 {
        let before = decoder.position();
        match decoder.step(&mut policy) {
            Ok(Step::Progress) => {}
            Err(DecodeError::Resource(BoundedError::Refused(()))) => {
                changed_on_refusal |= decoder.position() != before;
            }
            Ok(Step::Complete(published)) => {
                string = Some(published);
                ended = true;
                break;
            }
            Ok(Step::Finished) => {
                finished_early = true;
                break;
            }
            Err(_) => {
                ended = true;
                break;
            }
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
        ended,
        "the string decode reaches its outcome within its bound's steps"
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
