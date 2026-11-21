//! Kani harness of the decode's whole-operation bound (register item 4),
//! written and unverified until the gate runs it: [`decode_bound_with`]
//! covers what [`decode_with`] admits, requests, holds at once and retains,
//! unrefused and under a policy refusal at any one admission attempt or
//! allocation request, for every input of the domain. Policy refusal at
//! every attempt and request is covered; physical reservation failure is
//! not: `Vec::try_reserve_exact` under Kani's allocator never fails, so the
//! `Effect::Failed` paths are outside the domain.
//!
//! Domain, stated: every input of at most [`INPUT`] bytes, every byte any
//! value (every head of every major type, payloads, nesting, map keys in and
//! out of order, malformed and truncated inputs), every nesting limit up to
//! [`DEPTH`], under both text policies, and one refusal at any one attempt
//! and one at any one request (each index any `u64` or none, an index past
//! the run's last refusing nothing). The decode is synchronous and ends at
//! its first refusal, which every admission and growth returns through `?`
//! (decode.rs `decode_with`, :387-493), so at most one of the two refuses in
//! a run and no loop gains an iteration for a refusal. Granted bytes are
//! checked against the bound's `allocated` (`ResourceBound::allocated`,
//! `bounded.rs`:2151-2152); every attempted request's bytes, the refused one
//! included, against `allocated` and one request more, at most the bound's
//! `peak`, since a granted request's bytes are held at once
//! (`ResourceBound::peak`, :2153-2155). At
//! [`INPUT`] bytes a text payload holds at most three bytes, one scalar of
//! up to three bytes or three of one, so strict validation runs its
//! normalization over every text of that size.
//!
//! Exhaustion over larger inputs is beyond a bounded model checker. The
//! general argument for every length is the bound's own decomposition
//! (`Terms`): each node's head, payload, completion and key comparison is
//! one admission bounded by a constant or by its own bytes (the charge
//! rules `HEAD`, `PAYLOAD`, `COMPLETION`, `KEY`); the node count is at most
//! the input's bytes; the arenas grow by the growth recurrence, whose
//! closed form `owned_growth` has its own harness (`growth_proofs.rs`); and
//! text validation is `text::validation_bound`'s. Each premise is a
//! harness of its own: the arena growth (`growth_proofs.rs`), the head
//! (`header/proofs.rs` for the retained cursor's; this harness for the flat
//! decoder's), and text validation (`text/proofs.rs`, every UTF-8 text of at
//! most six bytes). Each written and unverified until the gate runs it.
//!
//! # Instances
//!
//! The domain is checked one size at a time: each instance fixes the input's
//! length, the nesting limit and the text policy, and leaves every byte any
//! value. The production bound is computed for those constants
//! ([`decode_bound_with`]), so symbolic execution reduces it to constants and
//! every loop's trip count follows from the instance's own bytes; the union of
//! the instances is the domain stated above. The property is one body,
//! [`check`]; the instances calling it are declared once, with their unwinds
//! and stubs, in `tests/data/proofs/instances.rs`, which `build.rs` generates
//! them from and the gate's census expects them by.
//!
//! # Unwind
//!
//! The loops an instance of `LEN` bytes reaches, each with its most
//! iterations:
//!
//! - `decode_with`'s node loop: one head of at least a byte per iteration,
//!   at most `LEN`, and its exit; its completion loop at most the frames
//!   open, at most [`DEPTH`], and the root's;
//! - UTF-8 validation, the quick check and normalization: at most one
//!   iteration per payload byte, fewer than `LEN`;
//! - `Owned::reserve`'s growth loop: one growth, four elements holding every
//!   node of at most [`INPUT`] bytes;
//! - `Normalizer::release`'s passes over its waiting parts: at most the
//!   parts of one text of fewer than `LEN` bytes.
//!
//! The claim is that each is within `LEN + 2` iterations, the instance's
//! `kani::unwind`; the unwinding assertions, which stay on, are what check it,
//! and an instance whose loop needs more fails. The release's prefix sum over
//! every combining class takes 256 iterations whatever the text; its bound is
//! the code's, declared once in the policy's function scope
//! (`tests/data/proofs/loop-bounds.json`).
//!
//! # The `half` conversion
//!
//! A two-byte float head (`f9 xx xx`, within [`INPUT`] bytes) reaches the
//! binary16 adapters (`crate::float::widened`, decode.rs:456, and
//! `crate::float::narrowed` through `validate_canonical_f16`, :455), whose `half`
//! dispatch is x86 inline assembly and F16C intrinsics Kani does not model.
//! Both adapters are stubbed with their exactness contracts
//! (`float/proofs.rs` `from_f64_contract`, `to_f64_contract`), the same
//! stubs `decode/proofs.rs` uses; the contracts themselves are checked
//! exhaustively over every binary16 pattern, natively and under Miri
//! (`float.rs` tests, `float/proofs.rs` "The `half` conversion").
//! Compiled only under `cfg(kani)`.

use super::super::proof_budget::Counting;
use super::{BoundedError, DecodeError, Options, TextPolicy, decode_bound_with, decode_with};
use TextPolicy::{Normalize, QuickOnly};

/// The longest input of the domain.
const INPUT: usize = 4;

/// The deepest nesting limit of the domain.
const DEPTH: usize = 2;

/// None, or any index.
fn any_index() -> Option<u64> {
    if kani::any() { Some(kani::any()) } else { None }
}

/// Every input of `LEN` bytes, under nesting limit `max_depth` and the
/// text policy `text`, and under one refusal at any one attempt and one at
/// any one request, is decoded or refused within its bound: the work
/// admitted, the bytes requested, the most held at once and what the
/// published document retains, each at most the bound's; a refused decode
/// returns its refusal and retains nothing; nothing is held once the result
/// drops.
fn check<const LEN: usize>(max_depth: usize, text: TextPolicy) {
    const { assert!(LEN <= INPUT, "an instance is within the domain's inputs") };
    assert!(
        max_depth <= DEPTH,
        "an instance is within the domain's nesting limits"
    );
    let bytes: [u8; LEN] = kani::any();
    let options = Options { max_depth, text };
    let input = &bytes[..];
    let bound = decode_bound_with::<()>(LEN as u64, options).expect("the domain's bound fits");
    let mut policy = Counting::scheduled(any_index(), any_index());
    let decoded = decode_with(input, options, &mut policy);
    let retained = policy.live();
    let returned_refusal = matches!(
        decoded,
        Err(DecodeError::Resource(BoundedError::Refused(())))
    );
    drop(decoded);
    assert!(
        policy.live() == 0,
        "nothing is held once the document drops"
    );
    if policy.refused {
        assert!(returned_refusal, "a refused decode returns its refusal");
        assert!(retained == 0, "a refused decode retains nothing");
    }
    assert!(
        bound.work().covers(&policy.admitted),
        "the decode admits no more work than its bound"
    );
    assert!(
        policy.granted <= bound.allocated,
        "the decode requests no more than its bound"
    );
    assert!(
        u128::from(policy.requested) <= u128::from(bound.allocated) + u128::from(bound.peak),
        "the decode's attempted requests, a refused one included, are within its bound and one request more"
    );
    assert!(
        policy.peak <= bound.peak,
        "the decode holds no more at once than its bound"
    );
    assert!(
        retained <= bound.retained,
        "the decode's document retains no more than its bound"
    );
}

// The instances, declared in tests/data/proofs/instances.rs and generated
// by build.rs: every input length through INPUT, every nesting limit
// through DEPTH, both text policies.
include!(concat!(env!("OUT_DIR"), "/proof_instances/decode.rs"));
