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
//! # Unwind
//!
//! The loops the domain reaches, each with its most iterations:
//!
//! - `decode_with`'s node loop (decode.rs:387): one head of at least a byte
//!   per iteration, so at most [`INPUT`]; its completion loop (:506) at most
//!   the frames open, [`DEPTH`], and the root's;
//! - `Owned::reserve`'s growth loop (`bounded.rs`:1799): one growth, four
//!   elements holding every node of [`INPUT`] bytes;
//! - strict validation's normalization (`text.rs` `normalize`, :263-295):
//!   per scalar and per part at most three; a release's counting pass
//!   (`Normalizer::release`, :139-176) clears and sums a table of every
//!   combining class, 256 iterations (:156, `CLASSES` :68), reached by a
//!   text holding a combining part, "a" and U+0301 among the domain's;
//! - the bound's own: `Terms::peak_of`'s splits (:706) at most [`INPUT`];
//!   the places' folds over 7 decode and 5 validation places (`bounded.rs`
//!   `additive`, :669).
//!
//! The longest is the counting pass's 256: `kani::unwind(257)`, its
//! iterations and its exit.
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

/// The longest input of the domain.
const INPUT: usize = 4;

/// The deepest nesting limit of the domain.
const DEPTH: usize = 2;

/// None, or any index.
fn any_index() -> Option<u64> {
    if kani::any() { Some(kani::any()) } else { None }
}

/// Every input of the domain, under one refusal at any one attempt and one
/// at any one request, is decoded or
/// refused within its bound: the work admitted, the bytes requested, the
/// most held at once and what the published document retains, each at most
/// the bound's; a refused decode returns its refusal and retains nothing;
/// nothing is held once the result drops.
#[kani::proof]
#[kani::unwind(257)]
#[kani::stub(crate::float::narrowed, crate::float::proofs::from_f64_contract)]
#[kani::stub(crate::float::widened, crate::float::proofs::to_f64_contract)]
fn the_decode_bound_covers_every_input() {
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
    let bound = decode_bound_with::<()>(length as u64, options).expect("the domain's bound fits");
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
