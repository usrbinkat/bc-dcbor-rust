//! Kani harness of strict NFC validation's bound (register item 4), written
//! and unverified until the gate runs it: [`validation_bound`] covers what
//! [`is_normalized`] admits, requests and holds at once, unrefused and under
//! a policy refusal at any one admission attempt or allocation request, for
//! every text of the domain, and the validation releases everything it
//! allocated. The premise the decode's whole-operation bound rests on for
//! its texts (`decode/decode_proofs.rs`). Policy refusal at every attempt
//! and request is covered; physical reservation failure is not:
//! `Vec::try_reserve_exact` under Kani's allocator never fails, so the
//! `Effect::Failed` paths are outside the domain.
//!
//! Domain, stated: every UTF-8 text of at most [`TEXT`] bytes, every byte
//! any value constrained only to be UTF-8: every scalar of one to four bytes
//! and every sequence of them that fits, combining marks, Hangul and
//! decomposable scalars included; and one refusal at any one attempt and one
//! at any one request (each index any `u64` or none, an index past the run's
//! last refusing nothing). The validation is synchronous and ends at its
//! first refusal, which every admission and growth returns through `?`
//! (`text.rs` `is_normalized` and `normalize`, :263-365), so at most one of
//! the two refuses in a run and no loop gains an iteration for a refusal.
//! Granted bytes are checked against the bound's `allocated`
//! (`ResourceBound::allocated`, `bounded.rs`:2151-2152); every attempted
//! request's bytes, the refused one included, against `allocated` and one
//! request more, at most the bound's `peak` (`ResourceBound::peak`,
//! :2153-2155). The bound is
//! taken at the text and its one-byte head (`validation_bound` bounds every
//! text of an input of that many bytes).
//!
//! # Unwind
//!
//! The loops reached, each with its most iterations: the quick check and
//! `normalize`'s per-scalar loop (`text.rs`:279) at most [`TEXT`] scalars;
//! each scalar's decomposition at most [`super::MAX_SCALAR_PARTS`] parts;
//! a release's counting pass (`Normalizer::release`, :139-176) over its
//! waiting parts, at most [`TEXT`], and its table of every combining class,
//! 256 iterations (:156, `CLASSES` :68); `Owned::reserve`'s growth loop
//! (`bounded.rs`:1799) and the bound's `owned_growth` (:1977), at most four
//! growths at the 21 normal-form bytes of a seven-byte input
//! (`PART_BYTES_PER_BYTE`, :404); the places' folds over 5 places
//! (`bounded.rs` `additive`, :669). The longest is the counting pass's 256:
//! `kani::unwind(257)`, its iterations and its exit. Compiled only under
//! `cfg(kani)`.

use super::super::proof_budget::Counting;
use super::{BoundedError, is_normalized, validation_bound};

/// The longest text of the domain.
const TEXT: usize = 6;

/// None, or any index.
fn any_index() -> Option<u64> {
    if kani::any() { Some(kani::any()) } else { None }
}

/// Every text of the domain, under one refusal at any one attempt and one at
/// any one request, is validated or
/// refused within its bound; a refused validation returns its refusal; it
/// holds nothing once it returns.
#[kani::proof]
#[kani::unwind(257)]
fn the_validation_bound_covers_every_text() {
    let bytes: [u8; TEXT] = kani::any();
    let length: usize = kani::any();
    kani::assume(length <= TEXT);
    kani::assume(core::str::from_utf8(&bytes[..length]).is_ok());
    let text = core::str::from_utf8(&bytes[..length]).expect("assumed UTF-8");
    let bound = validation_bound::<()>(length as u64 + 1).expect("the domain's bound fits");
    let mut policy = Counting::scheduled(any_index(), any_index());
    let validated = is_normalized(text, &mut policy);
    let returned_refusal = matches!(validated, Err(BoundedError::Refused(())));
    let completed = validated.is_ok();
    assert!(
        policy.live() == 0,
        "the validation releases everything it allocated"
    );
    if policy.refused {
        assert!(returned_refusal, "a refused validation returns its refusal");
    } else {
        assert!(completed, "an unrefusing validation completes");
    }
    assert!(
        bound.work().covers(&policy.admitted),
        "the validation admits no more work than its bound"
    );
    assert!(
        policy.granted <= bound.allocated,
        "the validation requests no more than its bound"
    );
    assert!(
        u128::from(policy.requested) <= u128::from(bound.allocated) + u128::from(bound.peak),
        "the validation's attempted requests, a refused one included, are within its bound and one request more"
    );
    assert!(
        policy.peak <= bound.peak,
        "the validation holds no more at once than its bound"
    );
}
