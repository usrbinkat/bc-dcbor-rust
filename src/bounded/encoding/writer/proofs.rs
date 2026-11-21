//! Kani harness of the emission's whole-operation bound (register item 4),
//! written and unverified until the gate runs it:
//! [`emit_bound`] covers what the one segment routine
//! ([`PlanView::segment`], shared by the borrowed writer, the owned writer
//! and publication in place) admits over a whole emission, and the emission
//! completes within the bound's steps.
//!
//! Domain, stated: every well-formed plan of at most [`BYTES`] plan bytes
//! and at most [`GAPS`] header gaps, every gap position and width. A plan
//! is well formed as preparation leaves it: gaps in increasing order, each
//! within the bytes and followed by at least one byte of its own (a gap
//! precedes a head of at least one byte, so a plan of `len` encoded bytes
//! has at most `len` gaps), and the encoded length the plan's bytes less its
//! gaps. The bytes' values do not enter the segment routine, so they are
//! fixed. [`BYTES`] exceeds two quanta of 64, so a segment cut by the
//! quantum, by a gap and by the plan's end are all in the domain. And one
//! refusal at any one attempt (the index any `u64` or none); emission
//! allocates nothing, so no request is refused. A refused unit moves nothing
//! (`segment` admits before it advances), so the emission steps on after it.
//!
//! The emission's own loop runs at most `ceil(BYTES / 64) + GAPS + GAPS + 1`
//! = 8 times (each gap ends one segment early and is passed in a unit of its
//! own), and the one refused call: 9, `kani::unwind(12)`. The decode's and the preparation's
//! whole-operation bounds have their own harnesses
//! (`bounded/decode/decode_proofs.rs`, `encoding/preparation_proofs.rs`).
//!
//! [`the_owned_emission_bound_covers_every_owned_write`] checks
//! [`owned_emit_bound`] against [`Prepared::encode_owned`]: the output's
//! release admitted, its storage requested and allocated, its
//! initialization, the write and the published encoding, unrefused and
//! under a policy refusal at any one admission attempt or allocation
//! request. Domain: every well-formed plan, as above, of at most
//! [`OWNED_BYTES`] plan bytes (past one quantum) and [`GAPS`] gaps, and one
//! refusal at any one attempt and one at any one request (each index any
//! `u64` or none). The write is synchronous and ends at its first refusal,
//! which every admission and the grant return through `?`
//! (`Prepared::encode_owned`, writer.rs:233-284), so at most one of the two
//! refuses in a run and no loop gains an iteration for a refusal. Granted
//! bytes are checked against the bound's `allocated`
//! (`ResourceBound::allocated`, `bounded.rs`:2151-2152); every attempted
//! request's bytes, the refused one included, against `allocated` and one
//! request more, at most the bound's `peak` (`ResourceBound::peak`,
//! :2153-2155). Policy refusal at every attempt and request is covered;
//! physical reservation failure is not: `Vec::try_reserve_exact` under
//! Kani's allocator never fails. Its loops: the plan's pushes, at most
//! [`OWNED_BYTES`] and [`GAPS`]; `Owned::reserve`'s growths, at most six
//! (`bounded.rs`:1799); the output's `resize` (writer.rs:275), one
//! iteration per byte, at most [`OWNED_BYTES`]; `encode_into`'s segment loop
//! (:190), at most `ceil(OWNED_BYTES / 64) + 2 GAPS + 1` = 7; and the
//! places' fold, 5. The longest, the plan's pushes and the output's resize,
//! 66 iterations each: `kani::unwind(67)`, held by each loop's unwinding
//! assertion.
//!
//! Both bounds, [`emit_bound`] and [`owned_emit_bound`], are checked
//! arithmetic on the encoded length (`Capped::covering`, `Unit::times`,
//! `Scan::units`, a fold over the fixed places) and hold no loop whose trip
//! count depends on it, so each harness computes its bound for the symbolic
//! encoded length directly.
//!
//! Compiled only under `cfg(kani)`.

use super::super::super::proof_budget::{Counting, Permit};
use super::*;

/// The most plan bytes of the domain: past two quanta.
const BYTES: usize = 130;

/// The most header gaps of the domain.
const GAPS: usize = 2;

/// Every well-formed plan's emission, under one refusal at any one attempt,
/// completes within [`emit_bound`]'s steps and the one refused call,
/// writing its whole encoded length, and admits no more work than the
/// bound; a refused unit moves nothing.
#[kani::proof]
#[kani::unwind(12)]
fn the_emission_bound_covers_every_emission() {
    let bytes = [0u8; BYTES];
    let length: usize = kani::any();
    kani::assume(length <= BYTES);
    let holes: [(usize, usize); GAPS] = kani::any();
    let count: usize = kani::any();
    kani::assume(count <= GAPS);
    let mut previous_end = 0usize;
    let mut skipped = 0usize;
    for &(start, skip) in &holes[..count] {
        kani::assume(start >= previous_end && start <= length);
        kani::assume(skip <= length - start);
        // A gap precedes a head byte of its own.
        kani::assume(start + skip < length);
        previous_end = start + skip + 1;
        skipped += skip;
    }
    let len = length - skipped;
    let view = PlanView {
        bytes: &bytes[..length],
        holes: &holes[..count],
        len,
    };
    let bound = emit_bound::<()>(len as u64).expect("the bound of the domain fits");
    let steps = bound.steps::<()>().expect("the steps of the domain fit");
    let mut at = EmitPosition::default();
    let mut budget = Counting::scheduled(any_index(), None);
    // The emission is stepped to its outcome, each call counted; the loop's
    // unwinding assertion establishes that every run reaches it within the
    // harness's unwind. Findings recorded in the loop and asserted after it,
    // so every run reaches the same tail.
    let mut calls = 0u64;
    let mut moved_on_refusal = false;
    let mut failed = false;
    loop {
        calls += 1;
        let before = at;
        match view.segment(&mut at, &mut budget) {
            Ok(Segment::Skip | Segment::Bytes(_)) => {}
            Ok(Segment::Complete) => break,
            Err(BoundedError::Refused(())) => moved_on_refusal |= at != before,
            Err(_) => {
                failed = true;
                break;
            }
        }
    }
    assert!(!moved_on_refusal, "a refused unit moves nothing");
    assert!(!failed, "a well-formed plan's emission fails");
    assert!(
        u128::from(calls) <= u128::from(steps) + 1,
        "the emission completes within its bound's steps and the one refused call"
    );
    assert!(at.written == len, "the emission writes the whole encoding");
    assert!(
        bound.work().covers(&budget.admitted),
        "the emission admits no more than its bound"
    );
}

/// The most plan bytes of the owned write's domain: past one quantum.
const OWNED_BYTES: usize = 66;

/// None, or any index.
fn any_index() -> Option<u64> {
    if kani::any() { Some(kani::any()) } else { None }
}

/// Every well-formed plan's owned write, under one refusal at any one
/// attempt and one at any one request, is
/// within [`owned_emit_bound`]: the work admitted, the bytes requested, the
/// most held at once and what the published encoding retains, each at most
/// the bound's; an unrefused write publishes the whole encoding; a refused
/// write returns its refusal and retains nothing; nothing is held once the
/// result drops.
#[kani::proof]
#[kani::unwind(67)]
fn the_owned_emission_bound_covers_every_owned_write() {
    let length: usize = kani::any();
    kani::assume(length <= OWNED_BYTES);
    let holes: [(usize, usize); GAPS] = kani::any();
    let count: usize = kani::any();
    kani::assume(count <= GAPS);
    let mut previous_end = 0usize;
    let mut skipped = 0usize;
    for &(start, skip) in &holes[..count] {
        kani::assume(start >= previous_end && start <= length);
        kani::assume(skip <= length - start);
        // A gap precedes a head byte of its own.
        kani::assume(start + skip < length);
        previous_end = start + skip + 1;
        skipped += skip;
    }
    let len = length - skipped;
    // The plan, built under a policy of its own: the write's policy sees
    // only the write.
    let mut planner = Counting::new(false);
    let owner = planner
        .owner()
        .expect("an unrecording budget names an owner");
    let mut bytes: Owned<u8, Permit> = Owned::new();
    for _ in 0..length {
        bytes
            .push(0, &mut planner, &owner)
            .expect("an unrefusing planner grants the plan");
    }
    let mut gaps: Owned<(usize, usize), Permit> = Owned::new();
    for &hole in &holes[..count] {
        gaps.push(hole, &mut planner, &owner)
            .expect("an unrefusing planner grants the gaps");
    }
    let plan = Prepared {
        bytes,
        holes: gaps,
        len,
        bytes_owner: None,
        holes_owner: None,
    };
    let bound = owned_emit_bound::<Permit, ()>(len as u64).expect("the domain's bound fits");
    let mut policy = Counting::scheduled(any_index(), any_index());
    let written = plan.encode_owned(&mut policy);
    let retained = policy.live();
    let returned_refusal = matches!(written, Err(BoundedError::Refused(())));
    let published = written
        .as_ref()
        .map(|encoded| AsRef::<[u8]>::as_ref(encoded).len())
        .ok();
    drop(written);
    assert!(
        policy.live() == 0,
        "nothing is held once the owned encoding drops"
    );
    if policy.refused {
        assert!(
            returned_refusal,
            "a refused owned write returns its refusal"
        );
        assert!(retained == 0, "a refused owned write retains nothing");
    } else {
        assert!(
            published == Some(len),
            "an unrefused owned write publishes the whole encoding"
        );
    }
    assert!(
        bound.work().covers(&policy.admitted),
        "the owned write admits no more work than its bound"
    );
    assert!(
        policy.granted <= bound.allocated,
        "the owned write requests no more than its bound"
    );
    assert!(
        u128::from(policy.requested) <= u128::from(bound.allocated) + u128::from(bound.peak),
        "the owned write's attempted requests, a refused one included, are within its bound and one request more"
    );
    assert!(
        policy.peak <= bound.peak,
        "the owned write holds no more at once than its bound"
    );
    assert!(
        retained <= bound.retained,
        "the owned write's encoding retains no more than its bound"
    );
}
