//! Allocation refusal must not replay an already admitted construction unit.
//!
//! One allocation request refused three times in a row, at the binding level
//! (no scope): the schedule no matrix stage makes. `support::refusal_matrix`
//! refuses each admission once, since a refused step leaves its state
//! unchanged and a second refusal repeats the same transition; that argument
//! is checked here for the one call whose refusal keeps admissions across
//! attempts, the metadata block's request, whose write and release were
//! admitted before it. The admitted trace must equal the unobstructed one, so
//! no prepaid admission is repeated. Ownership after every single refusal and
//! after a cancellation at every call is the matrix's, for the same types:
//! `refused_allocations_conserve_construction_work` (`tests/reclamation_owner.rs`).
use dcbor::bounded::decode::construction::in_place::{InPlace, StableOption};
use dcbor::bounded::{Call, Limits};
use dcbor_test_support as support;

#[global_allocator]
static HEAP: support::heap::Heap = support::heap::Heap;

/// Admitted calls of constructing `T` from the literal 1 with the first
/// `refusals` allocation requests refused.
fn run<T: InPlace<Limits>>(refusals: usize) -> Vec<Call> {
    let (built, accounting) = support::construction_requests::<T>(&[1], None, refusals, |_| {});
    assert!(built.built);
    accounting.request_refusals(refusals);
    accounting.into_admitted()
}

#[test]
fn native_option_retains_metadata_admission_across_allocation_refusal() {
    assert_eq!(run::<Option<u64>>(3), run::<Option<u64>>(0));
}

#[test]
fn stable_option_retains_metadata_admission_across_allocation_refusal() {
    assert_eq!(
        run::<StableOption<u64, Limits>>(3),
        run::<StableOption<u64, Limits>>(0)
    );
}
