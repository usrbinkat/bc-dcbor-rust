#![cfg(feature = "std")]

use dcbor::bounded::decode::construction::TypedDecoder;
use dcbor::bounded::decode::construction::in_place::{
    Built, ConstructionCost, InPlace, plus, unit,
};
use dcbor::bounded::decode::construction::reclamation::{
    PeekSlot, Reclaim, Reclaimed, Slot, Written,
};
use dcbor::bounded::decode::{ConstructResult, DecodeError, Document, Options, wrong_type};
use dcbor::bounded::{Allocator, BoundedError, BoundedResult, Limits};
use dcbor_test_support as support;
use std::sync::atomic::{AtomicUsize, Ordering};

static STARTS: AtomicUsize = AtomicUsize::new(0);
static DROPS: AtomicUsize = AtomicUsize::new(0);
static CLEANED: AtomicUsize = AtomicUsize::new(0);

struct Fails;
impl Drop for Fails {
    fn drop(&mut self) {
        DROPS.fetch_add(1, Ordering::SeqCst);
    }
}

// SAFETY: the zero-sized value is initialized in one admitted unit. Its state
// records completion before the later transition intentionally returns an error.
unsafe impl<A: Allocator> InPlace<A> for Fails {
    // Two build units, the second failing, and one cleanup unit.
    const COST: ConstructionCost = ConstructionCost::fixed(plus(plus(unit(0), unit(0)), unit(0)));

    #[expect(
        clippy::disallowed_methods,
        reason = "a third-party binding admits its own work, as `InPlace` documents"
    )]
    fn build_step(
        _: &Document<'_, A::Permit>,
        _: usize,
        mut slot: Slot<'_, Self, Written>,
        a: &mut A,
    ) -> ConstructResult<Built, A> {
        let (place, state) = slot.parts();
        a.traverse(1, 0).map_err(BoundedError::Refused)?;
        if *state == Written::Empty {
            // SAFETY: the slot pairs the place with this state, which is
            // empty; the write admitted above.
            unsafe { place.write(state, Self) };
            *state = Written::Initialized;
            STARTS.fetch_add(1, Ordering::SeqCst);
            return Ok(Built::Progress);
        }
        Err(wrong_type())
    }
}

// SAFETY: no child resources; explicit cleanup invalidates the initialized ZST
// exactly once and never invokes its synchronous destructor.
unsafe impl<A: Allocator> Reclaim<A> for Fails {
    type State = Written;
    const INITIAL: Written = Written::Empty;

    #[expect(
        clippy::disallowed_methods,
        reason = "a third-party binding admits its own cleanup, as `Reclaim` documents"
    )]
    fn reclaim_step(mut slot: Slot<'_, Self, Written>, a: &mut A) -> BoundedResult<Reclaimed, A> {
        a.traverse(1, 0).map_err(BoundedError::Refused)?;
        let state = slot.custody();
        if *state != Written::Empty {
            CLEANED.fetch_add(1, Ordering::SeqCst);
            *state = Written::Empty;
        }
        Ok(Reclaimed::Done)
    }

    /// One call, which is `Done`.
    fn remaining(_: PeekSlot<'_, Self, Written>) -> u64 {
        1
    }
}

#[test]
fn terminal_error_does_not_reinitialize_or_destroy_partial_construction() {
    let mut limits = Limits::unlimited().logged().strict();
    let wire = [0xf6];
    let (mut owner, input) = support::open(&mut limits, &wire);
    let held = limits.live_bytes();
    let mut decoder = TypedDecoder::<_, Fails, _>::new(input, Options::normalizing(8));
    let bound = support::typed_turns::<Fails>(wire.len());
    let failed = support::fail_within(&mut limits, &mut decoder, bound);
    assert!(
        matches!(failed, DecodeError::Invalid(_)),
        "invalid typed construction was published or never failed"
    );
    assert_eq!(STARTS.load(Ordering::SeqCst), 1);
    assert_eq!(DROPS.load(Ordering::SeqCst), 0);
    assert!(limits.live_bytes() > held);
    support::finish_within(&mut limits, &mut decoder, bound);
    assert_eq!(STARTS.load(Ordering::SeqCst), 1);
    assert_eq!(CLEANED.load(Ordering::SeqCst), 1);
    assert_eq!(DROPS.load(Ordering::SeqCst), 0);
    assert_eq!(
        owner.outstanding(),
        0,
        "Finished retained operation records"
    );
    drop(decoder);
    support::drain(&mut owner, &mut limits);
    assert_eq!(limits.live_bytes(), 0);
}
