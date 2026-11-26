// A payload declaring the dispatch-depth limit puts its construction record
// one level beyond it: decoding it fails to compile, so no step can reach it.
#[path = "../support/policy.rs"]
mod policy;

use dcbor::bounded::decode::ConstructResult;
use dcbor::bounded::decode::construction::in_place::{
    BindingContext, Building, Built, ConstructionCost, InPlace, reported, step, unit,
};
use dcbor::bounded::decode::construction::reclamation::{
    Cleanup, MAX_DISPATCH_DEPTH, PeekSlot, Reclaim, Reclaimed, Slot, Written,
};
use dcbor::bounded::decode::construction::{Borrowed, OwnedInitialized, TypedDecoder};
use dcbor::bounded::{Allocator, BoundedResult, CustodySink, PermitsObserved};

struct AtLimit;

unsafe impl<A: Allocator> Reclaim<A> for AtLimit {
    const DISPATCH_DEPTH: usize = MAX_DISPATCH_DEPTH;
    type State = Written;
    const INITIAL: Written = Written::Empty;

    fn reclaim_step(
        mut slot: Slot<'_, Self, Written>,
        cleanup: &mut Cleanup<'_, A>,
    ) -> BoundedResult<Reclaimed, A> {
        step(cleanup)?;
        *slot.custody() = Written::Empty;
        Ok(Reclaimed::Done)
    }

    fn remaining(_: PeekSlot<'_, Self, Written>) -> Option<u64> {
        Some(1)
    }

    fn observe_permits(
        _: PeekSlot<'_, Self, Written>,
        _: &mut dyn CustodySink<A::Permit>,
    ) -> PermitsObserved {
        PermitsObserved::Complete
    }
}

unsafe impl<A: Allocator> InPlace<A> for AtLimit {
    const COST: ConstructionCost =
        ConstructionCost::fixed(dcbor::const_cost!(unit(0).checked_mul(2)));

    fn build_step<'b>(
        ctx: BindingContext<'b, '_, '_, '_, Self, A>,
        a: &mut A,
    ) -> ConstructResult<Building<'b, Self>, A> {
        step(a)?;
        let assembly = ctx.assembly();
        *ctx.into_slot().custody() = Written::Initialized;
        // SAFETY: a unit owns nothing and reads no node: the admitted unit initializes it whole.
        Ok(unsafe { reported(Built::Done, assembly) })
    }
}

fn decode(input: OwnedInitialized<'static, Borrowed<'static>, policy::Policy>) {
    let mut decoder = TypedDecoder::<_, AtLimit, _>::new(input);
    let _ = decoder.step(&mut policy::Policy);
}

fn main() {
    let _: fn(OwnedInitialized<'static, Borrowed<'static>, policy::Policy>) = decode;
}
