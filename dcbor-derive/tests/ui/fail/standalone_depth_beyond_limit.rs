// A root declaring one dispatch level past the limit, built by the
// standalone driver: creating the driver fails to compile, as a scope
// record's allocation does, so no step can reach it. Control:
// tests/data/controls/standalone-depth-unchecked.patch.
use core::mem::MaybeUninit;
use dcbor::bounded::decode::construction::in_place::{
    BindingContext, Building, Built, ConstructionCost, InPlace, reported, step, unit,
};
use dcbor::bounded::decode::construction::reclamation::{
    Cleanup, MAX_DISPATCH_DEPTH, PeekSlot, Reclaim, Reclaimed, Slot, Written,
};
use dcbor::bounded::decode::construction::Standalone;
use dcbor::bounded::decode::{ConstructResult, decode};
use dcbor::bounded::{Allocator, BoundedResult, CustodySink, Limits, PermitsObserved};

struct BeyondLimit;

unsafe impl<A: Allocator> Reclaim<A> for BeyondLimit {
    const DISPATCH_DEPTH: usize = MAX_DISPATCH_DEPTH + 1;
    type State = Written;
    const INITIAL: Written = Written::Empty;

    fn reclaim_step(mut slot: Slot<'_, Self, Written>, cleanup: &mut Cleanup<'_, A>) -> BoundedResult<Reclaimed, A> {
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

unsafe impl<A: Allocator> InPlace<A> for BeyondLimit {
    const COST: ConstructionCost = ConstructionCost::fixed(dcbor::const_cost!(unit(0).checked_mul(2)));

    fn build_step<'b>(ctx: BindingContext<'b, '_, '_, '_, Self, A>, a: &mut A) -> ConstructResult<Building<'b, Self>, A> {
        step(a)?;
        let assembly = ctx.assembly();
        *ctx.into_slot().custody() = Written::Initialized;
        // SAFETY: a unit owns nothing and reads no node: the admitted unit initializes it whole.
        Ok(unsafe { reported(Built::Done, assembly) })
    }
}

fn main() {
    let mut parser = Limits::unlimited();
    let document = decode(&[0xf6], 1, &mut parser).unwrap();
    let mut value = MaybeUninit::<BeyondLimit>::uninit();
    let _ = Standalone::<BeyondLimit, Limits>::new(&document, &mut value);
}
