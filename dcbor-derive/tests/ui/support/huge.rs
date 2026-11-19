// A binding whose declared fixed cost is every value `u64` holds: a valid
// cost alone, which overflows in any composition that adds to it.
use dcbor::bounded::decode::construction::in_place::{
    BindingContext, Building, Built, ConstructionCost, InPlace, reported, step,
};
use dcbor::bounded::decode::construction::reclamation::{
    Cleanup, PeekSlot, Reclaim, Reclaimed, Slot, Written,
};
use dcbor::bounded::decode::ConstructResult;
use dcbor::bounded::{Allocator, BoundedResult, CustodySink, PermitsObserved, ResourceBound};

pub struct Huge;

unsafe impl<A: Allocator> Reclaim<A> for Huge {
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

unsafe impl<A: Allocator> InPlace<A> for Huge {
    const COST: ConstructionCost = ConstructionCost::fixed(ResourceBound {
        values: u64::MAX,
        bytes: 0,
        allocated: 0,
        peak: 0,
        retained: 0,
    });

    fn build_step<'b>(ctx: BindingContext<'b, '_, '_, '_, Self, A>, a: &mut A) -> ConstructResult<Building<'b, Self>, A> {
        step(a)?;
        let assembly = ctx.assembly();
        *ctx.into_slot().custody() = Written::Initialized;
        // SAFETY: a unit owns nothing and reads no node: the admitted unit initializes it whole.
        Ok(unsafe { reported(Built::Done, assembly) })
    }
}
