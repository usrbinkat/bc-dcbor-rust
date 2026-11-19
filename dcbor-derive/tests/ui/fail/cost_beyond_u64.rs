// A hand-written binding whose cost composition does not fit in u64: its
// `COST`, unwrapped by `const_cost!`, fails to compile where the binding is
// used with a concrete allocator, never wrapping and never panicking at run
// time.
#[path = "../support/huge.rs"]
mod huge;

use dcbor::bounded::decode::construction::in_place::{BindingContext, Building, Built, ConstructionCost, InPlace, reported, step, unit};
use dcbor::bounded::decode::construction::reclamation::{
    Cleanup, PeekSlot, Reclaim, Reclaimed, Slot, Written,
};
use dcbor::bounded::decode::ConstructResult;
use dcbor::bounded::{Allocator, BoundedResult, CustodySink, Limits, PermitsObserved};

struct Overflowing;

unsafe impl<A: Allocator> Reclaim<A> for Overflowing {
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

unsafe impl<A: Allocator> InPlace<A> for Overflowing {
    // The oversized binding's cost and one more unit.
    const COST: ConstructionCost = dcbor::const_cost!(
        <huge::Huge as InPlace<A>>::COST.checked_add(ConstructionCost::fixed(unit(0)))
    );

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

fn main() {
    let _ = <Overflowing as InPlace<Limits>>::COST;
}
