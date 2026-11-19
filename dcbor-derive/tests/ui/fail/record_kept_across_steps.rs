// A binding cannot keep its record past the step that minted it: the record
// bears the step's brand `'b`, invariant, and the step is generic over it, so
// a record stored where it outlives the step needs `'b: 'static`, which no
// such step can show (a lifetime error). Control:
// tests/data/controls/record-brand-contravariant.patch.
use std::cell::RefCell;

use dcbor::bounded::decode::construction::in_place::{
    BindingContext, Building, Built, ConstructionCost, InPlace, Initialized, reported, step, unit,
};
use dcbor::bounded::decode::construction::reclamation::{
    Cleanup, PeekSlot, Reclaim, Reclaimed, Slot, Written,
};
use dcbor::bounded::decode::ConstructResult;
use dcbor::bounded::{Allocator, BoundedResult, CustodySink, Limits, PermitsObserved};

struct Kept;

thread_local! {
    static KEPT: RefCell<Option<Initialized<'static, Kept>>> = const { RefCell::new(None) };
}

unsafe impl<A: Allocator> Reclaim<A> for Kept {
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

unsafe impl<A: Allocator> InPlace<A> for Kept {
    const COST: ConstructionCost = ConstructionCost::fixed(dcbor::const_cost!(unit(0).checked_mul(2)));

    fn build_step<'b>(ctx: BindingContext<'b, '_, '_, '_, Self, A>, a: &mut A) -> ConstructResult<Building<'b, Self>, A> {
        step(a)?;
        let assembly = ctx.assembly();
        *ctx.into_slot().custody() = Written::Initialized;
        // SAFETY: the zero-sized value is initialized whole by the admitted unit.
        let Building::Done(record) = (unsafe { reported(Built::Done, assembly) }) else { return Ok(Building::Progress) };
        KEPT.with(|kept| *kept.borrow_mut() = Some(record));
        Ok(Building::Progress)
    }
}

fn main() {
    let _ = Kept;
    let _ = <Kept as InPlace<Limits>>::COST;
}
