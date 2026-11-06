// A binding whose declared fixed cost is every value `u64` holds: a valid
// cost alone, which overflows in any composition that adds to it.
use dcbor::bounded::decode::construction::in_place::{Built, ConstructionCost, InPlace, step};
use dcbor::bounded::decode::construction::reclamation::{
    PeekSlot, Reclaim, Reclaimed, Slot, Written,
};
use dcbor::bounded::decode::{ConstructResult, Document};
use dcbor::bounded::{Allocator, BoundedResult, ResourceBound};

pub struct Huge;

unsafe impl<A: Allocator> Reclaim<A> for Huge {
    type State = Written;
    const INITIAL: Written = Written::Empty;

    fn reclaim_step(mut slot: Slot<'_, Self, Written>, a: &mut A) -> BoundedResult<Reclaimed, A> {
        step(a)?;
        *slot.custody() = Written::Empty;
        Ok(Reclaimed::Done)
    }

    fn remaining(_: PeekSlot<'_, Self, Written>) -> u64 {
        1
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

    fn build_step(
        _: &Document<'_, A::Permit>,
        _: usize,
        mut slot: Slot<'_, Self, Written>,
        a: &mut A,
    ) -> ConstructResult<Built, A> {
        step(a)?;
        *slot.custody() = Written::Initialized;
        Ok(Built::Done)
    }
}
