// A hand-written binding whose cost composition does not fit in u64: its
// `COST`, unwrapped by `const_cost!`, fails to compile where the binding is
// used with a concrete allocator, never wrapping and never panicking at run
// time.
#[path = "../support/huge.rs"]
mod huge;

use dcbor::bounded::decode::construction::in_place::{Built, ConstructionCost, InPlace, step, unit};
use dcbor::bounded::decode::construction::reclamation::{
    PeekSlot, Reclaim, Reclaimed, Slot, Written,
};
use dcbor::bounded::decode::{ConstructResult, Document};
use dcbor::bounded::{Allocator, BoundedResult, Limits};

struct Overflowing;

unsafe impl<A: Allocator> Reclaim<A> for Overflowing {
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

unsafe impl<A: Allocator> InPlace<A> for Overflowing {
    // The oversized binding's cost and one more unit.
    const COST: ConstructionCost = dcbor::const_cost!(
        <huge::Huge as InPlace<A>>::COST.checked_add(ConstructionCost::fixed(unit(0)))
    );

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

fn main() {
    let _ = <Overflowing as InPlace<Limits>>::COST;
}
