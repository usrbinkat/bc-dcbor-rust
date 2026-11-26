// A binding cannot hold its record from construction into cleanup: its
// state outlives every step, and the record bears the step's brand `'b`,
// invariant, so storing it in the state needs `'b: 'static`, which no such
// step can show (a lifetime error). Control:
// tests/data/controls/record-brand-contravariant.patch.
use dcbor::bounded::decode::ConstructResult;
use dcbor::bounded::decode::construction::in_place::{
    BindingContext, Building, Built, ConstructionCost, InPlace, Initialized, reported, step, unit,
};
use dcbor::bounded::decode::construction::reclamation::{
    Cleanup, Custody, PeekSlot, Reclaim, Reclaimed, Slot,
};
use dcbor::bounded::{Allocator, BoundedResult, CustodySink, Limits, PermitsObserved};

struct Lingering;

/// The record held from construction for cleanup to read.
struct Held(Option<Initialized<'static, Lingering>>);

impl Custody for Held {
    type Observation = bool;

    fn observe(&mut self) -> bool {
        self.0.is_some()
    }
}

unsafe impl<A: Allocator> Reclaim<A> for Lingering {
    type State = Held;
    const INITIAL: Held = Held(None);

    fn reclaim_step(
        mut slot: Slot<'_, Self, Held>,
        cleanup: &mut Cleanup<'_, A>,
    ) -> BoundedResult<Reclaimed, A> {
        step(cleanup)?;
        let held = slot.custody().0.take();
        drop(held);
        Ok(Reclaimed::Done)
    }

    fn remaining(_: PeekSlot<'_, Self, Held>) -> Option<u64> {
        Some(1)
    }

    fn observe_permits(
        _: PeekSlot<'_, Self, Held>,
        _: &mut dyn CustodySink<A::Permit>,
    ) -> PermitsObserved {
        PermitsObserved::Complete
    }
}

unsafe impl<A: Allocator> InPlace<A> for Lingering {
    const COST: ConstructionCost =
        ConstructionCost::fixed(dcbor::const_cost!(unit(0).checked_mul(2)));

    fn build_step<'b>(
        ctx: BindingContext<'b, '_, '_, '_, Self, A>,
        a: &mut A,
    ) -> ConstructResult<Building<'b, Self>, A> {
        step(a)?;
        let assembly = ctx.assembly();
        let mut slot = ctx.into_slot();
        let (place, state) = slot.parts();
        // SAFETY: the zero-sized value is written whole by the admitted unit.
        unsafe { place.write(state, Lingering) };
        // SAFETY: as above.
        let Building::Done(record) = (unsafe { reported(Built::Done, assembly) }) else {
            return Ok(Building::Progress);
        };
        let _ = state.0.replace(record);
        Ok(Building::Progress)
    }
}

fn main() {
    let _ = Lingering;
    let _ = <Lingering as InPlace<Limits>>::COST;
}
