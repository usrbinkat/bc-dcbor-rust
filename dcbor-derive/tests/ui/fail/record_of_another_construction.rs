// A binding cannot present a record minted under another brand, one that
// another construction's step left behind: its step is generic over its own
// brand `'b`, invariant, so a record of any other lifetime is no record of
// this step (a lifetime error). Control:
// tests/data/controls/record-brand-covariant.patch.
use std::sync::Mutex;

use dcbor::bounded::decode::construction::in_place::{
    BindingContext, Building, ConstructionCost, InPlace, Initialized, step, unit,
};
use dcbor::bounded::decode::construction::reclamation::{
    Cleanup, PeekSlot, Reclaim, Reclaimed, Slot, Written,
};
use dcbor::bounded::decode::ConstructResult;
use dcbor::bounded::{Allocator, BoundedResult, CustodySink, Limits, PermitsObserved};

struct Presented;

static LEFT: Mutex<Option<Initialized<'static, Presented>>> = Mutex::new(None);

unsafe impl<A: Allocator> Reclaim<A> for Presented {
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

unsafe impl<A: Allocator> InPlace<A> for Presented {
    const COST: ConstructionCost = ConstructionCost::fixed(dcbor::const_cost!(unit(0).checked_mul(2)));

    fn build_step<'b>(ctx: BindingContext<'b, '_, '_, '_, Self, A>, a: &mut A) -> ConstructResult<Building<'b, Self>, A> {
        step(a)?;
        *ctx.into_slot().custody() = Written::Initialized;
        let left = LEFT.lock().ok().and_then(|mut left| left.take());
        match left {
            Some(record) => Ok(Building::Done(record)),
            None => Ok(Building::Progress),
        }
    }
}

fn main() {
    let _ = Presented;
    let _ = <Presented as InPlace<Limits>>::COST;
}
