// A cleanup step is given the engine's cleanup capability, through which no
// new allocation can be requested: it implements no `Allocator`, so the call
// below is refused (E0599), `Allocator` being in scope so that nothing else
// refuses it. Control: tests/data/controls/cleanup-grants-allocation.patch.
use dcbor::bounded::decode::construction::reclamation::{
    Cleanup, PeekSlot, Reclaim, Reclaimed, Slot, Written,
};
use dcbor::bounded::{Allocator, BoundedResult, CustodySink, Limits, PermitsObserved, Reservation};

struct Leaf;

// SAFETY: the binding owns nothing; its one cleanup unit is `Done`.
unsafe impl Reclaim<Limits> for Leaf {
    type State = Written;
    const INITIAL: Written = Written::Empty;

    fn reclaim_step(
        _: Slot<'_, Self, Written>,
        cleanup: &mut Cleanup<'_, Limits>,
    ) -> BoundedResult<Reclaimed, Limits> {
        let _permit = cleanup.allocate(8);
        Ok(Reclaimed::Done)
    }

    fn remaining(_: PeekSlot<'_, Self, Written>) -> Option<u64> {
        Some(1)
    }

    fn observe_permits(
        _: PeekSlot<'_, Self, Written>,
        _: &mut dyn CustodySink<Reservation>,
    ) -> PermitsObserved {
        PermitsObserved::Complete
    }
}

fn main() {}
