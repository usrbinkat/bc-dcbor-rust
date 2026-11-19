//! In-place byte buffers beside their private native representation.
extern crate alloc;
use super::ByteString;
use crate::bounded::decode::construction::{
    in_place::{
        BindingContext, Building, Built, ConstructionCost, InPlace, Placeholder, rejected,
        reported,
        text::{
            Buffer, BufferState, buffer_cost, buffer_permits, buffer_remaining, copy_buffer,
            reclaim_buffer,
        },
    },
    reclamation::{Cleanup, PeekSlot, Reclaim, Reclaimed, Slot},
    stable::Pending,
};
use crate::bounded::decode::{ConstructResult, Kind};
use crate::bounded::{Allocator, BoundedResult, CustodySink, PermitsObserved};
use alloc::vec::Vec;

// SAFETY: resources: an empty native byte buffer owns no allocation and has
// no element destructor. bounded: `Vec::new` allocates nothing and writes a
// fixed-size header.
unsafe impl Placeholder for ByteString {
    fn placeholder() -> Self {
        Self(Vec::new())
    }
}

// SAFETY: an empty byte string owns no allocation; its vector is its own,
// and dropping it frees only that vector; any bytes are a valid byte string,
// so every position is a boundary.
unsafe impl Buffer for ByteString {
    type Source = [u8];

    fn empty() -> Self {
        Self(Vec::new())
    }

    fn source(source: &[u8]) -> &[u8] {
        source
    }

    fn boundary(_: &[u8], _: usize) -> bool {
        true
    }

    unsafe fn bytes(&mut self) -> &mut Vec<u8> {
        &mut self.0
    }
}

// SAFETY: admission, state, done, escape, provenance and order: the shared
// byte-buffer engine's (`copy_buffer`, `in_place/text.rs`, the one engine of
// String and ByteString): admission: each phase (release, allocation,
// header, each quantum of bytes) is admitted before it runs. state: its
// phases record the header, the payload's permit and the bytes copied,
// before each step returns, on error too. done: `Done` only once every byte
// is copied into the header it wrote, its phase `Complete`. escape: the
// buffer's pointer stays in the header the value owns. provenance: the
// header is written through the slot's place. order: a step whose source
// does not continue the copy, or one past completion or in cleanup, is
// refused and changes nothing. A node of the wrong kind is refused by one
// admitted unit (`rejected`). cost: `buffer_cost::<Self, A::Permit>()`, the
// engine's own.
unsafe impl<A: Allocator> InPlace<A> for ByteString {
    const COST: ConstructionCost = crate::const_cost!(buffer_cost::<Self, A::Permit>());

    fn build_step<'b>(
        ctx: BindingContext<'b, '_, '_, '_, Self, A>,
        a: &mut A,
    ) -> ConstructResult<Building<'b, Self>, A> {
        let Some(Kind::Bytes(bytes)) = ctx.node().map(|n| n.kind()) else {
            return rejected(a);
        };
        let assembly = ctx.assembly();
        let (slot, pending) = ctx.into_acquiring();
        let built = Self::copy_step(bytes, slot, pending, a)?;
        // SAFETY: the buffer engine reports `Done` only once every byte is
        // copied into the header it wrote, its phase `Complete`.
        Ok(unsafe { reported(built, assembly) })
    }
}

impl ByteString {
    /// Initialize a byte buffer in stable storage using the same custody
    /// phases as typed construction, from `source`, which every step of one
    /// copy passes alike: a step whose source does not continue the copy is
    /// refused ([`copy_buffer`]). Its acquisitions' credit is held in
    /// `pending`, its holder's.
    pub(crate) fn copy_step<A: Allocator>(
        source: &[u8],
        slot: Slot<'_, Self, BufferState<A::Permit>>,
        pending: &mut Pending<A::Origin>,
        a: &mut A,
    ) -> BoundedResult<Built, A> {
        copy_buffer::<Self, A>(source, slot, pending, a)
    }
}

// SAFETY: initial: `BufferState::INITIAL`, nothing installed or allocated.
// state: the buffer state records the installed header, the payload's
// permit and its phase. admission: each cleanup unit of the shared engine
// (`reclaim_buffer`) is admitted before it runs, a refusal changing nothing.
// cleanup: the native buffer contains bytes only; its allocation is released
// before either permit, no element destructor runs, nothing is allocated and
// nothing unwinds. done: `Done` once the buffer and both permits are
// released. order: a step after `Done` reports `Done`; the count and the
// observation read the state alone. depth: a leaf, the default 1. count:
// `buffer_remaining` counts the units left.
unsafe impl<A: Allocator> Reclaim<A> for ByteString {
    type State = BufferState<A::Permit>;
    const INITIAL: Self::State = BufferState::INITIAL;

    fn reclaim_step(
        slot: Slot<'_, Self, Self::State>,
        cleanup: &mut Cleanup<'_, A>,
    ) -> BoundedResult<Reclaimed, A> {
        reclaim_buffer::<Self, A>(slot, cleanup)
    }

    fn remaining(mut slot: PeekSlot<'_, Self, Self::State>) -> Option<u64> {
        buffer_remaining(slot.custody())
    }

    fn observe_permits(
        mut slot: PeekSlot<'_, Self, Self::State>,
        sink: &mut dyn CustodySink<A::Permit>,
    ) -> PermitsObserved {
        buffer_permits(slot.custody(), sink)
    }
}
