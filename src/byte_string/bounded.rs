//! In-place byte buffers beside their private native representation.
extern crate alloc;
use super::ByteString;
use crate::bounded::decode::construction::{
    in_place::{
        Built, ConstructionCost, InPlace, Placeholder, rejected,
        text::{Buffer, BufferState, buffer_cost, buffer_remaining, copy_buffer, reclaim_buffer},
    },
    node_at,
    reclamation::{PeekSlot, Reclaim, Reclaimed, Slot},
};
use crate::bounded::decode::{ConstructResult, Document, Kind};
use crate::bounded::{Allocator, BoundedResult};
use alloc::vec::Vec;

// SAFETY: empty native byte buffers have no allocation or child destructor.
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

// SAFETY: the shared byte-buffer phases record initialization and permits.
unsafe impl<A: Allocator> InPlace<A> for ByteString {
    const COST: ConstructionCost = buffer_cost::<Self, A::Permit>();

    fn build_step(
        document: &Document<'_, A::Permit>,
        index: usize,
        slot: Slot<'_, Self, Self::State>,
        a: &mut A,
    ) -> ConstructResult<Built, A> {
        let Some(Kind::Bytes(source)) = node_at(document, index).map(|n| n.kind()) else {
            return rejected(a);
        };
        Self::copy_step(source, slot, a).map_err(Into::into)
    }
}

impl ByteString {
    /// Initialize a byte buffer in stable storage using the same custody
    /// phases as typed construction, from `source`, which every step of one
    /// copy passes alike: a step whose source does not continue the copy is
    /// refused ([`copy_buffer`]).
    pub(crate) fn copy_step<A: Allocator>(
        source: &[u8],
        slot: Slot<'_, Self, BufferState<A::Permit>>,
        a: &mut A,
    ) -> BoundedResult<Built, A> {
        copy_buffer::<Self, A>(source, slot, a)
    }
}

// SAFETY: the native buffer contains bytes only. Its allocation is released
// before either permit, and no arbitrary element destructor is invoked.
unsafe impl<A: Allocator> Reclaim<A> for ByteString {
    type State = BufferState<A::Permit>;
    const INITIAL: Self::State = BufferState::INITIAL;

    fn reclaim_step(slot: Slot<'_, Self, Self::State>, a: &mut A) -> BoundedResult<Reclaimed, A> {
        reclaim_buffer::<Self, A>(slot, a)
    }

    fn remaining(mut slot: PeekSlot<'_, Self, Self::State>) -> u64 {
        buffer_remaining(slot.custody())
    }
}
