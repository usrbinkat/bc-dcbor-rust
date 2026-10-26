//! In-place byte buffers beside their private native representation.
extern crate alloc;
use super::ByteString;
use crate::bounded::decode::construction::{
    in_place::{
        Built, ConstructionCost, InPlace, Placeholder, rejected,
        text::{BufferState, buffer_cost, copy_buffer, reclaim_buffer},
    },
    node_at,
    reclamation::{Reclaim, Reclaimed},
};
use crate::bounded::decode::{ConstructResult, Document, Kind};
use crate::bounded::{Allocator, BoundedResult};
use alloc::vec::Vec;
use core::{
    mem::MaybeUninit,
    ptr::{self, NonNull},
};

// SAFETY: empty native byte buffers have no allocation or child destructor.
unsafe impl Placeholder for ByteString {
    fn placeholder() -> Self {
        Self(Vec::new())
    }
}

// SAFETY: the shared byte-buffer phases record initialization and permits.
unsafe impl<A: Allocator> InPlace<A> for ByteString {
    const COST: ConstructionCost = buffer_cost::<Self, A::Permit>();

    unsafe fn build_step(
        document: &Document<'_, A::Permit>,
        index: usize,
        place: NonNull<MaybeUninit<Self>>,
        state: &mut Self::State,
        a: &mut A,
    ) -> ConstructResult<Built, A> {
        let Some(Kind::Bytes(source)) = node_at(document, index).map(|n| n.kind()) else {
            return rejected(a);
        };
        unsafe { Self::copy_step(source, place, state, a) }.map_err(Into::into)
    }
}

impl ByteString {
    /// Initialize a byte buffer in stable storage using the same custody phases
    /// as typed construction. The caller retains the immutable source and state.
    ///
    /// # Safety
    /// The destination and state are an original stable construction pair.
    pub(crate) unsafe fn copy_step<A: Allocator>(
        source: &[u8],
        place: NonNull<MaybeUninit<Self>>,
        state: &mut BufferState<A::Permit>,
        a: &mut A,
    ) -> BoundedResult<Built, A> {
        let place = place.as_ptr().cast::<Self>();
        // SAFETY: forwarded from the caller; the vector is reached only after
        // the empty ByteString is written.
        unsafe {
            copy_buffer::<Self, A>(
                source,
                false,
                || place.write(Self(Vec::new())),
                || &mut (*place).0,
                state,
                a,
            )
        }
    }
}

// SAFETY: the native buffer contains bytes only. Its allocation is released
// before either permit, and no arbitrary element destructor is invoked.
unsafe impl<A: Allocator> Reclaim<A> for ByteString {
    type State = BufferState<A::Permit>;
    const INITIAL: Self::State = BufferState::INITIAL;

    unsafe fn reclaim_step(
        place: NonNull<MaybeUninit<Self>>,
        state: &mut Self::State,
        a: &mut A,
    ) -> BoundedResult<Reclaimed, A> {
        // SAFETY: the buffer phases prove initialization of this ByteString.
        unsafe {
            reclaim_buffer::<Self, A>(
                state,
                || ptr::drop_in_place(place.as_ptr().cast::<Self>()),
                a,
            )
        }
    }

    unsafe fn remaining(_: NonNull<MaybeUninit<Self>>, state: &mut Self::State) -> u64 {
        crate::bounded::decode::construction::in_place::text::buffer_remaining(state)
    }
}
