//! In-place byte buffers beside their private native representation.
extern crate alloc;
use super::ByteString;
use crate::bounded::decode::construction::{
    in_place::{
        Built, InPlace, Placeholder,
        text::{Meta, Phase, allocate_meta},
    },
    node_at,
    reclamation::{Cursor, Reclaim, Reclaimed},
};
use crate::bounded::decode::{ConstructResult, Document, Kind, wrong_type};
use crate::bounded::{Allocator, BoundedError, BoundedResult};
use alloc::{alloc::dealloc, vec::Vec};
use core::{
    alloc::Layout,
    mem::{MaybeUninit, size_of},
    ptr::{self, NonNull},
};

// SAFETY: empty native byte buffers have no allocation or child destructor.
unsafe impl Placeholder for ByteString {
    fn placeholder() -> Self {
        Self(Vec::new())
    }
}

// SAFETY: each phase records buffer initialization and its individual permits.
unsafe impl<A: Allocator> InPlace<A> for ByteString {
    unsafe fn build_step(
        document: &Document<'_, A::Permit>,
        index: usize,
        place: NonNull<MaybeUninit<Self>>,
        cursor: &mut Cursor,
        a: &mut A,
    ) -> ConstructResult<Built, A> {
        if cursor.state == 0 {
            allocate_meta(cursor, a)?;
            return Ok(Built::Progress);
        }
        let meta = unsafe { &mut *(cursor.state as *mut Meta<A::Permit>) };
        match meta.phase {
            Phase::Empty => {
                a.traverse(1, size_of::<Self>() as u64)
                    .map_err(BoundedError::Refused)?;
                if !matches!(
                    node_at(document, index).map(|n| n.kind()),
                    Some(Kind::Bytes(_))
                ) {
                    return Err(wrong_type());
                }
                unsafe {
                    place.as_ptr().write(MaybeUninit::new(Self(Vec::new())));
                }
                meta.phase = Phase::Initialized;
            }
            Phase::Initialized | Phase::AllocatePayload => {
                let Some(Kind::Bytes(source)) = node_at(document, index).map(|n| n.kind()) else {
                    return Err(wrong_type());
                };
                let bytes = u64::try_from(source.len()).map_err(|_| BoundedError::Overflow)?;
                if meta.phase == Phase::Initialized {
                    a.traverse(1, 0).map_err(BoundedError::Refused)?;
                    meta.phase = Phase::AllocatePayload;
                }
                meta.payload = Some(a.allocate(bytes).map_err(BoundedError::Refused)?);
                let value = unsafe { &mut *place.as_ptr().cast::<Self>() };
                value
                    .0
                    .try_reserve_exact(source.len())
                    .map_err(|_| BoundedError::Allocation { bytes })?;
                meta.phase = Phase::Copy;
            }
            Phase::Copy => {
                let Some(Kind::Bytes(source)) = node_at(document, index).map(|n| n.kind()) else {
                    return Err(wrong_type());
                };
                let start = cursor.position;
                let end = start
                    + source
                        .len()
                        .checked_sub(start)
                        .ok_or(BoundedError::PlanMismatch)?
                        .min(64);
                a.traverse(1, (end - start) as u64)
                    .map_err(BoundedError::Refused)?;
                unsafe { &mut *place.as_ptr().cast::<Self>() }
                    .0
                    .extend_from_slice(&source[start..end]);
                cursor.position = end;
                if end == source.len() {
                    meta.phase = Phase::Complete;
                    return Ok(Built::Done);
                }
            }
            _ => return Err(BoundedError::PlanMismatch.into()),
        }
        Ok(Built::Progress)
    }
}

// SAFETY: the native buffer contains bytes only. Its allocation is released
// before either permit, and no arbitrary element destructor is invoked.
unsafe impl<A: Allocator> Reclaim<A> for ByteString {
    unsafe fn reclaim_step(
        place: NonNull<MaybeUninit<Self>>,
        cursor: &mut Cursor,
        a: &mut A,
    ) -> BoundedResult<Reclaimed, A> {
        if cursor.state == 0 {
            a.traverse(1, 0).map_err(BoundedError::Refused)?;
            return Ok(Reclaimed::Done);
        }
        let raw = cursor.state as *mut Meta<A::Permit>;
        let meta = unsafe { &mut *raw };
        match meta.phase {
            Phase::Empty => {
                a.traverse(1, 0).map_err(BoundedError::Refused)?;
                meta.phase = Phase::BufferFreed;
            }
            Phase::Initialized | Phase::AllocatePayload | Phase::Copy | Phase::Complete => {
                a.traverse(1, size_of::<Self>() as u64)
                    .map_err(BoundedError::Refused)?;
                unsafe {
                    ptr::drop_in_place(place.as_ptr().cast::<Self>());
                }
                meta.phase = Phase::BufferFreed;
            }
            Phase::BufferFreed => {
                a.traverse(1, size_of::<A::Permit>() as u64)
                    .map_err(BoundedError::Refused)?;
                let permit = meta.payload.take();
                meta.phase = Phase::PermitReleased;
                drop(permit);
            }
            Phase::PermitReleased => {
                a.traverse(1, size_of::<A::Permit>() as u64)
                    .map_err(BoundedError::Refused)?;
                unsafe {
                    let permit = ptr::addr_of!((*raw).allocation).read();
                    dealloc(raw.cast(), Layout::new::<Meta<A::Permit>>());
                    *cursor = Cursor::default();
                    drop(permit);
                }
                return Ok(Reclaimed::Done);
            }
        }
        Ok(Reclaimed::Progress)
    }
}
