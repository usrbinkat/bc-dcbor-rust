//! String construction and reclamation with per-allocation custody.
extern crate alloc;

use alloc::alloc::{alloc, dealloc};
use alloc::string::String;
use core::alloc::Layout;
use core::mem::{MaybeUninit, size_of};
use core::ptr::{self, NonNull};

use super::*;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Phase {
    Empty,
    Initialized,
    AllocatePayload,
    Copy,
    Complete,
    BufferFreed,
    PermitReleased,
}

pub(crate) struct Meta<P> {
    pub(crate) phase: Phase,
    pub(crate) payload: Option<P>,
    pub(crate) allocation: P,
}

pub(crate) fn allocate_meta<A: Allocator>(cursor: &mut Cursor, a: &mut A) -> BoundedResult<(), A> {
    let layout = Layout::new::<Meta<A::Permit>>();
    if layout.size() > 64 {
        return Err(BoundedError::PlanMismatch);
    }
    let bytes = layout.size() as u64;
    if cursor.position == 0 {
        a.traverse(1, bytes).map_err(BoundedError::Refused)?;
        cursor.position = 1;
    }
    let permit = a.allocate(bytes).map_err(BoundedError::Refused)?;
    // SAFETY: Meta contains its permit and phase, so the layout is nonzero.
    let raw = unsafe { alloc(layout) }.cast::<Meta<A::Permit>>();
    let meta = NonNull::new(raw).ok_or(BoundedError::Allocation { bytes })?;
    // SAFETY: exclusively owned, correctly aligned allocation. The cursor is
    // published only after the entire fixed-size metadata has been initialized.
    unsafe {
        meta.as_ptr().write(Meta {
            phase: Phase::Empty,
            payload: None,
            allocation: permit,
        });
    }
    cursor.state = meta.as_ptr() as usize;
    cursor.position = 0;
    Ok(())
}

// SAFETY: every initialized String is recorded before returning. String's
// byte buffer has no element destructors. Its storage is freed in one admitted
// step, then its payload permit, then the metadata storage and its permit.
unsafe impl<A: Allocator> Reclaim<A> for String {
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
        // SAFETY: cursor.state was installed by allocate_meta and remains live
        // until the PermitReleased branch. No references escape this call.
        let meta = unsafe { &mut *raw };
        match meta.phase {
            Phase::Empty => {
                a.traverse(1, 0).map_err(BoundedError::Refused)?;
                meta.phase = Phase::BufferFreed;
            }
            Phase::Initialized | Phase::AllocatePayload | Phase::Copy | Phase::Complete => {
                a.traverse(1, size_of::<String>() as u64)
                    .map_err(BoundedError::Refused)?;
                // SAFETY: these phases prove String initialization. This is a
                // built-in byte-buffer destructor, not arbitrary custom Drop.
                unsafe { ptr::drop_in_place(place.as_ptr().cast::<String>()) };
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
                // SAFETY: payload is None and the String has been destroyed.
                // Move only the fixed-size permit, free its storage first.
                unsafe {
                    let permit = ptr::addr_of!((*raw).allocation).read();
                    dealloc(raw.cast(), Layout::new::<Meta<A::Permit>>());
                    cursor.state = 0;
                    cursor.position = 0;
                    drop(permit);
                }
                return Ok(Reclaimed::Done);
            }
        }
        Ok(Reclaimed::Progress)
    }
}

// SAFETY: construction writes the String header directly into its final place,
// reserves its byte allocation once, and appends only admitted UTF-8 chunks.
// All phases, including allocation failures, are understood by Reclaim above.
unsafe impl<A: Allocator> InPlace<A> for String {
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
        // SAFETY: the preceding phase initialized this metadata allocation.
        let meta = unsafe { &mut *(cursor.state as *mut Meta<A::Permit>) };
        match meta.phase {
            Phase::Empty => {
                a.traverse(1, size_of::<String>() as u64)
                    .map_err(BoundedError::Refused)?;
                if !matches!(
                    node_at(document, index).map(|n| n.kind()),
                    Some(Kind::Text(_))
                ) {
                    return Err(wrong_type());
                }
                // SAFETY: unique uninitialized destination, no allocation in new.
                unsafe { place.as_ptr().write(MaybeUninit::new(String::new())) };
                meta.phase = Phase::Initialized;
                Ok(Built::Progress)
            }
            Phase::Initialized | Phase::AllocatePayload => {
                let Some(Kind::Text(source)) = node_at(document, index).map(|n| n.kind()) else {
                    return Err(wrong_type());
                };
                let bytes = u64::try_from(source.len()).map_err(|_| BoundedError::Overflow)?;
                if meta.phase == Phase::Initialized {
                    a.traverse(1, 0).map_err(BoundedError::Refused)?;
                    meta.phase = Phase::AllocatePayload;
                }
                meta.payload = Some(a.allocate(bytes).map_err(BoundedError::Refused)?);
                // SAFETY: Initialized proves a valid empty String at place.
                let value = unsafe { &mut *place.as_ptr().cast::<String>() };
                value
                    .try_reserve_exact(source.len())
                    .map_err(|_| BoundedError::Allocation { bytes })?;
                meta.phase = Phase::Copy;
                Ok(Built::Progress)
            }
            Phase::Copy => {
                let Some(Kind::Text(source)) = node_at(document, index).map(|n| n.kind()) else {
                    return Err(wrong_type());
                };
                let start = cursor.position;
                let remaining = source
                    .len()
                    .checked_sub(start)
                    .ok_or(BoundedError::PlanMismatch)?;
                let mut end = start + remaining.min(64);
                while !source.is_char_boundary(end) {
                    end -= 1;
                }
                a.traverse(1, (end - start) as u64)
                    .map_err(BoundedError::Refused)?;
                // SAFETY: Copy proves initialization and sufficient reserved
                // capacity. Source boundaries are retained UTF-8 boundaries.
                unsafe { &mut *place.as_ptr().cast::<String>() }.push_str(&source[start..end]);
                cursor.position = end;
                if end == source.len() {
                    meta.phase = Phase::Complete;
                    Ok(Built::Done)
                } else {
                    Ok(Built::Progress)
                }
            }
            _ => Err(BoundedError::PlanMismatch.into()),
        }
    }
}
