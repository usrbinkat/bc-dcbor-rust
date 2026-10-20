//! Native Option projections through a valid, resource-free placeholder.
extern crate alloc;
use super::*;
use alloc::alloc::{alloc, dealloc};
use alloc::{string::String, vec::Vec};
use core::alloc::Layout;
use core::mem::{MaybeUninit, size_of};
use core::ptr::{self, NonNull};

/// A resource-free placeholder whose construction and move fit one quantum.
///
/// # Safety
/// The value must own no resources and require no destructor. Returning it must
/// take bounded work independent of child count. In-place initialization may
/// overwrite this placeholder without running Drop. This is deliberately not a
/// blanket Default implementation: arbitrary defaults do not meet this contract.
pub unsafe trait Placeholder: Sized {
    fn placeholder() -> Self;
}

macro_rules! scalars {
    ($($ty:ty),*) => {$(
        // SAFETY: a scalar zero has no owned resources and constant-size storage.
        unsafe impl Placeholder for $ty { fn placeholder() -> Self { 0 } }
    )*};
}
scalars!(u8, u16, u32, u64, usize, i8, i16, i32, i64);
// SAFETY: empty String and Vec own no allocations; their headers have fixed size.
unsafe impl Placeholder for String {
    fn placeholder() -> Self {
        String::new()
    }
}
unsafe impl<T> Placeholder for Vec<T> {
    fn placeholder() -> Self {
        Vec::new()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Empty,
    Child,
    Complete,
    Absent,
    Release,
}
struct Meta<T, P> {
    child: Cursor,
    place: *mut MaybeUninit<T>,
    phase: Phase,
    permit: P,
}

fn metadata<T, A: Allocator>(cursor: &mut Cursor, a: &mut A) -> BoundedResult<(), A> {
    let layout = Layout::new::<Meta<T, A::Permit>>();
    if layout.size() > 64 || size_of::<Option<T>>() > 64 {
        return Err(BoundedError::PlanMismatch);
    }
    let bytes = layout.size() as u64;
    a.traverse(1, bytes).map_err(BoundedError::Refused)?;
    let permit = a.allocate(bytes).map_err(BoundedError::Refused)?;
    // SAFETY: nonzero, aligned metadata allocation.
    let raw = unsafe { alloc(layout) }.cast::<Meta<T, A::Permit>>();
    let meta = NonNull::new(raw).ok_or(BoundedError::Allocation { bytes })?;
    unsafe {
        meta.as_ptr().write(Meta {
            child: Cursor::default(),
            place: ptr::null_mut(),
            phase: Phase::Empty,
            permit,
        })
    };
    cursor.state = meta.as_ptr() as usize;
    Ok(())
}

// SAFETY: None owns no child; Some retains its child's actual projected address
// and cleanup cursor. No assumed Option layout or whole-value destructor is used.
unsafe impl<T: Reclaim<A> + Placeholder, A: Allocator> Reclaim<A> for Option<T> {
    const DISPATCH_DEPTH: usize = T::DISPATCH_DEPTH.saturating_add(2);

    unsafe fn reclaim_step(
        place: NonNull<MaybeUninit<Self>>,
        cursor: &mut Cursor,
        a: &mut A,
    ) -> BoundedResult<Reclaimed, A> {
        let _ = place;
        if cursor.state == 0 {
            a.traverse(1, 0).map_err(BoundedError::Refused)?;
            return Ok(Reclaimed::Done);
        }
        let raw = cursor.state as *mut Meta<T, A::Permit>;
        // SAFETY: metadata is retained until Release.
        let meta = unsafe { &mut *raw };
        match meta.phase {
            Phase::Child | Phase::Complete => {
                let child = NonNull::new(meta.place).ok_or(BoundedError::PlanMismatch)?;
                if unsafe { T::reclaim_step(child, &mut meta.child, a)? } == Reclaimed::Done {
                    meta.phase = Phase::Release;
                }
            }
            Phase::Empty | Phase::Absent => {
                a.traverse(1, 0).map_err(BoundedError::Refused)?;
                meta.phase = Phase::Release;
            }
            Phase::Release => {
                a.traverse(1, size_of::<A::Permit>() as u64)
                    .map_err(BoundedError::Refused)?;
                unsafe {
                    let permit = ptr::addr_of!((*raw).permit).read();
                    dealloc(raw.cast(), Layout::new::<Meta<T, A::Permit>>());
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

// SAFETY: only bounded, resource-free placeholders are used. Projection occurs
// while Some is valid, before child construction; the raw projection is retained
// instead of forming references through a partially initialized Option later.
unsafe impl<T: InPlace<A> + Placeholder, A: Allocator> InPlace<A> for Option<T> {
    const OPTIONAL: bool = true;

    unsafe fn build_present(
        document: &Document<'_, A::Permit>,
        index: usize,
        place: NonNull<MaybeUninit<Self>>,
        cursor: &mut Cursor,
        a: &mut A,
    ) -> ConstructResult<Built, A> {
        if cursor.position == 0 {
            a.traverse(1, 0).map_err(BoundedError::Refused)?;
            cursor.position = 1;
            return Ok(Built::Progress);
        }
        unsafe { Self::build_step(document, index, place, cursor, a) }
    }
    unsafe fn build_absent(
        place: NonNull<MaybeUninit<Self>>,
        cursor: &mut Cursor,
        a: &mut A,
    ) -> ConstructResult<Built, A> {
        if cursor.state == 0 {
            metadata::<T, A>(cursor, a)?;
            return Ok(Built::Progress);
        }
        let meta = unsafe { &mut *(cursor.state as *mut Meta<T, A::Permit>) };
        if meta.phase != Phase::Empty {
            return Err(BoundedError::PlanMismatch.into());
        }
        a.traverse(1, size_of::<Self>() as u64)
            .map_err(BoundedError::Refused)?;
        unsafe { place.as_ptr().write(MaybeUninit::new(None)) };
        meta.phase = Phase::Absent;
        Ok(Built::Done)
    }

    unsafe fn build_step(
        document: &Document<'_, A::Permit>,
        index: usize,
        place: NonNull<MaybeUninit<Self>>,
        cursor: &mut Cursor,
        a: &mut A,
    ) -> ConstructResult<Built, A> {
        if cursor.state == 0 {
            metadata::<T, A>(cursor, a)?;
            return Ok(Built::Progress);
        }
        let meta = unsafe { &mut *(cursor.state as *mut Meta<T, A::Permit>) };
        match meta.phase {
            Phase::Empty => {
                a.traverse(1, size_of::<Self>() as u64)
                    .map_err(BoundedError::Refused)?;
                let node = node_at(document, index).ok_or_else(wrong_type)?;
                if cursor.position == 0 && matches!(node.kind(), Kind::Null) {
                    unsafe { place.as_ptr().write(MaybeUninit::new(None)) };
                    meta.phase = Phase::Absent;
                    return Ok(Built::Done);
                }
                unsafe {
                    place
                        .as_ptr()
                        .write(MaybeUninit::new(Some(T::placeholder())))
                };
                // SAFETY: just initialized Some with a valid resource-free T.
                let value = unsafe { &mut *place.as_ptr().cast::<Option<T>>() };
                meta.place = value.as_mut().ok_or(BoundedError::PlanMismatch)? as *mut T
                    as *mut MaybeUninit<T>;
                meta.phase = Phase::Child;
                Ok(Built::Progress)
            }
            Phase::Child => {
                let child = NonNull::new(meta.place).ok_or(BoundedError::PlanMismatch)?;
                let result = unsafe { T::build_step(document, index, child, &mut meta.child, a)? };
                if result == Built::Done {
                    meta.phase = Phase::Complete;
                }
                Ok(result)
            }
            _ => Err(BoundedError::PlanMismatch.into()),
        }
    }
}
