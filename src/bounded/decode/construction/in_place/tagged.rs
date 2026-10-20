//! Tag validation with independently retained payload initialization.
extern crate alloc;
use super::*;
use alloc::alloc::{alloc, dealloc};
use core::{alloc::Layout, mem::size_of, ptr};

/// Generated aligned projections for a tagged schema's untagged payload.
///
/// # Safety
/// The callbacks must retain the destination and cursor and obey InPlace and
/// Reclaim respectively. They must not inspect or initialize the outer tag.
pub unsafe trait Payload<A: Allocator>: Sized {
    const TAG: u64;
    /// # Safety
    /// The destination and cursor obey InPlace::build_step's contract.
    unsafe fn build_payload(
        document: &Document<'_, A::Permit>,
        index: usize,
        place: NonNull<MaybeUninit<Self>>,
        cursor: &mut Cursor,
        a: &mut A,
    ) -> ConstructResult<Built, A>;
    /// # Safety
    /// The destination and cursor are the original payload construction pair.
    unsafe fn reclaim_payload(
        place: NonNull<MaybeUninit<Self>>,
        cursor: &mut Cursor,
        a: &mut A,
    ) -> BoundedResult<Reclaimed, A>;
}

#[derive(Clone, Copy)]
enum Phase {
    Inspect,
    Build,
    Complete,
    Release,
}
struct Meta<P> {
    child: Cursor,
    index: usize,
    phase: Phase,
    permit: P,
}

/// # Safety
/// The caller provides a unique stable destination and its retained cursor.
pub unsafe fn build<T: Payload<A>, A: Allocator>(
    document: &Document<'_, A::Permit>,
    index: usize,
    place: NonNull<MaybeUninit<T>>,
    cursor: &mut Cursor,
    a: &mut A,
) -> ConstructResult<Built, A> {
    if cursor.state == 0 {
        let layout = Layout::new::<Meta<A::Permit>>();
        if layout.size() > 64 {
            return Err(BoundedError::PlanMismatch.into());
        }
        let bytes = layout.size() as u64;
        if cursor.position == 0 {
            a.traverse(1, bytes).map_err(BoundedError::Refused)?;
            cursor.position = 1;
        }
        let permit = a.allocate(bytes).map_err(BoundedError::Refused)?;
        // SAFETY: Meta has nonzero size and is initialized before registration.
        let raw = unsafe { alloc(layout) }.cast::<Meta<A::Permit>>();
        let meta = NonNull::new(raw).ok_or(BoundedError::Allocation { bytes })?;
        unsafe {
            meta.as_ptr().write(Meta {
                child: Cursor::default(),
                index,
                phase: Phase::Inspect,
                permit,
            })
        };
        cursor.state = meta.as_ptr() as usize;
        cursor.position = 0;
        return Ok(Built::Progress);
    }
    // SAFETY: the registered allocation remains live until reclaim releases it.
    let meta = unsafe { &mut *(cursor.state as *mut Meta<A::Permit>) };
    match meta.phase {
        Phase::Inspect => {
            a.traverse(1, 0).map_err(BoundedError::Refused)?;
            match node_at(document, meta.index).map(|node| node.kind()) {
                Some(Kind::Tagged(found)) if found == T::TAG => {}
                Some(Kind::Tagged(found)) => {
                    return Err(crate::bounded::decode::DecodeError::Invalid(
                        crate::Error::WrongTag(
                            crate::Tag::with_value(T::TAG),
                            crate::Tag::with_value(found),
                        ),
                    ));
                }
                _ => return Err(wrong_type()),
            }
            meta.index = meta.index.checked_add(1).ok_or(BoundedError::Overflow)?;
            meta.phase = Phase::Build;
            Ok(Built::Progress)
        }
        Phase::Build => {
            // SAFETY: only the payload callback uses the child cursor.
            let result =
                unsafe { T::build_payload(document, meta.index, place, &mut meta.child, a)? };
            if result == Built::Done {
                meta.phase = Phase::Complete;
            }
            Ok(result)
        }
        _ => Err(BoundedError::PlanMismatch.into()),
    }
}

/// # Safety
/// The destination and cursor must be the pair previously passed to build.
pub unsafe fn reclaim<T: Payload<A>, A: Allocator>(
    place: NonNull<MaybeUninit<T>>,
    cursor: &mut Cursor,
    a: &mut A,
) -> BoundedResult<Reclaimed, A> {
    if cursor.state == 0 {
        a.traverse(1, 0).map_err(BoundedError::Refused)?;
        return Ok(Reclaimed::Done);
    }
    let raw = cursor.state as *mut Meta<A::Permit>;
    // SAFETY: metadata remains registered throughout payload cleanup.
    let meta = unsafe { &mut *raw };
    match meta.phase {
        Phase::Inspect => {
            a.traverse(1, 0).map_err(BoundedError::Refused)?;
            meta.phase = Phase::Release;
        }
        Phase::Build | Phase::Complete => {
            // SAFETY: the payload cursor tracks all partial initialization.
            if unsafe { T::reclaim_payload(place, &mut meta.child, a)? } == Reclaimed::Done {
                meta.phase = Phase::Release;
            }
        }
        Phase::Release => {
            a.traverse(1, size_of::<A::Permit>() as u64)
                .map_err(BoundedError::Refused)?;
            // SAFETY: the payload owns no resources now; move out the sole permit
            // before freeing its storage, then release its accounting exactly once.
            unsafe {
                let permit = ptr::addr_of!((*raw).permit).read();
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
