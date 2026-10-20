//! Stable vector elements with retained per-element cleanup records.
extern crate alloc;
use super::*;
use alloc::alloc::{alloc, dealloc};
use alloc::vec::Vec;
use core::alloc::Layout;
use core::mem::{size_of, MaybeUninit};
use core::ptr::{self, NonNull};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Empty,
    Initialized,
    AllocatePayload,
    Next,
    AllocateChild,
    Child,
    Commit,
    Complete,
    Reclaim,
    ReleaseChild,
    BufferFreed,
    PayloadFreed,
}

struct Child<P> {
    cursor: Cursor,
    previous: *mut Child<P>,
    committed: bool,
    permit: P,
}

struct Meta<P> {
    phase: Phase,
    head: *mut Child<P>,
    payload: Option<P>,
    permit: P,
}

fn reserve<M, A: Allocator>(a: &mut A) -> BoundedResult<(NonNull<M>, A::Permit), A> {
    let layout = Layout::new::<M>();
    if layout.size() == 0 || layout.size() > 64 {
        return Err(BoundedError::PlanMismatch);
    }
    let bytes = layout.size() as u64;
    let permit = a.allocate(bytes).map_err(BoundedError::Refused)?;
    // SAFETY: layout is nonzero and belongs to the caller until initialized.
    let raw = unsafe { alloc(layout) }.cast::<M>();
    Ok((
        NonNull::new(raw).ok_or(BoundedError::Allocation { bytes })?,
        permit,
    ))
}

// SAFETY: Vec's header and each spare-capacity child are initialized directly
// in their final storage. A preallocated child record survives completion and
// describes that element until reclamation, including uncommitted partials.
unsafe impl<T: InPlace<A>, A: Allocator> InPlace<A> for Vec<T> {
    unsafe fn build_step(
        document: &Document<'_, A::Permit>,
        index: usize,
        place: NonNull<MaybeUninit<Self>>,
        cursor: &mut Cursor,
        a: &mut A,
    ) -> ConstructResult<Built, A> {
        if cursor.state == 0 {
            if cursor.position == 0 {
                a.traverse(1, size_of::<Meta<A::Permit>>() as u64)
                    .map_err(BoundedError::Refused)?;
                cursor.position = 1;
            }
            let (meta, permit) = reserve::<Meta<A::Permit>, A>(a)?;
            // SAFETY: the admitted allocation is unique and correctly aligned.
            unsafe {
                meta.as_ptr().write(Meta {
                    phase: Phase::Empty,
                    head: ptr::null_mut(),
                    payload: None,
                    permit,
                })
            };
            cursor.state = meta.as_ptr() as usize;
            cursor.position = 0;
            return Ok(Built::Progress);
        }
        // SAFETY: installed metadata remains live through final cleanup.
        let meta = unsafe { &mut *(cursor.state as *mut Meta<A::Permit>) };
        if meta.phase == Phase::Empty {
            a.traverse(1, size_of::<Vec<T>>() as u64)
                .map_err(BoundedError::Refused)?;
            if !matches!(
                node_at(document, index).map(|n| n.kind()),
                Some(Kind::Array(_))
            ) {
                return Err(wrong_type());
            }
            // SAFETY: no Vec has yet been initialized at this destination.
            unsafe { place.as_ptr().write(MaybeUninit::new(Vec::new())) };
            meta.phase = Phase::Initialized;
            cursor.position = index.checked_add(1).ok_or(BoundedError::Overflow)?;
            return Ok(Built::Progress);
        }
        let Some(Kind::Array(count)) = node_at(document, index).map(|n| n.kind()) else {
            return Err(wrong_type());
        };
        let count = usize::try_from(count).map_err(|_| BoundedError::Overflow)?;
        // SAFETY: all remaining construction phases have an initialized Vec.
        let values = unsafe { &mut *place.as_ptr().cast::<Vec<T>>() };
        match meta.phase {
            Phase::Initialized | Phase::AllocatePayload => {
                let bytes = count
                    .checked_mul(size_of::<T>())
                    .ok_or(BoundedError::Overflow)?;
                let bytes = u64::try_from(bytes).map_err(|_| BoundedError::Overflow)?;
                if meta.phase == Phase::Initialized {
                    a.traverse(1, 0).map_err(BoundedError::Refused)?;
                    meta.phase = Phase::AllocatePayload;
                }
                meta.payload = Some(a.allocate(bytes).map_err(BoundedError::Refused)?);
                values
                    .try_reserve_exact(count)
                    .map_err(|_| BoundedError::Allocation { bytes })?;
                meta.phase = Phase::Next;
            }
            Phase::Next | Phase::AllocateChild => {
                if values.len() == count {
                    a.traverse(1, 0).map_err(BoundedError::Refused)?;
                    meta.phase = Phase::Complete;
                    return Ok(Built::Done);
                }
                if meta.phase == Phase::Next {
                    a.traverse(1, size_of::<Child<A::Permit>>() as u64)
                        .map_err(BoundedError::Refused)?;
                    meta.phase = Phase::AllocateChild;
                }
                let (child, permit) = reserve::<Child<A::Permit>, A>(a)?;
                // SAFETY: reserve precedes acquiring any child-owned resource.
                unsafe {
                    child.as_ptr().write(Child {
                        cursor: Cursor::default(),
                        previous: meta.head,
                        committed: false,
                        permit,
                    })
                };
                meta.head = child.as_ptr();
                meta.phase = Phase::Child;
            }
            Phase::Child => {
                // SAFETY: a child record exists; len is the initialized prefix.
                // Reserved capacity cannot move during child construction.
                let child = unsafe { &mut *meta.head };
                let destination = NonNull::from(
                    values
                        .spare_capacity_mut()
                        .first_mut()
                        .ok_or(BoundedError::PlanMismatch)?,
                );
                if unsafe {
                    T::build_step(document, cursor.position, destination, &mut child.cursor, a)?
                } == Built::Done
                {
                    meta.phase = Phase::Commit;
                }
            }
            Phase::Commit => {
                a.traverse(1, 0).map_err(BoundedError::Refused)?;
                let node = node_at(document, cursor.position).ok_or_else(wrong_type)?;
                cursor.position = super::super::next_index(node);
                // SAFETY: the child returned Done at slot len; capacity was
                // reserved before its address was handed to construction.
                unsafe {
                    values.set_len(values.len() + 1);
                    (*meta.head).committed = true;
                }
                meta.phase = Phase::Next;
            }
            _ => return Err(BoundedError::PlanMismatch.into()),
        }
        Ok(Built::Progress)
    }
}

// SAFETY: cleanup follows the retained child records in reverse order. Partial
// children never enter Vec's initialized prefix. Completed elements leave that
// prefix only after their mandatory cleanup returns Done; Vec is dropped empty.
unsafe impl<T: Reclaim<A>, A: Allocator> Reclaim<A> for Vec<T> {
    const DISPATCH_DEPTH: usize = T::DISPATCH_DEPTH.saturating_add(1);

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
        // SAFETY: root metadata remains allocated until PayloadFreed.
        let meta = unsafe { &mut *raw };
        match meta.phase {
            Phase::Empty => {
                a.traverse(1, 0).map_err(BoundedError::Refused)?;
                meta.phase = Phase::BufferFreed;
            }
            Phase::Initialized
            | Phase::AllocatePayload
            | Phase::Next
            | Phase::AllocateChild
            | Phase::Child
            | Phase::Commit
            | Phase::Complete => {
                a.traverse(1, 0).map_err(BoundedError::Refused)?;
                meta.phase = Phase::Reclaim;
            }
            Phase::Reclaim => {
                // SAFETY: entering Reclaim proves the Vec header is initialized.
                let values = unsafe { &mut *place.as_ptr().cast::<Vec<T>>() };
                if meta.head.is_null() {
                    if !values.is_empty() {
                        return Err(BoundedError::PlanMismatch);
                    }
                    a.traverse(1, size_of::<Vec<T>>() as u64)
                        .map_err(BoundedError::Refused)?;
                    // SAFETY: no live elements remain; only the backing buffer
                    // is freed. Its payload reservation stays retained below.
                    unsafe { ptr::drop_in_place(values) };
                    meta.phase = Phase::BufferFreed;
                } else {
                    // SAFETY: head is a live child record, committed or partial.
                    let child = unsafe { &mut *meta.head };
                    let offset = if child.committed {
                        values
                            .len()
                            .checked_sub(1)
                            .ok_or(BoundedError::PlanMismatch)?
                    } else {
                        values.len()
                    };
                    // SAFETY: the partial slot was reserved before its record
                    // was linked; committed slots lie inside the prefix.
                    let destination = unsafe {
                        NonNull::new_unchecked(
                            values.as_mut_ptr().add(offset).cast::<MaybeUninit<T>>(),
                        )
                    };
                    if unsafe { T::reclaim_step(destination, &mut child.cursor, a)? }
                        == Reclaimed::Done
                    {
                        meta.phase = Phase::ReleaseChild;
                    }
                }
            }
            Phase::ReleaseChild => {
                a.traverse(1, size_of::<Child<A::Permit>>() as u64)
                    .map_err(BoundedError::Refused)?;
                let child = meta.head;
                // SAFETY: the head's cleanup completed in the preceding phase.
                // Remove it before freeing its metadata; retain its permit until
                // that storage is gone. No destructor is run on the element.
                unsafe {
                    let values = &mut *place.as_ptr().cast::<Vec<T>>();
                    if (*child).committed {
                        values.set_len(values.len() - 1);
                    }
                    meta.head = (*child).previous;
                    let permit = ptr::addr_of!((*child).permit).read();
                    dealloc(child.cast(), Layout::new::<Child<A::Permit>>());
                    meta.phase = Phase::Reclaim;
                    drop(permit);
                }
            }
            Phase::BufferFreed => {
                a.traverse(1, size_of::<A::Permit>() as u64)
                    .map_err(BoundedError::Refused)?;
                let permit = meta.payload.take();
                meta.phase = Phase::PayloadFreed;
                drop(permit);
            }
            Phase::PayloadFreed => {
                a.traverse(1, size_of::<A::Permit>() as u64)
                    .map_err(BoundedError::Refused)?;
                // SAFETY: no children or payload allocation remain.
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
}
