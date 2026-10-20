//! Retained required-field map construction for generated structs.
extern crate alloc;
use super::*;
use alloc::alloc::{alloc, dealloc};
use core::alloc::Layout;
use core::mem::{MaybeUninit, size_of};
use core::ptr::{self, NonNull};

/// Compiler-generated field projections, indexed by ascending integer wire key.
///
/// # Safety
/// Keys must be unique and strictly increasing. Every payload field must occur
/// exactly once; COUNT must equal the payload field count. Non-payload enum tags
/// are initialized separately by the enum engine. Projections must use the actual
/// aligned struct layout. Each field callback must delegate to that field's
/// InPlace/Reclaim implementation with the same stable address and cursor.
pub unsafe trait Fields<A: Allocator>: Sized {
    const COUNT: usize;
    const TAG: Option<u64> = None;
    const POSITIONAL: bool = false;
    fn key(field: usize) -> u64;
    fn optional(field: usize) -> bool;
    /// # Safety
    /// Initializes only the selected omitted field and retains its cleanup cursor.
    unsafe fn missing_field(
        field: usize,
        place: NonNull<MaybeUninit<Self>>,
        cursor: &mut Cursor,
        a: &mut A,
    ) -> ConstructResult<Built, A>;
    /// # Safety
    /// The root destination and child cursor satisfy InPlace's preconditions.
    unsafe fn build_field(
        field: usize,
        document: &Document<'_, A::Permit>,
        index: usize,
        place: NonNull<MaybeUninit<Self>>,
        cursor: &mut Cursor,
        a: &mut A,
    ) -> ConstructResult<Built, A>;
    /// # Safety
    /// The cursor tracks exactly the initialized parts of the selected field.
    unsafe fn reclaim_field(
        field: usize,
        place: NonNull<MaybeUninit<Self>>,
        cursor: &mut Cursor,
        a: &mut A,
    ) -> BoundedResult<Reclaimed, A>;
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Inspect,
    Map,
    Find,
    Search,
    Allocate,
    AllocateReady,
    Build,
    Missing,
    AdvanceMissing,
    Advance,
    Complete,
    Reclaim,
    Release,
}
struct Child<P> {
    cursor: Cursor,
    previous: *mut Child<P>,
    field: usize,
    permit: P,
}
struct Meta<P> {
    phase: Phase,
    next: usize,
    end: usize,
    low: usize,
    high: usize,
    head: *mut Child<P>,
    permit: P,
}

fn reserve<M, A: Allocator>(a: &mut A) -> BoundedResult<(NonNull<M>, A::Permit), A> {
    let layout = Layout::new::<M>();
    if layout.size() == 0 || layout.size() > 64 {
        return Err(BoundedError::PlanMismatch);
    }
    let bytes = layout.size() as u64;
    let permit = a.allocate(bytes).map_err(BoundedError::Refused)?;
    // SAFETY: nonzero layout, initialized by the caller before publication.
    let raw = unsafe { alloc(layout) }.cast::<M>();
    Ok((
        NonNull::new(raw).ok_or(BoundedError::Allocation { bytes })?,
        permit,
    ))
}

/// # Safety
/// Called with the stable root destination and its original initialization cursor.
pub unsafe fn build<T: Fields<A>, A: Allocator>(
    document: &Document<'_, A::Permit>,
    index: usize,
    place: NonNull<MaybeUninit<T>>,
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
        // SAFETY: initialize only fixed-size metadata, never a schema-sized tuple.
        unsafe {
            meta.as_ptr().write(Meta {
                phase: Phase::Inspect,
                next: index,
                end: 0,
                low: 0,
                high: 0,
                head: ptr::null_mut(),
                permit,
            })
        };
        cursor.state = meta.as_ptr() as usize;
        cursor.position = 0;
        return Ok(Built::Progress);
    }
    // SAFETY: this allocation is retained until reclaim releases it.
    let meta = unsafe { &mut *(cursor.state as *mut Meta<A::Permit>) };
    match meta.phase {
        Phase::Inspect => {
            a.traverse(1, 0).map_err(BoundedError::Refused)?;
            if let Some(expected) = T::TAG {
                let node = node_at(document, meta.next).ok_or_else(wrong_type)?;
                match node.kind() {
                    Kind::Tagged(found) if found == expected => {
                        meta.next = meta.next.checked_add(1).ok_or(BoundedError::Overflow)?;
                    }
                    Kind::Tagged(found) => {
                        return Err(crate::bounded::decode::DecodeError::Invalid(
                            crate::Error::WrongTag(
                                crate::Tag::with_value(expected),
                                crate::Tag::with_value(found),
                            ),
                        ));
                    }
                    _ => return Err(wrong_type()),
                }
            }
            meta.phase = Phase::Map;
        }
        Phase::Map => {
            a.traverse(1, 0).map_err(BoundedError::Refused)?;
            if T::POSITIONAL {
                meta.phase = Phase::Find;
                return Ok(Built::Progress);
            }
            let node = node_at(document, meta.next).ok_or_else(wrong_type)?;
            if !matches!(node.kind(), Kind::Map(_)) {
                return Err(wrong_type());
            }
            meta.next = meta.next.checked_add(1).ok_or(BoundedError::Overflow)?;
            meta.end = super::super::next_index(node);
            meta.phase = Phase::Find;
        }
        Phase::Find => {
            a.traverse(1, 0).map_err(BoundedError::Refused)?;
            if T::POSITIONAL {
                if cursor.position == T::COUNT {
                    meta.phase = Phase::Complete;
                    return Ok(Built::Done);
                }
                meta.low = cursor.position;
                meta.phase = Phase::Allocate;
                return Ok(Built::Progress);
            }
            if meta.next == meta.end {
                if cursor.position != T::COUNT {
                    meta.low = T::COUNT;
                    meta.phase = Phase::Allocate;
                    return Ok(Built::Progress);
                }
                meta.phase = Phase::Complete;
                return Ok(Built::Done);
            }
            meta.low = 0;
            meta.high = T::COUNT;
            meta.phase = Phase::Search;
        }
        Phase::Search => {
            a.traverse(1, 0).map_err(BoundedError::Refused)?;
            let node = node_at(document, meta.next).ok_or_else(wrong_type)?;
            if let Kind::Unsigned(key) = node.kind()
                && meta.low < meta.high
            {
                let mid = meta.low + (meta.high - meta.low) / 2;
                match key.cmp(&T::key(mid)) {
                    core::cmp::Ordering::Less => meta.high = mid,
                    core::cmp::Ordering::Greater => meta.low = mid + 1,
                    core::cmp::Ordering::Equal => {
                        if mid < cursor.position {
                            return Err(BoundedError::PlanMismatch.into());
                        }
                        meta.low = mid;
                        meta.phase = Phase::Allocate;
                    }
                }
                return Ok(Built::Progress);
            }
            let value = node_at(document, super::super::next_index(node)).ok_or_else(wrong_type)?;
            meta.next = super::super::next_index(value);
            meta.phase = Phase::Find;
        }
        Phase::Allocate | Phase::AllocateReady => {
            let missing = cursor.position < meta.low;
            let field = if missing { cursor.position } else { meta.low };
            if missing && !T::optional(field) {
                a.traverse(1, 0).map_err(BoundedError::Refused)?;
                return Err(crate::bounded::decode::DecodeError::Invalid(
                    crate::Error::MissingMapKey,
                ));
            }
            if meta.phase == Phase::Allocate {
                a.traverse(1, size_of::<Child<A::Permit>>() as u64)
                    .map_err(BoundedError::Refused)?;
                meta.phase = Phase::AllocateReady;
            }
            let (child, permit) = reserve::<Child<A::Permit>, A>(a)?;
            // SAFETY: register custody before invoking any field constructor.
            unsafe {
                child.as_ptr().write(Child {
                    cursor: Cursor::default(),
                    previous: meta.head,
                    field,
                    permit,
                })
            };
            meta.head = child.as_ptr();
            meta.phase = if missing {
                Phase::Missing
            } else {
                Phase::Build
            };
        }
        Phase::Missing => {
            let child = unsafe { &mut *meta.head };
            if unsafe { T::missing_field(child.field, place, &mut child.cursor, a)? } == Built::Done
            {
                meta.phase = Phase::AdvanceMissing;
            }
        }
        Phase::AdvanceMissing => {
            a.traverse(1, 0).map_err(BoundedError::Refused)?;
            cursor.position = cursor
                .position
                .checked_add(1)
                .ok_or(BoundedError::Overflow)?;
            meta.phase = if cursor.position == T::COUNT {
                Phase::Find
            } else {
                Phase::Allocate
            };
        }
        Phase::Build => {
            let key = node_at(document, meta.next).ok_or_else(wrong_type)?;
            // SAFETY: Allocate installed the active child; its exact projection
            // and cursor remain unchanged throughout suspension and cleanup.
            let child = unsafe { &mut *meta.head };
            if unsafe {
                T::build_field(
                    child.field,
                    document,
                    if T::POSITIONAL {
                        meta.next
                    } else {
                        super::super::next_index(key)
                    },
                    place,
                    &mut child.cursor,
                    a,
                )?
            } == Built::Done
            {
                meta.phase = Phase::Advance;
            }
        }
        Phase::Advance => {
            a.traverse(1, 0).map_err(BoundedError::Refused)?;
            let key = node_at(document, meta.next).ok_or_else(wrong_type)?;
            let value = if T::POSITIONAL {
                key
            } else {
                node_at(document, super::super::next_index(key)).ok_or_else(wrong_type)?
            };
            meta.next = super::super::next_index(value);
            cursor.position = cursor
                .position
                .checked_add(1)
                .ok_or(BoundedError::Overflow)?;
            meta.phase = Phase::Find;
        }
        _ => return Err(BoundedError::PlanMismatch.into()),
    }
    Ok(Built::Progress)
}

/// # Safety
/// Root and cursor must come from build, and all external value borrows must end.
pub unsafe fn reclaim<T: Fields<A>, A: Allocator>(
    place: NonNull<MaybeUninit<T>>,
    cursor: &mut Cursor,
    a: &mut A,
) -> BoundedResult<Reclaimed, A> {
    if cursor.state == 0 {
        a.traverse(1, 0).map_err(BoundedError::Refused)?;
        return Ok(Reclaimed::Done);
    }
    let raw = cursor.state as *mut Meta<A::Permit>;
    // SAFETY: retained metadata has not yet been released.
    let meta = unsafe { &mut *raw };
    match meta.phase {
        Phase::Reclaim => {
            if meta.head.is_null() {
                a.traverse(1, size_of::<A::Permit>() as u64)
                    .map_err(BoundedError::Refused)?;
                // SAFETY: every field record has completed cleanup and been freed.
                unsafe {
                    let permit = ptr::addr_of!((*raw).permit).read();
                    dealloc(raw.cast(), Layout::new::<Meta<A::Permit>>());
                    cursor.state = 0;
                    cursor.position = 0;
                    drop(permit);
                }
                return Ok(Reclaimed::Done);
            }
            // SAFETY: head retains either an initialized or partially built field.
            let child = unsafe { &mut *meta.head };
            if unsafe { T::reclaim_field(child.field, place, &mut child.cursor, a)? }
                == Reclaimed::Done
            {
                meta.phase = Phase::Release;
            }
        }
        Phase::Release => {
            a.traverse(1, size_of::<Child<A::Permit>>() as u64)
                .map_err(BoundedError::Refused)?;
            let child = meta.head;
            // SAFETY: the preceding phase reclaimed this exact field completely.
            unsafe {
                meta.head = (*child).previous;
                let permit = ptr::addr_of!((*child).permit).read();
                dealloc(child.cast(), Layout::new::<Child<A::Permit>>());
                meta.phase = Phase::Reclaim;
                drop(permit);
            }
        }
        _ => {
            a.traverse(1, 0).map_err(BoundedError::Refused)?;
            meta.phase = Phase::Reclaim;
        }
    }
    Ok(Reclaimed::Progress)
}
