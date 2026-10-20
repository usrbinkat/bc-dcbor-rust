//! Retained discriminant selection and tag-last enum construction.
extern crate alloc;
use super::*;
use alloc::alloc::{alloc, dealloc};
use core::{alloc::Layout, mem::size_of, ptr};

/// Representation-specific projections generated from explicit enum layouts.
///
/// # Safety
/// Descriptors select unique wire discriminants. Payload callbacks must project
/// the selected variant using its declared Rust representation, retaining the
/// same child cursor through cleanup. Commit writes only the native tag, after
/// all payload fields are initialized. No callback may construct an enum value
/// by value or form a reference to a partially initialized enum.
pub unsafe trait Variants<A: Allocator>: Sized {
    const COUNT: usize;
    const TAG: Option<u64>;
    const TAG_BYTES: usize;
    fn descriptor(variant: usize) -> (u64, u64);
    /// # Safety
    /// The destination is stable and the selected payload cursor is unique.
    unsafe fn build_variant(
        variant: usize,
        document: &Document<'_, A::Permit>,
        index: usize,
        place: NonNull<MaybeUninit<Self>>,
        cursor: &mut Cursor,
        a: &mut A,
    ) -> ConstructResult<Built, A>;
    /// # Safety
    /// The cursor and destination are the original selected payload pair.
    unsafe fn reclaim_variant(
        variant: usize,
        place: NonNull<MaybeUninit<Self>>,
        cursor: &mut Cursor,
        a: &mut A,
    ) -> BoundedResult<Reclaimed, A>;
    /// # Safety
    /// All selected payload fields are initialized; TAG_BYTES was admitted.
    unsafe fn commit(variant: usize, place: NonNull<MaybeUninit<Self>>);
}

#[derive(Clone, Copy)]
enum Phase {
    Tag,
    Shape,
    Discriminant,
    Select,
    Build,
    Commit,
    Complete,
    Release,
}
struct Meta<P> {
    child: Cursor,
    index: usize,
    discriminant: u64,
    length: u64,
    permit: P,
    phase: Phase,
}

/// # Safety
/// The destination and cursor satisfy InPlace's stable ownership contract.
pub unsafe fn build<T: Variants<A>, A: Allocator>(
    document: &Document<'_, A::Permit>,
    index: usize,
    place: NonNull<MaybeUninit<T>>,
    cursor: &mut Cursor,
    a: &mut A,
) -> ConstructResult<Built, A> {
    if cursor.state == 0 {
        let layout = Layout::new::<Meta<A::Permit>>();
        if layout.size() > 64 || T::TAG_BYTES > 64 {
            return Err(BoundedError::PlanMismatch.into());
        }
        let bytes = layout.size() as u64;
        if cursor.position == 0 {
            a.traverse(1, bytes).map_err(BoundedError::Refused)?;
            cursor.position = 1;
        }
        let permit = a.allocate(bytes).map_err(BoundedError::Refused)?;
        // SAFETY: nonzero metadata, initialized before registration.
        let raw = unsafe { alloc(layout) }.cast::<Meta<A::Permit>>();
        let meta = NonNull::new(raw).ok_or(BoundedError::Allocation { bytes })?;
        unsafe {
            meta.as_ptr().write(Meta {
                child: Cursor::default(),
                index,
                discriminant: 0,
                length: 0,
                permit,
                phase: Phase::Tag,
            })
        };
        cursor.state = meta.as_ptr() as usize;
        cursor.position = 0;
        return Ok(Built::Progress);
    }
    // SAFETY: metadata remains live until Release.
    let meta = unsafe { &mut *(cursor.state as *mut Meta<A::Permit>) };
    match meta.phase {
        Phase::Tag => {
            a.traverse(1, 0).map_err(BoundedError::Refused)?;
            if let Some(expected) = T::TAG {
                match node_at(document, meta.index).map(|n| n.kind()) {
                    Some(Kind::Tagged(found)) if found == expected => {}
                    Some(Kind::Tagged(found)) => {
                        return Err(crate::bounded::decode::DecodeError::Invalid(
                            crate::Error::WrongTag(
                                crate::Tag::with_value(expected),
                                crate::Tag::with_value(found),
                            ),
                        ));
                    }
                    _ => return Err(wrong_type()),
                }
                meta.index = meta.index.checked_add(1).ok_or(BoundedError::Overflow)?;
            }
            meta.phase = Phase::Shape;
        }
        Phase::Shape => {
            a.traverse(1, 0).map_err(BoundedError::Refused)?;
            match node_at(document, meta.index).map(|n| n.kind()) {
                Some(Kind::Unsigned(disc)) => {
                    meta.discriminant = disc;
                    meta.phase = Phase::Select;
                }
                Some(Kind::Array(length)) if length > 0 => {
                    meta.length = length;
                    meta.index = meta.index.checked_add(1).ok_or(BoundedError::Overflow)?;
                    meta.phase = Phase::Discriminant;
                }
                _ => return Err(wrong_type()),
            }
        }
        Phase::Discriminant => {
            a.traverse(1, 0).map_err(BoundedError::Refused)?;
            meta.discriminant = match node_at(document, meta.index).map(|n| n.kind()) {
                Some(Kind::Unsigned(disc)) => disc,
                Some(Kind::Negative(_)) => {
                    return Err(crate::bounded::decode::DecodeError::Invalid(
                        crate::Error::OutOfRange,
                    ));
                }
                _ => return Err(wrong_type()),
            };
            meta.index = meta.index.checked_add(1).ok_or(BoundedError::Overflow)?;
            meta.phase = Phase::Select;
        }
        Phase::Select => {
            a.traverse(1, 0).map_err(BoundedError::Refused)?;
            if cursor.position == T::COUNT {
                return Err(wrong_type());
            }
            let (disc, length) = T::descriptor(cursor.position);
            if disc == meta.discriminant {
                if length != meta.length {
                    return Err(wrong_type());
                }
                meta.phase = Phase::Build;
            } else {
                cursor.position += 1;
            }
        }
        Phase::Build => {
            if unsafe {
                T::build_variant(
                    cursor.position,
                    document,
                    meta.index,
                    place,
                    &mut meta.child,
                    a,
                )?
            } == Built::Done
            {
                meta.phase = Phase::Commit;
            }
        }
        Phase::Commit => {
            a.traverse(1, T::TAG_BYTES as u64)
                .map_err(BoundedError::Refused)?;
            unsafe { T::commit(cursor.position, place) };
            meta.phase = Phase::Complete;
            return Ok(Built::Done);
        }
        _ => return Err(BoundedError::PlanMismatch.into()),
    }
    Ok(Built::Progress)
}

/// # Safety
/// The destination and cursor are the original construction pair.
pub unsafe fn reclaim<T: Variants<A>, A: Allocator>(
    place: NonNull<MaybeUninit<T>>,
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
        Phase::Build | Phase::Commit | Phase::Complete => {
            if unsafe { T::reclaim_variant(cursor.position, place, &mut meta.child, a)? }
                == Reclaimed::Done
            {
                meta.phase = Phase::Release;
            }
        }
        Phase::Release => {
            a.traverse(1, size_of::<A::Permit>() as u64)
                .map_err(BoundedError::Refused)?;
            // SAFETY: payload reclamation finished, or no payload was started.
            unsafe {
                let permit = ptr::addr_of!((*raw).permit).read();
                dealloc(raw.cast(), Layout::new::<Meta<A::Permit>>());
                cursor.state = 0;
                cursor.position = 0;
                drop(permit);
            }
            return Ok(Reclaimed::Done);
        }
        _ => {
            a.traverse(1, 0).map_err(BoundedError::Refused)?;
            meta.phase = Phase::Release;
        }
    }
    Ok(Reclaimed::Progress)
}
