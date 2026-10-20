//! An optional payload whose native representation never contains T inline.
extern crate alloc;
use super::*;
use alloc::alloc::{alloc, dealloc};
use core::{alloc::Layout, marker::PhantomData, mem::size_of, ptr};

/// Optional stable storage for payloads that cannot use a bounded native
/// `Option<T>` placeholder. Construction publishes the pointer only after T is
/// initialized. Its enclosing decode record owns incremental reclamation.
///
/// The allocator parameter identifies the reservation stored with the payload.
/// Access is borrowed; there is no by-value extraction or synchronous Drop path.
pub struct StableOption<T, A: Allocator> {
    payload: Option<NonNull<Payload<T, A::Permit>>>,
    marker: PhantomData<(T, A::Permit)>,
}

struct Payload<T, P> {
    child: Cursor,
    phase: Phase,
    permit: P,
    value: MaybeUninit<T>,
}

#[derive(Clone, Copy)]
enum Phase {
    Build,
    Publish,
    Clean,
}

impl<T, A: Allocator> StableOption<T, A> {
    pub fn as_ref(&self) -> Option<&T> {
        self.payload.map(|payload| {
            // SAFETY: publication installs the pointer only after the child
            // returns Done. The enclosing value borrow excludes reclamation.
            unsafe { (&*ptr::addr_of!((*payload.as_ptr()).value)).assume_init_ref() }
        })
    }

    pub fn is_some(&self) -> bool {
        self.payload.is_some()
    }
}

// SAFETY: the cursor records the payload allocation before construction starts.
// No native Option<T> layout or placeholder is required, irrespective of T size.
unsafe impl<T: InPlace<A>, A: Allocator> InPlace<A> for StableOption<T, A> {
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
        if cursor.state != 0 || cursor.position > 1 {
            return Err(BoundedError::PlanMismatch.into());
        }
        a.traverse(1, size_of::<Self>() as u64)
            .map_err(BoundedError::Refused)?;
        unsafe {
            place.as_ptr().write(MaybeUninit::new(Self {
                payload: None,
                marker: PhantomData,
            }));
        }
        cursor.position = 2;
        Ok(Built::Done)
    }

    unsafe fn build_step(
        document: &Document<'_, A::Permit>,
        index: usize,
        place: NonNull<MaybeUninit<Self>>,
        cursor: &mut Cursor,
        a: &mut A,
    ) -> ConstructResult<Built, A> {
        if cursor.position == 2 {
            return Err(BoundedError::PlanMismatch.into());
        }
        if cursor.state == 0 {
            if cursor.position == 0 {
                a.traverse(1, 0).map_err(BoundedError::Refused)?;
                if matches!(
                    node_at(document, index).ok_or_else(wrong_type)?.kind(),
                    Kind::Null
                ) {
                    // Retain the null decision separately from its admitted write.
                    cursor.position = 3;
                } else {
                    cursor.position = 1;
                }
                return Ok(Built::Progress);
            }
            if cursor.position == 3 {
                a.traverse(1, size_of::<Self>() as u64)
                    .map_err(BoundedError::Refused)?;
                unsafe {
                    place.as_ptr().write(MaybeUninit::new(Self {
                        payload: None,
                        marker: PhantomData,
                    }));
                }
                cursor.position = 2;
                return Ok(Built::Done);
            }
            let metadata = size_of::<Cursor>() + size_of::<Phase>() + size_of::<A::Permit>();
            if metadata > 64 {
                return Err(BoundedError::PlanMismatch.into());
            }
            let layout = Layout::new::<Payload<T, A::Permit>>();
            let bytes = u64::try_from(layout.size()).map_err(|_| BoundedError::Overflow)?;
            a.traverse(1, metadata as u64)
                .map_err(BoundedError::Refused)?;
            let permit = a.allocate(bytes).map_err(BoundedError::Refused)?;
            // SAFETY: the metadata makes this layout nonzero, including for ZST T.
            let raw = unsafe { alloc(layout) }.cast::<Payload<T, A::Permit>>();
            let payload = NonNull::new(raw).ok_or(BoundedError::Allocation { bytes })?;
            unsafe {
                ptr::addr_of_mut!((*raw).child).write(Cursor::default());
                ptr::addr_of_mut!((*raw).phase).write(Phase::Build);
                ptr::addr_of_mut!((*raw).permit).write(permit);
            }
            cursor.state = payload.as_ptr() as usize;
            return Ok(Built::Progress);
        }
        let raw = cursor.state as *mut Payload<T, A::Permit>;
        let payload = unsafe { &mut *raw };
        match payload.phase {
            Phase::Build => {
                if unsafe {
                    T::build_step(
                        document,
                        index,
                        NonNull::from(&mut payload.value),
                        &mut payload.child,
                        a,
                    )?
                } == Built::Done
                {
                    payload.phase = Phase::Publish;
                }
                Ok(Built::Progress)
            }
            Phase::Publish => {
                a.traverse(1, size_of::<Self>() as u64)
                    .map_err(BoundedError::Refused)?;
                unsafe {
                    place.as_ptr().write(MaybeUninit::new(Self {
                        payload: NonNull::new(raw),
                        marker: PhantomData,
                    }));
                }
                cursor.position = 2;
                Ok(Built::Done)
            }
            Phase::Clean => Err(BoundedError::PlanMismatch.into()),
        }
    }
}

// SAFETY: cleanup uses the custody cursor, including before pointer publication.
// It releases the payload only after its mandatory incremental cleanup completes.
unsafe impl<T: Reclaim<A>, A: Allocator> Reclaim<A> for StableOption<T, A> {
    const DISPATCH_DEPTH: usize = T::DISPATCH_DEPTH.saturating_add(2);

    unsafe fn reclaim_step(
        _: NonNull<MaybeUninit<Self>>,
        cursor: &mut Cursor,
        a: &mut A,
    ) -> BoundedResult<Reclaimed, A> {
        if cursor.state == 0 {
            a.traverse(1, 0).map_err(BoundedError::Refused)?;
            cursor.position = 0;
            return Ok(Reclaimed::Done);
        }
        let raw = cursor.state as *mut Payload<T, A::Permit>;
        let payload = unsafe { &mut *raw };
        if !matches!(payload.phase, Phase::Clean) {
            if unsafe { T::reclaim_step(NonNull::from(&mut payload.value), &mut payload.child, a)? }
                == Reclaimed::Done
            {
                payload.phase = Phase::Clean;
            }
            return Ok(Reclaimed::Progress);
        }
        a.traverse(1, size_of::<A::Permit>() as u64)
            .map_err(BoundedError::Refused)?;
        unsafe {
            let permit = ptr::addr_of!((*raw).permit).read();
            dealloc(raw.cast(), Layout::new::<Payload<T, A::Permit>>());
            *cursor = Cursor::default();
            drop(permit);
        }
        Ok(Reclaimed::Done)
    }
}
