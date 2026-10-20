//! Stable allocations with intrusive, explicitly stepped reclamation.
//!
//! This owner never calls a value's `Drop`. Implementations explicitly reclaim
//! initialized subobjects, including partial construction, before returning Done.
extern crate alloc;

use alloc::alloc::{alloc, dealloc};
use core::alloc::Layout;
use core::cell::Cell;
use core::marker::{PhantomData, PhantomPinned};
use core::mem::{MaybeUninit, size_of};
use core::ptr::{self, NonNull};

use crate::bounded::{Allocator, BoundedError, BoundedResult};

mod owned;
pub use owned::{OwnedInitialized, OwnedReclaimer, OwnedRecord};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reclaimed {
    Progress,
    Done,
}

/// Fixed-size state initialized before a record can acquire child resources.
/// Its interpretation belongs to the resource implementation.
#[derive(Clone, Copy, Default)]
pub struct Cursor {
    pub position: usize,
    pub state: usize,
}

/// Maximum declared synchronous dispatch depth of an admitted stable record.
/// This is independent of input depth and checked before allocating the record.
pub const MAX_DISPATCH_DEPTH: usize = 64;

/// Mandatory cleanup for a stable, possibly partially initialized allocation.
///
/// # Safety
/// Implementations must interpret the initial zero cursor as uninitialized.
/// They must retain exact initialization/cleanup progress in the cursor or in
/// separately tracked stable storage. Every unit must be admitted before work;
/// refusal must preserve that unit's state. Cleanup must not allocate, unwind,
/// recursively destroy a value, or invoke an arbitrary user destructor.
/// `Done` promises that no initialized subobject or owned child allocation
/// remains and that releasing the outer allocation without `Drop` is sound.
pub unsafe trait Reclaim<A: Allocator>: Sized {
    /// Upper bound on nested construction/reclamation dispatch, including self.
    /// Implementations delegating to children must add their own fixed dispatch
    /// overhead to the maximum child's bound, using saturating arithmetic.
    /// The default is valid only for leaf bindings with no child dispatch.
    /// Understating this bound violates the unsafe implementation contract.
    const DISPATCH_DEPTH: usize = 1;

    /// # Safety
    /// `place` is the original stable allocation and `cursor` describes its
    /// initialized parts. No references into those parts may remain live.
    unsafe fn reclaim_step(
        place: NonNull<MaybeUninit<Self>>,
        cursor: &mut Cursor,
        allocator: &mut A,
    ) -> BoundedResult<Reclaimed, A>;
}

type Advance<A> = unsafe fn(NonNull<Header<A>>, &mut A) -> BoundedResult<Reclaimed, A>;
type Release<A> = unsafe fn(NonNull<Header<A>>);

#[derive(Clone, Copy, PartialEq, Eq)]
enum Custody {
    Handle,
    Queued,
    Active,
}

#[repr(C)]
struct Header<A: Allocator> {
    next: Option<NonNull<Self>>,
    advance: Advance<A>,
    release: Release<A>,
    custody: Custody,
    cleaned: bool,
    _pin: PhantomPinned,
}

#[repr(C)]
struct Block<T, A: Allocator> {
    header: Header<A>,
    cursor: Cursor,
    permit: A::Permit,
    value: MaybeUninit<T>,
}

/// Single-threaded custody owner. Handles borrow the owner; queued blocks are
/// owned by the intrusive list, not by a dropped handle.
///
/// Call `shutdown_step` until it returns Done before destroying the owner.
/// Dropping it with outstanding records is an invariant failure, never an
/// implicit synchronous drain or successful shutdown.
pub struct Reclaimer<A: Allocator> {
    head: Cell<Option<NonNull<Header<A>>>>,
    active: Cell<Option<NonNull<Header<A>>>>,
    outstanding: Cell<usize>,
    closed: Cell<bool>,
    stepping: Cell<bool>,
}

impl<A: Allocator> Default for Reclaimer<A> {
    fn default() -> Self {
        Self::new()
    }
}

impl<A: Allocator> Reclaimer<A> {
    pub const fn new() -> Self {
        Self {
            head: Cell::new(None),
            active: Cell::new(None),
            outstanding: Cell::new(0),
            closed: Cell::new(false),
            stepping: Cell::new(false),
        }
    }

    pub fn outstanding(&self) -> usize {
        self.outstanding.get()
    }

    /// Allocate uninitialized stable storage and its embedded custody record.
    /// No `T` is created or moved. A failed physical allocation releases its
    /// reservation without registering a nonexistent block.
    pub fn allocate<T: Reclaim<A> + 'static>(
        &self,
        a: &mut A,
    ) -> BoundedResult<Record<'_, T, A>, A> {
        // SAFETY: a static payload cannot borrow data that expires while queued.
        unsafe { self.allocate_scoped(a, &mut false) }
    }

    pub(crate) fn allocate_retained<T: Reclaim<A> + 'static>(
        &self,
        a: &mut A,
        admitted: &mut bool,
    ) -> BoundedResult<Record<'_, T, A>, A> {
        // SAFETY: the static payload outlives queued cleanup.
        unsafe { self.allocate_scoped(a, admitted) }
    }

    /// # Safety
    /// Every borrow in T must remain valid until this owner's final cleanup,
    /// including after the last public handle transfers custody to the queue.
    unsafe fn allocate_scoped<T: Reclaim<A>>(
        &self,
        a: &mut A,
        admitted: &mut bool,
    ) -> BoundedResult<Record<'_, T, A>, A> {
        if self.closed.get() || T::DISPATCH_DEPTH > MAX_DISPATCH_DEPTH {
            return Err(BoundedError::PlanMismatch);
        }
        let metadata = size_of::<Header<A>>()
            .checked_add(size_of::<Cursor>())
            .and_then(|n| n.checked_add(size_of::<A::Permit>()))
            .ok_or(BoundedError::Overflow)?;
        // Permit implementations are part of the execution contract. A large
        // inline permit cannot be transferred in a 64-byte unit.
        if metadata > 64 {
            return Err(BoundedError::PlanMismatch);
        }
        let layout = Layout::new::<Block<T, A>>();
        let bytes = u64::try_from(layout.size()).map_err(|_| BoundedError::Overflow)?;
        if !*admitted {
            a.traverse(1, metadata as u64)
                .map_err(BoundedError::Refused)?;
            *admitted = true;
        }
        if self.closed.get() {
            return Err(BoundedError::PlanMismatch);
        }
        let permit = a.allocate(bytes).map_err(BoundedError::Refused)?;
        // Budget/allocator implementations may hold another owner reference.
        // Closure and count must be observed after all external callbacks.
        if self.closed.get() {
            return Err(BoundedError::PlanMismatch);
        }
        let count = self
            .outstanding
            .get()
            .checked_add(1)
            .ok_or(BoundedError::Overflow)?;
        // SAFETY: nonzero layout includes the header, even for a zero-sized T.
        let raw = unsafe { alloc(layout) };
        let block =
            NonNull::new(raw.cast::<Block<T, A>>()).ok_or(BoundedError::Allocation { bytes })?;
        // SAFETY: uniquely owned, correctly aligned storage. Only metadata is
        // initialized; no reference or value is formed for the uninitialized T.
        unsafe {
            ptr::addr_of_mut!((*block.as_ptr()).header).write(Header {
                next: None,
                advance: advance::<T, A>,
                release: release::<T, A>,
                custody: Custody::Handle,
                cleaned: false,
                _pin: PhantomPinned,
            });
            ptr::addr_of_mut!((*block.as_ptr()).cursor).write(Cursor::default());
            ptr::addr_of_mut!((*block.as_ptr()).permit).write(permit);
        }
        self.outstanding.set(count);
        *admitted = false;
        Ok(Record {
            block,
            owner: self,
            marker: PhantomData,
        })
    }

    /// Perform one cleanup unit or release one already-clean block. On refusal
    /// or error the front record remains owned by this list.
    pub fn step(&self, a: &mut A) -> BoundedResult<Reclaimed, A> {
        if self.stepping.replace(true) {
            return Err(BoundedError::PlanMismatch);
        }
        struct Stepping<'a>(&'a Cell<bool>);
        impl Drop for Stepping<'_> {
            fn drop(&mut self) {
                self.0.set(false);
            }
        }
        let _stepping = Stepping(&self.stepping);
        let Some(head) = self.active.get() else {
            if self.head.get().is_some() {
                a.traverse(1, 0).map_err(BoundedError::Refused)?;
                // Re-read after admission: a callback may enqueue a handle.
                // Recursive step is rejected, so no callback can remove it.
                let head = self.head.get().ok_or(BoundedError::PlanMismatch)?;
                unsafe {
                    assert!((*head.as_ptr()).custody == Custody::Queued);
                    self.head.set((*head.as_ptr()).next);
                    (*head.as_ptr()).next = None;
                    (*head.as_ptr()).custody = Custody::Active;
                }
                self.active.set(Some(head));
                return Ok(Reclaimed::Progress);
            }
            return Ok(if self.outstanding.get() == 0 {
                Reclaimed::Done
            } else {
                Reclaimed::Progress
            });
        };
        // SAFETY: the list exclusively owns this block. Cell makes the owner
        // non-Sync and callbacks receive neither the owner nor its list.
        unsafe {
            assert!((*head.as_ptr()).custody == Custody::Active);
            if !(*head.as_ptr()).cleaned {
                if ((*head.as_ptr()).advance)(head, a)? == Reclaimed::Done {
                    (*head.as_ptr()).cleaned = true;
                }
                return Ok(Reclaimed::Progress);
            }
            a.traverse(1, size_of::<A::Permit>() as u64)
                .map_err(BoundedError::Refused)?;
            let release = (*head.as_ptr()).release;
            self.active.set(None);
            release(head);
        }
        self.outstanding.set(self.outstanding.get() - 1);
        Ok(if self.outstanding.get() == 0 {
            Reclaimed::Done
        } else {
            Reclaimed::Progress
        })
    }

    pub fn shutdown_step(&self, a: &mut A) -> BoundedResult<Reclaimed, A> {
        self.closed.set(true);
        self.step(a)
    }
}

/// Custody owner for records that borrow a decode scope's immutable input.
///
/// The invariant lifetime prevents shortening the scope through a shared owner
/// reference. Drop checking keeps borrowed input alive through queued cleanup,
/// even when the record handle has already been dropped. Shutdown is explicit.
pub struct ScopedReclaimer<'scope, A: Allocator> {
    inner: Reclaimer<A>,
    scope: PhantomData<Cell<&'scope ()>>,
}

impl<'scope, A: Allocator> ScopedReclaimer<'scope, A> {
    pub const fn new() -> Self {
        Self {
            inner: Reclaimer::new(),
            scope: PhantomData,
        }
    }

    pub fn allocate<T: Reclaim<A> + 'scope>(
        &self,
        a: &mut A,
    ) -> BoundedResult<Record<'_, T, A>, A> {
        // SAFETY: T outlives the invariant scope. The explicit Drop impl keeps
        // that scope live until inner has checked its complete-drain invariant.
        unsafe { self.inner.allocate_scoped(a, &mut false) }
    }

    pub(crate) fn allocate_retained<T: Reclaim<A> + 'scope>(
        &self,
        a: &mut A,
        admitted: &mut bool,
    ) -> BoundedResult<Record<'_, T, A>, A> {
        // SAFETY: the invariant scope remains live through queued cleanup.
        unsafe { self.inner.allocate_scoped(a, admitted) }
    }

    pub fn outstanding(&self) -> usize {
        self.inner.outstanding()
    }

    pub fn step(&self, a: &mut A) -> BoundedResult<Reclaimed, A> {
        self.inner.step(a)
    }

    pub fn shutdown_step(&self, a: &mut A) -> BoundedResult<Reclaimed, A> {
        self.inner.shutdown_step(a)
    }
}

impl<A: Allocator> Default for ScopedReclaimer<'_, A> {
    fn default() -> Self {
        Self::new()
    }
}

impl<A: Allocator> Drop for ScopedReclaimer<'_, A> {
    fn drop(&mut self) {
        // Deliberately retain drop checking for 'scope. The inner owner performs
        // the outstanding-record assertion; this destructor must not drain it.
    }
}

impl<A: Allocator> Drop for Reclaimer<A> {
    fn drop(&mut self) {
        assert_eq!(
            self.outstanding.get(),
            0,
            "reclamation owner dropped before shutdown completed"
        );
    }
}

/// Constant-size owning handle. Moving this handle never moves its allocation.
type InvariantOwned<T> = PhantomData<(T, fn(T) -> T)>;

pub struct Record<'r, T: Reclaim<A>, A: Allocator> {
    block: NonNull<Block<T, A>>,
    owner: &'r Reclaimer<A>,
    // Invariance prevents shortening a payload borrow after allocation and then
    // initializing a shorter-lived value in storage queued for a longer scope.
    marker: InvariantOwned<T>,
}

impl<'r, T: Reclaim<A>, A: Allocator> Record<'r, T, A> {
    /// Reclaim a still-owned record, preserving it on every refusal. This is
    /// the terminal-error path: completion means this record's storage and
    /// reservation were released, independent of other records in the owner.
    pub fn reclaim_step(record: &mut Option<Self>, a: &mut A) -> BoundedResult<Reclaimed, A> {
        let Some(current) = record.as_mut() else {
            return Ok(Reclaimed::Done);
        };
        let header = current.block.cast::<Header<A>>();
        // SAFETY: the unique handle has not been queued, and &mut Option<Self>
        // excludes publication and concurrent access to its destination.
        unsafe {
            assert!((*header.as_ptr()).custody == Custody::Handle);
            if !(*header.as_ptr()).cleaned {
                if ((*header.as_ptr()).advance)(header, a)? == Reclaimed::Done {
                    (*header.as_ptr()).cleaned = true;
                }
                return Ok(Reclaimed::Progress);
            }
            a.traverse(1, size_of::<A::Permit>() as u64)
                .map_err(BoundedError::Refused)?;
            // The Some branch above proves the take succeeds. Suppress Drop:
            // this handle is released here, never enqueued with a freed pointer.
            let current =
                core::mem::ManuallyDrop::new(record.take().ok_or(BoundedError::PlanMismatch)?);
            let owner = current.owner;
            ((*header.as_ptr()).release)(header);
            owner.outstanding.set(owner.outstanding.get() - 1);
        }
        Ok(Reclaimed::Done)
    }

    /// Publish a small owning handle without moving the initialized value.
    ///
    /// # Safety
    /// The entire destination must be a valid initialized T, and the cursor
    /// must describe all its resources for incremental reclamation. No mutable
    /// aliases or outstanding construction pointers may subsequently be used.
    pub unsafe fn publish(self) -> Initialized<'r, T, A> {
        Initialized { record: self }
    }

    /// Access the stable construction destination and its custody metadata.
    ///
    /// # Safety
    /// The caller must admit all work, update the cursor to track every acquired
    /// resource, and preserve the invariants required by `T::reclaim_step` on
    /// every return, including error and cancellation. No initialized T may be
    /// moved out and no pointer may be used after this record is dropped.
    pub unsafe fn destination(&mut self) -> (NonNull<MaybeUninit<T>>, &mut Cursor) {
        // SAFETY: &mut self grants exclusive access; the allocation stays fixed.
        unsafe {
            (
                NonNull::new_unchecked(ptr::addr_of_mut!((*self.block.as_ptr()).value)),
                &mut (*self.block.as_ptr()).cursor,
            )
        }
    }
}

/// Published stable value; destroying the handle only transfers its record.
pub struct Initialized<'r, T: Reclaim<A>, A: Allocator> {
    record: Record<'r, T, A>,
}

impl<T: Reclaim<A>, A: Allocator> Initialized<'_, T, A> {
    pub fn value(&self) -> &T {
        // SAFETY: publish requires complete initialization. The owning record
        // cannot be queued while this borrow is live, so cleanup cannot run.
        unsafe { (&*ptr::addr_of!((*self.record.block.as_ptr()).value)).assume_init_ref() }
    }
}

impl<T: Reclaim<A>, A: Allocator> Drop for Record<'_, T, A> {
    fn drop(&mut self) {
        let header = self.block.cast::<Header<A>>();
        // SAFETY: repr(C) places Header first; this unique handle transfers its
        // block exactly once. No allocation, traversal, or destructor is called.
        unsafe {
            assert!((*header.as_ptr()).custody == Custody::Handle);
            (*header.as_ptr()).next = self.owner.head.get();
            (*header.as_ptr()).custody = Custody::Queued;
        }
        self.owner.head.set(Some(header));
    }
}

unsafe fn advance<T: Reclaim<A>, A: Allocator>(
    header: NonNull<Header<A>>,
    a: &mut A,
) -> BoundedResult<Reclaimed, A> {
    let block = header.cast::<Block<T, A>>();
    // SAFETY: the vtable was installed for exactly this Block<T, A>, and the
    // caller has exclusive custody after the public handle was dropped.
    unsafe {
        T::reclaim_step(
            NonNull::new_unchecked(ptr::addr_of_mut!((*block.as_ptr()).value)),
            &mut (*block.as_ptr()).cursor,
            a,
        )
    }
}

unsafe fn release<T: Reclaim<A>, A: Allocator>(header: NonNull<Header<A>>) {
    let block = header.cast::<Block<T, A>>();
    // SAFETY: cleanup returned Done; there are no live child values. Read the
    // permit before freeing its storage, then release accounting after dealloc.
    unsafe {
        let permit = ptr::addr_of!((*block.as_ptr()).permit).read();
        dealloc(block.as_ptr().cast(), Layout::new::<Block<T, A>>());
        drop(permit);
    }
}
