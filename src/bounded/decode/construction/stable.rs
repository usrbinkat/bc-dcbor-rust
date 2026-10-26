//! The single stable-block primitive.
//!
//! Every fixed metadata record, child custody record, lifecycle record and
//! owned scope is one allocation acquired and released by this module, with the
//! same units: admission of the bytes written and of the block's eventual
//! release, a permit for the whole block, a fallible physical allocation,
//! initialization in place; later, the block freed and then its permit
//! released, which its acquisition paid for. No destructor of the held value
//! ever runs: its owner must have made it resource-free first.
extern crate alloc;

use alloc::alloc::{alloc, dealloc};
use core::alloc::Layout;
use core::marker::PhantomData;
use core::mem::{MaybeUninit, size_of};
use core::ptr::{self, NonNull};

use crate::bounded::{
    Allocator, BoundedError, BoundedResult, Caller, Capped, ResourceBound, TURN, Unit,
};

/// The largest unit of bytes any single admission may cover: the bytes of
/// one turn's quantum ([`TURN`]).
pub const QUANTUM: usize = TURN.bytes as usize;

/// Writing a block's value: one value and its bytes, at most a quantum. The
/// block's owner supplies the place.
const WRITE: Capped<Caller> = Capped::new(Caller, 1, TURN.bytes);

/// Releasing a block or a reservation held with permits of `P`: one value
/// and the permit's bytes. Admitted by the acquisition, before the
/// allocation exists, so the release is paid for on every path that frees
/// it, a metered cleanup step or a terminal one.
const fn released<P>() -> Unit<Caller> {
    Unit::new(Caller, 1, crate::bounded::permit_bytes::<P>() as u64)
}

/// Admit the release of an allocation with permits of `A::Permit` before
/// acquiring it: what every acquisition outside this module admits for the
/// allocation it is about to request ([`released`]), its permit checked
/// against [`crate::bounded::PERMIT_BYTES`] where the acquisition is used.
pub(crate) fn admit_release<A: Allocator>(a: &mut A) -> BoundedResult<(), A> {
    const { released::<A::Permit>() }.admit(a)
}

/// The admissions an acquisition has made toward a block, kept across a
/// refused or failed allocation so no admitted unit is repeated: none, the
/// block's write, or its write and its release. Its holder keeps it with the
/// slot the block will occupy. Part of every custody observation of an
/// acquisition in progress: it fixes what the acquisition's next step
/// admits.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub enum Admitted {
    #[default]
    Nothing,
    Write,
    Release,
}

/// The bytes a block's acquisition writes, established when its type is
/// instantiated: at most a quantum, so the write is one admitted unit, of a
/// block that occupies memory. Every caller constructs it in a constant
/// (`const { .. }` or an associated constant), so a block that cannot be
/// written in one unit fails to compile where its type is used, and
/// [`acquire`] holds no run-time check of either bound.
#[derive(Clone, Copy)]
pub(crate) struct Metadata {
    bytes: usize,
}

impl Metadata {
    /// `written` bytes of a block of `M` with permits of `P`.
    pub(crate) const fn new<M, P>(written: usize) -> Self {
        assert!(
            size_of::<Held<M, P>>() > 0,
            "a stable block occupies memory"
        );
        Self {
            bytes: crate::bounded::write_extent(written) as usize,
        }
    }

    /// The whole block of `M` with permits of `P`, written.
    pub(crate) const fn whole<M, P>() -> Self {
        Self::new::<M, P>(size_of::<Held<M, P>>())
    }

    /// The bytes written.
    pub(crate) const fn bytes(self) -> usize {
        self.bytes
    }
}

/// What [`acquire`] admits for a block whose initialization writes
/// `metadata`: one [`WRITE`] of its bytes. Its release ([`release_cost`]) is
/// admitted with it.
pub(crate) const fn acquire_cost(metadata: Metadata) -> ResourceBound {
    Unit::new(Caller, WRITE.values(), metadata.bytes as u64).bound()
}

/// What [`install`] admits for metadata `M` with permits of `P`: the whole
/// block written.
pub(crate) const fn install_cost<M, P>() -> ResourceBound {
    acquire_cost(Metadata::whole::<M, P>())
}

/// What one release unit admits, with permits of `P`, by the acquisition it
/// pays for ([`admit_release`], [`acquire`]).
pub(crate) const fn release_cost<P>() -> ResourceBound {
    released::<P>().bound()
}

/// A held value followed by the permit for its whole allocation. `value` is
/// first, so a pointer to the block is a pointer to the value's first field.
#[repr(C)]
pub(crate) struct Held<M, P> {
    pub(crate) value: M,
    permit: P,
}

impl<M, P> Held<M, P> {
    pub(crate) fn permit(&self) -> &P {
        &self.permit
    }
}

/// Acquire one stable block. `metadata` is what `init` writes, established
/// at compile time ([`Metadata`]). The write, then the block's release, are
/// each admitted once, before the allocation is requested; `admitted` keeps
/// what was admitted across a refused or failed allocation. `open` is
/// consulted after the permit is granted and before memory is touched,
/// because allocator callbacks may close the owning scope.
///
/// # Safety
/// `init` must initialize every part of the value that later code reads,
/// without unwinding, allocating, or reading uninitialized memory.
/// `metadata` was established for this `M` and `A::Permit`.
pub(crate) unsafe fn acquire<M, A: Allocator>(
    admitted: &mut Admitted,
    metadata: Metadata,
    open: impl Fn() -> bool,
    init: impl FnOnce(*mut M),
    a: &mut A,
) -> BoundedResult<NonNull<Held<M, A::Permit>>, A> {
    let layout = Layout::new::<Held<M, A::Permit>>();
    let bytes = u64::try_from(layout.size()).map_err(|_| BoundedError::Overflow)?;
    if !open() {
        return Err(BoundedError::PlanMismatch);
    }
    if *admitted == Admitted::Nothing {
        WRITE.admit(a, metadata.bytes as u64)?;
        *admitted = Admitted::Write;
    }
    if *admitted == Admitted::Write {
        admit_release(a)?;
        *admitted = Admitted::Release;
    }
    let permit = a.allocate(bytes).map_err(BoundedError::Refused)?;
    if !open() {
        return Err(BoundedError::PlanMismatch);
    }
    // SAFETY: the layout is nonzero ([`Metadata`]); a null result is a
    // physical failure and drops the granted permit, releasing exactly what
    // was admitted for it.
    let raw = NonNull::new(unsafe { alloc(layout) }.cast::<Held<M, A::Permit>>())
        .ok_or(BoundedError::Allocation { bytes })?;
    // SAFETY: the block is unique and aligned. The permit is written before
    // the value, so the block is always releasable once `init` returns.
    unsafe {
        ptr::addr_of_mut!((*raw.as_ptr()).permit).write(permit);
        init(ptr::addr_of_mut!((*raw.as_ptr()).value));
    }
    *admitted = Admitted::Nothing;
    Ok(raw)
}

/// Free a block and release its permit, a release its acquisition paid for:
/// the storage freed first, then the permit dropped.
///
/// # Safety
/// The block came from `acquire` with the same `M` and `P`, is not referenced
/// anywhere else, and its value owns no resources.
pub(crate) unsafe fn free<M, P>(held: NonNull<Held<M, P>>) {
    // SAFETY: read the permit out, free the storage, then release accounting.
    unsafe {
        let permit = ptr::addr_of!((*held.as_ptr()).permit).read();
        dealloc(held.as_ptr().cast(), Layout::new::<Held<M, P>>());
        drop(permit);
    }
}

/// The one authority over a stable block of metadata `M` and its permit `P`.
///
/// Only [`install`] creates one, from the block it has just acquired, and
/// only [`uninstall`] consumes one, releasing that block. The handle is not
/// `Copy` or `Clone` and has no public constructor, so no code outside this
/// module can mint one or duplicate it: holding the handle is holding the
/// block. The block's address is held as a pointer throughout, never as an
/// integer, so its provenance survives every suspension. The only other
/// pointers to the block are views ([`Self::view`]) its owner publishes for
/// shared reads, whose use the custody protocol ends before the block is
/// accessed mutably again or uninstalled.
pub struct Installed<M, P> {
    block: NonNull<Held<M, P>>,
    /// Owns a `Held<M, P>`, for variance and auto-trait purposes.
    marker: PhantomData<Held<M, P>>,
}

// SAFETY: an `Installed` is the unique owner of its block, as a `Box` is of
// its allocation: no other authority over the block exists, and views are
// held only beside the handle in the same record, so moving the handle
// moves the only mutable access. Sending it sends an `M` and a `P`, so it is
// `Send` exactly when both are.
unsafe impl<M: Send, P: Send> Send for Installed<M, P> {}
// SAFETY: shared access through `&Installed` yields only `&M` (`peek`) and a
// copy of the pointer (`view`); the permit is never reached. As for a `Box`,
// sharing the handle shares an `M`, so it is `Sync` exactly when `M` is.
unsafe impl<M: Sync, P> Sync for Installed<M, P> {}

impl<M, P> Installed<M, P> {
    /// The installed metadata, borrowed for as long as the handle is.
    pub(crate) fn get(&mut self) -> &mut M {
        // SAFETY: the handle owns its live, initialized block exclusively;
        // the borrow of `self` bounds the returned reference.
        unsafe { &mut (*self.block.as_ptr()).value }
    }

    /// The installed metadata, read through a shared borrow of the handle:
    /// how an observation reads progress kept in the block.
    pub(crate) fn peek(&self) -> &M {
        // SAFETY: the handle owns its live, initialized block; `get` needs
        // `&mut self`, so no mutable borrow coexists with this one.
        unsafe { &(*self.block.as_ptr()).value }
    }

    /// The block's address, for a view the owner publishes for shared reads:
    /// a copy of the handle's own pointer, so it carries the block's
    /// provenance. The owner must end every use of the view before the block
    /// is next accessed through [`Self::get`] or uninstalled.
    pub(crate) fn view(&self) -> NonNull<Held<M, P>> {
        self.block
    }

    /// Move the value out, leaving the block holding nothing: the handle
    /// returned is typed as vacated, so the moved-out bytes can never be
    /// read or dropped again, and the block can only be freed.
    pub(crate) fn vacate(self) -> (M, Installed<MaybeUninit<M>, P>) {
        const {
            assert!(
                size_of::<Held<M, P>>() == size_of::<Held<MaybeUninit<M>, P>>()
                    && core::mem::align_of::<Held<M, P>>()
                        == core::mem::align_of::<Held<MaybeUninit<M>, P>>(),
                "a vacated block has its value's layout"
            )
        };
        // SAFETY: the handle owns its live, initialized block exclusively and
        // is consumed here, so the value is read out exactly once; the
        // vacated handle reaches the same block, whose value it types as
        // uninitialized and whose permit is untouched. `Held` is `repr(C)`
        // and `MaybeUninit<M>` has `M`'s layout, so the permit keeps its
        // offset.
        unsafe {
            let value = ptr::addr_of!((*self.block.as_ptr()).value).read();
            (
                value,
                Installed {
                    block: self.block.cast(),
                    marker: PhantomData,
                },
            )
        }
    }

    /// Drop the value in place, then free the block and release its permit,
    /// a release its acquisition paid for: the terminal release of an
    /// owner dropped without stepped cleanup.
    ///
    /// # Safety
    /// The value's destructor frees only allocations admitted with their
    /// releases, and neither unwinds nor allocates.
    pub(crate) unsafe fn dispose(self) {
        // SAFETY: the handle owns its live, initialized block exclusively and
        // is consumed here; forwarded from the caller.
        unsafe {
            ptr::drop_in_place(ptr::addr_of_mut!((*self.block.as_ptr()).value));
            free(self.block);
        }
    }
}

impl<M, P> Installed<MaybeUninit<M>, P> {
    /// Free a vacated block and release its permit, a release its
    /// acquisition paid for. Its bytes hold no value, so nothing is dropped.
    pub(crate) fn free(self) {
        // SAFETY: the handle is the block's only authority and is consumed;
        // a vacated block's value owns nothing.
        unsafe { free(self.block) };
    }
}

/// Acquire a block of `M`, `init` writing `metadata` of it, admissions kept
/// in `admitted` across a refused or failed allocation; the handle that
/// owns it.
///
/// # Safety
/// As [`acquire`].
pub(crate) unsafe fn installed<M, A: Allocator>(
    admitted: &mut Admitted,
    metadata: Metadata,
    init: impl FnOnce(*mut M),
    a: &mut A,
) -> BoundedResult<Installed<M, A::Permit>, A> {
    // SAFETY: forwarded from the caller.
    let block = unsafe { acquire::<M, A>(admitted, metadata, || true, init, a)? };
    Ok(Installed {
        block,
        marker: PhantomData,
    })
}

/// Acquire a block of `M` into the empty `slot`, `init` writing `metadata`
/// of it, admissions kept in `admitted` across a refused or failed
/// allocation.
///
/// # Safety
/// As [`acquire`]. A `slot` already holding a block is a plan mismatch and
/// acquires nothing.
pub(crate) unsafe fn install<M, A: Allocator>(
    slot: &mut Option<Installed<M, A::Permit>>,
    admitted: &mut Admitted,
    metadata: Metadata,
    init: impl FnOnce(*mut M),
    a: &mut A,
) -> BoundedResult<(), A> {
    if slot.is_some() {
        return Err(BoundedError::PlanMismatch);
    }
    // SAFETY: forwarded from the caller.
    *slot = Some(unsafe { installed::<M, A>(admitted, metadata, init, a)? });
    Ok(())
}

/// Free the block `slot` holds, if any, and empty it: a release its
/// acquisition paid for, so nothing is admitted and nothing can refuse.
///
/// # Safety
/// The block's metadata owns no resources.
pub(crate) unsafe fn uninstall<M, P>(slot: &mut Option<Installed<M, P>>) {
    if let Some(installed) = slot.take() {
        // SAFETY: the handle was the block's only authority and is consumed
        // here; forwarded from the caller, its metadata owns nothing.
        unsafe { free(installed.block) };
    }
}

/// One child custody record: the child's own construction state, typed by
/// the engine that pushed it, and the record before it.
pub(crate) struct Child<S, P> {
    pub(crate) state: S,
    previous: Option<NonNull<Held<Child<S, P>, P>>>,
}

/// Last-in-first-out custody records for the children of one construction.
/// A record is pushed before its child acquires anything, so cleanup always
/// finds every partial child, newest first.
pub(crate) struct Stack<S, P> {
    head: Option<NonNull<Held<Child<S, P>, P>>>,
    admitted: Admitted,
    /// The records in the chain: a count the stack keeps beside its head,
    /// so observing it walks nothing.
    len: usize,
}

// SAFETY: the stack exclusively owns every record in its chain, as a
// `Box`-linked list does; sending it sends each record's `S` and `P`.
unsafe impl<S: Send, P: Send> Send for Stack<S, P> {}
// SAFETY: the only `&self` methods read the stack's own `len` and
// `admitted`, plain values; no record, state or permit is reached through
// shared access.
unsafe impl<S, P> Sync for Stack<S, P> {}

impl<S, P> Stack<S, P> {
    pub(crate) const fn new() -> Self {
        Self {
            head: None,
            admitted: Admitted::Nothing,
            len: 0,
        }
    }

    /// The records held, newest included.
    pub(crate) fn len(&self) -> usize {
        self.len
    }

    /// The admissions held toward the next record's block.
    pub(crate) fn admitted(&self) -> Admitted {
        self.admitted
    }

    /// Push a record holding `state`, the child's initial state, admissions
    /// kept across a refused or failed allocation.
    pub(crate) fn push<A: Allocator<Permit = P>>(
        &mut self,
        state: S,
        a: &mut A,
    ) -> BoundedResult<(), A> {
        let previous = self.head;
        // SAFETY: every field of Child is written by the initializer.
        let held = unsafe {
            acquire::<Child<S, P>, A>(
                &mut self.admitted,
                const { Metadata::whole::<Child<S, P>, P>() },
                || true,
                |child| child.write(Child { state, previous }),
                a,
            )?
        };
        self.head = Some(held);
        self.len += 1;
        Ok(())
    }

    /// Each record's state, newest first, under the stack's exclusive
    /// custody: how a holder sums what its children's cleanup still owes.
    /// Visits exactly [`Self::len`] records, changing none.
    pub(crate) fn for_each(&mut self, mut visit: impl FnMut(&mut S)) {
        let mut next = self.head;
        for _ in 0..self.len {
            let Some(held) = next else {
                return;
            };
            // SAFETY: every block in the chain is owned by this stack until
            // popped, and the exclusive borrow excludes popping meanwhile.
            unsafe {
                visit(&mut (*held.as_ptr()).value.state);
                next = (*held.as_ptr()).value.previous;
            }
        }
    }

    pub(crate) fn top(&mut self) -> Option<&mut Child<S, P>> {
        // SAFETY: the head block is owned by this stack until popped.
        self.head.map(|held| unsafe { &mut (*held.as_ptr()).value })
    }

    /// Release the newest record, whose child has been reclaimed, if any: a
    /// release its push paid for. True when a record was released.
    pub(crate) fn pop(&mut self) -> bool {
        let Some(held) = self.head else {
            return false;
        };
        // SAFETY: the head is owned by this stack and its child owns nothing.
        unsafe {
            self.head = (*held.as_ptr()).value.previous;
            free(held);
        }
        self.len -= 1;
        true
    }
}
