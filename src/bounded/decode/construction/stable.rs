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

use super::reclamation::Place;
use crate::bounded::{
    Allocator, BoundedError, BoundedResult, Caller, Capped, ResourceBound, TURN, Unit,
};
use crate::sync::{Atomics, Core, Representation};

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

/// The contract quantities of acquiring a block of `M` with permits of `P`
/// whose acquisition writes a header `W`: the bytes written, the permit and
/// the header, one typed value written whole, at most a quantum together, so
/// the write is one admitted unit ([`Self::write`]); and the block's bytes,
/// requested from the allocator and held until the block is freed
/// ([`Self::block`]). Padding the write does not reach, between the value
/// and the permit or past the header, is storage the block holds, not bytes
/// written.
///
/// The one definition of both: [`acquire`] admits exactly the contract it
/// is given, whose type names what it stores, and every cost term of a
/// block reads the same contract, so a block's charge and its bound cannot
/// diverge. `W` and `M` are the types the build stores; the quantities are
/// read from their production representation
/// ([`Representation::In<Core>`](Representation)), so they are the same in
/// every build whatever atomics a model checker substitutes, while
/// [`acquire`] stores and frees `M`'s physical layout. Built only by
/// [`Self::of`], which every caller evaluates in a constant (`const { .. }`
/// or an associated constant), so a write beyond a quantum fails to compile
/// where the block's type is used and [`acquire`] holds no run-time check.
pub(crate) struct Contract<W, M, P> {
    written: usize,
    block: usize,
    stored: PhantomData<Describes<W, M, P>>,
}

/// The types a [`Contract`] describes, named without being held: a contract
/// is two numbers about them, so it owns none of them and is `Copy`, `Send`
/// and `Sync` whatever they are.
type Describes<W, M, P> = fn() -> (W, M, P);

impl<W, M, P> Clone for Contract<W, M, P> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<W, M, P> Copy for Contract<W, M, P> {}

impl<W: Representation, M: Representation, P> Contract<W, M, P> {
    /// The contract of a block storing `M`, whose acquisition writes `W`,
    /// with permits of `P`: read from their production representation.
    pub(crate) const fn of() -> Self {
        Self {
            written: crate::bounded::write_extent(
                size_of::<W::In<Core>>() + crate::bounded::permit_bytes::<P>(),
            ) as usize,
            block: size_of::<Held<M::In<Core>, P>>(),
            stored: PhantomData,
        }
    }
}

impl<W, M, P> Contract<W, M, P> {
    /// What the acquisition admits for its write: one [`WRITE`] of its
    /// bytes. Its release ([`release_cost`]) is admitted with it.
    pub(crate) const fn write(self) -> ResourceBound {
        Unit::new(Caller, WRITE.values(), self.written as u64).bound()
    }

    /// The block's bytes: the allocation requested and held.
    pub(crate) const fn block(self) -> usize {
        self.block
    }
}

// A stored type that holds no primitive of an atomics family is itself in
// every family: the empty header of a block written in later units, an
// uninitialized value of such a type, and a child custody record.
impl Representation for () {
    type In<S: Atomics> = ();
}

impl<T: Representation> Representation for MaybeUninit<T> {
    type In<S: Atomics> = MaybeUninit<T::In<S>>;
}

impl<S, P> Representation for Child<S, P> {
    type In<F: Atomics> = Self;
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

/// Acquire one stable block of `M` whose acquisition writes the permit and
/// the header `head` makes, a `W` written whole at the place `project` names
/// in the value. What is admitted is `contract`'s ([`Contract`], evaluated
/// in a constant by the caller, its type naming what is stored): its write,
/// then the block's release, each admitted once, before its allocation is
/// requested; `admitted` keeps what was admitted across a refused or failed
/// allocation. What is stored is `M`'s physical layout, which beneath a
/// model checker's atomics exceeds the contract's block. `open` is consulted
/// after the permit is granted and before memory is touched, because
/// allocator callbacks may close the owning scope. The header is made only
/// once the block exists.
///
/// # Safety
/// `project` must return the address of a `W` within the value it is given,
/// aligned for `W`, without reading or writing memory. The header must be
/// every part of the value that later code reads before initializing more
/// in admitted units of its own. Neither `head` nor `project` may unwind,
/// allocate, or read uninitialized memory.
pub(crate) unsafe fn acquire<M, W, A: Allocator>(
    contract: Contract<W, M, A::Permit>,
    admitted: &mut Admitted,
    open: impl Fn() -> bool,
    head: impl FnOnce() -> W,
    project: impl FnOnce(*mut M) -> *mut W,
    a: &mut A,
) -> BoundedResult<NonNull<Held<M, A::Permit>>, A> {
    const {
        assert!(
            size_of::<Held<M, A::Permit>>() > 0,
            "a stable block occupies memory"
        )
    };
    let layout = Layout::new::<Held<M, A::Permit>>();
    let bytes = u64::try_from(contract.block).map_err(|_| BoundedError::Overflow)?;
    if !open() {
        return Err(BoundedError::PlanMismatch);
    }
    if *admitted == Admitted::Nothing {
        WRITE.admit(a, contract.written as u64)?;
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
    // SAFETY: the layout is nonzero (asserted above); a null result is a
    // physical failure and drops the granted permit, releasing exactly what
    // was admitted for it. The failure reports the request admitted.
    let raw = NonNull::new(unsafe { alloc(layout) }.cast::<Held<M, A::Permit>>())
        .ok_or(BoundedError::Allocation { bytes })?;
    // SAFETY: the block is unique and aligned. The permit is written before
    // the header, so the block is always releasable once the header is; the
    // caller guarantees `project` names an aligned `W` within the value.
    unsafe {
        ptr::addr_of_mut!((*raw.as_ptr()).permit).write(permit);
        project(ptr::addr_of_mut!((*raw.as_ptr()).value)).write(head());
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
/// pointers into the block derive from its value's place ([`Self::place`]),
/// whose every access borrows this handle, and from the views its owner
/// publishes from that place for shared reads, whose use the custody protocol
/// ends before the block is accessed mutably again or uninstalled.
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
// SAFETY: shared access through `&Installed` yields only `&M` (`peek`); the
// permit is never reached. As for a `Box`, sharing the handle shares an `M`,
// so it is `Sync` exactly when `M` is.
unsafe impl<M: Sync, P> Sync for Installed<M, P> {}

impl<M, P> Installed<M, P> {
    /// The installed metadata, borrowed for as long as the handle is.
    pub(crate) fn get(&mut self) -> &mut M {
        let value = self.place().as_ptr(self);
        // SAFETY: the handle owns its live, initialized block exclusively;
        // the borrow of `self` bounds the returned reference.
        unsafe { &mut *value }
    }

    /// The installed value's place, the root of its provenance for the
    /// block's life ([`Place::root`]), reborrowing none of it: for a holder
    /// that reaches one part of the value exclusively while a reader may
    /// hold another part borrowed, as a stable option's state counts its
    /// payload's cleanup beside the payload a reader borrows. Every use ends
    /// before the block is uninstalled. Its custody, the token every access
    /// through it borrows ([`Place`]), is this handle.
    pub(crate) fn place(&mut self) -> Place<M> {
        // SAFETY: the block is live and owned by this handle; the projection
        // forms no reference, and every access to the value is through this
        // place or `get`, whose borrow `&mut self` bounds.
        unsafe {
            Place::root(NonNull::new_unchecked(
                ptr::addr_of_mut!((*self.block.as_ptr()).value).cast::<MaybeUninit<M>>(),
            ))
        }
    }

    /// The installed metadata, read through a shared borrow of the handle:
    /// how an observation reads progress kept in the block.
    pub(crate) fn peek(&self) -> &M {
        // SAFETY: the handle owns its live, initialized block; `get` needs
        // `&mut self`, so no mutable borrow coexists with this one.
        unsafe { &(*self.block.as_ptr()).value }
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

/// Acquire a block of `M` whose acquisition writes the header `head` makes
/// at the place `project` names, admitting `contract`, admissions kept in
/// `admitted` across a refused or failed allocation; the handle that owns
/// it.
///
/// # Safety
/// As [`acquire`].
pub(crate) unsafe fn installed<M, W, A: Allocator>(
    contract: Contract<W, M, A::Permit>,
    admitted: &mut Admitted,
    head: impl FnOnce() -> W,
    project: impl FnOnce(*mut M) -> *mut W,
    a: &mut A,
) -> BoundedResult<Installed<M, A::Permit>, A> {
    // SAFETY: forwarded from the caller.
    let block = unsafe { acquire::<M, W, A>(contract, admitted, || true, head, project, a)? };
    Ok(Installed {
        block,
        marker: PhantomData,
    })
}

/// Acquire a block of `M` into the empty `slot`, admitting `contract`, its
/// acquisition writing the header `head` makes at the place `project`
/// names, admissions kept in `admitted` across a refused or failed
/// allocation.
///
/// # Safety
/// As [`acquire`]. A `slot` already holding a block is a plan mismatch and
/// acquires nothing.
pub(crate) unsafe fn install<M, W, A: Allocator>(
    contract: Contract<W, M, A::Permit>,
    slot: &mut Option<Installed<M, A::Permit>>,
    admitted: &mut Admitted,
    head: impl FnOnce() -> W,
    project: impl FnOnce(*mut M) -> *mut W,
    a: &mut A,
) -> BoundedResult<(), A> {
    if slot.is_some() {
        return Err(BoundedError::PlanMismatch);
    }
    // SAFETY: forwarded from the caller.
    *slot = Some(unsafe { installed::<M, W, A>(contract, admitted, head, project, a)? });
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
    /// What pushing one record admits and holds ([`Contract`]): the record
    /// written whole with its permit, and its block. Every cost term of a
    /// child record reads it.
    pub(crate) const RECORD: Contract<Child<S, P>, Child<S, P>, P> = Contract::of();

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
        // SAFETY: the header is the whole record, every field written.
        let held = unsafe {
            acquire::<Child<S, P>, Child<S, P>, A>(
                Self::RECORD,
                &mut self.admitted,
                || true,
                || Child { state, previous },
                |child| child,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bounded::Reservation;

    // Stored types of the fixtures below, none holding an atomics family.
    impl Representation for u32 {
        type In<S: Atomics> = Self;
    }
    impl Representation for u64 {
        type In<S: Atomics> = Self;
    }
    impl Representation for [u64; 4] {
        type In<S: Atomics> = Self;
    }

    /// A block's contract, evaluated at run time as every caller evaluates
    /// it in a constant: its write is the header's bytes and the permit's,
    /// whatever the rest of the value, one admitted value; a whole value is
    /// its own header; its block is the whole held value with its permit,
    /// padding included, the bytes the allocator is asked for.
    #[test]
    fn a_blocks_contract_is_its_header_and_permit_written_and_its_whole_block() {
        let permit = size_of::<Reservation>();
        let written = |bytes: usize| ResourceBound {
            values: 1,
            bytes: bytes as u64,
            ..ResourceBound::default()
        };
        let header = Contract::<u32, [u64; 4], Reservation>::of();
        assert_eq!(header.write(), written(4 + permit));
        assert_eq!(header.block(), 32 + permit);
        let whole = Contract::<u64, u64, Reservation>::of();
        assert_eq!(whole.write(), written(8 + permit));
        assert_eq!(whole.block(), 8 + permit);
        // A value whose size is not a multiple of the permit's alignment:
        // the block holds the padding before the permit, which is written
        // by no unit.
        let padded = Contract::<u32, u32, Reservation>::of();
        assert_eq!(padded.write(), written(4 + permit));
        assert_eq!(padded.block(), 8 + permit);
        assert_eq!(
            release_cost::<Reservation>(),
            ResourceBound {
                values: 1,
                bytes: permit as u64,
                ..ResourceBound::default()
            }
        );
    }
}
