//! Retained arena growth. An arena is settled, every element in its one
//! allocation, or relocating its elements into a grown allocation, each
//! admitted turn moving at most one. The grown allocation is staged in a
//! stable block beside the settled arena until a single write publishes the
//! relocation, so every state an admission can suspend in is a valid value
//! owning each allocation exactly once, and every transition writes the
//! whole state in one unit of at most a quantum.
use super::super::boundary::{Valuation, boundary, position};
use super::super::*;
use super::construction::reclamation::Slot;
use super::construction::stable::{self, Admitted, Installed, PENDING_UNITS, Pending, Ticket};
use super::initialization::init_field;
use crate::sync::{Atomics, Representation};
use core::mem::{self, MaybeUninit, size_of};

/// The old allocation's elements still to relocate, and its permit. Field
/// order frees the old allocation before releasing its permit.
struct Moving<T, P> {
    remaining: <Vec<T> as IntoIterator>::IntoIter,
    _permit: Option<P>,
}

/// A stable block holding an arena: where a grown allocation is built and
/// kept until it is published.
type Block<T, P> = Installed<Owned<T, P>, P>;

// An arena holds no primitive of an atomics family: its staging block is
// the same in every build.
impl<T, P> Representation for Owned<T, P> {
    type In<S: Atomics> = Self;
}

/// A growth of a settled arena, staged beside it, each stage holding exactly
/// what it has acquired: nothing, the staging block's acquisition under way
/// (its admissions held in the arena's pending custody, [`Storage`]), the
/// block with the grown allocation's acquisition under way, the block
/// holding the grown allocation, or the block vacated once the arena holds
/// that allocation, its release next. The two acquisitions are sequential:
/// the grown allocation's begins only once the staging block's ended, so
/// one pending custody serves both.
enum Growth<T, P> {
    Idle,
    Staging,
    Staged(Block<T, P>),
    Ready(Block<T, P>),
    Retired(Installed<MaybeUninit<Owned<T, P>>, P>),
}

/// Where an arena is.
enum State<T, P> {
    /// Every element in one allocation, readable; a growth may be staged.
    Settled {
        arena: Owned<T, P>,
        growth: Growth<T, P>,
    },
    /// Elements moving from the old allocation into the grown one, which
    /// its block holds; both are owned here and only here.
    Relocating {
        from: Moving<T, P>,
        into: Block<T, P>,
    },
    /// Every element in the grown allocation; the old one released.
    Relocated { into: Block<T, P> },
}

/// A retained arena of `T` with permits of `P`, its held credit settling
/// into origins of `O`. Its elements are readable only while it is settled
/// ([`Self::settle_step`]); a free slot is granted only by
/// [`Self::reserve_step`], so a push into reserved capacity cannot fail. Its
/// state is at most a quantum, a bound on `P` checked at compile time where
/// the arena is used, and every transition rewrites the state alone.
///
/// The credit a growth holds across a refused request (the staging block's
/// write and release, then the grown allocation's) is in `pending`, the
/// arena's one retained acquisition custody, which survives every refusal
/// and solely owns those obligations, each settling into the family that
/// admitted it; `holder` is the ticket of the acquisition under way. The
/// pending's owner is the arena's: the arena is made with no budget, so its
/// pending starts with its owner uninitialized ([`Pending::deferred`]), and
/// its first acquisition entry, under whatever budget performs it, ordinary
/// or recording, makes the owner once ([`Pending::bind`]). An initialized
/// owner is never replaced, even an ordinary one under a later recording
/// budget: that pairing is refused at the entry
/// ([`Budget::validate_owner`]), never adopted. Whether the owner is
/// initialized is the pending's own state, never read from its identity.
pub struct Storage<T, P, O: Origin> {
    state: State<T, P>,
    pending: Pending<O>,
    holder: Option<Ticket>,
}

/// Where an arena is in its growth, each stage a physical state of its
/// allocations: what the arena holds beyond its own allocation. An
/// acquisition under way that holds admissions but no block yet is no
/// physical state, so it is [`Self::Settled`]; what any acquisition has
/// admitted is acquisition custody, reported by the arena's custody
/// traversal ([`Storage::observe_custody`]), never by its stage.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum StorageStage {
    /// Settled on its allocation; no growth block held.
    Settled,
    /// Settled; the staging block held, the grown allocation not yet in it.
    Staged,
    /// Settled; the staging block holds the grown allocation.
    Ready,
    /// Elements moving from the old allocation into the grown one; both
    /// held, with the block.
    Relocating,
    /// Every element in the grown allocation, still in its block; the old
    /// allocation released.
    Relocated,
    /// Settled on the grown allocation; the vacated block held, its release
    /// next.
    Retired,
}

/// Constant-time storage observations: the arena's stage and the counts
/// that fix its remaining moves and drains: the one execution observation
/// of an arena ([`Storage::position`]), every field physical. Acquisition
/// custody is reported apart ([`Storage::observe_custody`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct StoragePosition {
    pub stage: StorageStage,
    pub initialized: usize,
    pub reserved_capacity: usize,
    pub physical_capacity: usize,
    pub relocating_remaining: usize,
    pub has_current_permit: bool,
    /// Grown allocation retained beside a settled arena. The staging block
    /// itself is identified by stage, including before it owns this allocation.
    pub staged_reserved_capacity: usize,
    pub staged_physical_capacity: usize,
    pub has_staged_permit: bool,
    /// The old allocation's permit remains live until its last element has
    /// moved or been drained, independently of the grown allocation's permit.
    pub has_relocating_permit: bool,
    /// The arena holds no element, allocation, reservation or growth under
    /// way ([`Storage::is_released`]): what a holder that steps an arena's
    /// cleanup only while it is unreleased reads. A settled empty arena
    /// whose staging block's acquisition is under way is `Settled` but not
    /// released: its cleanup's entry settles that acquisition's credit.
    pub released: bool,
}

impl Default for StoragePosition {
    fn default() -> Self {
        Storage::<u8, (), ()>::new().position()
    }
}

/// The free capacity of a settled arena, granted by
/// [`Storage::reserve_step`] for the rest of that step. The arena's tracked
/// capacity exceeds its length and its allocation was reserved for at least
/// that capacity, so filling it never reallocates and cannot fail.
pub struct Spare<'a, T, P> {
    owned: &'a mut Owned<T, P>,
}

impl<T, P> Spare<'_, T, P> {
    /// The elements the arena holds before the spare capacity is filled.
    pub fn len(&self) -> usize {
        self.owned.items.len()
    }

    /// Whether the arena holds no element yet.
    pub fn is_empty(&self) -> bool {
        self.owned.items.is_empty()
    }

    /// The free slots, at least one.
    pub fn room(&self) -> usize {
        self.owned.capacity - self.owned.items.len()
    }

    /// The elements the arena holds, readable through the capability that
    /// proves it settled.
    pub fn as_slice(&self) -> &[T] {
        &self.owned.items
    }

    /// The elements the arena holds, writable in place.
    pub fn as_mut_slice(&mut self) -> &mut [T] {
        &mut self.owned.items
    }

    /// Remove the newest element, freeing a slot: within the step's unit
    /// that consumes it.
    pub fn pop(&mut self) -> Option<T> {
        self.owned.items.pop()
    }

    /// Fill one free slot.
    pub fn push(self, value: T) {
        self.owned.items.push(value);
    }

    /// Append two elements without allocation or admission. Insufficient
    /// reserved capacity returns both values and leaves the arena unchanged.
    pub(crate) fn push_pair(self, values: [T; 2]) -> Result<(), [T; 2]> {
        if self.room() < 2 {
            return Err(values);
        }
        let [first, second] = values;
        self.owned.items.push(first);
        self.owned.items.push(second);
        Ok(())
    }
}

impl<T: Copy, P> Spare<'_, T, P> {
    /// Fill as many free slots as `values` and the room allow, in order;
    /// the number filled. Whether `values` fits the room is a boundary
    /// predicate recorded to `budget`.
    pub fn extend<B: Budget + ?Sized>(self, values: &[T], budget: &mut B) -> usize {
        let count = Bound::new(Predicate::ArenaLength, self.room()).clamp(budget, values.len());
        self.owned.items.extend_from_slice(&values[..count]);
        count
    }
}

/// One write of an arena's whole state, or of an arena into its block: one
/// value and its bytes, at most a quantum whatever the element and permit
/// types.
const WRITE: Capped<Caller> = Capped::new(Caller, 1, TURN.bytes);

/// The writes of one growth: the staging block's, the grown arena's into
/// it, the relocation's publication and its settlement.
const GROWTH_WRITES: u64 = 4;

impl<T, P, O: Origin> Storage<T, P, O> {
    /// An empty settled arena, no growth staged.
    const EMPTY: State<T, P> = State::Settled {
        arena: Owned::new(),
        growth: Growth::Idle,
    };

    /// The bytes one transition writes: the state, at most a quantum. The
    /// pending custody and the ticket beside it are written by their own
    /// operations, within the admissions that make them.
    const STATE_BYTES: u64 = write_extent(size_of::<State<T, P>>());

    /// The bytes writing a grown arena into its block writes: the grant's
    /// work a growth admits before requesting its allocation
    /// ([`Obligation::Grant`]), one [`WRITE`] of them.
    const ARENA_BYTES: u64 = write_extent(size_of::<Owned<T, P>>());

    /// What a growth's staging block admits and holds ([`stable::Contract`]):
    /// the empty arena written whole with the permit, and the block, which
    /// is at most a quantum, the bytes [`crate::bounded::storage_growth`]
    /// counts for every staging block. Checked where the arena grows, so an
    /// arena whose block would exceed it fails to compile there.
    pub(crate) const STAGING: stable::Contract<Owned<T, P>, Owned<T, P>, P> = {
        let staging = stable::Contract::of();
        assert!(
            staging.block() <= TURN.bytes as usize,
            "a staging block exceeds the quantum storage_growth counts for it"
        );
        staging
    };

    /// One element drained, or relocated into a grown allocation: one
    /// admitted unit of its bytes.
    const ELEMENT: Unit<Caller> = Unit::written::<T>(Caller);

    /// A caller's phase transition when nothing is held, or a truncation of
    /// plain data: one unit of no bytes.
    const STEP: Unit<Caller> = Unit::new(Caller, 1, 0);

    /// One part of a transfer into an owner's arena: the field moved, its
    /// bytes counted once.
    const TRANSFER: [Unit<Caller>; 3] = [
        Unit::written::<Vec<T>>(Caller),
        Unit::written::<usize>(Caller),
        Unit::written::<Option<P>>(Caller),
    ];

    /// The parts of a transfer into an owner's arena ([`Self::TRANSFER`]),
    /// the one count [`Self::transfer_step`] and an owner's arena prefix
    /// read.
    pub(crate) const TRANSFER_PARTS: usize = Self::TRANSFER.len();

    /// The units initializing an arena in place: its state, its ticket, and
    /// its pending custody's ([`PENDING_UNITS`], the owner's state among
    /// them), one field each, each at most a quantum.
    pub(crate) const INIT_STEPS: usize = 2 + PENDING_UNITS;

    /// The work of a whole transfer into an owner's arena
    /// ([`Self::transfer_step`]): its three parts, each one unit.
    pub(crate) fn transfer_work<R>() -> Result<WriteWork, BoundedError<R>> {
        WriteWork::checked_sequence(&[
            Self::TRANSFER[0].times(1)?,
            Self::TRANSFER[1].times(1)?,
            Self::TRANSFER[2].times(1)?,
        ])
        .ok_or(BoundedError::Overflow)
    }

    /// The work of moving `count` elements: drained, or relocated into a
    /// grown allocation.
    pub(crate) fn element_work<R>(count: u64) -> Result<WriteWork, BoundedError<R>> {
        Self::ELEMENT.times(count)
    }

    /// The work of `count` transitions or truncations, one unit of no bytes
    /// each.
    pub(crate) fn step_work<R>(count: u64) -> Result<WriteWork, BoundedError<R>> {
        Self::STEP.times(count)
    }

    /// The most work cleaning up such storage once drained takes, whatever
    /// its element and permit types: the reset of an interrupted
    /// relocation, at most a quantum, then the caller's transition, one unit
    /// of no bytes; the transition alone when it never allocated. Every
    /// release was paid for by the growth that acquired it.
    pub(crate) fn cleanup_work<R>(allocated: bool) -> Result<WriteWork, BoundedError<R>> {
        if allocated {
            WRITE
                .times(1)?
                .checked_then(Self::STEP.times(1)?)
                .ok_or(BoundedError::Overflow)
        } else {
            Self::STEP.times(1)
        }
    }

    /// The writes `growths` growths make ([`GROWTH_WRITES`]), each at most a
    /// quantum.
    pub(crate) fn growth_work<R>(growths: u64) -> Result<WriteWork, BoundedError<R>> {
        WRITE.times(mul(growths, GROWTH_WRITES)?)
    }

    /// An empty settled arena, no growth staged, its owner uninitialized
    /// until its first acquisition entry ([`Self`]).
    pub const fn new() -> Self {
        Self {
            state: Self::EMPTY,
            pending: Pending::deferred(),
            holder: None,
        }
    }

    /// Initialize the empty arena directly in its final destination, `slot`,
    /// one field per admitted unit ([`Self::INIT_STEPS`]): its state, its
    /// ticket, then its pending custody's units, the owner unobserved. No
    /// prefix owns a resource: the unobserved owner holds no session.
    /// Refused once initialized: a second write would discard whatever the
    /// arena has acquired since. True once every unit is written.
    pub(crate) fn initialize_step<A: Allocator<Permit = P, Origin = O>>(
        mut slot: Slot<'_, Self, usize>,
        a: &mut A,
    ) -> BoundedResult<bool, A> {
        use super::initialization::field;
        let (place, units) = slot.parts();
        if Bound::new(Predicate::Prefix, Self::INIT_STEPS).reached(a, *units) {
            return Err(BoundedError::PlanMismatch);
        }
        let raw = place.as_ptr(units);
        // SAFETY: the slot's place is valid, aligned and writable for the
        // arena, its units below `*units` written; each projection reaches
        // one field by field syntax, forming no reference to the whole.
        unsafe {
            match *units {
                0 => field(core::ptr::addr_of_mut!((*raw).state), || Self::EMPTY, a)?,
                1 => field(core::ptr::addr_of_mut!((*raw).holder), || None, a)?,
                // The owner uninitialized: the arena's first acquisition
                // entry makes it.
                unit => stable::initialize_pending(
                    core::ptr::addr_of_mut!((*raw).pending),
                    unit - 2,
                    None,
                    a,
                )?,
            }
        }
        *units += 1;
        Ok(*units == Self::INIT_STEPS)
    }

    /// Drop in place the first `written` units [`Self::initialize_step`]
    /// wrote of the arena at `raw`, newest first: the cleanup of a parent
    /// whose block runs no destructor and whose arena was initialized only
    /// in part. A prefix holds no allocation and no admitted credit (the
    /// state is the empty arena, the pending idle, its owner unobserved), so
    /// this frees nothing and records nothing: allocation-free,
    /// non-unwinding, admitting nothing. A fully initialized arena is
    /// dropped as a whole instead (`ptr::drop_in_place`), its own `Drop`
    /// releasing whatever it holds.
    ///
    /// # Safety
    /// `raw` is valid and aligned for the arena, exactly its first
    /// `written` units are initialized, and nothing reads them afterwards.
    ///
    /// Its holders are the bindings whose blocks hold arenas initialized in
    /// part, the B-tree's (`in_place::btree`), and this module's prefix test,
    /// both compiled only with the forked standard library's collections, so
    /// it is too.
    #[cfg(feature = "custom-std-collections")]
    pub(crate) unsafe fn drop_prefix(raw: *mut Self, written: usize) {
        // SAFETY: forwarded from the caller; each projection reaches one
        // initialized field by field syntax, forming no reference.
        unsafe {
            if written > 2 {
                stable::drop_pending(core::ptr::addr_of_mut!((*raw).pending), written - 2);
            }
            // The holder, written by the second unit, is an
            // `Option<Ticket>`: `Copy`, owning nothing, so it needs no drop.
            if written > 0 {
                core::ptr::drop_in_place(core::ptr::addr_of_mut!((*raw).state));
            }
        }
    }

    pub fn position(&self) -> StoragePosition {
        let released = self.is_released();
        match &self.state {
            State::Settled { arena, growth } => StoragePosition {
                stage: match growth {
                    Growth::Idle | Growth::Staging => StorageStage::Settled,
                    Growth::Staged(_) => StorageStage::Staged,
                    Growth::Ready(_) => StorageStage::Ready,
                    Growth::Retired(_) => StorageStage::Retired,
                },
                initialized: arena.items.len(),
                reserved_capacity: arena.capacity,
                physical_capacity: arena.items.capacity(),
                relocating_remaining: 0,
                has_current_permit: arena.permit.is_some(),
                staged_reserved_capacity: match growth {
                    Growth::Staged(block) | Growth::Ready(block) => block.peek().capacity,
                    _ => 0,
                },
                staged_physical_capacity: match growth {
                    Growth::Staged(block) | Growth::Ready(block) => block.peek().items.capacity(),
                    _ => 0,
                },
                has_staged_permit: match growth {
                    Growth::Staged(block) | Growth::Ready(block) => block.peek().permit.is_some(),
                    _ => false,
                },
                has_relocating_permit: false,
                released,
            },
            State::Relocating { from, into } => {
                let into = into.peek();
                StoragePosition {
                    stage: StorageStage::Relocating,
                    initialized: into.items.len(),
                    reserved_capacity: into.capacity,
                    physical_capacity: into.items.capacity(),
                    relocating_remaining: from.remaining.len(),
                    has_current_permit: into.permit.is_some(),
                    staged_reserved_capacity: 0,
                    staged_physical_capacity: 0,
                    has_staged_permit: false,
                    has_relocating_permit: from._permit.is_some(),
                    released,
                }
            }
            State::Relocated { into } => {
                let into = into.peek();
                StoragePosition {
                    stage: StorageStage::Relocated,
                    initialized: into.items.len(),
                    reserved_capacity: into.capacity,
                    physical_capacity: into.items.capacity(),
                    relocating_remaining: 0,
                    has_current_permit: into.permit.is_some(),
                    staged_reserved_capacity: 0,
                    staged_physical_capacity: 0,
                    has_staged_permit: false,
                    has_relocating_permit: false,
                    released,
                }
            }
        }
    }

    /// The elements held, relocated or not.
    pub fn len(&self) -> usize {
        match &self.state {
            State::Settled { arena, .. } => arena.items.len(),
            State::Relocating { from, into } => into.peek().items.len() + from.remaining.len(),
            State::Relocated { into } => into.peek().items.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The newest element, in whichever allocation holds it: a total
    /// observation, valid in every state. Relocation moves the oldest first,
    /// so while it runs the newest is the old allocation's last. A relocating
    /// arena always holds an element still to move: relocation begins only
    /// from a nonempty arena, and leaves `Relocating` in the step that moves
    /// its last element, as cleanup does in the step that drains it. A
    /// contract its holders rely on (the B-tree cleanup's newest entry, found
    /// by identity), pinned in every state by
    /// `last_is_the_newest_and_every_element_is_visited_once`.
    pub fn last(&self) -> Option<&T> {
        match &self.state {
            State::Settled { arena, .. } => arena.items.last(),
            State::Relocating { from, .. } => from.remaining.as_slice().last(),
            State::Relocated { into } => into.peek().items.last(),
        }
    }

    /// The newest element, writable, in whichever allocation holds it: how
    /// the holder of an arena of construction records observes the active
    /// record's custody in every state, relocation included. Moves nothing
    /// and admits nothing. While relocating, the old allocation's last, as
    /// [`Self::last`]: the same element, in every state.
    #[cfg(feature = "custom-std-collections")]
    pub(crate) fn last_mut(&mut self) -> Option<&mut T> {
        match &mut self.state {
            State::Settled { arena, .. } => arena.items.last_mut(),
            State::Relocating { from, .. } => from.remaining.as_mut_slice().last_mut(),
            State::Relocated { into } => into.get().items.last_mut(),
        }
    }

    /// Every element held, in whichever allocation holds it, writable: how
    /// the holder of an arena of construction records sums what their
    /// cleanup still owes, relocation included. Moves nothing and admits
    /// nothing. Every element is visited exactly once, in no order a holder
    /// may rely on: while relocating, the old allocation's elements still to
    /// move, then the grown allocation's, which is not index order.
    pub(crate) fn for_each_mut(&mut self, mut visit: impl FnMut(&mut T)) {
        match &mut self.state {
            State::Settled { arena, .. } => arena.items.iter_mut().for_each(visit),
            State::Relocating { from, into } => {
                from.remaining
                    .as_mut_slice()
                    .iter_mut()
                    .for_each(&mut visit);
                into.get().items.iter_mut().for_each(visit);
            }
            State::Relocated { into } => into.get().items.iter_mut().for_each(visit),
        }
    }

    /// Every element held, shared, in whichever allocation holds it, each
    /// exactly once, in the order [`Self::for_each_mut`] visits: how a
    /// holder observes the credit its elements' custody holds, relocation
    /// included. Moves nothing and admits nothing.
    pub(crate) fn for_each(&self, mut visit: impl FnMut(&T)) {
        match &self.state {
            State::Settled { arena, .. } => arena.items.iter().for_each(visit),
            State::Relocating { from, into } => {
                from.remaining.as_slice().iter().for_each(&mut visit);
                into.peek().items.iter().for_each(visit);
            }
            State::Relocated { into } => into.peek().items.iter().for_each(visit),
        }
    }

    /// What the acquisition under way has admitted toward its grant: the
    /// staging block's while staging, the grown allocation's once staged;
    /// nothing when none is under way. Read from the pending custody's
    /// credit slots, the one record of it, with no ticket check that could
    /// fail: an observation never masks a mismatch as `Nothing`.
    fn admitted(&self) -> Admitted {
        self.pending.held_phase()
    }

    /// This arena's custody, one group under its pending custody's stored
    /// owner (`None` while deferred, before the arena's first acquisition),
    /// the owner every one of its acquisitions names ([`CustodySink`]): the
    /// pending custody's own group, the one place a growth's credit is held
    /// ([`Pending`], never inferred from the growth's stage), nested inside;
    /// then each permit the arena physically owns, once each: the settled
    /// allocation's, a staged, ready or relocating growth's block's and its
    /// grown allocation's, a relocation's old allocation's, and a vacated
    /// block's. The arena's elements are its holder's to report, not its
    /// own. Read-only and allocation-free; it admits, mints, publishes and
    /// settles nothing. Callable from a holder with `&Storage` alone, inside
    /// the holder's own open group.
    pub fn observe_custody(&self, sink: &mut dyn CustodySink<P>) -> PermitsObserved {
        fn arena<T, P>(owned: &Owned<T, P>, sink: &mut dyn CustodySink<P>) {
            if let Some(permit) = &owned.permit {
                sink.permit(permit, None);
            }
        }
        sink.begin(self.owner_id());
        let pending = self.pending.observe_custody(sink);
        match &self.state {
            State::Settled {
                arena: owned,
                growth,
            } => {
                arena(owned, sink);
                match growth {
                    Growth::Idle | Growth::Staging => {}
                    Growth::Staged(block) | Growth::Ready(block) => {
                        sink.permit(block.permit(), None);
                        arena(block.peek(), sink);
                    }
                    Growth::Retired(vacated) => sink.permit(vacated.permit(), None),
                }
            }
            State::Relocating { from, into } => {
                if let Some(permit) = &from._permit {
                    sink.permit(permit, None);
                }
                sink.permit(into.permit(), None);
                arena(into.peek(), sink);
            }
            State::Relocated { into } => {
                sink.permit(into.permit(), None);
                arena(into.peek(), sink);
            }
        }
        sink.end();
        pending
    }

    /// The identity of this arena's owner, read from the owner its pending
    /// custody stores, the one its acquisitions name and its custody group
    /// is under; `None` while it is deferred, before the arena's first
    /// acquisition. What a published value carrying the arena's allocation
    /// records as the owner it was granted under.
    pub fn owner_id(&self) -> Option<Identity> {
        self.pending.owner_id()
    }

    /// The most units [`Self::reclaim_step`] or [`Self::reclaim_copy_step`]
    /// takes from here to report the storage released: a staged growth's
    /// release, one drain per element (or one truncation of plain data), the
    /// allocation's release or an interrupted relocation's reset, then the
    /// completing transition; `None` when that count does not fit in `u64`,
    /// never a saturated count.
    pub(crate) fn reclaim_remaining(&self) -> Option<u64> {
        u64::try_from(self.len()).ok()?.checked_add(3)
    }

    /// [`Self::reclaim_remaining`] for a holder that steps this storage's
    /// cleanup only while it is not [`Self::is_released`]: none once it is.
    pub(crate) fn unreleased_remaining(&self) -> Option<u64> {
        if self.is_released() {
            Some(0)
        } else {
            self.reclaim_remaining()
        }
    }

    /// The most units [`Self::settle_step`] takes before it grants the
    /// settled arena: one per element still relocating, then the settlement;
    /// `None` when that count does not fit in `u64`.
    #[cfg(feature = "custom-std-collections")]
    pub(crate) fn settle_remaining(&self) -> Option<u64> {
        match &self.state {
            State::Settled { .. } => Some(0),
            State::Relocating { from, .. } => {
                u64::try_from(from.remaining.len()).ok()?.checked_add(1)
            }
            State::Relocated { .. } => Some(1),
        }
    }

    /// The settled arena, shared, or `None` while its elements are in a
    /// grown allocation: an observation that does no work.
    pub fn settled(&self) -> Option<&Owned<T, P>> {
        match &self.state {
            State::Settled { arena, .. } => Some(arena),
            State::Relocating { .. } | State::Relocated { .. } => None,
        }
    }

    /// The elements in their final allocation.
    pub fn relocated(&self) -> usize {
        match &self.state {
            State::Settled { arena, .. } => arena.items.len(),
            State::Relocating { into, .. } | State::Relocated { into } => into.peek().items.len(),
        }
    }

    /// Whether the storage holds no element, allocation, reservation or
    /// staged growth.
    pub(crate) fn is_released(&self) -> bool {
        matches!(
            &self.state,
            State::Settled { arena, growth: Growth::Idle } if arena.items.is_empty() && !arena.holds()
        )
    }

    /// Free capacity of at least one slot, growing the allocation to at
    /// most `maximum` elements: granted when the settled arena has room and
    /// no growth is staged, otherwise one unit of growth or relocation and
    /// `None`. Callers choose a nondecreasing cap.
    pub fn reserve_step<A: Allocator<Permit = P, Origin = O>>(
        &mut self,
        maximum: usize,
        a: &mut A,
    ) -> BoundedResult<Option<Spare<'_, T, P>>, A> {
        // Whether a slot is free is decided through a shared borrow, so the
        // mutable borrow the grant returns is taken in a statement of its
        // own: a borrow returned from one match arm while another arm uses
        // the storage is rejected by the stable borrow checker.
        let free = match &self.state {
            State::Settled {
                arena,
                growth: Growth::Idle,
            } => Bound::new(Predicate::ArenaLength, arena.capacity).below(a, arena.items.len()),
            _ => false,
        };
        if !free {
            self.grow_step(maximum, a)?;
            return Ok(None);
        }
        match &mut self.state {
            State::Settled { arena, .. } => Ok(Some(Spare { owned: arena })),
            // A free slot was just found in a settled arena.
            State::Relocating { .. } | State::Relocated { .. } => Err(BoundedError::PlanMismatch),
        }
    }

    /// The settled arena, readable and writable in place; or, while its
    /// elements are relocating, one admitted unit of the relocation
    /// ([`Self::relocate_step`]) and `None`. A growth staged beside a
    /// settled arena leaves it readable, and is never resumed here: only
    /// [`Self::reserve_step`] grows. So settling acquires nothing, and is
    /// bound on [`Releasing`]: cleanup steps it through its capability
    /// (`reclamation::Cleanup`), through which no new allocation can be
    /// requested.
    pub fn settle_step<A: Releasing<Permit = P, Origin = O>>(
        &mut self,
        a: &mut A,
    ) -> BoundedResult<Option<&mut Owned<T, P>>, A> {
        match self.state {
            State::Settled { ref mut arena, .. } => Ok(Some(arena)),
            _ => {
                self.relocate_step(a)?;
                Ok(None)
            }
        }
    }

    /// One admitted unit of a relocation under way: one element moved into
    /// the grown allocation, or, every element moved, the grown arena
    /// settled and its vacated block kept for release. The one
    /// implementation of relocation, reached by settling
    /// ([`Self::settle_step`]) and by growth ([`Self::grow_step`]); it
    /// acquires nothing. Refused on a settled arena: nothing relocates.
    fn relocate_step<A: Releasing<Permit = P, Origin = O>>(
        &mut self,
        a: &mut A,
    ) -> BoundedResult<(), A> {
        let (next, result) = match mem::replace(&mut self.state, Self::EMPTY) {
            settled @ State::Settled { .. } => (settled, Err(BoundedError::PlanMismatch)),
            State::Relocating { mut from, mut into } => match Self::ELEMENT.admit(a) {
                Err(error) => (State::Relocating { from, into }, Err(error)),
                Ok(()) => {
                    let moved = into.peek().items.len();
                    boundary!(a, Predicate::Growth => Valuation::Relocate);
                    boundary!(a, Predicate::Relocation => position(moved, moved + from.remaining.len()));
                    // The grown allocation reserved more than every old
                    // element, so the push never reallocates.
                    if let Some(value) = from.remaining.next() {
                        into.get().items.push(value);
                    }
                    if from.remaining.as_slice().is_empty() {
                        // The old allocation's release was paid for by its
                        // growth.
                        drop(from);
                        (State::Relocated { into }, Ok(()))
                    } else {
                        (State::Relocating { from, into }, Ok(()))
                    }
                }
            },
            State::Relocated { into } => match WRITE.admit(a, Self::STATE_BYTES) {
                Err(error) => (State::Relocated { into }, Err(error)),
                Ok(()) => {
                    boundary!(a, Predicate::Growth => Valuation::Settle);
                    let (arena, vacated) = into.vacate();
                    (
                        State::Settled {
                            arena,
                            growth: Growth::Retired(vacated),
                        },
                        Ok(()),
                    )
                }
            },
        };
        self.state = next;
        result
    }

    /// The settled arena, taken, leaving an empty one; or, while its
    /// elements are relocating, one admitted unit of the relocation and
    /// `None`. A staged growth stays with the storage for its cleanup.
    /// Acquires nothing ([`Self::settle_step`]).
    pub(crate) fn take_step<A: Releasing<Permit = P, Origin = O>>(
        &mut self,
        a: &mut A,
    ) -> BoundedResult<Option<Owned<T, P>>, A> {
        Ok(self.settle_step(a)?.map(mem::take))
    }

    /// One admitted unit of growth: the staging block acquired, the grown
    /// allocation requested into it, the relocation published, one element
    /// relocated, the relocated arena settled, or the vacated block
    /// released. Every path writes the state back, refusals included.
    fn grow_step<A: Allocator<Permit = P, Origin = O>>(
        &mut self,
        maximum: usize,
        a: &mut A,
    ) -> BoundedResult<(), A> {
        // A relocation under way is the one relocation step's, which
        // acquires nothing; only a settled arena's growth acquires.
        if !matches!(self.state, State::Settled { .. }) {
            return self.relocate_step(a);
        }
        let (next, result) = match mem::replace(&mut self.state, Self::EMPTY) {
            State::Settled {
                arena,
                growth: Growth::Idle | Growth::Staging,
            } => {
                // SAFETY: the header is the empty arena, written whole.
                match unsafe {
                    stable::installed::<Owned<T, P>, Owned<T, P>, A>(
                        Self::STAGING,
                        &mut self.pending,
                        &mut self.holder,
                        Owned::new,
                        |owned| owned,
                        a,
                    )
                } {
                    Ok(block) => {
                        boundary!(a, Predicate::Growth => Valuation::Stage);
                        (
                            State::Settled {
                                arena,
                                growth: Growth::Staged(block),
                            },
                            Ok(()),
                        )
                    }
                    // A refusal keeps the acquisition, its admissions held
                    // in the pending custody, for the retry; a failure ended
                    // it, the holder's ticket cleared. A refusal of its first
                    // admission held nothing: the growth stays idle, as a
                    // refused unit changes nothing the arena reports, its
                    // binding kept for the retry (`Pending::bind`).
                    Err(error) => (
                        State::Settled {
                            arena,
                            growth: if self.holder.is_some() && self.admitted() != Admitted::Nothing
                            {
                                Growth::Staging
                            } else {
                                Growth::Idle
                            },
                        },
                        Err(error),
                    ),
                }
            }
            State::Settled {
                arena,
                growth: Growth::Staged(mut block),
            } => match Self::allocate_grown(
                &arena,
                block.get(),
                &mut self.pending,
                &mut self.holder,
                maximum,
                a,
            ) {
                Ok(()) => {
                    boundary!(a, Predicate::Growth => Valuation::Allocate);
                    (
                        State::Settled {
                            arena,
                            growth: Growth::Ready(block),
                        },
                        Ok(()),
                    )
                }
                Err(error) => (
                    State::Settled {
                        arena,
                        growth: Growth::Staged(block),
                    },
                    Err(error),
                ),
            },
            State::Settled {
                arena,
                growth: Growth::Ready(block),
            } => match WRITE.admit(a, Self::STATE_BYTES) {
                Err(error) => (
                    State::Settled {
                        arena,
                        growth: Growth::Ready(block),
                    },
                    Err(error),
                ),
                // An empty arena has nothing to relocate: the grown one is
                // settled at once, the old allocation released.
                Ok(()) if arena.items.is_empty() => {
                    boundary!(a, Predicate::Growth => Valuation::Publish);
                    boundary!(a, Predicate::Relocation => Valuation::Empty);
                    let (grown, vacated) = block.vacate();
                    drop(arena);
                    (
                        State::Settled {
                            arena: grown,
                            growth: Growth::Retired(vacated),
                        },
                        Ok(()),
                    )
                }
                Ok(()) => {
                    boundary!(a, Predicate::Growth => Valuation::Publish);
                    let Owned { items, permit, .. } = arena;
                    (
                        State::Relocating {
                            from: Moving {
                                remaining: items.into_iter(),
                                _permit: permit,
                            },
                            into: block,
                        },
                        Ok(()),
                    )
                }
            },
            State::Settled {
                arena,
                growth: Growth::Retired(vacated),
            } => {
                boundary!(a, Predicate::Growth => Valuation::Retire);
                // The block's release was paid for by its acquisition.
                vacated.free();
                (
                    State::Settled {
                        arena,
                        growth: Growth::Idle,
                    },
                    Ok(()),
                )
            }
            // Taken by the one relocation step above, before this match.
            relocating @ (State::Relocating { .. } | State::Relocated { .. }) => {
                (relocating, Err(BoundedError::PlanMismatch))
            }
        };
        self.state = next;
        result
    }

    /// Request the grown allocation into the staged arena `grown`, the
    /// arena's second acquisition, through its pending custody: its write and
    /// its release admitted held there first (each kept, with the family that
    /// admitted it, across a refused request), then the grant
    /// ([`stable::grant`]): the release spent at the permit, the physical
    /// reservation made, its effect reported, the write spent or, when the
    /// reservation failed, forfeited. Capacity doubles from four, capped at
    /// `maximum`.
    fn allocate_grown<A: Allocator<Permit = P, Origin = O>>(
        arena: &Owned<T, P>,
        grown: &mut Owned<T, P>,
        pending: &mut Pending<O>,
        holder: &mut Option<Ticket>,
        maximum: usize,
        a: &mut A,
    ) -> BoundedResult<(), A> {
        let capacity = crate::bounded::grown(arena.capacity)?;
        let capacity = Bound::new(Predicate::ArenaLength, maximum).clamp(a, capacity);
        if Bound::new(Predicate::ArenaLength, arena.items.len()).admits(a, capacity) {
            return Err(BoundedError::PlanMismatch);
        }
        let bytes = mul(widen(capacity)?, widen(size_of::<T>())?)?;
        // What an earlier, refused, entry of this acquisition already
        // admitted is held in `pending` and never admitted again.
        let admitted = match *holder {
            Some(ticket) => pending.admitted(ticket)?,
            None => Admitted::Nothing,
        };
        if admitted == Admitted::Nothing {
            stable::admit_obligation(
                pending,
                holder,
                &[Admitted::Nothing],
                |a, owner, acquisition| {
                    WRITE.admit_held(a, Self::ARENA_BYTES, Obligation::Grant, owner, acquisition)
                },
                a,
            )?;
        }
        if admitted != Admitted::Release {
            stable::admit_obligation(
                pending,
                holder,
                &[Admitted::Write],
                |a, owner, acquisition| {
                    RELEASED.admit_held(
                        a,
                        Owned::<T, P>::RELEASE_BYTES,
                        Obligation::Release,
                        owner,
                        acquisition,
                    )
                },
                a,
            )?;
        }
        let (permit, items) = stable::grant(
            pending,
            holder,
            bytes,
            || {
                let mut items = Vec::new();
                items
                    .try_reserve_exact(capacity)
                    .map_err(|_| Forfeit::AcquisitionFailed)?;
                Ok(items)
            },
            a,
        )?;
        *grown = Owned {
            items,
            capacity,
            permit: Some(permit),
        };
        Ok(())
    }

    /// One unit of cleanup: a staged growth's block and allocation released,
    /// then one element drained per admitted unit, then an interrupted
    /// relocation reset to an empty arena in one admitted write; once
    /// nothing is held, the caller's transition admitted and true. Every
    /// release was paid for by its acquisition. Elements must need no
    /// cleanup of their own.
    ///
    /// Cleanup entry forfeits every obligation the pending custody holds,
    /// Cancelled, each into the family that admitted it, and clears the
    /// acquisition's ticket, before the first unit is admitted and whatever
    /// that unit's outcome: a refused unit leaves no credit held and the
    /// installed resources owned for the next. Settling an idle pending
    /// changes nothing, so every later call settles nothing again.
    ///
    /// Bound on [`Releasing`], not [`Allocator`]: cleanup admits work and
    /// releases what it holds, and no new allocation can be requested
    /// through the capability it is given.
    pub fn reclaim_step<A: Releasing<Permit = P, Origin = O>>(
        &mut self,
        a: &mut A,
    ) -> BoundedResult<bool, A> {
        self.enter_cleanup(a.performer());
        let (next, result) = match mem::replace(&mut self.state, Self::EMPTY) {
            // A staging block never acquired holds nothing once its
            // admissions are settled: the arena's own cleanup follows.
            State::Settled {
                arena,
                growth: Growth::Idle | Growth::Staging,
            } => Self::reclaim_settled(arena, a),
            State::Settled { arena, growth } => {
                Self::release_growth(growth);
                (
                    State::Settled {
                        arena,
                        growth: Growth::Idle,
                    },
                    Ok(false),
                )
            }
            State::Relocating { mut from, mut into } => match Self::ELEMENT.admit(a) {
                Err(error) => (State::Relocating { from, into }, Err(error)),
                Ok(()) => {
                    // The drained element: the grown allocation's newest
                    // while it holds any, otherwise the old one's last.
                    let relocated = into.peek().items.len();
                    let held = relocated + from.remaining.len();
                    let drained = if relocated == 0 {
                        held - 1
                    } else {
                        relocated - 1
                    };
                    boundary!(a, Predicate::Relocation => position(drained, held));
                    if into.get().items.pop().is_none() {
                        from.remaining.next_back();
                    }
                    if from.remaining.as_slice().is_empty() {
                        drop(from);
                        (State::Relocated { into }, Ok(false))
                    } else {
                        (State::Relocating { from, into }, Ok(false))
                    }
                }
            },
            State::Relocated { mut into } if !into.peek().items.is_empty() => {
                match Self::ELEMENT.admit(a) {
                    Err(error) => (State::Relocated { into }, Err(error)),
                    Ok(()) => {
                        into.get().items.pop();
                        (State::Relocated { into }, Ok(false))
                    }
                }
            }
            State::Relocated { into } => match WRITE.admit(a, Self::STATE_BYTES) {
                Err(error) => (State::Relocated { into }, Err(error)),
                Ok(()) => {
                    // SAFETY: every element was drained; the grown arena
                    // owns only its allocation and permit, releases its
                    // growth paid for.
                    unsafe { into.dispose() };
                    (Self::EMPTY, Ok(false))
                }
            },
        };
        self.state = next;
        result
    }

    /// Cleanup entry, the one settlement of every cleanup path: every
    /// obligation the pending custody holds forfeited Cancelled into its own
    /// origin, `by` performing it, and the acquisition's ticket cleared.
    /// Admits nothing and cannot refuse; idempotent on an idle pending.
    fn enter_cleanup(&mut self, by: Performer) {
        self.pending.settle_all(by);
        self.holder = None;
    }

    /// One unit of cleanup of a settled arena with no growth staged.
    fn reclaim_settled<A: Releasing<Permit = P, Origin = O>>(
        mut arena: Owned<T, P>,
        a: &mut A,
    ) -> (State<T, P>, BoundedResult<bool, A>) {
        let growth = Growth::Idle;
        if !arena.items.is_empty() {
            let result = Self::ELEMENT.admit(a).map(|()| {
                arena.items.pop();
                false
            });
            return (State::Settled { arena, growth }, result);
        }
        if arena.release() {
            return (State::Settled { arena, growth }, Ok(false));
        }
        let result = Self::STEP.admit(a).map(|()| true);
        (State::Settled { arena, growth }, result)
    }

    /// Release a staged growth's block, and its grown allocation if it was
    /// requested: releases their acquisitions paid for.
    fn release_growth(growth: Growth<T, P>) {
        match growth {
            Growth::Idle | Growth::Staging => {}
            // SAFETY: a staged or ready arena is empty: it owns only its
            // allocation and permit, if any.
            Growth::Staged(block) | Growth::Ready(block) => unsafe { block.dispose() },
            Growth::Retired(vacated) => vacated.free(),
        }
    }

    /// One part of a transfer of the settled arena into `destination`, the
    /// destination paired with the parts transferred, one admitted unit
    /// each ([`Self::TRANSFER`], the unit [`init_field!`] admits for the
    /// part's type); while its elements are relocating, one unit of the
    /// relocation instead. True once every part is transferred; refused past
    /// the last part.
    pub(crate) fn transfer_step<A: Allocator<Permit = P, Origin = O>>(
        &mut self,
        mut destination: Slot<'_, Owned<T, P>, usize>,
        a: &mut A,
    ) -> BoundedResult<bool, A> {
        if Bound::new(Predicate::Prefix, Self::TRANSFER_PARTS).reached(a, *destination.custody()) {
            return Err(BoundedError::PlanMismatch);
        }
        let Some(arena) = self.settle_step(a)? else {
            return Ok(false);
        };
        match *destination.custody() {
            0 => init_field!(destination, items, || mem::take(&mut arena.items), a)?,
            1 => init_field!(destination, capacity, || mem::take(&mut arena.capacity), a)?,
            _ => init_field!(destination, permit, || arena.permit.take(), a)?,
        }
        let part = destination.custody();
        *part += 1;
        Ok(*part == Self::TRANSFER_PARTS)
    }
}

impl<T: Copy, P, O: Origin> Storage<T, P, O> {
    /// Remaining Copy cleanup calls, including completion. Block-free
    /// settled storage clears in one unit; physical growth is released
    /// before that clear. Relocation still drains complete elements.
    pub(crate) fn reclaim_copy_remaining(&self) -> Option<u64> {
        match &self.state {
            State::Settled { arena, growth } => {
                let growth = match growth {
                    Growth::Idle | Growth::Staging => 0,
                    Growth::Staged(_) | Growth::Ready(_) | Growth::Retired(_) => 1,
                };
                Some(growth + u64::from(!arena.items.is_empty()) + u64::from(arena.holds()) + 1)
            }
            State::Relocating { .. } | State::Relocated { .. } => self.reclaim_remaining(),
        }
    }

    /// Copy cleanup calls for holders that stop once storage is released.
    pub(crate) fn unreleased_copy_remaining(&self) -> Option<u64> {
        if self.is_released() {
            Some(0)
        } else {
            self.reclaim_copy_remaining()
        }
    }

    /// Discard settled plain data beyond `len` in one unit, keeping the
    /// allocation and its reservation; while its elements are relocating,
    /// one unit of the relocation instead. True once truncated.
    pub fn truncate_copy_step<A: Allocator<Permit = P, Origin = O>>(
        &mut self,
        len: usize,
        a: &mut A,
    ) -> BoundedResult<bool, A> {
        let Some(arena) = self.settle_step(a)? else {
            return Ok(false);
        };
        Self::STEP.admit(a)?;
        if boundary!(a, Predicate::ArenaLength, len, arena.items.len()).is_lt() {
            arena.items.truncate(len);
        }
        Ok(true)
    }

    /// [`Self::reclaim_step`], discarding settled plain data in one unit
    /// instead of one value at a time. Its entry settles the pending custody
    /// ([`Self::enter_cleanup`]) before that unit; falling through to
    /// [`Self::reclaim_step`] enters again, which settles nothing a second
    /// time: the pending is idle by then. A staging growth holds no block,
    /// and its admissions are settled by that entry, so its arena is
    /// physically the idle one and is discarded the same way: the unit
    /// follows the arena's physical stage ([`Self::position`]), never what
    /// its acquisition held. Bound on [`Releasing`], as
    /// [`Self::reclaim_step`] is.
    pub(crate) fn reclaim_copy_step<A: Releasing<Permit = P, Origin = O>>(
        &mut self,
        a: &mut A,
    ) -> BoundedResult<bool, A> {
        self.enter_cleanup(a.performer());
        if let State::Settled {
            arena,
            growth: Growth::Idle | Growth::Staging,
        } = &mut self.state
            && !arena.items.is_empty()
        {
            Self::STEP.admit(a)?;
            arena.items.clear();
            return Ok(false);
        }
        self.reclaim_step(a)
    }
}

impl<T, P, O: Origin> Default for Storage<T, P, O> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T, P, O: Origin> Drop for Storage<T, P, O> {
    /// The terminal release of storage dropped without stepped cleanup:
    /// every allocation, staged, relocating or settled, freed with its
    /// permit, each a release its acquisition paid for; whatever credit the
    /// pending custody still holds forfeited, each obligation into its own
    /// origin, with no policy performing it. Allocation-free and
    /// non-unwinding. The pending, the ticket and the owner then drop as
    /// fields: the owner's drop decrements its session's count.
    fn drop(&mut self) {
        self.enter_cleanup(Performer::None);
        match mem::replace(&mut self.state, Self::EMPTY) {
            State::Settled { arena, growth } => {
                Self::release_growth(growth);
                drop(arena);
            }
            State::Relocating { from, into } => {
                drop(from);
                // SAFETY: the grown arena owns its relocated elements, its
                // allocation and its permit, dropped as a vector's.
                unsafe { into.dispose() };
            }
            // SAFETY: as above.
            State::Relocated { into } => unsafe { into.dispose() },
        }
    }
}

/// The settlement count the B-tree's cleanup declares through
/// ([`Storage::settle_remaining`]), checked exactly: it is the calls of
/// [`Storage::settle_step`] that do not yet grant the arena, from every
/// relocation position and once settled.
#[cfg(test)]
#[cfg(feature = "custom-std-collections")]
mod tests {
    use super::*;
    use crate::bounded::{Credits, Family, Limits, Reservation};

    #[test]
    fn pair_append_is_atomic_at_the_reserved_capacity_boundary() {
        let mut a = Limits::unlimited();
        let mut storage = settled(&mut a);
        let arena = match &mut storage.state {
            State::Settled {
                arena,
                growth: Growth::Idle,
            } => arena,
            _ => panic!("the fixture is settled"),
        };
        // Three held, one free slot: a pair does not fit.
        arena.items.pop();
        let before = arena.items.clone();
        let capacity = arena.items.capacity();
        assert_eq!(Spare { owned: &mut *arena }.push_pair([7, 8]), Err([7, 8]));
        assert_eq!(arena.items, before, "failed append wrote a prefix");
        assert_eq!(arena.items.capacity(), capacity, "failed append allocated");
        // Two held, two free slots: the pair fits whole.
        arena.items.pop();
        assert_eq!(Spare { owned: &mut *arena }.push_pair([7, 8]), Ok(()));
        assert_eq!(arena.items, [0, 1, 7, 8]);
        assert_eq!(arena.items.capacity(), capacity, "pair append allocated");
    }

    /// An arena of four `u32`, full, whose growth has relocated `moved`
    /// elements: staged, allocated, published, then `moved` relocation
    /// units.
    fn relocating(moved: usize, a: &mut Limits) -> Storage<u32, Reservation, Family> {
        let mut storage = settled(a);
        for _ in 0..3 + moved {
            assert!(storage.reserve_step(usize::MAX, a).unwrap().is_none());
        }
        storage
    }

    #[test]
    fn settle_remaining_counts_every_unit_before_the_grant() {
        let mut a = Limits::unlimited();
        for moved in 0..=4 {
            let mut storage = relocating(moved, &mut a);
            let declared = storage
                .settle_remaining()
                .expect("four elements' settlement count fits in u64");
            let mut taken = 0u64;
            for _ in 0..8 {
                if storage.settle_step(&mut a).unwrap().is_some() {
                    break;
                }
                taken += 1;
            }
            assert_eq!(declared, taken, "after {moved} relocated elements");
            assert_eq!(storage.settle_remaining(), Some(0), "a settled arena");
        }
    }

    #[test]
    fn copy_cleanup_remaining_bounds_every_growth_and_cleanup_boundary() {
        // Three growth transitions precede the four element moves; the
        // following transitions install the arena and retire its old block.
        for growth_steps in 0..=9 {
            let mut policy = Limits::unlimited();
            let mut storage = settled(&mut policy);
            for _ in 0..growth_steps {
                let _ = storage.reserve_step(usize::MAX, &mut policy).unwrap();
            }
            let initial = storage.reclaim_copy_remaining().unwrap();
            let mut allowances = Vec::new();
            let mut completed = false;
            for call in 0..initial {
                let remaining = storage.reclaim_copy_remaining().unwrap();
                allowances.push((call, remaining));
                let before = storage.position();
                let mut refused = Limits::unlimited().refusing(Some(0));
                let done = match storage.reclaim_copy_step(&mut refused) {
                    Err(BoundedError::Refused(_)) => {
                        assert_eq!(
                            storage.position(),
                            before,
                            "growth {growth_steps}, cleanup {call}: refused cleanup moved storage"
                        );
                        storage.reclaim_copy_step(&mut policy).unwrap()
                    }
                    Ok(done) => {
                        // Prepaid releases do not require admission. Count
                        // that call in this schedule just like admitted work.
                        done
                    }
                    Err(error) => panic!("growth {growth_steps}: {error:?}"),
                };
                if done {
                    completed = true;
                    let actual = call + 1;
                    for (at, bound) in &allowances {
                        assert!(
                            actual - at <= *bound,
                            "growth {growth_steps}, cleanup {at}: remaining bound understated"
                        );
                    }
                    break;
                }
            }
            assert!(completed, "growth {growth_steps}: cleanup bound exhausted");
            assert_eq!(
                policy.live_bytes(),
                0,
                "growth {growth_steps}: storage leaked"
            );
        }
    }

    /// A full arena of four `u32`, `0` through `3`, settled with no growth
    /// begun.
    fn settled(a: &mut Limits) -> Storage<u32, Reservation, Family> {
        let mut storage = Storage::new();
        for value in 0..4u32 {
            let mut pushed = false;
            for _ in 0..storage.len() + 6 {
                if let Some(spare) = storage.reserve_step(usize::MAX, a).unwrap() {
                    spare.push(value);
                    pushed = true;
                    break;
                }
            }
            assert!(pushed, "push {value} exceeded its growth units");
        }
        storage
    }

    /// The elements `for_each_mut` visits, each once, sorted.
    fn visited(storage: &mut Storage<u32, Reservation, Family>) -> Vec<u32> {
        let mut seen = Vec::new();
        storage.for_each_mut(|value| seen.push(*value));
        seen.sort_unstable();
        seen
    }

    /// The contract the B-tree cleanup's newest-entry identity rests on, in
    /// every state: settled, relocating after every number of moved
    /// elements (an element always remains to move), and relocated, `last`
    /// and `last_mut` are the element pushed last, and `for_each_mut` visits
    /// every element exactly once.
    #[test]
    fn last_is_the_newest_and_every_element_is_visited_once() {
        let mut a = Limits::unlimited();
        let mut arenas = vec![("settled".to_string(), settled(&mut a))];
        assert_eq!(arenas[0].1.position().stage, StorageStage::Settled);
        for moved in 0..=4 {
            let storage = relocating(moved, &mut a);
            let position = storage.position();
            if moved < 4 {
                assert_eq!(position.stage, StorageStage::Relocating, "{moved} moved");
                assert_eq!(position.relocating_remaining, 4 - moved, "{moved} moved");
            } else {
                assert_eq!(position.stage, StorageStage::Relocated);
            }
            arenas.push((format!("{moved} relocated"), storage));
        }
        for (name, mut storage) in arenas {
            assert_eq!(storage.last(), Some(&3), "{name}: last");
            assert_eq!(storage.last_mut().copied(), Some(3), "{name}: last_mut");
            assert_eq!(visited(&mut storage), [0, 1, 2, 3], "{name}: visited");
        }
    }

    /// The planted control: a `last` that reads the newest allocation's last
    /// while the arena relocates, as an index-order reading would, is not
    /// the newest element at some relocation position.
    #[test]
    fn a_last_of_the_grown_allocation_is_refused_while_relocating() {
        fn grown_last(storage: &Storage<u32, Reservation, Family>) -> Option<&u32> {
            match &storage.state {
                State::Settled { arena, .. } => arena.items.last(),
                State::Relocating { into, .. } | State::Relocated { into } => {
                    into.peek().items.last()
                }
            }
        }
        let mut a = Limits::unlimited();
        let wrong = (0..4).any(|moved| grown_last(&relocating(moved, &mut a)) != Some(&3));
        assert!(
            wrong,
            "the grown allocation's last was the newest at every position"
        );
    }

    const NOTHING: WriteWork = WriteWork::new(0, 0);

    /// The credit `storage`'s custody holds: the checked fold of its one
    /// traversal ([`total_held`] over [`Storage::observe_custody`]), as every
    /// holder totals it. `None` when the sum does not fit.
    fn held(storage: &Storage<u32, Reservation, Family>) -> Option<WriteWork> {
        total_held(|sink| storage.observe_custody(sink))
    }

    /// The kinds of the obligations `storage`'s custody holds, in its one
    /// traversal's order ([`crate::bounded::held_of`] over
    /// [`Storage::observe_custody`]): the retained admissions of an
    /// acquisition under way, which its execution stage never carries.
    fn retained(storage: &Storage<u32, Reservation, Family>) -> Vec<Obligation> {
        let mut kinds = Vec::new();
        let observed = crate::bounded::held_of(|sink| storage.observe_custody(sink), &mut |hold| {
            kinds.push(hold.obligation)
        });
        assert_eq!(observed, crate::bounded::PermitsObserved::Complete);
        kinds
    }

    /// A full arena of four, settled under `s`, whose next acquisition is
    /// the staging block's, or, `staged`, the grown allocation's (the staging
    /// block acquired under `s` first); then that acquisition's grant
    /// admitted under `a`, every admission of which `a` refuses once, so its
    /// release is refused there; then its release admitted under `b`, whose
    /// first request is refused. The arena then holds A's grant and B's
    /// release, nothing else, toward the acquisition's retry.
    fn held_across_families(
        staged: bool,
        s: &mut Limits,
        a: &mut Limits,
        b: &mut Limits,
    ) -> Storage<u32, Reservation, Family> {
        let mut storage = settled(s);
        if staged {
            assert!(storage.reserve_step(usize::MAX, s).unwrap().is_none());
            assert_eq!(storage.position().stage, StorageStage::Staged);
            assert_eq!(retained(&storage), []);
        }
        let mut granted = false;
        for _ in 0..8 {
            match storage.reserve_step(usize::MAX, a) {
                Err(BoundedError::Refused(_)) => {}
                other => panic!("staged {staged}: under A: {:?}", other.map(|s| s.is_some())),
            }
            if held(&storage) != Some(NOTHING) {
                granted = true;
                break;
            }
        }
        assert!(granted, "staged {staged}: the grant was never held under A");
        match storage.reserve_step(usize::MAX, b) {
            Err(BoundedError::Refused(_)) => {}
            other => panic!("staged {staged}: under B: {:?}", other.map(|s| s.is_some())),
        }
        assert_eq!(b.requests(), 1, "staged {staged}: B's one request");
        assert_eq!(
            storage.position().stage,
            if staged {
                StorageStage::Staged
            } else {
                StorageStage::Settled
            },
            "staged {staged}"
        );
        assert_eq!(
            retained(&storage),
            [Obligation::Grant, Obligation::Release],
            "staged {staged}"
        );
        for (name, family) in [("A", &*a), ("B", &*b)] {
            let credits = family.credits();
            assert_ne!(
                credits.admitted, NOTHING,
                "staged {staged}: {name} admitted nothing"
            );
            assert_eq!(credits.consumed, NOTHING, "staged {staged}: {name}");
            assert_eq!(credits.forfeited, NOTHING, "staged {staged}: {name}");
            assert!(!credits.violated, "staged {staged}: {name}");
        }
        storage
    }

    /// W1. Cleanup entry settles every family before its first unit, the
    /// unit's outcome aside: after a first cleanup call under D refused at
    /// its first admission, the arena holds no credit, A and B have
    /// forfeited exactly what each held (admitted and consumed unchanged,
    /// each conserving with nothing held), D's ledgers are untouched, and
    /// the installed elements are still owned. Cleanup then completes with
    /// no second settlement: A's and B's ledgers stay as they were.
    #[test]
    fn cleanup_entry_settles_every_family_before_its_first_unit() {
        for staged in [false, true] {
            let (mut s, mut a, mut b) = (
                Limits::unlimited(),
                Limits::unlimited().refusing_each(),
                Limits::unlimited().refusing_request(Some(0)),
            );
            let mut storage = held_across_families(staged, &mut s, &mut a, &mut b);
            let before = [a.credits(), b.credits()];
            let mut d = Limits::unlimited().refusing(Some(0));
            let first = storage.reclaim_step(&mut d);
            if !staged {
                // The staging growth holds no block: the first unit drains
                // an element, and D refuses it.
                assert!(
                    matches!(first, Err(BoundedError::Refused(_))),
                    "the first unit was not refused"
                );
            }
            assert_eq!(held(&storage), Some(NOTHING), "staged {staged}");
            assert_eq!(storage.len(), 4, "staged {staged}: an element was lost");
            for ((name, family), before) in [("A", &a), ("B", &b)].into_iter().zip(before) {
                let after = family.credits();
                assert_eq!(after.admitted, before.admitted, "staged {staged}: {name}");
                assert_eq!(after.consumed, before.consumed, "staged {staged}: {name}");
                assert_ne!(
                    after.forfeited, NOTHING,
                    "staged {staged}: {name} forfeited nothing"
                );
                assert_eq!(
                    after.conserved_with(NOTHING),
                    Some(true),
                    "staged {staged}: {name} still holds credit"
                );
            }
            assert_eq!(
                d.credits(),
                Credits::default(),
                "staged {staged}: D's ledgers"
            );
            let settled = [a.credits(), b.credits()];
            let mut done = false;
            for _ in 0..16 {
                match storage.reclaim_step(&mut d) {
                    Ok(true) => {
                        done = true;
                        break;
                    }
                    Ok(false) | Err(BoundedError::Refused(_)) => {}
                    Err(error) => panic!("staged {staged}: {error:?}"),
                }
            }
            assert!(done, "staged {staged}: cleanup did not finish");
            assert_eq!(
                [a.credits(), b.credits()],
                settled,
                "staged {staged}: settled a second time"
            );
            assert_eq!(s.live_bytes(), 0, "staged {staged}");
        }
    }

    /// Block-free staging changes custody, not the Copy arena's physical
    /// cancellation schedule, including a refused first clear.
    #[test]
    fn copy_cleanup_of_idle_and_credit_holding_arenas_has_the_same_schedule() {
        let session = Session::new(Capacity::DEFAULT);
        let mut s = Limits::recorded_unlimited(&session);
        let mut a = Limits::recorded_unlimited(&session).refusing_each();
        let mut b = Limits::recorded_unlimited(&session).refusing_request(Some(0));
        let mut idle = settled(&mut s);
        let mut pending = held_across_families(false, &mut s, &mut a, &mut b);
        assert_eq!(idle.position(), pending.position());
        let mut holds = Vec::new();
        assert_eq!(
            held_of(|sink| pending.observe_custody(sink), &mut |hold| holds
                .push(hold)),
            PermitsObserved::Complete
        );
        assert_eq!(holds.len(), 2, "both acquisition obligations must be held");
        let acquisition = holds[0].acquisition;
        assert_eq!(holds[1].acquisition, acquisition);
        let mut left = Limits::recorded_unlimited(&session).refusing(Some(0));
        let mut right = Limits::recorded_unlimited(&session).refusing(Some(0));
        let by = right.performer();
        let before = pending.position();
        assert!(matches!(
            idle.reclaim_copy_step(&mut left),
            Err(BoundedError::Refused(_))
        ));
        assert!(matches!(
            pending.reclaim_copy_step(&mut right),
            Err(BoundedError::Refused(_))
        ));
        assert_eq!(
            pending.position(),
            before,
            "refused clear moved physical custody"
        );
        assert_eq!(idle.position(), pending.position());
        assert_eq!(idle.settled().unwrap().as_slice(), &[0, 1, 2, 3]);
        assert_eq!(pending.settled().unwrap().as_slice(), &[0, 1, 2, 3]);
        assert_eq!(held(&pending), Some(NOTHING));
        let settled_credit = [a.credits(), b.credits()];
        let bound = pending.reclaim_copy_remaining().unwrap();
        assert_eq!(
            bound, 3,
            "one clear, one allocation release, one completion"
        );
        let mut completed = false;
        for turn in 0..bound {
            assert_eq!(
                idle.reclaim_copy_remaining(),
                pending.reclaim_copy_remaining(),
                "cleanup remaining schedule differs at {turn}"
            );
            let l = idle.reclaim_copy_step(&mut left).unwrap();
            let r = pending.reclaim_copy_step(&mut right).unwrap();
            assert_eq!(l, r, "cleanup completion differs at {turn}");
            assert_eq!(
                idle.position(),
                pending.position(),
                "cleanup schedule differs at {turn}"
            );
            assert_eq!(left.used(), right.used(), "cleanup work differs at {turn}");
            if l {
                completed = true;
                break;
            }
        }
        assert!(completed, "copy cleanup exceeded its remaining bound");
        assert_eq!(
            [a.credits(), b.credits()],
            settled_credit,
            "cleanup settled twice"
        );
        assert_eq!((left.requests(), right.requests()), (0, 0));
        drop((idle, pending, s, a, b, left, right));
        let events = session.finish().unwrap();
        for hold in holds {
            let settlements: Vec<_> = events
                .iter()
                .filter_map(|event| match event.event {
                    Event::Credit(Credit::Forfeit(settled, rule)) if settled.id == hold.id => {
                        Some((
                            event.family,
                            event.by,
                            settled.acquisition,
                            settled.work,
                            rule,
                        ))
                    }
                    _ => None,
                })
                .collect();
            assert_eq!(
                settlements,
                [(
                    hold.id.family(),
                    by,
                    acquisition,
                    hold.work,
                    Forfeit::Cancelled
                )]
            );
        }
        let ends: Vec<_> = events
            .iter()
            .filter(|event| {
                matches!(
                    event.event, Event::End { acquisition: id, .. } if id == acquisition
                )
            })
            .collect();
        assert_eq!(ends.len(), 1, "cancelled acquisition must end exactly once");
        assert_eq!((ends[0].family, ends[0].by), (acquisition.family(), by));
    }

    /// W2. A held acquisition is admitted once across refused requests:
    /// with A's grant and B's release held, C refuses `n` requests and then
    /// grants. A and B each admitted exactly once (their admissions
    /// unchanged by C's retries), both are consumed whole at the grant with
    /// nothing forfeited, C admits no work and makes `n + 1` requests (B's
    /// refused one apart), and C holds the permit. For the staging block's
    /// acquisition and the grown allocation's.
    #[test]
    fn a_held_acquisition_is_admitted_once_across_refused_requests() {
        for staged in [false, true] {
            for n in [0, 1, 3] {
                let (mut s, mut a, mut b) = (
                    Limits::unlimited(),
                    Limits::unlimited().refusing_each(),
                    Limits::unlimited().refusing_request(Some(0)),
                );
                let mut storage = held_across_families(staged, &mut s, &mut a, &mut b);
                let admitted = [a.credits().admitted, b.credits().admitted];
                let mut c = Limits::unlimited().refusing_requests(n);
                for refusal in 0..n {
                    match storage.reserve_step(usize::MAX, &mut c) {
                        Err(BoundedError::Refused(_)) => {}
                        other => panic!(
                            "staged {staged}, n {n}: refusal {refusal}: {:?}",
                            other.map(|s| s.is_some())
                        ),
                    }
                    assert_eq!(
                        [a.credits().admitted, b.credits().admitted],
                        admitted,
                        "staged {staged}, n {n}: readmitted at refusal {refusal}"
                    );
                }
                match storage.reserve_step(usize::MAX, &mut c) {
                    Ok(None) => {}
                    other => panic!(
                        "staged {staged}, n {n}: the grant: {:?}",
                        other.map(|s| s.is_some())
                    ),
                }
                assert_eq!(
                    storage.position().stage,
                    if staged {
                        StorageStage::Ready
                    } else {
                        StorageStage::Staged
                    },
                    "staged {staged}, n {n}"
                );
                assert_eq!(retained(&storage), [], "staged {staged}, n {n}");
                assert_eq!(c.requests(), n + 1, "staged {staged}, n {n}: C's requests");
                assert_eq!(c.credits(), Credits::default(), "staged {staged}, n {n}: C");
                assert_ne!(
                    c.live_bytes(),
                    0,
                    "staged {staged}, n {n}: C holds no permit"
                );
                for ((name, family), admitted) in [("A", &a), ("B", &b)].into_iter().zip(admitted) {
                    let credits = family.credits();
                    assert_eq!(credits.admitted, admitted, "staged {staged}, n {n}: {name}");
                    assert_eq!(credits.consumed, admitted, "staged {staged}, n {n}: {name}");
                    assert_eq!(credits.forfeited, NOTHING, "staged {staged}, n {n}: {name}");
                    assert_eq!(held(&storage), Some(NOTHING), "staged {staged}, n {n}");
                }
                let mut done = false;
                for _ in 0..16 {
                    if storage.reclaim_step(&mut s).expect("an unlimited cleanup") {
                        done = true;
                        break;
                    }
                }
                assert!(done, "staged {staged}, n {n}: cleanup did not finish");
                assert_eq!(c.live_bytes(), 0, "staged {staged}, n {n}: C's permit kept");
            }
        }
    }

    /// W3, the prefix-safety witness. Every initialization prefix, the empty
    /// one and the whole arena included, written under a recorded policy, is
    /// destroyed exactly through [`Storage::drop_prefix`]: each initialized
    /// field once, no unwritten one read. Dropping past what was written
    /// reads uninitialized discriminants, which only Miri observes
    /// (`tests/miri-suites.txt`, the storage-prefix-overdrop control, its
    /// intended failure Miri's access to an unwritten field).
    ///
    /// A prefix holds no owned custody (a deferred owner, a plain head,
    /// empty slots), which the session's finished stream shows: every
    /// observation is an initialization unit's call admitted and its
    /// admission consumed whole, no owner made, no acquisition bound, no
    /// credit held, no permit granted or released, so nothing a prefix's
    /// destruction could have to settle; and the session finishes whole once
    /// the policy drops, nothing of it outliving the prefix. This is no
    /// refinement of the stream: the refined lifecycle evidence of a prefix
    /// destroyed in production is the B-tree's metadata-prefix stops, each
    /// destroying its arenas through this function under a recorded run
    /// (`tests/owned_btree.rs`
    /// `tree_construction_is_complete_and_its_transitions_legal`).
    #[test]
    fn every_initialization_prefix_drops_and_releases_its_session() {
        use super::super::construction::reclamation::Place;
        use crate::bounded::{Answer, Call, Capacity, Credit, Event, Session};
        type Arena = Storage<u32, Reservation, Family>;
        for written in 0..=Arena::INIT_STEPS {
            let session = Session::new(Capacity::DEFAULT);
            let mut r = Limits::recorded_unlimited(&session);
            let mut raw = MaybeUninit::<Arena>::uninit();
            let mut units = 0usize;
            for _ in 0..written {
                // SAFETY: `raw` is a stable, aligned destination this test
                // owns outright, reached only through this place; `units`
                // counts exactly the units written.
                let slot = unsafe {
                    Slot::new(Place::root(core::ptr::NonNull::from(&mut raw)), &mut units)
                };
                Arena::initialize_step(slot, &mut r).expect("an unlimited unit");
            }
            assert_eq!(units, written);
            // SAFETY: exactly the first `written` units are initialized,
            // and nothing reads them afterwards.
            unsafe { Arena::drop_prefix(raw.as_mut_ptr(), written) };
            drop(r);
            let observed = session.finish().unwrap_or_else(|incomplete| {
                panic!("{written} units: the session is still held or invalid: {incomplete:?}")
            });
            let (mut calls, mut consumed) = (0, 0);
            for observation in &observed {
                match observation.event {
                    Event::Call(Call::Work { .. }, Answer::Admitted) => calls += 1,
                    Event::Credit(Credit::Admit { held: None, .. }) => consumed += 1,
                    event => panic!("{written} units: a prefix observed {event:?}"),
                }
            }
            assert_eq!(
                (calls, consumed),
                (written, written),
                "{written} units: one admitted unit, consumed whole, per field written"
            );
        }
    }

    /// The defaults are the empty arena and its position: settled, nothing
    /// held, nothing staged.
    #[test]
    fn the_default_arena_is_empty_and_settled() {
        let storage = Storage::<u8, (), ()>::default();
        assert!(storage.is_released());
        assert_eq!(storage.position(), StoragePosition::default());
        assert_eq!(
            StoragePosition::default(),
            StoragePosition {
                stage: StorageStage::Settled,
                initialized: 0,
                reserved_capacity: 0,
                physical_capacity: 0,
                relocating_remaining: 0,
                has_current_permit: false,
                staged_reserved_capacity: 0,
                staged_physical_capacity: 0,
                has_staged_permit: false,
                has_relocating_permit: false,
                released: true,
            }
        );
    }

    /// The element counts [`every_growth_admits_exactly_its_bound`] checks:
    /// every count from none through this one, nine growths.
    const GROWTH_DOMAIN: u64 = 2048;

    /// The retained arena's growth against its bound
    /// ([`crate::bounded::storage_growth`]), for every count of `u64`
    /// elements through [`GROWTH_DOMAIN`]: an arena grown from empty to `n`
    /// elements by [`Storage::reserve_step`] and [`Spare::push`] under an
    /// unlimited policy
    ///
    /// - makes exactly the bound's allocation requests, two per growth (the
    ///   staging block and the grown allocation);
    /// - requests exactly the arena's growths
    ///   ([`crate::bounded::owned_growth`]) and one staging block
    ///   ([`Storage::STAGING`]) per growth, at most the bound's bytes;
    /// - holds at most the bound's peak, exactly the last growth's old and
    ///   grown allocations beside its staging block, and ends holding the
    ///   bound's final allocation alone;
    /// - admits exactly one unit per relocated element, of its bytes
    ///   ([`Storage::element_work`]), one value per growth write and one per
    ///   release admitted with each allocation ([`RELEASED`]), within the
    ///   bound's work and the releases its allocations admit, each at most a
    ///   full release unit. A growth writes [`GROWTH_WRITES`] units of
    ///   [`WRITE`], except the first: an empty arena's grown allocation is
    ///   settled at its publication ([`Storage::grow_step`], `Ready` of an
    ///   empty arena), so it makes no settlement write, one fewer than the
    ///   bound counts.
    ///
    /// Checked over the stated domain, not proved.
    ///
    /// # The argument beyond the domain (source-reviewed, not checked)
    ///
    /// Every growth of a retained arena is the same transition sequence,
    /// read from [`Storage::grow_step`], [`Storage::relocate_step`] and
    /// [`Storage::allocate_grown`]; the count enters only through `c`, the
    /// capacity before the growth:
    ///
    /// 1. It begins only from a settled arena with no growth staged and no
    ///    free slot ([`Storage::reserve_step`]'s `free`), and slots are
    ///    filled only through [`Spare`], one per granted free slot, so
    ///    `len == c`: the full arena the recurrence grows.
    /// 2. Stage: the staging block's acquisition ([`Storage::STAGING`]), one
    ///    write unit of at most a quantum and one release unit, and one
    ///    request of `STAGING.block()`, at most `TURN.bytes` (asserted at
    ///    compile time).
    /// 3. Allocate: one grant write ([`WRITE`] of `ARENA_BYTES`) and one
    ///    release ([`RELEASED`]), then one request of `g(c) * s`, `g` the
    ///    growth rule (`crate::bounded::grown`, [`crate::bounded::grown_capacity`]),
    ///    clamped to the caller's `maximum`: a clamp only shortens the last
    ///    growth (a growth that cannot pass `len` is refused), so it requests
    ///    no more than the unclamped rule.
    /// 4. Publish: one [`WRITE`]. From an empty arena (`c == 0`) the grown
    ///    allocation settles here, and steps 5 and 6 are skipped.
    /// 5. Relocate: `c` units of [`Storage::ELEMENT`], one per element.
    /// 6. Settle: one [`WRITE`].
    /// 7. Retire: no admission; the staging block freed before any later
    ///    growth can stage.
    ///
    /// So one growth admits the recurrence step's relocation (`c` elements,
    /// `c * s` bytes) and requests its grown allocation (`g(c) * s`), holding
    /// the old and the grown allocation at once beside the staging block,
    /// plus a fixed overhead: one staging request of at most a quantum, at
    /// most four writes and two releases of at most a quantum each. A refused
    /// unit admits nothing new and is retried without readmitting what its
    /// acquisition holds (`a_held_acquisition_is_admitted_once_across_refused_requests`).
    /// By induction on the number of growths, an arena that has grown `k`
    /// times has admitted and requested the recurrence's state after `k`
    /// steps plus `k` overheads, which is `storage_growth`'s formula, and the
    /// closed-form harnesses relate that formula to the recurrence
    /// (`bounded::growth_proofs`). The step list is read from source: this
    /// test checks it over its domain, and no harness checks it beyond.
    #[test]
    fn every_growth_admits_exactly_its_bound() {
        type Arena = Storage<u64, Reservation, Family>;
        let element = size_of::<u64>() as u64;
        let staging = Arena::STAGING.block() as u64;
        let release = WriteWork::new(RELEASED.values(), RELEASED.cap());
        for n in 0..=GROWTH_DOMAIN {
            let (bound, work) = storage_growth::<()>(n, element).expect("the domain's bound fits");
            let arena = owned_growth::<()>(n, element).expect("the domain's arena fits");
            let relocated = owned_growth::<()>(n, 1)
                .expect("the domain's count fits")
                .copied;
            let growths = arena.allocations;
            let mut a = Limits::unlimited();
            let mut storage = Arena::new();
            // Each growth from capacity `c` takes at most `c + 5` calls
            // (stage, allocate, publish, `c` relocations, settle, retire),
            // and each push one more.
            let most = 8 * GROWTH_DOMAIN + 64;
            let mut calls = 0u64;
            for value in 0..n {
                loop {
                    calls += 1;
                    assert!(calls <= most, "{n}: the arena did not grow to hold {value}");
                    if let Some(spare) = storage
                        .reserve_step(usize::MAX, &mut a)
                        .expect("an unlimited growth")
                    {
                        spare.push(value);
                        break;
                    }
                }
            }
            assert_eq!(storage.len() as u64, n, "{n}: the elements held");
            assert_eq!(
                a.requests() as u64,
                bound.allocations,
                "{n}: the allocation requests"
            );
            assert_eq!(
                a.requested_bytes(),
                arena.allocated + growths * staging,
                "{n}: the bytes requested"
            );
            assert!(
                a.requested_bytes() <= bound.allocated,
                "{n}: {} bytes requested beyond the bound's {}",
                a.requested_bytes(),
                bound.allocated
            );
            let peak = if growths == 0 {
                0
            } else {
                arena.peak + staging
            };
            assert_eq!(a.peak_bytes(), peak, "{n}: the most bytes held at once");
            assert!(
                a.peak_bytes() <= bound.peak,
                "{n}: a peak of {} beyond the bound's {}",
                a.peak_bytes(),
                bound.peak
            );
            assert_eq!(a.live_bytes(), bound.held, "{n}: the bytes held at the end");
            let relocation = Arena::element_work::<()>(relocated).expect("the domain's work fits");
            // The first growth's settlement write is never made.
            let writes = (growths * GROWTH_WRITES).saturating_sub(u64::from(growths != 0));
            let used = a.used();
            assert_eq!(
                used.values,
                relocation.values + writes * WRITE.values() + bound.allocations * RELEASED.values(),
                "{n}: the values admitted"
            );
            assert!(
                used.bytes >= relocation.bytes,
                "{n}: {} bytes admitted, fewer than the relocations' {}",
                used.bytes,
                relocation.bytes
            );
            let covered = work
                .checked_then(
                    release
                        .checked_times(bound.allocations)
                        .expect("the domain's releases fit"),
                )
                .expect("the domain's work fits");
            assert!(
                used.values <= covered.values && used.bytes <= covered.bytes,
                "{n}: admitted {used:?} beyond the bound's work and releases {covered:?}"
            );
            drop(storage);
            assert_eq!(a.live_bytes(), 0, "{n}: the arena outlived its drop");
        }
    }
}
