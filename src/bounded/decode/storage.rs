//! Retained arena growth. An arena is settled, every element in its one
//! allocation, or relocating its elements into a grown allocation, each
//! admitted turn moving at most one. The grown allocation is staged in a
//! stable block beside the settled arena until a single write publishes the
//! relocation, so every state an admission can suspend in is a valid value
//! owning each allocation exactly once, and every transition writes the
//! whole state in one unit of at most a quantum.
use super::super::*;
use super::construction::stable::{self, Admitted, Installed, Metadata};
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

/// A growth of a settled arena, staged beside it, each stage holding exactly
/// what it has acquired: nothing, the admissions of the staging block, the
/// block and the admissions of the grown allocation, the block holding the
/// grown allocation, or the block vacated once the arena holds that
/// allocation, its release next.
enum Growth<T, P> {
    Idle,
    Staging(Admitted),
    Staged(Block<T, P>, Admitted),
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

/// A retained arena of `T` with permits of `P`. Its elements are readable
/// only while it is settled ([`Self::settle_step`]); a free slot is granted
/// only by [`Self::reserve_step`], so a push into reserved capacity cannot
/// fail. The whole state is at most a quantum, a bound on `P` checked at
/// compile time where the arena is used.
pub struct Storage<T, P> {
    state: State<T, P>,
}

/// Where an arena is in its growth, each stage naming exactly what it holds
/// beyond the arena's own allocation: the typestate of [`Storage`], with the
/// admissions a refused acquisition keeps, since they decide what its next
/// step admits.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum StorageStage {
    /// Settled; no growth begun.
    Settled,
    /// Settled; admissions held toward the staging block, no block yet.
    Staging(Admitted),
    /// Settled; the staging block held, admissions held toward the grown
    /// allocation it will hold.
    Staged(Admitted),
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
/// that fix its remaining moves and drains.
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
}

impl Default for StoragePosition {
    fn default() -> Self {
        Storage::<u8, ()>::new().position()
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
}

impl<T: Copy, P> Spare<'_, T, P> {
    /// Fill as many free slots as `values` and the room allow, in order;
    /// the number filled.
    pub fn extend(self, values: &[T]) -> usize {
        let count = values.len().min(self.room());
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

impl<T, P> Storage<T, P> {
    /// An empty settled arena, no growth staged.
    const EMPTY: State<T, P> = State::Settled {
        arena: Owned::new(),
        growth: Growth::Idle,
    };

    /// The bytes one transition writes: the whole state, at most a quantum.
    const STATE_BYTES: u64 = write_extent(size_of::<Self>());

    /// The bytes writing a grown arena into its block writes.
    const ARENA_BYTES: u64 = write_extent(size_of::<Owned<T, P>>());

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

    pub(crate) const INIT_STEPS: usize = 1;

    /// The work of a whole transfer into an owner's arena
    /// ([`Self::transfer_step`]): its three parts, each one unit.
    pub(crate) fn transfer_work<R>() -> Result<WriteWork, BoundedError<R>> {
        Self::TRANSFER[0]
            .times(1)?
            .then(Self::TRANSFER[1].times(1)?)?
            .then(Self::TRANSFER[2].times(1)?)
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
            WRITE.times(1)?.then(Self::STEP.times(1)?)
        } else {
            Self::STEP.times(1)
        }
    }

    /// The writes `growths` growths make ([`GROWTH_WRITES`]), each at most a
    /// quantum.
    pub(crate) fn growth_work<R>(growths: u64) -> Result<WriteWork, BoundedError<R>> {
        WRITE.times(mul(growths, GROWTH_WRITES)?)
    }

    pub const fn new() -> Self {
        Self { state: Self::EMPTY }
    }

    /// Initialize the empty arena directly in its final destination, in one
    /// unit of the whole state. Partial initialization owns no resources.
    ///
    /// # Safety
    /// The destination is unique and stable; step starts at zero and is
    /// retained.
    pub(crate) unsafe fn initialize_step<A: Allocator<Permit = P>>(
        place: *mut Self,
        step: &mut usize,
        a: &mut A,
    ) -> BoundedResult<bool, A> {
        // SAFETY: forwarded from the caller; the empty arena owns nothing.
        unsafe { super::initialization::field(place, Self::new, a)? };
        *step = Self::INIT_STEPS;
        Ok(true)
    }

    pub fn position(&self) -> StoragePosition {
        match &self.state {
            State::Settled { arena, growth } => StoragePosition {
                stage: match growth {
                    Growth::Idle => StorageStage::Settled,
                    Growth::Staging(admitted) => StorageStage::Staging(*admitted),
                    Growth::Staged(_, admitted) => StorageStage::Staged(*admitted),
                    Growth::Ready(_) => StorageStage::Ready,
                    Growth::Retired(_) => StorageStage::Retired,
                },
                initialized: arena.items.len(),
                reserved_capacity: arena.capacity,
                physical_capacity: arena.items.capacity(),
                relocating_remaining: 0,
                has_current_permit: arena.permit.is_some(),
                staged_reserved_capacity: match growth {
                    Growth::Staged(block, _) | Growth::Ready(block) => block.peek().capacity,
                    _ => 0,
                },
                staged_physical_capacity: match growth {
                    Growth::Staged(block, _) | Growth::Ready(block) => {
                        block.peek().items.capacity()
                    }
                    _ => 0,
                },
                has_staged_permit: match growth {
                    Growth::Staged(block, _) | Growth::Ready(block) => {
                        block.peek().permit.is_some()
                    }
                    _ => false,
                },
                has_relocating_permit: false,
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
    /// so while it runs the newest is the old allocation's last.
    pub fn last(&self) -> Option<&T> {
        match &self.state {
            State::Settled { arena, .. } => arena.items.last(),
            State::Relocating { from, into } => from
                .remaining
                .as_slice()
                .last()
                .or_else(|| into.peek().items.last()),
            State::Relocated { into } => into.peek().items.last(),
        }
    }

    /// The newest element, writable, in whichever allocation holds it: how
    /// the holder of an arena of construction records observes the active
    /// record's custody in every state, relocation included. Moves nothing
    /// and admits nothing.
    #[cfg(feature = "custom-std-collections")]
    pub(crate) fn last_mut(&mut self) -> Option<&mut T> {
        match &mut self.state {
            State::Settled { arena, .. } => arena.items.last_mut(),
            State::Relocating { from, into } => {
                if let Some(last) = from.remaining.as_mut_slice().last_mut() {
                    return Some(last);
                }
                into.get().items.last_mut()
            }
            State::Relocated { into } => into.get().items.last_mut(),
        }
    }

    /// Every element held, in whichever allocation holds it, writable: how
    /// the holder of an arena of construction records sums what their
    /// cleanup still owes, relocation included. Moves nothing and admits
    /// nothing.
    #[cfg(feature = "custom-std-collections")]
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

    /// The most units [`Self::reclaim_step`] or [`Self::reclaim_copy_step`]
    /// takes from here to report the storage released: a staged growth's
    /// release, one drain per element (or one truncation of plain data), the
    /// allocation's release or an interrupted relocation's reset, then the
    /// completing transition.
    pub(crate) fn reclaim_remaining(&self) -> u64 {
        (self.len() as u64).saturating_add(3)
    }

    /// [`Self::reclaim_remaining`] for a holder that steps this storage's
    /// cleanup only while it is not [`Self::is_released`]: none once it is.
    pub(crate) fn unreleased_remaining(&self) -> u64 {
        if self.is_released() {
            0
        } else {
            self.reclaim_remaining()
        }
    }

    /// The most units [`Self::settle_step`] takes before it grants the
    /// settled arena: one per element still relocating, then the settlement.
    #[cfg(feature = "custom-std-collections")]
    pub(crate) fn settle_remaining(&self) -> u64 {
        match &self.state {
            State::Settled { .. } => 0,
            State::Relocating { from, .. } => (from.remaining.len() as u64).saturating_add(1),
            State::Relocated { .. } => 1,
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
    pub fn reserve_step<A: Allocator<Permit = P>>(
        &mut self,
        maximum: usize,
        a: &mut A,
    ) -> BoundedResult<Option<Spare<'_, T, P>>, A> {
        // Whether a slot is free is decided through a shared borrow, so the
        // mutable borrow the grant returns is taken in a statement of its
        // own: a borrow returned from one match arm while another arm uses
        // the storage is rejected by the stable borrow checker.
        let free = matches!(
            &self.state,
            State::Settled {
                arena,
                growth: Growth::Idle,
            } if arena.items.len() < arena.capacity
        );
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
    /// elements are relocating, one admitted unit of the relocation and
    /// `None`. A growth staged beside a settled arena leaves it readable.
    pub fn settle_step<A: Allocator<Permit = P>>(
        &mut self,
        a: &mut A,
    ) -> BoundedResult<Option<&mut Owned<T, P>>, A> {
        match self.state {
            State::Settled { ref mut arena, .. } => Ok(Some(arena)),
            _ => {
                self.grow_step(usize::MAX, a)?;
                Ok(None)
            }
        }
    }

    /// The settled arena, taken, leaving an empty one; or, while its
    /// elements are relocating, one admitted unit of the relocation and
    /// `None`. A staged growth stays with the storage for its cleanup.
    pub(crate) fn take_step<A: Allocator<Permit = P>>(
        &mut self,
        a: &mut A,
    ) -> BoundedResult<Option<Owned<T, P>>, A> {
        Ok(self.settle_step(a)?.map(mem::take))
    }

    /// One admitted unit of growth: the staging block acquired, the grown
    /// allocation requested into it, the relocation published, one element
    /// relocated, the relocated arena settled, or the vacated block
    /// released. Every path writes the state back, refusals included.
    fn grow_step<A: Allocator<Permit = P>>(
        &mut self,
        maximum: usize,
        a: &mut A,
    ) -> BoundedResult<(), A> {
        let (next, result) = match mem::replace(&mut self.state, Self::EMPTY) {
            State::Settled {
                arena,
                growth: growth @ (Growth::Idle | Growth::Staging(_)),
            } => {
                let mut admitted = match growth {
                    Growth::Staging(admitted) => admitted,
                    _ => Admitted::Nothing,
                };
                // SAFETY: the initializer writes the empty arena whole.
                match unsafe {
                    stable::installed::<Owned<T, P>, A>(
                        &mut admitted,
                        const { Metadata::whole::<Owned<T, P>, P>() },
                        |owned| owned.write(Owned::new()),
                        a,
                    )
                } {
                    Ok(block) => (
                        State::Settled {
                            arena,
                            growth: Growth::Staged(block, Admitted::Nothing),
                        },
                        Ok(()),
                    ),
                    Err(error) => (
                        State::Settled {
                            arena,
                            growth: match admitted {
                                Admitted::Nothing => Growth::Idle,
                                _ => Growth::Staging(admitted),
                            },
                        },
                        Err(error),
                    ),
                }
            }
            State::Settled {
                arena,
                growth: Growth::Staged(mut block, mut admitted),
            } => match Self::allocate_grown(&arena, block.get(), &mut admitted, maximum, a) {
                Ok(()) => (
                    State::Settled {
                        arena,
                        growth: Growth::Ready(block),
                    },
                    Ok(()),
                ),
                Err(error) => (
                    State::Settled {
                        arena,
                        growth: Growth::Staged(block, admitted),
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
            State::Relocating { mut from, mut into } => match Self::ELEMENT.admit(a) {
                Err(error) => (State::Relocating { from, into }, Err(error)),
                Ok(()) => {
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

    /// Request the grown allocation into the staged arena `grown`: its
    /// write and its release admitted first, kept in `admitted` across a
    /// refused allocation. Capacity doubles from four, capped at `maximum`.
    fn allocate_grown<A: Allocator<Permit = P>>(
        arena: &Owned<T, P>,
        grown: &mut Owned<T, P>,
        admitted: &mut Admitted,
        maximum: usize,
        a: &mut A,
    ) -> BoundedResult<(), A> {
        let capacity = if arena.capacity == 0 {
            4
        } else {
            arena
                .capacity
                .checked_mul(2)
                .ok_or(BoundedError::Overflow)?
        };
        let capacity = capacity.min(maximum);
        if capacity <= arena.items.len() {
            return Err(BoundedError::PlanMismatch);
        }
        let bytes = mul(widen(capacity)?, widen(size_of::<T>())?)?;
        if *admitted == Admitted::Nothing {
            WRITE.admit(a, Self::ARENA_BYTES)?;
            *admitted = Admitted::Write;
        }
        if *admitted == Admitted::Write {
            RELEASED.admit(a, Owned::<T, P>::RELEASE_BYTES)?;
            *admitted = Admitted::Release;
        }
        let permit = a.allocate(bytes).map_err(BoundedError::Refused)?;
        let mut items = Vec::new();
        // On failure the permit drops here, releasing what was admitted for
        // the allocation that did not happen.
        items
            .try_reserve_exact(capacity)
            .map_err(|_| BoundedError::Allocation { bytes })?;
        *grown = Owned {
            items,
            capacity,
            permit: Some(permit),
        };
        *admitted = Admitted::Nothing;
        Ok(())
    }

    /// One unit of cleanup: a staged growth's block and allocation released,
    /// then one element drained per admitted unit, then an interrupted
    /// relocation reset to an empty arena in one admitted write; once
    /// nothing is held, the caller's transition admitted and true. Every
    /// release was paid for by its acquisition. Elements must need no
    /// cleanup of their own.
    pub fn reclaim_step<A: Allocator<Permit = P>>(&mut self, a: &mut A) -> BoundedResult<bool, A> {
        let (next, result) = match mem::replace(&mut self.state, Self::EMPTY) {
            // A growth that holds only admissions for its block forfeits
            // them within the arena's own next unit of cleanup: a step that
            // only dropped them would neither admit work nor release an
            // allocation.
            State::Settled {
                arena,
                growth: Growth::Idle,
            } => Self::reclaim_settled(arena, a),
            State::Settled {
                arena,
                growth: Growth::Staging(admitted),
            } => {
                let (mut next, result) = Self::reclaim_settled(arena, a);
                // Forfeiture belongs to the successful cleanup unit. A
                // refused first drain must retain even the admissions for
                // a staging block that has not yet been allocated.
                if result.is_err()
                    && let State::Settled { growth, .. } = &mut next
                {
                    *growth = Growth::Staging(admitted);
                }
                (next, result)
            }
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

    /// One unit of cleanup of a settled arena with no growth staged.
    fn reclaim_settled<A: Allocator<Permit = P>>(
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
            Growth::Idle | Growth::Staging(_) => {}
            // SAFETY: a staged or ready arena is empty: it owns only its
            // allocation and permit, if any.
            Growth::Staged(block, _) | Growth::Ready(block) => unsafe { block.dispose() },
            Growth::Retired(vacated) => vacated.free(),
        }
    }

    /// One part of a transfer of the settled arena into `destination`, one
    /// admitted unit each; while its elements are relocating, one unit of
    /// the relocation instead. True once every part is transferred.
    ///
    /// # Safety
    /// Destination is stable uninitialized Owned storage. Retain part from zero
    /// and do not use this storage except to finish transfer or reclaim it.
    pub(crate) unsafe fn transfer_step<A: Allocator<Permit = P>>(
        &mut self,
        destination: *mut Owned<T, P>,
        part: &mut usize,
        a: &mut A,
    ) -> BoundedResult<bool, A> {
        use core::ptr::addr_of_mut;
        let Some(arena) = self.settle_step(a)? else {
            return Ok(false);
        };
        Self::TRANSFER
            .get(*part)
            .ok_or(BoundedError::PlanMismatch)?
            .admit(a)?;
        // SAFETY: forwarded from the caller; each part is written once.
        unsafe {
            match *part {
                0 => addr_of_mut!((*destination).items).write(mem::take(&mut arena.items)),
                1 => addr_of_mut!((*destination).capacity).write(mem::take(&mut arena.capacity)),
                _ => addr_of_mut!((*destination).permit).write(arena.permit.take()),
            }
        }
        *part += 1;
        Ok(*part == Self::TRANSFER.len())
    }
}

impl<T: Copy, P> Storage<T, P> {
    /// Discard settled plain data beyond `len` in one unit, keeping the
    /// allocation and its reservation; while its elements are relocating,
    /// one unit of the relocation instead. True once truncated.
    pub fn truncate_copy_step<A: Allocator<Permit = P>>(
        &mut self,
        len: usize,
        a: &mut A,
    ) -> BoundedResult<bool, A> {
        let Some(arena) = self.settle_step(a)? else {
            return Ok(false);
        };
        Self::STEP.admit(a)?;
        arena.items.truncate(len);
        Ok(true)
    }

    /// [`Self::reclaim_step`], discarding settled plain data in one unit
    /// instead of one value at a time.
    pub(crate) fn reclaim_copy_step<A: Allocator<Permit = P>>(
        &mut self,
        a: &mut A,
    ) -> BoundedResult<bool, A> {
        if let State::Settled {
            arena,
            growth: Growth::Idle,
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

impl<T, P> Default for Storage<T, P> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T, P> Drop for Storage<T, P> {
    /// The terminal release of storage dropped without stepped cleanup:
    /// every allocation, staged, relocating or settled, freed with its
    /// permit, each a release its acquisition paid for.
    fn drop(&mut self) {
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
#[cfg(all(test, feature = "custom-std-collections"))]
mod tests {
    use super::*;
    use crate::bounded::{Limits, Reservation};

    /// An arena of four `u32`, full, whose growth has relocated `moved`
    /// elements: staged, allocated, published, then `moved` relocation
    /// units.
    fn relocating(moved: usize, a: &mut Limits) -> Storage<u32, Reservation> {
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
            let declared = storage.settle_remaining();
            let mut taken = 0u64;
            for _ in 0..8 {
                if storage.settle_step(&mut a).unwrap().is_some() {
                    break;
                }
                taken += 1;
            }
            assert_eq!(declared, taken, "after {moved} relocated elements");
            assert_eq!(storage.settle_remaining(), 0, "a settled arena");
        }
    }
}
