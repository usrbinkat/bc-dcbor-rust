use super::*;
use crate::bounded::decode::construction::reclamation::Slot;
use core::ptr::addr_of_mut;

/// What a record holds of its document arena, the arena's custody: the
/// ownership parts transferred into it from the parser and the parts
/// released, each counted in order. A slot pairs the arena's place with it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct ArenaParts {
    pub(crate) transferred: usize,
    pub(crate) released: usize,
}

impl<I, P> ParserContinuation<I, P> {
    /// Transfer the validated arena into `arena`, its retained destination
    /// paired with its parts, one ownership field per admitted unit. Refused
    /// unless the parser is ready to publish, and once the arena's release
    /// has begun.
    pub(crate) fn publish_arena_step<A: Allocator<Permit = P>>(
        &mut self,
        mut arena: Slot<'_, DocumentArena<P>, ArenaParts>,
        a: &mut A,
    ) -> BoundedResult<bool, A> {
        if !self.ready_to_publish() || arena.custody().released > 0 {
            return Err(BoundedError::PlanMismatch);
        }
        // SAFETY: the arena's one field is its node storage, projected by
        // field syntax, and the parts transferred are exactly that storage's
        // units written.
        let entries = unsafe {
            arena.child(
                |arena| addr_of_mut!((*arena).entries),
                |parts| &mut parts.transferred,
            )
        };
        let done = self.entries.transfer_step(entries, a)?;
        if done {
            self.phase = Phase::Finished;
        }
        Ok(done)
    }

    pub(crate) fn ready_to_publish(&self) -> bool {
        self.phase == Phase::Publish
    }
}

impl<P> DocumentArena<P> {
    /// Releasing the arena's items: one value and the vector's bytes.
    const ITEMS: Unit<Caller> = Unit::of::<Vec<Entry>>(Caller);

    /// Releasing the arena's permit: one value and the slot's bytes.
    const PERMIT: Unit<Caller> = Unit::of::<Option<P>>(Caller);

    /// The work of transferring the arena from its parser
    /// ([`ParserContinuation::publish_arena_step`]): its storage's transfer.
    pub(crate) fn transfer_work<R>() -> Result<WriteWork, BoundedError<R>> {
        Storage::<Entry, P>::transfer_work()
    }

    /// The work of releasing every part ([`Self::release_parts_step`]),
    /// transferred or not: one unit per part.
    pub(crate) fn release_work<R>() -> Result<WriteWork, BoundedError<R>> {
        Self::ITEMS.times(1)?.then(Self::PERMIT.times(1)?)
    }

    /// Release one transferred part of the arena in `arena`, its place
    /// paired with its parts, per admitted unit: the node vector if it was
    /// transferred, then the permit if it was. The caller holds the arena
    /// past every document view of it.
    pub(crate) fn release_parts_step<A: Allocator<Permit = P>>(
        mut arena: Slot<'_, Self, ArenaParts>,
        a: &mut A,
    ) -> BoundedResult<bool, A> {
        let (place, parts) = arena.parts();
        let ArenaParts {
            transferred,
            released,
        } = *parts;
        let raw = place.as_ptr(parts);
        match released {
            0 => {
                Self::ITEMS.admit(a)?;
                if transferred >= 1 {
                    // SAFETY: the parts pair with the arena's place, and a
                    // first part transferred is the node vector written,
                    // reached by field syntax and dropped once: the parts
                    // released advance past it below.
                    unsafe { core::ptr::drop_in_place(addr_of_mut!((*raw).entries.items)) };
                }
            }
            1 => {
                Self::PERMIT.admit(a)?;
                if transferred == 3 {
                    // SAFETY: as above, the third part transferred is the
                    // permit written.
                    unsafe { core::ptr::drop_in_place(addr_of_mut!((*raw).entries.permit)) };
                }
            }
            2 => return Ok(true),
            _ => return Err(BoundedError::PlanMismatch),
        }
        parts.released += 1;
        Ok(parts.released == 2)
    }

    /// The most calls [`Self::release_parts_step`] still takes after
    /// `released` parts, the one returning true included: one per part not
    /// yet released, or one once both are.
    pub(crate) fn release_remaining(released: usize) -> u64 {
        (2u64.saturating_sub(released as u64)).max(1)
    }
}
