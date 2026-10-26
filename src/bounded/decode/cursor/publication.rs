use super::*;
use core::ptr::addr_of_mut;

impl<I, P> ParserContinuation<I, P> {
    /// Transfer the validated arena into its retained destination one
    /// ownership field per admitted unit. `initialized` counts the parts.
    ///
    /// # Safety
    /// The destination is stable uninitialized arena storage, `initialized`
    /// starts at zero, and the parser is ready to publish.
    pub(crate) unsafe fn publish_arena_step<A: Allocator<Permit = P>>(
        &mut self,
        place: *mut DocumentArena<P>,
        initialized: &mut usize,
        a: &mut A,
    ) -> BoundedResult<bool, A> {
        if !self.ready_to_publish() {
            return Err(BoundedError::PlanMismatch);
        }
        let done = unsafe {
            self.entries
                .transfer_step(addr_of_mut!((*place).entries), initialized, a)?
        };
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

    /// Release one transferred part per admitted unit.
    ///
    /// # Safety
    /// `place` and `initialized` describe the destination of
    /// `publish_arena_step`; `released` starts at zero and is retained. No
    /// document views may remain live.
    pub(crate) unsafe fn release_parts_step<A: Allocator<Permit = P>>(
        place: *mut Self,
        initialized: usize,
        released: &mut usize,
        a: &mut A,
    ) -> BoundedResult<bool, A> {
        match *released {
            0 => {
                Self::ITEMS.admit(a)?;
                if initialized >= 1 {
                    unsafe { core::ptr::drop_in_place(addr_of_mut!((*place).entries.items)) };
                }
            }
            1 => {
                Self::PERMIT.admit(a)?;
                if initialized == 3 {
                    unsafe { core::ptr::drop_in_place(addr_of_mut!((*place).entries.permit)) };
                }
            }
            2 => return Ok(true),
            _ => return Err(BoundedError::PlanMismatch),
        }
        *released += 1;
        Ok(*released == 2)
    }

    /// The most calls [`Self::release_parts_step`] still takes after
    /// `released` parts, the one returning true included: one per part not
    /// yet released, or one once both are.
    pub(crate) fn release_remaining(released: usize) -> u64 {
        (2u64.saturating_sub(released as u64)).max(1)
    }
}
