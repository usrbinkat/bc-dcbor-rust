use super::*;
use core::ptr::addr_of_mut;

impl<'a, P> Decoder<'a, P> {
    pub(crate) fn ready_to_publish(&self) -> bool {
        self.phase == Phase::Publish
    }

    /// Transfer a validated document header one field at a time. The input and
    /// arena never move; their ownership metadata moves in separately admitted
    /// units. The caller retains initialized fields for cancellation cleanup.
    ///
    /// # Safety
    /// The destination is stable uninitialized document storage and initialized
    /// starts at zero. This is called only after ready_to_publish returns true.
    pub(crate) unsafe fn publish_step<A: Allocator<Permit = P>>(
        &mut self,
        place: *mut Document<'a, P>,
        initialized: &mut usize,
        a: &mut A,
    ) -> BoundedResult<bool, A> {
        if !self.ready_to_publish() {
            return Err(BoundedError::PlanMismatch);
        }
        if *initialized == 0 {
            unsafe {
                super::super::initialization::field(
                    addr_of_mut!((*place).input),
                    || self.input,
                    a,
                )?;
            }
            *initialized = 1;
            return Ok(false);
        }
        let mut part = *initialized - 1;
        let done = unsafe {
            self.entries
                .transfer_step(addr_of_mut!((*place).entries), &mut part, a)?
        };
        *initialized = part + 1;
        if done {
            self.phase = Phase::Finished;
        }
        Ok(done)
    }
}

impl<P> Document<'_, P> {
    /// # Safety
    /// place and initialized describe the destination of publish_step. released
    /// starts at zero and is retained. No document views may remain live.
    pub(crate) unsafe fn release_parts_step<A: Allocator<Permit = P>>(
        place: *mut Self,
        initialized: usize,
        released: &mut usize,
        a: &mut A,
    ) -> BoundedResult<bool, A> {
        match *released {
            0 => {
                a.traverse(1, core::mem::size_of::<Vec<Entry<'_>>>() as u64)
                    .map_err(BoundedError::Refused)?;
                if initialized >= 2 {
                    // Entries contain only scalar data and borrowed slices;
                    // Vec destruction releases one allocation without children.
                    unsafe {
                        core::ptr::drop_in_place(addr_of_mut!((*place).entries.items));
                    }
                }
            }
            1 => {
                a.traverse(1, core::mem::size_of::<Option<P>>() as u64)
                    .map_err(BoundedError::Refused)?;
                if initialized == 4 {
                    unsafe {
                        core::ptr::drop_in_place(addr_of_mut!((*place).entries.permit));
                    }
                }
            }
            2 => return Ok(true),
            _ => return Err(BoundedError::PlanMismatch),
        }
        *released += 1;
        Ok(*released == 2)
    }
}
