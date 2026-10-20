use super::*;
use crate::bounded::decode::initialization::field;
use core::ptr::addr_of_mut;

impl<'a, P> TextEncoder<'a, P> {
    pub(crate) const INIT_STEPS: usize =
        Storage::<char, P>::INIT_STEPS + ordering::Ordering::<P>::INIT_STEPS + 18;

    /// # Safety
    /// Stable unique destination and retained zero-based cursor. Initialization
    /// acquires no resources, so an incomplete prefix needs no destruction.
    pub(crate) unsafe fn initialize_step<A: Allocator<Permit = P>>(
        place: *mut Self,
        source: &'a str,
        step: &mut usize,
        a: &mut A,
    ) -> BoundedResult<bool, A> {
        let storage = Storage::<char, P>::INIT_STEPS;
        let ordering = ordering::Ordering::<P>::INIT_STEPS;
        if *step < storage {
            unsafe {
                Storage::initialize_step(addr_of_mut!((*place).chars), step, a)?;
            }
            return Ok(false);
        }
        if *step < storage + ordering {
            let mut sub = *step - storage;
            unsafe {
                ordering::Ordering::initialize_step(addr_of_mut!((*place).ordering), &mut sub, a)?;
            }
            *step = storage + sub;
            return Ok(false);
        }
        unsafe {
            match *step - storage - ordering {
                0 => field(addr_of_mut!((*place).source), || source, a)?,
                1 => field(addr_of_mut!((*place).phase), || Phase::Read, a)?,
                2 => field(addr_of_mut!((*place).source_at), || 0, a)?,
                3 => field(
                    addr_of_mut!((*place).pending).cast::<[char; 16]>(),
                    || ['\0'; 16],
                    a,
                )?,
                4 => field(
                    addr_of_mut!((*place).pending)
                        .cast::<char>()
                        .add(16)
                        .cast::<[char; 2]>(),
                    || ['\0'; 2],
                    a,
                )?,
                5 => field(addr_of_mut!((*place).pending_len), || 0, a)?,
                6 => field(addr_of_mut!((*place).pending_at), || 0, a)?,
                7 => field(addr_of_mut!((*place).read), || 0, a)?,
                8 => field(addr_of_mut!((*place).written), || 0, a)?,
                9 => field(addr_of_mut!((*place).starter), || None, a)?,
                10 => field(addr_of_mut!((*place).last_class), || 0, a)?,
                11 => field(addr_of_mut!((*place).measure_at), || 0, a)?,
                12 => field(addr_of_mut!((*place).payload_len), || 0, a)?,
                13 => field(addr_of_mut!((*place).header), || [0; MAX_HEAD_LEN], a)?,
                14 => field(addr_of_mut!((*place).header_len), || 0, a)?,
                15 => field(addr_of_mut!((*place).emit_at), || 0, a)?,
                16 => field(addr_of_mut!((*place).bytes), Vec::new, a)?,
                17 => field(addr_of_mut!((*place).permit), || None, a)?,
                _ => return Err(BoundedError::PlanMismatch),
            }
        }
        *step += 1;
        Ok(*step == Self::INIT_STEPS)
    }
}
