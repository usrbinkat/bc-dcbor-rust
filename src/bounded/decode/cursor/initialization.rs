use super::*;
use crate::bounded::decode::initialization::field;
use core::ptr::addr_of_mut;

impl<'a, P> Decoder<'a, P> {
    pub(crate) const INIT_STEPS: usize =
        Storage::<Entry<'a>, P>::INIT_STEPS + Storage::<Frame, P>::INIT_STEPS + 17;

    /// # Safety
    /// The destination is stable, unique and initially uninitialized. The cursor
    /// starts at zero. A partial prefix owns no resources and must not be read as
    /// a Decoder. No parser operation is permitted before this returns true.
    pub(crate) unsafe fn initialize_step<A: Allocator<Permit = P>>(
        place: *mut Self,
        input: &'a [u8],
        options: Options,
        step: &mut usize,
        a: &mut A,
    ) -> BoundedResult<bool, A> {
        let entries = Storage::<Entry<'a>, P>::INIT_STEPS;
        let stack = Storage::<Frame, P>::INIT_STEPS;
        if *step < entries {
            unsafe {
                Storage::initialize_step(addr_of_mut!((*place).entries), step, a)?;
            }
            return Ok(false);
        }
        if *step < entries + stack {
            let mut sub = *step - entries;
            unsafe {
                Storage::initialize_step(addr_of_mut!((*place).stack), &mut sub, a)?;
            }
            *step = entries + sub;
            return Ok(false);
        }
        unsafe {
            match *step - entries - stack {
                0 => field(addr_of_mut!((*place).input), || input, a)?,
                1 => field(addr_of_mut!((*place).options), || options, a)?,
                2 => field(addr_of_mut!((*place).phase), || Phase::Header, a)?,
                3 => field(
                    addr_of_mut!((*place).header),
                    || HeaderCursor::new(input),
                    a,
                )?,
                4 => field(addr_of_mut!((*place).parsed), || None, a)?,
                5 => field(addr_of_mut!((*place).start), || 0, a)?,
                6 => field(addr_of_mut!((*place).position), || 0, a)?,
                7 => field(addr_of_mut!((*place).payload_end), || 0, a)?,
                8 => field(addr_of_mut!((*place).kind), || Kind::Null, a)?,
                9 => field(addr_of_mut!((*place).children), || 0, a)?,
                10 => field(addr_of_mut!((*place).completed), || 0, a)?,
                11 => field(addr_of_mut!((*place).child_count), || 0, a)?,
                12 => field(addr_of_mut!((*place).utf8), || None, a)?,
                13 => field(addr_of_mut!((*place).normalizer_init), || 0, a)?,
                14 => field(addr_of_mut!((*place).normalized), || None, a)?,
                15 => field(addr_of_mut!((*place).text_compared), || 0, a)?,
                16 => field(addr_of_mut!((*place).comparison), || None, a)?,
                _ => return Err(BoundedError::PlanMismatch),
            }
        }
        *step += 1;
        Ok(*step == Self::INIT_STEPS)
    }
}

impl<P> Drop for Decoder<'_, P> {
    fn drop(&mut self) {
        // Direct parser users retain ordinary RAII semantics. The owner-backed
        // typed path instead drains the parser and releases its record without
        // invoking this destructor. An unfinished initialization owns nothing.
        if self.normalizer_init == TextEncoder::<P>::INIT_STEPS {
            unsafe { self.normalizer.assume_init_drop() };
        }
    }
}
