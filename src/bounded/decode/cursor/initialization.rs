use super::*;
use crate::bounded::decode::construction::reclamation::Slot;
use crate::bounded::decode::initialization::{init_field, init_part};

impl<I: Copy, P> ParserContinuation<I, P> {
    pub(crate) const INIT_STEPS: usize =
        Storage::<Entry, P>::INIT_STEPS + Storage::<Frame, P>::INIT_STEPS + 17;

    /// Initialize one unit of the parser in `slot`, its stable destination
    /// paired with its units initialized: the node arena and the frame
    /// stack, each on its own units, then one scalar field per unit; the
    /// normalizer's slot is left uninitialized, its own count
    /// (`normalizer_init`) zero. A partial prefix owns no resources; its
    /// holder reads it as a parser only once this returns true. Refused once
    /// initialized.
    pub(crate) fn initialize_step<A: Allocator<Permit = P>>(
        mut slot: Slot<'_, Self, usize>,
        input: I,
        options: Options,
        a: &mut A,
    ) -> BoundedResult<bool, A> {
        let entries = Storage::<Entry, P>::INIT_STEPS;
        let stack = Storage::<Frame, P>::INIT_STEPS;
        if *slot.custody() < entries {
            init_part!(slot, entries, 0, |part| Storage::initialize_step(part, a)?);
            return Ok(false);
        }
        if *slot.custody() < entries + stack {
            init_part!(slot, stack, entries, |part| Storage::initialize_step(
                part, a
            )?);
            return Ok(false);
        }
        match *slot.custody() - entries - stack {
            0 => init_field!(slot, input, || input, a)?,
            1 => init_field!(slot, options, || options, a)?,
            2 => init_field!(slot, phase, || Phase::Header, a)?,
            3 => init_field!(slot, header, HeaderState::new, a)?,
            4 => init_field!(slot, parsed, || None, a)?,
            5 => init_field!(slot, start, || 0, a)?,
            6 => init_field!(slot, position, || 0, a)?,
            7 => init_field!(slot, payload_end, || 0, a)?,
            8 => init_field!(slot, kind, || StoredKind::Null, a)?,
            9 => init_field!(slot, children, || 0, a)?,
            10 => init_field!(slot, completed, || 0, a)?,
            11 => init_field!(slot, child_count, || 0, a)?,
            12 => init_field!(slot, utf8, || None, a)?,
            13 => init_field!(slot, normalizer_init, || 0, a)?,
            14 => init_field!(slot, normalized, || None, a)?,
            15 => init_field!(slot, text_compared, || 0, a)?,
            16 => init_field!(slot, comparison, || None, a)?,
            _ => return Err(BoundedError::PlanMismatch),
        }
        let units = slot.custody();
        *units += 1;
        Ok(*units == Self::INIT_STEPS)
    }
}

impl<I, P> Drop for ParserContinuation<I, P> {
    fn drop(&mut self) {
        // Direct parser users retain ordinary RAII semantics. The owner-backed
        // typed path instead drains the parser and releases its record without
        // invoking this destructor. An unfinished initialization owns nothing.
        if self.normalizer_init == TextContinuation::<(), P>::INIT_STEPS {
            unsafe { self.normalizer.assume_init_drop() };
        }
    }
}
