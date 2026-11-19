use super::*;
use crate::bounded::boundary::{Bound, Predicate};
use crate::bounded::decode::construction::reclamation::Slot;
use crate::bounded::decode::initialization::{init_field, init_part};

impl<I: Copy, P, O: Origin> ParserContinuation<I, P, O> {
    pub(crate) const INIT_STEPS: usize =
        Storage::<Entry, P, O>::INIT_STEPS + Storage::<Frame, P, O>::INIT_STEPS + 17;

    /// Initialize one unit of the parser in `slot`, its stable destination
    /// paired with its units initialized: the node arena and the frame
    /// stack, each on its own units, then one scalar field per unit; the
    /// normalizer's slot is left uninitialized, its own count
    /// (`normalizer_init`) zero. A partial prefix owns no resources; its
    /// holder reads it as a parser only once this returns true. Refused once
    /// initialized.
    pub(crate) fn initialize_step<A: Allocator<Permit = P, Origin = O>>(
        mut slot: Slot<'_, Self, usize>,
        input: I,
        options: Options,
        a: &mut A,
    ) -> BoundedResult<bool, A> {
        let entries = Storage::<Entry, P, O>::INIT_STEPS;
        let stack = Storage::<Frame, P, O>::INIT_STEPS;
        if Bound::new(Predicate::Prefix, entries).below(a, *slot.custody()) {
            init_part!(slot, entries, 0, a, |part| Storage::initialize_step(
                part, a
            )?);
            return Ok(false);
        }
        if Bound::new(Predicate::Prefix, entries + stack).below(a, *slot.custody()) {
            init_part!(slot, stack, entries, a, |part| Storage::initialize_step(
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

impl<I, P, O: Origin> Drop for ParserContinuation<I, P, O> {
    fn drop(&mut self) {
        // Direct parser users retain ordinary RAII semantics. The owner-backed
        // path (`construction/parse.rs`, `Parsed`) drains the parser first and
        // then drops it in place, so this destructor and its arenas' run
        // with nothing left to free: what they still release is each arena
        // pending's owner, its session reference. An unfinished
        // initialization owns nothing.
        if self.normalizer_init == TextContinuation::<(), P, O>::INIT_STEPS {
            unsafe { self.normalizer.assume_init_drop() };
        }
    }
}
