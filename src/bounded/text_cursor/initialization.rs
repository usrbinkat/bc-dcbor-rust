use super::*;
use crate::bounded::decode::construction::reclamation::Slot;
use crate::bounded::decode::initialization::{init_field, init_part};

impl<S: Copy, P, O: Origin> TextContinuation<S, P, O> {
    /// The arena's and the ordering's own steps, then one per scalar field;
    /// the decomposition scratch is one field, its extent checked by
    /// [`field`](crate::bounded::decode::initialization::field).
    pub(crate) const INIT_STEPS: usize =
        Storage::<char, P, O>::INIT_STEPS + ordering::Ordering::<P, O>::INIT_STEPS + 20;

    /// Initialize one unit of the continuation in `slot`, its stable
    /// destination paired with its units initialized: the character arena
    /// and the ordering, each on its own units, then one scalar field per
    /// unit. Initialization acquires no resources, so an incomplete prefix
    /// needs no destruction; a continuation that published its output holds
    /// nothing, so it is initialized again the same way for its next text.
    /// Refused once initialized.
    pub(crate) fn initialize_step<A: Allocator<Permit = P, Origin = O>>(
        mut slot: Slot<'_, Self, usize>,
        source: S,
        a: &mut A,
    ) -> BoundedResult<bool, A> {
        let storage = Storage::<char, P, O>::INIT_STEPS;
        let ordering = ordering::Ordering::<P, O>::INIT_STEPS;
        let units = *slot.custody();
        if Bound::new(Predicate::Prefix, storage).below(a, units) {
            init_part!(slot, chars, 0, a, |chars| Storage::initialize_step(
                chars, a
            )?);
            return Ok(false);
        }
        if Bound::new(Predicate::Prefix, storage + ordering).below(a, units) {
            init_part!(slot, ordering, storage, a, |part| {
                ordering::Ordering::initialize_step(part, a)?
            });
            return Ok(false);
        }
        match *slot.custody() - storage - ordering {
            0 => init_field!(slot, source, || source, a)?,
            1 => init_field!(slot, phase, || Phase::Read, a)?,
            2 => init_field!(slot, source_at, || 0, a)?,
            3 => init_field!(slot, pending, || ['\0'; text::MAX_SCALAR_PARTS], a)?,
            4 => init_field!(slot, pending_len, || 0, a)?,
            5 => init_field!(slot, pending_at, || 0, a)?,
            6 => init_field!(slot, read, || 0, a)?,
            7 => init_field!(slot, written, || 0, a)?,
            8 => init_field!(slot, starter, || None, a)?,
            9 => init_field!(slot, last_class, || 0, a)?,
            10 => init_field!(slot, measure_at, || 0, a)?,
            11 => init_field!(slot, payload_len, || 0, a)?,
            12 => init_field!(slot, header, || [0; MAX_HEAD_LEN], a)?,
            13 => init_field!(slot, header_len, || 0, a)?,
            14 => init_field!(slot, emit_at, || 0, a)?,
            15 => init_field!(slot, bytes, Vec::new, a)?,
            16 => init_field!(slot, permit, || None, a)?,
            // The output acquisition's owner, identity and held release:
            // none until its first entry, which takes the owner.
            17 => init_field!(slot, owner, || None, a)?,
            18 => init_field!(slot, acquisition, || None, a)?,
            19 => init_field!(slot, output_release, || None, a)?,
            _ => return Err(BoundedError::PlanMismatch),
        }
        let units = slot.custody();
        *units += 1;
        Ok(*units == Self::INIT_STEPS)
    }
}
