//! In-place permutation of variable-sized encoded entries. A visited bitmap
//! replaces a second payload allocation. Each cycle retains its saved byte.
//!
//! The entries partition the original payload. Sorting changes only their
//! order, so their destination intervals also partition the payload. Mapping
//! each destination byte to the same offset in its entry's original interval
//! is therefore a bijection, even when entry lengths differ. A cycle saves its
//! first byte before overwriting any byte and closes using that saved byte.
//! Each destination is written once. Binary lookup costs O(log(entries)) per
//! moved byte; byte movement is linear, but total lookup work is not.
use super::*;
use maps::order::Entry;

#[cfg(test)]
mod tests;

/// Assigning one entry its output offset, or ending the pass: the offset and
/// the running total.
pub(super) const OFFSET: Unit<PreparationPlace> = Unit::new(
    PreparationPlace::Permutation,
    1,
    2 * core::mem::size_of::<usize>() as u64,
);

/// Filling the visited bitmap with zeros: one value and at most a quantum of
/// bytes; one unit of none once it is filled.
pub(super) const FILL: Capped<PreparationPlace> = Capped::new(
    PreparationPlace::Permutation,
    1,
    decode::construction::stable::QUANTUM as u64,
);

/// Scanning the bitmap for the next cycle's start: one value and at most a
/// quantum of bytes.
pub(super) const SCAN: Capped<PreparationPlace> = Capped::new(
    PreparationPlace::Permutation,
    1,
    decode::construction::stable::QUANTUM as u64,
);

/// One probe of a byte's source entry: the entry's start, end and output.
pub(super) const LOOKUP: Unit<PreparationPlace> = Unit::new(
    PreparationPlace::Permutation,
    1,
    3 * core::mem::size_of::<usize>() as u64,
);

/// Moving one byte: the source byte read and the destination written, and
/// its bitmap byte read and written.
pub(super) const MOVE: Unit<PreparationPlace> = Unit::new(PreparationPlace::Permutation, 1, 4);

/// Completing a permutation: its offset and entry reset.
pub(super) const PERMUTED: Unit<PreparationPlace> = Unit::new(
    PreparationPlace::Permutation,
    1,
    2 * core::mem::size_of::<usize>() as u64,
);

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum PermutationPhase {
    #[default]
    Offsets,
    Bitmap,
    FindCycle,
    Lookup,
    Move,
    Clear,
    Release,
    Complete,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PermutationPosition {
    pub phase: PermutationPhase,
    pub entry: usize,
    pub offset: usize,
    pub cycle: usize,
    pub current: usize,
    pub source: usize,
    pub low: usize,
    pub high: usize,
    pub bitmap_bytes: usize,
}

pub(super) struct Permutation<P> {
    pub(super) visited: Storage<u8, P>,
    position: PermutationPosition,
    pub(super) saved: u8,
}

impl<P> Permutation<P> {
    /// Every unit of [`Self::initialize_step`]: the bitmap arena, the nine
    /// position fields, and the saved byte. The position exceeds one admitted
    /// write, so its fields are written separately.
    pub const INIT_STEPS: usize = Storage::<u8, P>::INIT_STEPS + 10;

    /// Initialize one unit of the empty permutation [`Self::new`] builds in
    /// `slot`, its destination paired with its units initialized: the bitmap
    /// arena, then one field per unit. An incomplete prefix owns nothing.
    /// Refused once initialized.
    pub fn initialize_step<A: Allocator<Permit = P>>(
        mut slot: reclamation::Slot<'_, Self, usize>,
        a: &mut A,
    ) -> BoundedResult<bool, A> {
        use decode::initialization::{init_field, init_part};
        let storage = Storage::<u8, P>::INIT_STEPS;
        if *slot.custody() < storage {
            init_part!(slot, visited, 0, |visited| Storage::initialize_step(
                visited, a
            )?);
            return Ok(false);
        }
        match *slot.custody() - storage {
            0 => init_field!(slot, position.phase, PermutationPhase::default, a)?,
            1 => init_field!(slot, position.entry, || 0, a)?,
            2 => init_field!(slot, position.offset, || 0, a)?,
            3 => init_field!(slot, position.cycle, || 0, a)?,
            4 => init_field!(slot, position.current, || 0, a)?,
            5 => init_field!(slot, position.source, || 0, a)?,
            6 => init_field!(slot, position.low, || 0, a)?,
            7 => init_field!(slot, position.high, || 0, a)?,
            8 => init_field!(slot, position.bitmap_bytes, || 0, a)?,
            9 => init_field!(slot, saved, || 0, a)?,
            _ => return Err(BoundedError::PlanMismatch),
        }
        let units = slot.custody();
        *units += 1;
        Ok(*units == Self::INIT_STEPS)
    }

    /// Whether the visited bitmap holds nothing.
    pub fn is_released(&self) -> bool {
        self.visited.is_released()
    }

    /// One admitted unit releasing the visited bitmap; true once released.
    /// The caller supplies the place.
    pub fn reclaim_step<A: Allocator<Permit = P>>(&mut self, a: &mut A) -> BoundedResult<bool, A> {
        self.visited.reclaim_copy_step(a)
    }

    pub fn new() -> Self {
        Self {
            visited: Storage::new(),
            position: PermutationPosition::default(),
            saved: 0,
        }
    }

    pub fn position(&self) -> PermutationPosition {
        PermutationPosition {
            bitmap_bytes: self.visited.len(),
            ..self.position
        }
    }

    /// The visited bitmap, settled; or, while it relocates, one unit of its
    /// relocation as the step's work and `None`.
    fn settled<'s, A: Allocator<Permit = P>>(
        visited: &'s mut Storage<u8, P>,
        a: &mut A,
    ) -> BoundedResult<Option<&'s mut Owned<u8, P>>, A> {
        at(PreparationPlace::Visited, || visited.settle_step(a))
    }

    pub fn step<A: Allocator<Permit = P>>(
        &mut self,
        entries: &mut [Entry],
        bytes: &mut [u8],
        base: usize,
        a: &mut A,
    ) -> BoundedResult<bool, A> {
        let length = bytes
            .len()
            .checked_sub(base)
            .ok_or(BoundedError::PlanMismatch)?;
        let p = &mut self.position;
        match p.phase {
            PermutationPhase::Offsets => {
                OFFSET.admit(a)?;
                if let Some(entry) = entries.get_mut(p.entry) {
                    entry.output = base.checked_add(p.offset).ok_or(BoundedError::Overflow)?;
                    p.offset = p
                        .offset
                        .checked_add(entry.end - entry.start)
                        .ok_or(BoundedError::Overflow)?;
                    p.entry += 1;
                } else {
                    if p.offset != length {
                        return Err(BoundedError::PlanMismatch);
                    }
                    p.phase = PermutationPhase::Bitmap;
                }
            }
            PermutationPhase::Bitmap => {
                let count = length.div_ceil(8);
                if self.visited.len() < count {
                    // Growth and relocation are turns of their own, capped at
                    // the bitmap's bytes; free bytes are zeroed in this one.
                    let visited = &mut self.visited;
                    let Some(spare) =
                        at(PreparationPlace::Visited, || visited.reserve_step(count, a))?
                    else {
                        return Ok(false);
                    };
                    let amount = (count - spare.len())
                        .min(decode::construction::stable::QUANTUM)
                        .min(spare.room());
                    FILL.admit(a, amount as u64)?;
                    spare.extend(&[0; decode::construction::stable::QUANTUM][..amount]);
                } else {
                    FILL.admit(a, 0)?;
                    p.cycle = base;
                    p.phase = PermutationPhase::FindCycle;
                }
            }
            PermutationPhase::FindCycle => {
                let Some(visited) = Self::settled(&mut self.visited, a)? else {
                    return Ok(false);
                };
                let visited = visited.as_slice();
                let count = (bytes.len() - p.cycle).min(decode::construction::stable::QUANTUM);
                SCAN.admit(a, count as u64)?;
                let end = p.cycle + count;
                while p.cycle < end {
                    let bit = p.cycle - base;
                    if visited[bit / 8] & (1 << (bit % 8)) == 0 {
                        self.saved = bytes[p.cycle];
                        p.current = p.cycle;
                        p.low = 0;
                        p.high = entries.len();
                        p.phase = PermutationPhase::Lookup;
                        return Ok(false);
                    }
                    p.cycle += 1;
                }
                if p.cycle == bytes.len() {
                    p.phase = PermutationPhase::Clear;
                }
            }
            PermutationPhase::Lookup => {
                LOOKUP.admit(a)?;
                if p.low == p.high {
                    return Err(BoundedError::PlanMismatch);
                }
                let mid = p.low + (p.high - p.low) / 2;
                let entry = &entries[mid];
                let end = entry.output + (entry.end - entry.start);
                if p.current < entry.output {
                    p.high = mid;
                } else if p.current >= end {
                    p.low = mid + 1;
                } else {
                    p.source = entry.start + (p.current - entry.output);
                    p.phase = PermutationPhase::Move;
                }
            }
            PermutationPhase::Move => {
                let Some(visited) = Self::settled(&mut self.visited, a)? else {
                    return Ok(false);
                };
                MOVE.admit(a)?;
                let value = if p.source == p.cycle {
                    self.saved
                } else {
                    bytes[p.source]
                };
                bytes[p.current] = value;
                let bit = p.current - base;
                visited.as_mut_slice()[bit / 8] |= 1 << (bit % 8);
                if p.source == p.cycle {
                    p.cycle += 1;
                    p.phase = PermutationPhase::FindCycle;
                } else {
                    p.current = p.source;
                    p.low = 0;
                    p.high = entries.len();
                    p.phase = PermutationPhase::Lookup;
                }
            }
            PermutationPhase::Clear => {
                let visited = &mut self.visited;
                if at(PreparationPlace::Permutation, || {
                    visited.truncate_copy_step(0, a)
                })? {
                    p.phase = PermutationPhase::Release;
                }
            }
            PermutationPhase::Release => {
                // The bitmap's releases were paid for by the growths that
                // acquired it; the unit that finds it released admits the
                // transition.
                let visited = &mut self.visited;
                if at(PreparationPlace::Permutation, || {
                    visited.reclaim_copy_step(a)
                })? {
                    p.phase = PermutationPhase::Complete;
                }
            }
            PermutationPhase::Complete => {
                PERMUTED.admit(a)?;
                p.phase = PermutationPhase::Offsets;
                p.entry = 0;
                p.offset = 0;
                return Ok(true);
            }
        }
        Ok(false)
    }
}
