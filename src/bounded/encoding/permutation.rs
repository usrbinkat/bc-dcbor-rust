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
    visited: Storage<u8, P>,
    position: PermutationPosition,
    saved: u8,
}

impl<P> Permutation<P> {
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
                a.traverse(1, 16).map_err(BoundedError::Refused)?;
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
                    if self.visited.ready().is_none() {
                        self.visited.reserve_capped_step(count, a)?;
                        return Ok(false);
                    }
                    if !self.visited.reserve_capped_step(count, a)? {
                        return Ok(false);
                    }
                    let amount = (count - self.visited.len())
                        .min(64)
                        .min(self.visited.spare_ready());
                    a.traverse(1, amount as u64)
                        .map_err(BoundedError::Refused)?;
                    self.visited
                        .extend_reserved(&[0; 64][..amount])
                        .map_err(|_| BoundedError::PlanMismatch)?;
                } else {
                    a.traverse(1, 0).map_err(BoundedError::Refused)?;
                    p.cycle = base;
                    p.phase = PermutationPhase::FindCycle;
                }
            }
            PermutationPhase::FindCycle => {
                let count = (bytes.len() - p.cycle).min(64);
                a.traverse(1, count as u64).map_err(BoundedError::Refused)?;
                let end = p.cycle + count;
                let visited = self.visited.ready().ok_or(BoundedError::PlanMismatch)?;
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
                a.traverse(1, 24).map_err(BoundedError::Refused)?;
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
                a.traverse(1, 4).map_err(BoundedError::Refused)?;
                let value = if p.source == p.cycle {
                    self.saved
                } else {
                    bytes[p.source]
                };
                bytes[p.current] = value;
                let bit = p.current - base;
                self.visited.ready_mut().ok_or(BoundedError::PlanMismatch)?[bit / 8] |=
                    1 << (bit % 8);
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
                self.visited.truncate_copy_step(0, a)?;
                p.phase = PermutationPhase::Release;
            }
            PermutationPhase::Release => {
                if self.visited.release_step(a)? {
                    p.phase = PermutationPhase::Complete;
                }
            }
            PermutationPhase::Complete => {
                a.traverse(1, 16).map_err(BoundedError::Refused)?;
                p.phase = PermutationPhase::Offsets;
                p.entry = 0;
                p.offset = 0;
                return Ok(true);
            }
        }
        Ok(false)
    }
}
