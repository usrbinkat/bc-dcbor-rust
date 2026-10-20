//! Postorder map preparation with flat storage and no recursive continuations.
use super::*;
use maps::order::{Entry, Order};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum DynamicPhase {
    #[default]
    Order,
    CheckOrder,
    Assemble,
    Clear,
    Complete,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DynamicPosition {
    pub entries: usize,
    pub phase: DynamicPhase,
    pub entry: usize,
    pub byte: usize,
    pub scratch: usize,
    pub compact_source: usize,
    pub compact_destination: usize,
    pub compact_hole: usize,
    pub ordering: maps::OrderPosition,
    pub permutation: PermutationPosition,
}

struct Compact {
    source: usize,
    destination: usize,
    hole: usize,
    end: usize,
}

pub(super) struct Dynamic<P> {
    pub entries: Storage<Entry, P>,
    order: Order<P>,
    permutation: permutation::Permutation<P>,
    compact: Option<Compact>,
    phase: DynamicPhase,
    entry: usize,
    byte: usize,
}

impl<P> Dynamic<P> {
    pub fn new() -> Self {
        Self {
            entries: Storage::new(),
            order: Order::new(),
            permutation: permutation::Permutation::new(),
            compact: None,
            phase: DynamicPhase::Order,
            entry: 0,
            byte: 0,
        }
    }

    pub fn position(&self) -> DynamicPosition {
        DynamicPosition {
            entries: self.entries.len(),
            phase: self.phase,
            entry: self.entry,
            byte: self.byte,
            scratch: self.permutation.position().bitmap_bytes,
            compact_source: self.compact.as_ref().map_or(0, |c| c.source),
            compact_destination: self.compact.as_ref().map_or(0, |c| c.destination),
            compact_hole: self.compact.as_ref().map_or(0, |c| c.hole),
            ordering: self.order.position(),
            permutation: self.permutation.position(),
        }
    }
}

impl<P> Preparation<'_, P> {
    /// Runs only after a child frame has completed. Nested maps have already
    /// removed their descriptors, so the last descriptor belongs to this map.
    pub(super) fn dynamic_step<A: Allocator<Permit = P>>(
        &mut self,
        a: &mut A,
    ) -> BoundedResult<bool, A> {
        let Some(frame) = self.frames.ready().and_then(|frames| frames.last()) else {
            return Ok(false);
        };
        let Some(index) = frame.map else {
            return Ok(false);
        };
        let map = self
            .map_frames
            .ready()
            .and_then(|s| s.get(index))
            .ok_or(BoundedError::PlanMismatch)?;
        let MapState::Dynamic { phase, .. } = &map.state else {
            return Ok(false);
        };
        match phase {
            EntryPhase::Scan => {
                // Reserve before asking the schema for its next bucket. This
                // keeps successful bucket inspection from replaying on refusal.
                if self.dynamic.entries.ready().is_none() {
                    self.dynamic.entries.reserve_step(a)?;
                    return Ok(true);
                }
                Ok(!self.dynamic.entries.reserve_step(a)?)
            }
            EntryPhase::Key(_) | EntryPhase::Value => {
                self.compact_child(a)?;
                Ok(true)
            }
            EntryPhase::Order => {
                self.sort_map(a)?;
                Ok(true)
            }
        }
    }

    fn compact_child<A: Allocator<Permit = P>>(&mut self, a: &mut A) -> BoundedResult<(), A> {
        let frame = self
            .frames
            .ready_mut()
            .and_then(|s| s.last_mut())
            .ok_or(BoundedError::PlanMismatch)?;
        let map = self
            .map_frames
            .ready_mut()
            .and_then(|s| frame.map.and_then(|i| s.get_mut(i)))
            .ok_or(BoundedError::PlanMismatch)?;
        let MapState::Dynamic { phase, .. } = &mut map.state else {
            return Err(BoundedError::PlanMismatch);
        };
        let entry = self
            .dynamic
            .entries
            .ready_mut()
            .and_then(|s| s.last_mut())
            .ok_or(BoundedError::PlanMismatch)?;
        let Some(c) = &mut self.dynamic.compact else {
            a.traverse(1, 32).map_err(BoundedError::Refused)?;
            // Bytes before the first gap are already at their final addresses.
            // With no gaps, completion needs no payload scan at all.
            let start = self
                .holes
                .ready()
                .ok_or(BoundedError::PlanMismatch)?
                .get(map.hole + 1)
                .map_or(self.bytes.len(), |hole| hole.0);
            self.dynamic.compact = Some(Compact {
                source: start,
                destination: start,
                hole: map.hole + 1,
                end: self.bytes.len(),
            });
            return Ok(());
        };
        if c.source < c.end {
            if let Some(&(start, skip)) = self
                .holes
                .ready()
                .ok_or(BoundedError::PlanMismatch)?
                .get(c.hole)
                && start == c.source
            {
                a.traverse(1, 16).map_err(BoundedError::Refused)?;
                c.source += skip;
                c.hole += 1;
                self.omitted = self
                    .omitted
                    .checked_sub(skip)
                    .ok_or(BoundedError::PlanMismatch)?;
            } else {
                let boundary = self
                    .holes
                    .ready()
                    .and_then(|s| s.get(c.hole))
                    .map_or(c.end, |h| h.0);
                let count = (boundary - c.source).min(64);
                a.traverse(1, widen(count)?)
                    .map_err(BoundedError::Refused)?;
                let bytes = self.bytes.ready_mut().ok_or(BoundedError::PlanMismatch)?;
                bytes.copy_within(c.source..c.source + count, c.destination);
                c.source += count;
                c.destination += count;
            }
        } else if self.bytes.len() > c.destination {
            self.bytes.truncate_copy_step(c.destination, a)?;
        } else if self.holes.len() > map.hole + 1 {
            self.holes.truncate_copy_step(map.hole + 1, a)?;
        } else {
            a.traverse(1, 32).map_err(BoundedError::Refused)?;
            if let EntryPhase::Key(value) = phase {
                entry.key_end = self.bytes.len();
                self.child = Some(*value);
                *phase = EntryPhase::Value;
            } else {
                entry.end = self.bytes.len();
                *phase = EntryPhase::Scan;
            }
            self.dynamic.compact = None;
        }
        Ok(())
    }

    fn sort_map<A: Allocator<Permit = P>>(&mut self, a: &mut A) -> BoundedResult<(), A> {
        let root = self.frames.len() == 1;
        let frame = self
            .frames
            .ready()
            .and_then(|s| s.last())
            .ok_or(BoundedError::PlanMismatch)?;
        let map = self
            .map_frames
            .ready()
            .and_then(|s| frame.map.and_then(|i| s.get(i)))
            .ok_or(BoundedError::PlanMismatch)?;
        let MapState::Dynamic { start, .. } = map.state else {
            return Err(BoundedError::PlanMismatch);
        };
        let data_start = self
            .holes
            .ready()
            .and_then(|s| s.get(map.hole))
            .ok_or(BoundedError::PlanMismatch)?
            .0
            + MAX_HEAD_LEN;
        let d = &mut self.dynamic;
        match d.phase {
            DynamicPhase::Order => {
                if d.order.step(
                    &mut d.entries.ready_mut().ok_or(BoundedError::PlanMismatch)?[start..],
                    self.bytes.ready().ok_or(BoundedError::PlanMismatch)?,
                    a,
                )? {
                    if root {
                        // The writer can consume root descriptors directly.
                        // A parent's key comparison cannot observe this payload.
                        self.root_payload = Some(data_start);
                        d.phase = DynamicPhase::Clear;
                    } else {
                        d.phase = DynamicPhase::CheckOrder;
                    }
                    d.entry = start;
                    d.byte = data_start;
                }
            }
            DynamicPhase::CheckOrder => {
                a.traverse(1, 0).map_err(BoundedError::Refused)?;
                if let Some(entry) = d.entries.ready().and_then(|s| s.get(d.entry)) {
                    if entry.start == d.byte {
                        d.byte = entry.end;
                        d.entry += 1;
                    } else {
                        d.phase = DynamicPhase::Assemble;
                        d.entry = start;
                        d.byte = 0;
                    }
                } else {
                    d.phase = DynamicPhase::Clear;
                }
            }
            DynamicPhase::Assemble => {
                if d.permutation.step(
                    &mut d.entries.ready_mut().ok_or(BoundedError::PlanMismatch)?[start..],
                    self.bytes.ready_mut().ok_or(BoundedError::PlanMismatch)?,
                    data_start,
                    a,
                )? {
                    d.phase = DynamicPhase::Clear;
                }
            }
            DynamicPhase::Clear => {
                if self.root_payload.is_none() && d.entries.len() > start {
                    d.entries.truncate_copy_step(start, a)?;
                } else {
                    // Reset only ordering metadata; its flat scratch allocation
                    // is reused by the next completed map, including its parent.
                    d.order.reset(a)?;
                    d.phase = DynamicPhase::Complete;
                }
            }
            DynamicPhase::Complete => {
                a.traverse(1, widen(core::mem::size_of::<Frame<'_>>())?)
                    .map_err(BoundedError::Refused)?;
                self.frames.pop_ready();
                self.map_frames.pop_ready();
                d.phase = DynamicPhase::Order;
                d.entry = 0;
                d.byte = 0;
            }
        }
        Ok(())
    }
}
