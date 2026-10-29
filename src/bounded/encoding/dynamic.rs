//! Postorder map preparation with flat storage and no recursive continuations.
use super::*;
use maps::order::{Entry, Order};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum DynamicPhase {
    #[default]
    Order,
    /// Entries a cursor yielded in canonical order: each key compared with
    /// the one before it, in place of sorting.
    Verify,
    CheckOrder,
    Assemble,
    Clear,
    Complete,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DynamicPosition {
    /// Descriptor, merge-scratch and permutation-bitmap custody, including
    /// retained growth admissions and relocation stages.
    pub entry_storage: decode::storage::StoragePosition,
    pub merge_storage: decode::storage::StoragePosition,
    pub bitmap_storage: decode::storage::StoragePosition,
    pub merge_middle: usize,
    pub merge_end: usize,
    pub merge_forward: bool,
    pub permutation_saved: u8,
    /// None distinguishes an absent compaction from one starting at zero.
    pub compact_end: Option<usize>,
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

/// Opening or closing one key's or value's compaction: one value and its
/// record's bytes.
pub(super) const COMPACT: Unit<PreparationPlace> =
    Unit::of::<Compact>(PreparationPlace::Compaction);

/// Removing one header gap from a compacted payload: its gap record read.
pub(super) const GAP: Unit<PreparationPlace> =
    Unit::of::<(usize, usize)>(PreparationPlace::Compaction);

/// Moving a run of compacted bytes: one value and at most a quantum.
pub(super) const MOVE: Capped<PreparationPlace> = Capped::new(
    PreparationPlace::Compaction,
    1,
    decode::construction::stable::QUANTUM as u64,
);

/// Checking one entry of a nested map's order, or its end.
pub(super) const CHECK: Unit<PreparationPlace> = Unit::new(PreparationPlace::Check, 1, 0);

/// Popping a completed map's frame.
pub(super) const COMPLETE: Unit<PreparationPlace> =
    Unit::of::<Frame<'static>>(PreparationPlace::Completion);

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
    /// Every unit of [`Self::initialize_step`]: the entry arena, the ordering
    /// and permutation engines, and four scalar fields.
    pub(super) const INIT_STEPS: usize = Storage::<Entry, P>::INIT_STEPS
        + Order::<P>::INIT_STEPS
        + permutation::Permutation::<P>::INIT_STEPS
        + 4;

    /// Initialize one unit of the empty engine [`Self::new`] builds in
    /// `slot`, its destination paired with its units initialized: the entry
    /// arena, the ordering and the permutation, each on its own units, then
    /// one scalar field per unit. An incomplete prefix owns nothing.
    /// Refused once initialized.
    pub(super) fn initialize_step<A: Allocator<Permit = P>>(
        mut slot: reclamation::Slot<'_, Self, usize>,
        a: &mut A,
    ) -> BoundedResult<bool, A> {
        use decode::initialization::{init_field, init_part};
        let storage = Storage::<Entry, P>::INIT_STEPS;
        let order = Order::<P>::INIT_STEPS;
        let permutation = permutation::Permutation::<P>::INIT_STEPS;
        if *slot.custody() < storage {
            init_part!(slot, entries, 0, |entries| Storage::initialize_step(
                entries, a
            )?);
            return Ok(false);
        }
        if *slot.custody() < storage + order {
            init_part!(slot, order, storage, |part| Order::initialize_step(
                part, a
            )?);
            return Ok(false);
        }
        if *slot.custody() < storage + order + permutation {
            init_part!(slot, permutation, storage + order, |part| {
                permutation::Permutation::initialize_step(part, a)?
            });
            return Ok(false);
        }
        match *slot.custody() - storage - order - permutation {
            0 => init_field!(slot, compact, || None, a)?,
            1 => init_field!(slot, phase, || DynamicPhase::Order, a)?,
            2 => init_field!(slot, entry, || 0, a)?,
            3 => init_field!(slot, byte, || 0, a)?,
            _ => return Err(BoundedError::PlanMismatch),
        }
        let units = slot.custody();
        *units += 1;
        Ok(*units == Self::INIT_STEPS)
    }

    /// Whether the entry descriptors and both scratch arenas hold nothing.
    pub(super) fn is_released(&self) -> bool {
        self.entries.is_released() && self.order.is_released() && self.permutation.is_released()
    }

    /// One admitted unit releasing the entry descriptors, then the ordering
    /// and permutation scratch. Called only while [`Self::is_released`] is
    /// false.
    pub(super) fn reclaim_step<A: Allocator<Permit = P>>(
        &mut self,
        a: &mut A,
    ) -> BoundedResult<(), A> {
        let cleanup = PreparationPlace::Cleanup;
        if !self.entries.is_released() {
            at(cleanup, || self.entries.reclaim_copy_step(a))?;
        } else if !self.order.is_released() {
            at(cleanup, || self.order.reclaim_step(a))?;
        } else {
            at(cleanup, || self.permutation.reclaim_step(a))?;
        }
        Ok(())
    }

    /// The most calls [`Self::reclaim_step`] still takes until
    /// [`Self::is_released`]: each arena not yet released, its own count.
    pub(super) fn reclaim_remaining(&self) -> u64 {
        self.entries
            .unreleased_remaining()
            .saturating_add(self.order.scratch.unreleased_remaining())
            .saturating_add(self.permutation.visited.unreleased_remaining())
    }

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
            entry_storage: self.entries.position(),
            merge_storage: self.order.scratch.position(),
            bitmap_storage: self.permutation.visited.position(),
            merge_middle: self.order.middle,
            merge_end: self.order.end,
            merge_forward: self.order.forward,
            permutation_saved: self.permutation.saved,
            compact_end: self.compact.as_ref().map(|compact| compact.end),
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
    /// One unit of the top unordered map's own work, once a child frame has
    /// completed: a key or value compacted, or the map sorted, checked,
    /// permuted and completed. True when the step did work, a unit of an
    /// arena's relocation included; false when the top frame has no
    /// unordered map past its scan. Nested maps have already removed their
    /// descriptors, so the last descriptor belongs to this map.
    pub(super) fn dynamic_step<A: Allocator<Permit = P>>(
        &mut self,
        a: &mut A,
    ) -> BoundedResult<bool, A> {
        let frames = &mut self.frames;
        let Some(frames) = at(PreparationPlace::Frames, || frames.settle_step(a))? else {
            return Ok(true);
        };
        let Some(index) = frames.as_slice().last().and_then(|frame| frame.map) else {
            return Ok(false);
        };
        let maps = &mut self.map_frames;
        let Some(maps) = at(PreparationPlace::OpenMaps, || maps.settle_step(a))? else {
            return Ok(true);
        };
        let map = maps
            .as_slice()
            .get(index)
            .ok_or(BoundedError::PlanMismatch)?;
        let MapState::Dynamic { phase, .. } = map.state else {
            return Ok(false);
        };
        match phase {
            // The next entry's slot is reserved with the instruction that
            // draws it ([`Preparation::advance`]).
            EntryPhase::Scan => Ok(false),
            EntryPhase::Key | EntryPhase::Value => {
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
        let frames = &mut self.frames;
        let Some(frames) = at(PreparationPlace::Frames, || frames.settle_step(a))? else {
            return Ok(());
        };
        let maps = &mut self.map_frames;
        let Some(maps) = at(PreparationPlace::OpenMaps, || maps.settle_step(a))? else {
            return Ok(());
        };
        let entries = &mut self.dynamic.entries;
        let Some(entries) = at(PreparationPlace::EntryArena, || entries.settle_step(a))? else {
            return Ok(());
        };
        let holes = &mut self.holes;
        let Some(holes) = at(PreparationPlace::Gaps, || holes.settle_step(a))? else {
            return Ok(());
        };
        let bytes = &mut self.bytes;
        let Some(bytes) = at(PreparationPlace::PlanBytes, || bytes.settle_step(a))? else {
            return Ok(());
        };
        let map = frames
            .as_slice()
            .last()
            .and_then(|frame| frame.map)
            .and_then(|index| maps.as_mut_slice().get_mut(index))
            .ok_or(BoundedError::PlanMismatch)?;
        let holes_start = map.holes_start;
        let MapState::Dynamic { phase, value, .. } = &mut map.state else {
            return Err(BoundedError::PlanMismatch);
        };
        let entry = entries
            .as_mut_slice()
            .last_mut()
            .ok_or(BoundedError::PlanMismatch)?;
        let Some(c) = &mut self.dynamic.compact else {
            COMPACT.admit(a)?;
            // Bytes before the first gap are already at their final addresses.
            // With no gaps, completion needs no payload scan at all.
            let start = holes
                .as_slice()
                .get(holes_start)
                .map_or(bytes.len(), |hole| hole.0);
            self.dynamic.compact = Some(Compact {
                source: start,
                destination: start,
                hole: holes_start,
                end: bytes.len(),
            });
            return Ok(());
        };
        if c.source < c.end {
            if let Some(&(start, skip)) = holes.as_slice().get(c.hole)
                && start == c.source
            {
                GAP.admit(a)?;
                c.source += skip;
                c.hole += 1;
                self.omitted = self
                    .omitted
                    .checked_sub(skip)
                    .ok_or(BoundedError::PlanMismatch)?;
            } else {
                let boundary = holes.as_slice().get(c.hole).map_or(c.end, |h| h.0);
                let count = (boundary - c.source).min(decode::construction::stable::QUANTUM);
                MOVE.admit(a, widen(count)?)?;
                bytes
                    .as_mut_slice()
                    .copy_within(c.source..c.source + count, c.destination);
                c.source += count;
                c.destination += count;
            }
        } else if bytes.len() > c.destination {
            let destination = c.destination;
            let bytes = &mut self.bytes;
            at(PreparationPlace::Compaction, || {
                bytes.truncate_copy_step(destination, a)
            })?;
        } else if holes.len() > holes_start {
            let holes = &mut self.holes;
            at(PreparationPlace::Compaction, || {
                holes.truncate_copy_step(holes_start, a)
            })?;
        } else {
            COMPACT.admit(a)?;
            if *phase == EntryPhase::Key {
                // The key is compacted: its value, held since the entry was
                // drawn, is the next child.
                let pending = value.take().ok_or(BoundedError::PlanMismatch)?;
                entry.key_end = bytes.len();
                self.child = Some(pending);
                *phase = EntryPhase::Value;
            } else {
                entry.end = bytes.len();
                *phase = EntryPhase::Scan;
            }
            self.dynamic.compact = None;
        }
        Ok(())
    }

    fn sort_map<A: Allocator<Permit = P>>(&mut self, a: &mut A) -> BoundedResult<(), A> {
        let frames = &mut self.frames;
        let Some(frames) = at(PreparationPlace::Frames, || frames.settle_step(a))? else {
            return Ok(());
        };
        let maps = &mut self.map_frames;
        let Some(maps) = at(PreparationPlace::OpenMaps, || maps.settle_step(a))? else {
            return Ok(());
        };
        let entries = &mut self.dynamic.entries;
        let Some(entries) = at(PreparationPlace::EntryArena, || entries.settle_step(a))? else {
            return Ok(());
        };
        let bytes = &mut self.bytes;
        let Some(bytes) = at(PreparationPlace::PlanBytes, || bytes.settle_step(a))? else {
            return Ok(());
        };
        let map = frames
            .as_slice()
            .last()
            .and_then(|frame| frame.map)
            .and_then(|index| maps.as_slice().get(index))
            .ok_or(BoundedError::PlanMismatch)?;
        let MapState::Dynamic { start, ordered, .. } = map.state else {
            return Err(BoundedError::PlanMismatch);
        };
        let data_start = map.data_start;
        // Each field the sort reads or advances, borrowed apart from the
        // entry arena held above.
        let order = &mut self.dynamic.order;
        let permutation = &mut self.dynamic.permutation;
        let phase = &mut self.dynamic.phase;
        let at_entry = &mut self.dynamic.entry;
        let byte = &mut self.dynamic.byte;
        match *phase {
            // A cursor yielding canonical order needs no sort: each key is
            // checked against the one before it.
            DynamicPhase::Order if ordered => {
                CHECK.admit(a)?;
                *phase = DynamicPhase::Verify;
                *at_entry = start + 1;
                *byte = 0;
            }
            DynamicPhase::Order => {
                if order.step(&mut entries.as_mut_slice()[start..], bytes.as_slice(), a)? {
                    // Every map, the root's included, is put in order in its
                    // own bytes: the plan is its encoding, gaps aside.
                    *phase = DynamicPhase::CheckOrder;
                    *at_entry = start;
                    *byte = data_start;
                }
            }
            DynamicPhase::Verify => {
                let entries = entries.as_slice();
                match (entries.get(*at_entry - 1), entries.get(*at_entry)) {
                    (Some(previous), Some(entry)) => {
                        let bytes = bytes.as_slice();
                        let (previous, entry) = (
                            &bytes[previous.start..previous.key_end],
                            &bytes[entry.start..entry.key_end],
                        );
                        if let Some(ordering) = at(PreparationPlace::Comparisons, || {
                            decode::comparison::compare_step(previous, entry, byte, a)
                        })? {
                            match ordering {
                                cmp::Ordering::Less => {
                                    *at_entry += 1;
                                    *byte = 0;
                                }
                                cmp::Ordering::Equal => return Err(BoundedError::DuplicateKey),
                                // A cursor claiming canonical order yielded
                                // keys out of it.
                                cmp::Ordering::Greater => return Err(BoundedError::PlanMismatch),
                            }
                        }
                    }
                    _ => {
                        CHECK.admit(a)?;
                        *phase = DynamicPhase::Clear;
                    }
                }
            }
            DynamicPhase::CheckOrder => {
                CHECK.admit(a)?;
                if let Some(entry) = entries.as_slice().get(*at_entry) {
                    if entry.start == *byte {
                        *byte = entry.end;
                        *at_entry += 1;
                    } else {
                        *phase = DynamicPhase::Assemble;
                        *at_entry = start;
                        *byte = 0;
                    }
                } else {
                    *phase = DynamicPhase::Clear;
                }
            }
            DynamicPhase::Assemble => {
                if permutation.step(
                    &mut entries.as_mut_slice()[start..],
                    bytes.as_mut_slice(),
                    data_start,
                    a,
                )? {
                    *phase = DynamicPhase::Clear;
                }
            }
            DynamicPhase::Clear => {
                if entries.len() > start {
                    // Truncating plain descriptors is one unit; the entry
                    // arena is settled, so it truncates in this one.
                    let entries = &mut self.dynamic.entries;
                    at(PreparationPlace::Completion, || {
                        entries.truncate_copy_step(start, a)
                    })?;
                } else {
                    // Reset only ordering metadata; its flat scratch allocation
                    // is reused by the next completed map, including its parent.
                    order.reset(a)?;
                    *phase = DynamicPhase::Complete;
                }
            }
            DynamicPhase::Complete => {
                COMPLETE.admit(a)?;
                frames.pop();
                maps.pop();
                *phase = DynamicPhase::Order;
                *at_entry = 0;
                *byte = 0;
            }
        }
        Ok(())
    }
}
