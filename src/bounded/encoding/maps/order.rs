use super::*;
use decode::comparison::compare_step;
use decode::initialization::{init_field, init_part};

/// One step of a merge: a run begun or passed, a phase changed, the merge
/// finished.
pub(in crate::bounded::encoding) const MERGE_STEP: Unit<PreparationPlace> =
    Unit::new(PreparationPlace::Merging, 1, 0);

/// One entry moved: copied into the scratch, or written back.
pub(in crate::bounded::encoding) const MERGE_MOVE: Unit<PreparationPlace> =
    Unit::of::<Entry>(PreparationPlace::Merging);

/// Resetting the ordering for the next map: its position rewritten.
pub(in crate::bounded::encoding) const RESET: Unit<PreparationPlace> =
    Unit::of::<OrderPosition>(PreparationPlace::Completion);

#[derive(Clone, Copy, Debug, Default)]
pub(in crate::bounded::encoding) struct Entry {
    pub start: usize,
    pub key_end: usize,
    pub end: usize,
    pub output: usize,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum OrderPhase {
    #[default]
    Run,
    Copy,
    Compare,
    WriteLeft,
    WriteRight,
    Clear,
    Complete,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OrderPosition {
    pub phase: OrderPhase,
    pub width: usize,
    pub run: usize,
    pub left: usize,
    pub right: usize,
    pub output: usize,
    pub compared: usize,
    pub scratch: usize,
}

pub(in crate::bounded::encoding) struct Order<P> {
    pub(in crate::bounded::encoding) scratch: Storage<Entry, P>,
    position: OrderPosition,
    pub(in crate::bounded::encoding) middle: usize,
    pub(in crate::bounded::encoding) end: usize,
    pub(in crate::bounded::encoding) forward: bool,
}

impl<P> Order<P> {
    /// Every unit of [`Self::initialize_step`]: the scratch arena and four
    /// scalar fields.
    pub const INIT_STEPS: usize = Storage::<Entry, P>::INIT_STEPS + 4;

    /// Initialize one unit of the empty ordering [`Self::new`] builds in
    /// `slot`, its destination paired with its units initialized: the
    /// scratch arena, then one scalar field per unit. An incomplete prefix
    /// owns nothing. Refused once initialized.
    pub fn initialize_step<A: Allocator<Permit = P>>(
        mut slot: decode::construction::reclamation::Slot<'_, Self, usize>,
        a: &mut A,
    ) -> BoundedResult<bool, A> {
        let storage = Storage::<Entry, P>::INIT_STEPS;
        if *slot.custody() < storage {
            init_part!(slot, scratch, 0, |scratch| Storage::initialize_step(
                scratch, a
            )?);
            return Ok(false);
        }
        match *slot.custody() - storage {
            0 => init_field!(slot, position, OrderPosition::default, a)?,
            1 => init_field!(slot, middle, || 0, a)?,
            2 => init_field!(slot, end, || 0, a)?,
            3 => init_field!(slot, forward, || true, a)?,
            _ => return Err(BoundedError::PlanMismatch),
        }
        let units = slot.custody();
        *units += 1;
        Ok(*units == Self::INIT_STEPS)
    }

    /// Whether the merge scratch holds nothing.
    pub fn is_released(&self) -> bool {
        self.scratch.is_released()
    }

    /// One admitted unit releasing the merge scratch; true once released.
    /// The caller supplies the place.
    pub fn reclaim_step<A: Allocator<Permit = P>>(&mut self, a: &mut A) -> BoundedResult<bool, A> {
        self.scratch.reclaim_copy_step(a)
    }

    pub fn new() -> Self {
        Self {
            scratch: Storage::new(),
            position: OrderPosition::default(),
            middle: 0,
            end: 0,
            forward: true,
        }
    }

    pub fn position(&self) -> OrderPosition {
        OrderPosition {
            scratch: self.scratch.len(),
            ..self.position
        }
    }

    pub fn reset<A: Allocator<Permit = P>>(&mut self, a: &mut A) -> BoundedResult<(), A> {
        RESET.admit(a)?;
        self.position = OrderPosition::default();
        Ok(())
    }

    /// The merge scratch, settled; or, while it relocates, one unit of its
    /// relocation as the step's work and `None`.
    fn settled<'s, A: Allocator<Permit = P>>(
        scratch: &'s mut Storage<Entry, P>,
        a: &mut A,
    ) -> BoundedResult<Option<&'s mut Owned<Entry, P>>, A> {
        at(PreparationPlace::Scratch, || scratch.settle_step(a))
    }

    pub fn step<A: Allocator<Permit = P>>(
        &mut self,
        entries: &mut [Entry],
        bytes: &[u8],
        a: &mut A,
    ) -> BoundedResult<bool, A> {
        let p = &mut self.position;
        match p.phase {
            OrderPhase::Run => {
                MERGE_STEP.admit(a)?;
                p.width = p.width.max(1);
                if p.width >= entries.len() {
                    p.phase = OrderPhase::Complete;
                } else if p.run == entries.len() {
                    p.width = p.width.checked_mul(2).ok_or(BoundedError::Overflow)?;
                    p.run = 0;
                } else {
                    self.middle = p.run + p.width.min(entries.len() - p.run);
                    self.end = self.middle + p.width.min(entries.len() - self.middle);
                    if self.middle == self.end {
                        p.run = self.end;
                        return Ok(false);
                    }
                    self.forward = self.middle - p.run <= self.end - self.middle;
                    p.phase = OrderPhase::Copy;
                }
            }
            OrderPhase::Copy => {
                let (start, count) = if self.forward {
                    (p.run, self.middle - p.run)
                } else {
                    (self.middle, self.end - self.middle)
                };
                if self.scratch.len() < count {
                    // Scratch is retained across runs and maps. Grow
                    // geometrically rather than capping at this run's length:
                    // successive short caps would introduce extra growths
                    // beyond the retained arena's doubling bound.
                    let scratch = &mut self.scratch;
                    let Some(spare) = at(PreparationPlace::Scratch, || {
                        scratch.reserve_step(usize::MAX, a)
                    })?
                    else {
                        return Ok(false);
                    };
                    MERGE_MOVE.admit(a)?;
                    let copied = spare.len();
                    spare.push(entries[start + copied]);
                } else {
                    MERGE_STEP.admit(a)?;
                    (p.left, p.right, p.output) = if self.forward {
                        (0, self.middle, p.run)
                    } else {
                        (self.middle, count, self.end)
                    };
                    p.compared = 0;
                    p.phase = OrderPhase::Compare;
                }
            }
            OrderPhase::Compare => {
                let scratch_done = if self.forward {
                    p.left == self.scratch.len()
                } else {
                    p.right == 0
                };
                let other_done = if self.forward {
                    p.right == self.end
                } else {
                    p.left == p.run
                };
                if scratch_done || other_done {
                    MERGE_STEP.admit(a)?;
                    p.phase = if scratch_done {
                        OrderPhase::Clear
                    } else if self.forward {
                        OrderPhase::WriteLeft
                    } else {
                        OrderPhase::WriteRight
                    };
                } else {
                    let Some(scratch) = Self::settled(&mut self.scratch, a)? else {
                        return Ok(false);
                    };
                    let scratch = scratch.as_slice();
                    let (left, right) = if self.forward {
                        (&scratch[p.left], &entries[p.right])
                    } else {
                        (&entries[p.left - 1], &scratch[p.right - 1])
                    };
                    if let Some(ordering) = at(PreparationPlace::Comparisons, || {
                        compare_step(
                            &bytes[left.start..left.key_end],
                            &bytes[right.start..right.key_end],
                            &mut p.compared,
                            a,
                        )
                    })? {
                        if ordering == cmp::Ordering::Equal {
                            return Err(BoundedError::DuplicateKey);
                        }
                        let left = if self.forward {
                            ordering == cmp::Ordering::Less
                        } else {
                            ordering == cmp::Ordering::Greater
                        };
                        p.phase = if left {
                            OrderPhase::WriteLeft
                        } else {
                            OrderPhase::WriteRight
                        };
                    }
                }
            }
            OrderPhase::WriteLeft | OrderPhase::WriteRight => {
                let Some(scratch) = Self::settled(&mut self.scratch, a)? else {
                    return Ok(false);
                };
                let scratch = scratch.as_slice();
                MERGE_MOVE.admit(a)?;
                let left = p.phase == OrderPhase::WriteLeft;
                if self.forward {
                    entries[p.output] = if left {
                        scratch[p.left]
                    } else {
                        entries[p.right]
                    };
                    if left {
                        p.left += 1;
                    } else {
                        p.right += 1;
                    }
                    p.output += 1;
                } else {
                    p.output -= 1;
                    if left {
                        p.left -= 1;
                        entries[p.output] = entries[p.left];
                    } else {
                        p.right -= 1;
                        entries[p.output] = scratch[p.right];
                    }
                }
                p.compared = 0;
                p.phase = OrderPhase::Compare;
            }
            OrderPhase::Clear => {
                let scratch = &mut self.scratch;
                if at(PreparationPlace::Merging, || {
                    scratch.truncate_copy_step(0, a)
                })? {
                    p.run = self.end;
                    p.phase = OrderPhase::Run;
                }
            }
            OrderPhase::Complete => {
                MERGE_STEP.admit(a)?;
                return Ok(true);
            }
        }
        Ok(false)
    }
}
