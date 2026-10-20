use super::*;
use decode::comparison::compare_step;

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
    scratch: Storage<Entry, P>,
    position: OrderPosition,
    middle: usize,
    end: usize,
    forward: bool,
}

impl<P> Order<P> {
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
        a.traverse(1, widen(core::mem::size_of::<OrderPosition>())?)
            .map_err(BoundedError::Refused)?;
        self.position = OrderPosition::default();
        Ok(())
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
                a.traverse(1, 0).map_err(BoundedError::Refused)?;
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
                    if self.scratch.ready().is_none() {
                        self.scratch.reserve_capped_step(count, a)?;
                        return Ok(false);
                    }
                    if !self.scratch.reserve_capped_step(count, a)? {
                        return Ok(false);
                    }
                    a.traverse(1, widen(core::mem::size_of::<Entry>())?)
                        .map_err(BoundedError::Refused)?;
                    self.scratch
                        .push_reserved(entries[start + self.scratch.len()])
                        .map_err(|_| BoundedError::PlanMismatch)?;
                } else {
                    a.traverse(1, 0).map_err(BoundedError::Refused)?;
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
                    a.traverse(1, 0).map_err(BoundedError::Refused)?;
                    p.phase = if scratch_done {
                        OrderPhase::Clear
                    } else if self.forward {
                        OrderPhase::WriteLeft
                    } else {
                        OrderPhase::WriteRight
                    };
                } else {
                    let scratch = self.scratch.ready().ok_or(BoundedError::PlanMismatch)?;
                    let (left, right) = if self.forward {
                        (&scratch[p.left], &entries[p.right])
                    } else {
                        (&entries[p.left - 1], &scratch[p.right - 1])
                    };
                    if let Some(ordering) = compare_step(
                        &bytes[left.start..left.key_end],
                        &bytes[right.start..right.key_end],
                        &mut p.compared,
                        a,
                    )? {
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
                a.traverse(1, widen(core::mem::size_of::<Entry>())?)
                    .map_err(BoundedError::Refused)?;
                let left = p.phase == OrderPhase::WriteLeft;
                let scratch = self.scratch.ready().ok_or(BoundedError::PlanMismatch)?;
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
                self.scratch.truncate_copy_step(0, a)?;
                p.run = self.end;
                p.phase = OrderPhase::Run;
            }
            OrderPhase::Complete => {
                a.traverse(1, 0).map_err(BoundedError::Refused)?;
                return Ok(true);
            }
        }
        Ok(false)
    }
}
