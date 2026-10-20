//! Stable, retained merge ordering within canonical combining sequences.
//! Like unicode-normalization's Decompositions::sort_pending, equal classes
//! retain source order and starters delimit independently sorted sequences.
use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OrderingPosition {
    pub phase: u8,
    pub buffered: usize,
    pub relocated: usize,
    pub start: usize,
    pub end: usize,
    pub width: usize,
    pub left: usize,
    pub consumed_left: usize,
    pub consumed_right: usize,
}

pub(super) struct Ordering<P> {
    scratch: Storage<char, P>,
    phase: u8,
    start: usize,
    end: usize,
    width: usize,
    left: usize,
    mid: usize,
    right: usize,
    a: usize,
    b: usize,
    out: usize,
}

impl<P> Ordering<P> {
    pub(super) const INIT_STEPS: usize = Storage::<char, P>::INIT_STEPS + 10;

    /// # Safety
    /// Stable uninitialized destination; retained step begins at zero. Every
    /// initialized field is resource-free until the complete ordering is used.
    pub(super) unsafe fn initialize_step<A: Allocator<Permit = P>>(
        place: *mut Self,
        step: &mut usize,
        a: &mut A,
    ) -> BoundedResult<bool, A> {
        use crate::bounded::decode::initialization::field;
        use core::ptr::addr_of_mut;
        let storage_steps = Storage::<char, P>::INIT_STEPS;
        if *step < storage_steps {
            unsafe {
                Storage::initialize_step(addr_of_mut!((*place).scratch), step, a)?;
            }
            return Ok(false);
        }
        unsafe {
            match *step - storage_steps {
                0 => field(addr_of_mut!((*place).phase), || 0, a)?,
                1 => field(addr_of_mut!((*place).start), || 0, a)?,
                2 => field(addr_of_mut!((*place).end), || 0, a)?,
                3 => field(addr_of_mut!((*place).width), || 1, a)?,
                4 => field(addr_of_mut!((*place).left), || 0, a)?,
                5 => field(addr_of_mut!((*place).mid), || 0, a)?,
                6 => field(addr_of_mut!((*place).right), || 0, a)?,
                7 => field(addr_of_mut!((*place).a), || 0, a)?,
                8 => field(addr_of_mut!((*place).b), || 0, a)?,
                9 => field(addr_of_mut!((*place).out), || 0, a)?,
                _ => return Err(BoundedError::PlanMismatch),
            }
        }
        *step += 1;
        Ok(*step == Self::INIT_STEPS)
    }

    pub(super) const fn new() -> Self {
        Self {
            scratch: Storage::new(),
            phase: 0,
            start: 0,
            end: 0,
            width: 1,
            left: 0,
            mid: 0,
            right: 0,
            a: 0,
            b: 0,
            out: 0,
        }
    }

    pub(super) fn position(&self) -> usize {
        self.out
    }

    pub(super) fn reclaim_step<A: Allocator<Permit = P>>(
        &mut self,
        allocator: &mut A,
    ) -> BoundedResult<bool, A> {
        if self.scratch.drain_step(allocator)?.is_some() {
            return Ok(false);
        }
        self.scratch.release_transition_step(allocator)
    }

    pub(super) fn state(&self) -> OrderingPosition {
        OrderingPosition {
            phase: self.phase,
            buffered: self.scratch.len(),
            relocated: self.scratch.relocated(),
            start: self.start,
            end: self.end,
            width: self.width,
            left: self.left,
            consumed_left: self.a,
            consumed_right: self.b,
        }
    }

    pub(super) fn step<A: Allocator<Permit = P>>(
        &mut self,
        chars: &mut [char],
        allocator: &mut A,
    ) -> BoundedResult<bool, A> {
        if self.phase == 0 && self.scratch.len() < chars.len() {
            if !self.scratch.reserve_step(allocator)? {
                if self.scratch.relocated() == 0 {
                    self.scratch.reserve_step(allocator)?;
                }
                return Ok(false);
            }
            allocator.traverse(1, 4).map_err(BoundedError::Refused)?;
            self.scratch
                .push_reserved(chars[self.scratch.len()])
                .map_err(|_| BoundedError::PlanMismatch)?;
            return Ok(false);
        }
        allocator.traverse(3, 12).map_err(BoundedError::Refused)?;
        match self.phase {
            0 => {
                self.phase = 1;
            }
            1 => {
                if self.start == chars.len() {
                    return Ok(true);
                }
                if self.end == self.start && canonical_combining_class(chars[self.start]) == 0 {
                    self.start += 1;
                    self.end = self.start;
                } else if self.end < chars.len() && canonical_combining_class(chars[self.end]) != 0
                {
                    self.end += 1;
                } else {
                    self.width = 1;
                    self.left = self.start;
                    self.phase = 2;
                }
            }
            2 => {
                if self.width >= self.end - self.start {
                    self.start = self.end;
                    self.phase = 1;
                } else if self.left == self.end {
                    self.width = self.width.checked_mul(2).ok_or(BoundedError::Overflow)?;
                    self.left = self.start;
                } else {
                    self.mid = self.left + self.width.min(self.end - self.left);
                    self.right = self.mid + self.width.min(self.end - self.mid);
                    self.a = self.left;
                    self.b = self.mid;
                    self.out = self.left;
                    self.phase = 3;
                }
            }
            3 => {
                if self.out == self.right {
                    self.out = self.left;
                    self.phase = 4;
                } else {
                    let take_left = self.b == self.right
                        || (self.a < self.mid
                            && canonical_combining_class(chars[self.a])
                                <= canonical_combining_class(chars[self.b]));
                    let index = if take_left {
                        let index = self.a;
                        self.a += 1;
                        index
                    } else {
                        let index = self.b;
                        self.b += 1;
                        index
                    };
                    self.scratch.ready_mut().ok_or(BoundedError::PlanMismatch)?[self.out] =
                        chars[index];
                    self.out += 1;
                }
            }
            4 => {
                if self.out == self.right {
                    self.left = self.right;
                    self.phase = 2;
                } else {
                    chars[self.out] =
                        self.scratch.ready().ok_or(BoundedError::PlanMismatch)?[self.out];
                    self.out += 1;
                }
            }
            _ => return Err(BoundedError::PlanMismatch),
        }
        Ok(false)
    }
}
