//! Stable, retained radix ordering within canonical combining sequences.
//! Like unicode-normalization's Decompositions::sort_pending, equal classes
//! retain source order and starters delimit independently sorted sequences.
//!
//! A run of combining parts is ordered by its canonical combining classes,
//! eight bits each, in two stable counting passes over their low and then
//! their high four bits (least significant digit first). Sixteen counters of
//! `u32` fill exactly one quantum ([`TABLE`]): the table is cleared, summed
//! and held in one admitted unit each, and retained across turns as one
//! field. One pass over the whole eight-bit class would need 256 counters,
//! a kilobyte, sixteen quanta to clear and to sum for every run. So a run
//! of `r` parts costs two passes of a clear, `r` counts, a prefix sum, `r`
//! stable scatters into the scratch and `r` copies back: `4` table units and
//! `6r` part units, linear in the run whatever its length.
use super::*;
use crate::bounded::decode::storage::StoragePosition;

/// Copying one character into the scratch the passes scatter into.
pub(super) const COPY: Unit<TextPlace> = Unit::of::<char>(TextPlace::Copying);

/// Finding the runs: one character examined, a run's end decided, or the
/// ordering begun or ended.
pub(super) const FIND: Unit<TextPlace> = Unit::of::<char>(TextPlace::Ordering);

/// One part of a pass: counted (its character read and its counter
/// raised), scattered (read, its counter read and raised, written into the
/// scratch) or copied back (read and written): at most three values and
/// three of their four-byte words.
pub(super) const MARK: Unit<TextPlace> = Unit::new(
    TextPlace::Ordering,
    3,
    3 * core::mem::size_of::<char>() as u64,
);

/// The counter table cleared, or summed into its offsets: one value and its
/// sixteen counters' bytes, one quantum.
pub(super) const TABLE: Unit<TextPlace> = {
    // Sixteen counters of a four-bit digit fill the quantum exactly: the
    // widest table one unit writes.
    assert!(
        core::mem::size_of::<[u32; DIGITS]>()
            == crate::bounded::decode::construction::stable::QUANTUM,
        "the counter table is one quantum"
    );
    Unit::written::<[u32; DIGITS]>(TextPlace::Ordering)
};

/// The values of one digit: four bits of a combining class.
const DIGITS: usize = 16;

/// Where the ordering is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum OrderingPhase {
    /// Copying the characters into the scratch.
    Copy,
    /// Finding the next run of two or more combining parts.
    Find,
    /// Clearing the counters for a pass.
    Clear,
    /// Counting each part's digit.
    Count,
    /// Summing the counters into each digit's first offset.
    Prefix,
    /// Placing each part at its digit's next offset in the scratch.
    Scatter,
    /// Copying the ordered run back.
    Back,
}

/// The ordering's progress and custody, projected from its authoritative
/// continuation without allocating or advancing it. The scratch stage retains
/// acquisition and relocation distinctions; the counters fix future scatters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct OrderingPosition {
    pub scratch: StoragePosition,
    pub counts: [u32; DIGITS],
    pub phase: OrderingPhase,
    pub buffered: usize,
    pub relocated: usize,
    /// The run being ordered, or the next run's start while finding.
    pub start: usize,
    pub end: usize,
    /// The pass over the run: zero for the low four bits, one for the high.
    pub pass: u8,
    /// The part the current phase reaches next.
    pub at: usize,
}

pub(super) struct Ordering<P> {
    scratch: Storage<char, P>,
    phase: OrderingPhase,
    start: usize,
    end: usize,
    pass: u8,
    at: usize,
    counts: [u32; DIGITS],
}

impl<P> Ordering<P> {
    pub(super) const INIT_STEPS: usize = Storage::<char, P>::INIT_STEPS + 6;

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
                0 => field(addr_of_mut!((*place).phase), || OrderingPhase::Copy, a)?,
                1 => field(addr_of_mut!((*place).start), || 0, a)?,
                2 => field(addr_of_mut!((*place).end), || 0, a)?,
                3 => field(addr_of_mut!((*place).pass), || 0, a)?,
                4 => field(addr_of_mut!((*place).at), || 0, a)?,
                5 => field(addr_of_mut!((*place).counts), || [0; DIGITS], a)?,
                _ => return Err(BoundedError::PlanMismatch),
            }
        }
        *step += 1;
        Ok(*step == Self::INIT_STEPS)
    }

    pub(super) const fn new() -> Self {
        Self {
            scratch: Storage::new(),
            phase: OrderingPhase::Copy,
            start: 0,
            end: 0,
            pass: 0,
            at: 0,
            counts: [0; DIGITS],
        }
    }

    pub(super) fn position(&self) -> usize {
        self.at
    }

    pub(super) fn reclaim_step<A: Allocator<Permit = P>>(
        &mut self,
        allocator: &mut A,
    ) -> BoundedResult<bool, A> {
        self.scratch.reclaim_step(allocator)
    }

    /// The most calls [`Self::reclaim_step`] still takes, the one reporting
    /// the scratch released included: its storage's own count.
    pub(super) fn reclaim_remaining(&self) -> u64 {
        self.scratch.reclaim_remaining()
    }

    pub(super) fn state(&self) -> OrderingPosition {
        OrderingPosition {
            scratch: self.scratch.position(),
            counts: self.counts,
            phase: self.phase,
            buffered: self.scratch.len(),
            relocated: self.scratch.relocated(),
            start: self.start,
            end: self.end,
            pass: self.pass,
            at: self.at,
        }
    }

    /// The digit of `ch` pass `pass` orders by.
    fn digit(pass: u8, ch: char) -> usize {
        let class = canonical_combining_class(ch);
        usize::from(if pass == 0 { class & 0xf } else { class >> 4 })
    }

    /// One admitted unit of ordering: true once every run is ordered. Each
    /// step admits its one unit before it changes anything.
    pub(super) fn step<A: Allocator<Permit = P>>(
        &mut self,
        chars: &mut [char],
        allocator: &mut A,
    ) -> BoundedResult<bool, A> {
        if self.phase == OrderingPhase::Copy && self.scratch.len() < chars.len() {
            let scratch = &mut self.scratch;
            // A growth unit of the scratch, or a free slot for the next
            // character.
            if let Some(spare) = at(TextPlace::Copying, || {
                scratch.reserve_step(usize::MAX, allocator)
            })? {
                COPY.admit(allocator)?;
                let next = chars[spare.len()];
                spare.push(next);
            }
            return Ok(false);
        }
        match self.phase {
            OrderingPhase::Copy => {
                FIND.admit(allocator)?;
                self.phase = OrderingPhase::Find;
            }
            OrderingPhase::Find => {
                FIND.admit(allocator)?;
                if self.start == chars.len() {
                    return Ok(true);
                }
                if self.end == self.start && canonical_combining_class(chars[self.start]) == 0 {
                    self.start += 1;
                    self.end = self.start;
                } else if self.end < chars.len() && canonical_combining_class(chars[self.end]) != 0
                {
                    self.end += 1;
                } else if self.end - self.start < 2 {
                    // A run of one part is in order.
                    self.start = self.end;
                } else {
                    // Each counter counts at most the run's parts.
                    u32::try_from(self.end - self.start).map_err(|_| BoundedError::Overflow)?;
                    self.pass = 0;
                    self.phase = OrderingPhase::Clear;
                }
            }
            OrderingPhase::Clear => {
                TABLE.admit(allocator)?;
                self.counts = [0; DIGITS];
                self.at = self.start;
                self.phase = OrderingPhase::Count;
            }
            OrderingPhase::Count => {
                MARK.admit(allocator)?;
                let digit = Self::digit(self.pass, chars[self.at]);
                self.counts[digit] += 1;
                self.at += 1;
                if self.at == self.end {
                    self.phase = OrderingPhase::Prefix;
                }
            }
            OrderingPhase::Prefix => {
                TABLE.admit(allocator)?;
                let mut offset = 0u32;
                for count in &mut self.counts {
                    let next = offset + *count;
                    *count = offset;
                    offset = next;
                }
                self.at = self.start;
                self.phase = OrderingPhase::Scatter;
            }
            OrderingPhase::Scatter => {
                let Some(scratch) = self.scratch.settle_step(allocator)? else {
                    return Ok(false);
                };
                MARK.admit(allocator)?;
                let ch = chars[self.at];
                let digit = Self::digit(self.pass, ch);
                let slot = self.start + self.counts[digit] as usize;
                self.counts[digit] += 1;
                scratch.as_mut_slice()[slot] = ch;
                self.at += 1;
                if self.at == self.end {
                    self.at = self.start;
                    self.phase = OrderingPhase::Back;
                }
            }
            OrderingPhase::Back => {
                let Some(scratch) = self.scratch.settle_step(allocator)? else {
                    return Ok(false);
                };
                MARK.admit(allocator)?;
                chars[self.at] = scratch.as_slice()[self.at];
                self.at += 1;
                if self.at == self.end {
                    if self.pass == 0 {
                        self.pass = 1;
                        self.phase = OrderingPhase::Clear;
                    } else {
                        self.start = self.end;
                        self.phase = OrderingPhase::Find;
                    }
                }
            }
        }
        Ok(false)
    }
}
