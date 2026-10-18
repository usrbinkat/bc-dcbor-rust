//! A finite policy suitable for request-scoped encoding and decoding. Policy
//! construction allocates one shared counter; operation storage is admitted
//! separately. Counters measure requested capacities, not process RSS.
extern crate alloc;
use super::{Allocator, Budget, WriteWork};
use alloc::rc::Rc;
use core::cell::Cell;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Which finite allowance was exhausted.
pub enum LimitRefusal {
    Work,
    Storage,
}

impl core::error::Error for LimitRefusal {}

impl core::fmt::Display for LimitRefusal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Work => "work limit",
            Self::Storage => "storage limit",
        })
    }
}

/// Storage admission released when its owning allocation is dropped.
pub struct Reservation {
    live: Rc<Cell<u64>>,
    bytes: u64,
}
impl Drop for Reservation {
    fn drop(&mut self) {
        self.live.set(self.live.get() - self.bytes);
    }
}

/// Request-scoped work and live requested-capacity limits. This policy is
/// single-threaded (`Rc`); applications needing cross-thread ownership can
/// supply their own `Allocator` and permit type.
pub struct Limits {
    remaining: WriteWork,
    storage: u64,
    live: Rc<Cell<u64>>,
}
impl Limits {
    /// Construct the policy before entering the metered operation. The shared
    /// counter allocation belongs to policy setup, not the storage allowance.
    pub fn new(values: u64, bytes: u64, storage: u64) -> Self {
        Self {
            remaining: WriteWork::new(values, bytes),
            storage,
            live: Rc::new(Cell::new(0)),
        }
    }
    /// Work remaining; successful admissions consume it permanently.
    pub fn remaining(&self) -> WriteWork {
        self.remaining
    }
    /// Requested capacities currently held by live reservations.
    pub fn live_bytes(&self) -> u64 {
        self.live.get()
    }
}
impl Budget for Limits {
    type Refusal = LimitRefusal;
    fn traverse(&mut self, values: u64, bytes: u64) -> Result<(), LimitRefusal> {
        let values = self
            .remaining
            .values
            .checked_sub(values)
            .ok_or(LimitRefusal::Work)?;
        let bytes = self
            .remaining
            .bytes
            .checked_sub(bytes)
            .ok_or(LimitRefusal::Work)?;
        self.remaining = WriteWork::new(values, bytes);
        Ok(())
    }
}
impl Allocator for Limits {
    type Permit = Reservation;
    fn allocate(&mut self, bytes: u64) -> Result<Reservation, LimitRefusal> {
        let live = self
            .live
            .get()
            .checked_add(bytes)
            .ok_or(LimitRefusal::Storage)?;
        if live > self.storage {
            return Err(LimitRefusal::Storage);
        }
        self.live.set(live);
        Ok(Reservation {
            live: self.live.clone(),
            bytes,
        })
    }
}
