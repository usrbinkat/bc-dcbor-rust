use dcbor::bounded::{Allocator, Budget};
use std::sync::{Arc, Mutex};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    Work,
    Capacity,
    Deadline,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Call {
    Work { values: u64, bytes: u64 },
    Allocate(u64),
}

#[derive(Default, Debug)]
struct Capacity {
    live: u64,
    peak: u64,
    limit: u64,
}

#[derive(Clone, Debug)]
pub struct Pool(Arc<Mutex<Capacity>>);
impl Pool {
    pub fn new(limit: u64) -> Self {
        Self(Arc::new(Mutex::new(Capacity {
            limit,
            ..Capacity::default()
        })))
    }
    pub fn live(&self) -> u64 {
        self.0.lock().unwrap().live
    }
    pub fn peak(&self) -> u64 {
        self.0.lock().unwrap().peak
    }
    pub fn reserve(&self, bytes: u64) -> Result<Permit, Refusal> {
        let mut state = self.0.lock().unwrap();
        let live = state.live.checked_add(bytes).ok_or(Refusal::Capacity)?;
        if live > state.limit {
            return Err(Refusal::Capacity);
        }
        state.live = live;
        state.peak = state.peak.max(live);
        Ok(Permit {
            pool: self.clone(),
            bytes,
        })
    }
}

#[derive(Debug)]
pub struct Permit {
    pool: Pool,
    bytes: u64,
}
impl Drop for Permit {
    fn drop(&mut self) {
        let mut state = self.pool.0.lock().unwrap();
        state.live = state.live.checked_sub(self.bytes).expect("double release");
    }
}

pub struct Meter {
    pub pool: Pool,
    pub calls: Vec<Call>,
    pub refused: Option<(usize, Refusal)>,
    pub fail_at: Option<(usize, Refusal)>,
    pub values: u64,
    pub bytes: u64,
    pub limit_values: u64,
    pub limit_bytes: u64,
    /// Deterministic scheduler clock, advanced at each admission boundary.
    /// This tests deadline policy, not CPU duration or internal parser offsets.
    pub clock: u64,
    pub deadline: Option<u64>,
}
impl Meter {
    pub fn new(pool: Pool) -> Self {
        Self {
            pool,
            calls: Vec::new(),
            refused: None,
            fail_at: None,
            values: 0,
            bytes: 0,
            limit_values: u64::MAX,
            limit_bytes: u64::MAX,
            clock: 0,
            deadline: None,
        }
    }
    fn record(&mut self, call: Call) -> Result<(), Refusal> {
        assert!(self.refused.is_none(), "execution continued after refusal");
        let index = self.calls.len();
        self.calls.push(call);
        let now = self.clock;
        self.clock = self.clock.checked_add(1).expect("test clock overflow");
        if self.deadline.is_some_and(|deadline| now >= deadline) {
            self.refused = Some((index, Refusal::Deadline));
            return Err(Refusal::Deadline);
        }
        if let Some((at, reason)) = self.fail_at
            && at == index
        {
            self.refused = Some((index, reason));
            return Err(reason);
        }
        Ok(())
    }
    pub fn assert_units(&self, values: u64, bytes: u64) {
        for (index, call) in self.calls.iter().enumerate() {
            if let Call::Work {
                values: v,
                bytes: b,
            } = call
            {
                assert!(
                    *v <= values && *b <= bytes,
                    "indivisible operation {index}: {call:?} exceeds quantum ({values}, {bytes})"
                );
            }
        }
    }
}
impl Budget for Meter {
    type Refusal = Refusal;
    fn traverse(&mut self, values: u64, bytes: u64) -> Result<(), Refusal> {
        self.record(Call::Work { values, bytes })?;
        let next_values = self.values.checked_add(values).unwrap();
        let next_bytes = self.bytes.checked_add(bytes).unwrap();
        if next_values > self.limit_values || next_bytes > self.limit_bytes {
            self.refused = Some((self.calls.len() - 1, Refusal::Work));
            return Err(Refusal::Work);
        }
        self.values = next_values;
        self.bytes = next_bytes;
        Ok(())
    }
}
impl Allocator for Meter {
    type Permit = Permit;
    fn allocate(&mut self, bytes: u64) -> Result<Permit, Refusal> {
        self.record(Call::Allocate(bytes))?;
        self.pool
            .reserve(bytes)
            .inspect(|_| super::heap::admitted(bytes))
            .inspect_err(|reason| {
                self.refused = Some((self.calls.len() - 1, *reason));
            })
    }
}

pub fn meter() -> Meter {
    Meter::new(Pool::new(32 * 1024 * 1024))
}

/// Execute every independent fault schedule even while the capability is red.
/// Catching an assertion does not pass the test: all failures are reported at
/// the end, so the first missing continuation cannot hide later boundaries.
pub fn every_case(count: usize, mut case: impl FnMut(usize)) {
    assert!(count > 0, "empty fault matrix");
    let mut failures = Vec::new();
    for index in 0..count {
        if let Err(error) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| case(index))) {
            let message = error
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| error.downcast_ref::<&str>().map(|s| (*s).to_owned()))
                .unwrap_or_else(|| "non-string panic".to_owned());
            failures.push((index, message));
        }
    }
    assert!(
        failures.is_empty(),
        "{} of {count} schedules failed: {failures:#?}",
        failures.len()
    );
}

pub fn text_wire(text: &str) -> Vec<u8> {
    let n = text.len();
    let mut wire = match n {
        0..24 => vec![0x60 | n as u8],
        24..256 => vec![0x78, n as u8],
        256..65536 => vec![0x79, (n >> 8) as u8, n as u8],
        _ => {
            let mut v = vec![0x7a];
            v.extend(u32::try_from(n).unwrap().to_be_bytes());
            v
        }
    };
    wire.extend(text.as_bytes());
    wire
}
