//! The bounded policy: finite work, requested and live storage, a deterministic
//! deadline, a fault schedule, and allocation-free observation. Policy
//! construction allocates one shared counter; call logs allocate only when
//! enabled with [`Limits::logged`]. Counters measure requested capacities, not
//! process RSS.
extern crate alloc;
use super::{Allocator, Budget, WriteWork};
use crate::bounded::decode::construction::TypedPosition;
use alloc::{sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicU64, Ordering};

/// The quantum of one bounded turn: three values and 64 bytes.
pub const TURN: WriteWork = WriteWork::new(3, 64);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Why an admission was refused.
pub enum LimitRefusal {
    /// A work limit: the turn's quantum or the cumulative allowance.
    Work,
    /// Live capacity or the requested-bytes allowance.
    Storage,
    /// The deterministic clock reached the deadline.
    Deadline,
    /// The fault schedule refused the call with this index.
    Scheduled(usize),
}

impl core::error::Error for LimitRefusal {}

impl core::fmt::Display for LimitRefusal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Work => f.write_str("work limit"),
            Self::Storage => f.write_str("storage limit"),
            Self::Deadline => f.write_str("deadline"),
            Self::Scheduled(index) => write!(f, "scheduled refusal of call {index}"),
        }
    }
}

/// One admission request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Call {
    Work { values: u64, bytes: u64 },
    Allocate(u64),
}

#[derive(Debug, Default)]
struct Counters {
    live: AtomicU64,
    peak: AtomicU64,
    release_observer: Option<fn(u64)>,
}

/// Storage admission released when its owning allocation is released. A
/// reservation may be released on any thread; release is one atomic
/// subtraction, allocates nothing, and panics on a release it never admitted.
#[derive(Debug)]
pub struct Reservation {
    counters: Arc<Counters>,
    bytes: u64,
}

impl Drop for Reservation {
    fn drop(&mut self) {
        let previous = self.counters.live.fetch_sub(self.bytes, Ordering::AcqRel);
        assert!(previous >= self.bytes, "reservation released twice");
        if self.bytes != 0
            && let Some(observer) = self.counters.release_observer
        {
            observer(self.bytes);
        }
    }
}

/// Why a transfer between reservations was refused. The reservations involved
/// are unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferRefusal {
    /// A split asked for more bytes than the reservation holds.
    Insufficient { requested: u64, held: u64 },
    /// The reservations count against different storage.
    Foreign,
    /// The merged size does not fit in `u64`.
    Overflow,
}

impl core::error::Error for TransferRefusal {}

impl core::fmt::Display for TransferRefusal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Insufficient { requested, held } => {
                write!(f, "split of {requested} bytes from a reservation of {held}")
            }
            Self::Foreign => f.write_str("reservations count against different storage"),
            Self::Overflow => f.write_str("merged reservation exceeds u64"),
        }
    }
}

impl Reservation {
    /// The requested bytes this reservation holds.
    pub fn bytes(&self) -> u64 {
        self.bytes
    }

    /// Move `bytes` of this reservation into a new one over the same storage,
    /// as when one allocation's ownership is divided between two owners. Live
    /// and peak storage are unchanged; each part is released with its own
    /// owner. A zero-byte split is an owner of nothing.
    pub fn split(&mut self, bytes: u64) -> Result<Reservation, TransferRefusal> {
        let remaining = self
            .bytes
            .checked_sub(bytes)
            .ok_or(TransferRefusal::Insufficient {
                requested: bytes,
                held: self.bytes,
            })?;
        self.bytes = remaining;
        Ok(Reservation {
            counters: self.counters.clone(),
            bytes,
        })
    }

    /// Take over `other`'s bytes, as when two owners' storage passes to one.
    /// Live and peak storage are unchanged. A refused merge returns `other`
    /// unchanged with the reason.
    pub fn merge(&mut self, mut other: Reservation) -> Result<(), (Reservation, TransferRefusal)> {
        if !Arc::ptr_eq(&self.counters, &other.counters) {
            return Err((other, TransferRefusal::Foreign));
        }
        let Some(bytes) = self.bytes.checked_add(other.bytes) else {
            return Err((other, TransferRefusal::Overflow));
        };
        self.bytes = bytes;
        // The bytes now belong to this reservation: the emptied one releases
        // nothing when it drops.
        other.bytes = 0;
        Ok(())
    }
}

/// One recorded admission and the state it observed.
#[derive(Clone, Copy, Debug)]
pub struct Admission {
    pub index: usize,
    pub call: Call,
    pub result: Result<(), LimitRefusal>,
    /// Cumulative admitted work after the call.
    pub work: WriteWork,
    /// Live and peak storage after the call.
    pub storage: (u64, u64),
    /// The caller-supplied lifecycle position current at the call, its
    /// value's custody elided ([`TypedPosition::outline`]).
    pub position: Option<TypedPosition<()>>,
}

/// The most recent admissions in fixed storage, and the first refusal kept
/// separately so long resumptions cannot overwrite its cause. Recording never
/// allocates.
pub struct AdmissionTrace {
    recent: [Option<Admission>; 32],
    count: usize,
    first_refusal: Option<Admission>,
    context: Option<TypedPosition<()>>,
}

impl AdmissionTrace {
    pub const fn new() -> Self {
        Self {
            recent: [None; 32],
            count: 0,
            first_refusal: None,
            context: None,
        }
    }

    pub fn context<O>(&mut self, position: TypedPosition<O>) {
        self.context = Some(position.outline());
    }

    pub fn first_refusal(&self) -> Option<Admission> {
        self.first_refusal
    }

    pub fn count(&self) -> usize {
        self.count
    }

    /// The most recent admission attempt: what a stalled operation last
    /// asked for, and why it was refused.
    pub fn last(&self) -> Option<Admission> {
        let index = self.count.checked_sub(1)?;
        self.recent[index % self.recent.len()]
    }

    fn record(&mut self, mut event: Admission) {
        event.position = self.context;
        if event.result.is_err() && self.first_refusal.is_none() {
            self.first_refusal = Some(event);
        }
        self.recent[self.count % self.recent.len()] = Some(event);
        self.count += 1;
    }

    /// Panic with the first difference and this trace unless `actual` and
    /// `expected` are the same call sequence. `run` names the run by what it
    /// is, never by its position among others: a case's name, or a schedule's
    /// operation and refused call.
    pub fn assert_calls(&self, actual: &[Call], expected: &[Call], run: &str) {
        if actual == expected {
            return;
        }
        let at = actual
            .iter()
            .zip(expected)
            .position(|(a, b)| a != b)
            .unwrap_or(actual.len().min(expected.len()));
        let start = at.saturating_sub(2);
        panic!(
            "admission replay: run={run}, first_difference={at}, actual_len={}, expected_len={}\nactual_window={:?}\nexpected_window={:?}\n{self:?}",
            actual.len(),
            expected.len(),
            &actual[start..actual.len().min(at + 4)],
            &expected[start..expected.len().min(at + 4)]
        );
    }
}

impl Default for AdmissionTrace {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for AdmissionTrace {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        writeln!(
            f,
            "first_refusal={:?}; total_events={}",
            self.first_refusal, self.count
        )?;
        for index in self.count.saturating_sub(self.recent.len())..self.count {
            if let Some(event) = self.recent[index % self.recent.len()] {
                writeln!(
                    f,
                    "call={} {:?} -> {:?}; work={:?}; live_peak={:?}; position={:?}",
                    event.index,
                    event.call,
                    event.result,
                    event.work,
                    event.storage,
                    event.position
                )?;
            }
        }
        Ok(())
    }
}

/// Work and live requested-capacity limits, with the observation and fault
/// injection a scheduler or test needs. The policy is used by one operation
/// at a time; its reservations may move to and be released on other threads.
pub struct Limits {
    /// Cumulative admitted work.
    used: WriteWork,
    /// Cumulative work allowance; a turn moves it one quantum past `used`.
    limit: WriteWork,
    storage: u64,
    requested: u64,
    requested_limit: u64,
    counters: Arc<Counters>,
    attempts: usize,
    requests: usize,
    refusals: usize,
    scheduled_refusals: usize,
    injected_refusals: usize,
    last_injected: bool,
    refused: Option<(usize, LimitRefusal)>,
    fail_at: Option<(usize, LimitRefusal)>,
    /// Refuse every admission once: each call is refused on its first
    /// attempt and admitted on the attempt after.
    refuse_each: bool,
    /// The last attempt was refused under `refuse_each`, so the next is
    /// its retry.
    retrying: bool,
    fail_request: Option<usize>,
    fail_requests: usize,
    clock: u64,
    deadline: Option<u64>,
    observer: Option<fn(u64)>,
    logging: bool,
    strict: bool,
    terminal: bool,
    calls: Vec<Call>,
    admitted: Vec<Call>,
    refused_calls: Vec<(usize, LimitRefusal, bool)>,
    trace: AdmissionTrace,
}

impl Limits {
    /// `values` and `bytes` of work in total and `storage` live requested
    /// bytes. The shared counter allocation belongs to policy setup.
    pub fn new(values: u64, bytes: u64, storage: u64) -> Self {
        Self::with_counters(values, bytes, storage, Arc::new(Counters::default()))
    }

    fn with_counters(values: u64, bytes: u64, storage: u64, counters: Arc<Counters>) -> Self {
        Self {
            used: WriteWork::default(),
            limit: WriteWork::new(values, bytes),
            storage,
            requested: 0,
            requested_limit: u64::MAX,
            counters,
            attempts: 0,
            requests: 0,
            refusals: 0,
            scheduled_refusals: 0,
            injected_refusals: 0,
            last_injected: false,
            refused: None,
            fail_at: None,
            refuse_each: false,
            retrying: false,
            fail_request: None,
            fail_requests: 0,
            clock: 0,
            deadline: None,
            observer: None,
            logging: false,
            strict: false,
            terminal: false,
            calls: Vec::new(),
            admitted: Vec::new(),
            refused_calls: Vec::new(),
            trace: AdmissionTrace::new(),
        }
    }

    /// A fresh policy over the same live storage: its reservations count
    /// against this policy's capacity, peak and live bytes.
    pub fn share(&self) -> Self {
        let mut shared = Self::new(u64::MAX, u64::MAX, self.storage);
        shared.counters = self.counters.clone();
        shared.observer = self.observer;
        shared.logging = self.logging;
        shared.strict = self.strict;
        shared
    }

    /// No work, storage or requested-bytes limit.
    pub fn unlimited() -> Self {
        Self::new(u64::MAX, u64::MAX, u64::MAX)
    }

    /// Unlimited storage and one fresh turn of work.
    pub fn turns() -> Self {
        let mut limits = Self::unlimited();
        limits.fresh();
        limits
    }

    /// Record every attempted and admitted call.
    pub fn logged(mut self) -> Self {
        self.logging = true;
        self
    }

    /// Reserve room for `additional` logged calls, so that logging inside an
    /// observed interval performs no allocation.
    pub fn reserve_log(&mut self, additional: usize) {
        self.calls.reserve(additional);
        self.admitted.reserve(additional);
        self.refused_calls.reserve(additional);
    }

    /// Panic when a call follows a refusal that was not cleared with
    /// [`Self::clear_refusal`]: the operation under test must stop at a
    /// refusal and resume only in a later turn.
    pub fn strict(mut self) -> Self {
        self.strict = true;
        self
    }

    /// Refuse the attempted call with index `at`, once.
    pub fn refusing(mut self, at: Option<usize>) -> Self {
        self.fail_call(at.map(|at| (at, LimitRefusal::Scheduled(at))));
        self
    }

    /// Refuse the attempted call with the given index, for the given reason.
    pub fn fail_call(&mut self, at: Option<(usize, LimitRefusal)>) {
        self.fail_at = at;
    }

    /// Refuse every admission once, as a scheduled refusal of its attempt:
    /// each call is refused when first attempted and admitted when next
    /// attempted. One run then suspends at every admission an operation
    /// makes, each from the state the unrefused run reaches there, so the
    /// refusal contract of every step is checked in one pass.
    pub fn refusing_each(mut self) -> Self {
        self.fail_each();
        self
    }

    /// Refuse every admission from the next attempt on, once each
    /// ([`Self::refusing_each`]).
    pub fn fail_each(&mut self) {
        self.refuse_each = true;
        self.retrying = false;
    }

    /// Whether every admission is refused once ([`Self::refusing_each`]):
    /// each takes two attempts, so a turn bound counts twice as many turns.
    pub fn refuses_each(&self) -> bool {
        self.refuse_each
    }

    /// The steps an operation of `steps` steps
    /// ([`crate::bounded::ResourceBound::steps`]) may take under this
    /// policy's refusals: twice as many, and one more, when every admission is
    /// refused once ([`Self::refuses_each`]), since each refused admission
    /// costs a step of its own. The one refusal allowance of every bounded
    /// driver, in this crate's tests and its integration harness alike.
    /// Refused, never saturated, when the result does not fit in `u64`.
    pub fn allowed<R>(&self, steps: u64) -> Result<u64, crate::bounded::BoundedError<R>> {
        if self.refuse_each {
            crate::bounded::add(crate::bounded::mul(steps, 2)?, 1)
        } else {
            Ok(steps)
        }
    }

    /// Refuse the next call, of either kind, once.
    pub fn refuse_next(&mut self) {
        let at = self.attempts;
        self.fail_call(Some((at, LimitRefusal::Scheduled(at))));
    }

    /// Forget the current refusal so that calls may continue.
    pub fn clear_refusal(&mut self) {
        self.refused = None;
    }

    /// Refuse the allocation request with index `at`, once.
    pub fn refusing_request(mut self, at: Option<usize>) -> Self {
        self.fail_request(at);
        self
    }

    /// Refuse the allocation request with index `at` among requests counted
    /// since construction or the last [`Self::measure`], once.
    pub fn fail_request(&mut self, at: Option<usize>) {
        self.fail_request = at;
    }

    /// Refuse the next `count` allocation requests.
    pub fn refusing_requests(mut self, count: usize) -> Self {
        self.fail_requests(count);
        self
    }

    /// Refuse the next `count` allocation requests.
    pub fn fail_requests(&mut self, count: usize) {
        self.fail_requests = count;
    }

    /// Refuse cumulative requested allocation bytes beyond `bytes`.
    pub fn requesting_at_most(mut self, bytes: u64) -> Self {
        self.requested_limit = bytes;
        self
    }

    /// Refuse every call once the deterministic clock reaches `deadline`.
    /// The clock advances by one at each attempted call.
    pub fn deadline(&mut self, deadline: Option<u64>) {
        self.deadline = deadline;
    }

    /// Called with the bytes of each granted allocation, before the caller
    /// performs the physical allocation.
    pub fn observe(mut self, observer: fn(u64)) -> Self {
        self.observer = Some(observer);
        self
    }

    /// Observe nonzero reservation releases on the thread performing the
    /// release, including releases through shared policies and split permits.
    /// Configure before sharing the policy or issuing any reservation.
    ///
    /// # Safety
    /// The callback must perform bounded, nonblocking work and must not
    /// allocate, panic, or reenter the policy. Releases also occur during
    /// allocation-free terminal cleanup and unwinding.
    pub unsafe fn observe_releases(mut self, observer: fn(u64)) -> Self {
        Arc::get_mut(&mut self.counters)
            .expect("release observation must be configured before sharing")
            .release_observer = Some(observer);
        self
    }

    /// Whether this storage pool reports reservation releases.
    pub fn observes_releases(&self) -> bool {
        self.counters.release_observer.is_some()
    }

    /// Start a new turn: one quantum of work past what was admitted.
    pub fn fresh(&mut self) {
        self.limit = WriteWork::new(
            self.used.values.saturating_add(TURN.values),
            self.used.bytes.saturating_add(TURN.bytes),
        );
    }

    /// A new scheduler turn: forget the current refusal and admit one more
    /// quantum of work.
    pub fn turn(&mut self) {
        self.clear_refusal();
        self.fresh();
    }

    /// Lift the work limit, as for setup outside a measured operation.
    pub fn open(&mut self) {
        self.limit = WriteWork::new(u64::MAX, u64::MAX);
    }

    /// Set the cumulative work limit.
    pub fn set_limit(&mut self, limit: WriteWork) {
        self.limit = limit;
    }

    /// End the current turn: no further work is admitted until `fresh`.
    pub fn exhaust(&mut self) {
        self.limit = self.used;
    }

    /// Forget counts, logs and the fault schedule's progress so that only the
    /// following calls are measured. Live storage is unaffected.
    pub fn measure(&mut self) {
        self.used = WriteWork::default();
        self.fresh();
        self.requested = 0;
        self.attempts = 0;
        self.requests = 0;
        self.refusals = 0;
        self.scheduled_refusals = 0;
        self.injected_refusals = 0;
        self.last_injected = false;
        self.refused = None;
        self.retrying = false;
        self.calls.clear();
        self.admitted.clear();
        self.refused_calls.clear();
        self.trace = AdmissionTrace::new();
    }

    /// Work remaining; successful admissions consume it permanently.
    pub fn remaining(&self) -> WriteWork {
        WriteWork::new(
            self.limit.values.saturating_sub(self.used.values),
            self.limit.bytes.saturating_sub(self.used.bytes),
        )
    }

    /// Cumulative admitted work.
    pub fn used(&self) -> WriteWork {
        self.used
    }

    /// Requested capacities currently held by live reservations.
    pub fn live_bytes(&self) -> u64 {
        self.counters.live.load(Ordering::Acquire)
    }

    /// The most live bytes held at once.
    pub fn peak_bytes(&self) -> u64 {
        self.counters.peak.load(Ordering::Acquire)
    }

    /// Cumulative bytes of granted allocation requests.
    pub fn requested_bytes(&self) -> u64 {
        self.requested
    }

    /// Attempted calls, refused ones included.
    pub fn attempts(&self) -> usize {
        self.attempts
    }

    /// Allocation requests, refused ones included.
    pub fn requests(&self) -> usize {
        self.requests
    }

    /// Refusals returned.
    pub fn refusals(&self) -> usize {
        self.refusals
    }

    /// Refusals whose reason is `Scheduled`. Use `injected_refusals` to count
    /// explicit injections carrying any reason, including Work or Storage.
    pub fn scheduled_refusals(&self) -> usize {
        self.scheduled_refusals
    }

    /// Refusals caused by an explicit fault injection, whatever its reason.
    pub fn injected_refusals(&self) -> usize {
        self.injected_refusals
    }

    /// Logged refused callbacks: index, reason, and whether explicitly injected.
    pub fn refused_calls(&self) -> &[(usize, LimitRefusal, bool)] {
        &self.refused_calls
    }

    /// The refusal not yet cleared: its call index and reason.
    pub fn first_refusal(&self) -> Option<(usize, LimitRefusal)> {
        self.refused
    }

    /// The deterministic clock: one tick per attempted call.
    pub fn clock(&self) -> u64 {
        self.clock
    }

    /// Attempted calls, when logging.
    pub fn calls(&self) -> &[Call] {
        &self.calls
    }

    /// Admitted calls, when logging.
    pub fn admitted(&self) -> &[Call] {
        &self.admitted
    }

    pub fn trace(&self) -> &AdmissionTrace {
        &self.trace
    }

    pub fn trace_mut(&mut self) -> &mut AdmissionTrace {
        &mut self.trace
    }

    /// Panic unless every logged work call fit in `quantum`.
    pub fn assert_units(&self, quantum: WriteWork) {
        for (index, call) in self.calls.iter().enumerate() {
            if let Call::Work { values, bytes } = call {
                assert!(
                    *values <= quantum.values && *bytes <= quantum.bytes,
                    "indivisible operation {index}: {call:?} exceeds {quantum:?}"
                );
            }
        }
    }

    fn admit(&mut self, call: Call) -> Result<(), LimitRefusal> {
        if self.strict {
            assert!(
                self.refused.is_none(),
                "execution continued after refusal {:?}",
                self.refused
            );
        }
        let index = self.attempts;
        self.attempts += 1;
        if self.logging {
            self.calls.push(call);
        }
        let now = self.clock;
        self.clock = self.clock.saturating_add(1);
        if self.deadline.is_some_and(|deadline| now >= deadline) {
            return Err(LimitRefusal::Deadline);
        }
        if let Some((at, reason)) = self.fail_at
            && at == index
        {
            self.last_injected = true;
            return Err(reason);
        }
        if self.refuse_each {
            self.retrying = !self.retrying;
            if self.retrying {
                self.last_injected = true;
                return Err(LimitRefusal::Scheduled(index));
            }
        }
        match call {
            Call::Work { values, bytes } => {
                let used = self
                    .used
                    .then::<()>(WriteWork::new(values, bytes))
                    .map_err(|_| LimitRefusal::Work)?;
                if !self.limit.covers(&used) {
                    return Err(LimitRefusal::Work);
                }
                self.used = used;
            }
            Call::Allocate(bytes) => {
                let request = self.requests;
                self.requests += 1;
                if self.fail_request == Some(request) {
                    self.last_injected = true;
                    return Err(LimitRefusal::Scheduled(index));
                }
                if self.fail_requests > 0 {
                    self.last_injected = true;
                    self.fail_requests -= 1;
                    return Err(LimitRefusal::Scheduled(index));
                }
                let requested = self
                    .requested
                    .checked_add(bytes)
                    .filter(|total| *total <= self.requested_limit)
                    .ok_or(LimitRefusal::Storage)?;
                // Shared policies can admit concurrently. Check capacity and
                // reserve it in one atomic update, retrying against the latest
                // total when another admission or release wins the race.
                let mut previous = self.counters.live.load(Ordering::Acquire);
                let live = loop {
                    let next = previous
                        .checked_add(bytes)
                        .filter(|next| *next <= self.storage)
                        .ok_or(LimitRefusal::Storage)?;
                    match self.counters.live.compare_exchange_weak(
                        previous,
                        next,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    ) {
                        Ok(_) => break next,
                        Err(current) => previous = current,
                    }
                };
                self.counters.peak.fetch_max(live, Ordering::AcqRel);
                self.requested = requested;
            }
        }
        if self.logging {
            self.admitted.push(call);
        }
        Ok(())
    }

    fn admit_traced(&mut self, call: Call) -> Result<(), LimitRefusal> {
        if self.terminal {
            return match call {
                Call::Work { .. } => Ok(()),
                Call::Allocate(_) => Err(LimitRefusal::Storage),
            };
        }
        self.last_injected = false;
        let result = self.admit(call);
        if let Err(reason) = result {
            self.refusals += 1;
            self.injected_refusals += usize::from(self.last_injected);
            if self.logging {
                self.refused_calls
                    .push((self.attempts - 1, reason, self.last_injected));
            }
            if matches!(reason, LimitRefusal::Scheduled(_)) {
                self.scheduled_refusals += 1;
            }
            self.refused.get_or_insert((self.attempts - 1, reason));
        }
        self.trace.record(Admission {
            index: self.attempts - 1,
            call,
            result,
            work: self.used,
            storage: (self.live_bytes(), self.peak_bytes()),
            position: None,
        });
        result
    }
}

impl Default for Limits {
    fn default() -> Self {
        Self::unlimited()
    }
}

impl Budget for Limits {
    type Refusal = LimitRefusal;
    fn traverse(&mut self, values: u64, bytes: u64) -> Result<(), LimitRefusal> {
        self.admit_traced(Call::Work { values, bytes })
    }
}

// SAFETY: constructing this policy only clones an existing Arc. Terminal
// admissions bypass logging and counters, never refuse work, and reject all
// allocation requests. Its fields have allocation-free, non-unwinding drops.
unsafe impl super::TerminalAllocator for Limits {
    fn terminal(permit: &Reservation) -> Self {
        let mut policy = Self::with_counters(u64::MAX, u64::MAX, u64::MAX, permit.counters.clone());
        policy.terminal = true;
        policy
    }
}

impl Allocator for Limits {
    type Permit = Reservation;
    fn allocate(&mut self, bytes: u64) -> Result<Reservation, LimitRefusal> {
        self.admit_traced(Call::Allocate(bytes))?;
        if let Some(observer) = self.observer {
            observer(bytes);
        }
        Ok(Reservation {
            counters: self.counters.clone(),
            bytes,
        })
    }
}
