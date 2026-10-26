//! The physical heap observer shared by every test binary. Only the observing
//! thread is counted. Bookkeeping uses fixed storage and cannot recursively
//! allocate through the global allocator.
//!
//! Install with `#[global_allocator] static HEAP: heap::Heap = heap::Heap;` and
//! pass `heap::admitted` to `Limits::observe` so admitted allocations can be
//! matched against physical requests.
//!
//! Both records the observer keeps, the outstanding admitted sizes and the
//! live allocations, are sorted arrays with a count: a lookup is a binary
//! search and an insertion or removal one move of the tail, so the observer's
//! own cost per request does not grow with what it holds, which matters
//! where every instruction is interpreted, as under Miri. Beginning an
//! observation resets the counts, not the storage.
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::{Cell, RefCell};

/// The most outstanding admissions and live allocations an observation
/// records; past it the observation is marked incomplete.
const CAPACITY: usize = 512;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    /// Physical allocation requests while armed.
    pub calls: usize,
    /// Requests the observer refused.
    pub denied: usize,
    /// Requests no admitted allocation covered.
    pub unadmitted: usize,
    /// Live and peak observed bytes.
    pub live: usize,
    pub peak: usize,
    /// Fixed storage was exhausted; the other figures are incomplete.
    pub overflow: bool,
}

/// A sorted array of `T` in fixed storage, its first `len` entries in use.
struct Sorted<T: Copy> {
    entries: [T; CAPACITY],
    len: usize,
}

impl<T: Copy> Sorted<T> {
    /// The used entries, in order.
    fn used(&self) -> &[T] {
        &self.entries[..self.len]
    }

    /// Insert `entry` at `at`, its sorted position; false when full.
    fn insert(&mut self, at: usize, entry: T) -> bool {
        if self.len == CAPACITY {
            return false;
        }
        self.entries.copy_within(at..self.len, at + 1);
        self.entries[at] = entry;
        self.len += 1;
        true
    }

    /// Remove the entry at `at`.
    fn remove(&mut self, at: usize) {
        self.entries.copy_within(at + 1..self.len, at);
        self.len -= 1;
    }
}

struct State {
    armed: bool,
    fail_at: Option<usize>,
    /// Admitted sizes not yet matched by a physical request, ascending.
    admitted: Sorted<u64>,
    /// Live observed allocations, `(address, bytes)`, by address.
    slots: Sorted<(usize, usize)>,
    stats: Stats,
}

thread_local! {
    static RESERVATION_RELEASES: Cell<u64> = const { Cell::new(0) };
    static STATE: RefCell<State> = const { RefCell::new(State {
        armed: false,
        fail_at: None,
        admitted: Sorted { entries: [0; CAPACITY], len: 0 },
        slots: Sorted { entries: [(0, 0); CAPACITY], len: 0 },
        stats: Stats { calls: 0, denied: 0, unadmitted: 0, live: 0, peak: 0, overflow: false },
    }) };
}

/// Reservation-release events on this thread, independent of the physical
/// observation window. Other workers cannot supply or hide this witness.
pub fn reservation_releases() -> u64 {
    RESERVATION_RELEASES.with(Cell::get)
}

/// Allocation-free, non-panicking policy callback, including during TLS
/// teardown. Zero-byte transfers are not releases and are never reported.
pub fn reservation_released(_: u64) {
    let _ = RESERVATION_RELEASES.try_with(|count| count.set(count.get().wrapping_add(1)));
}

/// Install the reservation witness before the policy is shared or used.
pub fn observe_releases(m: dcbor::bounded::Limits) -> dcbor::bounded::Limits {
    // SAFETY: the callback only updates a const-initialized TLS Cell; it
    // neither allocates, panics, nor accesses the policy.
    unsafe { m.observe_releases(reservation_released) }
}

fn with<R>(f: impl FnOnce(&mut State) -> R) -> Option<R> {
    STATE.try_with(|state| f(&mut state.borrow_mut())).ok()
}

/// Record an admitted allocation of `bytes`. Pass to `Limits::observe`.
pub fn admitted(bytes: u64) {
    with(|state| {
        if !state.armed || bytes == 0 {
            return;
        }
        let at = state.admitted.used().partition_point(|held| *held < bytes);
        if !state.admitted.insert(at, bytes) {
            state.stats.overflow = true;
        }
    });
}

fn deny(bytes: usize) -> bool {
    with(|state| {
        if !state.armed {
            return false;
        }
        // A field can be reserved before its container's metadata, so the
        // request is matched to the smallest outstanding admission that
        // covers it, not only the last one.
        let at = state
            .admitted
            .used()
            .partition_point(|held| *held < bytes as u64);
        if at < state.admitted.len {
            state.admitted.remove(at);
        } else {
            state.stats.unadmitted += 1;
        }
        let denied = state.fail_at == Some(state.stats.calls);
        state.stats.calls += 1;
        if denied {
            state.stats.denied += 1;
        }
        denied
    })
    .unwrap_or(false)
}

fn allocated(ptr: *mut u8, bytes: usize) {
    if ptr.is_null() {
        return;
    }
    with(|state| {
        if !state.armed {
            return;
        }
        let address = ptr as usize;
        let at = state
            .slots
            .used()
            .partition_point(|(held, _)| *held < address);
        if state.slots.insert(at, (address, bytes)) {
            state.stats.live += bytes;
            state.stats.peak = state.stats.peak.max(state.stats.live);
        } else {
            state.stats.overflow = true;
        }
    });
}

/// Forget a released allocation the observation recorded, armed or not: an
/// allocation observed while armed may be freed outside the window.
fn released(ptr: *mut u8) {
    with(|state| {
        if state.slots.len == 0 {
            return;
        }
        let address = ptr as usize;
        if let Ok(at) = state
            .slots
            .used()
            .binary_search_by_key(&address, |(held, _)| *held)
        {
            state.stats.live -= state.slots.entries[at].1;
            state.slots.remove(at);
        }
    });
}

pub struct Heap;

// System owns every pointer. The observer only refuses a selected request and
// records addresses; it never dereferences them or changes allocation layouts.
unsafe impl GlobalAlloc for Heap {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if deny(layout.size()) {
            return std::ptr::null_mut();
        }
        let ptr = unsafe { System.alloc(layout) };
        allocated(ptr, layout.size());
        ptr
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        if deny(layout.size()) {
            return std::ptr::null_mut();
        }
        let ptr = unsafe { System.alloc_zeroed(layout) };
        allocated(ptr, layout.size());
        ptr
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        if deny(size) {
            return std::ptr::null_mut();
        }
        let replacement = unsafe { System.realloc(ptr, layout, size) };
        if !replacement.is_null() {
            // Count requested old/new overlap, even if System grew in place.
            with(|state| {
                if state.armed {
                    state.stats.peak = state.stats.peak.max(state.stats.live + size);
                }
            });
            released(ptr);
            allocated(replacement, size);
        }
        replacement
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        released(ptr);
        unsafe { System.dealloc(ptr, layout) };
    }
}

/// Whether this binary installs [`Heap`] as its global allocator: one probe
/// allocation in an observation of its own, which only an installed observer
/// sees. A check that witnesses physical storage requires it, so it is never
/// silently skipped in a binary that observes nothing.
pub fn installed() -> bool {
    let observation = Observation::begin(None);
    let probe = std::hint::black_box(Box::new(0u8));
    observation.stop();
    let seen = observation.snapshot().calls > 0;
    drop(probe);
    seen
}

/// One observation on this thread. It counts across every armed interval;
/// dropping it disarms the observer.
pub struct Observation;

impl Observation {
    /// Begin observing, armed, failing physical request `fail_at`.
    pub fn begin(fail_at: Option<usize>) -> Self {
        with(|state| {
            assert!(!state.armed, "nested observation");
            state.stats = Stats::default();
            state.admitted.len = 0;
            state.slots.len = 0;
            state.fail_at = fail_at;
            state.armed = true;
        });
        Self
    }

    /// Run `f` in one armed observation failing physical request `fail_at`,
    /// and return its result with the observation's figures.
    pub fn run<R>(fail_at: Option<usize>, f: impl FnOnce() -> R) -> (R, Stats) {
        let observation = Self::begin(fail_at);
        let result = f();
        let stats = observation.snapshot();
        (result, stats)
    }

    pub fn snapshot(&self) -> Stats {
        with(|state| state.stats).unwrap_or_default()
    }

    pub fn stop(&self) {
        with(|state| state.armed = false);
    }

    pub fn resume(&self) {
        with(|state| state.armed = true);
    }

    /// Fail the next physical request, then resume observing.
    pub fn fail_next(&self) {
        with(|state| {
            state.fail_at = Some(state.stats.calls);
            state.armed = true;
        });
    }

    /// Run `f` armed, then disarm, even when `f` unwinds.
    pub fn window<R>(&self, f: impl FnOnce() -> R) -> R {
        let _armed = self.armed();
        f()
    }

    /// Armed until the guard drops.
    pub fn armed(&self) -> Armed<'_> {
        self.resume();
        Armed(self)
    }
}

impl Drop for Observation {
    fn drop(&mut self) {
        self.stop();
    }
}

pub struct Armed<'o>(&'o Observation);

impl Drop for Armed<'_> {
    fn drop(&mut self) {
        self.0.stop();
    }
}
