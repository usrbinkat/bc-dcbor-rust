//! Real heap instrumentation. Only this test thread is observed. Bookkeeping
//! uses fixed storage and cannot recursively allocate through GlobalAlloc.
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::RefCell;

#[derive(Clone, Copy, Debug, Default)]
pub struct Stats {
    pub calls: usize,
    pub denied: bool,
    pub live: usize,
    pub peak: usize,
    pub unadmitted: usize,
    pub overflow: bool,
}
struct State {
    active: bool,
    fail_at: Option<usize>,
    admitted: [u64; 512],
    slots: [(usize, usize); 512],
    stats: Stats,
}
thread_local! {
    static STATE: RefCell<State> = const { RefCell::new(State {
        active: false, fail_at: None, admitted: [0; 512], slots: [(0, 0); 512],
        stats: Stats { calls: 0, denied: false, live: 0, peak: 0,
            unadmitted: 0, overflow: false },
    }) };
}

pub fn admitted(bytes: u64) {
    let _ = STATE.try_with(|state| {
        let mut state = state.borrow_mut();
        if state.active {
            if bytes == 0 {
                return;
            }
            if let Some(slot) = state.admitted.iter_mut().find(|slot| **slot == 0) {
                *slot = bytes;
            } else {
                state.stats.overflow = true;
            }
        }
    });
}

fn deny(bytes: usize) -> bool {
    STATE
        .try_with(|state| {
            let mut state = state.borrow_mut();
            if !state.active {
                return false;
            }
            // A field can be reserved before its permit-container metadata.
            // Match outstanding admissions rather than assuming the last
            // admitted allocation must be the next physical request.
            if let Some((index, _)) = state
                .admitted
                .iter()
                .enumerate()
                .filter(|(_, held)| **held >= bytes as u64 && **held != 0)
                .min_by_key(|(_, held)| **held)
            {
                state.admitted[index] = 0;
            } else {
                state.stats.unadmitted += 1;
            }
            let denied = state.fail_at == Some(state.stats.calls);
            state.stats.calls += 1;
            state.stats.denied |= denied;
            denied
        })
        .unwrap_or(false)
}

fn allocated(ptr: *mut u8, bytes: usize) {
    if ptr.is_null() {
        return;
    }
    let _ = STATE.try_with(|state| {
        let mut state = state.borrow_mut();
        if !state.active {
            return;
        }
        if let Some(slot) = state.slots.iter_mut().find(|slot| slot.0 == 0) {
            *slot = (ptr as usize, bytes);
            state.stats.live += bytes;
            state.stats.peak = state.stats.peak.max(state.stats.live);
        } else {
            state.stats.overflow = true;
        }
    });
}

fn released(ptr: *mut u8) {
    let _ = STATE.try_with(|state| {
        let mut state = state.borrow_mut();
        if state.stats.live == 0 {
            return;
        }
        if let Some(index) = state
            .slots
            .iter()
            .position(|slot| slot.0 == ptr as usize && slot.0 != 0)
        {
            state.stats.live -= state.slots[index].1;
            state.slots[index] = (0, 0);
        }
    });
}

struct Observed;
// System owns every pointer. The observer only refuses a selected request and
// records addresses; it never dereferences them or changes allocation layouts.
unsafe impl GlobalAlloc for Observed {
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
            let _ = STATE.try_with(|state| {
                let mut state = state.borrow_mut();
                if state.active {
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
#[global_allocator]
static ALLOCATOR: Observed = Observed;

pub struct Observation;
impl Observation {
    pub fn begin(fail_at: Option<usize>) -> Self {
        STATE.with(|state| {
            let mut state = state.borrow_mut();
            assert!(
                !state.active && state.stats.live == 0,
                "nested observation/live previous output"
            );
            state.stats = Stats::default();
            state.admitted = [0; 512];
            state.fail_at = fail_at;
            state.active = true;
        });
        Self
    }
    pub fn snapshot(&self) -> Stats {
        STATE.with(|state| state.borrow().stats)
    }
    pub fn stop(&self) {
        STATE.with(|state| state.borrow_mut().active = false);
    }
}
impl Drop for Observation {
    fn drop(&mut self) {
        self.stop();
    }
}

#[test]
fn physical_observer_detects_an_unreported_allocation() {
    let observer = Observation::begin(None);
    let bytes = std::hint::black_box(vec![7u8; 1024]);
    observer.stop();
    let stats = observer.snapshot();
    assert!(stats.calls > 0 && stats.unadmitted > 0);
    assert!(stats.live >= 1024);
    drop(bytes);
    assert_eq!(observer.snapshot().live, 0);
}

#[test]
fn every_real_decoder_allocation_failure_releases_physical_and_permit_ownership() {
    use super::harness::*;
    use dcbor::bounded::BoundedError;
    use dcbor::bounded::decode::DecodeError;
    let wire = text_wire(&"q\u{301}😀".repeat(64));
    let mut baseline = meter();
    baseline.calls.reserve(16384);
    let observer = Observation::begin(None);
    let value = retained_value::<String>(&wire, &mut baseline).unwrap();
    observer.stop();
    let stats = observer.snapshot();
    assert!(!stats.overflow && stats.calls > 0);
    assert_eq!(stats.unadmitted, 0);
    assert!(stats.live <= baseline.pool.live() as usize);
    assert!(stats.peak <= baseline.pool.peak() as usize);
    drop(value);
    assert_eq!(observer.snapshot().live, 0);
    assert_eq!(baseline.pool.live(), 0);
    drop(observer);
    every_case(stats.calls, |index| {
        let mut m = meter();
        m.calls.reserve(16384);
        let observer = Observation::begin(Some(index));
        let result = retained_value::<String>(&wire, &mut m);
        observer.stop();
        let stats = observer.snapshot();
        assert!(stats.denied, "allocation {index} never intercepted");
        assert!(!stats.overflow);
        assert_eq!(stats.unadmitted, 0);
        assert!(matches!(
            result,
            Err(DecodeError::Resource(BoundedError::Allocation { .. }))
        ));
        drop(result);
        assert_eq!(observer.snapshot().live, 0);
        assert_eq!(m.pool.live(), 0);
    });
}

// Ownership floor: Tokio's sync_semaphore_owned.rs::try_acquire_many and
// stress_test. Extend that floor by observing actual storage simultaneously
// with reservations, including every physical allocation failure.
fn retained_value<T: dcbor::bounded::decode::construction::ResumableDecodable>(
    wire: &[u8],
    meter: &mut super::harness::Meter,
) -> Result<
    dcbor::bounded::decode::construction::TypedValue<T, super::harness::Permit>,
    dcbor::bounded::decode::DecodeError<super::harness::Refusal>,
> {
    use dcbor::bounded::decode::Options;
    use dcbor::bounded::decode::construction::{TypedDecoder, TypedStep};
    let mut decoder = TypedDecoder::<T, _>::new(wire, Options::normalizing(8));
    for _ in 0..wire.len() * 128 + 4096 {
        let before = (meter.values, meter.bytes);
        meter.limit_values = before.0.checked_add(3).unwrap();
        meter.limit_bytes = before.1.checked_add(64).unwrap();
        let outcome = decoder.step(meter)?;
        assert!(meter.values - before.0 <= 3 && meter.bytes - before.1 <= 64);
        match outcome {
            TypedStep::Progress => {
                assert!(meter.values > before.0 || meter.bytes > before.1);
            }
            TypedStep::Complete(value) => {
                let held = meter.pool.live();
                drop(decoder);
                assert_eq!(meter.pool.live(), held);
                return Ok(value);
            }
            TypedStep::Finished => panic!("retained decoder lost its output"),
        }
    }
    panic!("retained decoder failed to terminate");
}

#[test]
fn every_real_normalization_and_output_allocation_can_fail_without_leaking() {
    use super::harness::*;
    use dcbor::bounded::BoundedError;
    let source = format!("q{}", "\u{301}\u{316}".repeat(64));
    let expected = text_wire(&format!(
        "q{}{}",
        "\u{316}".repeat(64),
        "\u{301}".repeat(64)
    ));
    let mut baseline = meter();
    baseline.calls.reserve(16384);
    let observer = Observation::begin(None);
    let output = retained_text(&source, &mut baseline).unwrap();
    observer.stop();
    assert_eq!(output.as_ref(), expected);
    let measured = observer.snapshot();
    assert!(measured.calls > 0 && !measured.overflow);
    assert_eq!(measured.unadmitted, 0);
    assert!(measured.live <= baseline.pool.live() as usize);
    assert!(measured.peak <= baseline.pool.peak() as usize);
    drop(output);
    assert_eq!(observer.snapshot().live, 0);
    assert_eq!(baseline.pool.live(), 0);
    drop(observer);
    every_case(measured.calls, |index| {
        let mut m = meter();
        m.calls.reserve(16384);
        let observer = Observation::begin(Some(index));
        let output = retained_text(&source, &mut m);
        observer.stop();
        let measured = observer.snapshot();
        assert!(
            measured.denied,
            "physical failure {index} was not exercised"
        );
        assert!(!measured.overflow);
        assert_eq!(measured.unadmitted, 0);
        assert!(matches!(output, Err(BoundedError::Allocation { .. })));
        drop(output);
        assert_eq!(observer.snapshot().live, 0);
        assert_eq!(m.pool.live(), 0);
    });
}

#[test]
fn physical_growth_failure_preserves_old_bytes_and_their_reservation() {
    use super::harness::*;
    use dcbor::bounded::{BoundedError, Owned};
    let mut m = meter();
    m.calls.reserve(16384);
    let observer = Observation::begin(None);
    let mut bytes = Owned::new();
    bytes.push(7u8, &mut m).unwrap();
    observer.stop();
    let old = observer.snapshot().live;
    let held = m.pool.live();
    assert!(old > 0 && old <= held as usize);
    // Re-arm the existing observation, retaining the old allocation registry.
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        state.active = true;
        state.fail_at = Some(state.stats.calls);
    });
    let result = bytes.reserve(4096, &mut m);
    observer.stop();
    assert!(matches!(result, Err(BoundedError::Allocation { .. })));
    assert!(observer.snapshot().denied);
    assert_eq!(bytes.as_slice(), &[7]);
    assert_eq!(observer.snapshot().live, old);
    assert_eq!(m.pool.live(), held);
    drop(bytes);
    assert_eq!(observer.snapshot().live, 0);
    assert_eq!(m.pool.live(), 0);
}

fn retained_text(
    source: &str,
    meter: &mut super::harness::Meter,
) -> Result<
    dcbor::bounded::Encoded<super::harness::Permit>,
    dcbor::bounded::BoundedError<super::harness::Refusal>,
> {
    use dcbor::bounded::text_cursor::{TextEncoder, TextStep};
    let mut encoder = TextEncoder::new(source);
    for _ in 0..source.len() * source.len() * 8 + 4096 {
        let before = (meter.values, meter.bytes);
        meter.limit_values = before.0.checked_add(3).unwrap();
        meter.limit_bytes = before.1.checked_add(64).unwrap();
        let outcome = encoder.step(meter)?;
        assert!(meter.values - before.0 <= 3 && meter.bytes - before.1 <= 64);
        match outcome {
            TextStep::Progress => {
                assert!(meter.values > before.0 || meter.bytes > before.1);
            }
            TextStep::Complete(value) => {
                let held = meter.pool.live();
                drop(encoder);
                assert_eq!(meter.pool.live(), held);
                return Ok(value);
            }
            TextStep::Finished => panic!("retained encoder lost its output"),
        }
    }
    panic!("retained encoder failed to terminate");
}

#[cfg(feature = "derive")]
#[test]
fn derived_nested_values_release_every_failed_physical_allocation() {
    use super::harness::*;
    use dcbor::bounded::{BoundedError, decode::DecodeError};
    #[derive(dcbor::CBORBoundedDecodable)]
    struct Record {
        #[cbor(n = 1)]
        first: String,
        #[cbor(n = 2)]
        nested: Vec<Vec<String>>,
    }
    // Literal map {1: "a", 2: [["b", "c"], ["d"]]}.
    let wire = [
        0xa2, 1, 0x61, b'a', 2, 0x82, 0x82, 0x61, b'b', 0x61, b'c', 0x81, 0x61, b'd',
    ];
    let mut baseline = meter();
    baseline.calls.reserve(16384);
    let observer = Observation::begin(None);
    let output = retained_value::<Record>(&wire, &mut baseline).unwrap();
    observer.stop();
    let stats = observer.snapshot();
    assert!(stats.calls > 0 && !stats.overflow);
    assert_eq!(stats.unadmitted, 0);
    assert!(stats.live <= baseline.pool.live() as usize);
    assert!(stats.peak <= baseline.pool.peak() as usize);
    assert_eq!(output.value().first, "a");
    assert_eq!(output.value().nested[0], ["b", "c"]);
    assert_eq!(output.value().nested[1], ["d"]);
    drop(output);
    assert_eq!(observer.snapshot().live, 0);
    assert_eq!(baseline.pool.live(), 0);
    drop(observer);
    every_case(stats.calls, |index| {
        let mut meter = meter();
        meter.calls.reserve(16384);
        let observer = Observation::begin(Some(index));
        let result = retained_value::<Record>(&wire, &mut meter);
        observer.stop();
        let measured = observer.snapshot();
        assert!(measured.denied && !measured.overflow);
        assert_eq!(measured.unadmitted, 0);
        assert!(matches!(
            result,
            Err(DecodeError::Resource(BoundedError::Allocation { .. }))
        ));
        drop(result);
        assert_eq!(observer.snapshot().live, 0);
        assert_eq!(meter.pool.live(), 0);
    });
}
