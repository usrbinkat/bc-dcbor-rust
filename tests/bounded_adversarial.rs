#![cfg(all(feature = "std", feature = "derive"))]
//! Black-box resource and failure tests. No normalization or encoder internals
//! are used; the allocator observes real heap requests on the test thread.
use dcbor::{ByteString, CBOR, CBORBoundedEncodable, CBOREncodable, bounded::*};
use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
    rc::Rc,
};

#[derive(Clone, Copy, Default, Debug)]
struct Heap {
    active: bool,
    calls: usize,
    fail_at: Option<usize>,
    denied: bool,
    admitted_bytes: u64,
    unadmitted: usize,
}
thread_local! { static HEAP: Cell<Heap> = const { Cell::new(Heap {
    active: false, calls: 0, fail_at: None, denied: false,
    admitted_bytes: 0, unadmitted: 0,
}) }; }
struct Observed;
fn deny_allocation(bytes: usize) -> bool {
    HEAP.try_with(|state| {
        let mut s = state.get();
        if !s.active {
            return false;
        }
        let deny = s.fail_at == Some(s.calls);
        if bytes as u64 > s.admitted_bytes {
            s.unadmitted += 1;
        }
        s.admitted_bytes = 0;
        s.calls += 1;
        s.denied |= deny;
        state.set(s);
        deny
    })
    .unwrap_or(false)
}
// The wrapper preserves System's layout/pointer contract. Only a configured
// allocation request returns null; deallocations are always forwarded.
unsafe impl GlobalAlloc for Observed {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if deny_allocation(layout.size()) {
            std::ptr::null_mut()
        } else {
            unsafe { System.alloc(layout) }
        }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        if deny_allocation(layout.size()) {
            std::ptr::null_mut()
        } else {
            unsafe { System.alloc_zeroed(layout) }
        }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        if deny_allocation(size) {
            std::ptr::null_mut()
        } else {
            unsafe { System.realloc(ptr, layout, size) }
        }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
}
#[global_allocator]
static ALLOCATOR: Observed = Observed;

fn observe<T>(fail_at: Option<usize>, f: impl FnOnce() -> T) -> (T, Heap) {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            HEAP.with(|s| {
                let mut h = s.get();
                h.active = false;
                s.set(h);
            });
        }
    }
    HEAP.with(|s| {
        s.set(Heap {
            active: true,
            fail_at,
            ..Heap::default()
        })
    });
    let reset = Reset;
    let result = f();
    let heap = HEAP.with(Cell::get);
    drop(reset);
    (result, heap)
}

#[derive(Debug, PartialEq, Eq)]
struct Refusal(usize);
struct Permit {
    bytes: u64,
    live: Rc<Cell<u64>>,
}
impl Drop for Permit {
    fn drop(&mut self) {
        self.live
            .set(self.live.get().checked_sub(self.bytes).unwrap());
    }
}
struct Policy {
    calls: usize,
    refuse_at: Option<usize>,
    live: Rc<Cell<u64>>,
    peak: u64,
    limit: u64,
    work: WriteWork,
}
impl Policy {
    fn new(refuse_at: Option<usize>) -> Self {
        Self {
            calls: 0,
            refuse_at,
            live: Rc::new(Cell::new(0)),
            peak: 0,
            limit: u64::MAX,
            work: WriteWork::default(),
        }
    }
    fn admit(&mut self) -> Result<(), Refusal> {
        let index = self.calls;
        self.calls += 1;
        if self.refuse_at == Some(index) {
            Err(Refusal(index))
        } else {
            Ok(())
        }
    }
}
impl Budget for Policy {
    type Refusal = Refusal;
    fn traverse(&mut self, values: u64, bytes: u64) -> Result<(), Refusal> {
        self.admit()?;
        self.work = self.work.then::<()>(WriteWork::new(values, bytes)).unwrap();
        Ok(())
    }
}
impl Allocator for Policy {
    type Permit = Permit;
    fn allocate(&mut self, bytes: u64) -> Result<Permit, Refusal> {
        self.admit()?;
        let live = self.live.get().checked_add(bytes).unwrap();
        if live > self.limit {
            return Err(Refusal(self.calls - 1));
        }
        self.live.set(live);
        self.peak = self.peak.max(live);
        HEAP.with(|state| {
            let mut heap = state.get();
            if heap.active {
                heap.admitted_bytes = bytes;
            }
            state.set(heap);
        });
        Ok(Permit {
            bytes,
            live: self.live.clone(),
        })
    }
}

#[derive(Clone, CBOREncodable, CBORBoundedEncodable)]
struct Record {
    #[cbor(n = 256)]
    text: Vec<String>,
    #[cbor(n = 0)]
    flags: Vec<bool>,
    #[cbor(n = 24)]
    bytes: ByteString,
    #[cbor(n = 1)]
    floats: Vec<f64>,
    #[cbor(n = 23)]
    optional: Option<String>,
}
fn record() -> Record {
    Record {
        text: vec![
            "ascii".into(),
            "e\u{301}".into(),
            format!("a{}b", "\u{301}\u{316}".repeat(32)),
            "\u{1100}\u{1161}\u{11a8}".into(),
            "\u{301}".into(),
        ],
        flags: vec![true; 256],
        bytes: ByteString::new(vec![0xa5; 256]),
        floats: vec![-33554432.0, 4294967296.0, f64::NAN, -0.0, f64::INFINITY],
        optional: Some("A\u{30a}".into()),
    }
}

#[test]
fn every_preparation_admission_can_refuse_without_leaking() {
    let value = record();
    let mut baseline = Policy::new(None);
    drop(prepare(&value, &mut baseline).unwrap());
    assert_eq!(baseline.live.get(), 0);
    assert!(baseline.calls > 100);
    for at in 0..baseline.calls {
        let mut policy = Policy::new(Some(at));
        let (result, heap) = observe(None, || prepare(&value, &mut policy));
        assert_eq!(
            heap.unadmitted, 0,
            "heap request preceded admission at step {at}"
        );
        if at == 0 {
            assert_eq!(heap.calls, 0);
        }
        let error = result.err().expect("refusal must propagate");
        assert_eq!(error, BoundedError::Refused(Refusal(at)));
        assert_eq!(policy.calls, at + 1, "no further admission after refusal");
        assert_eq!(policy.live.get(), 0, "leak at admission {at}");
    }
}

#[test]
fn every_real_scratch_allocation_can_fail_after_admission() {
    let value = record();
    let mut baseline = Policy::new(None);
    let (prepared, heap) = observe(None, || prepare(&value, &mut baseline));
    drop(prepared.unwrap());
    assert!(heap.calls > 0);
    assert_eq!(heap.unadmitted, 0);
    for at in 0..heap.calls {
        let mut policy = Policy::new(None);
        let (result, heap) = observe(Some(at), || prepare(&value, &mut policy));
        assert!(heap.denied);
        assert_eq!(heap.unadmitted, 0);
        assert!(
            matches!(result, Err(BoundedError::Allocation { .. })),
            "failure {at}"
        );
        drop(result);
        assert_eq!(
            policy.live.get(),
            0,
            "permits survive allocation failure {at}"
        );
    }
}

#[test]
fn peak_live_limit_counts_old_and_new_reservations() {
    let value = record();
    let mut baseline = Policy::new(None);
    let prepared = prepare(&value, &mut baseline).unwrap();
    let peak = baseline.peak;
    assert!(peak > 0);
    drop(prepared);
    for limit in [0, peak / 2, peak - 1, peak] {
        let mut policy = Policy::new(None);
        policy.limit = limit;
        let result = prepare(&value, &mut policy);
        assert_eq!(result.is_ok(), limit == peak);
        assert!(policy.peak <= limit);
        drop(result);
        assert_eq!(policy.live.get(), 0);
    }
}

#[test]
fn every_write_refusal_preserves_guards_and_allows_retry_without_allocating() {
    let value = record();
    let symbolic = CBOR::from(value.clone()).to_cbor_data();
    let mut allocator = Policy::new(None);
    let prepared = prepare(&value, &mut allocator).unwrap();
    let len = prepared.len() as usize;
    let mut guarded = vec![0xee; len + 2];
    let mut baseline = Policy::new(None);
    let (result, heap) = observe(None, || {
        prepared.encode_into(&mut guarded[1..=len], &mut baseline)
    });
    result.unwrap();
    assert_eq!(heap.calls, 0, "writing requested real heap storage");
    assert_eq!(&guarded[1..=len], symbolic);
    assert!(prepared.write_work().covers(&baseline.work));
    for at in 0..baseline.calls {
        guarded.fill(0xee);
        let mut policy = Policy::new(Some(at));
        let (result, heap) = observe(None, || {
            prepared.encode_into(&mut guarded[1..=len], &mut policy)
        });
        assert_eq!(result, Err(BoundedError::Refused(Refusal(at))));
        assert_eq!(heap.calls, 0);
        assert_eq!(policy.calls, at + 1);
        assert_eq!((guarded[0], guarded[len + 1]), (0xee, 0xee));
        if at == 0 {
            assert!(guarded.iter().all(|b| *b == 0xee));
        }
        // A cursor is per attempt, not consumed permanently by a failed write.
        prepared
            .encode_into(&mut guarded[1..=len], &mut Policy::new(None))
            .unwrap();
        assert_eq!(&guarded[1..=len], symbolic);
    }
    drop(prepared);
    assert_eq!(allocator.live.get(), 0);
}

#[test]
fn wrong_output_size_is_rejected_before_budget_or_output_changes() {
    let value = record();
    let mut allocator = Policy::new(None);
    let prepared = prepare(&value, &mut allocator).unwrap();
    for size in [0, prepared.len() as usize - 1, prepared.len() as usize + 1] {
        let mut output = vec![0xee; size];
        let mut policy = Policy::new(Some(0));
        let result = prepared.encode_into(&mut output, &mut policy);
        assert!(matches!(result, Err(BoundedError::OutputSize { .. })));
        assert_eq!(policy.calls, 0);
        assert!(output.iter().all(|b| *b == 0xee));
    }
}

struct Underreported(WriteWork);
impl BoundedEncodable for Underreported {
    fn measure<A: Allocator>(
        &self,
        _: &mut Plan<A::Permit>,
        _: &mut A,
    ) -> BoundedResult<Measure, A> {
        Ok(Measure {
            len: 1,
            write: WriteWork::default(),
        })
    }
    fn write<P, B: Budget>(
        &self,
        _: &mut Cursor<'_, P>,
        output: &mut Output<'_>,
        budget: &mut B,
    ) -> BoundedResult<(), B> {
        budget
            .traverse(self.0.values, self.0.bytes)
            .map_err(BoundedError::Refused)?;
        output.byte(0)
    }
}
#[test]
fn understated_work_is_an_invariant_error_before_the_caller_is_charged() {
    for work in [WriteWork::new(1, 0), WriteWork::new(0, 1)] {
        let value = Underreported(work);
        let mut allocator = Policy::new(None);
        let prepared = prepare(&value, &mut allocator).unwrap();
        let mut output = [0xee];
        let mut budget = Policy::new(None);
        assert_eq!(
            prepared.encode_into(&mut output, &mut budget),
            Err(BoundedError::WorkExceeded {
                predicted: WriteWork::default(),
                attempted: work,
            })
        );
        assert_eq!(budget.calls, 0);
        assert_eq!(output, [0xee]);
    }
}

struct BadLength {
    measured: u64,
    written: usize,
}

struct CumulativeOverflow(bool);
impl BoundedEncodable for CumulativeOverflow {
    fn measure<A: Allocator>(
        &self,
        _: &mut Plan<A::Permit>,
        _: &mut A,
    ) -> BoundedResult<Measure, A> {
        Ok(Measure {
            len: 1,
            write: WriteWork::new(u64::MAX, u64::MAX),
        })
    }
    fn write<P, B: Budget>(
        &self,
        _: &mut Cursor<'_, P>,
        output: &mut Output<'_>,
        budget: &mut B,
    ) -> BoundedResult<(), B> {
        let (values, bytes) = if self.0 { (u64::MAX, 0) } else { (0, u64::MAX) };
        budget
            .traverse(values, bytes)
            .map_err(BoundedError::Refused)?;
        budget
            .traverse(u64::from(self.0), u64::from(!self.0))
            .map_err(BoundedError::Refused)?;
        output.byte(0)
    }
}

#[test]
fn cumulative_write_work_overflow_is_not_forwarded() {
    for value in [CumulativeOverflow(false), CumulativeOverflow(true)] {
        let prepared = prepare(&value, &mut Policy::new(None)).unwrap();
        let mut policy = Policy::new(None);
        let mut bytes = [0xee];
        let (result, heap) = observe(None, || prepared.encode_into(&mut bytes, &mut policy));
        assert_eq!(result, Err(BoundedError::Overflow));
        assert_eq!(policy.calls, 1);
        assert_eq!(bytes, [0xee]);
        assert_eq!(heap.calls, 0);
    }
}

#[derive(CBORBoundedEncodable)]
struct AbsentFields {
    #[cbor(n = 0)]
    a: Option<bool>,
    #[cbor(n = 1)]
    b: Option<bool>,
}

#[test]
fn absent_fields_are_admitted_even_when_nothing_is_encoded() {
    let value = AbsentFields { a: None, b: None };
    let mut allocator = Policy::new(None);
    let prepared = prepare(&value, &mut allocator).unwrap();
    assert!(
        allocator.work.values >= 3,
        "map plus both field inspections"
    );
    let mut policy = Policy::new(Some(0));
    let mut bytes = [0xee];
    assert_eq!(
        prepared.encode_into(&mut bytes, &mut policy),
        Err(BoundedError::Refused(Refusal(0)))
    );
    assert_eq!(bytes, [0xee]);
    let mut policy = Policy::new(None);
    prepared.encode_into(&mut bytes, &mut policy).unwrap();
    assert_eq!(bytes, [0xa0]);
    assert!(policy.work.values >= 3);
    assert!(prepared.write_work().covers(&policy.work));
}
impl BoundedEncodable for BadLength {
    fn measure<A: Allocator>(
        &self,
        _: &mut Plan<A::Permit>,
        _: &mut A,
    ) -> BoundedResult<Measure, A> {
        Ok(Measure::leaf(self.measured, 0))
    }
    fn write<P, B: Budget>(
        &self,
        _: &mut Cursor<'_, P>,
        output: &mut Output<'_>,
        _: &mut B,
    ) -> BoundedResult<(), B> {
        output.slice(&[0; 3][..self.written])
    }
}
#[test]
fn incorrect_lengths_fail_at_the_sink() {
    for (measured, written) in [(1, 2), (2, 1)] {
        let value = BadLength { measured, written };
        let prepared = prepare(&value, &mut Policy::new(None)).unwrap();
        let mut output = [0xee; 4];
        let result = prepared.encode_into(
            &mut output[1..1 + measured as usize],
            &mut Policy::new(None),
        );
        assert!(if written as u64 > measured {
            matches!(result, Err(BoundedError::Capacity { .. }))
        } else {
            matches!(result, Err(BoundedError::Length { .. }))
        });
        assert_eq!((output[0], output[3]), (0xee, 0xee));
    }
}

struct BadPlan(bool);
impl BoundedEncodable for BadPlan {
    fn measure<A: Allocator>(
        &self,
        plan: &mut Plan<A::Permit>,
        allocator: &mut A,
    ) -> BoundedResult<Measure, A> {
        if self.0 {
            text::measure_text("e\u{301}", plan, allocator)
        } else {
            Ok(Measure::leaf(3, 100))
        }
    }
    fn write<P, B: Budget>(
        &self,
        plan: &mut Cursor<'_, P>,
        output: &mut Output<'_>,
        budget: &mut B,
    ) -> BoundedResult<(), B> {
        if self.0 {
            output.slice(&[0x62, 0xc3, 0xa9])
        } else {
            text::write_text("e\u{301}", plan, output, budget)
        }
    }
}
#[test]
fn missing_and_unconsumed_plan_entries_are_rejected() {
    for value in [BadPlan(false), BadPlan(true)] {
        let mut allocator = Policy::new(None);
        let prepared = prepare(&value, &mut allocator).unwrap();
        assert_eq!(
            prepared.encode_into(&mut [0; 3], &mut Policy::new(None)),
            Err(BoundedError::PlanMismatch)
        );
        drop(prepared);
        assert_eq!(allocator.live.get(), 0);
    }
}

struct Huge;
impl BoundedEncodable for Huge {
    const FIXED: Option<Measure> = Some(Measure {
        len: u64::MAX,
        write: WriteWork::new(u64::MAX, 0),
    });
    fn measure<A: Allocator>(
        &self,
        _: &mut Plan<A::Permit>,
        _: &mut A,
    ) -> BoundedResult<Measure, A> {
        Ok(Self::FIXED.unwrap())
    }
    fn write<P, B: Budget>(
        &self,
        _: &mut Cursor<'_, P>,
        _: &mut Output<'_>,
        _: &mut B,
    ) -> BoundedResult<(), B> {
        panic!("overflow must stop preparation")
    }
}
#[test]
fn fixed_measure_overflow_never_reaches_writing_or_allocation() {
    let mut policy = Policy::new(None);
    assert!(matches!(
        prepare(&[Huge, Huge], &mut policy),
        Err(BoundedError::Overflow)
    ));
    assert_eq!(policy.live.get(), 0);
}

struct FalseFixed;
impl BoundedEncodable for FalseFixed {
    const FIXED: Option<Measure> = Some(Measure {
        len: 1,
        write: WriteWork::new(0, 0),
    });
    fn measure<A: Allocator>(
        &self,
        _: &mut Plan<A::Permit>,
        _: &mut A,
    ) -> BoundedResult<Measure, A> {
        Ok(Measure::leaf(1, 0))
    }
    fn write<P, B: Budget>(
        &self,
        _: &mut Cursor<'_, P>,
        output: &mut Output<'_>,
        budget: &mut B,
    ) -> BoundedResult<(), B> {
        budget.traverse(1, 0).map_err(BoundedError::Refused)?;
        output.byte(0)
    }
}

#[test]
fn false_fixed_prediction_is_enforced_when_composed() {
    let value = [FalseFixed];
    let prepared = prepare(&value, &mut Policy::new(None)).unwrap();
    let mut budget = Policy::new(None);
    let mut output = [0xee; 2];
    assert!(matches!(
        prepared.encode_into(&mut output, &mut budget),
        Err(BoundedError::WorkExceeded { .. })
    ));
    assert_eq!(
        budget.calls, 1,
        "only the admitted array visit reaches the caller"
    );
    assert_eq!(output, [0x81, 0xee]);
}

#[test]
fn heap_observer_detects_unreported_allocations() {
    // Positive control: if instrumentation is accidentally disabled, the
    // allocation-free tests must not silently become vacuous.
    let (bytes, heap) = observe(None, || std::hint::black_box(vec![7u8; 1024]));
    assert!(heap.calls > 0);
    assert!(heap.unadmitted > 0);
    assert_eq!(bytes.len(), 1024);
}

#[test]
fn already_normal_text_and_numeric_arrays_prepare_without_heap_storage() {
    let text = "ordinary NFC text".repeat(4096);
    let numbers = vec![1.5f64; 4096];
    let mut policy = Policy::new(None);
    let (result, heap) = observe(None, || prepare(&text, &mut policy));
    drop(result.unwrap());
    assert_eq!(heap.calls, 0);
    let (result, heap) = observe(None, || prepare(&numbers, &mut policy));
    drop(result.unwrap());
    assert_eq!(
        heap.calls, 0,
        "preparing numbers must not allocate per-number plans"
    );
}

#[test]
fn every_head_width_refuses_short_outputs_atomically() {
    for argument in [
        Argument::Shortest(0),
        Argument::Shortest(24),
        Argument::Shortest(256),
        Argument::Shortest(65536),
        Argument::Shortest(u64::MAX),
        Argument::Fixed8(0),
        Argument::Fixed16(1),
        Argument::Fixed32(0),
        Argument::Fixed64(0),
    ] {
        for major in [
            MajorType::Unsigned,
            MajorType::Negative,
            MajorType::ByteString,
            MajorType::Text,
            MajorType::Array,
            MajorType::Map,
            MajorType::Tagged,
            MajorType::Simple,
        ] {
            for size in 0..argument.head_len() {
                let mut guarded = [0xee; MAX_HEAD_LEN + 2];
                let mut output = Output::new(&mut guarded[1..1 + size]);
                assert!(matches!(
                    output.argument::<()>(major, argument),
                    Err(BoundedError::Capacity { .. })
                ));
                assert_eq!(output.written(), 0);
                assert!(guarded.iter().all(|b| *b == 0xee));
            }
        }
    }
}

#[test]
fn pointer_forwarding_writes_without_cloning_or_allocating() {
    fn check<T: BoundedEncodable>(value: &T) {
        let mut allocator = Policy::new(None);
        let prepared = prepare(value, &mut allocator).unwrap();
        let mut bytes = vec![0; prepared.len() as usize];
        let mut budget = Policy::new(None);
        let (result, heap) = observe(None, || prepared.encode_into(&mut bytes, &mut budget));
        result.unwrap();
        assert_eq!(heap.calls, 0);
        assert_eq!(bytes, [0x62, 0xc3, 0xa9]);
    }
    let text = "e\u{301}".to_string();
    check(&&text);
    check(&Box::new(text.clone()));
    check(&Rc::new(text.clone()));
    check(&std::sync::Arc::new(text));
}

#[test]
fn reservation_growth_holds_old_permit_until_replacement_succeeds() {
    let mut policy = Policy::new(None);
    let mut owned = Owned::<u8, Permit>::new();
    owned.push(1, &mut policy).unwrap();
    let old = policy.live.get();
    assert!(old > 0);
    // Force growth beyond the admitted capacity without assuming its size.
    let additional = usize::try_from(old).unwrap();
    let (result, heap) = observe(Some(0), || owned.reserve(additional, &mut policy));
    assert!(matches!(result, Err(BoundedError::Allocation { .. })));
    assert!(heap.denied);
    assert_eq!(policy.live.get(), old, "old storage still owns its permit");
    assert_eq!(owned.as_slice(), &[1]);
    let failed_peak = policy.peak;
    owned.reserve(additional, &mut policy).unwrap();
    let new = policy.live.get();
    assert!(new > old);
    assert!(
        failed_peak >= old + new,
        "new admission overlaps the live old reservation"
    );
    drop(owned);
    assert_eq!(policy.live.get(), 0);
}

#[test]
fn all_major_types_and_head_widths_have_literal_bytes() {
    let fixtures: &[(Argument, &[u8])] = &[
        (Argument::Shortest(23), &[0x17]),
        (Argument::Shortest(24), &[0x18, 0x18]),
        (Argument::Shortest(256), &[0x19, 0x01, 0x00]),
        (Argument::Shortest(65536), &[0x1a, 0x00, 0x01, 0x00, 0x00]),
        (
            Argument::Shortest(4294967296),
            &[0x1b, 0, 0, 0, 1, 0, 0, 0, 0],
        ),
        (Argument::Fixed8(1), &[0x18, 1]),
        (Argument::Fixed16(1), &[0x19, 0, 1]),
        (Argument::Fixed32(1), &[0x1a, 0, 0, 0, 1]),
        (Argument::Fixed64(1), &[0x1b, 0, 0, 0, 0, 0, 0, 0, 1]),
    ];
    for (major, prefix) in [
        (MajorType::Unsigned, 0x00),
        (MajorType::Negative, 0x20),
        (MajorType::ByteString, 0x40),
        (MajorType::Text, 0x60),
        (MajorType::Array, 0x80),
        (MajorType::Map, 0xa0),
        (MajorType::Tagged, 0xc0),
        (MajorType::Simple, 0xe0),
    ] {
        for &(argument, literal) in fixtures {
            let mut guarded = [0xee; MAX_HEAD_LEN + 2];
            let mut output = Output::new(&mut guarded[1..1 + literal.len()]);
            output.argument::<()>(major, argument).unwrap();
            output.finish::<()>(literal.len() as u64).unwrap();
            assert_eq!(guarded[1], literal[0] | prefix);
            assert_eq!(&guarded[2..1 + literal.len()], &literal[1..]);
            assert_eq!(guarded[0], 0xee);
            assert_eq!(guarded[1 + literal.len()], 0xee);
        }
    }
}

#[test]
fn decoder_refuses_every_admission_and_real_allocation_without_leaking() {
    use dcbor::bounded::decode::{DecodeError, decode};
    // NFC Maybe forces exact validation scratch; nesting grows the explicit
    // stack, while many siblings grow the flat node arena.
    let input = CBOR::from(vec![vec!["q\u{301}"; 12]; 4]).to_cbor_data();
    let mut baseline = Policy::new(None);
    let (result, heap) = observe(None, || decode(&input, 8, &mut baseline));
    drop(result.unwrap());
    assert_eq!(baseline.live.get(), 0);
    assert_eq!(heap.unadmitted, 0);
    assert!(heap.calls > 0);
    for at in 0..baseline.calls {
        let mut policy = Policy::new(Some(at));
        let (result, heap) = observe(None, || decode(&input, 8, &mut policy));
        assert!(
            matches!(result, Err(DecodeError::Resource(BoundedError::Refused(Refusal(n)))) if n == at)
        );
        assert_eq!(policy.calls, at + 1);
        assert_eq!(policy.live.get(), 0);
        assert_eq!(heap.unadmitted, 0);
    }
    for at in 0..heap.calls {
        let mut policy = Policy::new(None);
        let (result, heap) = observe(Some(at), || decode(&input, 8, &mut policy));
        assert!(heap.denied);
        assert_eq!(heap.unadmitted, 0);
        assert!(matches!(
            result,
            Err(DecodeError::Resource(BoundedError::Allocation { .. }))
        ));
        drop(result);
        assert_eq!(policy.live.get(), 0);
    }
}

fn extended_failures<T: BoundedEncodable>(value: &T) {
    let mut baseline = Policy::new(None);
    let (result, heap) = observe(None, || encode(value, &mut baseline));
    let expected = result.unwrap();
    assert_eq!(heap.unadmitted, 0);
    assert_eq!(baseline.live.get(), expected.as_ref().len() as u64);
    for at in 0..baseline.calls {
        let mut policy = Policy::new(Some(at));
        let (result, heap) = observe(None, || encode(value, &mut policy));
        assert!(matches!(result, Err(BoundedError::Refused(Refusal(n))) if n == at));
        assert_eq!(policy.calls, at + 1);
        assert_eq!(policy.live.get(), 0);
        assert_eq!(heap.unadmitted, 0);
    }
    for at in 0..heap.calls {
        let mut policy = Policy::new(None);
        let (result, heap) = observe(Some(at), || encode(value, &mut policy));
        assert!(heap.denied);
        assert_eq!(heap.unadmitted, 0);
        assert!(matches!(result, Err(BoundedError::Allocation { .. })));
        drop(result);
        assert_eq!(policy.live.get(), 0);
    }
    let mut policy = Policy::new(None);
    let prepared = prepare(value, &mut policy).unwrap();
    let mut bytes = vec![0; prepared.len() as usize];
    let mut budget = Policy::new(None);
    let (result, heap) = observe(None, || prepared.encode_into(&mut bytes, &mut budget));
    result.unwrap();
    assert_eq!(heap.calls, 0);
    assert_eq!(bytes, expected.as_ref());
    for at in 0..budget.calls {
        let mut budget = Policy::new(Some(at));
        let (result, heap) = observe(None, || prepared.encode_into(&mut bytes, &mut budget));
        assert_eq!(result, Err(BoundedError::Refused(Refusal(at))));
        assert_eq!(heap.calls, 0);
        prepared
            .encode_into(&mut bytes, &mut Policy::new(None))
            .unwrap();
        assert_eq!(bytes, expected.as_ref());
    }
    drop(prepared);
    assert_eq!(policy.live.get(), 0);
    drop(expected);
    assert_eq!(baseline.live.get(), 0);
}

#[test]
fn extended_encoders_and_output_owner_handle_all_resource_failures() {
    let map = std::collections::BTreeMap::from([
        ("aa", vec![Some("e\u{301}"), None]),
        ("b", vec![None, Some("q\u{301}")]),
    ]);
    extended_failures(&map);
    let value = CBOR::from(record());
    extended_failures(&value);
    extended_failures(&Tagged {
        tag: 1000,
        value: dcbor::Date::from_timestamp(0.5),
    });
    #[cfg(feature = "num-bigint")]
    extended_failures(&-(num_bigint::BigInt::from(1) << 129usize));
}
