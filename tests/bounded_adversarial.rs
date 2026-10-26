#![cfg(all(feature = "std", feature = "derive"))]
//! Black-box resource and failure tests. No normalization or encoder internals
//! are used; the allocator observes real heap requests on the test thread.
#[global_allocator]
static HEAP: heap::Heap = heap::Heap;
use core::cell::Cell;
use dcbor::bounded::encoding::{BUCKET_WINDOW, Instruction, Shape};
use dcbor::{ByteString, CBOR, CBORBoundedEncodable, CBOREncodable, bounded::*};
use dcbor_test_support::heap::{self, Observation};
use dcbor_test_support::{physical_matrix, synchronous_matrix};
use std::rc::Rc;

/// An unlimited policy refusing call `refuse_at`, reporting each admitted
/// allocation to the heap observer.
fn policy(refuse_at: Option<usize>) -> Limits {
    Limits::unlimited()
        .refusing(refuse_at)
        .observe(heap::admitted)
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

/// Require that preparing `value` fails with exactly `expected`, every heap
/// request admitted first and nothing held after.
#[track_caller]
fn refused_as(value: &dyn Schema, expected: BoundedError<LimitRefusal>) -> Limits {
    let mut policy = policy(None);
    let (result, heap) = Observation::run(None, || prepare(value, &mut policy));
    match result {
        Err(error) => assert_eq!(error, expected),
        Ok(prepared) => panic!("prepared {} bytes, expected {expected:?}", prepared.len()),
    }
    assert_eq!(heap.unadmitted, 0, "heap request preceded admission");
    assert_eq!(policy.live_bytes(), 0, "storage held after {expected:?}");
    policy
}

#[test]
fn every_preparation_admission_can_refuse_without_leaking() {
    let value = record();
    let mut baseline = policy(None);
    drop(prepare(&value, &mut baseline).unwrap());
    assert_eq!(baseline.live_bytes(), 0);
    assert!(baseline.attempts() > 100);
    synchronous_matrix("preparing a record", baseline.attempts(), |at| {
        let mut policy = policy(Some(at));
        let (result, heap) = Observation::run(None, || prepare(&value, &mut policy));
        assert_eq!(
            heap.unadmitted, 0,
            "heap request preceded admission at step {at}"
        );
        if at == 0 {
            assert_eq!(heap.calls, 0);
        }
        let error = result.err().expect("refusal must propagate");
        assert_eq!(error, BoundedError::Refused(LimitRefusal::Scheduled(at)));
        assert_eq!(
            policy.attempts(),
            at + 1,
            "no further admission after refusal"
        );
        assert_eq!(policy.live_bytes(), 0, "leak at admission {at}");
    });
}

#[test]
fn every_real_scratch_allocation_can_fail_after_admission() {
    let value = record();
    physical_matrix("preparing a record physically", |failure| {
        let mut policy = policy(None);
        let (result, heap) = Observation::run(failure, || prepare(&value, &mut policy));
        assert_eq!(heap.unadmitted, 0, "heap request preceded admission");
        match failure {
            None => drop(result.expect("the unobstructed preparation")),
            Some(at) => {
                assert_eq!(heap.denied, 1, "failure {at} was not exercised");
                assert!(
                    matches!(result, Err(BoundedError::Allocation { .. })),
                    "failure {at}"
                );
                drop(result);
            }
        }
        assert_eq!(
            policy.live_bytes(),
            0,
            "permits survive allocation failure {failure:?}"
        );
        heap.calls
    });
}

#[test]
fn peak_live_limit_counts_old_and_new_reservations() {
    let value = record();
    let mut baseline = policy(None);
    let prepared = prepare(&value, &mut baseline).unwrap();
    let peak = baseline.peak_bytes();
    assert!(peak > 0);
    drop(prepared);
    for limit in [0, peak / 2, peak - 1, peak] {
        let mut policy = Limits::new(u64::MAX, u64::MAX, limit);
        let result = prepare(&value, &mut policy);
        assert_eq!(result.is_ok(), limit == peak);
        assert!(policy.peak_bytes() <= limit);
        drop(result);
        assert_eq!(policy.live_bytes(), 0);
    }
}

#[test]
fn every_write_refusal_preserves_guards_and_allows_retry_without_allocating() {
    let value = record();
    let symbolic = CBOR::from(value.clone()).to_cbor_data();
    let mut allocator = policy(None);
    let prepared = prepare(&value, &mut allocator).unwrap();
    let len = prepared.len();
    let mut guarded = vec![0xee; len + 2];
    let mut baseline = policy(None);
    let (result, heap) = Observation::run(None, || {
        prepared.encode_into(&mut guarded[1..=len], &mut baseline)
    });
    result.unwrap();
    assert_eq!(heap.calls, 0, "writing requested real heap storage");
    assert_eq!(&guarded[1..=len], symbolic);
    let write = prepared
        .write_work::<()>()
        .expect("the write bound of a plan held in memory fits in u64");
    assert!(
        write.covers(&baseline.used()),
        "{:?} beyond {write:?}",
        baseline.used()
    );
    synchronous_matrix("writing a record's plan", baseline.attempts(), |at| {
        guarded.fill(0xee);
        let mut refusing = policy(Some(at));
        let (result, heap) = Observation::run(None, || {
            prepared.encode_into(&mut guarded[1..=len], &mut refusing)
        });
        assert_eq!(
            result,
            Err(BoundedError::Refused(LimitRefusal::Scheduled(at)))
        );
        assert_eq!(heap.calls, 0);
        assert_eq!(refusing.attempts(), at + 1);
        assert_eq!((guarded[0], guarded[len + 1]), (0xee, 0xee));
        if at == 0 {
            assert!(guarded.iter().all(|b| *b == 0xee));
        }
        // A writer is per attempt, not consumed permanently by a failed write.
        prepared
            .encode_into(&mut guarded[1..=len], &mut policy(None))
            .unwrap();
        assert_eq!(&guarded[1..=len], symbolic);
    });
    drop(prepared);
    assert_eq!(allocator.live_bytes(), 0);
}

#[test]
fn wrong_output_size_is_rejected_before_budget_or_output_changes() {
    let value = record();
    let mut allocator = policy(None);
    let prepared = prepare(&value, &mut allocator).unwrap();
    let len = prepared.len();
    for size in [0, len - 1, len + 1] {
        let mut output = vec![0xee; size];
        let mut policy = policy(Some(0));
        assert_eq!(
            prepared.encode_into(&mut output, &mut policy),
            Err(BoundedError::OutputSize {
                measured: len as u64,
                provided: size as u64,
            })
        );
        assert_eq!(policy.attempts(), 0);
        assert!(output.iter().all(|b| *b == 0xee));
    }
}

/// A source answering differently on each pass: a byte string of one byte
/// while its shape is walked, of every byte it holds once it is prepared.
struct Unstable {
    passes: Cell<usize>,
    bytes: [u8; 200],
}

impl Schema for Unstable {
    fn instruction(&self, index: usize) -> Instruction<'_> {
        if index == 0 {
            self.passes.set(self.passes.get() + 1);
        }
        let len = if self.passes.get() == 1 {
            1
        } else {
            self.bytes.len()
        };
        match index {
            0 => Instruction::Head(MajorType::ByteString, Argument::Shortest(len as u64)),
            1 => Instruction::Bytes(&self.bytes[..len]),
            _ => Instruction::End,
        }
    }
}

/// A source longer when prepared than when walked cannot grow the plan's
/// arena past the walked extent: the growth that would pass it is refused.
#[test]
fn a_source_longer_than_its_walk_is_refused_at_the_arena_cap() {
    let value = Unstable {
        passes: Cell::new(0),
        bytes: [0x5a; 200],
    };
    refused_as(&value, BoundedError::PlanMismatch);
    assert_eq!(value.passes.get(), 2, "walked once, prepared once");
}

/// A counted map whose source visits another number of fields than its head
/// carries.
struct Miscounted;

impl Schema for Miscounted {
    fn instruction(&self, index: usize) -> Instruction<'_> {
        match index {
            0 => Instruction::CountedMap(2),
            1 => Instruction::Field(0, Some(&true)),
            _ => Instruction::End,
        }
    }
}

#[test]
fn a_counted_map_visiting_another_count_is_refused_at_its_end() {
    refused_as(&Miscounted, BoundedError::PlanMismatch);
}

/// An unordered map whose entry claims to inspect a whole window past the
/// most one instruction may.
struct Leaping;

impl Schema for Leaping {
    fn instruction(&self, index: usize) -> Instruction<'_> {
        match index {
            0 => Instruction::UnorderedMap,
            1 => Instruction::Entry {
                next: 2 + BUCKET_WINDOW,
                entry: None,
            },
            _ => Instruction::End,
        }
    }
}

#[test]
fn an_entry_past_its_window_is_refused() {
    refused_as(&Leaping, BoundedError::PlanMismatch);
}

/// A source that is its own child, without end.
struct Endless;

impl Schema for Endless {
    fn instruction(&self, index: usize) -> Instruction<'_> {
        match index {
            0 => Instruction::Child(self),
            _ => Instruction::End,
        }
    }
}

/// Unbounded nesting is refused by the shape walk, before anything is
/// requested.
#[test]
fn an_endless_source_is_refused_before_any_allocation() {
    let policy = refused_as(&Endless, BoundedError::DepthLimit);
    assert_eq!(policy.requests(), 0, "the walk requested storage");
}

#[derive(CBORBoundedEncodable)]
struct AbsentFields {
    #[cbor(n = 0)]
    a: Option<bool>,
    #[cbor(n = 1)]
    b: Option<bool>,
}

/// Absent fields are inspected, for the map's counted head, when the value is
/// walked and when it is prepared; writing the encoding inspects nothing.
#[test]
fn absent_fields_are_inspected_in_preparation_and_not_when_written() {
    let value = AbsentFields { a: None, b: None };
    let mut allocator = policy(None);
    let prepared = prepare(&value, &mut allocator).unwrap();
    // Walked, then prepared: each pass its five instructions (the
    // inspection, the counted map, two fields, the end) and two presences.
    assert!(
        allocator.used().values >= 2 * (5 + 2),
        "{:?}: the inspections were not admitted",
        allocator.used()
    );
    let mut refusing = policy(Some(0));
    let mut bytes = [0xee];
    assert_eq!(
        prepared.encode_into(&mut bytes, &mut refusing),
        Err(BoundedError::Refused(LimitRefusal::Scheduled(0)))
    );
    assert_eq!(bytes, [0xee]);
    let mut admitting = policy(None);
    prepared.encode_into(&mut bytes, &mut admitting).unwrap();
    assert_eq!(bytes, [0xa0]);
    // One segment of the head's byte, then the completion.
    assert_eq!(admitting.used(), WriteWork::new(2, 1));
    let write = prepared
        .write_work::<()>()
        .expect("the write bound of a plan held in memory fits in u64");
    assert!(write.covers(&admitting.used()));
}

#[test]
fn heap_observer_detects_unreported_allocations() {
    // Positive control: if instrumentation is accidentally disabled, the
    // allocation-free tests must not silently become vacuous.
    let (bytes, heap) = Observation::run(None, || std::hint::black_box(vec![7u8; 1024]));
    assert!(heap.calls > 0);
    assert!(heap.unadmitted > 0);
    assert_eq!(bytes.len(), 1024);
}

/// The heap requests of preparing `value`, all admitted.
fn requests(value: &dyn Schema) -> (usize, usize) {
    let mut policy = policy(None);
    let (result, heap) = Observation::run(None, || prepare(value, &mut policy));
    drop(result.unwrap());
    assert_eq!(heap.unadmitted, 0);
    assert_eq!(policy.live_bytes(), 0);
    (heap.calls, policy.requests())
}

/// Text the quick check proves normal is copied as it is, and numbers are
/// appended head by head: each prepares with exactly the requests of a byte
/// string of the same encoded length, the plan's own arenas, nothing per
/// text or per number.
#[test]
fn already_normal_text_and_numeric_arrays_request_only_the_plan() {
    let text = "ordinary NFC text".repeat(4096);
    let numbers = vec![1.5f64; 4096];
    let numbers_len = CBOR::from(numbers.clone()).to_cbor_data().len();
    // The array's head and the byte string's are both three bytes.
    let numbers_peer = ByteString::new(vec![0; numbers_len - 3]);
    let text_peer = ByteString::new(text.as_bytes());
    assert_eq!(requests(&text), requests(&text_peer), "the text allocated");
    assert_eq!(
        requests(&numbers),
        requests(&numbers_peer),
        "preparing numbers allocated per number"
    );
}

/// A head alone, as a source.
struct HeadOnly(MajorType, Argument);

impl Schema for HeadOnly {
    fn instruction(&self, index: usize) -> Instruction<'_> {
        match index {
            0 => Instruction::Head(self.0, self.1),
            _ => Instruction::End,
        }
    }
}

const MAJORS: [(MajorType, u8); 8] = [
    (MajorType::Unsigned, 0x00),
    (MajorType::Negative, 0x20),
    (MajorType::ByteString, 0x40),
    (MajorType::Text, 0x60),
    (MajorType::Array, 0x80),
    (MajorType::Map, 0xa0),
    (MajorType::Tagged, 0xc0),
    (MajorType::Simple, 0xe0),
];

#[test]
fn every_head_width_refuses_wrong_outputs_atomically() {
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
        for (major, _) in MAJORS {
            let prepared = prepare(&HeadOnly(major, argument), &mut policy(None)).unwrap();
            let len = argument.head_len();
            assert_eq!(prepared.len(), len, "{major:?} {argument:?}");
            for size in (0..len).chain([len + 1]) {
                let mut guarded = [0xee; MAX_HEAD_LEN + 3];
                let mut budget = policy(None);
                assert_eq!(
                    prepared.encode_into(&mut guarded[1..1 + size], &mut budget),
                    Err(BoundedError::OutputSize {
                        measured: len as u64,
                        provided: size as u64,
                    }),
                    "{major:?} {argument:?} into {size} bytes"
                );
                assert_eq!(budget.attempts(), 0);
                assert!(guarded.iter().all(|b| *b == 0xee));
            }
        }
    }
}

#[test]
fn pointer_forwarding_writes_without_cloning_or_allocating() {
    fn check<T: Schema>(value: &T) {
        let mut allocator = policy(None);
        let prepared = prepare(value, &mut allocator).unwrap();
        let mut bytes = vec![0; prepared.len()];
        let mut budget = policy(None);
        let (result, heap) =
            Observation::run(None, || prepared.encode_into(&mut bytes, &mut budget));
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
    let mut policy = policy(None);
    let mut owned = Owned::<u8, Reservation>::new();
    owned.push(1, &mut policy).unwrap();
    let old = policy.live_bytes();
    assert!(old > 0);
    // Force growth beyond the admitted capacity without assuming its size.
    let additional = usize::try_from(old).unwrap();
    let (result, heap) = Observation::run(Some(0), || owned.reserve(additional, &mut policy));
    assert!(matches!(result, Err(BoundedError::Allocation { .. })));
    assert_eq!(heap.denied, 1);
    assert_eq!(
        policy.live_bytes(),
        old,
        "old storage still owns its permit"
    );
    assert_eq!(owned.as_slice(), &[1]);
    let failed_peak = policy.peak_bytes();
    owned.reserve(additional, &mut policy).unwrap();
    let new = policy.live_bytes();
    assert!(new > old);
    assert!(
        failed_peak >= old + new,
        "new admission overlaps the live old reservation"
    );
    drop(owned);
    assert_eq!(policy.live_bytes(), 0);
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
    for (major, prefix) in MAJORS {
        for &(argument, literal) in fixtures {
            let mut limits = policy(None);
            let encoded = encode(&HeadOnly(major, argument), &mut limits).unwrap();
            let mut expected = literal.to_vec();
            expected[0] |= prefix;
            assert_eq!(encoded.as_ref(), expected, "{major:?} {argument:?}");
            drop(encoded);
            assert_eq!(limits.live_bytes(), 0);
        }
    }
}

#[test]
fn decoder_refuses_every_admission_and_real_allocation_without_leaking() {
    use dcbor::bounded::decode::{DecodeError, decode};
    // NFC Maybe forces exact validation scratch; nesting grows the explicit
    // stack, while many siblings grow the flat node arena.
    let input = CBOR::from(vec![vec!["q\u{301}"; 12]; 4]).to_cbor_data();
    let mut baseline = policy(None);
    drop(decode(&input, 8, &mut baseline).unwrap());
    assert_eq!(baseline.live_bytes(), 0);
    synchronous_matrix("decoding nested texts", baseline.attempts(), |at| {
        let mut policy = policy(Some(at));
        let (result, heap) = Observation::run(None, || decode(&input, 8, &mut policy));
        assert!(matches!(
            result,
            Err(DecodeError::Resource(BoundedError::Refused(LimitRefusal::Scheduled(n)))) if n == at
        ));
        assert_eq!(policy.attempts(), at + 1);
        assert_eq!(policy.live_bytes(), 0);
        assert_eq!(heap.unadmitted, 0);
    });
    physical_matrix("decoding nested texts physically", |failure| {
        let mut policy = policy(None);
        let (result, heap) = Observation::run(failure, || decode(&input, 8, &mut policy));
        assert_eq!(heap.unadmitted, 0);
        match failure {
            None => drop(result.expect("the unobstructed decode")),
            Some(at) => {
                assert_eq!(heap.denied, 1, "failure {at} was not exercised");
                assert!(matches!(
                    result,
                    Err(DecodeError::Resource(BoundedError::Allocation { .. }))
                ));
                drop(result);
            }
        }
        assert_eq!(policy.live_bytes(), 0);
        heap.calls
    });
}

/// Encoding `value` survives every refusal and every physical allocation
/// failure without leaking; the published encoding holds the plan's arena,
/// at least its bytes and within its bound; writing the same plan into
/// caller storage survives every refusal without allocating.
fn extended_failures<T: Schema + ?Sized>(name: &str, value: &T) {
    let source: &dyn Schema = &value;
    let shape = Shape::of(source, &mut Limits::unlimited()).expect("the source is walkable");
    let bound = encode_bound::<Reservation, ()>(shape).expect("the bound fits in u64");
    let mut baseline = policy(None);
    let (result, heap) = Observation::run(None, || encode(value, &mut baseline));
    let expected = result.unwrap();
    assert_eq!(heap.unadmitted, 0);
    let held = baseline.live_bytes();
    let len = expected.as_ref().len() as u64;
    assert!(
        len <= held && held <= bound.retained,
        "{len} encoded bytes held in {held}, bounded by {}",
        bound.retained
    );
    synchronous_matrix(&format!("encoding {name}"), baseline.attempts(), |at| {
        let mut policy = policy(Some(at));
        let (result, heap) = Observation::run(None, || encode(value, &mut policy));
        assert!(
            matches!(result, Err(BoundedError::Refused(LimitRefusal::Scheduled(n))) if n == at)
        );
        assert_eq!(policy.attempts(), at + 1);
        assert_eq!(policy.live_bytes(), 0);
        assert_eq!(heap.unadmitted, 0);
    });
    physical_matrix(&format!("encoding {name} physically"), |failure| {
        let mut policy = policy(None);
        let (result, heap) = Observation::run(failure, || encode(value, &mut policy));
        assert_eq!(heap.unadmitted, 0);
        match failure {
            None => assert_eq!(
                result.expect("the unobstructed encoding").as_ref(),
                expected.as_ref()
            ),
            Some(at) => {
                assert_eq!(heap.denied, 1, "failure {at} was not exercised");
                assert!(matches!(result, Err(BoundedError::Allocation { .. })));
            }
        }
        assert_eq!(policy.live_bytes(), 0);
        heap.calls
    });
    let mut allocator = policy(None);
    let prepared = prepare(value, &mut allocator).unwrap();
    let mut bytes = vec![0; prepared.len()];
    let mut budget = policy(None);
    let (result, heap) = Observation::run(None, || prepared.encode_into(&mut bytes, &mut budget));
    result.unwrap();
    assert_eq!(heap.calls, 0);
    assert_eq!(bytes, expected.as_ref());
    synchronous_matrix(&format!("writing {name}'s plan"), budget.attempts(), |at| {
        let mut budget = policy(Some(at));
        let (result, heap) =
            Observation::run(None, || prepared.encode_into(&mut bytes, &mut budget));
        assert_eq!(
            result,
            Err(BoundedError::Refused(LimitRefusal::Scheduled(at)))
        );
        assert_eq!(heap.calls, 0);
        prepared.encode_into(&mut bytes, &mut policy(None)).unwrap();
        assert_eq!(bytes, expected.as_ref());
    });
    drop(prepared);
    assert_eq!(allocator.live_bytes(), 0);
    drop(expected);
    assert_eq!(baseline.live_bytes(), 0);
}

#[test]
fn extended_encoders_and_output_owner_handle_all_resource_failures() {
    let map = std::collections::BTreeMap::from([
        ("aa", vec![Some("e\u{301}"), None]),
        ("b", vec![None, Some("q\u{301}")]),
    ]);
    extended_failures("an ordered map", &map);
    let value = CBOR::from(record());
    extended_failures("a symbolic record", &value);
    extended_failures(
        "a tagged date",
        &Tagged {
            tag: 1000,
            value: dcbor::Date::from_timestamp(0.5),
        },
    );
    #[cfg(feature = "num-bigint")]
    extended_failures(
        "a negative bignum",
        &-(num_bigint::BigInt::from(1) << 129usize),
    );
}
