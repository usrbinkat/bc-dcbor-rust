//! Each owned copy whose storage the heap refuses: the typed decoder's text
//! and byte-string copies and an array's elements' storage, the string
//! decoder's buffer, and an encoding written into storage its own call
//! allocates. Each refused request is reported as the failure of an
//! allocation of exactly its own size, the copy's among them at exactly the
//! copy's length, and nothing admitted for it is still held.
#[global_allocator]
static HEAP: heap::Heap = heap::Heap;
use dcbor::bounded::decode::construction::in_place::Transferable;
use dcbor::bounded::decode::string_cursor::{Phase, StringDecoder};
use dcbor::bounded::decode::{DecodeError, Options, decode_typed};
use dcbor::bounded::encoding::{Preparation, Prepared};
use dcbor::bounded::{
    BoundedError, Encoded, Family, LimitRefusal, Limits, Reservation, Step, WriteWork,
};
use dcbor::{ByteString, CBOR};
use dcbor_test_support::{self as support, Retirement, heap, pipeline::Unwitnessed};

thread_local! {
    static RELEASE_STATE: std::cell::Cell<(usize, usize)> = const { std::cell::Cell::new((0, 0)) };
}

/// Observe physical storage at permit release without disarming the test's
/// existing heap observation or allocating from inside the release callback.
fn output_released(_: u64) {
    let observation = std::mem::ManuallyDrop::new(heap::Observation);
    let live = observation.snapshot().live;
    RELEASE_STATE.with(|state| {
        let (calls, maximum) = state.get();
        state.set((calls + 1, maximum.max(live)));
    });
}

/// Keep setup custody recorded outside the encoding's physical observation.
fn prepared(source: &str, body: impl FnOnce(&Prepared<Reservation>)) {
    support::recorded_run(|run| {
        let policy = run.policy(u64::MAX);
        run.holding(
            Preparation::new(&source),
            Retirement::Released,
            &Unwitnessed,
            |preparation| {
                preparation.drive(
                    policy,
                    support::prepare_turns(support::shape(&source)),
                    Retirement::Released,
                    |plan| body(plan.value()),
                )
            },
        )?;
        run.with_policy(policy, |m| assert_eq!(m.live_bytes(), 0));
        Ok(())
    });
}

#[test]
fn an_owned_encoding_frees_storage_before_its_permit_on_every_refusal() {
    assert!(heap::installed());
    let source = "z".repeat(100);
    prepared(&source, |plan| {
        let mut clean = Limits::unlimited();
        drop(
            plan.encode_owned(&mut clean)
                .expect("an unlimited emission completes"),
        );
        for at in 0..clean.attempts() {
            RELEASE_STATE.with(|state| state.set((0, 0)));
            let mut budget = Limits::unlimited()
                .observe(heap::admitted)
                .observe_releases(output_released);
            budget.fail_call(Some((at, LimitRefusal::Scheduled(at))));
            let (result, stats) =
                heap::Observation::run(None, || plan.encode_owned(&mut budget).map(drop));
            assert!(
                matches!(result, Err(BoundedError::Refused(LimitRefusal::Scheduled(n))) if n == at)
            );
            assert_eq!(stats.live, 0, "attempt {at}: physical storage remains");
            assert!(!stats.overflow, "attempt {at}: physical evidence lost");
            assert_eq!(stats.unadmitted, 0, "attempt {at}: unadmitted allocation");
            assert_eq!(budget.live_bytes(), 0, "attempt {at}: permit remains");
            RELEASE_STATE.with(|state| {
                let (releases, live) = state.get();
                assert_eq!(releases, stats.calls, "attempt {at}: release count");
                assert_eq!(
                    live, 0,
                    "attempt {at}: permit released before physical storage"
                );
            });
        }
    });
}

/// `wire` decoded as `T` under one level of nesting, an array of scalars at
/// most, its value dropped: the physical requests made and the result,
/// failing request `fail_at`.
fn typed<T: Transferable<Limits> + 'static>(
    wire: &[u8],
    fail_at: Option<usize>,
) -> (Result<(), DecodeError<LimitRefusal>>, heap::Stats, Limits) {
    let mut limits = Limits::unlimited();
    let (result, stats) = heap::Observation::run(fail_at, || {
        decode_typed::<T, _>(wire, 1, &mut limits).map(drop)
    });
    (result, stats, limits)
}

/// Every physical request of the typed decode refused in turn: each an
/// allocation failure, everything released, and the copy's, of the copy's
/// length, among them. The retained decode requests its scope, the copied
/// input, the document and the value's records and storage, so the copy is
/// not its last request (an array's element records follow its storage).
fn refused_copy<T: Transferable<Limits> + 'static>(wire: &[u8], len: u64) {
    let (clean, stats, _) = typed::<T>(wire, None);
    assert!(clean.is_ok(), "{clean:?}");
    assert!(stats.calls > 0, "the decode made no physical request");
    let mut copy = false;
    for at in 0..stats.calls {
        let (refused, stats, limits) = typed::<T>(wire, Some(at));
        assert_eq!(stats.denied, 1, "request {at}");
        match refused {
            Err(DecodeError::Resource(BoundedError::Allocation { bytes })) => copy |= bytes == len,
            other => panic!("request {at}: {other:?}"),
        }
        assert_eq!(limits.live_bytes(), 0, "request {at}");
    }
    assert!(copy, "no refused request was the copy's, of {len} bytes");
}

#[test]
fn a_typed_copy_the_heap_refuses_fails_at_its_length() {
    assert!(heap::installed());
    refused_copy::<String>(&CBOR::from("x".repeat(100).as_str()).to_cbor_data(), 100);
    refused_copy::<ByteString>(
        &CBOR::from(ByteString::from(vec![0x5a; 100])).to_cbor_data(),
        100,
    );
    // Three integers: their elements' storage, requested whole before any
    // element is built; integers allocate nothing after it.
    refused_copy::<Vec<u64>>(
        &CBOR::from(vec![1u64, 2, 3]).to_cbor_data(),
        3 * size_of::<u64>() as u64,
    );
}

/// `wire` decoded into an owned string, failing physical request `fail_at`:
/// the requests made, the result, and the decoder after it.
fn string<'w>(
    wire: &'w [u8],
    fail_at: Option<usize>,
) -> (
    Result<usize, DecodeError<LimitRefusal>>,
    heap::Stats,
    Limits,
    StringDecoder<'w, Reservation, Family>,
) {
    let turns = support::string_turns(wire.len());
    let mut limits = Limits::unlimited();
    let mut decoder = StringDecoder::new(wire, Options::normalizing(0));
    let (result, stats) = heap::Observation::run(fail_at, || {
        for _ in 0..turns {
            match decoder.step(&mut limits)? {
                Step::Progress => {}
                Step::Complete(string) => return Ok(string.value().len()),
                Step::Finished => panic!("finished without a string"),
            }
        }
        panic!("the string decode exceeded {turns} turns");
    });
    (result, stats, limits, decoder)
}

/// The string decoder's buffer, its last request, refused: an allocation
/// failure of the text's length; the decoder is finished, its document and
/// the buffer's permit released.
#[test]
fn a_string_buffer_the_heap_refuses_fails_at_its_length() {
    assert!(heap::installed());
    let wire = CBOR::from("y".repeat(100).as_str()).to_cbor_data();
    let (clean, stats, _, _) = string(&wire, None);
    assert!(matches!(clean, Ok(100)), "{clean:?}");
    let (refused, stats, mut limits, mut decoder) = string(&wire, Some(stats.calls - 1));
    assert_eq!(stats.denied, 1);
    assert!(
        matches!(
            refused,
            Err(DecodeError::Resource(BoundedError::Allocation {
                bytes: 100
            }))
        ),
        "{refused:?}"
    );
    assert_eq!(decoder.position().phase, Phase::Finished);
    assert_eq!(limits.live_bytes(), 0);
    assert!(matches!(decoder.step(&mut limits), Ok(Step::Finished)));
}

/// An encoding written into storage its call requests from its policy and
/// allocates: its one physical request is that storage. Refused, it is an
/// allocation failure of the encoding's length, made after only the
/// storage's release was admitted, forfeited, and the permit the policy
/// granted for it is released.
#[test]
fn an_owned_encoding_the_heap_refuses_fails_at_its_length() {
    assert!(heap::installed());
    let source = "z".repeat(100);
    prepared(&source, |plan| {
        let expected = CBOR::from(source.as_str()).to_cbor_data();
        let mut budget = Limits::unlimited();
        let (clean, stats) = heap::Observation::run(None, || {
            plan.encode_owned(&mut budget)
                .map(|encoded| encoded.as_ref() == expected.as_slice())
        });
        assert!(matches!(clean, Ok(true)), "{clean:?}");
        assert_eq!(stats.calls, 1);
        assert_eq!(budget.requested_bytes(), expected.len() as u64);
        let mut budget = Limits::unlimited();
        let (refused, stats) =
            heap::Observation::run(Some(0), || plan.encode_owned(&mut budget).map(drop));
        assert_eq!(stats.denied, 1);
        assert!(
            matches!(refused, Err(BoundedError::Allocation { bytes }) if bytes == expected.len() as u64),
            "{refused:?}"
        );
        assert_eq!(
            budget.used(),
            WriteWork::new(1, size_of::<Encoded<Reservation>>() as u64),
            "only the release of the published record was admitted"
        );
        assert_eq!(budget.requested_bytes(), expected.len() as u64);
        assert_eq!(budget.live_bytes(), 0, "the granted permit is released");
    });
}
