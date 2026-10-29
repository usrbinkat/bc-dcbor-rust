//! Each owned copy whose storage the heap refuses: the typed decoder's text
//! and byte-string copies and an array's elements' storage, the string
//! decoder's buffer, and an encoding written into storage its own call
//! allocates. The refused request is the copy's own, the last physical
//! request each makes. It is reported as the failure of an allocation of
//! exactly the copy's length, and nothing admitted for it is still held.
#[global_allocator]
static HEAP: heap::Heap = heap::Heap;
use dcbor::bounded::decode::string_cursor::{Phase, StringDecoder};
use dcbor::bounded::decode::{BoundedDecodable, DecodeError, Options, decode_typed};
use dcbor::bounded::encoding::Preparation;
use dcbor::bounded::{BoundedError, LimitRefusal, Limits, Reservation, Step, WriteWork};
use dcbor::{ByteString, CBOR};
use dcbor_test_support::{self as support, heap};

/// `wire` decoded as `T` under one level of nesting, an array of scalars at
/// most, its value dropped: the physical requests made and the result,
/// failing request `fail_at`.
fn typed<T: BoundedDecodable>(
    wire: &[u8],
    fail_at: Option<usize>,
) -> (Result<(), DecodeError<LimitRefusal>>, heap::Stats, Limits) {
    let mut limits = Limits::unlimited();
    let (result, stats) = heap::Observation::run(fail_at, || {
        decode_typed::<T, _>(wire, 1, &mut limits).map(drop)
    });
    (result, stats, limits)
}

/// The typed decoder's copy, the last request after the document's arena
/// and the copy's permit record, refused: an allocation failure of the
/// copy's length, the document and the permit released.
fn refused_copy<T: BoundedDecodable>(wire: &[u8], len: u64) {
    let (clean, stats, _) = typed::<T>(wire, None);
    assert!(clean.is_ok(), "{clean:?}");
    assert!(stats.calls > 0, "the decode made no physical request");
    let (refused, stats, limits) = typed::<T>(wire, Some(stats.calls - 1));
    assert_eq!(stats.denied, 1);
    assert!(
        matches!(
            refused,
            Err(DecodeError::Resource(BoundedError::Allocation { bytes })) if bytes == len
        ),
        "{refused:?}"
    );
    assert_eq!(limits.live_bytes(), 0);
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
    StringDecoder<'w, Reservation>,
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

/// An encoding written into storage its call allocates: its one physical
/// request is that storage. Refused, it is an allocation failure of the
/// encoding's length, made before anything is admitted.
#[test]
fn an_owned_encoding_the_heap_refuses_fails_at_its_length() {
    assert!(heap::installed());
    let source = "z".repeat(100);
    let mut m = Limits::unlimited();
    let plan = support::drive_within(
        &mut m,
        &mut Preparation::new(&source),
        support::prepare_turns(support::shape(&source)),
    )
    .expect("an unlimited preparation completes");
    let expected = CBOR::from(source.as_str()).to_cbor_data();
    let mut budget = Limits::unlimited();
    let (clean, stats) = heap::Observation::run(None, || {
        plan.encode_owned((), &mut budget)
            .map(|encoded| encoded.as_ref() == expected.as_slice())
    });
    assert!(matches!(clean, Ok(true)), "{clean:?}");
    assert_eq!(stats.calls, 1);
    let mut budget = Limits::unlimited();
    let (refused, stats) =
        heap::Observation::run(Some(0), || plan.encode_owned((), &mut budget).map(drop));
    assert_eq!(stats.denied, 1);
    assert!(
        matches!(refused, Err(BoundedError::Allocation { bytes }) if bytes == expected.len() as u64),
        "{refused:?}"
    );
    assert_eq!(budget.used(), WriteWork::default());
}
