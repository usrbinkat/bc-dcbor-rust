//! Physical heap tests over the shared observer: every real allocation of a
//! retained decode, normalization and storage growth can fail, and failure,
//! retirement and drain release physical storage and reservations exactly
//! without allocating.
use super::bindings::text_encoder;
use super::harness::*;
use super::heap::Observation;
use super::support::{
    self, Fault, allowed, drive_faulted, physical_matrix, refusal_matrix, refuse, rigor::rigor,
};
use dcbor::bounded::decode::construction::{
    Borrowed, DecodeOwner, TypedDecoder, TypedValue,
    in_place::{StableOption, Transferable},
};
use dcbor::bounded::decode::{DecodeError, Options};
use dcbor::bounded::{BoundedError, Encoded, Reservation};

type Decoded<'s, T> = Result<TypedValue<'s, Borrowed<'s>, T, Limits>, DecodeError<LimitRefusal>>;

/// Open a scope over `wire` unobserved, then decode `T` in an armed window of
/// `observer`.
fn decoded<'s, T: Transferable<Limits> + 's>(
    m: &mut Limits,
    wire: &'s [u8],
    observer: &Observation,
) -> (DecodeOwner<'s, Limits>, Decoded<'s, T>) {
    observer.stop();
    let (owner, input) = support::open(m, wire);
    let result = observer.window(|| support::decode::<_, T>(m, input, Options::normalizing(8)));
    (owner, result)
}

/// After cleanup: no physical request since `calls`, nothing observed live,
/// every request admitted, and complete bookkeeping.
fn cleaned(observer: &Observation, calls: usize) {
    let stats = observer.snapshot();
    assert_eq!(stats.calls, calls, "cleanup allocated");
    assert_eq!(stats.live, 0);
    assert_eq!(stats.unadmitted, 0);
    assert!(!stats.overflow);
}

/// Every physical allocation of decoding `wire` as `T`, failed in turn. The
/// baseline publishes a value `check` accepts, within its reservations;
/// retirement and drain are observed and allocate nothing. Every failure is an
/// allocation error whose cleanup allocates nothing and recovers every byte
/// and reservation.
fn allocation_matrix<T: Transferable<Limits> + 'static>(wire: &[u8], check: impl Fn(&T)) {
    let name = format!("decode physically of {}", core::any::type_name::<T>());
    physical_matrix(&name, |failure| {
        let mut m = meter();
        let observer = Observation::begin(failure);
        let (mut owner, result) = decoded::<T>(&mut m, wire, &observer);
        match failure {
            None => {
                let value = result.expect("baseline decode");
                check(value.value());
                let published = observer.snapshot();
                assert!(published.calls > 0 && !published.overflow);
                assert_eq!(published.unadmitted, 0);
                assert!(published.live <= m.live_bytes() as usize);
                assert!(published.peak <= m.peak_bytes() as usize);
                observer.window(|| drop(value));
                let queued = observer.snapshot();
                assert_eq!(
                    (queued.calls, queued.live),
                    (published.calls, published.live),
                    "retirement allocated or released synchronously"
                );
                observer.window(|| support::drain(&mut owner, &mut m));
                cleaned(&observer, published.calls);
                assert_eq!(m.live_bytes(), 0);
                published.calls
            }
            Some(index) => {
                assert!(
                    matches!(
                        result,
                        Err(DecodeError::Resource(BoundedError::Allocation { .. }))
                    ),
                    "allocation {index} did not fail the decode"
                );
                observer.window(|| drop(result));
                let failed = observer.snapshot();
                assert_eq!(failed.denied, 1, "allocation {index} never intercepted");
                observer.window(|| support::drain(&mut owner, &mut m));
                cleaned(&observer, failed.calls);
                assert_eq!(m.live_bytes(), 0);
                failed.calls
            }
        }
    });
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
    let text = "q\u{301}\u{1f600}".repeat(64);
    allocation_matrix::<String>(&text_wire(&text), |value| assert_eq!(*value, text));
}

#[test]
fn stable_optional_acquisitions_fail_physically_and_cleanup_never_allocates() {
    allocation_matrix::<StableOption<String, Limits>>(&[0x63, b'q', 0xcc, 0x81], |value| {
        assert_eq!(value.as_ref().map(String::as_str), Some("q\u{301}"));
    });
}

/// A typed decode of a literal vector of texts under the fault matrix, its
/// heap observed: constructing the decoder allocates nothing; wherever a
/// refusal cancels it (each turn begins with an admission, so every turn
/// boundary is among them), dropping it there allocates nothing and
/// releases nothing synchronously, and the drain allocates nothing and
/// releases everything; a resumed decode publishes the literal value.
#[test]
fn every_public_decoder_cancellation_transfers_custody_without_allocating() {
    // Literal ["q\u{301}", "b"] crosses parser, normalizer, document transfer,
    // vector child construction and pre-publication cleanup boundaries.
    let wire = [0x82, 0x63, b'q', 0xcc, 0x81, 0x61, b'b'];
    refusal_matrix(
        "typed decode of a text vector, observed",
        rigor(),
        |fault: Fault| {
            let mut m = meter();
            let observer = Observation::begin(None);
            observer.stop();
            let (mut owner, input) = support::open(&mut m, &wire);
            // The decode alone is under test: the scope and input are setup.
            m.measure();
            refuse(&mut m, fault.refusal);
            let mut decoder = observer.window(|| {
                TypedDecoder::<_, Vec<String>, Limits>::new(input, Options::normalizing(8))
            });
            assert_eq!(observer.snapshot().calls, 0, "constructors allocated");
            let turns = allowed(&m, typed_turns::<Vec<String>>(wire.len()));
            let value = observer
                .window(|| drive_faulted(&mut m, &mut decoder, turns, fault.cancel))
                .expect("a literal vector of texts decodes");
            let calls = support::RefusalRun::of(&m);
            if let Some(value) = &value {
                assert_eq!(value.value(), &["q\u{301}", "b"]);
            }
            let before = observer.snapshot();
            observer.window(|| drop(decoder));
            observer.window(|| drop(value));
            let queued = observer.snapshot();
            assert_eq!(
                (queued.calls, queued.live),
                (before.calls, before.live),
                "retirement allocated or released synchronously"
            );
            observer.window(|| support::drain(&mut owner, &mut m));
            cleaned(&observer, before.calls);
            assert_eq!(m.live_bytes(), 0);
            calls
        },
    );
}

/// Encode `source` in an armed window of `observer`. A terminal failure is
/// followed by the encoder's own cleanup, also observed. Returns the outcome
/// and the policy holding any output's reservation.
fn encoded(
    source: &str,
    observer: &Observation,
) -> (
    Result<Encoded<Reservation>, BoundedError<LimitRefusal>>,
    Limits,
) {
    observer.stop();
    let mut m = meter();
    let bound = normalize_turns(source);
    let mut encoder = text_encoder(source);
    let result = observer.window(|| support::drive_within(&mut m, &mut encoder, bound));
    if result.is_err() {
        observer.window(|| support::finish_within(&mut m, &mut encoder, bound));
    }
    let held = m.live_bytes();
    drop(encoder);
    assert_eq!(
        m.live_bytes(),
        held,
        "retiring the encoder released storage synchronously"
    );
    (result, m)
}

#[test]
fn every_real_normalization_and_output_allocation_can_fail_without_leaking() {
    let source = format!("q{}", "\u{301}\u{316}".repeat(64));
    let expected = text_wire(&format!(
        "q{}{}",
        "\u{316}".repeat(64),
        "\u{301}".repeat(64)
    ));
    physical_matrix("text encoding physically", |failure| {
        let observer = Observation::begin(failure);
        let (output, pool) = encoded(&source, &observer);
        let measured = observer.snapshot();
        assert!(!measured.overflow);
        assert_eq!(measured.unadmitted, 0);
        match failure {
            None => {
                let output = output.expect("baseline encoding failed");
                assert_eq!(output.as_ref(), expected);
                assert!(measured.calls > 0);
                assert!(measured.live <= pool.live_bytes() as usize);
                assert!(measured.peak <= pool.peak_bytes() as usize);
                drop(output);
            }
            Some(index) => {
                assert_eq!(
                    measured.denied, 1,
                    "physical failure {index} was not exercised"
                );
                assert!(
                    matches!(output, Err(BoundedError::Allocation { .. })),
                    "physical failure {index} did not fail the encoding"
                );
            }
        }
        assert_eq!(observer.snapshot().live, 0);
        assert_eq!(pool.live_bytes(), 0);
        measured.calls
    });
}

#[test]
fn physical_growth_failure_preserves_old_bytes_and_their_reservation() {
    use dcbor::bounded::Owned;
    let mut m = meter();
    let observer = Observation::begin(None);
    let mut bytes = Owned::new();
    bytes.push(7u8, &mut m).unwrap();
    observer.stop();
    let old = observer.snapshot().live;
    let held = m.live_bytes();
    assert!(old > 0 && old <= held as usize);
    // Re-arm the same observation, retaining the old allocation registry.
    observer.fail_next();
    let result = bytes.reserve(4096, &mut m);
    observer.stop();
    assert!(matches!(result, Err(BoundedError::Allocation { .. })));
    assert_eq!(observer.snapshot().denied, 1);
    assert_eq!(bytes.as_slice(), &[7]);
    assert_eq!(observer.snapshot().live, old);
    assert_eq!(m.live_bytes(), held);
    drop(bytes);
    assert_eq!(observer.snapshot().live, 0);
    assert_eq!(m.live_bytes(), 0);
}

#[cfg(feature = "derive")]
#[test]
fn derived_nested_values_release_every_failed_physical_allocation() {
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
    allocation_matrix::<Record>(&wire, |value| {
        assert_eq!(value.first, "a");
        assert_eq!(value.nested[0], ["b", "c"]);
        assert_eq!(value.nested[1], ["d"]);
    });
}
