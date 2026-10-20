use super::bindings::string_driver;
use super::driver::{Step, finish};
use super::harness::*;
use dcbor::bounded::decode::{BoundedDecodable, DecodeError, decode, decode_typed};
use dcbor::bounded::{BoundedError, Owned};

#[test]
fn input_parser_fields_and_output_have_separate_observed_lifetimes() {
    let text = "q\u{301}😀".repeat(64);
    let wire = text_wire(&text);
    let pool = Pool::new(1024 * 1024);
    // Input storage is consumer-owned in the current borrowed-input API.
    let input_owner = pool.reserve(wire.len() as u64).unwrap();
    let input_live = pool.live();
    assert_eq!(input_live, wire.len() as u64);
    let mut parser = Meter::new(pool.clone());
    let document = decode(&wire, 8, &mut parser).unwrap();
    let parsed_live = pool.live();
    assert!(parsed_live > input_live);
    let mut constructor = Meter::new(pool.clone());
    let mut output_permits = Owned::new();
    let value = String::construct(document.root(), &mut output_permits, &mut constructor).unwrap();
    let constructed_live = pool.live();
    assert!(constructed_live >= parsed_live + text.len() as u64);
    assert_eq!(value, text);
    drop(document);
    assert_eq!(pool.live(), constructed_live - (parsed_live - input_live));
    drop(parser);
    drop(constructor);
    assert_eq!(pool.live(), constructed_live - (parsed_live - input_live));
    drop(wire);
    drop(input_owner);
    assert!(pool.live() >= text.len() as u64);
    assert_eq!(value, text);
    drop(value);
    assert!(pool.live() > 0, "explicit permit owner is still alive");
    drop(output_permits);
    assert_eq!(pool.live(), 0);
}

#[test]
fn cancellation_at_every_actual_constructor_admission_returns_capacity() {
    let wire = text_wire("q\u{301}😀");
    let mut reference = string_driver(&wire, meter());
    finish(&mut reference, 4096);
    drop(reference.output.take());
    let baseline = reference.meter;
    let capacity = 1024 * 1024;
    for stop in 0..baseline.calls.len() {
        let pool = Pool::new(capacity);
        let mut m = Meter::new(pool.clone());
        m.fail_at = Some((stop, Refusal::Work));
        let mut driver = string_driver(&wire, m);
        let mut suspended = false;
        for _ in 0..4096 {
            match driver.step().unwrap() {
                Step::Progress => assert!(driver.output.is_none()),
                Step::Refused(Refusal::Work) => {
                    suspended = true;
                    break;
                }
                other => panic!("cancellation boundary {stop}: {other:?}"),
            }
        }
        assert!(suspended);
        assert_eq!(driver.meter.refused, Some((stop, Refusal::Work)));
        assert_eq!(driver.meter.calls, baseline.calls[..=stop]);
        assert!(driver.output.is_none());
        driver.meter.assert_units(3, 64);
        drop(driver);
        assert_eq!(pool.live(), 0, "cancellation at callback {stop}");
        let all = pool.reserve(capacity).unwrap();
        assert!(pool.reserve(1).is_err());
        drop(all);
    }
}

#[test]
fn partial_field_reservations_are_released_when_failed_construction_is_cancelled() {
    let wire = [0x82, 0x63, b'a', b'b', b'c', 0x63, b'd', b'e', b'f'];
    let mut parser = meter();
    let document = decode(&wire, 8, &mut parser).unwrap();
    let mut baseline = meter();
    let mut permits = Owned::new();
    let output = Vec::<String>::construct(document.root(), &mut permits, &mut baseline).unwrap();
    assert_eq!(output, ["abc", "def"]);
    drop(output);
    drop(permits);
    let stop = baseline
        .calls
        .iter()
        .enumerate()
        .filter(|(_, call)| {
            **call
                == Call::Work {
                    values: 0,
                    bytes: 3,
                }
        })
        .nth(1)
        .unwrap()
        .0;
    let mut m = meter();
    m.fail_at = Some((stop, Refusal::Work));
    let mut permits = Owned::new();
    let result = Vec::<String>::construct(document.root(), &mut permits, &mut m);
    assert!(matches!(
        result,
        Err(DecodeError::Resource(BoundedError::Refused(Refusal::Work)))
    ));
    assert_eq!(m.refused, Some((stop, Refusal::Work)));
    assert!(
        m.pool.live() > 0,
        "completed field reservations were discarded"
    );
    drop(result);
    drop(permits);
    assert_eq!(m.pool.live(), 0);
    drop(document);
    assert_eq!(parser.pool.live(), 0);
}

#[test]
fn completed_field_values_not_just_permits_survive_later_refusal() {
    use dcbor::bounded::Allocator;
    use dcbor::bounded::decode::construction::in_place::{Built, InPlace};
    use dcbor::bounded::decode::construction::reclamation::{Cursor, Reclaim, Reclaimed};
    use dcbor::bounded::decode::construction::{DecodeOwner, TypedDecoder, TypedStep};
    use dcbor::bounded::decode::{ConstructResult, Document, Options};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::{
        mem::MaybeUninit,
        ptr::{NonNull, addr_of_mut},
    };
    static CREATED: AtomicUsize = AtomicUsize::new(0);
    static DROPPED: AtomicUsize = AtomicUsize::new(0);
    struct Tracked(String);
    // SAFETY: the compiler projection preserves the single String field's final
    // address, and the same cursor is used for construction and reclamation.
    unsafe impl<A: Allocator> InPlace<A> for Tracked {
        unsafe fn build_step(
            document: &Document<'_, A::Permit>,
            index: usize,
            place: NonNull<MaybeUninit<Self>>,
            cursor: &mut Cursor,
            allocator: &mut A,
        ) -> ConstructResult<Built, A> {
            let child = unsafe {
                NonNull::new_unchecked(addr_of_mut!((*place.as_ptr().cast::<Self>()).0).cast())
            };
            let result = unsafe { String::build_step(document, index, child, cursor, allocator)? };
            if result == Built::Done {
                CREATED.fetch_add(1, Ordering::SeqCst);
            }
            Ok(result)
        }
    }
    // SAFETY: only the initialized String field is reclaimed; no Tracked Drop.
    unsafe impl<A: Allocator> Reclaim<A> for Tracked {
        unsafe fn reclaim_step(
            place: NonNull<MaybeUninit<Self>>,
            cursor: &mut Cursor,
            a: &mut A,
        ) -> dcbor::bounded::BoundedResult<Reclaimed, A> {
            let child = unsafe {
                NonNull::new_unchecked(addr_of_mut!((*place.as_ptr().cast::<Self>()).0).cast())
            };
            let result = unsafe { String::reclaim_step(child, cursor, a)? };
            if result == Reclaimed::Done {
                DROPPED.fetch_add(1, Ordering::SeqCst);
            }
            Ok(result)
        }
    }
    impl Drop for Tracked {
        fn drop(&mut self) {
            assert!(!self.0.is_empty());
            DROPPED.fetch_add(1, Ordering::SeqCst);
        }
    }
    let wire = [0x82, 0x63, b'a', b'b', b'c', 0x63, b'd', b'e', b'f'];
    let created = CREATED.load(Ordering::SeqCst);
    let dropped = DROPPED.load(Ordering::SeqCst);
    let mut m = meter();
    let owner = DecodeOwner::new();
    let mut operation =
        TypedDecoder::<Vec<Tracked>, Meter>::new(&owner, &wire, Options::normalizing(8));
    let mut reached = false;
    for _ in 0..4096 {
        assert!(matches!(
            operation.step(&mut m).unwrap(),
            TypedStep::Progress
        ));
        if CREATED.load(Ordering::SeqCst) == created + 1 {
            reached = true;
            break;
        }
    }
    assert!(reached, "first field never completed");
    let held = m.pool.live();
    assert!(held > 0);
    let stop = m.calls.len();
    m.fail_at = Some((stop, Refusal::Work));
    let outcome = operation.step(&mut m);
    assert_eq!(m.refused, Some((stop, Refusal::Work)));
    assert!(matches!(
        outcome,
        Err(DecodeError::Resource(BoundedError::Refused(Refusal::Work)))
    ));
    assert_eq!(
        CREATED.load(Ordering::SeqCst) - created,
        1,
        "first field was not completed"
    );
    let prematurely_dropped = DROPPED.load(Ordering::SeqCst) - dropped;
    assert_eq!(m.pool.live(), held);
    drop(outcome);
    m.fail_at = None;
    // Begin a new scheduler turn after positively observing the refusal.
    // Consumption and allocation ownership remain cumulative.
    m.refused = None;
    let mut output = None;
    for _ in 0..4096 {
        let before = (m.values, m.bytes);
        m.limit_values = before.0.checked_add(3).unwrap();
        m.limit_bytes = before.1.checked_add(64).unwrap();
        match operation.step(&mut m).unwrap() {
            TypedStep::Progress => {
                assert!(m.values > before.0 || m.bytes > before.1);
            }
            TypedStep::Complete(value) => {
                output = Some(value);
                break;
            }
            TypedStep::Finished => panic!("completed fields were lost"),
        }
        assert!(m.values - before.0 <= 3 && m.bytes - before.1 <= 64);
    }
    let output = output.expect("retained construction did not complete");
    assert_eq!(
        output
            .value()
            .iter()
            .map(|v| v.0.as_str())
            .collect::<Vec<_>>(),
        ["abc", "def"]
    );
    assert_eq!(CREATED.load(Ordering::SeqCst) - created, 2);
    m.assert_units(3, 64);
    drop(operation);
    assert!(m.pool.live() > 0);
    assert_eq!(DROPPED.load(Ordering::SeqCst), dropped);
    drop(output);
    assert_eq!(DROPPED.load(Ordering::SeqCst), dropped);
    super::heap::drain_decode(&owner, &mut m);
    assert_eq!(m.pool.live(), 0);
    assert_eq!(
        CREATED.load(Ordering::SeqCst),
        DROPPED.load(Ordering::SeqCst)
    );
    assert_eq!(
        prematurely_dropped, 0,
        "completed field value was discarded while its reservation survived"
    );
}

#[test]
fn output_moved_to_another_thread_releases_only_at_the_last_owner() {
    let wire = text_wire("é😀");
    let mut m = meter();
    let output = decode_typed::<String, _>(&wire, 8, &mut m).unwrap();
    let pool = m.pool.clone();
    let held = pool.live();
    assert!(held >= 6);
    let (ready, wait_ready) = std::sync::mpsc::channel();
    let (release, wait_release) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        assert_eq!(output.value(), "é😀");
        ready.send(()).unwrap();
        wait_release.recv().unwrap();
        drop(output);
    });
    wait_ready.recv().unwrap();
    drop(m);
    drop(wire);
    assert_eq!(pool.live(), held);
    release.send(()).unwrap();
    worker.join().unwrap();
    assert_eq!(pool.live(), 0);
}

#[test]
fn failed_growth_keeps_old_reservation_until_a_successful_replacement() {
    let pool = Pool::new(4096);
    let mut m = Meter::new(pool.clone());
    let mut storage = Owned::new();
    storage.push(7u8, &mut m).unwrap();
    let old = pool.live();
    let blocker = pool.reserve(4096 - old).unwrap();
    let failure = storage.reserve(256, &mut m);
    assert!(matches!(
        failure,
        Err(BoundedError::Refused(Refusal::Capacity))
    ));
    assert_eq!(storage.as_slice(), &[7]);
    assert_eq!(pool.live(), 4096);
    drop(blocker);
    assert_eq!(pool.live(), old);
    // A new operation meter, same storage owner. This tests reserve, not decode
    // continuation, and therefore does not misrepresent a restarted parser.
    let mut next = Meter::new(pool.clone());
    storage.reserve(256, &mut next).unwrap();
    assert_eq!(storage.as_slice(), &[7]);
    assert!(pool.live() > old);
    drop(storage);
    assert_eq!(pool.live(), 0);
}
