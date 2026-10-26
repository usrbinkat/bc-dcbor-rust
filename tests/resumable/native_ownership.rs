use super::bindings::string_decoder;
use super::harness::*;
use super::support::{
    self, Fault, allowed, checked, contracted, drive_faulted, refusal_matrix, refuse, rigor::rigor,
};
use dcbor::bounded::decode::{BoundedDecodable, DecodeError, decode, decode_typed};
use dcbor::bounded::{Allocator, BoundedError, Owned, Step};

#[test]
fn input_parser_fields_and_output_have_separate_observed_lifetimes() {
    let text = "q\u{301}\u{1f600}".repeat(64);
    let wire = text_wire(&text);
    let mut pool = meter_with(1024 * 1024);
    // Input storage is consumer-owned in the borrowed-input API.
    let input_owner = pool.allocate(wire.len() as u64).unwrap();
    let input_live = pool.live_bytes();
    assert_eq!(input_live, wire.len() as u64);
    let mut parser = pool.share();
    let document = decode(&wire, 8, &mut parser).unwrap();
    let parsed_live = pool.live_bytes();
    assert!(parsed_live > input_live);
    let mut constructor = pool.share();
    let mut output_permits = Owned::new();
    let value = String::construct(document.root(), &mut output_permits, &mut constructor).unwrap();
    let constructed_live = pool.live_bytes();
    assert!(constructed_live >= parsed_live + text.len() as u64);
    assert_eq!(value, text);
    drop(document);
    assert_eq!(
        pool.live_bytes(),
        constructed_live - (parsed_live - input_live)
    );
    drop(parser);
    drop(constructor);
    assert_eq!(
        pool.live_bytes(),
        constructed_live - (parsed_live - input_live)
    );
    drop(wire);
    drop(input_owner);
    assert!(pool.live_bytes() >= text.len() as u64);
    assert_eq!(value, text);
    drop(value);
    assert!(
        pool.live_bytes() > 0,
        "explicit permit owner is still alive"
    );
    drop(output_permits);
    assert_eq!(pool.live_bytes(), 0);
}

/// Every admission of a string decode refused, resumed and cancelled, in a
/// pool of fixed capacity: after each run, cancelled or published and
/// released, the pool's whole capacity can be reacquired exactly, and one
/// byte more cannot.
#[test]
fn cancellation_at_every_actual_constructor_admission_returns_capacity() {
    let wire = text_wire("q\u{301}\u{1f600}");
    let capacity = 1024 * 1024;
    refusal_matrix("string decode in a fixed pool", rigor(), |fault: Fault| {
        let mut pool = meter_with(capacity);
        let mut m = pool.share();
        refuse(&mut m, fault.refusal);
        let mut operation = string_decoder(&wire);
        let turns = allowed(&m, string_turns(wire.len()));
        let value = drive_faulted(&mut m, &mut operation, turns, fault.cancel)
            .expect("canonical text decodes");
        m.assert_units(TURN);
        drop(operation);
        drop(value);
        assert_eq!(pool.live_bytes(), 0, "a run kept capacity");
        let all = pool.allocate(capacity).unwrap();
        assert!(pool.allocate(1).is_err());
        drop(all);
        support::RefusalRun::of(&m)
    });
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
        .calls()
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
    refuse(
        &mut m,
        support::pipeline::Refusal::For(stop, LimitRefusal::Work),
    );
    let mut permits = Owned::new();
    let result = Vec::<String>::construct(document.root(), &mut permits, &mut m);
    assert!(matches!(
        result,
        Err(DecodeError::Resource(BoundedError::Refused(
            LimitRefusal::Work
        )))
    ));
    assert_eq!(m.first_refusal(), Some((stop, LimitRefusal::Work)));
    assert!(
        m.live_bytes() > 0,
        "completed field reservations were discarded"
    );
    drop(result);
    drop(permits);
    assert_eq!(m.live_bytes(), 0);
    drop(document);
    assert_eq!(parser.live_bytes(), 0);
}

#[test]
fn completed_field_values_not_just_permits_survive_later_refusal() {
    use dcbor::bounded::decode::construction::TypedDecoder;
    use dcbor::bounded::decode::construction::in_place::{Built, ConstructionCost, InPlace};
    use dcbor::bounded::decode::construction::reclamation::{Reclaim, Reclaimed};
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
    // address, and the field's own state is used for construction and
    // reclamation.
    unsafe impl<A: Allocator> InPlace<A> for Tracked {
        // Construction and cleanup are the single String field's.
        const COST: ConstructionCost = <String as InPlace<A>>::COST;

        unsafe fn build_step(
            document: &Document<'_, A::Permit>,
            index: usize,
            place: NonNull<MaybeUninit<Self>>,
            state: &mut Self::State,
            allocator: &mut A,
        ) -> ConstructResult<Built, A> {
            let child = unsafe {
                NonNull::new_unchecked(addr_of_mut!((*place.as_ptr().cast::<Self>()).0).cast())
            };
            let result = unsafe { String::build_step(document, index, child, state, allocator)? };
            if result == Built::Done {
                CREATED.fetch_add(1, Ordering::SeqCst);
            }
            Ok(result)
        }
    }
    // SAFETY: only the initialized String field is reclaimed; no Tracked Drop.
    unsafe impl<A: Allocator> Reclaim<A> for Tracked {
        type State = <String as Reclaim<A>>::State;
        const INITIAL: Self::State = <String as Reclaim<A>>::INITIAL;

        unsafe fn reclaim_step(
            place: NonNull<MaybeUninit<Self>>,
            state: &mut Self::State,
            a: &mut A,
        ) -> dcbor::bounded::BoundedResult<Reclaimed, A> {
            let child = unsafe {
                NonNull::new_unchecked(addr_of_mut!((*place.as_ptr().cast::<Self>()).0).cast())
            };
            let result = unsafe { String::reclaim_step(child, state, a)? };
            if result == Reclaimed::Done {
                DROPPED.fetch_add(1, Ordering::SeqCst);
            }
            Ok(result)
        }

        /// The wrapped string's own count, at the same projection.
        unsafe fn remaining(place: NonNull<MaybeUninit<Self>>, state: &mut Self::State) -> u64 {
            let child = unsafe {
                NonNull::new_unchecked(addr_of_mut!((*place.as_ptr().cast::<Self>()).0).cast())
            };
            unsafe { <String as Reclaim<A>>::remaining(child, state) }
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
    let (mut owner, input) = support::open(&mut m, &wire);
    m.open();
    let mut operation =
        TypedDecoder::<_, Vec<Tracked>, Limits>::new(input, Options::normalizing(8));
    let turns = support::typed_turns::<Vec<Tracked>>(wire.len());
    let mut reached = false;
    for _ in 0..turns {
        assert!(matches!(
            contracted(&mut m, &mut operation).unwrap(),
            Step::Progress
        ));
        if CREATED.load(Ordering::SeqCst) == created + 1 {
            reached = true;
            break;
        }
    }
    assert!(reached, "first field never completed");
    let held = m.live_bytes();
    assert!(held > 0);
    let position = operation.position();
    support::repeated_refusal("completed tracked field", &mut m, position, 3, |m| {
        let result = contracted(m, &mut operation).map(|_| ());
        (operation.position(), result)
    });
    assert_eq!(
        CREATED.load(Ordering::SeqCst) - created,
        1,
        "first field was not completed"
    );
    let prematurely_dropped = DROPPED.load(Ordering::SeqCst) - dropped;
    assert_eq!(m.live_bytes(), held);
    // Each later scheduler turn begins after positively observing the
    // refusal. Consumption and allocation ownership remain cumulative.
    let output = support::drive_within(&mut m, &mut operation, turns)
        .expect("retained construction did not complete");
    support::exhausted(&mut m, &mut operation);
    assert_eq!(
        output
            .value()
            .iter()
            .map(|v| v.0.as_str())
            .collect::<Vec<_>>(),
        ["abc", "def"]
    );
    assert_eq!(CREATED.load(Ordering::SeqCst) - created, 2);
    m.assert_units(TURN);
    drop(operation);
    assert!(m.live_bytes() > 0);
    assert_eq!(DROPPED.load(Ordering::SeqCst), dropped);
    drop(output);
    assert_eq!(DROPPED.load(Ordering::SeqCst), dropped);
    support::drain(&mut owner, &mut m);
    assert_eq!(m.live_bytes(), 0);
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
    let wire = text_wire("\u{e9}\u{1f600}");
    let mut m = meter();
    let output = decode_typed::<String, _>(&wire, 8, &mut m).unwrap();
    let pool = m.share();
    let held = pool.live_bytes();
    assert!(held >= 6);
    let (ready, wait_ready) = std::sync::mpsc::channel();
    let (release, wait_release) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        assert_eq!(output.value(), "\u{e9}\u{1f600}");
        ready.send(()).unwrap();
        wait_release.recv().unwrap();
        drop(output);
    });
    wait_ready.recv().unwrap();
    drop(m);
    drop(wire);
    assert_eq!(pool.live_bytes(), held);
    release.send(()).unwrap();
    worker.join().unwrap();
    assert_eq!(pool.live_bytes(), 0);
}

// Transfers follow merge and split in tokio/tests/sync_semaphore_owned.rs:
// intermediate ownership is exact, zero-sized and refused transfers change
// nothing, and the final owner releases exactly what it holds.
#[test]
fn split_merge_zero_and_refused_transfers_preserve_exact_capacity() {
    use dcbor::bounded::TransferRefusal;
    let capacity = 4096;
    let mut pool = meter_with(capacity);
    let mut first = pool.allocate(3).unwrap();
    assert_eq!((pool.live_bytes(), pool.peak_bytes()), (3, 3));
    let mut second = first.split(1).unwrap();
    assert_eq!((first.bytes(), second.bytes()), (2, 1));
    assert_eq!((pool.live_bytes(), pool.peak_bytes()), (3, 3));
    let empty = first.split(0).unwrap();
    assert_eq!(empty.bytes(), 0);
    for requested in [3, u64::MAX] {
        assert_eq!(
            first.split(requested).unwrap_err(),
            TransferRefusal::Insufficient { requested, held: 2 }
        );
        assert_eq!(first.bytes(), 2);
        assert_eq!(pool.live_bytes(), 3);
    }
    first.merge(second).unwrap();
    assert_eq!(first.bytes(), 3);
    assert_eq!(pool.live_bytes(), 3);
    // A reservation of other storage is returned unchanged.
    let mut foreign_pool = meter_with(capacity);
    let foreign = foreign_pool.allocate(5).unwrap();
    let (foreign, refusal) = first.merge(foreign).unwrap_err();
    assert_eq!(refusal, TransferRefusal::Foreign);
    assert_eq!((first.bytes(), foreign.bytes()), (3, 5));
    assert_eq!((pool.live_bytes(), foreign_pool.live_bytes()), (3, 5));
    drop(foreign);
    assert_eq!(foreign_pool.live_bytes(), 0);
    second = first.split(1).unwrap();
    drop(first);
    assert_eq!(pool.live_bytes(), 1);
    let last = second.split(1).unwrap();
    assert_eq!(
        second.split(1).unwrap_err(),
        TransferRefusal::Insufficient {
            requested: 1,
            held: 0
        }
    );
    drop(second);
    drop(empty);
    assert_eq!(pool.live_bytes(), 1);
    drop(last);
    assert_eq!(pool.live_bytes(), 0);
    let all = pool.allocate(capacity).unwrap();
    assert!(pool.allocate(1).is_err());
    drop(all);
    assert_eq!(pool.live_bytes(), 0);
}

/// Where a typed decode's storage is held, as its position reports it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Held {
    /// The parse record and its arenas.
    ParserScratch,
    /// The construction record and a field under construction.
    PartialField,
    /// The complete value, before publication.
    TypedOutput,
}

fn held(
    position: &dcbor::bounded::decode::construction::TypedPosition<
        dcbor::bounded::decode::construction::in_place::BufferObservation,
    >,
) -> Option<Held> {
    use dcbor::bounded::decode::construction::in_place::BufferObservation;
    use dcbor::bounded::decode::construction::{ConstructPhase, TypedPosition};
    match position {
        TypedPosition::Parse(parse) if parse.allocated => Some(Held::ParserScratch),
        TypedPosition::Construct(construct) => match construct.detail.phase {
            // The byte buffer holds its metadata block: a field under
            // construction, its payload acquired or not.
            Some(ConstructPhase::Build)
                if matches!(construct.detail.build, Some(BufferObservation::Held(_))) =>
            {
                Some(Held::PartialField)
            }
            Some(ConstructPhase::Detach | ConstructPhase::Publish) => Some(Held::TypedOutput),
            _ => None,
        },
        _ => None,
    }
}

#[test]
fn ownership_is_accounted_at_every_phase_transition_and_cancellation() {
    use dcbor::ByteString;
    use dcbor::bounded::decode::Options;
    use dcbor::bounded::decode::construction::{DecodeOwner, Reclaimed, TypedDecoder};
    let payload: Vec<u8> = (0..65536u32).map(|i| (i % 251) as u8).collect();
    let wire = dcbor::CBOR::to_byte_string(&payload).to_cbor_data();
    let len = wire.len() as u64;
    for stop in [Held::ParserScratch, Held::PartialField, Held::TypedOutput] {
        for cancel in [false, true] {
            let mut m = meter();
            let mut owner: DecodeOwner<'static, Limits> = support::scope(&mut m);
            let input = support::copy(&owner, &mut m, &wire);
            // Input retained: the copy and its record, before any decoding.
            let input_live = m.live_bytes();
            assert!(input_live >= len);
            let mut operation =
                TypedDecoder::<_, ByteString, Limits>::new(input, Options::normalizing(8));
            let mut fired = false;
            let mut output = None;
            let mut previous = None;
            for _ in 0..support::typed_turns::<ByteString>(wire.len()) {
                let phase = held(&operation.position());
                match phase {
                    Some(Held::ParserScratch) => assert!(m.live_bytes() > input_live),
                    Some(Held::PartialField) => assert!(m.live_bytes() > input_live),
                    Some(Held::TypedOutput) => assert!(m.live_bytes() >= input_live + len),
                    None => {}
                }
                // Phases are entered in order, each once.
                if phase.is_some() && phase != previous {
                    assert!(phase > previous, "{phase:?} after {previous:?}");
                    previous = phase;
                }
                if phase == Some(stop) && !fired {
                    let position = operation.position();
                    let live = m.live_bytes();
                    support::repeated_refusal("typed ownership phase", &mut m, position, 3, |m| {
                        let result = contracted(m, &mut operation).map(|_| ());
                        (operation.position(), result)
                    });
                    assert_eq!(m.live_bytes(), live, "a refusal changed ownership");
                    fired = true;
                    if cancel {
                        operation.cancel();
                        support::finish_within(
                            &mut m,
                            &mut operation,
                            support::typed_turns::<ByteString>(wire.len()),
                        );
                        break;
                    }
                    continue;
                }
                match checked(&mut m, |m| contracted(m, &mut operation)) {
                    Ok(Step::Progress) => {}
                    Ok(Step::Complete(value)) => {
                        support::exhausted(&mut m, &mut operation);
                        output = Some(value);
                        break;
                    }
                    Err(error) if support::ordinary_exhaustion(&m, &error) => {}
                    other => panic!("unexpected ownership outcome: {}", support::label(&other)),
                }
            }
            assert!(fired, "{stop:?} was never reached");
            assert_eq!(output.is_some(), !cancel);
            drop(operation);
            if let Some(value) = output {
                assert_eq!(value.value().data(), &payload[..]);
                // Scratch released: the retired parse record is reclaimed from
                // the queue while the published value and its input remain.
                let retained = m.live_bytes();
                // The retired parse record's cleanup is within the typed
                // decode's bound.
                let mut idle = false;
                for _ in 0..support::typed_turns::<ByteString>(wire.len()) {
                    match checked(&mut m, |m| owner.step(m)) {
                        Ok(Reclaimed::Waiting | Reclaimed::Done) => {
                            idle = true;
                            break;
                        }
                        Ok(Reclaimed::Progress) => {}
                        Err(error) if support::ordinary_exhaustion(&m, &error) => {}
                        Err(error) => panic!("queued cleanup failed: {error:?}"),
                    }
                }
                assert!(idle, "queued cleanup exceeded the decode's bound");
                let output_live = m.live_bytes();
                assert!(output_live < retained, "parser scratch was not released");
                assert!(output_live >= input_live + payload.len() as u64);
                assert_eq!(value.value().data(), &payload[..]);
                drop(value);
            }
            support::drain(&mut owner, &mut m);
            assert_eq!(m.live_bytes(), 0, "leaked at {stop:?}, cancel={cancel}");
        }
    }
}

#[test]
fn failed_growth_keeps_old_reservation_until_a_successful_replacement() {
    let mut pool = meter_with(4096);
    let mut m = pool.share();
    let mut storage = Owned::new();
    storage.push(7u8, &mut m).unwrap();
    let old = pool.live_bytes();
    let blocker = pool.allocate(4096 - old).unwrap();
    let failure = storage.reserve(256, &mut m);
    assert!(matches!(
        failure,
        Err(BoundedError::Refused(LimitRefusal::Storage))
    ));
    assert_eq!(storage.as_slice(), &[7]);
    assert_eq!(pool.live_bytes(), 4096);
    drop(blocker);
    assert_eq!(pool.live_bytes(), old);
    // A new operation policy, same storage owner. This tests reserve, not
    // decode continuation, and therefore does not misrepresent a restarted
    // parser.
    let mut next = pool.share();
    storage.reserve(256, &mut next).unwrap();
    assert_eq!(storage.as_slice(), &[7]);
    assert!(pool.live_bytes() > old);
    drop(storage);
    assert_eq!(pool.live_bytes(), 0);
}
