#![cfg(feature = "std")]

// The observed construction driver witnesses physical storage.
#[global_allocator]
static HEAP: support::heap::Heap = support::heap::Heap;

use dcbor_test_support as support;

#[cfg(feature = "derive")]
#[path = "reclamation/schema.rs"]
mod schema;

#[path = "reclamation/parser.rs"]
mod parser;

#[path = "reclamation/destination.rs"]
mod destination;

#[path = "reclamation/scoped.rs"]
mod scoped;

use dcbor::bounded::decode::construction::in_place::Transferable;
use dcbor::bounded::decode::construction::reclamation::{Custody, Reclaim, Reclaimed};
use dcbor::bounded::decode::construction::{Acquisition, Construction};
use dcbor::bounded::decode::{DecodeError, Options};
use dcbor::bounded::{BoundedError, BoundedResult, Budget, Limits, Step};
use std::cell::Cell;
use std::mem::MaybeUninit;
use std::ptr::NonNull;
use support::{document, drain, scope};

thread_local! {
    static CLEANED: Cell<usize> = const { Cell::new(0) };
    static DROPPED: Cell<usize> = const { Cell::new(0) };
}

/// The policy of these gates: logged and strict.
fn meter() -> Limits {
    Limits::unlimited().logged().strict()
}

/// The fault matrix of constructing `T` from `wire`, parsing being setup
/// ([`support::refusal_matrix`]): every admission, each allocation request
/// among them, refused once in one run, which must attempt exactly the
/// admitted calls each twice in a row (ordinary turn exhaustion is witnessed
/// separately), so work admitted before a refused
/// allocation is retained and never admitted again; in the exhaustive layer
/// each refused in a run of its own; and a cancellation at every call. A
/// published value satisfies `inspect`; every reservation is recovered.
fn refused_allocations_conserve_work<T: Transferable<Limits> + 'static>(
    wire: &[u8],
    inspect: &dyn Fn(&T),
) {
    let name = format!(
        "construction of {} from {wire:02x?}",
        core::any::type_name::<T>()
    );
    let baseline = support::refusal_matrix(&name, support::rigor::rigor(), |fault| {
        let mut m = meter();
        let (mut owner, document) = document(&mut m, wire, Options::normalizing(8));
        // Measure construction alone: parsing is setup.
        m.measure();
        support::refuse(&mut m, fault.refusal);
        let mut operation = Construction::<_, T, Limits>::construct(document);
        let turns = support::allowed(&m, support::typed_turns::<T>(wire.len()));
        let value = support::drive_faulted(&mut m, &mut operation, turns, fault.cancel)
            .expect("construction failed");
        if let Some(value) = &value {
            inspect(value.value());
        }
        let calls = support::RefusalRun::of(&m);
        drop(value);
        drop(operation);
        drain(&mut owner, &mut m);
        assert_eq!(m.live_bytes(), 0);
        calls
    });
    assert!(
        baseline
            .calls()
            .iter()
            .any(|call| matches!(call, dcbor::bounded::Call::Allocate(_))),
        "{name}: the fixture performs no allocation"
    );
}

#[test]
fn refused_allocations_conserve_construction_work() {
    use dcbor::bounded::decode::construction::in_place::StableOption;

    refused_allocations_conserve_work::<Option<u64>>(&[0x07], &|v| assert_eq!(*v, Some(7)));
    refused_allocations_conserve_work::<Option<u64>>(&[0xf6], &|v| assert_eq!(*v, None));
    refused_allocations_conserve_work::<Option<String>>(&[0x61, b'x'], &|v| {
        assert_eq!(v.as_deref(), Some("x"))
    });
    refused_allocations_conserve_work::<StableOption<u64, Limits>>(&[0x07], &|v| {
        assert_eq!(v.as_ref(), Some(&7))
    });
    refused_allocations_conserve_work::<StableOption<u64, Limits>>(&[0xf6], &|v| {
        assert!(!v.is_some())
    });
    refused_allocations_conserve_work::<String>(&[0x61, b'x'], &|v| assert_eq!(v, "x"));
    // [[1, 24], [], [256]]
    refused_allocations_conserve_work::<Vec<Vec<u64>>>(
        &[0x83, 0x82, 0x01, 0x18, 0x18, 0x80, 0x81, 0x19, 0x01, 0x00],
        &|v| assert_eq!(v, &[vec![1, 24], vec![], vec![256]]),
    );
    // Fixed arrays build each element in the destination's own slot.
    refused_allocations_conserve_work::<[u64; 3]>(
        &[0x83, 0x01, 0x18, 0x18, 0x19, 0x01, 0x00],
        &|v| assert_eq!(v, &[1, 24, 256]),
    );
    // [["a"], []]
    refused_allocations_conserve_work::<[Vec<String>; 2]>(&[0x82, 0x81, 0x61, b'a', 0x80], &|v| {
        assert_eq!(v, &[vec!["a".to_string()], vec![]])
    });
}

/// Every built-in construction is within its type's cost, built or failed:
/// scalars, byte buffers short and spanning several copy units, multibyte
/// text, vectors and nested vectors, fixed arrays of the right and wrong
/// lengths, native and stable optionals present and null, and nodes of the
/// wrong kind.
#[test]
fn every_built_in_construction_is_within_its_cost() {
    use dcbor::ByteString;
    use dcbor::bounded::decode::construction::in_place::StableOption;
    use support::{builds_within_cost as builds, rejects_within_cost as rejects};
    let text = |text: &str| dcbor::CBOR::from(text).to_cbor_data();
    let long = "x".repeat(1000);
    let multibyte = "\u{e9}\u{1f600}".repeat(100);
    builds::<u64>(&[0x19, 0x01, 0x00], |v| assert_eq!(*v, 256));
    rejects::<u8>(&[0x19, 0x01, 0x00]);
    builds::<i64>(&[0x38, 0x18], |v| assert_eq!(*v, -25));
    builds::<bool>(&[0xf5], |v| assert!(*v));
    builds::<f64>(&[0xf9, 0x3e, 0x00], |v| assert_eq!(*v, 1.5));
    rejects::<u64>(&[0x61, b'x']);
    for source in ["", "x", &long, &multibyte] {
        builds::<String>(&text(source), |v| assert_eq!(v, source));
    }
    rejects::<String>(&[0x41, 0x00]);
    let bytes = dcbor::CBOR::to_byte_string(vec![0x5a; 1000]).to_cbor_data();
    builds::<ByteString>(&bytes, |v| assert_eq!(v.data(), &[0x5a; 1000][..]));
    rejects::<ByteString>(&text("x"));
    let values: Vec<u64> = (0..300).collect();
    let numbers = dcbor::CBOR::from(values.clone()).to_cbor_data();
    builds::<Vec<u64>>(&numbers, |v| assert_eq!(v, &values));
    rejects::<Vec<String>>(&numbers);
    let sources = [long.clone(), multibyte.clone(), String::new()];
    let strings = dcbor::CBOR::from(sources.to_vec()).to_cbor_data();
    builds::<Vec<String>>(&strings, |v| assert_eq!(v, &sources));
    let nested = [0x83, 0x82, 0x01, 0x18, 0x18, 0x80, 0x81, 0x19, 0x01, 0x00];
    builds::<Vec<Vec<u64>>>(&nested, |v| {
        assert_eq!(v, &[vec![1, 24], vec![], vec![256]])
    });
    builds::<[String; 3]>(&strings, |v| assert_eq!(v, &sources));
    rejects::<[String; 2]>(&strings);
    builds::<Option<String>>(&text(&long), |v| {
        assert_eq!(v.as_deref(), Some(long.as_str()))
    });
    builds::<Option<String>>(&[0xf6], |v| assert_eq!(*v, None));
    builds::<StableOption<Vec<u64>, Limits>>(&numbers, |v| assert_eq!(v.as_ref(), Some(&values)));
    builds::<StableOption<Vec<u64>, Limits>>(&[0xf6], |v| assert!(!v.is_some()));
    rejects::<StableOption<Vec<u64>, Limits>>(&text("x"));
}

/// Every reducing built-in binding's declared cleanup reduction is a
/// simulation of cleanup on every state its construction reaches, cancelled
/// at each build step ([`support::certified`]), and every transition those
/// constructions and cleanups take is in the binding's successor relations,
/// with exactly the cleanup they bound ([`support::legal`]): byte buffers
/// empty, within one copy unit, across copy units and of multibyte text;
/// native options of a scalar and of text, present and null; stable options
/// of a scalar and of text, present and null; and a rejection at each
/// binding's own inspection. The evidence is these fixtures' reached states,
/// each binding's argument for its reduction stated at its definition.
#[test]
fn every_reducing_binding_is_certified_and_its_transitions_legal() {
    use dcbor::ByteString;
    use dcbor::bounded::decode::construction::in_place::StableOption;
    use support::legality::{buffer, optional, stable_option, written};
    use support::{certified, legal};
    let text = |text: &str| dcbor::CBOR::from(text).to_cbor_data();
    let long = "x".repeat(65);
    let multibyte = "\u{e9}\u{1f600}".repeat(20);
    let bytes = dcbor::CBOR::to_byte_string(vec![0x5a; 70]).to_cbor_data();
    let texts = [text(""), text("x"), text(&long), text(&multibyte)];
    for wire in &texts {
        let name = format!("String from {wire:02x?}");
        legal(&name, &certified::<String>(&name, wire), &buffer());
    }
    let mistyped = text("x");
    for wire in [&[0x40][..], bytes.as_slice(), mistyped.as_slice()] {
        let name = format!("ByteString from {wire:02x?}");
        legal(&name, &certified::<ByteString>(&name, wire), &buffer());
    }
    // A text, an integer and a byte string where a text is expected: each
    // rejected by the payload's own inspection.
    for wire in [
        &[0xf6][..],
        texts[1].as_slice(),
        texts[2].as_slice(),
        &[0x41, 0x00],
    ] {
        let name = format!("Option<String> from {wire:02x?}");
        legal(
            &name,
            &certified::<Option<String>>(&name, wire),
            &optional(buffer()),
        );
    }
    for wire in [&[0x07][..], &[0xf6], texts[1].as_slice()] {
        let name = format!("Option<u64> from {wire:02x?}");
        legal(
            &name,
            &certified::<Option<u64>>(&name, wire),
            &optional(written()),
        );
    }
    for wire in [&[0xf6][..], texts[2].as_slice(), &[0x07]] {
        let name = format!("StableOption<String> from {wire:02x?}");
        legal(
            &name,
            &certified::<StableOption<String, Limits>>(&name, wire),
            &stable_option(buffer()),
        );
    }
    for wire in [&[0x07][..], &[0xf6], texts[1].as_slice()] {
        let name = format!("StableOption<u64> from {wire:02x?}");
        legal(
            &name,
            &certified::<StableOption<u64, Limits>>(&name, wire),
            &stable_option(written()),
        );
    }
}

/// A container declares no reduction: its observation counts older children
/// whose custody may differ. Its observation is still complete for custody:
/// on every state its construction reaches, two equal observations hold
/// equal live bytes and clean up identically, unit by unit
/// ([`support::observation`]); and every transition is in the sequence's
/// successor relations over its element's, with the remaining cleanup and
/// the witnessed allocations wherever the observation determines them
/// ([`support::legal`]). Vectors of text, of optional text present and null
/// (the case a container reduction would merge), of integers, nested
/// vectors, an empty vector, and fixed arrays, built and rejected.
#[test]
fn every_container_observation_is_complete_and_its_transitions_legal() {
    use support::legality::{buffer, optional, sequence, written};
    use support::{legal, observation};
    // ["a", "bc"]
    let strings = [0x82, 0x61, b'a', 0x62, b'b', b'c'];
    // ["a", null, "b"]
    let optionals = [0x83, 0x61, b'a', 0xf6, 0x61, b'b'];
    // [[1, 24], [], [256]]
    let nested = [0x83, 0x82, 0x01, 0x18, 0x18, 0x80, 0x81, 0x19, 0x01, 0x00];
    // [1, 24, 256]
    let integers = [0x83, 0x01, 0x18, 0x18, 0x19, 0x01, 0x00];
    let name = "Vec<String>";
    legal(
        name,
        &observation::<Vec<String>, _>(name, &strings, |o| *o),
        &sequence(buffer(), false),
    );
    let name = "Vec<Option<String>>";
    legal(
        name,
        &observation::<Vec<Option<String>>, _>(name, &optionals, |o| *o),
        &sequence(optional(buffer()), false),
    );
    let name = "Vec<Vec<u64>>";
    legal(
        name,
        &observation::<Vec<Vec<u64>>, _>(name, &nested, |o| *o),
        &sequence(sequence(written(), false), false),
    );
    let name = "Vec<u64>";
    legal(
        name,
        &observation::<Vec<u64>, _>(name, &integers, |o| *o),
        &sequence(written(), false),
    );
    let name = "empty Vec<String>";
    legal(
        name,
        &observation::<Vec<String>, _>(name, &[0x80], |o| *o),
        &sequence(buffer(), false),
    );
    let name = "[String; 2]";
    legal(
        name,
        &observation::<[String; 2], _>(name, &strings, |o| *o),
        &sequence(buffer(), true),
    );
    let name = "[u64; 3]";
    legal(
        name,
        &observation::<[u64; 3], _>(name, &integers, |o| *o),
        &sequence(written(), true),
    );
    // Three elements where two are declared: rejected at the inspection.
    let name = "[String; 2] of three";
    legal(
        name,
        &observation::<[String; 2], _>(name, &optionals, |o| *o),
        &sequence(buffer(), true),
    );
    // An element of the wrong kind: rejected after the first commit.
    let name = "Vec<String> with an integer";
    legal(
        name,
        &observation::<Vec<String>, _>(name, &[0x82, 0x61, b'a', 0x01], |o| *o),
        &sequence(buffer(), false),
    );
}

/// Properties over counts and lengths, each domain enumerated whole, each
/// member certified or checked complete and legal with its exact cleanup
/// and witnessed allocations: every text length from empty through three
/// copy units and one byte more, in one-byte scalars and in two-byte ones,
/// whose copies back off to a scalar boundary wherever a unit ends inside
/// one; every vector length through nine, of text whose lengths cycle
/// across a copy unit and of optional text alternating present and null;
/// and nested vectors of every shape up to three by three. The exhaustive
/// layer extends the text lengths to eight copy units and the vector
/// lengths to twenty-four.
#[test]
fn properties_hold_across_counts_and_lengths() {
    use dcbor::CBOR;
    use support::legality::{buffer, optional, sequence, written};
    use support::rigor::{Rigor, rigor};
    use support::{certified, legal, observation};
    let exhaustive = rigor() == Rigor::Exhaustive;
    let units = if exhaustive { 8 } else { 3 };
    for length in 0..=units * 64 + 1 {
        for source in ["x".repeat(length), "\u{e9}".repeat(length / 2)] {
            let name = format!("String of {} bytes", source.len());
            let wire = CBOR::from(source).to_cbor_data();
            legal(&name, &certified::<String>(&name, &wire), &buffer());
        }
    }
    let counts = if exhaustive { 24 } else { 9 };
    for count in 0..=counts {
        let texts: Vec<String> = (0..count).map(|n| "y".repeat((n * 37) % 130)).collect();
        let name = format!("Vec<String> of {count}");
        let wire = CBOR::from(texts).to_cbor_data();
        legal(
            &name,
            &observation::<Vec<String>, _>(&name, &wire, |o| *o),
            &sequence(buffer(), false),
        );
        let optionals: Vec<CBOR> = (0..count)
            .map(|n| {
                if n % 2 == 0 {
                    CBOR::from("z")
                } else {
                    CBOR::null()
                }
            })
            .collect();
        let name = format!("Vec<Option<String>> of {count}");
        let wire = CBOR::from(optionals).to_cbor_data();
        legal(
            &name,
            &observation::<Vec<Option<String>>, _>(&name, &wire, |o| *o),
            &sequence(optional(buffer()), false),
        );
    }
    for outer in 0..=3usize {
        for inner in 0..=3u64 {
            let nested: Vec<CBOR> = (0..outer)
                .map(|row| {
                    CBOR::from(
                        (0..inner)
                            .map(|n| n * 24 + row as u64)
                            .collect::<Vec<u64>>(),
                    )
                })
                .collect();
            let name = format!("Vec<Vec<u64>> of {outer} by {inner}");
            let wire = CBOR::from(nested).to_cbor_data();
            legal(
                &name,
                &observation::<Vec<Vec<u64>>, _>(&name, &wire, |o| *o),
                &sequence(sequence(written(), false), false),
            );
        }
    }
}

/// The text fixture every planted defect is put through: long enough to
/// cross a copy unit, so the payload is held over several states.
fn planted_text() -> Vec<u8> {
    dcbor::CBOR::from("x".repeat(65)).to_cbor_data()
}

/// A planted buffer reduction that drops whether the payload permit is
/// held merges states whose cleanup releases different bytes.
#[test]
#[should_panic(expected = "the class merges states of different custody")]
fn a_buffer_reduction_merging_payload_custody_is_rejected() {
    use dcbor::bounded::decode::construction::in_place::BufferClass;
    use dcbor::bounded::decode::construction::reclamation::Reduction;
    type State = <String as Reclaim<Limits>>::State;
    support::simulation::<String, _>("planted buffer reduction", &planted_text(), |observation| {
        match <State as Reduction>::class(observation) {
            BufferClass::Written { .. } => BufferClass::Written { payload: false },
            BufferClass::Freed { .. } => BufferClass::Freed { payload: false },
            class => class,
        }
    });
}

/// A planted optional reduction that merges a live payload with an idle
/// option merges states whose cleanup takes different units.
#[test]
#[should_panic(expected = "the class merges states of different custody")]
fn an_optional_reduction_merging_idle_and_live_payloads_is_rejected() {
    use dcbor::bounded::decode::construction::in_place::OptionalClass;
    use dcbor::bounded::decode::construction::reclamation::Reduction;
    type State = <Option<String> as Reclaim<Limits>>::State;
    support::simulation::<Option<String>, _>(
        "planted optional reduction",
        &planted_text(),
        |observation| match <State as Reduction>::class(observation) {
            OptionalClass::Live(_) => OptionalClass::Idle,
            class => class,
        },
    );
}

/// A planted observer reporting a stale phase, every held buffer as empty,
/// merges states whose next cleanup unit admits different work.
#[test]
#[should_panic(expected = "the class merges states of different custody")]
fn an_observation_reporting_a_stale_phase_is_rejected() {
    use dcbor::bounded::decode::construction::in_place::{
        BufferCustody, BufferObservation, BufferPhase,
    };
    support::observation::<String, _>("planted stale phase", &planted_text(), |observation| {
        match *observation {
            BufferObservation::Held(custody) => BufferObservation::Held(BufferCustody {
                phase: BufferPhase::Empty,
                ..custody
            }),
            unallocated => unallocated,
        }
    });
}

/// A planted claim that a freed buffer's allocation is still live, its
/// permit being kept: every transition and every permit is as the real
/// binding's, so only the heap observer's witness can catch it.
#[test]
#[should_panic(expected = "the live physical allocations witnessed differ")]
fn a_claim_of_a_freed_buffer_is_rejected_by_the_heap_witness() {
    use support::legality::{Legality, buffer};
    let real = buffer();
    let planted = Legality {
        physical: std::rc::Rc::clone(&real.permits),
        ..real
    };
    let name = "planted physical claim";
    support::legal(
        name,
        &support::certified::<String>(name, &planted_text()),
        &planted,
    );
}

/// A planted observer that never reports the payload permit leaves every
/// reached state distinct, so no completeness check can merge them; the
/// successor relation catches it, since a granted payload must appear.
#[test]
#[should_panic(expected = "is not in the binding's successor relation")]
fn an_observation_omitting_the_payload_permit_is_rejected() {
    use dcbor::bounded::decode::construction::in_place::{BufferCustody, BufferObservation};
    let name = "planted payload omission";
    let states: Vec<_> = support::certified::<String>(name, &planted_text())
        .into_iter()
        .map(|state| {
            state.project(|observation| match *observation {
                BufferObservation::Held(custody) => BufferObservation::Held(BufferCustody {
                    payload: false,
                    ..custody
                }),
                unallocated => unallocated,
            })
        })
        .collect();
    support::legal(name, &states, &support::legality::buffer());
}

#[test]
fn fixed_arrays_construct_in_place_and_reclaim_every_element() {
    // [[1, 2], [3, 24]], independently specified canonical bytes.
    let wire = [0x82, 0x82, 0x01, 0x02, 0x82, 0x03, 0x18, 0x18];
    let mut m = meter();
    let (mut owner, document) = document(&mut m, &wire, Options::normalizing(8));
    let output = support::construct::<_, [[u64; 2]; 2]>(&mut m, document)
        .expect("fixed array construction failed");
    assert_eq!(output.value(), &[[1, 2], [3, 24]]);
    assert_eq!(output.bytes(), wire);
    let held = m.live_bytes();
    drop(output);
    assert_eq!(m.live_bytes(), held);
    drain(&mut owner, &mut m);
    assert_eq!(m.live_bytes(), 0);
}

struct Payload([u8; 192]);
impl Drop for Payload {
    fn drop(&mut self) {
        DROPPED.set(DROPPED.get() + 1);
    }
}

/// A [`Payload`]'s state: the bytes of its prefix initialized.
struct PayloadState {
    initialized: usize,
}

/// The initialized prefix's bytes are the payload's whole custody.
impl Custody for PayloadState {
    type Observation = usize;

    fn observe(&mut self) -> usize {
        self.initialized
    }
}

// SAFETY: Payload owns no child allocations. The initialized byte prefix is
// tracked exactly; cleanup invalidates at most 64 bytes after admission, without
// reading uninitialized storage or invoking Payload's synchronous destructor.
unsafe impl Reclaim<Limits> for Payload {
    type State = PayloadState;
    const INITIAL: PayloadState = PayloadState { initialized: 0 };

    #[expect(
        clippy::disallowed_methods,
        reason = "a custom resource binding admits its own cleanup, as `Reclaim` documents"
    )]
    unsafe fn reclaim_step(
        _: NonNull<MaybeUninit<Self>>,
        state: &mut PayloadState,
        a: &mut Limits,
    ) -> BoundedResult<Reclaimed, Limits> {
        let bytes = state.initialized.min(64);
        a.traverse(1, bytes as u64).map_err(BoundedError::Refused)?;
        state.initialized -= bytes;
        CLEANED.set(CLEANED.get() + bytes);
        Ok(if state.initialized == 0 {
            Reclaimed::Done
        } else {
            Reclaimed::Progress
        })
    }

    /// One call per 64-byte chunk still initialized, and one for an empty
    /// prefix, whose call reports `Done` at once.
    unsafe fn remaining(_: NonNull<MaybeUninit<Self>>, state: &mut PayloadState) -> u64 {
        (state.initialized.div_ceil(64) as u64).max(1)
    }
}

/// A payload record with `chunks` admitted 64-byte chunks initialized.
#[expect(
    clippy::disallowed_methods,
    reason = "a custom resource binding admits its record's initialization, as \
              `OwnedRecord::destination` documents"
)]
fn payload<'s>(
    owner: &dcbor::bounded::decode::construction::DecodeOwner<'s, Limits>,
    m: &mut Limits,
    chunks: usize,
) -> (
    dcbor::bounded::decode::construction::OwnedRecord<'s, Payload, Limits>,
    usize,
) {
    m.fresh();
    let mut record = support::acquire::<Payload>(owner, m, &mut Acquisition::new());
    let mut construction_address = 0;
    for _ in 0..chunks {
        m.fresh();
        m.traverse(1, 64).unwrap();
        // SAFETY: byte-only payload; each admitted chunk initializes the
        // next prefix and records it before cancellation can occur.
        unsafe {
            let (place, state) = record.destination();
            construction_address = place.as_ptr() as usize;
            place
                .as_ptr()
                .cast::<u8>()
                .add(state.initialized)
                .write_bytes(0x5a, 64);
            state.initialized += 64;
        }
    }
    (record, construction_address)
}

#[test]
fn stable_publication_and_every_cleanup_admission_refusal() {
    // Select and three 64-byte cleanup units may refuse. The last cleanup
    // unit also frees the record and scope using their prepaid admissions.
    support::stop_matrix(
        "published payload cleanup refusal boundaries",
        3,
        |refuse_at| {
            CLEANED.set(0);
            DROPPED.set(0);
            let mut m = meter();
            let mut owner = scope(&mut m);
            let (record, construction_address) = payload(&owner, &mut m, 3);
            // SAFETY: all 192 bytes are initialized and tracked; no pointer escapes.
            let value = unsafe { record.publish() };
            let published_address = std::ptr::from_ref(value.value()) as usize;
            assert_eq!(value.value().0, [0x5a; 192]);
            drop(value);
            let held = m.live_bytes();
            assert!(held >= 192);
            assert_eq!(DROPPED.get(), 0);
            let refusals = m.refusals();
            for unit in 0..4 {
                if unit == refuse_at {
                    let progress = CLEANED.get();
                    support::repeated_refusal(
                        "published payload cleanup",
                        &mut m,
                        (progress, 1, held),
                        3,
                        |m| {
                            let result =
                                support::checked(m, |m| owner.shutdown_step(m)).map(|_| ());
                            ((CLEANED.get(), owner.outstanding(), m.live_bytes()), result)
                        },
                    );
                }
                m.clear_refusal();
                m.fresh();
                let result = owner.shutdown_step(&mut m).unwrap();
                assert_eq!(
                    result,
                    if unit == 3 {
                        Reclaimed::Done
                    } else {
                        Reclaimed::Progress
                    }
                );
            }
            assert_eq!(construction_address, published_address);
            assert_eq!(m.refusals() - refusals, 3);
            assert_eq!(CLEANED.get(), 192);
            assert_eq!(DROPPED.get(), 0);
            assert_eq!(m.live_bytes(), 0);
            assert_eq!(owner.outstanding(), 0);
            m.fresh();
            assert!(matches!(
                owner.allocate_step::<Payload>(&mut m, &mut Acquisition::new()),
                Err(BoundedError::PlanMismatch)
            ));
        },
    );
}

/// A planted binding understating its cleanup: it declares one call but
/// takes one per unit `left`, then its `Done`.
struct Understated;

/// The cleanup units an [`Understated`] still takes before its `Done`.
struct UnderstatedState {
    left: usize,
}

/// The units left are the binding's whole custody.
impl Custody for UnderstatedState {
    type Observation = usize;

    fn observe(&mut self) -> usize {
        self.left
    }
}

// SAFETY: the binding owns nothing; its cleanup only counts down. Its
// declared count deliberately understates, the defect the scope must refuse.
unsafe impl Reclaim<Limits> for Understated {
    type State = UnderstatedState;
    const INITIAL: UnderstatedState = UnderstatedState { left: 0 };

    #[expect(
        clippy::disallowed_methods,
        reason = "a custom resource binding admits its own cleanup, as `Reclaim` documents"
    )]
    unsafe fn reclaim_step(
        _: NonNull<MaybeUninit<Self>>,
        state: &mut UnderstatedState,
        a: &mut Limits,
    ) -> BoundedResult<Reclaimed, Limits> {
        a.traverse(1, 0).map_err(BoundedError::Refused)?;
        if state.left == 0 {
            return Ok(Reclaimed::Done);
        }
        state.left -= 1;
        Ok(Reclaimed::Progress)
    }

    unsafe fn remaining(_: NonNull<MaybeUninit<Self>>, _: &mut UnderstatedState) -> u64 {
        1
    }
}

/// The scope holds a queued record to the cleanup count it declared when its
/// cleanup began: a record understating it is refused as a defect at the
/// first call beyond it, so no drain runs on unbounded. The first step
/// removes the record, the second spends its one declared call, the third
/// is refused.
#[test]
fn a_record_cleaning_up_beyond_its_declared_count_is_a_defect() {
    let mut m = meter();
    let owner = scope(&mut m);
    let mut record = support::acquire::<Understated>(&owner, &mut m, &mut Acquisition::new());
    // SAFETY: the binding owns nothing; the state is its only custody.
    unsafe { record.destination().1.left = 2 };
    drop(record);
    for step in ["removal", "declared call"] {
        m.fresh();
        assert_eq!(
            owner.step(&mut m),
            Ok(Reclaimed::Progress),
            "the {step} was not taken"
        );
    }
    m.fresh();
    assert_eq!(owner.step(&mut m), Err(BoundedError::PlanMismatch));
    assert_eq!(owner.outstanding(), 1);
    // The defect leaves custody its contract no longer describes: stepping
    // on, or the terminal drain dropping the owner would start, aborts by
    // design. The scope is deliberately leaked to end the test.
    std::mem::forget(owner);
}

#[test]
fn cancellation_reclaims_only_the_initialized_prefix() {
    for chunks in 0..=3 {
        CLEANED.set(0);
        let mut m = meter();
        let mut owner = scope(&mut m);
        let (record, _) = payload(&owner, &mut m, chunks);
        let held = m.live_bytes();
        drop(record);
        assert_eq!(m.live_bytes(), held);
        drain(&mut owner, &mut m);
        assert_eq!(CLEANED.get(), chunks * 64);
        assert_eq!(m.live_bytes(), 0);
    }
}

#[test]
fn text_build_publication_and_cancellation_keep_per_allocation_custody() {
    // Literal canonical text containing 65 ASCII bytes crosses a copy quantum.
    let mut wire = vec![0x78, 65];
    wire.extend_from_slice(&[b'x'; 65]);
    let boundaries =
        retired_text(&wire, usize::MAX).expect("text construction never reached publication");
    support::stop_matrix("retired text construction", boundaries, |stop| {
        assert_eq!(
            retired_text(&wire, stop).is_some(),
            stop == boundaries,
            "a stop after {stop} turns"
        );
    });
}

/// Construct the text `wire` holds, retiring the construction after `stop`
/// turns: retirement releases nothing, since handle drops only transfer
/// custody, and the scope's queued cleanup never acquires storage and
/// recovers everything, all within the decode's bound. The turns
/// construction took to publish, when it published within `stop`.
fn retired_text(wire: &[u8], stop: usize) -> Option<usize> {
    let bound = support::typed_turns::<String>(wire.len());
    let mut m = meter();
    let (mut owner, document) = document(&mut m, wire, Options::normalizing(8));
    let mut operation = Construction::<_, String, Limits>::construct(document);
    let mut output = None;
    let mut published = None;
    for turn in 0..stop.min(bound) {
        match support::checked(&mut m, |m| support::contracted(m, &mut operation)) {
            Ok(Step::Progress) | Err(DecodeError::Resource(BoundedError::Refused(_))) => {}
            Ok(Step::Complete(value)) => {
                support::exhausted(&mut m, &mut operation);
                assert_eq!(value.value().as_bytes(), &[b'x'; 65]);
                output = Some(value);
                published = Some(turn + 1);
                break;
            }
            _ => panic!("construction finished without publishing"),
        }
    }
    let held = m.live_bytes();
    drop(operation);
    drop(output);
    // Handle drops transfer custody; they cannot return any reservations.
    assert_eq!(m.live_bytes(), held);
    let mut previous = held;
    let mut drained = false;
    for _ in 0..bound {
        let result = support::checked(&mut m, |m| owner.shutdown_step(m)).unwrap();
        let live = m.live_bytes();
        assert!(live <= previous, "reclamation acquired new storage");
        previous = live;
        if result == Reclaimed::Done {
            drained = true;
            break;
        }
    }
    assert!(drained, "text cleanup exceeded its bound of {bound} turns");
    assert_eq!(m.live_bytes(), 0);
    published
}

#[test]
fn nested_vectors_construct_children_in_place_and_reclaim_all_allocations() {
    // [[1, 24], [], [256]], independently specified canonical bytes.
    let wire = [0x83, 0x82, 0x01, 0x18, 0x18, 0x80, 0x81, 0x19, 0x01, 0x00];
    let mut m = meter();
    let (mut owner, document) = document(&mut m, &wire, Options::normalizing(8));
    let output = support::construct::<_, Vec<Vec<u64>>>(&mut m, document)
        .expect("nested construction failed");
    assert_eq!(output.value(), &[vec![1, 24], vec![], vec![256]]);
    assert_eq!(output.bytes(), wire);
    let held = m.live_bytes();
    drop(output);
    assert_eq!(m.live_bytes(), held);
    drain(&mut owner, &mut m);
    assert_eq!(m.live_bytes(), 0);
}

#[cfg(feature = "derive")]
#[test]
fn derived_newtype_uses_stable_child_construction_and_cleanup() {
    #[derive(dcbor::CBORBoundedDecodable)]
    struct Wrapped(Vec<String>);

    let wire = [0x82, 0x61, b'a', 0x62, b'b', b'c'];
    let mut m = meter();
    let (mut owner, document) = document(&mut m, &wire, Options::normalizing(8));
    let output = support::construct::<_, Wrapped>(&mut m, document)
        .expect("newtype failed its finite completion bound");
    assert_eq!(output.value().0, ["a", "bc"]);
    drop(output);
    drain(&mut owner, &mut m);
    assert_eq!(m.live_bytes(), 0);
}

#[cfg(feature = "derive")]
#[test]
fn named_fields_build_in_wire_order_and_abort_missing_required_fields() {
    #[derive(dcbor::CBORBoundedDecodable)]
    struct Named {
        #[cbor(n = 9)]
        numbers: Vec<u64>,
        #[cbor(n = 1)]
        text: String,
    }
    // Unknown key 3 is ignored. Declaration order differs from wire order.
    let complete = &[0xa3, 1, 0x61, b'x', 3, 0xf6, 9, 0x81, 7][..];
    let missing = &[0xa1, 1, 0x61, b'x'][..];
    for wire in [complete, missing] {
        let mut m = meter();
        let (mut owner, document) = document(&mut m, wire, Options::normalizing(8));
        let mut operation = Construction::<_, Named, Limits>::construct(document);
        // The construction's own bound covers it, and its cleanup after the
        // missing field's rejection.
        let turns = support::typed_turns::<Named>(wire.len());
        match support::drive_within(&mut m, &mut operation, turns) {
            Ok(value) => {
                assert_eq!(wire, complete);
                assert_eq!(value.value().text, "x");
                assert_eq!(value.value().numbers, [7]);
            }
            Err(DecodeError::Invalid(dcbor::Error::MissingMapKey)) => {
                assert_eq!(wire, missing);
                support::finish_within(&mut m, &mut operation, turns);
                assert_eq!(owner.outstanding(), 0, "failed construction kept records");
            }
            Err(error) => panic!("unexpected named-field construction result: {error:?}"),
        }
        drop(operation);
        drain(&mut owner, &mut m);
        assert_eq!(m.live_bytes(), 0);
    }
}

#[cfg(feature = "derive")]
#[test]
fn tagged_named_construction_validates_tag_before_initializing_fields() {
    #[derive(dcbor::CBORBoundedDecodable)]
    #[cbor(tag = 42)]
    struct Tagged {
        #[cbor(n = 0)]
        number: u64,
    }
    for tag in [42, 43] {
        let wire = [0xd8, tag, 0xa1, 0, 7];
        let mut m = meter();
        let (mut owner, document) = document(&mut m, &wire, Options::normalizing(8));
        let mut operation = Construction::<_, Tagged, Limits>::construct(document);
        // The construction's own bound covers it, and its cleanup after the
        // wrong tag's rejection.
        let turns = support::typed_turns::<Tagged>(wire.len());
        match support::drive_within(&mut m, &mut operation, turns) {
            Ok(value) => {
                assert_eq!(tag, 42);
                assert_eq!(value.value().number, 7);
            }
            Err(DecodeError::Invalid(dcbor::Error::WrongTag(expected, found))) => {
                assert_eq!(expected.value(), 42);
                assert_eq!(found.value(), 43);
                support::finish_within(&mut m, &mut operation, turns);
                assert_eq!(owner.outstanding(), 0);
            }
            Err(error) => panic!("unexpected tagged construction result: {error:?}"),
        }
        drop(operation);
        drain(&mut owner, &mut m);
        assert_eq!(owner.outstanding(), 0);
        assert_eq!(m.live_bytes(), 0);
    }
}
