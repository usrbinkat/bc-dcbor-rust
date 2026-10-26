use super::*;

#[path = "enumeration.rs"]
mod enumeration;

/// Construct `T` from `wire`, observing that every transition is first
/// refused, without releasing anything, before it is admitted. An invalid
/// input fails once, then its cleanup runs to `Finished` under the same
/// refuse-then-admit discipline.
fn fixture<T: Transferable<Limits> + 'static>(wire: &[u8], inspect: impl Fn(&T), invalid: bool) {
    let mut m = meter();
    let (mut owner, document) = document(&mut m, wire, Options::normalizing(8));
    let mut operation = Construction::<_, T, Limits>::construct(document);
    let mut failed = false;
    let mut terminal = false;
    let refusals = m.refusals();
    // Construction to publication, or to its rejection and then its cleanup,
    // is within its cost, which the typed decode's bound includes.
    for _ in 0..support::typed_turns::<T>(wire.len()) {
        // Each transition first observes refusal with no released reservations.
        let held = m.live_bytes();
        let admitted = m.admitted().len();
        m.clear_refusal();
        m.exhaust();
        match support::contracted(&mut m, &mut operation) {
            Err(DecodeError::Resource(BoundedError::Refused(_))) => {}
            Ok(Step::Finished) if failed => {
                terminal = true;
                break;
            }
            Ok(Step::Progress) => {
                assert!(
                    m.live_bytes() < held
                        || (m.admitted().len() > admitted
                            && m.admitted()[admitted..]
                                .iter()
                                .all(|call| matches!(call, dcbor::bounded::Call::Allocate(_)))),
                    "progress neither released storage nor completed a prepaid acquisition"
                );
                continue;
            }
            other => panic!(
                "transition did work without admission: {} at {:?}",
                support::label(&other),
                operation.position()
            ),
        }
        assert_eq!(m.live_bytes(), held);
        match support::checked(&mut m, |m| support::contracted(m, &mut operation)) {
            Ok(Step::Progress) => {}
            Ok(Step::Complete(value)) => {
                assert!(!invalid);
                support::exhausted(&mut m, &mut operation);
                inspect(value.value());
                drop(value);
                terminal = true;
                break;
            }
            Ok(Step::Finished) if failed => {
                support::exhausted(&mut m, &mut operation);
                terminal = true;
                break;
            }
            Err(DecodeError::Invalid(_)) => {
                assert!(invalid);
                assert!(!failed, "terminal error replayed");
                failed = true;
            }
            Err(DecodeError::Resource(BoundedError::Refused(_))) => {}
            _ => panic!("unexpected schema transition"),
        }
    }
    drop(operation);
    drain(&mut owner, &mut m);
    assert!(terminal);
    assert_eq!(failed, invalid);
    assert!(m.refusals() > refusals);
    assert_eq!(owner.outstanding(), 0);
    assert_eq!(m.live_bytes(), 0);
}

#[test]
fn tagged_newtype_and_unit_have_separate_payload_custody() {
    #[derive(dcbor::CBORBoundedDecodable)]
    #[cbor(tag = 42)]
    struct Text(String);
    #[derive(dcbor::CBORBoundedDecodable)]
    #[cbor(tag = 42)]
    struct Unit;
    fixture::<Text>(&[0xd8, 42, 0x61, b'x'], |v| assert_eq!(v.0, "x"), false);
    fixture::<Text>(
        &[0xd8, 43, 0x61, b'x'],
        |_| panic!("wrong tag published"),
        true,
    );
    fixture::<Unit>(&[0xd8, 42, 0xf6], |_| {}, false);
    fixture::<Unit>(&[0xd8, 43, 0xf6], |_| panic!("wrong tag published"), true);
}

/// Every derived construction is within the cost its derive generates, built
/// or failed: records with present, omitted, unknown and wrong-kind fields,
/// tagged records with the right and wrong tag, newtypes, units, and enums
/// of every shape with known and unknown discriminants.
#[test]
fn every_derived_construction_is_within_its_cost() {
    use support::{builds_within_cost as builds, rejects_within_cost as rejects};
    #[derive(dcbor::CBORBoundedDecodable)]
    struct Fields {
        #[cbor(n = 0)]
        before: Option<u64>,
        #[cbor(n = 1)]
        required: u64,
        #[cbor(n = 2)]
        after: Option<String>,
        #[cbor(n = 3)]
        list: Vec<String>,
    }
    #[derive(dcbor::CBORBoundedDecodable)]
    #[cbor(tag = 42)]
    struct Tagged {
        #[cbor(n = 0)]
        number: u64,
    }
    #[derive(dcbor::CBORBoundedDecodable)]
    struct Wrapped(Vec<String>);
    #[derive(dcbor::CBORBoundedDecodable)]
    #[cbor(tag = 7)]
    struct TaggedWrapped(String);
    #[derive(dcbor::CBORBoundedDecodable)]
    struct Unit;
    #[derive(dcbor::CBORBoundedDecodable)]
    #[repr(C, u8)]
    enum Choice {
        #[cbor(n = 0)]
        Empty,
        #[cbor(n = 1)]
        Text(String, u64),
        #[cbor(n = 2)]
        Named {
            #[cbor(n = 0)]
            value: String,
        },
    }
    let long = "y".repeat(300);
    let mut record = vec![0xa4, 0, 9, 1, 7, 2, 0x79, 0x01, 0x2c];
    record.extend(long.as_bytes());
    record.extend([3, 0x82, 0x61, b'a', 0x61, b'b']);
    builds::<Fields>(&record, |v| {
        assert_eq!((v.before, v.required), (Some(9), 7));
        assert_eq!(v.after.as_deref(), Some(long.as_str()));
        assert_eq!(v.list, ["a", "b"]);
    });
    builds::<Fields>(&[0xa2, 1, 7, 3, 0x80], |v| {
        assert_eq!((v.before, v.required, v.after.as_deref()), (None, 7, None));
        assert!(v.list.is_empty());
    });
    // An unknown key is skipped; a missing required field fails.
    builds::<Fields>(&[0xa3, 1, 7, 3, 0x80, 9, 0xf5], |v| {
        assert_eq!(v.required, 7)
    });
    rejects::<Fields>(&[0xa1, 3, 0x80]);
    rejects::<Fields>(&[0xa2, 1, 0x61, b'x', 3, 0x80]);
    builds::<Tagged>(&[0xd8, 42, 0xa1, 0, 7], |v| assert_eq!(v.number, 7));
    rejects::<Tagged>(&[0xd8, 43, 0xa1, 0, 7]);
    builds::<Wrapped>(&[0x82, 0x61, b'a', 0x62, b'b', b'c'], |v| {
        assert_eq!(v.0, ["a", "bc"])
    });
    builds::<TaggedWrapped>(&[0xc7, 0x61, b'x'], |v| assert_eq!(v.0, "x"));
    rejects::<TaggedWrapped>(&[0xc8, 0x61, b'x']);
    builds::<Unit>(&[0xf6], |_| {});
    rejects::<Unit>(&[0x00]);
    builds::<Choice>(&[0x00], |v| assert!(matches!(v, Choice::Empty)));
    builds::<Choice>(&[0x83, 0x01, 0x61, b'x', 0x05], |v| {
        assert!(matches!(v, Choice::Text(text, 5) if text == "x"))
    });
    builds::<Choice>(&[0x82, 0x02, 0xa1, 0x00, 0x61, b'x'], |v| {
        assert!(matches!(v, Choice::Named { value } if value == "x"))
    });
    rejects::<Choice>(&[0x03]);
    rejects::<Choice>(&[0x82, 0x01, 0x61, b'x']);
}

/// An enum's selection is charged exactly the term its cost declares
/// ([`enumeration::selection`]): a discriminant no variant has is compared
/// with every variant and then rejected, one value per call, the most a
/// selection takes. The selection is measured as the calls made while the
/// enum is observed in its `Select` phase; the cleanup that follows takes
/// exactly the calls the state declares.
#[test]
fn an_unknown_discriminant_takes_exactly_the_declared_selection() {
    use dcbor::bounded::decode::construction::in_place::enumeration::{
        self, EnumObservation, EnumPhase, Variants,
    };
    use dcbor::bounded::decode::construction::in_place::{Built, STEP_COST, times};
    #[derive(dcbor::CBORBoundedDecodable)]
    #[repr(C, u8)]
    enum Choice {
        #[cbor(n = 0)]
        Empty,
        #[cbor(n = 1)]
        Text(String, u64),
        #[cbor(n = 2)]
        Named {
            #[cbor(n = 0)]
            value: String,
        },
    }
    // The array form, its discriminant 3 past every variant.
    let wire = [0x82, 0x03, 0x61, b'x'];
    let mut parser = Limits::unlimited();
    let document = dcbor::bounded::decode::decode(&wire, 1, &mut parser).unwrap();
    let mut a = Limits::unlimited();
    let mut place = MaybeUninit::<Choice>::uninit();
    let place = NonNull::from(&mut place);
    let mut state = <Choice as Reclaim<Limits>>::INITIAL;
    let count = <Choice as Variants<Limits>>::COUNT;
    let (mut selecting, mut charged) = (0u64, 0u64);
    // Installation, the tag, shape and discriminant inspections, then at
    // most one selection call per variant and the rejection.
    let mut rejection = None;
    for _ in 0..4 + count + 1 {
        let selects = matches!(
            state.observe(),
            EnumObservation::Held {
                phase: EnumPhase::Select { .. },
                ..
            }
        );
        let before = a.used().values;
        let result = unsafe {
            enumeration::build::<Choice, Limits>(&document, 0, place, &mut state, &mut a)
        };
        if selects {
            selecting += 1;
            charged += a.used().values - before;
        }
        match result {
            Ok(Built::Progress) => {}
            Ok(Built::Done) => panic!("built from a discriminant no variant has"),
            Err(error) => {
                rejection = Some(error);
                break;
            }
        }
    }
    let rejection = rejection.expect("the selection rejects within its declared calls");
    assert!(
        matches!(rejection, DecodeError::Invalid(_)),
        "an unknown discriminant is invalid input: {rejection:?}"
    );
    assert_eq!(
        selecting,
        count as u64 + 1,
        "every variant compared, then the rejection"
    );
    assert_eq!(charged, selecting, "one value per selection call");
    assert_eq!(
        enumeration::selection(count),
        times(STEP_COST, selecting),
        "the declared selection against the measured"
    );
    let declared = unsafe { enumeration::remaining::<Choice, Limits>(place, &mut state) };
    let mut taken = 0u64;
    loop {
        taken += 1;
        assert!(
            taken <= declared,
            "cleanup beyond its declared {declared} calls"
        );
        match unsafe { enumeration::reclaim::<Choice, Limits>(place, &mut state, &mut a) }.unwrap()
        {
            Reclaimed::Done => break,
            Reclaimed::Progress => {}
            Reclaimed::Waiting => panic!("an enum's own cleanup never waits"),
        }
    }
    assert_eq!(taken, declared, "the cleanup's declared calls");
    assert_eq!(a.live_bytes(), 0);
    // The same enum's known discriminants select their variants and build
    // their payloads.
    support::builds_within_cost::<Choice>(&[0x00], |v| assert!(matches!(v, Choice::Empty)));
    support::builds_within_cost::<Choice>(&[0x83, 0x01, 0x61, b'x', 0x05], |v| {
        assert!(matches!(v, Choice::Text(text, 5) if text == "x"))
    });
    support::builds_within_cost::<Choice>(&[0x82, 0x02, 0xa1, 0x00, 0x61, b'x'], |v| {
        assert!(matches!(v, Choice::Named { value } if value == "x"))
    });
}

/// The units of one keyed entry, measured: the record of `T`, whose fields
/// are keyed from 1 and all optional, built from `wire`, a map whose first
/// entry is the unknown key 0. Counts the calls made while the record is
/// observed finding or searching before the map's end, each admitting one
/// value; then the record is built, its absent fields written, and cleaned
/// up within the calls its state declares.
fn unknown_entry_units<T>(wire: &[u8]) -> u64
where
    T: dcbor::bounded::decode::construction::in_place::fields::Fields<Limits>
        + Reclaim<
            Limits,
            State = dcbor::bounded::decode::construction::in_place::fields::State<
                <T as dcbor::bounded::decode::construction::in_place::fields::Fields<Limits>>::Field,
                dcbor::bounded::Reservation,
            >,
        >,
{
    use dcbor::bounded::decode::construction::in_place::Built;
    use dcbor::bounded::decode::construction::in_place::fields::{self, FieldsObservation, Phase};
    let mut parser = Limits::unlimited();
    let document = dcbor::bounded::decode::decode(wire, 1, &mut parser).unwrap();
    let mut a = Limits::unlimited();
    let mut place = MaybeUninit::<T>::uninit();
    let place = NonNull::from(&mut place);
    let mut state = <T as Reclaim<Limits>>::INITIAL;
    let (mut searching, mut charged) = (0u64, 0u64);
    let mut built = false;
    for _ in 0..support::TURNS {
        let entry = matches!(
            state.observe(),
            FieldsObservation::Held(custody)
                if matches!(custody.phase, Phase::Find | Phase::Search)
                    && custody.next != custody.end
        );
        let before = a.used().values;
        let result = unsafe { fields::build::<T, Limits>(&document, 0, place, &mut state, &mut a) };
        if entry {
            searching += 1;
            charged += a.used().values - before;
        }
        if result.expect("a record of optional fields builds") == Built::Done {
            built = true;
            break;
        }
    }
    assert!(
        built,
        "the record was not built within {} calls",
        support::TURNS
    );
    assert_eq!(charged, searching, "one value per find and search call");
    let declared = unsafe { fields::remaining::<T, Limits>(place, &mut state) };
    let mut taken = 0u64;
    loop {
        taken += 1;
        assert!(
            taken <= declared,
            "cleanup beyond its declared {declared} calls"
        );
        match unsafe { fields::reclaim::<T, Limits>(place, &mut state, &mut a) }.unwrap() {
            Reclaimed::Done => break,
            Reclaimed::Progress => {}
            Reclaimed::Waiting => panic!("a record's own cleanup never waits"),
        }
    }
    assert_eq!(taken, declared, "the cleanup's declared calls");
    assert_eq!(a.live_bytes(), 0);
    searching
}

/// A keyed entry is charged exactly the units its cost declares
/// ([`fields::entry`]), and the record's per-byte entry term charges a
/// minimal entry, a one-byte key and a one-byte value, exactly one entry
/// ([`fields::entries`]): an unknown key below every field's is found,
/// compared `floor(log2 count) + 1` times and its value skipped, for a
/// record of one field and of four.
#[test]
fn an_unknown_key_takes_exactly_the_declared_entry() {
    use dcbor::bounded::decode::construction::in_place::fields;
    use dcbor::bounded::decode::construction::in_place::{STEP_COST, times};
    #[derive(dcbor::CBORBoundedDecodable)]
    struct One {
        #[cbor(n = 1)]
        a: Option<u64>,
    }
    #[derive(dcbor::CBORBoundedDecodable)]
    struct Four {
        #[cbor(n = 1)]
        a: Option<u64>,
        #[cbor(n = 2)]
        b: Option<u64>,
        #[cbor(n = 3)]
        c: Option<u64>,
        #[cbor(n = 4)]
        d: Option<u64>,
    }
    // {0: true}: one entry of two bytes, its key below every field's.
    let wire = [0xa1, 0x00, 0xf5];
    for (count, measured) in [
        (1usize, unknown_entry_units::<One>(&wire)),
        (4, unknown_entry_units::<Four>(&wire)),
    ] {
        assert_eq!(
            measured,
            count.ilog2() as u64 + 3,
            "a find, every comparison and the skip, of {count} fields"
        );
        assert_eq!(
            fields::entry(count),
            times(STEP_COST, measured),
            "the declared entry of {count} fields against the measured"
        );
        assert_eq!(
            fields::entries(count).bound::<()>(2).unwrap(),
            times(STEP_COST, measured),
            "the per-byte entry term over a two-byte entry of {count} fields"
        );
    }
}

/// Every derived container's observation is complete for custody
/// ([`support::observation`]) and every transition is in its successor
/// relations ([`support::legal`]): field maps with present, omitted,
/// unknown and wrong-kind fields and a missing required one; an enum of
/// every shape with a known and an unknown discriminant; a tagged field map
/// with the right and the wrong tag; and a newtype over a vector, its state
/// the vector's own. A generated field or payload state is related only by
/// its changes ([`support::legality::opaque`]).
#[test]
fn derived_container_transitions_are_legal() {
    use support::legality::{buffer, enumeration, fields, opaque, sequence};
    use support::{legal, observation};
    #[derive(dcbor::CBORBoundedDecodable)]
    struct Fields {
        #[cbor(n = 0)]
        before: Option<u64>,
        #[cbor(n = 1)]
        required: u64,
        #[cbor(n = 2)]
        after: Option<String>,
        #[cbor(n = 3)]
        list: Vec<String>,
    }
    #[derive(dcbor::CBORBoundedDecodable)]
    #[cbor(tag = 42)]
    struct Tagged {
        #[cbor(n = 0)]
        number: u64,
    }
    #[derive(dcbor::CBORBoundedDecodable)]
    struct Wrapped(Vec<String>);
    #[derive(dcbor::CBORBoundedDecodable)]
    #[repr(C, u8)]
    enum Choice {
        #[cbor(n = 0)]
        Empty,
        #[cbor(n = 1)]
        Text(String, u64),
        #[cbor(n = 2)]
        Named {
            #[cbor(n = 0)]
            value: String,
        },
    }
    let records: [&[u8]; 5] = [
        // Every field, the optional text present.
        &[
            0xa4, 0, 9, 1, 7, 2, 0x61, b'y', 3, 0x82, 0x61, b'a', 0x61, b'b',
        ],
        // Optional fields omitted.
        &[0xa2, 1, 7, 3, 0x80],
        // An unknown key skipped.
        &[0xa3, 1, 7, 3, 0x80, 9, 0xf5],
        // The required field missing.
        &[0xa1, 3, 0x80],
        // The required field of the wrong kind.
        &[0xa2, 1, 0x61, b'x', 3, 0x80],
    ];
    for wire in records {
        let name = format!("derived fields from {wire:02x?}");
        legal(
            &name,
            &observation::<Fields, _>(&name, wire, |o| *o),
            &fields(opaque()),
        );
    }
    // Check the payloads independently of their custody projections: a legal
    // continuation must also construct the exact variant and field values.
    support::builds_within_cost::<Choice>(&[0x00], |value| {
        assert!(matches!(value, Choice::Empty));
    });
    support::builds_within_cost::<Choice>(&[0x83, 0x01, 0x61, b'x', 0x05], |value| {
        let Choice::Text(text, number) = value else {
            panic!("text variant was not constructed");
        };
        assert_eq!(text, "x");
        assert_eq!(*number, 5);
    });
    support::builds_within_cost::<Choice>(&[0x82, 0x02, 0xa1, 0x00, 0x61, b'x'], |value| {
        let Choice::Named { value } = value else {
            panic!("named variant was not constructed");
        };
        assert_eq!(value, "x");
    });
    let choices: [&[u8]; 5] = [
        &[0x00],
        &[0x83, 0x01, 0x61, b'x', 0x05],
        &[0x82, 0x02, 0xa1, 0x00, 0x61, b'x'],
        &[0x03],
        &[0x82, 0x01, 0x61, b'x'],
    ];
    for wire in choices {
        let name = format!("derived enum from {wire:02x?}");
        legal(
            &name,
            &observation::<Choice, _>(&name, wire, |o| *o),
            &enumeration(opaque()),
        );
    }
    for wire in [&[0xd8, 42, 0xa1, 0, 7][..], &[0xd8, 43, 0xa1, 0, 7]] {
        let name = format!("tagged fields from {wire:02x?}");
        legal(
            &name,
            &observation::<Tagged, _>(&name, wire, |o| *o),
            // Named records validate their tag inside the field-map machine;
            // only tagged newtypes and units use the tagged wrapper state.
            &fields(opaque()),
        );
    }
    let name = "derived newtype over Vec<String>";
    legal(
        name,
        &observation::<Wrapped, _>(name, &[0x82, 0x61, b'a', 0x62, b'b', b'c'], |o| *o),
        &sequence(buffer(), false),
    );
}

/// A derived tagged value whose untagged payload reduces, a newtype over
/// text or a unit, carries the tagged binding's declared reduction over its
/// payload's: certified on every state its construction reaches
/// ([`support::certified`]), and every transition in the tagged relations
/// over the payload's ([`support::legal`]). Built, refused at the tag's
/// inspection, and, for the newtype, refused by the payload's own.
#[test]
fn derived_tagged_bindings_are_certified_and_their_transitions_legal() {
    use support::legality::{buffer, tagged, written};
    use support::{certified, legal};
    #[derive(dcbor::CBORBoundedDecodable)]
    #[cbor(tag = 7)]
    struct TaggedText(String);
    #[derive(dcbor::CBORBoundedDecodable)]
    #[cbor(tag = 42)]
    struct TaggedUnit;
    for wire in [&[0xc7, 0x61, b'x'][..], &[0xc8, 0x61, b'x'], &[0xc7, 0x07]] {
        let name = format!("tagged text from {wire:02x?}");
        legal(
            &name,
            &certified::<TaggedText>(&name, wire),
            &tagged(buffer()),
        );
    }
    for wire in [&[0xd8, 42, 0xf6][..], &[0xd8, 43, 0xf6], &[0xd8, 42, 0x07]] {
        let name = format!("tagged unit from {wire:02x?}");
        legal(
            &name,
            &certified::<TaggedUnit>(&name, wire),
            &tagged(written()),
        );
    }
}

#[test]
fn fixed_arrays_require_their_exact_length_and_reclaim_committed_prefixes() {
    fixture::<[String; 2]>(
        &[0x82, 0x61, b'a', 0x62, b'b', b'c'],
        |v| assert_eq!(v, &["a", "bc"]),
        false,
    );
    fixture::<[u64; 0]>(&[0x80], |v| assert!(v.is_empty()), false);
    fixture::<[String; 2]>(
        &[0x83, 0x61, b'a', 0x61, b'b', 0x61, b'c'],
        |_| panic!("three elements published as two"),
        true,
    );
    fixture::<[String; 2]>(
        &[0x81, 0x61, b'a'],
        |_| panic!("one element published as two"),
        true,
    );
    fixture::<[String; 2]>(
        &[0x61, b'a'],
        |_| panic!("text published as an array"),
        true,
    );
    // The second element fails after the first committed: the committed
    // prefix and the partial element are both reclaimed.
    fixture::<[String; 2]>(
        &[0x82, 0x61, b'a', 0x01],
        |_| panic!("an integer published as text"),
        true,
    );
}

#[test]
fn refused_allocations_conserve_derived_field_work() {
    #[derive(dcbor::CBORBoundedDecodable)]
    struct Fields {
        #[cbor(n = 0)]
        before: Option<u64>,
        #[cbor(n = 1)]
        required: u64,
        #[cbor(n = 2)]
        after: Option<String>,
    }
    // Absent optional, required scalar, present optional text.
    super::refused_allocations_conserve_work::<Fields>(&[0xa2, 1, 7, 2, 0x61, b'x'], &|v| {
        assert_eq!(v.before, None);
        assert_eq!(v.required, 7);
        assert_eq!(v.after.as_deref(), Some("x"));
    });
}

#[test]
fn optional_omission_and_present_payload_are_distinct() {
    #[derive(dcbor::CBORBoundedDecodable)]
    struct Fields {
        #[cbor(n = 0)]
        before: Option<u64>,
        #[cbor(n = 1)]
        required: u64,
        #[cbor(n = 2)]
        after: Option<String>,
    }
    fixture::<Fields>(
        &[0xa1, 1, 7],
        |v| {
            assert_eq!(v.before, None);
            assert_eq!(v.required, 7);
            assert_eq!(v.after, None);
        },
        false,
    );
    fixture::<Fields>(
        &[0xa3, 0, 9, 1, 7, 2, 0x61, b'x'],
        |v| {
            assert_eq!(v.before, Some(9));
            assert_eq!(v.required, 7);
            assert_eq!(v.after.as_deref(), Some("x"));
        },
        false,
    );
    fixture::<Fields>(&[0xa2, 0, 0xf6, 1, 7], |_| panic!("null published"), true);
    fixture::<Fields>(
        &[0xa0],
        |_| panic!("missing required field published"),
        true,
    );
}
