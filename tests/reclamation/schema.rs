use super::*;
use dcbor::bounded::decode::construction::reclamation::Place;
use std::mem::MaybeUninit;
use std::ptr::NonNull;

#[path = "enumeration.rs"]
mod enumeration;

/// Step a binding's cleanup to `Done` through `reclaim`, requiring it to
/// take exactly the `declared` calls its state declared when cleanup began
/// ([`Reclaim::remaining`]): never more, which would break the binding's
/// contract, and, for these exact witnesses, never fewer.
fn reclaims_as_declared(what: &str, declared: u64, mut reclaim: impl FnMut() -> Reclaimed) {
    let mut taken = 0u64;
    loop {
        taken += 1;
        assert!(
            taken <= declared,
            "{what}: cleanup beyond its declared {declared} calls"
        );
        match reclaim() {
            Reclaimed::Done => break,
            Reclaimed::Progress => {}
            Reclaimed::Waiting => panic!("{what}: a binding's own cleanup never waits"),
        }
    }
    assert_eq!(taken, declared, "{what}: the cleanup's declared calls");
}

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
    let mut value = MaybeUninit::<Choice>::uninit();
    let mut state = <Choice as Reclaim<Limits>>::INITIAL;
    // SAFETY: the test owns the destination and pairs it with its initial
    // state; every access to either is through this slot for the test.
    let mut slot = unsafe { Slot::new(Place::root(NonNull::from(&mut value)), &mut state) };
    let count = <Choice as Variants<Limits>>::COUNT;
    let (mut selecting, mut charged) = (0u64, 0u64);
    // Installation, the tag, shape and discriminant inspections, then at
    // most one selection call per variant and the rejection.
    let mut rejection = None;
    for _ in 0..4 + count + 1 {
        let selects = matches!(
            slot.custody().observe(),
            EnumObservation::Held {
                phase: EnumPhase::Select { .. },
                ..
            }
        );
        let before = a.used().values;
        let result = enumeration::build::<Choice, Limits>(&document, 0, slot.reborrow(), &mut a);
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
    let declared = enumeration::remaining::<Choice, Limits>(slot.observe());
    reclaims_as_declared("an enum", declared, || {
        enumeration::reclaim::<Choice, Limits>(slot.reborrow(), &mut a).unwrap()
    });
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
/// are all optional, built from `wire`, a map of that one entry. Counts the
/// calls made while the record is observed finding or searching before the
/// map's end, each admitting one value; then the record is built, its
/// absent fields written, and cleaned up within the calls its state
/// declares.
fn entry_units<T>(wire: &[u8]) -> u64
where
    T: dcbor::bounded::decode::construction::in_place::fields::Fields<Limits>
        + dcbor::bounded::decode::construction::in_place::InPlace<Limits>
        + Reclaim<
            Limits,
            State = dcbor::bounded::decode::construction::in_place::fields::State<
                <T as dcbor::bounded::decode::construction::in_place::fields::Fields<Limits>>::Field,
                dcbor::bounded::Reservation,
            >,
        >,
{
    use dcbor::bounded::decode::construction::in_place::fields::{self, FieldsObservation, Phase};
    use dcbor::bounded::decode::construction::in_place::{Built, InPlace};
    let mut parser = Limits::unlimited();
    let document = dcbor::bounded::decode::decode(wire, 1, &mut parser).unwrap();
    let mut a = Limits::unlimited();
    let mut value = MaybeUninit::<T>::uninit();
    let mut state = <T as Reclaim<Limits>>::INITIAL;
    // SAFETY: the function owns the destination and pairs it with its initial
    // state; every access to either is through this slot until it returns.
    let mut slot = unsafe { Slot::new(Place::root(NonNull::from(&mut value)), &mut state) };
    let (mut searching, mut charged) = (0u64, 0u64);
    let mut built = false;
    // The record's own cost bounds its build calls; the unlimited policy
    // never refuses.
    let calls = support::turns(
        <T as InPlace<Limits>>::COST
            .bound::<()>(wire.len() as u64)
            .expect("the cost of a fixture fits in u64"),
    );
    for _ in 0..calls {
        let entry = matches!(
            slot.custody().observe(),
            FieldsObservation::Held(custody)
                if matches!(custody.phase, Phase::Find | Phase::Search)
                    && custody.next != custody.end
        );
        let before = a.used().values;
        let result = fields::build::<T, Limits>(&document, 0, slot.reborrow(), &mut a);
        if entry {
            searching += 1;
            charged += a.used().values - before;
        }
        if result.expect("a record of optional fields builds") == Built::Done {
            built = true;
            break;
        }
    }
    assert!(built, "the record was not built within {calls} calls");
    assert_eq!(charged, searching, "one value per find and search call");
    let declared = fields::remaining::<T, Limits>(slot.observe());
    reclaims_as_declared("a record", declared, || {
        fields::reclaim::<T, Limits>(slot.reborrow(), &mut a).unwrap()
    });
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
        (1usize, entry_units::<One>(&wire)),
        (4, entry_units::<Four>(&wire)),
    ] {
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

/// The find and search calls the half-interval binary search specifies for
/// an entry whose key is `key` (none for a key that is not an integer) over
/// fields keyed `keys`, ascending: the find; then, while the interval
/// `[low, high)` is nonempty, one comparison with its midpoint, rounded
/// down, ending at an equal key; an exhausted interval, or a key that is
/// not an integer, takes one more call to skip the entry's value.
fn search_path(keys: &[u64], key: Option<u64>) -> u64 {
    let Some(key) = key else {
        return 2;
    };
    let (mut low, mut high, mut calls) = (0usize, keys.len(), 1u64);
    loop {
        calls += 1;
        if low >= high {
            return calls;
        }
        let mid = low + (high - low) / 2;
        match key.cmp(&keys[mid]) {
            std::cmp::Ordering::Less => high = mid,
            std::cmp::Ordering::Greater => low = mid + 1,
            std::cmp::Ordering::Equal => return calls,
        }
    }
}

/// Every key position takes exactly the search path the binary search
/// specifies ([`search_path`], derived from the specification, not from the
/// cost), and no path exceeds the declared entry ([`fields::entry`]): keys
/// below every field, between each two, equal to each, past the last, and
/// a key that is not an integer, over a record of five optional fields
/// keyed 2, 4, 6, 8 and 10. The worst position attains the declared entry.
#[test]
fn every_key_position_takes_its_search_path_within_the_declared_entry() {
    use dcbor::bounded::decode::construction::in_place::fields;
    #[derive(dcbor::CBORBoundedDecodable)]
    struct Five {
        #[cbor(n = 2)]
        a: Option<u64>,
        #[cbor(n = 4)]
        b: Option<u64>,
        #[cbor(n = 6)]
        c: Option<u64>,
        #[cbor(n = 8)]
        d: Option<u64>,
        #[cbor(n = 10)]
        e: Option<u64>,
    }
    let keys = [2u64, 4, 6, 8, 10];
    let declared = fields::entry(keys.len()).values;
    let mut worst = 0;
    // Each integer key 0 through 11 as a one-entry map {key: 7}, then a text
    // key, {"x": 7}.
    let mut wires: Vec<(Option<u64>, Vec<u8>)> = (0u8..12)
        .map(|key| (Some(u64::from(key)), vec![0xa1, key, 0x07]))
        .collect();
    wires.push((None, vec![0xa1, 0x61, b'x', 0x07]));
    for (key, wire) in wires {
        let measured = entry_units::<Five>(&wire);
        assert_eq!(
            measured,
            search_path(&keys, key),
            "the search path of key {key:?}"
        );
        assert!(
            measured <= declared,
            "key {key:?} took {measured} calls, beyond the declared {declared}"
        );
        worst = worst.max(measured);
    }
    assert_eq!(
        worst, declared,
        "the worst position attains the declared entry"
    );
}

/// A text whose every copy backs off to a scalar boundary is within its
/// cost, and the per-byte copy term is exactly what its copies require: the
/// values a copy charges for every sixty-fourth's share of the fewest bytes
/// a copy but the last covers, both measured from the construction (the
/// copied count it observes between copy calls, and the meter's values per
/// call). A leading run of 61 ASCII bytes puts a four-byte scalar across the
/// first quantum's end, and each period of 57 ASCII bytes and one such
/// scalar puts the next one across the next copy's end, so every copy but
/// the last backs off its three continuation bytes.
#[test]
fn a_text_whose_every_copy_backs_off_is_within_its_cost() {
    use dcbor::bounded::decode::construction::in_place::{
        BufferCustody, BufferObservation, BufferPhase, Built, InPlace, PER_BYTE_SCALE,
    };
    let mut text = "a".repeat(61);
    for _ in 0..400 {
        text.push('\u{1f600}');
        text.push_str(&"a".repeat(57));
    }
    let wire = dcbor::CBOR::from(text.as_str()).to_cbor_data();
    support::builds_within_cost::<String>(&wire, |v| assert_eq!(v, &text));
    let mut parser = Limits::unlimited();
    let document = dcbor::bounded::decode::decode(&wire, 1, &mut parser).unwrap();
    let mut a = Limits::unlimited();
    let mut value = MaybeUninit::<String>::uninit();
    let mut state = <String as Reclaim<Limits>>::INITIAL;
    // SAFETY: the test owns the destination and pairs it with its initial
    // state; every access to either is through this slot for the test.
    let mut slot = unsafe { Slot::new(Place::root(NonNull::from(&mut value)), &mut state) };
    // Bytes covered and values charged by each copy call, in order.
    let mut copies = Vec::new();
    let mut built = false;
    // The text's own cost bounds its build calls; the unlimited policy never
    // refuses.
    let calls = support::turns(
        <String as InPlace<Limits>>::COST
            .bound::<()>(wire.len() as u64)
            .expect("the cost of a fixture fits in u64"),
    );
    for _ in 0..calls {
        let copying = match slot.custody().observe() {
            BufferObservation::Held(BufferCustody {
                phase: BufferPhase::Copy,
                copied,
                ..
            }) => Some(copied),
            _ => None,
        };
        let before = a.used().values;
        let step = <String as InPlace<Limits>>::build_step(&document, 0, slot.reborrow(), &mut a)
            .expect("the text builds");
        if let (Some(start), BufferObservation::Held(BufferCustody { copied, .. })) =
            (copying, slot.custody().observe())
        {
            copies.push((copied - start, a.used().values - before));
        }
        if step == Built::Done {
            built = true;
            break;
        }
    }
    assert!(built, "the text was not built within {calls} calls");
    assert_eq!(
        copies.iter().map(|(bytes, _)| bytes).sum::<usize>(),
        text.len(),
        "every byte copied once"
    );
    let (last, others) = copies.split_last().expect("a text of many quanta copies");
    assert!(last.0 > 0, "the last copy covers the rest");
    let fewest = others
        .iter()
        .map(|(bytes, _)| *bytes as u64)
        .min()
        .expect("more than one copy");
    let charged = copies[0].1;
    assert!(
        copies.iter().all(|(_, values)| *values == charged),
        "every copy charges alike: {copies:?}"
    );
    assert_eq!(
        <String as InPlace<Limits>>::COST.per_byte.values,
        charged * PER_BYTE_SCALE.div_ceil(fewest),
        "the per-byte copy term against the fewest bytes a copy covered ({fewest})"
    );
    let declared = <String as Reclaim<Limits>>::remaining(slot.observe());
    reclaims_as_declared("a text", declared, || {
        <String as Reclaim<Limits>>::reclaim_step(slot.reborrow(), &mut a).unwrap()
    });
    assert_eq!(a.live_bytes(), 0);
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
