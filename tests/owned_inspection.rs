//! Production-backed owned inspection and operation-local cancellation matrix.
#[global_allocator]
static HEAP: heap::Heap = heap::Heap;
use dcbor::ByteString;
use dcbor::bounded::{
    BoundedError, Call, Limits, Step,
    decode::{DecodeError, Options, construction::DocumentDecoder},
};
use dcbor_test_support::classes::{self, Class, Classes};
use dcbor_test_support::pipeline::{Expected, inspect, matrix};
use dcbor_test_support::rigor::{Progress, Rigor, rigor};
use dcbor_test_support::{self as support, heap};

fn meter() -> Limits {
    Limits::unlimited().logged().strict()
}

/// What one run of [`shared_owner`] reached: the second inspection's turns,
/// the cleanup class of its position at each boundary ([`classes::parse`]),
/// and the calls admitted from the cut on, through the scope's drain.
struct Run {
    turns: usize,
    classes: Vec<Option<Class>>,
    cleanup: Vec<Call>,
}

/// Two inspections in one scope: the first's document held live while the
/// second parses, cancelled at its `cut`th boundary when one is given.
fn shared_owner(cut: Option<usize>) -> Run {
    const OPTIONS: Options = Options::normalizing(16);
    let mut m = meter();
    let mut owner = support::scope(&mut m);
    let first = support::copy(&owner, &mut m, &[0x81, 0x01]);
    let document = support::parse(&mut m, first, OPTIONS).expect("first inspection failed");
    let source = dcbor::CBOR::from("\u{301}".repeat(128)).to_cbor_data();
    let second = support::copy(&owner, &mut m, &source);
    let mut second = DocumentDecoder::parse(second, OPTIONS);
    // The whole operation, its record's cleanup included, is within its
    // parse bound, and a cancelled one runs a prefix of its parse, then that
    // cleanup; the copied input it holds is reclaimed in it too, and that
    // input's cleanup is accounted by its acquisition's bound, not the
    // parse's.
    let len = source.len() as u64;
    let bound = support::turns(
        dcbor::bounded::decode::construction::parse_bound::<ByteString, Limits, ()>(len, OPTIONS)
            .expect("the parse bound of an input held in memory fits in u64"),
    ) + support::turns(
        dcbor::bounded::decode::construction::copy_bound::<Limits, ()>(len)
            .expect("the copy bound of an input held in memory fits in u64"),
    );
    let mut turns = 0;
    let mut finished = false;
    let mut cancellation_refused = false;
    let mut published = None;
    let mut classes = Vec::new();
    let mut cut_at = None;
    for turn in 0..bound {
        turns += 1;
        classes.push(classes::parse(&second.position()));
        if cut == Some(turn) {
            cut_at = Some(m.admitted().len());
            second.cancel();
            // An exhausted turn positively refuses the first cleanup unit.
            m.clear_refusal();
            m.exhaust();
            cancellation_refused = matches!(
                support::contracted(&mut m, &mut second),
                Err(DecodeError::Resource(BoundedError::Refused(_)))
            );
        }
        match support::checked(&mut m, |m| support::contracted(m, &mut second)) {
            Ok(Step::Complete(value)) => {
                support::exhausted(&mut m, &mut second);
                published = Some(value);
                finished = true;
                break;
            }
            Ok(Step::Finished) => {
                support::exhausted(&mut m, &mut second);
                finished = true;
                break;
            }
            Ok(Step::Progress) | Err(DecodeError::Resource(BoundedError::Refused(_))) => {}
            _ => panic!("second inspection failed"),
        }
        assert_eq!(document.root().encoded(), [0x81, 0x01]);
    }
    // B must finish before A is retired. A's bytes and arena remain usable.
    document.with_document(|view| assert_eq!(view.root().encoded(), [0x81, 0x01]));
    assert_eq!(document.bytes(), [0x81, 0x01]);
    let cancelled = cut.is_some();
    let unexpectedly_published = cancelled && published.is_some();
    drop(second);
    drop(published);
    drop(document);
    support::drain(&mut owner, &mut m);
    assert!(
        finished,
        "the second inspection exceeded its bound of {bound} turns"
    );
    assert!(!unexpectedly_published);
    assert!(!cancelled || cancellation_refused);
    assert_eq!(m.live_bytes(), 0);
    let cleanup = cut_at.map_or_else(Vec::new, |at| m.admitted()[at..].to_vec());
    Run {
        turns,
        classes,
        cleanup,
    }
}

/// The second inspection cancelled at its boundaries while the first's
/// document stays live and readable. The fast layer cancels at the first
/// boundary of each parse class and at every boundary of none; the
/// exhaustive layer at every boundary, every member of a class required to
/// clean up with exactly the calls its first member admitted.
#[test]
fn inspection_cancellation_at_every_turn_is_independent_of_live_document() {
    let baseline = shared_owner(None);
    let mut first = std::collections::BTreeSet::new();
    let selected: Vec<usize> = (0..baseline.turns)
        .filter(|&cut| match (&baseline.classes[cut], rigor()) {
            (_, Rigor::Exhaustive) | (None, Rigor::Fast) => true,
            (Some(class), Rigor::Fast) => first.insert(class.clone()),
        })
        .collect();
    let mut progress = Progress::new("an inspection cancelled beside a live document");
    progress.stage("cancellations", selected.len(), baseline.turns);
    let mut members = Vec::new();
    for cut in selected {
        progress.case(format!("cancelled at boundary {cut}"));
        let run = shared_owner(Some(cut));
        if let Some(class) = &baseline.classes[cut] {
            members.push((format!("boundary {cut}"), class.clone(), run.cleanup));
        }
    }
    support::agree("inspection cancellation", members);
}

#[test]
fn inspected_input_moves_out_without_copying_and_the_arena_retires() {
    let mut m = meter();
    let mut owner = support::scope(&mut m);
    let wire = [0x82, 0x01, 0x02];
    let input = support::copy(&owner, &mut m, &wire);
    let document = support::parse(&mut m, input, Options::quick_only(4)).expect("inspection");
    let address = document.input().data().as_ptr();
    assert_eq!(document.root().children().count(), 2);
    let input = document.into_input();
    assert_eq!(input.value().data(), wire);
    assert_eq!(input.value().data().as_ptr(), address, "input was copied");
    drop(input);
    support::drain(&mut owner, &mut m);
    assert_eq!(m.live_bytes(), 0);
}

#[test]
fn every_inspection_admission_allocation_and_stop_boundary() {
    let inputs = [
        ("null", vec![0xf6]),
        ("nested array", vec![0x82, 0x01, 0x82, 0x02, 0x03]),
        (
            "64 combining marks",
            dcbor::CBOR::from("\u{301}".repeat(64)).to_cbor_data(),
        ),
    ];
    for (name, wire) in inputs {
        matrix(
            &format!("inspect {name}"),
            rigor(),
            Expected::Complete,
            |schedule| inspect(&wire, schedule, &Classes::certified()),
        );
    }
}

/// A planted class that merges every boundary of an inspection into one:
/// states of different custody clean up differently, and the exhaustive
/// layer rejects the class, naming it.
#[test]
#[should_panic(expected = "the class merges states of different custody")]
fn a_class_merging_states_of_different_custody_is_rejected() {
    let wire = [0x82, 0x01, 0x82, 0x02, 0x03];
    let merged = Classes {
        input: |_| Some("merged".to_owned()),
        parse: |_| Some("merged".to_owned()),
        decode: |_| None,
    };
    matrix(
        "inspection under a planted class",
        Rigor::Exhaustive,
        Expected::Complete,
        |schedule| inspect(&wire, schedule, &merged),
    );
}
