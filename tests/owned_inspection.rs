//! Production-backed owned inspection and operation-local cancellation matrix.
#[global_allocator]
static HEAP: heap::Heap = heap::Heap;
use dcbor::ByteString;
use dcbor::bounded::{
    BoundedError, Call, Limits, Step,
    decode::{
        DecodeError, Options,
        construction::{DecodeOwner, DocumentDecoder},
    },
};
use dcbor_test_support::classes::{self, Class, Classes};
use dcbor_test_support::pipeline::{Expected, inspect, matrix};
use dcbor_test_support::rigor::{Progress, Rigor, rigor, sized};
use dcbor_test_support::{
    self as support, Finding, Holding, Lent, PolicyId, Retirement, heap,
    pipeline::Unwitnessed,
};

/// What the options both inspections parse under.
const OPTIONS: Options = Options::normalizing(16);

/// The second inspection's parse, held beside the first's live document.
type Second<'r, 's> = Holding<'r, 's, DocumentDecoder<'static, ByteString, Limits>, Unwitnessed>;

/// What the second inspection did: its turns, the class at each boundary,
/// the admitted-call count at its cut, whether it published, and whether an
/// exhausted turn refused its first cleanup unit.
struct Inspected {
    turns: usize,
    classes: Vec<Option<Class>>,
    cut_at: Option<usize>,
    published: bool,
    cancellation_refused: bool,
}

/// The live first document of [`shared_owner`]: a text of 256 ASCII bytes,
/// whose head is the two-byte form (`0x79 0x01 0x00`). Parsed once per run,
/// outside the cancellation loop, it takes the two-byte head paths (the
/// header's, and the head width of its parse bound) that the second
/// inspection's minimal text of combining marks is too short for, at a cost
/// independent of the cancellations.
fn first_document() -> Vec<u8> {
    dcbor::CBOR::from("a".repeat(256)).to_cbor_data()
}

/// What one run of [`shared_owner`] reached: the second inspection's turns,
/// the cleanup class of its position at each boundary ([`classes::parse`]),
/// and the calls admitted from the cut on, through the scope's drain.
struct Run {
    turns: usize,
    classes: Vec<Option<Class>>,
    cleanup: Vec<Call>,
}

/// Two inspections in one scope, one recorded run: the first's document held
/// live while the second parses, cancelled at its `cut`th boundary when one
/// is given; the run's finalizer refines the stream once everything is
/// drained.
fn shared_owner(cut: Option<usize>) -> Run {
    support::recorded_run(|run| {
        let policy = run.policy(u64::MAX);
        let first_wire = first_document();
        // 128 combining marks (U+0301) natively, 33 at minimal witness
        // sizes: the two-byte head the full text reaches is taken by the
        // first document instead. The reach map runs each test at both sizes
        // and fails when the minimal run leaves unexecuted any region of this
        // crate the full run executes (`tests/reach-map.sh`).
        let source = dcbor::CBOR::from("\u{301}".repeat(sized(128, 33))).to_cbor_data();
        let inspected = run.scoped(policy, &Unwitnessed, |owner| {
            owner.lending(Retirement::Exhausted, Lent::new, |view| {
                let scope = view.value().get();
                view.copied(policy, &first_wire, |first| {
                    first.parse(policy, OPTIONS, |document| {
                        assert_eq!(document.value().root().encoded(), first_wire);
                        // The second inspection runs while the first's
                        // document is held: every turn's checkpoint observes
                        // the document's custody beside the second's.
                        let inspected =
                            document.holding(Lent::new(scope), Retirement::Exhausted, |view| {
                                view.copied(policy, &source, |second| {
                                    second.transfer(
                                        |second| DocumentDecoder::parse(second, OPTIONS),
                                        Retirement::Stopped,
                                        |second| inspect_second(second, policy, cut, source.len()),
                                    )
                                })
                            })??;
                        // The second retired before the first: the first's
                        // bytes and arena remain readable.
                        let document = document.value();
                        document.with_document(|view| {
                            assert_eq!(view.root().encoded(), first_wire)
                        });
                        assert_eq!(document.root().encoded(), first_wire);
                        assert_eq!(document.bytes(), first_wire);
                        Ok::<_, Finding>(inspected)
                    })?
                })?
            })
        })?;
        assert!(
            !(cut.is_some() && inspected.published),
            "a cancelled inspection published"
        );
        assert!(
            cut.is_none() || inspected.cancellation_refused,
            "an exhausted turn did not refuse the cancelled inspection's first cleanup unit"
        );
        let cleanup = run.with_policy(policy, |m| {
            assert_eq!(m.live_bytes(), 0);
            inspected
                .cut_at
                .map_or_else(Vec::new, |at| m.admitted_calls()[at..].to_vec())
        });
        Ok(Run {
            turns: inspected.turns,
            classes: inspected.classes,
            cleanup,
        })
    })
}

/// The second inspection driven through the shared schedule, its boundary
/// classed before each turn and, at `cut`, cancelled: an exhausted turn
/// must then refuse its first cleanup unit, and its own cleanup runs to
/// `Finished`. The bound covers the parse, its record's cleanup included,
/// and the copied input's cleanup, which its acquisition's bound accounts.
fn inspect_second(
    second: &mut Second<'_, '_>,
    policy: PolicyId,
    cut: Option<usize>,
    len: usize,
) -> Result<Inspected, Finding> {
    let len = len as u64;
    let bound = support::turns(
        dcbor::bounded::decode::construction::parse_bound::<ByteString, Limits, ()>(len, OPTIONS)
            .expect("the parse bound of an input held in memory fits in u64"),
    ) + support::turns(
        dcbor::bounded::decode::construction::copy_bound::<Limits, ()>(len)
            .expect("the copy bound of an input held in memory fits in u64"),
    );
    let mut inspected = Inspected {
        turns: 0,
        classes: Vec::new(),
        cut_at: None,
        published: false,
        cancellation_refused: false,
    };
    let published = second.controlled(
        policy,
        bound,
        Retirement::Published,
        true,
        |m, operation, at| {
            inspected.turns += 1;
            inspected.classes.push(classes::parse(&operation.position()));
            if cut == Some(at) {
                inspected.cut_at = Some(m.admitted_calls().len());
                operation.cancel();
                return true;
            }
            false
        },
        |_| (),
    )?;
    inspected.published = published.is_some();
    if inspected.cut_at.is_some() {
        // An exhausted turn positively refuses the first cleanup unit.
        let refused = second.with_policy(policy, |operation, m| {
            m.clear_refusal();
            m.exhaust();
            support::contracted(m, operation)
        });
        match refused {
            Err(DecodeError::Resource(BoundedError::Refused(_))) => {
                inspected.cancellation_refused = true;
            }
            Ok(Step::Complete(value)) => {
                second.holding(value, Retirement::Published, |_| ());
                inspected.published = true;
            }
            _ => {}
        }
        second.finish(policy, bound, Retirement::Published)?;
    }
    Ok(inspected)
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
    support::recorded_run(|run| {
        let policy = run.policy(u64::MAX);
        let wire = [0x82, 0x01, 0x02];
        let options = Options::quick_only(4);
        let bound = support::turns(
            dcbor::bounded::decode::construction::parse_bound::<ByteString, Limits, ()>(
                wire.len() as u64,
                options,
            )
            .expect("the literal's parse bound fits in u64"),
        );
        run.holding(
            DecodeOwner::new(),
            Retirement::Scope,
            &Unwitnessed,
            |owner| {
                owner.initialize(policy)?;
                owner.copied(policy, &wire, |input| {
                    input.transfer(
                        |input| DocumentDecoder::parse(input, options),
                        Retirement::Stopped,
                        |parser| {
                            parser.drive(policy, bound, Retirement::Published, |document| {
                                let address = document.value().input().data().as_ptr();
                                assert_eq!(document.value().root().children().count(), 2);
                                document.transfer(
                                    |document| document.into_input(),
                                    Retirement::Published,
                                    |input| {
                                        assert_eq!(input.value().value().data(), wire);
                                        assert_eq!(
                                            input.value().value().data().as_ptr(),
                                            address,
                                            "input was copied",
                                        );
                                    },
                                );
                            })
                        },
                    )
                })??;
                owner.drain(policy)
            },
        )?;
        run.with_policy(policy, |m| assert_eq!(m.live_bytes(), 0));
        Ok(())
    });
}

#[test]
fn every_inspection_admission_allocation_and_stop_boundary() {
    // 64 combining marks natively; at minimal witness sizes 42, the fewest
    // whose input (2 bytes a mark and a one-byte head: 86 bytes) has a parse
    // bound of at least 256 part bytes (`text::PART_BYTES_PER_BYTE`, 3), so
    // the bound's head takes the two-byte form the full input's does.
    let combining = sized(64, 42);
    let inputs = [
        ("null".to_string(), vec![0xf6]),
        (
            "nested array".to_string(),
            vec![0x82, 0x01, 0x82, 0x02, 0x03],
        ),
        (
            format!("{combining} combining marks"),
            dcbor::CBOR::from("\u{301}".repeat(combining)).to_cbor_data(),
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
        prepare: |_| None,
        emit: |_| None,
    };
    matrix(
        "inspection under a planted class",
        Rigor::Exhaustive,
        Expected::Complete,
        |schedule| inspect(&wire, schedule, &merged),
    );
}
