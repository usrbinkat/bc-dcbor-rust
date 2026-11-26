//! Recorded baselines. Every other trace check in this suite compares a
//! refused, resumed or cancelled run with an unobstructed baseline of the same
//! build: it proves nothing is replayed, and nothing about the baseline
//! itself. Here the baselines are fixed in `tests/data/admission-traces.txt`,
//! so a change to any operation's admissions (an amount, an order, a call
//! added or removed) fails at that operation's first differing point. The
//! resumed and cancelled traces the other checks derive from a baseline are
//! fixed with it.
//!
//! A recorded baseline is its run's identity-keyed contract
//! ([`refinement::Run`]): the recording session's whole stream, every
//! observation in the session's one order, each with the family that
//! published it and the policy that performed it; the custody its
//! operation's owners held after every turn, owner by owner, from the one
//! grouped production traversal (`observe_custody`, collected after every
//! turn by the holding schedules, [`support::Holding::drive`]); where its
//! driver began
//! cleanup and why; what it published, by permit identity; and its end. Each
//! case is one recorded run of its own ([`support::recorded_run`]): the
//! runner refines the stream and every checkpoint before the row is built,
//! the row's marks are checked again when it is rendered
//! ([`refinement::check`]), and every recorded row again when it is read. The
//! machine is a refusal check: a run it refuses is never recorded, and
//! acceptance upgrades nothing, every row `observed`
//! ([`refinement::evidence`]). The gate refuses every record holding a row
//! the machine refuses (`gate refine`).
//!
//! A baseline is evidence only of an outcome its case was written to reach.
//! Each case declares that outcome, published or rejected as invalid input,
//! and the recorder classifies what its operation reached by the outcome
//! taxonomy ([`Failure::class`]): a case that reached anything else, a defect,
//! a refusal or a physical failure above all, is never recorded and never
//! compared, so no defect can become an accepted trace. The declarations of
//! the decoding wires are themselves checked against the symbolic decoder,
//! an oracle independent of the bounded engine.
//!
//! Each case is driven by the shared driver under its witness's policy, one
//! quantum per turn, so a recorded trace also fixes where each call falls
//! against the quanta. A terminal error is followed by the operation's own
//! cleanup, recorded with it. Setting `DCBOR_RECORD_TRACES` rewrites the data
//! from the current build, written whole to a temporary file and then renamed
//! over the record, so a failed recording leaves the last record intact; a
//! change to it states the trace delta it carries. Every record names the
//! configuration it was recorded under (`DCBOR_CONFIGURATION`, exported by
//! the flake's shells: the toolchain and the standard library it builds
//! against), and recording refuses without one. Recorded amounts include
//! `size_of` values: the data is for 64-bit targets, and kept apart for
//! builds that encode bignums, whose preparation record holds one
//! (`.num-bigint`), and for builds over the forked standard library's
//! collections, whose ordered trees are walked by a stepped cursor stating no
//! node moves (`.custom-std`): `admission-traces.txt`,
//! `admission-traces.num-bigint.txt`, `admission-traces.custom-std.txt` and
//! `admission-traces.custom-std.num-bigint.txt`.
use super::bindings::{string_decoder, text_encoder};
use super::harness::*;
use super::support::classes::Classes;
use super::support::pipeline::{Physical, Under};
use super::support::{
    self, Finding, Holding, PolicyId, RecordedRun, Retirement, Stopped, heap, pipeline,
};
use dcbor::bounded::decode::construction::DecodeOwner;
use dcbor::bounded::decode::construction::in_place::StableOption;
use dcbor::bounded::decode::cursor::Decoder;
use dcbor::bounded::decode::header::HeaderCursor;
use dcbor::bounded::decode::{Options, decode_typed, decode_with};
use dcbor::bounded::encoding::{Preparation, Schema};
use dcbor::bounded::text_cursor::pipeline::TextPreparation;
use dcbor::bounded::{
    Admission, AdmissionTrace, BoundedError, BoundedResult, Class, Custodial, CustodySink, Failure,
    Family, Identity, PermitsObserved, Resumable, Step, Tagged, encode, permits_of, prepare,
};
use dcbor::{ByteString, CBOR, Map};
use dcbor_record as record;
use dcbor_refinement::{
    self as refinement, Cause, Checkpoint, End, Observed, Outcome, Publication, Row, Run,
};
use record::capabilities::{Capabilities, Capability};
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fmt::Debug;
use std::rc::Rc;

/// The recorded baselines, relative to this package, of this build's variant
/// (`variant!`, `dcbor_record::declare_variant`): their admissions depend on
/// which collections walk ordered trees (the standard library's iterator, or
/// the forked library's stepped cursor) and on whether bignums are encoded
/// (the preparation record holds one).
const RECORDED: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/data/admission-traces",
    variant!(),
    ".txt"
);

/// Rewrites [`RECORDED`] from the current build when set.
const RECORD: &str = "DCBOR_RECORD_TRACES";

/// This build's capabilities: which gated cases it compiles
/// ([`record::capabilities`], the one definition of every gating feature).
const CAPABILITIES: Capabilities = record::capabilities!();

/// Whether this build enables `feature`, a recorded row's gate: one of
/// [`Capability::ALL`], any other name refused.
fn enabled(feature: &str) -> bool {
    match Capability::parse(feature) {
        Some(capability) => CAPABILITIES.enables(capability),
        None => panic!(
            "{feature} is not a gating feature; the features are {:?}",
            Capability::ALL.map(Capability::name)
        ),
    }
}

/// What a case's operation reached: an outcome a case can declare, or a
/// description of anything else.
type Reached = Result<Outcome, String>;

/// The outcome `result` reached, classified by the outcome taxonomy: an
/// output published, an input rejected as invalid, or, described, an error
/// of any other class.
fn reached<T, E: Failure + Debug>(result: &Result<T, E>) -> Reached
where
    E::Refusal: Debug,
{
    match result {
        Ok(_) => Ok(Outcome::Published),
        Err(error) => match error.class() {
            Class::Invalid => Ok(Outcome::Invalid),
            class => Err(format!("{error:?}, of class {class:?}")),
        },
    }
}

/// The end a run that reached `reached` records: its outcome's, or, for a
/// run that reached no outcome a case can declare, a defect's. Such a run is
/// inadmissible ([`Cases::inadmissible`]) and never recorded, whatever its
/// end.
fn end(reached: &Reached) -> End {
    match reached {
        Ok(outcome) => outcome.end(),
        Err(_) => End::Failed(Class::Defect),
    }
}

/// The class of a terminal error, owned: the cause a driver's cleanup mark
/// names ([`Cause::Error`]).
fn owned_class(class: Class<&LimitRefusal>) -> Class<LimitRefusal> {
    match class {
        Class::Refused(refusal) => Class::Refused(*refusal),
        Class::Allocation => Class::Allocation,
        Class::Invalid => Class::Invalid,
        Class::Defect => Class::Defect,
    }
}

/// The permits `output` holds, by identity: the publication mark's.
fn published_permits(output: &mut impl Custodial<Reservation>) -> Vec<Identity> {
    let mut permits = Vec::new();
    let observed = permits_of::<Limits>(|sink| output.observe_custody(sink), &mut |permit| {
        permits.push(permit)
    });
    assert_eq!(
        observed,
        PermitsObserved::Complete,
        "a published output's custody is no observation"
    );
    permits
}

/// The marks a case's driver places in its run ([`Run`]): where cleanup
/// began and why, and what it published.
#[derive(Default)]
struct Marks {
    cleaning: Option<(usize, Cause)>,
    published: Option<Publication>,
}

/// The operation `holding` holds, driven under `policy` to publication, or
/// failed and then driven through its own cleanup to `Finished`, within
/// `bound` turns each ([`Holding::drive`], [`Holding::finish`]): the whole
/// holding stack checkpointed after every turn of both, the operation, the
/// output a completing turn publishes and every custody that surrounds them
/// (a writer's lent plan), each permit once. Its publication is marked with
/// the output's permits, read while the scope holds it, its cleanup where it
/// began, with the error's class. The output is retired as released storage
/// once marked; the operation, published or finished, as its type declares
/// ([`support::Terminal`]); a stopped one as releasing its storage. What the
/// operation reached is its own outcome, its error classified by the outcome
/// taxonomy ([`reached`]); any other stop of the drive or of the cleanup is
/// no outcome a case declares but the run's finding, every custody already
/// retired by its holding.
fn drive_retained<O, W: Physical>(
    holding: &mut Holding<'_, '_, O, W>,
    policy: PolicyId,
    marks: &mut Marks,
    bound: usize,
) -> Result<Reached, Finding>
where
    O: Resumable<Limits> + Custodial<Reservation> + support::Terminal,
    O::Output: Custodial<Reservation>,
    O::Error: Failure<Refusal = LimitRefusal> + Debug,
    O::Position: Debug,
{
    let published = holding.drive(policy, bound, Retirement::Released, |output| {
        marks.published = Some(Publication {
            boundary: output.boundary(),
            permits: published_permits(output.value()),
        });
    });
    match published {
        Ok(()) => Ok(Ok(Outcome::Published)),
        Err(Stopped::Operation(error)) => {
            marks.cleaning = Some((holding.boundary(), Cause::Error(owned_class(error.class()))));
            let outcome = reached::<(), _>(&Err(error));
            holding.finish(policy, bound, Retirement::Released)?;
            Ok(outcome)
        }
        Err(stop) => Err(stop.into()),
    }
}

/// One operation's baseline: its name, the feature its case is compiled
/// under, the outcome it declares and the one it reached, its run, and its
/// policy's admission trace when it ran under a policy of its own, the
/// diagnostic of a difference.
struct Case {
    name: String,
    feature: Option<&'static str>,
    outcome: Outcome,
    reached: Reached,
    run: Run,
    trace: Option<AdmissionTrace>,
}

/// Every case, each named once, the feature the cases being added are
/// compiled under, and how each case's policy is made: its witness's
/// ([`Physical::policy`], [`RecordedRun::witnessed_policy`]), the heap
/// guard's natively, the admission oracle's alone inside a model.
struct Cases {
    cases: Vec<Case>,
    feature: Option<&'static str>,
    policy: fn(&mut RecordedRun) -> PolicyId,
}

impl Cases {
    /// No case yet, each to run under witness `W`'s policy.
    fn under<W: Physical>() -> Self {
        Self {
            cases: Vec::new(),
            feature: None,
            policy: RecordedRun::witnessed_policy::<W>,
        }
    }

    /// A case and its run, named once.
    fn push(
        &mut self,
        name: String,
        outcome: Outcome,
        reached: Reached,
        run: Run,
        trace: Option<AdmissionTrace>,
    ) {
        assert!(
            !self.cases.iter().any(|case| case.name == name),
            "case {name} is named twice"
        );
        self.cases.push(Case {
            name,
            feature: self.feature,
            outcome,
            reached,
            run,
            trace,
        });
    }

    /// A case recorded as one run of its own ([`support::recorded_run`]):
    /// `body` runs the operation under the case's one policy and places its
    /// marks; the runner finishes and refines the session and its
    /// checkpoints; the case's row holds that finished stream, those
    /// checkpoints, the marks, and the end of what `body` reached. A finding
    /// `body` returns (a driver's stop that is no outcome a case declares)
    /// is the run's, reported by its finalization: nothing is recorded.
    fn record(
        &mut self,
        name: String,
        outcome: Outcome,
        body: impl FnOnce(&mut RecordedRun, PolicyId, &mut Marks) -> Result<Reached, Finding>,
    ) {
        type Evidence = Rc<RefCell<Option<(Vec<Observed>, Vec<Checkpoint>)>>>;
        let evidence: Evidence = Rc::default();
        let kept = Rc::clone(&evidence);
        let policy = self.policy;
        let (reached, marks, trace) = support::recorded_run(|run| {
            let id = policy(run);
            let mut marks = Marks::default();
            let reached = body(run, id, &mut marks)?;
            let trace = run.with_policy(id, |m| m.trace().clone());
            run.inspect_evidence(move |observed, checkpoints| {
                *kept.borrow_mut() = Some((observed.to_vec(), checkpoints.to_vec()));
            });
            Ok((reached, marks, trace))
        });
        let (observed, checkpoints) = evidence
            .take()
            .expect("the runner reads every run's evidence");
        let run = Run {
            observed,
            checkpoints,
            cleaning: marks.cleaning,
            published: marks.published,
            end: end(&reached),
        };
        self.push(name, outcome, reached, run, Some(trace));
    }

    /// The cases `add` adds, compiled only under `capability`.
    #[cfg(any(feature = "derive", feature = "hashbrown"))]
    fn gated(&mut self, capability: Capability, add: impl FnOnce(&mut Self)) {
        let feature = capability.name();
        assert!(
            CAPABILITIES.enables(capability),
            "{feature} cases run only under {feature}"
        );
        assert!(self.feature.is_none(), "cases are gated on one feature");
        self.feature = Some(feature);
        add(self);
        self.feature = None;
    }

    /// A retained operation held by its run, driven to publication, or
    /// failed and then driven through its own cleanup ([`drive_retained`]).
    /// Stopped, it releases its own storage as it drops.
    fn retained<O>(&mut self, name: String, outcome: Outcome, operation: O, bound: usize)
    where
        O: Resumable<Limits> + Custodial<Reservation> + support::Terminal,
        O::Output: Custodial<Reservation>,
        O::Error: Failure<Refusal = LimitRefusal> + Debug,
        O::Position: Debug,
    {
        self.record(name, outcome, |run, policy, marks| {
            run.holding(
                operation,
                Retirement::Released,
                &pipeline::Unwitnessed,
                |held| drive_retained(held, policy, marks, bound),
            )
        });
    }

    /// A synchronous operation: one call of `operation` under the case's
    /// policy, which returns what it reached. Its publication leaves no
    /// surviving output for the run to hold, so its mark names the
    /// completion's boundary alone, no permit; its rejection of an invalid
    /// input is its cleaning cause, `reached` having classified the error's
    /// class as [`Class::Invalid`].
    fn synchronous(
        &mut self,
        name: &str,
        outcome: Outcome,
        operation: impl FnOnce(&mut Limits) -> Reached,
    ) {
        self.record(name.into(), outcome, |run, policy, marks| {
            let reached = run.with_policy(policy, operation);
            match reached {
                Ok(Outcome::Published) => {
                    marks.published = Some(Publication {
                        boundary: run.boundary(),
                        permits: Vec::new(),
                    });
                }
                Ok(Outcome::Invalid) => {
                    marks.cleaning =
                        Some((run.boundary(), Cause::Error(owned_class(Class::Invalid))));
                }
                _ => {}
            }
            Ok(reached)
        });
    }

    /// Every case that did not reach the outcome it declares, described:
    /// none of them is recorded or compared.
    fn inadmissible(&self) -> Vec<String> {
        self.cases
            .iter()
            .filter(|case| case.reached != Ok(case.outcome))
            .map(|case| {
                let reached = match &case.reached {
                    Ok(outcome) => outcome.name().to_string(),
                    Err(description) => description.clone(),
                };
                format!(
                    "{}: declared {}, reached {reached}",
                    case.name,
                    case.outcome.name()
                )
            })
            .collect()
    }
}

/// Long byte-string keys sharing a 255-byte prefix.
fn long_keys() -> Vec<u8> {
    let mut wire = vec![0xa2];
    for last in *b"ab" {
        wire.extend_from_slice(&[0x59, 0x01, 0x00]);
        wire.extend(std::iter::repeat_n(b'a', 255));
        wire.push(last);
        wire.push(0x01);
    }
    wire
}

/// One wire the decoding operations read, and what it is: canonical dCBOR or
/// not; every text proven normal by the quick check; a text at its root; a
/// first head that is valid on its own.
struct Wire {
    name: &'static str,
    bytes: Vec<u8>,
    canonical: bool,
    proven: bool,
    text_root: bool,
    head: bool,
}

impl Wire {
    /// A canonical wire whose texts the quick check proves normal, of no
    /// text root.
    fn canonical(name: &'static str, bytes: Vec<u8>) -> Self {
        Self {
            name,
            bytes,
            canonical: true,
            proven: true,
            text_root: false,
            head: true,
        }
    }

    /// A wire that is not canonical dCBOR, its first head valid.
    fn invalid(name: &'static str, bytes: Vec<u8>) -> Self {
        Self {
            canonical: false,
            ..Self::canonical(name, bytes)
        }
    }

    /// What a decode of this wire reaches: published only when the wire is
    /// canonical and, under the quick-only policy, every text is proven.
    fn decoded(&self, quick: bool) -> Outcome {
        if self.canonical && (self.proven || !quick) {
            Outcome::Published
        } else {
            Outcome::Invalid
        }
    }

    /// What a string decode of this wire reaches: published only for a
    /// canonical wire whose root is a text.
    fn string(&self) -> Outcome {
        if self.canonical && self.text_root {
            Outcome::Published
        } else {
            Outcome::Invalid
        }
    }

    /// What reading this wire's first head reaches.
    fn first_head(&self) -> Outcome {
        if self.head {
            Outcome::Published
        } else {
            Outcome::Invalid
        }
    }
}

/// Every wire the decoding operations read: each major type, nesting, long
/// keys, normal, composed and undecided text, and malformed, misordered,
/// duplicate, non-NFC, truncated and trailing input.
fn wires() -> Vec<Wire> {
    let mut nested = vec![0x81; 12];
    nested.push(0x01);
    vec![
        Wire::canonical("unsigned", vec![0x19, 0x01, 0x00]),
        Wire::canonical("wide unsigned", vec![0x1b, 0, 0, 0, 1, 0, 0, 0, 0]),
        Wire::canonical("negative", vec![0x38, 0x18]),
        Wire::canonical("float", vec![0xf9, 0x3e, 0x00]),
        Wire::canonical("simple", vec![0x82, 0xf5, 0xf6]),
        Wire::canonical(
            "texts",
            vec![
                0x83, 0x63, b'a', b'b', b'c', 0x63, b'1', b'2', b'3', 0x61, b'x',
            ],
        ),
        Wire::canonical("nested", nested),
        Wire::canonical("long keys", long_keys()),
        Wire::canonical("bytes", CBOR::to_byte_string([0x5a; 100]).to_cbor_data()),
        Wire {
            text_root: true,
            ..Wire::canonical("composed", text_wire("\u{e9}t\u{e9}"))
        },
        // A leading combining mark: normal, but the quick check leaves it
        // undecided.
        Wire {
            proven: false,
            text_root: true,
            ..Wire::canonical(
                "undecided",
                text_wire(&format!("\u{301}{}", "\u{e9}".repeat(40))),
            )
        },
        Wire::canonical("tagged", vec![0xd8, 0x2a, 0x01]),
        Wire::canonical(
            "map",
            vec![0xa2, 0x00, 0x82, 0x01, 0x02, 0x01, 0x62, 0xc3, 0xa9],
        ),
        // The only first head that is invalid on its own: 23 encoded in two
        // bytes.
        Wire {
            head: false,
            ..Wire::invalid("non-shortest", vec![0x18, 0x17])
        },
        Wire::invalid("misordered", vec![0xa2, 0x02, 0x00, 0x01, 0x00]),
        Wire::invalid("duplicate", vec![0xa2, 0x01, 0x00, 0x01, 0x00]),
        Wire {
            text_root: true,
            ..Wire::invalid("non-NFC", text_wire("e\u{301}"))
        },
        Wire::invalid("truncated", vec![0x82, 0x01]),
        Wire::invalid("trailing", vec![0x01, 0x01]),
        Wire::invalid("invalid simple", vec![0xf7]),
    ]
}

fn decoding(cases: &mut Cases) {
    for wire in wires() {
        let name = wire.name;
        for (policy, options, quick) in [
            ("normalizing", Options::normalizing(16), false),
            ("quick", Options::quick_only(16), true),
        ] {
            cases.synchronous(
                &format!("decode_with {name} {policy}"),
                wire.decoded(quick),
                |m| reached(&decode_with(&wire.bytes, options, m)),
            );
            cases.retained(
                format!("Decoder {name} {policy}"),
                wire.decoded(quick),
                Decoder::<Reservation, Family>::new(&wire.bytes, options),
                support::decode_turns(wire.bytes.len()),
            );
        }
        cases.retained(
            format!("string_decoder {name}"),
            wire.string(),
            string_decoder(&wire.bytes),
            support::string_turns(wire.bytes.len()),
        );
        cases.retained(
            format!("HeaderCursor {name}"),
            wire.first_head(),
            HeaderCursor::new(&wire.bytes),
            support::decode_turns(wire.bytes.len()),
        );
    }
    let texts = [
        0x83, 0x63, b'a', b'b', b'c', 0x63, b'1', b'2', b'3', 0x61, b'x',
    ];
    cases.synchronous("decode_typed Vec<String>", Outcome::Published, |m| {
        reached(&decode_typed::<Vec<String>, _>(&texts, m))
    });
    cases.synchronous("decode_typed String", Outcome::Published, |m| {
        reached(&decode_typed::<String, _>(&text_wire("\u{e9}t\u{e9}"), m))
    });
    cases.synchronous("decode_typed ByteString", Outcome::Published, |m| {
        let wire = CBOR::to_byte_string([7u8; 70]).to_cbor_data();
        reached(&decode_typed::<ByteString, _>(&wire, m))
    });
    cases.synchronous("decode_typed wrong type", Outcome::Invalid, |m| {
        reached(&decode_typed::<Vec<u64>, _>(&text_wire("x"), m))
    });
}

/// A typed decode in its own scope, held by its run from the scope's
/// initialization through the borrowed input, the decode, the value's
/// retirement into the scope's queue and the drain, to the scope's terminal
/// destruction ([`Holding::decoded`]). The decode's publication is marked
/// with the published value's permits, read while the scope holds it; its
/// own error is its outcome and its cleaning cause, the stopped decoder
/// retired, its records queued, before the drain; any other stop, the
/// scope's and the drain's included, is the run's finding.
fn owned_decode<T>(cases: &mut Cases, name: &str, outcome: Outcome, wire: &[u8])
where
    T: dcbor::bounded::decode::construction::in_place::Transferable<Limits>,
{
    cases.record(
        format!("owned decode {name}"),
        outcome,
        |run, policy, marks| {
            run.holding(
                DecodeOwner::new(),
                Retirement::Scope,
                &pipeline::Unwitnessed,
                |scope| {
                    scope.initialize(policy)?;
                    let outcome = match scope.decoded::<T, _>(policy, wire, |value| {
                        marks.published = Some(Publication {
                            boundary: value.boundary(),
                            permits: published_permits(value.value()),
                        });
                    })? {
                        Ok(()) => Ok(Outcome::Published),
                        Err(error) => {
                            marks.cleaning =
                                Some((scope.boundary(), Cause::Error(owned_class(error.class()))));
                            reached::<(), _>(&Err(error))
                        }
                    };
                    scope.drain(policy)?;
                    Ok(outcome)
                },
            )
        },
    );
}

/// What an observed owned pipeline reached: its selected end with the
/// input's exact bytes, the input rejected, or, described, anything else.
fn pipeline_reached(report: &pipeline::Report) -> Reached {
    match (
        report.complete,
        report.invalid,
        report.failed,
        report.stopped,
    ) {
        (true, false, false, false) => Ok(Outcome::Published),
        (false, true, false, false) => Ok(Outcome::Invalid),
        (complete, invalid, failed, stopped) => Err(format!(
            "complete {complete}, invalid {invalid}, failed {failed}, stopped {stopped}"
        )),
    }
}

/// The owned cases, the pipeline's under witness `W` ([`Under`]). A pipeline
/// run owns its recording session whole and refines it itself; its row is
/// that finished stream and its end, with no marks: a mark adds checks, its
/// absence relaxes none.
fn owned<W: Physical>(cases: &mut Cases) {
    let texts = [
        0x83, 0x63, b'a', b'b', b'c', 0x63, b'1', b'2', b'3', 0x61, b'x',
    ];
    owned_decode::<String>(cases, "String", Outcome::Published, &text_wire("q\u{301}a"));
    owned_decode::<Vec<String>>(cases, "Vec<String>", Outcome::Published, &texts);
    owned_decode::<ByteString>(
        cases,
        "ByteString",
        Outcome::Published,
        &CBOR::to_byte_string([7u8; 70]).to_cbor_data(),
    );
    owned_decode::<Vec<u64>>(cases, "wrong type", Outcome::Invalid, &text_wire("x"));
    // A stable option present, its payload block acquired with exactly the
    // bytes its acquisition writes, and null, no block acquired.
    owned_decode::<StableOption<u64, Limits>>(
        cases,
        "StableOption present",
        Outcome::Published,
        &[0x03],
    );
    owned_decode::<StableOption<u64, Limits>>(
        cases,
        "StableOption null",
        Outcome::Published,
        &[0xf6],
    );
    // An ordered map over the forked library's fixed-address nodes: its
    // metadata, arenas and node blocks each acquired with their exact bytes.
    #[cfg(feature = "custom-std-collections")]
    owned_decode::<BTreeMap<u64, u64>>(
        cases,
        "BTreeMap<u64, u64>",
        Outcome::Published,
        &[0xa2, 0x01, 0x02, 0x03, 0x04],
    );
    let integers = CBOR::from((0..40u64).collect::<Vec<_>>()).to_cbor_data();
    let text = text_wire("\u{e9}t\u{e9} long enough to copy in several units");
    // A baseline records its admissions; no stop is selected, so no
    // boundary is classed.
    let baseline = &pipeline::Schedule::BASELINE;
    let unclassed = &Classes::none();
    let reports = [
        (
            "u64",
            Outcome::Published,
            Under::<W>::encode::<u64>(&[0x19, 0x01, 0x00], baseline, &Classes::none()),
        ),
        (
            "String",
            Outcome::Published,
            Under::<W>::encode::<String>(&text, baseline, &Classes::none()),
        ),
        (
            "Vec<u64>",
            Outcome::Published,
            Under::<W>::encode::<Vec<u64>>(&integers, baseline, &Classes::none()),
        ),
        (
            "Vec<String>",
            Outcome::Published,
            Under::<W>::encode::<Vec<String>>(&texts, baseline, &Classes::none()),
        ),
        (
            "inspect",
            Outcome::Published,
            Under::<W>::inspect(&integers, baseline, unclassed),
        ),
        (
            "inspect invalid",
            Outcome::Invalid,
            Under::<W>::inspect(&[0x82, 0x01], baseline, unclassed),
        ),
        (
            "acquire",
            Outcome::Published,
            Under::<W>::acquire(&integers, baseline, unclassed),
        ),
    ];
    for (name, outcome, report) in reports {
        // No injected refusal. Acquisition may still exhaust a fresh turn
        // between its prepaid write and release admissions; those attempts
        // are positively refused, not admitted trace entries.
        assert_eq!(report.refused, 0, "{name}");
        assert_eq!(
            report.attempts,
            report.accounting.admitted().len() + report.refusals,
            "{name}"
        );
        let reached = pipeline_reached(&report);
        // The pipeline's own row carries no per-phase mark site: its one
        // mark stands at the stream's end, the quiescent boundary its drain
        // reaches, the pipeline's publication named by no permit (each
        // phase's output retired before it) and its rejection of an invalid
        // input by its class, the outcome taxonomy's own
        // (`pipeline_reached`).
        let boundary = report.observed.len();
        let (cleaning, published) = match &reached {
            Ok(Outcome::Published) => (
                None,
                Some(Publication {
                    boundary,
                    permits: Vec::new(),
                }),
            ),
            Ok(Outcome::Invalid) => (
                Some((boundary, Cause::Error(owned_class(Class::Invalid)))),
                None,
            ),
            _ => (None, None),
        };
        let run = Run {
            observed: report.observed,
            checkpoints: Vec::new(),
            cleaning,
            published,
            end: end(&reached),
        };
        cases.push(
            format!("owned pipeline {name}"),
            outcome,
            reached,
            run,
            None,
        );
    }
}

/// Texts every text operation normalizes: empty, ordinary, a long
/// disordered run, repeated marks, Hangul, leading marks and composed text.
fn texts() -> Vec<(&'static str, String)> {
    vec![
        ("empty", String::new()),
        ("ordinary", "x".repeat(200)),
        ("disordered", format!("q{}", "\u{301}\u{316}".repeat(64))),
        ("marks", "a\u{301}\u{316}".repeat(20)),
        ("hangul", "\u{1100}\u{1161}\u{11a8}".repeat(20)),
        ("leading", "\u{301}".repeat(50)),
        ("composed", "\u{e9}".repeat(50)),
    ]
}

fn text(cases: &mut Cases) {
    for (name, source) in texts() {
        let turns = support::normalize_turns(&source);
        cases.retained(
            format!("text_encoder {name}"),
            Outcome::Published,
            text_encoder(&source),
            turns,
        );
        cases.retained(
            format!("TextPreparation {name}"),
            Outcome::Published,
            TextPreparation::<Reservation, Family>::new(&source),
            turns,
        );
        // The writer's run prepares its plan first, under the same policy,
        // held by the run, and lends the plan to the writer it holds while
        // the write is driven: every custody the run makes is the run's.
        cases.record(
            format!("TextWriter {name}"),
            Outcome::Published,
            |run, policy, marks| {
                run.holding(
                    TextPreparation::<Reservation, Family>::new(&source),
                    Retirement::Released,
                    &pipeline::Unwitnessed,
                    |preparing| {
                        preparing
                            .drive(policy, turns, Retirement::Released, |plan| {
                                let len = usize::try_from(plan.value().len())
                                    .expect("a text plan fits in memory");
                                let mut bytes = vec![0; len];
                                plan.lending(
                                    Retirement::Released,
                                    |plan| plan.writer(&mut bytes),
                                    |writer| {
                                        drive_retained(
                                            writer,
                                            policy,
                                            marks,
                                            support::text_emit_turns(len),
                                        )
                                    },
                                )
                            })
                            .map_err(Finding::from)
                            .and_then(|outcome| outcome)
                    },
                )
            },
        );
    }
}

/// Every source the preparation prepares under the default features.
fn sources() -> Vec<(&'static str, Box<dyn Schema>)> {
    let mut nested: Box<dyn Schema> = Box::new(7u64);
    for _ in 0..12 {
        nested = Box::new(vec![nested]);
    }
    vec![
        ("integers", Box::new((0..300u64).collect::<Vec<_>>())),
        ("text", Box::new("x".repeat(200))),
        ("texts", Box::new(vec!["e\u{301}".to_string(); 8])),
        (
            "disordered",
            Box::new(format!("q{}", "\u{301}\u{316}".repeat(64))),
        ),
        ("bytes", Box::new(ByteString::from(vec![0xaa; 256]))),
        ("floats", Box::new(vec![1.0f64, 1.5, f64::NAN])),
        ("options", Box::new(vec![Some(1u64), None, Some(24)])),
        (
            "tagged",
            Box::new(Tagged {
                tag: 42,
                value: 7u64,
            }),
        ),
        ("nested", nested),
    ]
}

/// `source` prepared, then its plan emitted, each its own case, each
/// published: the preparation driven with its custody checkpointed, and the
/// writer's run preparing its plan first, under the same policy.
fn prepared_and_emitted(cases: &mut Cases, name: &str, source: &dyn Schema) {
    cases.retained(
        format!("Preparation {name}"),
        Outcome::Published,
        Preparation::<Reservation, Family>::new(source),
        support::prepare_turns(support::shape(source)),
    );
    cases.record(
        format!("Writer {name}"),
        Outcome::Published,
        |run, policy, marks| {
            run.holding(
                Preparation::<Reservation, Family>::new(source),
                Retirement::Released,
                &pipeline::Unwitnessed,
                |preparing| {
                    preparing
                        .drive(
                            policy,
                            support::prepare_turns(support::shape(source)),
                            Retirement::Released,
                            |plan| {
                                let len = plan.value().len();
                                let mut bytes = vec![0; len];
                                plan.lending(
                                    Retirement::Released,
                                    |plan| plan.writer(&mut bytes),
                                    |writer| {
                                        drive_retained(
                                            writer,
                                            policy,
                                            marks,
                                            support::emit_turns(len),
                                        )
                                    },
                                )
                            },
                        )
                        .map_err(Finding::from)
                        .and_then(|outcome| outcome)
                },
            )
        },
    );
}

fn preparation(cases: &mut Cases) {
    for (name, source) in sources() {
        prepared_and_emitted(cases, name, source.as_ref());
    }
    #[cfg(feature = "hashbrown")]
    cases.gated(Capability::Hashbrown, |cases| {
        let mut table = hashbrown::HashTable::new();
        for (hash, key, value) in [
            (0, "z", 1u64),
            (1, "aa", 2),
            (2, "a", 3),
            (3, "e\u{301}", 4),
        ] {
            table.insert_unique(hash, (key.to_string(), value), |(_, value)| *value);
        }
        prepared_and_emitted(cases, "hash table", &table);
        // Two keys of one canonical encoding: the source is rejected.
        let mut duplicate = hashbrown::HashTable::new();
        duplicate.insert_unique(0, ("e\u{301}".to_string(), 1u64), |(_, v)| *v);
        duplicate.insert_unique(1, ("\u{e9}".to_string(), 2u64), |(_, v)| *v);
        cases.retained(
            "Preparation duplicate keys".into(),
            Outcome::Invalid,
            Preparation::<Reservation, Family>::new(&duplicate),
            support::prepare_turns(support::shape(&duplicate)),
        );
    });
    #[cfg(feature = "derive")]
    cases.gated(Capability::Derive, |cases| {
        use super::schema_encoding::Record;
        let record = Record {
            omitted: None,
            enabled: true,
            nested: vec![vec!["e\u{301}".into()]],
        };
        prepared_and_emitted(cases, "derived record", &record);
    });
}

fn synchronous_encoding(cases: &mut Cases) {
    let tree: BTreeMap<String, u64> = (0..20u64).rev().map(|n| (format!("k{n:02}"), n)).collect();
    let mut symbolic = Map::new();
    symbolic.insert("k", 1.5f64).unwrap();
    symbolic.insert(-1i64, true).unwrap();
    symbolic.insert(10u64, "a").unwrap();
    cases.synchronous("encode Vec<u64>", Outcome::Published, |m| {
        reached(&encode(&(0..300u64).collect::<Vec<_>>(), m))
    });
    cases.synchronous("encode text", Outcome::Published, |m| {
        reached(&encode(&format!("q{}", "\u{301}\u{316}".repeat(16)), m))
    });
    cases.synchronous("encode BTreeMap", Outcome::Published, |m| {
        reached(&encode(&tree, m))
    });
    cases.synchronous("encode CBOR", Outcome::Published, |m| {
        reached(&encode(&CBOR::from(symbolic.clone()), m))
    });
    cases.synchronous("encode Tagged", Outcome::Published, |m| {
        reached(&encode(&Tagged { tag: 2, value: "x" }, m))
    });
    cases.synchronous("encode ByteString", Outcome::Published, |m| {
        reached(&encode(&ByteString::from(vec![1u8; 100]), m))
    });
    cases.synchronous("encode Option", Outcome::Published, |m| {
        reached(&encode(&Some(vec![None, Some(1u64)]), m))
    });
    cases.synchronous("prepare encode_into", Outcome::Published, |m| {
        let value = vec!["a\u{301}".to_string(), "b".into()];
        let prepared = match prepare(&value, m) {
            Ok(prepared) => prepared,
            Err(error) => return reached::<(), _>(&Err(error)),
        };
        let mut bytes = vec![0; prepared.len()];
        reached(&prepared.encode_into(&mut bytes, m))
    });
}

#[cfg(feature = "derive")]
fn derived(cases: &mut Cases) {
    use super::derive::{Choice, Record};
    let record = [
        0xa3, 0x00, 0x62, 0xc3, 0xa9, 0x01, 0x42, 0x00, 0xff, 0x02, 0xf4,
    ];
    let choice = [0x82, 0x02, 0xa1, 0x00, 0x61, b'x'];
    cases.synchronous("decode_typed derived record", Outcome::Published, |m| {
        reached(&decode_typed::<Record, _>(&record, m))
    });
    cases.synchronous("decode_typed derived choice", Outcome::Published, |m| {
        reached(&decode_typed::<Choice, _>(&choice, m))
    });
    cases.synchronous("encode derived choice", Outcome::Published, |m| {
        reached(&encode(&Choice::Text("x".into()), m))
    });
    owned_decode::<Record>(cases, "derived record", Outcome::Published, &record);
    owned_decode::<Choice>(cases, "derived choice", Outcome::Published, &choice);
}

/// A hash table enumerated by the engine's one bucket traversal, each call
/// in a fresh turn, the cursor's custody checkpointed after each: its
/// window, reported in the group of the owner its windows are acquisitions
/// of, which this driver holds ([`BucketCursor::observe_window`]); its
/// windows, the entries ending them early, and the completion forfeiting
/// the last window's credit.
#[cfg(feature = "hashbrown")]
fn buckets(cases: &mut Cases) {
    use dcbor::bounded::encoding::{
        BUCKET_WINDOW,
        buckets::{BucketCursor, BucketPosition, BucketStep, Buckets},
    };
    let mut table = hashbrown::HashTable::with_capacity(64);
    for key in [0u64, 17, 40, 63] {
        table.insert_unique(key, (key, key), |pair| pair.0);
    }
    let source: &dyn Buckets = &table;
    // At most a call per window and per entry, then the completion.
    let calls = table.num_buckets().div_ceil(BUCKET_WINDOW) + table.len() + 1;
    cases.record(
        "BucketCursor".into(),
        Outcome::Published,
        |run, policy, marks| {
            let owner = run.with_policy(policy, |m| {
                m.owner().expect("the run's policy makes an owner")
            });
            let (mut position, mut window, mut acquisition) = (BucketPosition::new(), None, None);
            let mut cursor = BucketCursor::new(&mut position, &mut window, &mut acquisition);
            let mut outcome = Err(format!("incomplete after {calls} calls"));
            for _ in 0..calls {
                let step = run.with_policy(policy, |m| {
                    m.fresh();
                    cursor
                        .step(source, &owner, m)
                        .map(|step| matches!(step, BucketStep::Complete))
                });
                run.checkpoint(|sink| {
                    sink.begin(Some(owner.id()));
                    cursor.observe_window(sink);
                    sink.end();
                    PermitsObserved::Complete
                });
                match step {
                    Ok(true) => {
                        // The enumeration's completion publishes: the
                        // completion forfeited the last window's credit, so
                        // its output holds no permit to name.
                        marks.published = Some(Publication {
                            boundary: run.boundary(),
                            permits: Vec::new(),
                        });
                        outcome = Ok(Outcome::Published);
                        break;
                    }
                    Ok(false) => {}
                    Err(error) => {
                        marks.cleaning =
                            Some((run.boundary(), Cause::Error(owned_class(error.class()))));
                        outcome = reached::<(), _>(&Err(error));
                        break;
                    }
                }
            }
            drop(owner);
            Ok(outcome)
        },
    );
}

fn cases<W: Physical>() -> Cases {
    let mut cases = Cases::under::<W>();
    decoding(&mut cases);
    owned::<W>(&mut cases);
    text(&mut cases);
    preparation(&mut cases);
    synchronous_encoding(&mut cases);
    #[cfg(feature = "derive")]
    cases.gated(Capability::Derive, derived);
    #[cfg(feature = "hashbrown")]
    cases.gated(Capability::Hashbrown, buckets);
    cases
}

/// The recorded data, a record ([`record::render`]) under `configuration`:
/// one row per case ([`Row::render`]), sorted by name. Only admissible cases
/// are rendered ([`Cases::inadmissible`]), and only runs the refinement
/// machine accepts: a refused run names where and the rule.
fn render(cases: &Cases, configuration: &str) -> String {
    let inadmissible = cases.inadmissible();
    assert!(
        inadmissible.is_empty(),
        "refusing trace evidence: {inadmissible:#?}"
    );
    let sorted: BTreeMap<&str, &Case> = cases
        .cases
        .iter()
        .map(|case| (case.name.as_str(), case))
        .collect();
    let rows: Vec<String> = sorted
        .into_values()
        .map(|case| {
            Row {
                name: case.name.clone(),
                feature: case.feature.map(str::to_string),
                outcome: case.outcome,
                run: case.run.clone(),
            }
            .render()
            .unwrap_or_else(|error| panic!("refusing trace evidence: {error}"))
        })
        .collect();
    record::render(configuration, rows.iter().map(String::as_str))
}

/// One recorded case: the feature it is gated on, its outcome, and its run.
struct Recorded {
    feature: Option<String>,
    outcome: Outcome,
    run: Run,
}

/// The configuration a record was recorded under, and every recorded case
/// by name ([`parse`]).
fn recorded() -> (String, BTreeMap<String, Recorded>) {
    let data = std::fs::read_to_string(RECORDED)
        .unwrap_or_else(|error| panic!("{RECORDED}: {error}; record it with {RECORD}=1"));
    parse(RECORDED, &data)
}

/// The configuration the record `data` at `path` was recorded under, and
/// every recorded case by name, each row read and checked by the refinement
/// machine ([`refinement::parse_record`]) and each feature one of
/// [`Capability::ALL`]: a row the machine refuses, or claiming another class than
/// it supports, is refused, naming the line.
fn parse(path: &str, data: &str) -> (String, BTreeMap<String, Recorded>) {
    if record::try_read(data).is_none() {
        record::read(path, data, &format!("{RECORD}=1"));
    }
    let (configuration, rows) =
        refinement::parse_record(path, data).unwrap_or_else(|error| panic!("{error}"));
    let recorded = rows
        .into_iter()
        .map(|(_, row)| {
            if let Some(feature) = &row.feature {
                enabled(feature);
            }
            (
                row.name,
                Recorded {
                    feature: row.feature,
                    outcome: row.outcome,
                    run: row.run,
                },
            )
        })
        .collect();
    (configuration, recorded)
}

/// Every case reaches the outcome it declares before anything is recorded or
/// compared; recording rewrites every case, so it runs only where every
/// gated case is compiled, and only under a named configuration.
///
/// The one model entry point of these baselines (`tests/unsafe_census.rs`,
/// `MODEL_ENTRY_POINTS`). Under a model checker's cfg the library holds that
/// checker's atomics (`src/sync.rs`), which exist only inside a model, so
/// the same cases run as one single-threaded execution of it and are
/// compared with the same record: a checker build admits exactly what
/// production admits (I3), by the one driver, under the admission oracle
/// alone ([`pipeline::Unwitnessed`]), which reproduces the record natively
/// ([`the_admission_oracle_alone_reproduces_the_record`]).
///
/// The model is configured by the one runner of every model
/// ([`support::model`]): its bound and stack are recorded, derived by the
/// concurrency gate (`tests/gate`). Under loom the baselines run on one
/// spawned thread of the recorded stack, loom's own default stack being
/// measured too small for them.
#[test]
fn every_baseline_admits_exactly_its_recorded_calls() {
    #[cfg(not(any(loom, shuttle)))]
    baselines::<heap::Observation>();

    /// The test target and the model of this entry point, as the bounds
    /// record names them (`dcbor_model_bounds`).
    #[cfg(any(loom, shuttle))]
    const MODEL: (&str, &str) = (
        "resumable_contract",
        "traces::every_baseline_admits_exactly_its_recorded_calls",
    );

    #[cfg(loom)]
    support::model::loom_sized(MODEL.0, MODEL.1, baselines::<pipeline::Unwitnessed>);

    #[cfg(all(shuttle, not(loom)))]
    support::model::shuttle(MODEL.0, MODEL.1, baselines::<pipeline::Unwitnessed>);
}

/// The admission oracle alone ([`pipeline::Unwitnessed`]), run natively,
/// renders the recorded baselines byte for byte: dropping the physical
/// witness changes only what is observed, never an observation a session
/// records nor what a custody holds, so the models compare against the one
/// record, not a second. The record holds every gated case; a build renders
/// the ones it compiles, so the comparison is of the record's configuration
/// line, its ungated cases and the cases of every feature this build
/// enables, each line whole.
#[test]
fn the_admission_oracle_alone_reproduces_the_record() {
    let (recorded_under, _) = recorded();
    let record = std::fs::read_to_string(RECORDED)
        .unwrap_or_else(|error| panic!("{RECORDED}: {error}; record it with {RECORD}=1"));
    let compiled: String = record
        .split_inclusive('\n')
        .enumerate()
        .filter(|(at, line)| {
            *at == 0 || {
                let feature = line.split('\t').nth(1).unwrap_or(refinement::UNGATED);
                feature == refinement::UNGATED || enabled(feature)
            }
        })
        .map(|(_, line)| line)
        .collect();
    let rendered = render(&cases::<pipeline::Unwitnessed>(), &recorded_under);
    assert!(
        rendered == compiled,
        "the admission oracle alone diverged from {RECORDED}"
    );
}

/// Panic at the first point `actual` and `expected` differ, naming `run`:
/// their observations, each in its canonical text, compared one by one and a
/// window of both shown around the first difference; then their marks and
/// their end. Canonical text, since identities are numbered by first
/// appearance ([`refinement::render_run`]).
fn assert_run(actual: &Run, expected: &Run, run: &str) {
    let (actual_observed, actual_marks, actual_end) = refinement::render_run(actual);
    let (expected_observed, expected_marks, expected_end) = refinement::render_run(expected);
    if actual_observed != expected_observed {
        let actual: Vec<&str> = actual_observed.split("; ").collect();
        let expected: Vec<&str> = expected_observed.split("; ").collect();
        let at = actual
            .iter()
            .zip(&expected)
            .position(|(a, b)| a != b)
            .unwrap_or(actual.len().min(expected.len()));
        let start = at.saturating_sub(2);
        let window = |observed: &[&str]| {
            observed[start.min(observed.len())..observed.len().min(at + 4)].join("; ")
        };
        panic!(
            "trace divergence: run={run}, first_difference={at}, actual_len={}, expected_len={}\n\
             actual_window={}\nexpected_window={}",
            actual.len(),
            expected.len(),
            window(&actual),
            window(&expected)
        );
    }
    assert_eq!(actual_marks, expected_marks, "{run}: its marks differ");
    assert_eq!(actual_end, expected_end, "{run}: its end differs");
}

/// The baselines, compared with their record or, under `DCBOR_RECORD_TRACES`,
/// recorded ([`every_baseline_admits_exactly_its_recorded_calls`]). Each
/// case's calls are compared first, under its policy's trace, the
/// diagnostic of an admission's difference; then its whole run.
fn baselines<W: Physical>() {
    let cases = cases::<W>();
    let inadmissible = cases.inadmissible();
    assert!(
        inadmissible.is_empty(),
        "cases that did not reach their declared outcome, neither recorded nor compared: \
         {inadmissible:#?}"
    );
    if std::env::var_os(RECORD).is_some() {
        CAPABILITIES.require_complete();
        record::publish(
            RECORDED,
            &render(&cases, &record::recording_configuration()),
        );
        return;
    }
    let (recorded_under, recorded) = recorded();
    let running_under =
        record::configuration().unwrap_or_else(|| "an unnamed configuration".into());
    // A case gated on a feature this build enables must run; one gated on a
    // disabled feature is not compiled, and is checked in the builds that are.
    let unrun: Vec<&String> = recorded
        .iter()
        .filter(|(_, case)| case.feature.as_deref().is_none_or(enabled))
        .map(|(name, _)| name)
        .filter(|name| !cases.cases.iter().any(|case| &case.name == *name))
        .collect();
    assert!(unrun.is_empty(), "recorded but no longer run: {unrun:#?}");
    let diagnostic = AdmissionTrace::new();
    // Every case's run finalized when it was recorded: what remains is
    // comparison, each case a fixture, every difference reported together
    // at the test's boundary, where nothing is held.
    let compared = every_fixture(cases.cases.len(), |index| {
        let case = &cases.cases[index];
        let expected = recorded
            .get(&case.name)
            .unwrap_or_else(|| panic!("{}: not recorded; record it with {RECORD}=1", case.name));
        assert_eq!(
            expected.feature.as_deref(),
            case.feature,
            "{}: recorded under another feature",
            case.name
        );
        assert_eq!(
            expected.outcome, case.outcome,
            "{}: recorded with another outcome",
            case.name
        );
        let run = format!(
            "{} (recorded under {recorded_under}; running under {running_under})",
            case.name
        );
        let trace = case.trace.as_ref().unwrap_or(&diagnostic);
        trace.assert_calls(
            &refinement::calls(&case.run.observed),
            &refinement::calls(&expected.run.observed),
            &run,
        );
        assert_run(&case.run, &expected.run, &run);
        Ok(())
    });
    if let Err(findings) = compared {
        panic!(
            "{} of {} baselines differ from {RECORDED}: {findings:#?}",
            findings.len(),
            cases.cases.len()
        );
    }
}

/// Each wire's declaration agrees with the symbolic decoder, an oracle
/// independent of the bounded engine: a wire is canonical exactly when the
/// symbolic decoder accepts it, and its root is a text exactly when a
/// string is read from what it accepts.
#[test]
fn every_wire_declaration_agrees_with_the_symbolic_decoder() {
    for wire in wires() {
        let symbolic = CBOR::try_from_data(&wire.bytes);
        assert_eq!(
            symbolic.is_ok(),
            wire.canonical,
            "{}: {symbolic:?}",
            wire.name
        );
        if let Ok(value) = symbolic {
            assert_eq!(
                String::try_from(value).is_ok(),
                wire.text_root,
                "{}: text root",
                wire.name
            );
        }
    }
}

/// An operation that fails with an implementation defect on its first step
/// and is finished on the next: a planted defect.
#[derive(Default)]
struct Defective {
    failed: bool,
}

impl Resumable<Limits> for Defective {
    type Output = ();
    type Error = BoundedError<LimitRefusal>;
    type Position = bool;

    fn step(&mut self, _: &mut Limits) -> BoundedResult<Step<()>, Limits> {
        if self.failed {
            return Ok(Step::Finished);
        }
        self.failed = true;
        Err(BoundedError::PlanMismatch)
    }

    fn position(&mut self) -> bool {
        self.failed
    }
}

/// The planted defect admits nothing, so holds nothing.
impl Custodial<Reservation> for Defective {
    fn observe_custody(&mut self, _: &mut dyn CustodySink<Reservation>) -> PermitsObserved {
        PermitsObserved::Complete
    }
}

// Holding nothing at any step, it holds nothing once published.
dcbor_test_support::terminal!(Exhausted: [] Defective);

/// The recorder refuses a planted defect, and a planted outcome other than
/// the one declared, naming each case and what it reached; an admissible
/// case beside them is not refused.
#[test]
fn a_planted_defect_or_undeclared_outcome_is_never_recorded() {
    let mut cases = Cases::under::<heap::Observation>();
    cases.retained(
        "planted defect".into(),
        Outcome::Published,
        Defective::default(),
        1,
    );
    cases.synchronous("planted outcome", Outcome::Published, |_| {
        Ok(Outcome::Invalid)
    });
    cases.retained(
        "admissible".into(),
        Outcome::Invalid,
        HeaderCursor::new(&[0x18, 0x17]),
        support::decode_turns(2),
    );
    let inadmissible = cases.inadmissible();
    assert_eq!(inadmissible.len(), 2, "{inadmissible:#?}");
    assert!(
        inadmissible[0].starts_with("planted defect: declared published, reached PlanMismatch"),
        "{inadmissible:#?}"
    );
    assert!(
        inadmissible[0].ends_with("of class Defect"),
        "{inadmissible:#?}"
    );
    assert_eq!(
        inadmissible[1],
        "planted outcome: declared published, reached invalid"
    );
    let path = std::env::temp_dir().join(format!("dcbor-trace-defect-{}.txt", std::process::id()));
    std::fs::write(&path, "previous evidence").unwrap();
    let failure = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        record::publish(
            path.to_str().unwrap(),
            &render(&cases, "planted configuration"),
        );
    }))
    .expect_err("trace recorder accepted a defect");
    let message = failure
        .downcast::<String>()
        .expect("named defect diagnostic");
    assert!(message.contains("planted defect"));
    assert!(message.contains("planted outcome"));
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "previous evidence");
    std::fs::remove_file(path).unwrap();
}

/// Planted control: an admissible case whose run the refinement machine
/// refuses (a grant whose release was never paid, nothing preceding it) is
/// never rendered, naming the case and the machine's refusal.
#[test]
fn a_run_the_machine_refuses_is_never_recorded() {
    let mut cases = Cases::under::<heap::Observation>();
    let observed = refinement::parse_observed("1 1 allocate 8 granted 1.1")
        .expect("a planted observation in canonical text");
    cases.push(
        "planted allocation".into(),
        Outcome::Published,
        Ok(Outcome::Published),
        Run {
            observed: vec![observed],
            checkpoints: Vec::new(),
            cleaning: None,
            published: None,
            end: End::Published,
        },
        None,
    );
    let failure = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        render(&cases, "planted configuration")
    }))
    .expect_err("a refused run was rendered");
    let message = failure
        .downcast::<String>()
        .expect("named refinement diagnostic");
    assert!(
        message.contains("planted allocation: the refinement machine refused its run at"),
        "{message}"
    );
}

/// A trace record is a record ([`record::render`]) whose rows are its cases
/// ([`Row::render`]); its header and publication are the record module's,
/// its rows' grammar the refinement crate's, each checked there. A rendered
/// record reads back to the same case: its outcome, its feature and its run,
/// the end its outcome's, the row's class `observed`.
#[test]
fn a_trace_record_names_its_configuration_and_each_case() {
    let mut cases = Cases::under::<heap::Observation>();
    cases.retained(
        "one".into(),
        Outcome::Invalid,
        HeaderCursor::new(&[0x18, 0x17]),
        support::decode_turns(2),
    );
    let rendered = render(&cases, "toolchain=t std=s");
    let (observed, marks, end) = refinement::render_run(&cases.cases[0].run);
    assert_eq!(
        rendered,
        record::render(
            "toolchain=t std=s",
            [format!(
                "one\t{}\tinvalid\tobserved\t{observed}\t{marks}\t{end}",
                refinement::UNGATED
            )
            .as_str()]
        )
    );
    assert_eq!(end, "invalid");
    let (configuration, recorded) = parse("rendered", &rendered);
    assert_eq!(configuration, "toolchain=t std=s");
    assert_eq!(recorded["one"].outcome, Outcome::Invalid);
    assert_eq!(recorded["one"].feature, None);
    assert_eq!(recorded["one"].run.end, End::Failed(Class::Invalid));
    assert_run(&recorded["one"].run, &cases.cases[0].run, "read back");
}

/// Planted controls: a row claiming a class its run does not support,
/// `checked` and `derived` each, is refused naming the line and the class
/// it claims.
#[test]
fn a_row_claiming_another_evidence_class_is_refused() {
    let mut cases = Cases::under::<heap::Observation>();
    cases.retained(
        "one".into(),
        Outcome::Invalid,
        HeaderCursor::new(&[0x18, 0x17]),
        support::decode_turns(2),
    );
    // Establish valid evidence before changing only its claimed class.
    let valid = render(&cases, "toolchain=t std=s");
    assert_eq!(parse("valid", &valid).1.len(), 1);
    let (observed, marks, end) = refinement::render_run(&cases.cases[0].run);
    for claimed in ["checked", "derived"] {
        let data = record::render(
            "toolchain=t std=s",
            [format!(
                "one\t{}\tinvalid\t{claimed}\t{observed}\t{marks}\t{end}",
                refinement::UNGATED
            )
            .as_str()],
        );
        let failure = std::panic::catch_unwind(|| parse("planted", &data).1.len())
            .expect_err("a misclassified row was read");
        let message = failure
            .downcast::<String>()
            .expect("a named class diagnostic");
        assert!(
            message.contains(&format!(
                "planted:2: one claims {claimed}, its row supports observed"
            )),
            "{message}"
        );
    }
}

/// A case's admission diagnostic is its own policy's trace, kept past the
/// run: a case driven under a policy of its own carries the trace whose
/// first admission is its first call.
#[test]
fn a_case_keeps_its_policys_admission_trace() {
    let mut cases = Cases::under::<heap::Observation>();
    cases.synchronous("one decode", Outcome::Published, |m| {
        reached(&decode_with(&[0x01], Options::normalizing(1), m))
    });
    let trace = cases.cases[0]
        .trace
        .as_ref()
        .expect("a recorded case keeps its policy's trace");
    let first: Option<Admission> = trace.recent().next();
    assert_eq!(
        first.map(|admission| admission.call),
        refinement::calls(&cases.cases[0].run.observed)
            .first()
            .copied(),
        "the kept trace is not the case's policy's"
    );
}

/// The permits a publication mark names are the output's own, by identity:
/// a published decode's arena permit, granted under the run's policy.
#[test]
fn a_publication_names_the_outputs_permits() {
    let mut cases = Cases::under::<heap::Observation>();
    cases.retained(
        "Decoder published".into(),
        Outcome::Published,
        Decoder::<Reservation, Family>::new(&[0x82, 0x01, 0x02], Options::normalizing(4)),
        support::decode_turns(3),
    );
    let run = &cases.cases[0].run;
    let publication = run.published.as_ref().expect("a published run is marked");
    assert!(
        !publication.permits.is_empty(),
        "the document holds its arena"
    );
    let granted: Vec<Identity> = run
        .observed
        .iter()
        .filter_map(|observation| match observation.event {
            dcbor::bounded::Event::Call(_, dcbor::bounded::Answer::Granted(permit)) => Some(permit),
            _ => None,
        })
        .collect();
    for permit in &publication.permits {
        assert!(
            granted.contains(permit),
            "published permit {permit:?} was never granted in the run"
        );
    }
}
