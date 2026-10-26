//! Recorded baselines. Every other trace check in this suite compares a
//! refused, resumed or cancelled run with an unobstructed baseline of the same
//! build: it proves nothing is replayed, and nothing about the baseline
//! itself. Here the baselines are fixed in `tests/data/admission-traces.txt`,
//! so a change to any operation's admissions (an amount, an order, a call
//! added or removed) fails at that operation's first differing call. The
//! resumed and cancelled traces the other checks derive from a baseline are
//! fixed with it.
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
//! Each case is driven by the shared driver under the suite's policy, one
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
use super::support::{self, drive_within, finish_within, pipeline};
use dcbor::bounded::decode::construction::in_place::StableOption;
use dcbor::bounded::decode::cursor::Decoder;
use dcbor::bounded::decode::header::HeaderCursor;
use dcbor::bounded::decode::{Options, decode_typed, decode_with};
use dcbor::bounded::encoding::Schema;
use dcbor::bounded::text_cursor::pipeline::TextPreparation;
use dcbor::bounded::{
    AdmissionTrace, BoundedError, BoundedResult, Class, Failure, Resumable, Step, Tagged, encode,
    prepare,
};
use dcbor::{ByteString, CBOR, Map};
use std::collections::BTreeMap;
use std::fmt::Debug;

/// The variant of the recorded baselines the standard library's collections
/// select: ordered trees walked by their iterator, or by the forked library's
/// stepped cursor.
#[cfg(not(feature = "custom-std-collections"))]
macro_rules! collections_variant {
    () => {
        ""
    };
}
#[cfg(feature = "custom-std-collections")]
macro_rules! collections_variant {
    () => {
        ".custom-std"
    };
}

/// The variant of the recorded baselines bignums select: whether the
/// preparation record holds one.
#[cfg(not(feature = "num-bigint"))]
macro_rules! bignum_variant {
    () => {
        ""
    };
}
#[cfg(feature = "num-bigint")]
macro_rules! bignum_variant {
    () => {
        ".num-bigint"
    };
}

/// The recorded baselines, relative to this package: their admissions depend
/// on which collections walk ordered trees and on whether bignums are
/// encoded.
const RECORDED: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/data/admission-traces",
    collections_variant!(),
    bignum_variant!(),
    ".txt"
);

/// Rewrites [`RECORDED`] from the current build when set.
const RECORD: &str = "DCBOR_RECORD_TRACES";

/// The configuration a run is under, exported by the flake's shells.
const CONFIGURATION: &str = "DCBOR_CONFIGURATION";

/// The first line of every record: this marker, then its configuration.
const CONFIGURATION_LINE: &str = "#\tconfiguration\t";

/// Every feature a case may be gated on, and whether this build enables it.
const FEATURES: &[(&str, bool)] = &[
    ("derive", cfg!(feature = "derive")),
    ("hashbrown", cfg!(feature = "hashbrown")),
];

/// The recorded column of a case gated on no feature.
const UNGATED: &str = "-";

/// Whether this build enables `feature`, one of [`FEATURES`].
fn enabled(feature: &str) -> bool {
    match FEATURES.iter().find(|(name, _)| *name == feature) {
        Some(&(_, enabled)) => enabled,
        None => panic!("{feature} is not a gating feature; the features are {FEATURES:?}"),
    }
}

/// The configuration this run is under, when its shell exports one.
fn configuration() -> Option<String> {
    std::env::var(CONFIGURATION)
        .ok()
        .filter(|identity| !identity.is_empty())
}

/// What a case is written to reach: its operation publishes, or rejects its
/// input as invalid. The suite's policy admits all work and holds 32 MiB, so
/// a refusal, a physical failure or a defect is never what a case is for,
/// and none of them can be declared.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Outcome {
    Published,
    Invalid,
}

impl Outcome {
    const ALL: [Self; 2] = [Self::Published, Self::Invalid];

    /// The recorded column of this outcome.
    const fn name(self) -> &'static str {
        match self {
            Self::Published => "published",
            Self::Invalid => "invalid",
        }
    }

    /// The outcome whose recorded column is `text`.
    fn parse(text: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|outcome| outcome.name() == text)
    }
}

/// What a case's operation reached: an outcome a case can declare, or a
/// description of anything else.
type Observed = Result<Outcome, String>;

/// The outcome `result` reached, classified by the outcome taxonomy: an
/// output published, an input rejected as invalid, or, described, an error
/// of any other class.
fn observed<T, E: Failure + Debug>(result: &Result<T, E>) -> Observed
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

/// One operation's baseline: its name, the feature its case is compiled
/// under, the outcome it declares and the one it reached, its calls, and the
/// policy it ran under when it has one of its own, whose trace is the
/// diagnostic of a difference.
struct Case {
    name: String,
    feature: Option<&'static str>,
    outcome: Outcome,
    observed: Observed,
    calls: Vec<Call>,
    policy: Option<Limits>,
}

/// Every case, each named once, and the feature the cases being added are
/// compiled under.
#[derive(Default)]
struct Cases {
    cases: Vec<Case>,
    feature: Option<&'static str>,
}

impl Cases {
    fn add(
        &mut self,
        name: String,
        outcome: Outcome,
        observed: Observed,
        calls: Vec<Call>,
        policy: Option<Limits>,
    ) {
        assert!(
            !self.cases.iter().any(|case| case.name == name),
            "case {name} is named twice"
        );
        self.cases.push(Case {
            name,
            feature: self.feature,
            outcome,
            observed,
            calls,
            policy,
        });
    }

    /// The cases `add` adds, compiled only under `feature`.
    #[cfg(any(feature = "derive", feature = "hashbrown"))]
    fn gated(&mut self, feature: &'static str, add: impl FnOnce(&mut Self)) {
        assert!(enabled(feature), "{feature} cases run only under {feature}");
        assert!(self.feature.is_none(), "cases are gated on one feature");
        self.feature = Some(feature);
        add(self);
        self.feature = None;
    }

    /// The calls `m` attempted, under `m`'s own trace.
    fn policy(&mut self, name: String, outcome: Outcome, observed: Observed, m: Limits) {
        let calls = m.calls().to_vec();
        self.add(name, outcome, observed, calls, Some(m));
    }

    /// A retained operation driven to publication, or failed and then driven
    /// through its own cleanup to `Finished`.
    fn retained<O: Resumable<Limits>>(
        &mut self,
        name: String,
        outcome: Outcome,
        mut operation: O,
        bound: usize,
    ) where
        O::Error: Debug,
    {
        let mut m = meter();
        let result = drive_within(&mut m, &mut operation, bound);
        let reached = observed(&result);
        match result {
            Ok(output) => drop(output),
            Err(_) => finish_within(&mut m, &mut operation, bound),
        }
        drop(operation);
        self.policy(name, outcome, reached, m);
    }

    /// A synchronous operation: one call of `operation` under the suite's
    /// policy, which returns what it reached.
    fn synchronous(
        &mut self,
        name: &str,
        outcome: Outcome,
        operation: impl FnOnce(&mut Limits) -> Observed,
    ) {
        let mut m = meter();
        let reached = operation(&mut m);
        self.policy(name.into(), outcome, reached, m);
    }

    /// Every case that did not reach the outcome it declares, described:
    /// none of them is recorded or compared.
    fn inadmissible(&self) -> Vec<String> {
        self.cases
            .iter()
            .filter(|case| case.observed != Ok(case.outcome))
            .map(|case| {
                let reached = match &case.observed {
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
                |m| observed(&decode_with(&wire.bytes, options, m)),
            );
            cases.retained(
                format!("Decoder {name} {policy}"),
                wire.decoded(quick),
                Decoder::<Reservation>::new(&wire.bytes, options),
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
        observed(&decode_typed::<Vec<String>, _>(&texts, 8, m))
    });
    cases.synchronous("decode_typed String", Outcome::Published, |m| {
        observed(&decode_typed::<String, _>(
            &text_wire("\u{e9}t\u{e9}"),
            8,
            m,
        ))
    });
    cases.synchronous("decode_typed ByteString", Outcome::Published, |m| {
        let wire = CBOR::to_byte_string([7u8; 70]).to_cbor_data();
        observed(&decode_typed::<ByteString, _>(&wire, 8, m))
    });
    cases.synchronous("decode_typed wrong type", Outcome::Invalid, |m| {
        observed(&decode_typed::<Vec<u64>, _>(&text_wire("x"), 8, m))
    });
}

/// A typed decode in its own scope, from scope initialization through the
/// borrowed input, the decode, the value's retirement and the drain.
fn owned_decode<T>(cases: &mut Cases, name: &str, outcome: Outcome, wire: &[u8])
where
    T: dcbor::bounded::decode::construction::in_place::Transferable<Limits>,
{
    let mut m = meter();
    let (mut owner, input) = support::open(&mut m, wire);
    let result = support::decode::<_, T>(&mut m, input, Options::normalizing(8));
    let reached = observed(&result);
    drop(result);
    support::drain(&mut owner, &mut m);
    cases.policy(format!("owned decode {name}"), outcome, reached, m);
}

/// What an observed owned pipeline reached: its selected end with the
/// input's exact bytes, the input rejected, or, described, anything else.
fn reached(report: &pipeline::Report) -> Observed {
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

fn owned(cases: &mut Cases) {
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
            pipeline::encode::<u64>(&[0x19, 0x01, 0x00], baseline, &Classes::none()),
        ),
        (
            "String",
            Outcome::Published,
            pipeline::encode::<String>(&text, baseline, &Classes::none()),
        ),
        (
            "Vec<u64>",
            Outcome::Published,
            pipeline::encode::<Vec<u64>>(&integers, baseline, &Classes::none()),
        ),
        (
            "Vec<String>",
            Outcome::Published,
            pipeline::encode::<Vec<String>>(&texts, baseline, &Classes::none()),
        ),
        (
            "inspect",
            Outcome::Published,
            pipeline::inspect(&integers, baseline, unclassed),
        ),
        (
            "inspect invalid",
            Outcome::Invalid,
            pipeline::inspect(&[0x82, 0x01], baseline, unclassed),
        ),
        (
            "acquire",
            Outcome::Published,
            pipeline::acquire(&integers, baseline, unclassed),
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
        let reached = reached(&report);
        cases.add(
            format!("owned pipeline {name}"),
            outcome,
            reached,
            report.accounting.into_admitted(),
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
        cases.retained(
            format!("text_encoder {name}"),
            Outcome::Published,
            text_encoder(&source),
            support::normalize_turns(&source),
        );
        let mut m = meter();
        let result = drive_within(
            &mut m,
            &mut TextPreparation::new(&source),
            support::normalize_turns(&source),
        );
        let reached = observed(&result);
        cases.policy(
            format!("TextPreparation {name}"),
            Outcome::Published,
            reached,
            m,
        );
        let plan = result.expect("a text preparation publishes");
        let mut bytes = vec![0; usize::try_from(plan.len()).expect("a text plan fits in memory")];
        cases.retained(
            format!("TextWriter {name}"),
            Outcome::Published,
            plan.writer(&mut bytes),
            support::text_emit_turns(
                usize::try_from(plan.len()).expect("a text plan fits in memory"),
            ),
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
/// published.
fn prepared_and_emitted(cases: &mut Cases, name: &str, source: &dyn Schema) {
    let (plan, m) = prepared(source);
    let mut bytes = vec![0; plan.len()];
    cases.retained(
        format!("Writer {name}"),
        Outcome::Published,
        plan.writer(&mut bytes),
        support::emit_turns(plan.len()),
    );
    drop(plan);
    // The preparation published its plan: `prepared` requires it.
    cases.policy(
        format!("Preparation {name}"),
        Outcome::Published,
        Ok(Outcome::Published),
        m,
    );
}

fn preparation(cases: &mut Cases) {
    for (name, source) in sources() {
        prepared_and_emitted(cases, name, source.as_ref());
    }
    #[cfg(feature = "hashbrown")]
    cases.gated("hashbrown", |cases| {
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
            dcbor::bounded::encoding::Preparation::<Reservation>::new(&duplicate),
            support::prepare_turns(support::shape(&duplicate)),
        );
    });
    #[cfg(feature = "derive")]
    cases.gated("derive", |cases| {
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
    symbolic.insert("k", 1.5f64);
    symbolic.insert(-1i64, true);
    symbolic.insert(10u64, "a");
    cases.synchronous("encode Vec<u64>", Outcome::Published, |m| {
        observed(&encode(&(0..300u64).collect::<Vec<_>>(), m))
    });
    cases.synchronous("encode text", Outcome::Published, |m| {
        observed(&encode(&format!("q{}", "\u{301}\u{316}".repeat(16)), m))
    });
    cases.synchronous("encode BTreeMap", Outcome::Published, |m| {
        observed(&encode(&tree, m))
    });
    cases.synchronous("encode CBOR", Outcome::Published, |m| {
        observed(&encode(&CBOR::from(symbolic.clone()), m))
    });
    cases.synchronous("encode Tagged", Outcome::Published, |m| {
        observed(&encode(&Tagged { tag: 2, value: "x" }, m))
    });
    cases.synchronous("encode ByteString", Outcome::Published, |m| {
        observed(&encode(&ByteString::from(vec![1u8; 100]), m))
    });
    cases.synchronous("encode Option", Outcome::Published, |m| {
        observed(&encode(&Some(vec![None, Some(1u64)]), m))
    });
    cases.synchronous("prepare encode_into", Outcome::Published, |m| {
        let value = vec!["a\u{301}".to_string(), "b".into()];
        let prepared = match prepare(&value, m) {
            Ok(prepared) => prepared,
            Err(error) => return observed::<(), _>(&Err(error)),
        };
        let mut bytes = vec![0; prepared.len()];
        observed(&prepared.encode_into(&mut bytes, m))
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
        observed(&decode_typed::<Record, _>(&record, 8, m))
    });
    cases.synchronous("decode_typed derived choice", Outcome::Published, |m| {
        observed(&decode_typed::<Choice, _>(&choice, 8, m))
    });
    cases.synchronous("encode derived choice", Outcome::Published, |m| {
        observed(&encode(&Choice::Text("x".into()), m))
    });
    owned_decode::<Record>(cases, "derived record", Outcome::Published, &record);
    owned_decode::<Choice>(cases, "derived choice", Outcome::Published, &choice);
}

#[cfg(feature = "hashbrown")]
fn buckets(cases: &mut Cases) {
    use dcbor::bounded::encoding::buckets::{BucketCursor, BucketStep};
    let mut table = hashbrown::HashTable::with_capacity(64);
    for value in [0u64, 17, 40, 63] {
        table.insert_unique(value, value, |value| *value);
    }
    for (name, batched) in [("single", false), ("batched", true)] {
        let mut m = meter();
        let mut cursor = BucketCursor::new(&table);
        let mut reached = Err(format!(
            "incomplete after {} buckets",
            table.num_buckets() + 1
        ));
        for _ in 0..=table.num_buckets() {
            m.fresh();
            let step = if batched {
                cursor.step_batch(&mut m)
            } else {
                cursor.step(&mut m)
            };
            match step {
                Ok(BucketStep::Complete) => {
                    reached = Ok(Outcome::Published);
                    break;
                }
                Ok(_) => {}
                Err(error) => {
                    reached = observed::<(), _>(&Err(error));
                    break;
                }
            }
        }
        cases.policy(
            format!("BucketCursor {name}"),
            Outcome::Published,
            reached,
            m,
        );
    }
}

fn cases() -> Cases {
    let mut cases = Cases::default();
    decoding(&mut cases);
    owned(&mut cases);
    text(&mut cases);
    preparation(&mut cases);
    synchronous_encoding(&mut cases);
    #[cfg(feature = "derive")]
    cases.gated("derive", derived);
    #[cfg(feature = "hashbrown")]
    cases.gated("hashbrown", buckets);
    cases
}

/// One call from its `Debug` rendering, the inverse of `{call:?}`.
fn parse_call(text: &str) -> Result<Call, String> {
    let number = |digits: &str| {
        digits
            .parse::<u64>()
            .map_err(|error| format!("{text:?}: {error}"))
    };
    if let Some(bytes) = text
        .strip_prefix("Allocate(")
        .and_then(|rest| rest.strip_suffix(')'))
    {
        return Ok(Call::Allocate(number(bytes)?));
    }
    let fields = text
        .strip_prefix("Work { values: ")
        .and_then(|rest| rest.strip_suffix(" }"))
        .ok_or_else(|| format!("{text:?} is not a call"))?;
    let (values, bytes) = fields
        .split_once(", bytes: ")
        .ok_or_else(|| format!("{text:?} is not a work call"))?;
    Ok(Call::Work {
        values: number(values)?,
        bytes: number(bytes)?,
    })
}

/// The recorded data: [`CONFIGURATION_LINE`] and `configuration`, then one
/// case per line, sorted by name: its name, the feature it is gated on or
/// [`UNGATED`], its outcome, and its calls in their `Debug` rendering
/// separated by `; `, the four separated by tabs. Only admissible cases are
/// rendered ([`Cases::inadmissible`]).
fn render(cases: &Cases, configuration: &str) -> String {
    let inadmissible = cases.inadmissible();
    assert!(
        inadmissible.is_empty(),
        "refusing trace evidence: {inadmissible:#?}"
    );
    let sorted: BTreeMap<&str, (&str, Outcome, &[Call])> = cases
        .cases
        .iter()
        .map(|case| {
            let feature = case.feature.unwrap_or(UNGATED);
            (
                case.name.as_str(),
                (feature, case.outcome, case.calls.as_slice()),
            )
        })
        .collect();
    let mut data = format!("{CONFIGURATION_LINE}{configuration}\n");
    for (name, (feature, outcome, calls)) in sorted {
        let calls: Vec<String> = calls.iter().map(|call| format!("{call:?}")).collect();
        data.push_str(&format!(
            "{name}\t{feature}\t{}\t{}\n",
            outcome.name(),
            calls.join("; ")
        ));
    }
    data
}

/// Publish `data` as `path` whole: written to a temporary file beside it,
/// then renamed over it, so a failed write leaves the previous record.
fn publish(path: &str, data: &str) {
    use std::io::Write;
    use std::sync::atomic::{AtomicUsize, Ordering};
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let temporary = format!(
        "{path}.{}.{}.tmp",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    );
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .unwrap_or_else(|error| panic!("{temporary}: {error}"));
    let result = file
        .write_all(data.as_bytes())
        .and_then(|_| file.sync_all());
    drop(file);
    if let Err(error) = result.and_then(|_| std::fs::rename(&temporary, path)) {
        let _ = std::fs::remove_file(&temporary);
        panic!("{path}: {error}");
    }
}

/// One recorded case: the feature it is gated on, its outcome, and its
/// calls.
struct Recorded {
    feature: Option<String>,
    outcome: Outcome,
    calls: Vec<Call>,
}

/// The configuration a record was recorded under, and every recorded case
/// by name. Each call renders back to its own text, each feature is one of
/// [`FEATURES`], and each outcome is one a case can declare.
fn recorded() -> (String, BTreeMap<String, Recorded>) {
    let data = std::fs::read_to_string(RECORDED)
        .unwrap_or_else(|error| panic!("{RECORDED}: {error}; record it with {RECORD}=1"));
    let mut lines = data.lines();
    let configuration = lines
        .next()
        .and_then(|line| line.strip_prefix(CONFIGURATION_LINE))
        .unwrap_or_else(|| {
            panic!("{RECORDED}:1: not the configuration it was recorded under; record it with {RECORD}=1")
        })
        .to_string();
    let mut recorded = BTreeMap::new();
    for (number, line) in lines.enumerate() {
        let at = number + 2;
        let mut columns = line.splitn(4, '\t');
        let (Some(name), Some(feature), Some(outcome), Some(calls)) = (
            columns.next(),
            columns.next(),
            columns.next(),
            columns.next(),
        ) else {
            panic!("{RECORDED}:{at}: not four columns: {line:?}");
        };
        let feature = (feature != UNGATED).then(|| {
            enabled(feature);
            feature.to_string()
        });
        let outcome = Outcome::parse(outcome)
            .unwrap_or_else(|| panic!("{RECORDED}:{at}: no outcome {outcome:?}"));
        let calls: Vec<Call> = if calls.is_empty() {
            Vec::new()
        } else {
            calls
                .split("; ")
                .map(|text| {
                    let call =
                        parse_call(text).unwrap_or_else(|error| panic!("{RECORDED}:{at}: {error}"));
                    assert_eq!(format!("{call:?}"), text, "{RECORDED}:{at}");
                    call
                })
                .collect()
        };
        assert!(
            recorded
                .insert(
                    name.to_string(),
                    Recorded {
                        feature,
                        outcome,
                        calls
                    }
                )
                .is_none(),
            "{RECORDED}:{at}: {name} is recorded twice"
        );
    }
    (configuration, recorded)
}

/// Every case reaches the outcome it declares before anything is recorded or
/// compared; recording rewrites every case, so it runs only where every
/// gated case is compiled, and only under a named configuration.
#[test]
fn every_baseline_admits_exactly_its_recorded_calls() {
    let cases = cases();
    let inadmissible = cases.inadmissible();
    assert!(
        inadmissible.is_empty(),
        "cases that did not reach their declared outcome, neither recorded nor compared: \
         {inadmissible:#?}"
    );
    if std::env::var_os(RECORD).is_some() {
        let disabled: Vec<&str> = FEATURES
            .iter()
            .filter(|(_, enabled)| !enabled)
            .map(|(name, _)| *name)
            .collect();
        assert!(
            disabled.is_empty(),
            "recording requires every gating feature; disabled: {disabled:?}"
        );
        let configuration = configuration().unwrap_or_else(|| {
            panic!("recording requires {CONFIGURATION}, which the flake's shells export")
        });
        publish(RECORDED, &render(&cases, &configuration));
        return;
    }
    let (recorded_under, recorded) = recorded();
    let running_under = configuration().unwrap_or_else(|| "an unnamed configuration".into());
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
    every_fixture(cases.cases.len(), |index| {
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
        let trace = case.policy.as_ref().map_or(&diagnostic, Limits::trace);
        trace.assert_calls(
            &case.calls,
            &expected.calls,
            &format!(
                "{} (recorded under {recorded_under}; running under {running_under})",
                case.name
            ),
        );
    });
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

/// The recorder refuses a planted defect, and a planted outcome other than
/// the one declared, naming each case and what it reached; an admissible
/// case beside them is not refused.
#[test]
fn a_planted_defect_or_undeclared_outcome_is_never_recorded() {
    let mut cases = Cases::default();
    cases.retained(
        "planted defect".into(),
        Outcome::Published,
        Defective::default(),
        1,
    );
    cases.synchronous("planted outcome", Outcome::Published, |_| {
        Ok(Outcome::Invalid)
    });
    cases.synchronous("admissible", Outcome::Invalid, |_| Ok(Outcome::Invalid));
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
        publish(
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

/// A record renders its configuration first and every case's outcome, and
/// publication replaces the record whole, leaving no temporary file.
#[test]
fn a_record_names_its_configuration_and_is_published_whole() {
    let mut cases = Cases::default();
    cases.synchronous("one", Outcome::Invalid, |_| Ok(Outcome::Invalid));
    let data = render(&cases, "toolchain=t std=s");
    assert_eq!(
        data,
        format!("{CONFIGURATION_LINE}toolchain=t std=s\none\t{UNGATED}\tinvalid\t\n")
    );
    let directory = std::env::temp_dir().join(format!("dcbor-traces-{}", std::process::id()));
    std::fs::create_dir_all(&directory).expect("a temporary directory");
    let path = directory.join("record.txt");
    let path = path.to_str().expect("a UTF-8 temporary path");
    std::fs::write(path, "previous").expect("the previous record");
    publish(path, &data);
    assert_eq!(std::fs::read_to_string(path).expect("the record"), data);
    assert_eq!(
        std::fs::read_dir(&directory).unwrap().count(),
        1,
        "temporary evidence was not removed"
    );
    std::fs::remove_dir_all(&directory).expect("the temporary directory removed");
}

#[test]
fn a_call_renders_back_to_itself() {
    for call in [
        Call::Work {
            values: 0,
            bytes: 0,
        },
        Call::Work {
            values: u64::MAX,
            bytes: 64,
        },
        Call::Allocate(u64::MAX),
    ] {
        assert_eq!(parse_call(&format!("{call:?}")), Ok(call));
    }
    for text in [
        "",
        "Allocate()",
        "Allocate(-1)",
        "Work { values: 1 }",
        "Work",
    ] {
        assert!(parse_call(text).is_err(), "{text:?} parsed");
    }
}
