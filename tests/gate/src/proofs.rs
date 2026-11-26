//! The proof harnesses' one build and one run (register item 4): `cargo
//! kani` over the package's library, defined once, read by the cfg census
//! (`cfgs`) so that every `cfg(kani)` predicate holds in a build the gates
//! make, by the controls' Kani runner (`controls`), and by the proof suite's
//! evidence ([`run`]).
//!
//! What the build defines is Kani's, read in its source (model-checking/kani
//! 0d2328a, `kani-driver/src/call_single_file.rs` `base_rustc_flags` and
//! `kani_rustc_flags`, `kani-driver/src/call_cargo.rs` `cargo_build`):
//! `--cfg=kani` passed to every crate of the build; `cargo rustc --lib` in
//! the dev profile, so `debug_assertions` and no `test` (`--tests` is not
//! passed: the harnesses live in the library); overflow checks on. The
//! build links Kani's own standard library, so the forked collections
//! (`custom-std-collections`, which needs a rebuilt standard library
//! exposing `hashmap_bucket_access`) are not selected: the build is the
//! crate's default `std` build.
//!
//! A run's report is read per harness (kani-driver `harness_runner.rs`
//! `check_harness`, `print_final_summary`; `cbmc_property_renderer.rs`
//! `format_result`): each `Checking harness NAME...` line opens a harness's
//! block, which its `VERIFICATION:- SUCCESSFUL` or `VERIFICATION:- FAILED`
//! line ends. A block reporting a reachable unsupported construct or a
//! failed unwinding assertion is classed by that fundamental failure, never
//! as verified or as an intended assertion failure
//! ([`crate::outcome::kani`]). The harnesses a run checked must be exactly
//! the `#[kani::proof]` functions of the library's source ([`harnesses`]):
//! a harness compiled out, renamed or never checked is a fault, not a
//! silence.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use crate::outcome::{self, Outcome, Termination};
use crate::rows::{Evidence, Physical, Purpose, Row};

/// The one declaration of the harness instances, shared with the library's
/// `build.rs`, which generates them: the census expects exactly the
/// harnesses its expansion names ([`harnesses`]).
#[path = "../../data/proofs/instances.rs"]
pub mod instances;

mod adoption;
mod calibration;
pub mod diagnostics;
mod eligibility;
mod readiness;

pub use adoption::{Adoption, adopt};
pub use calibration::{
    CalibrationRequest, Observed, Runtime, Schedule, Scheduled, calibrate, calibration,
};
pub use eligibility::{
    AdoptionReceipt, CalibrationSample, RunRecords, eligible_sample, ran_sample,
};
pub use readiness::{
    Clocks, ControlVerdict, LockRecord, Prerequisites, Readiness, Settled, SettlingPolicy,
    SystemClocks, WORKLOAD_LOCK, WorkloadLock, control_verdict, readiness, settle, settling_policy,
};

/// The build's name in the census.
pub const NAME: &str = "kani proofs";

/// The runner a proof harness's results row names.
pub const RUNNER: &str = "kani";

/// Its cargo feature arguments, as `cargo kani` takes them.
pub const FEATURES: &[&str] = &["--no-default-features", "--features", "std"];

/// The cfg names the build defines beside the host's (`unix`).
pub const NAMES: &[&str] = &["kani", "debug_assertions"];

/// The unstable Kani features the harnesses use: `stubbing`, for
/// `#[kani::stub]`, which the float and decode harnesses replace the `half`
/// adapters with (`src/float/proofs.rs`, `src/decode/proofs.rs`). Without it
/// the build refuses every stub ("Using the stub attribute requires
/// activating the unstable `stubbing` feature"). Kani 0.68.0's `-Z,
/// --unstable` list names it (`cargo kani --help`). `unstable-options`, for
/// `--loop-bounds`, which the patched driver accepts only with it (kani-driver
/// `args/mod.rs`, `loop-bounds`). No global `--harness-timeout` is passed:
/// the driver refuses it beside `--loop-bounds`, and each harness's deadline
/// is the run's policy's ([`EXPECTATIONS`], [`selected`]).
pub const UNSTABLE: &[&str] = &["-Z", "stubbing", "-Z", "unstable-options"];

/// The `cargo` arguments that make the build and run every harness in it:
/// the package's library alone, under [`FEATURES`], with [`UNSTABLE`]. Each
/// option is one `cargo kani` declares (kani-driver/src/args/cargo.rs:
/// `--package`, and `--no-default-features`, `--features` in
/// `CargoCommonArgs`; `--lib` in `CargoTargetArgs`, which with `--lib`
/// includes the library and no test target, `include_lib`, `include_tests`;
/// `-Z` in the common options).
pub fn arguments() -> Vec<&'static str> {
    let mut arguments = vec!["kani", "--package", "dcbor", "--lib"];
    arguments.extend_from_slice(FEATURES);
    arguments.extend_from_slice(UNSTABLE);
    arguments
}

/// The one layout of a Kani run's arguments: the build's own
/// ([`arguments`]), then `--harness HARNESS --exact` for each harness an
/// explicit `selection` names, then the run's target directory, its
/// selected policy file (`--loop-bounds`) and its evidence directory
/// (`--loop-bounds-evidence`). What `process::kani` launches with and what
/// a run's recorded invocation is held to ([`eligible_sample`]).
pub fn invocation_arguments(
    selection: &Selection,
    target_dir: &str,
    policy: &str,
    bounds: &str,
) -> Vec<String> {
    let mut invocation: Vec<String> = arguments().into_iter().map(str::to_string).collect();
    if let Selection::Only(harnesses) = selection {
        for harness in harnesses {
            invocation.extend([
                "--harness".to_string(),
                harness.clone(),
                "--exact".to_string(),
            ]);
        }
    }
    invocation.extend([
        "--target-dir".to_string(),
        target_dir.to_string(),
        "--loop-bounds".to_string(),
        policy.to_string(),
        "--loop-bounds-evidence".to_string(),
        bounds.to_string(),
    ]);
    invocation
}

/// Each harness's predicted verification time, relative to the root a run
/// verifies ([`expectations`]): the one document of the census's predictions
/// and the one reader of it. Every prediction is fitted by [`RULE`] from
/// calibration runs the tree holds ([`CALIBRATION`]), recomputed by the
/// reader from their raw records, never taken from the document. A
/// qualifying run gives each harness a deadline of [`DEADLINE_MARGIN`] times
/// its prediction ([`RunPurpose::deadlines`]); a harness whose recorded CBMC
/// run, from immediately after its spawn to its end, took longer than its
/// prediction fails the run though it met its deadline
/// ([`check_expectations`]). A run that exceeds either shows that the harness
/// is wrongly sized for its prediction, that the prediction is wrong, or that
/// the code it checks regressed. A prediction is never revised solely to turn
/// a failed run green: a correction needs its own justification, the failed
/// run's evidence is kept, and the run is repeated.
pub const EXPECTATIONS: &str = "tests/data/proofs/expectations.json";

/// The operational margin of every qualifying deadline over its prediction:
/// the operator's direction that a harness's deadline is twice its expected
/// wall-clock time. A policy value, never a model of the prediction's
/// uncertainty; applied once, when the predictions are read
/// ([`expectations_of`]).
pub const DEADLINE_MARGIN: u64 = 2;

/// The adopted calibration runs, relative to the root: one directory per run,
/// named by its identifier, holding its log and evidence as the gate wrote
/// them, every instrumented binary but recorded by digest alone
/// ([`adopt`]).
pub const CALIBRATION: &str = "tests/data/proofs/calibration";

/// The version of every document the proof suite's runtime evidence reads
/// and writes: plans, run identities, manifests and predictions.
pub const RUNTIME_VERSION: u64 = 1;

/// The purposes a run's identity names ([`RunPurpose::name`]).
pub const PURPOSE_CALIBRATION: &str = "calibration";
pub const PURPOSE_QUALIFICATION: &str = "qualification";
pub const PURPOSE_CONTROL: &str = "control";
pub const PURPOSE_DISCOVERY: &str = "discovery";

/// The records a run keeps of the documents it was given, beside its
/// identity ([`RunPurpose::documents`]).
pub const PLAN_RECORD: &str = "plan.json";
pub const READINESS_RECORD: &str = "readiness.json";
pub const EXPECTATIONS_RECORD: &str = "expectations.json";
pub const DISCOVERY_RECORD: &str = "discovery.json";

/// The deadline every harness of a discovery is given, and why: the driver
/// writes a harness's loop discovery (`discovery.*`) before it spawns CBMC
/// (nix/kani-driver-loop-bounds.patch, `loop_bounds.rs` `discover` before
/// `launch`), so a discovery has nothing to wait for once CBMC starts.
pub const DISCOVERY_MILLISECONDS: u64 = 1;
pub const DISCOVERY_REASON: &str = "discovery only: the driver records loop discovery before CBMC \
     starts; the solver is stopped at once and nothing is verified";

/// The records a run keeps of the inputs its validated execution bound
/// (`process::kani`): the program it launched; the tree's loop-bound policy
/// file as read, the bytes its identity's policy digest is of; every source
/// path's own digest, what its identity's source state is the digest of
/// ([`tree_digest_of`]); and its invocation, the launcher and every argument
/// it was given.
pub const LAUNCHER_RECORD: &str = "launcher";
pub const LOOP_POLICY_RECORD: &str = "loop-policy.json";
pub const SOURCES_RECORD: &str = "sources.json";
pub const INVOCATION_RECORD: &str = "invocation.json";

/// An adopted run's acceptance receipt, beside its log and evidence
/// ([`adopt`], [`AdoptionReceipt`]): written only once the publication's
/// durability was established, and required by every reader of an adopted
/// run.
pub const ADOPTION_RECORD: &str = "adoption.json";

/// The one prediction rule: per-harness repeatability. From [`SAMPLES`]
/// verified calibration executions of the harness, each in a run of its own,
/// all of one artifact, verifier, build, loop-bound policy and environment,
/// with durations `t`: `max(t)` plus the larger of the harness's own spread
/// `max(t) - min(t)` and the envelope's (the largest spread of any harness
/// the document predicts), rounded up to whole milliseconds. The spread is an
/// empirical allowance for the variation observed, not a confidence bound; no
/// timing is transferred from one harness to another.
pub const RULE: &str = "repeatability-v1";

/// The calibration executions [`RULE`] takes per harness.
pub const SAMPLES: usize = 3;

/// What a recorded duration measures: the driver's solver execution record.
pub const TIMING_BOUNDARY: &str = "solver.execution.json elapsed: from immediately after CBMC's \
     spawn to its exit reaped, the deadline's detection, or an execution error \
     (nix/kani-driver-loop-bounds.patch, loop_bounds.rs SolverTermination)";

/// A JSON value read so that no object anywhere in it holds a key twice,
/// where `serde_json` would keep the last ([`strict_json`]).
struct Strict(serde_json::Value);

impl<'de> serde::Deserialize<'de> for Strict {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visit;
        impl<'de> serde::de::Visitor<'de> for Visit {
            type Value = Strict;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("JSON in which no object holds a key twice")
            }

            fn visit_bool<E>(self, value: bool) -> Result<Strict, E> {
                Ok(Strict(serde_json::Value::Bool(value)))
            }

            fn visit_i64<E>(self, value: i64) -> Result<Strict, E> {
                Ok(Strict(value.into()))
            }

            fn visit_u64<E>(self, value: u64) -> Result<Strict, E> {
                Ok(Strict(value.into()))
            }

            fn visit_f64<E: serde::de::Error>(self, value: f64) -> Result<Strict, E> {
                serde_json::Number::from_f64(value)
                    .map(|number| Strict(serde_json::Value::Number(number)))
                    .ok_or_else(|| E::custom(format!("{value} is not a JSON number")))
            }

            fn visit_str<E>(self, value: &str) -> Result<Strict, E> {
                Ok(Strict(serde_json::Value::String(value.to_string())))
            }

            fn visit_string<E>(self, value: String) -> Result<Strict, E> {
                Ok(Strict(serde_json::Value::String(value)))
            }

            fn visit_unit<E>(self) -> Result<Strict, E> {
                Ok(Strict(serde_json::Value::Null))
            }

            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<Strict, A::Error> {
                let mut items = Vec::new();
                while let Some(Strict(item)) = seq.next_element()? {
                    items.push(item);
                }
                Ok(Strict(serde_json::Value::Array(items)))
            }

            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> Result<Strict, A::Error> {
                let mut object = serde_json::Map::new();
                while let Some(key) = map.next_key::<String>()? {
                    let Strict(value) = map.next_value()?;
                    if object.insert(key.clone(), value).is_some() {
                        return Err(serde::de::Error::custom(format!(
                            "the key {key:?} appears twice in one object"
                        )));
                    }
                }
                Ok(Strict(serde_json::Value::Object(object)))
            }
        }
        deserializer.deserialize_any(Visit)
    }
}

/// `text` as JSON in which no object, at any depth, holds a key twice.
pub fn strict_json(text: &[u8]) -> Result<serde_json::Value, String> {
    serde_json::from_slice::<Strict>(text)
        .map(|Strict(value)| value)
        .map_err(|error| format!("not JSON: {error}"))
}

/// `value` as `T`, refusing unknown fields where `T` does, `what` naming it.
fn typed<T: serde::de::DeserializeOwned>(
    value: serde_json::Value,
    what: &str,
) -> Result<T, String> {
    serde_json::from_value(value).map_err(|error| format!("{what}: {error}"))
}

/// The deadline a run gives one harness, and why: the one form both
/// purposes give the driver ([`selected`]), made only from a validated
/// plan's limit or a validated prediction ([`RunPurpose::deadlines`]): a
/// positive number of milliseconds and a non-blank reason.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Deadline {
    milliseconds: u64,
    reason: String,
}

impl Deadline {
    pub fn milliseconds(&self) -> u64 {
        self.milliseconds
    }

    pub fn reason(&self) -> &str {
        &self.reason
    }
}

/// A validated calibration plan ([`plan_of`], its only maker): the
/// harnesses a calibration runs, each with its operational limit, the bytes
/// of the document stating them, and those bytes' digest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Plan {
    sha256: String,
    bytes: Vec<u8>,
    deadlines: BTreeMap<String, Deadline>,
}

impl Plan {
    /// The digest of the document's bytes.
    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    /// The document's bytes, as read.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Each planned harness's limit.
    pub fn deadlines(&self) -> &BTreeMap<String, Deadline> {
        &self.deadlines
    }
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PlanDocument {
    version: u64,
    purpose: String,
    harnesses: BTreeMap<String, PlanEntry>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PlanEntry {
    limit_milliseconds: u64,
    reason: String,
}

/// The calibration plan at `path` ([`plan_of`]).
pub fn plan(path: &Path, declared: &BTreeSet<String>) -> Result<Plan, String> {
    let bytes = std::fs::read(path).map_err(|error| format!("{}: {error}", path.display()))?;
    plan_of(&bytes, declared).map_err(|fault| format!("{}: {fault}", path.display()))
}

/// The calibration plan of the byte snapshot `bytes`, its digest taken from
/// those same bytes: exactly `version` ([`RUNTIME_VERSION`]), `purpose`
/// (`calibration`) and `harnesses`, a non-empty object of harnesses of
/// `declared`, each exactly a positive `limit_milliseconds` and a non-blank
/// `reason`. A limit is an operational resource cap, never a prediction.
/// Refused otherwise, a key repeated anywhere included, before anything
/// runs.
pub fn plan_of(bytes: &[u8], declared: &BTreeSet<String>) -> Result<Plan, String> {
    let sha256 = crate::process::sha256_bytes(bytes)?;
    let document: PlanDocument = typed(strict_json(bytes)?, "not a calibration plan")?;
    if document.version != RUNTIME_VERSION {
        return Err(format!(
            "version {}, the gate reads {RUNTIME_VERSION}",
            document.version
        ));
    }
    if document.purpose != "calibration" {
        return Err(format!(
            "its purpose is {:?}, not \"calibration\"",
            document.purpose
        ));
    }
    if document.harnesses.is_empty() {
        return Err("it selects no harness".to_string());
    }
    let mut deadlines = BTreeMap::new();
    for (harness, entry) in document.harnesses {
        if !declared.contains(&harness) {
            return Err(format!(
                "harness {harness}: planned, but declared by no #[kani::proof] of the source"
            ));
        }
        if entry.limit_milliseconds == 0 {
            return Err(format!("harness {harness}: a limit of 0 ms"));
        }
        if entry.reason.trim().is_empty() {
            return Err(format!("harness {harness}: its limit gives no reason"));
        }
        deadlines.insert(
            harness,
            Deadline {
                milliseconds: entry.limit_milliseconds,
                reason: entry.reason,
            },
        );
    }
    Ok(Plan {
        sha256,
        bytes: bytes.to_vec(),
        deadlines,
    })
}

/// What a Kani run is for, and what it brings: a calibration measures under
/// its plan and qualifies nothing, its results never a proof row or a
/// control's side; a qualification verifies the census in the tree it was
/// calibrated on; a control side (its baseline, red or green) runs one
/// harness on a control's copy, held to the same predictions under the
/// authorization its control's runner validated for that side
/// ([`crate::controls::Authorization`]), never a bare exemption.
/// A calibration's readiness to run ([`readiness`], its only maker), the
/// receipt's bytes as preserved and their digest: what every calibration run
/// keeps beside its plan, binding it to the control run and the settling it
/// followed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ready {
    sha256: String,
    bytes: Vec<u8>,
}

impl Ready {
    pub fn sha256(&self) -> &str {
        &self.sha256
    }
}

/// A validated discovery ([`discovery_of`], its only maker): the harnesses a
/// discovery run compiles and inventories the loops of, the bytes of its
/// record (the harnesses sorted, one per line, each ended by a newline) and
/// those bytes' digest, the run's revision. A discovery verifies nothing, is
/// never a sample and is never adopted; what it establishes is each
/// harness's preserved instrumented binary and the driver's loop discovery
/// of it, from which the loop-bound policy's selectors are copied.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Discovery {
    selection: BTreeSet<String>,
    bytes: Vec<u8>,
    sha256: String,
}

impl Discovery {
    /// The harnesses it discovers.
    pub fn selection(&self) -> &BTreeSet<String> {
        &self.selection
    }

    /// The digest of its record's bytes.
    pub fn sha256(&self) -> &str {
        &self.sha256
    }
}

/// The discovery of `harnesses` of the census `declared`: refused when it
/// selects no harness, names one twice, or names one no `#[kani::proof]` of
/// the source declares, before anything runs.
pub fn discovery_of(
    harnesses: &[String],
    declared: &BTreeSet<String>,
) -> Result<Discovery, String> {
    if harnesses.is_empty() {
        return Err("a discovery selects no harness".to_string());
    }
    let mut selection = BTreeSet::new();
    for harness in harnesses {
        if !declared.contains(harness) {
            return Err(format!(
                "harness {harness}: selected for discovery, but declared by no #[kani::proof] of \
                 the source"
            ));
        }
        if !selection.insert(harness.clone()) {
            return Err(format!("harness {harness}: selected for discovery twice"));
        }
    }
    let bytes: Vec<u8> = selection
        .iter()
        .flat_map(|harness| harness.bytes().chain(*b"\n"))
        .collect();
    Ok(Discovery {
        sha256: crate::process::sha256_bytes(&bytes)?,
        bytes,
        selection,
    })
}

#[derive(Clone, Debug, PartialEq)]
pub enum RunPurpose {
    Calibration {
        plan: Plan,
        ready: Ready,
    },
    Qualification(Expectations),
    Control {
        expectations: Expectations,
        authorization: Box<crate::controls::Authorization>,
    },
    Discovery(Discovery),
}

/// Which instrumented binary a prediction applies to at a run: exactly its
/// calibration's (the suite's qualification, in the tree calibrated); or, for
/// a control side, what its authorization binds: a baseline's own build of
/// the copy, recorded beside the calibration's with the transfer that
/// justifies it; a red side's mutated build, recorded; a restored green
/// side's, equal to its verified baseline's.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Applicability<'a> {
    Calibrated,
    Control(&'a crate::controls::Authorization),
}

impl RunPurpose {
    /// The purpose's name, as a run's identity records it.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Calibration { .. } => PURPOSE_CALIBRATION,
            Self::Qualification(_) => PURPOSE_QUALIFICATION,
            Self::Control { .. } => PURPOSE_CONTROL,
            Self::Discovery(_) => PURPOSE_DISCOVERY,
        }
    }

    /// The documents the run was given, as its evidence keeps them before it
    /// launches, each by its file name and bytes: the plan, the predictions
    /// or the discovery's selection first, whose digest is the run's revision
    /// ([`Self::revision`]), then a calibration's readiness.
    pub fn documents(&self) -> Vec<(&'static str, &[u8])> {
        match self {
            Self::Calibration { plan, ready } => {
                vec![(PLAN_RECORD, &plan.bytes), (READINESS_RECORD, &ready.bytes)]
            }
            Self::Qualification(expectations) | Self::Control { expectations, .. } => {
                vec![(EXPECTATIONS_RECORD, &expectations.bytes)]
            }
            Self::Discovery(discovery) => vec![(DISCOVERY_RECORD, &discovery.bytes)],
        }
    }

    /// The digest of the plan, the predictions or the discovery's selection
    /// the run was given.
    pub fn revision(&self) -> &str {
        match self {
            Self::Calibration { plan, .. } => &plan.sha256,
            Self::Qualification(expectations) | Self::Control { expectations, .. } => {
                &expectations.sha256
            }
            Self::Discovery(discovery) => &discovery.sha256,
        }
    }

    /// Every harness's deadline, built once for each purpose: a
    /// calibration's limit as its plan states it, a qualification's or a
    /// control side's [`DEADLINE_MARGIN`] times its prediction, a
    /// discovery's [`DISCOVERY_MILLISECONDS`] for each harness it selects.
    pub fn deadlines(&self) -> BTreeMap<String, Deadline> {
        match self {
            Self::Discovery(discovery) => discovery
                .selection
                .iter()
                .map(|harness| {
                    (
                        harness.clone(),
                        Deadline {
                            milliseconds: DISCOVERY_MILLISECONDS,
                            reason: DISCOVERY_REASON.to_string(),
                        },
                    )
                })
                .collect(),
            Self::Calibration { plan, .. } => plan.deadlines.clone(),
            Self::Qualification(expectations) | Self::Control { expectations, .. } => expectations
                .harnesses
                .iter()
                .map(|(harness, expectation)| {
                    (
                        harness.clone(),
                        Deadline {
                            milliseconds: expectation.deadline_milliseconds,
                            reason: format!(
                                "{DEADLINE_MARGIN} times the predicted {} ms ({RULE}): {}",
                                expectation.milliseconds, expectation.transfer
                            ),
                        },
                    )
                })
                .collect(),
        }
    }
}

/// Which harnesses a run checks: the whole census, or exactly these.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Selection {
    All,
    Only(BTreeSet<String>),
}

impl Selection {
    /// The selection of the one harness `harness`.
    pub fn one(harness: &str) -> Self {
        Self::Only(BTreeSet::from([harness.to_string()]))
    }

    pub fn contains(&self, harness: &str) -> bool {
        match self {
            Self::All => true,
            Self::Only(harnesses) => harnesses.contains(harness),
        }
    }
}

/// The effective execution environment of a run's workload, as its process
/// was found once its confinement had moved it out of the gate's own control
/// group, each fact `None` when it could not be read: the processor's model;
/// the processors the workload may run on, its affinity (`/proc/PID/status`
/// `Cpus_allowed_list`) and its group's effective cpuset
/// (`cpuset.cpus.effective`); and its group and every ancestor through `/`
/// ([`limits`]), each with its path and its `cpu.max` and `memory.max`
/// observations ([`LimitObservation`]), which together bound what the
/// workload can use. A record is what was observed, kept whatever it holds;
/// only an established one ([`EnvironmentRecord::establish`]) is compared
/// ([`EstablishedEnvironment::equivalent`]), its constraints alone: every
/// run's confinement is a transient scope of its own, whose name differs.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentRecord {
    pub cpu_model: Option<String>,
    pub cpus_allowed: Option<String>,
    pub cpuset_effective: Option<String>,
    pub levels: Vec<Level>,
}

/// One control group of a workload's hierarchy, its path (provenance, never
/// compared) and its processor and memory limits as read.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Level {
    pub path: String,
    pub cpu_max: LimitObservation,
    pub memory_max: LimitObservation,
}

/// One limit file of one control group, as read: its validated value; its
/// absence where cgroup v2 establishes the file is inapplicable, and why
/// (the root group keeps no `cpu.max` or `memory.max`; a group whose parent
/// does not enable the file's controller for its children, its
/// `cgroup.subtree_control` read, has none of that controller's files); or
/// its unavailability, any other outcome: a malformed value, a permission
/// failure, a group that disappeared, a file missing though its controller
/// is enabled, or a parent whose controls could not be read. Absence is
/// never taken for an unlimited value.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "state", rename_all = "kebab-case", deny_unknown_fields)]
pub enum LimitObservation {
    Value { value: String },
    Absent { reason: String },
    Unavailable { error: String },
}

/// Whether `text` is a CPU list as the kernel writes one (`0-3,8,10-11`):
/// non-empty, every range ascending.
fn cpu_list(text: &str) -> bool {
    !text.is_empty()
        && text.split(',').all(|range| {
            let (low, high) = range.split_once('-').unwrap_or((range, range));
            matches!((low.parse::<u32>(), high.parse::<u32>()), (Ok(low), Ok(high)) if low <= high)
        })
}

/// Whether `value` is a valid `name` limit: `cpu.max`, a quota (`max` or a
/// positive integer) and a positive period; `memory.max`, `max` or an
/// integer of bytes.
fn limit_valid(name: &str, value: &str) -> bool {
    match name {
        "cpu.max" => {
            let parts: Vec<&str> = value.split(' ').collect();
            matches!(parts.as_slice(), [quota, period]
                if (*quota == "max" || quota.parse::<u64>().is_ok_and(|quota| quota > 0))
                    && period.parse::<u64>().is_ok_and(|period| period > 0))
        }
        "memory.max" => value == "max" || value.parse::<u64>().is_ok(),
        _ => false,
    }
}

/// The control group `workload` and every ancestor through the root `/`,
/// innermost first, each exactly once.
fn ancestry(workload: &str) -> Vec<String> {
    let mut paths = Vec::new();
    let mut at = workload.trim_end_matches('/').to_string();
    while !at.is_empty() {
        paths.push(at.clone());
        at = at
            .rsplit_once('/')
            .map(|(parent, _)| parent.to_string())
            .unwrap_or_default();
    }
    paths.push("/".to_string());
    paths
}

/// The directory of the group `path` in the hierarchy mounted at `hierarchy`.
fn group_directory(hierarchy: &Path, path: &str) -> std::path::PathBuf {
    hierarchy.join(path.trim_start_matches('/'))
}

/// The limit file `name` (`cpu.max`, `memory.max`) of the group `path`,
/// whose parent is `parent` (none for the root), in the hierarchy at
/// `hierarchy`, as [`LimitObservation`] states it.
fn limit(hierarchy: &Path, path: &str, parent: Option<&str>, name: &str) -> LimitObservation {
    let directory = group_directory(hierarchy, path);
    let file = directory.join(name);
    match std::fs::read_to_string(&file) {
        Ok(text) => {
            let value = text.trim().to_string();
            if limit_valid(name, &value) {
                LimitObservation::Value { value }
            } else {
                LimitObservation::Unavailable {
                    error: format!("{}: malformed: {value:?}", file.display()),
                }
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            if !std::fs::symlink_metadata(&directory).is_ok_and(|metadata| metadata.is_dir()) {
                return LimitObservation::Unavailable {
                    error: format!("{}: the group no longer exists", directory.display()),
                };
            }
            let controller = name.split('.').next().unwrap_or(name);
            let Some(parent) = parent else {
                return LimitObservation::Absent {
                    reason: format!("cgroup v2 keeps no {name} in the root group"),
                };
            };
            let controls = group_directory(hierarchy, parent).join("cgroup.subtree_control");
            match std::fs::read_to_string(&controls) {
                Ok(enabled) if !enabled.split_whitespace().any(|found| found == controller) => {
                    LimitObservation::Absent {
                        reason: format!(
                            "{parent} does not enable the {controller} controller for its \
                             children ({}: {:?})",
                            controls.display(),
                            enabled.trim()
                        ),
                    }
                }
                Ok(_) => LimitObservation::Unavailable {
                    error: format!(
                        "{}: missing, though {parent} enables the {controller} controller",
                        file.display()
                    ),
                },
                Err(error) => LimitObservation::Unavailable {
                    error: format!(
                        "{}: missing, and whether its controller is enabled is unknown: {}: \
                         {error}",
                        file.display(),
                        controls.display()
                    ),
                },
            }
        }
        Err(error) => LimitObservation::Unavailable {
            error: format!("{}: {error}", file.display()),
        },
    }
}

/// The limits of the control group `workload` and of every ancestor through
/// the root `/`, innermost first ([`ancestry`]), read from the cgroup
/// hierarchy mounted at `hierarchy` (`/sys/fs/cgroup`), each file as
/// [`LimitObservation`] states it.
pub fn limits(hierarchy: &Path, workload: &str) -> Vec<Level> {
    let paths = ancestry(workload);
    paths
        .iter()
        .enumerate()
        .map(|(at, path)| {
            let parent = paths.get(at + 1).map(String::as_str);
            Level {
                cpu_max: limit(hierarchy, path, parent, "cpu.max"),
                memory_max: limit(hierarchy, path, parent, "memory.max"),
                path: path.clone(),
            }
        })
        .collect()
}

/// The effective cpuset of the group `workload`: the innermost group of its
/// ancestry whose `cpuset.cpus.effective` exists (a group whose parent does
/// not enable the cpuset controller has none and runs on its nearest
/// cpuset-enabled ancestor's), as read; `None` when none can be read.
pub fn effective_cpuset(hierarchy: &Path, workload: &str) -> Option<String> {
    ancestry(workload).iter().find_map(|path| {
        std::fs::read_to_string(group_directory(hierarchy, path).join("cpuset.cpus.effective"))
            .ok()
            .map(|text| text.trim().to_string())
    })
}

/// How long the gate waits for a launched workload's confinement to move it
/// out of the gate's own control group: the transient scope is created
/// before the workload's command is exec'd (tests/workload.sh), in well under
/// a second; past this bound the confinement is not established and every
/// confinement fact is unknown.
pub const CONFINEMENT_WAIT: std::time::Duration = std::time::Duration::from_secs(10);

/// An environment every fact of which is established ([`EnvironmentRecord::
/// establish`], its only maker): the record it was validated from, kept
/// whole for diagnosis, and its constraints, the one thing compared.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EstablishedEnvironment {
    record: EnvironmentRecord,
}

impl EstablishedEnvironment {
    /// The record it was established from.
    pub fn record(&self) -> &EnvironmentRecord {
        &self.record
    }

    /// Whether this environment and `other` constrain a workload alike: the
    /// processor model, the affinity, the effective cpuset and every level's
    /// limits in ancestry order; the levels' paths, transient scope names
    /// among them, are provenance and not compared.
    pub fn equivalent(&self, other: &Self) -> bool {
        let constraints = |environment: &Self| {
            let record = &environment.record;
            (
                record.cpu_model.clone(),
                record.cpus_allowed.clone(),
                record.cpuset_effective.clone(),
                record
                    .levels
                    .iter()
                    .map(|level| (level.cpu_max.clone(), level.memory_max.clone()))
                    .collect::<Vec<_>>(),
            )
        };
        constraints(self) == constraints(other)
    }
}

impl EnvironmentRecord {
    /// This record established, every fact validated as a live observation
    /// is, whether it was just observed or read back from evidence: a
    /// non-blank processor model; an affinity and an effective cpuset that
    /// are non-empty CPU lists; a hierarchy that is exactly one group's
    /// ancestry through `/` ([`ancestry`]); and at every level each limit a
    /// value valid for its file ([`limit_valid`]) or an absence with its
    /// reason, none unavailable. Refused naming the first fact that is not.
    pub fn establish(&self) -> Result<EstablishedEnvironment, String> {
        let fault = |what: String| Err(format!("the environment is not established: {what}"));
        if !self
            .cpu_model
            .as_deref()
            .is_some_and(|model| !model.trim().is_empty())
        {
            return fault(format!("its processor model is {:?}", self.cpu_model));
        }
        for (what, list) in [
            ("affinity", &self.cpus_allowed),
            ("effective cpuset", &self.cpuset_effective),
        ] {
            if !list.as_deref().is_some_and(cpu_list) {
                return fault(format!("its {what} is {list:?}, not a CPU list"));
            }
        }
        let Some(innermost) = self.levels.first() else {
            return fault("it records no control group".to_string());
        };
        let paths: Vec<&str> = self
            .levels
            .iter()
            .map(|level| level.path.as_str())
            .collect();
        if paths
            != ancestry(&innermost.path)
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>()
        {
            return fault(format!(
                "its levels {paths:?} are not the ancestry of {} through /",
                innermost.path
            ));
        }
        for level in &self.levels {
            for (name, observation) in [
                ("cpu.max", &level.cpu_max),
                ("memory.max", &level.memory_max),
            ] {
                let established = match observation {
                    LimitObservation::Value { value } => limit_valid(name, value),
                    LimitObservation::Absent { reason } => !reason.trim().is_empty(),
                    LimitObservation::Unavailable { .. } => false,
                };
                if !established {
                    return fault(format!("{} {name} is {observation:?}", level.path));
                }
            }
        }
        Ok(EstablishedEnvironment {
            record: self.clone(),
        })
    }

    /// An environment of which nothing is known.
    pub fn unknown() -> Self {
        Self {
            cpu_model: None,
            cpus_allowed: None,
            cpuset_effective: None,
            levels: Vec::new(),
        }
    }

    /// The environment of the launched workload `child`, and its control
    /// group: the group read until the confinement has moved the process out
    /// of the gate's own, the process has exited (an exited child is never
    /// waited on here, so a zombie's entry cannot hold the gate), or
    /// [`CONFINEMENT_WAIT`] has passed, whichever is first. A workload whose
    /// group was not seen to move has no known confinement.
    pub fn of_workload(child: &mut std::process::Child) -> (Self, Option<String>) {
        let read = |path: &str| std::fs::read_to_string(path).ok();
        let group = |path: &str| {
            read(path).and_then(|text| {
                text.lines()
                    .find_map(|line| line.strip_prefix("0::"))
                    .map(str::to_string)
            })
        };
        let pid = child.id();
        // The gate's own group unknown, no group the workload is found in
        // can be told apart from it: the confinement stays unestablished.
        let Some(own) = group("/proc/self/cgroup") else {
            return (Self::unknown(), None);
        };
        let waited = std::time::Instant::now();
        let mut workload = None;
        while waited.elapsed() < CONFINEMENT_WAIT && matches!(child.try_wait(), Ok(None)) {
            match group(&format!("/proc/{pid}/cgroup")) {
                Some(found) if found != own => {
                    workload = Some(found);
                    break;
                }
                Some(_) => std::thread::sleep(std::time::Duration::from_millis(10)),
                None => break,
            }
        }
        let cpus_allowed = workload.as_ref().and_then(|_| {
            read(&format!("/proc/{pid}/status")).and_then(|text| {
                text.lines()
                    .find_map(|line| line.strip_prefix("Cpus_allowed_list:"))
                    .map(|list| list.trim().to_string())
            })
        });
        let hierarchy = Path::new("/sys/fs/cgroup");
        let environment = Self {
            cpu_model: read("/proc/cpuinfo").and_then(|text| {
                text.lines()
                    .find_map(|line| line.strip_prefix("model name"))
                    .and_then(|rest| rest.split_once(':'))
                    .map(|(_, model)| model.trim().to_string())
            }),
            cpus_allowed,
            cpuset_effective: workload
                .as_deref()
                .and_then(|path| effective_cpuset(hierarchy, path)),
            levels: workload
                .as_deref()
                .map(|path| limits(hierarchy, path))
                .unwrap_or_default(),
        };
        (environment, workload)
    }
}

/// A duration as the gate and the driver record it: whole seconds and the
/// nanoseconds below one.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(deny_unknown_fields)]
pub struct Instant {
    pub seconds: u64,
    pub nanoseconds: u32,
}

/// The time now as a run records it.
pub(crate) fn now() -> Result<Instant, String> {
    let since = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|error| format!("the clock is before the Unix epoch: {error}"))?;
    Ok(Instant {
        seconds: since.as_secs(),
        nanoseconds: since.subsec_nanos(),
    })
}

/// A run's identity, written into its evidence before it launches: a fresh
/// identifier (`/proc/sys/kernel/random/uuid`), its purpose and the digest of
/// the document it was given (kept beside it, [`RunPurpose::document`]), the
/// digest of the source state of the copy it ran ([`tree_digest`]; the commit
/// the copy was archived from is its script's record, `commit.txt`), the
/// build's arguments, the loop-bound policy's digest, and its start, seconds
/// and nanoseconds since the Unix epoch. Its environment and the system's
/// load are recorded once the workload is launched ([`Launch`]).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunIdentityRecord {
    pub version: u64,
    pub id: String,
    pub purpose: String,
    pub revision: String,
    pub tree_sha256: String,
    pub build: String,
    pub loop_policy_sha256: String,
    pub started: Instant,
}

impl RunIdentityRecord {
    /// This record validated ([`RunIdentity`]): of [`RUNTIME_VERSION`], its
    /// identifier a run identifier ([`run_identifier`]), its purpose one a
    /// run has, its revision, source state and policy SHA-256 digests, its
    /// build named, its start's nanoseconds below a second.
    pub fn validate(self) -> Result<RunIdentity, String> {
        let fault = |what: String| Err(format!("run.json: {what}"));
        if self.version != RUNTIME_VERSION {
            return fault(format!(
                "version {}, the gate reads {RUNTIME_VERSION}",
                self.version
            ));
        }
        run_identifier(&self.id)?;
        if ![
            PURPOSE_CALIBRATION,
            PURPOSE_QUALIFICATION,
            PURPOSE_CONTROL,
            PURPOSE_DISCOVERY,
        ]
        .contains(&self.purpose.as_str())
        {
            return fault(format!("no run has the purpose {:?}", self.purpose));
        }
        for (what, digest) in [
            ("revision", &self.revision),
            ("source state", &self.tree_sha256),
            ("loop-bound policy", &self.loop_policy_sha256),
        ] {
            if !sha256_text(digest) {
                return fault(format!("its {what} {digest:?} is no SHA-256 digest"));
            }
        }
        if self.build.trim().is_empty() {
            return fault("it names no build".to_string());
        }
        if self.started.nanoseconds >= 1_000_000_000 {
            return fault(format!(
                "its start's nanoseconds {} are not below a second",
                self.started.nanoseconds
            ));
        }
        Ok(RunIdentity { record: self })
    }
}

/// A validated run identity ([`RunIdentityRecord::validate`], its only
/// maker): what a run's judgement and every reader of its evidence hold it
/// to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunIdentity {
    record: RunIdentityRecord,
}

impl RunIdentity {
    pub fn record(&self) -> &RunIdentityRecord {
        &self.record
    }

    pub fn id(&self) -> &str {
        &self.record.id
    }

    pub fn purpose(&self) -> &str {
        &self.record.purpose
    }

    pub fn revision(&self) -> &str {
        &self.record.revision
    }

    pub fn tree_sha256(&self) -> &str {
        &self.record.tree_sha256
    }

    pub fn build(&self) -> &str {
        &self.record.build
    }

    pub fn loop_policy_sha256(&self) -> &str {
        &self.record.loop_policy_sha256
    }
}

/// What the launch of a run's workload established: its environment and its
/// own control group ([`EnvironmentRecord::of_workload`]), recorded and never
/// compared, and the system's load averages and run queue (`/proc/loadavg`)
/// before and after it.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Launch {
    pub environment: EnvironmentRecord,
    pub workload_cgroup: Option<String>,
    pub load_before: Option<String>,
    pub load_after: Option<String>,
}

/// The system's load averages and run queue now; `None` when unreadable.
pub fn load() -> Option<String> {
    std::fs::read_to_string("/proc/loadavg")
        .ok()
        .map(|text| text.trim().to_string())
}

/// The domain and version of one entry's record stream ([`tree_stream`]),
/// its first bytes, so no digest of another encoding can equal one of this.
const ENTRY_DOMAIN: &[u8] = b"dcbor-gate source entry v2\0";

/// The domain and version of a tree's stream of entry digests
/// ([`tree_digest_of`]).
const TREE_DOMAIN: &[u8] = b"dcbor-gate source tree v2\0";

/// One record of a source stream: its path's raw bytes relative to
/// the tree's root (never decoded), its kind, the kind's metadata and its
/// payload, every variable field preceded by its length as eight
/// little-endian bytes.
fn tree_record(stream: &mut Vec<u8>, path: &[u8], kind: u8, metadata: &[u8], payload: &[u8]) {
    for (index, bytes) in [path, metadata, payload].into_iter().enumerate() {
        if index == 1 {
            stream.push(kind);
        }
        stream.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
        stream.extend_from_slice(bytes);
    }
}

/// The digest of a tree's source state from each path's own digest
/// ([`SourceState::digests`]), in byte order of the paths: [`TREE_DOMAIN`],
/// then one record (`e`) per path carrying its digest. What a run retains
/// (`sources.json`) recomputes its identity's source state by, and what
/// [`SourceState::digest`] is.
pub fn tree_digest_of(digests: &BTreeMap<String, String>) -> Result<String, String> {
    let mut stream = TREE_DOMAIN.to_vec();
    for (path, digest) in digests {
        tree_record(&mut stream, path.as_bytes(), b'e', &[], digest.as_bytes());
    }
    crate::process::sha256_bytes(&stream)
}

/// The digest of one regular file's entry at `path` ([`SourceState::digests`]):
/// what a run's retained copy of a source file is held to against its
/// retained per-path digests.
pub(crate) fn file_entry_digest(
    path: &str,
    contents: &[u8],
    executable: bool,
) -> Result<String, String> {
    entry_digest(
        path.as_bytes(),
        &TreeEntry::File {
            executable,
            contents: contents.to_vec(),
        },
    )
}

/// The digest of the one entry `entry` at `path`: its record stream
/// ([`tree_stream`]) digested by the one digest authority.
fn entry_digest(path: &[u8], entry: &TreeEntry) -> Result<String, String> {
    let one = BTreeMap::from([(path.to_vec(), entry.clone())]);
    crate::process::sha256_bytes(&tree_stream(&one))
}

/// The record stream of the entries `entries`, each a path's raw bytes and
/// the entry found there, in byte order of the paths, prefixed by
/// [`ENTRY_DOMAIN`]: a regular file (`f`) with its executable bit and its
/// contents; a symbolic link (`l`) with its target's bytes, never followed;
/// a listed path absent from the tree (`d`), with nothing. Each path's own
/// digest is the digest of its one entry's stream ([`entry_digest`]).
fn tree_stream(entries: &BTreeMap<Vec<u8>, TreeEntry>) -> Vec<u8> {
    let mut stream = ENTRY_DOMAIN.to_vec();
    for (path, entry) in entries {
        match entry {
            TreeEntry::File {
                executable,
                contents,
            } => tree_record(&mut stream, path, b'f', &[u8::from(*executable)], contents),
            TreeEntry::Link(target) => tree_record(&mut stream, path, b'l', &[], target),
            TreeEntry::Deleted => tree_record(&mut stream, path, b'd', &[], &[]),
        }
    }
    stream
}

/// What a source path holds ([`tree_stream`]).
#[derive(Clone, Debug, PartialEq, Eq)]
enum TreeEntry {
    File { executable: bool, contents: Vec<u8> },
    Link(Vec<u8>),
    Deleted,
}

/// The source state of a tree: every entry beneath its root but directories,
/// by its path's raw bytes relative to the root, each read once without
/// following a link ([`SourceState::read`]). The tree is a stable copy of a
/// commit (`git archive` extracted, tests/gate-common.sh `copy_of`), whose
/// build output lives outside it, so every entry is source; the gate never
/// asks git what a tree holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceState(BTreeMap<Vec<u8>, TreeEntry>);

impl SourceState {
    /// The source state of the tree at `root`: a regular file with its
    /// executable bit and contents, a symbolic link with its target's bytes.
    /// Any other kind of entry, or one that cannot be read, refuses the
    /// state.
    pub fn read(root: &Path) -> Result<Self, String> {
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::PermissionsExt;
        let mut entries = BTreeMap::new();
        let mut pending = vec![std::path::PathBuf::new()];
        while let Some(relative) = pending.pop() {
            let directory = root.join(&relative);
            let found = std::fs::read_dir(&directory)
                .map_err(|error| format!("{}: {error}", directory.display()))?;
            for found in found {
                let found = found.map_err(|error| format!("{}: {error}", directory.display()))?;
                let path = relative.join(found.file_name());
                let file = root.join(&path);
                let metadata = std::fs::symlink_metadata(&file)
                    .map_err(|error| format!("{}: {error}", file.display()))?;
                let kind = metadata.file_type();
                let entry = if kind.is_dir() {
                    pending.push(path);
                    continue;
                } else if kind.is_symlink() {
                    TreeEntry::Link(
                        std::fs::read_link(&file)
                            .map_err(|error| format!("{}: {error}", file.display()))?
                            .as_os_str()
                            .as_bytes()
                            .to_vec(),
                    )
                } else if kind.is_file() {
                    TreeEntry::File {
                        executable: metadata.permissions().mode() & 0o111 != 0,
                        contents: std::fs::read(&file)
                            .map_err(|error| format!("{}: {error}", file.display()))?,
                    }
                } else {
                    return Err(format!(
                        "{}: neither a regular file nor a symbolic link: the tree has no source \
                         identity",
                        file.display()
                    ));
                };
                entries.insert(path.as_os_str().as_bytes().to_vec(), entry);
            }
        }
        Ok(Self(entries))
    }

    /// This state with each path of `listed` (another state's paths,
    /// [`Self::paths`]) it does not hold recorded as that path's deletion.
    pub fn with_deletions(mut self, listed: &BTreeSet<Vec<u8>>) -> Self {
        for path in listed {
            self.0.entry(path.clone()).or_insert(TreeEntry::Deleted);
        }
        self
    }

    /// The state written out as a tree at `at`, a directory this creates and
    /// that must not exist: every file with its bytes and its executable bit
    /// (mode 0755, else 0644, the only mode the state records), every link
    /// with its target, never followed, the directories between them made
    /// as needed. A state holding a deletion has no tree and is refused.
    pub fn materialize(&self, at: &Path) -> Result<(), String> {
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::PermissionsExt;
        std::fs::create_dir(at).map_err(|error| format!("{}: {error}", at.display()))?;
        for (path, entry) in &self.0 {
            let target = at.join(std::ffi::OsStr::from_bytes(path));
            if let Some(parent) = target.parent() {
                std::fs::create_dir_all(parent)
                    .map_err(|error| format!("{}: {error}", parent.display()))?;
            }
            match entry {
                TreeEntry::File {
                    executable,
                    contents,
                } => {
                    std::fs::write(&target, contents)
                        .and_then(|()| {
                            std::fs::set_permissions(
                                &target,
                                std::fs::Permissions::from_mode(if *executable {
                                    0o755
                                } else {
                                    0o644
                                }),
                            )
                        })
                        .map_err(|error| format!("{}: {error}", target.display()))?;
                }
                TreeEntry::Link(link) => {
                    std::os::unix::fs::symlink(std::ffi::OsStr::from_bytes(link), &target)
                        .map_err(|error| format!("{}: {error}", target.display()))?;
                }
                TreeEntry::Deleted => {
                    return Err(format!(
                        "{}: a deletion, which no tree holds",
                        target.display()
                    ));
                }
            }
        }
        Ok(())
    }

    /// The paths the state holds, its deletions left out.
    pub fn paths(&self) -> BTreeSet<Vec<u8>> {
        self.0
            .iter()
            .filter(|(_, entry)| **entry != TreeEntry::Deleted)
            .map(|(path, _)| path.clone())
            .collect()
    }

    /// The paths whose entry differs between this state and `other`, a path
    /// one holds and the other does not included.
    pub fn changed(&self, other: &Self) -> BTreeSet<Vec<u8>> {
        self.0
            .keys()
            .chain(other.0.keys())
            .filter(|path| self.0.get(*path) != other.0.get(*path))
            .cloned()
            .collect()
    }

    /// The state's digest: the digest of its paths' own digests
    /// ([`tree_digest_of`] of [`Self::digests`]), so a run that retains its
    /// per-path digests retains what its source state's digest is
    /// recomputed from. Timestamps and inode numbers are no part of it.
    pub fn digest(&self) -> Result<String, String> {
        tree_digest_of(&self.digests()?)
    }

    /// Every path's own digest, the record stream of that one entry, so its
    /// kind, mode, target and bytes, its deletion included, each change it:
    /// what a control side's source transition is checked path by path
    /// against ([`crate::controls::Authorization`]), and what a run's source
    /// state is the digest of. Refused for a path that is not UTF-8, which
    /// no registered diff can name and no retained record can hold.
    pub fn digests(&self) -> Result<BTreeMap<String, String>, String> {
        let mut digests = BTreeMap::new();
        for (path, entry) in &self.0 {
            let name = String::from_utf8(path.clone()).map_err(|_| {
                format!(
                    "{}: a source path that is not UTF-8",
                    String::from_utf8_lossy(path)
                )
            })?;
            digests.insert(name, entry_digest(path, entry)?);
        }
        Ok(digests)
    }
}

/// The digest of the source state of the tree at `root` ([`SourceState`]):
/// a tree changed while it is read yields the digest of no one state, so a
/// run's identity reads its tree before it launches and again after it ends
/// (`process::kani`), refusing a source that moved.
pub fn tree_digest(root: &Path) -> Result<String, String> {
    SourceState::read(root)?.digest()
}

/// The identity of a run of `purpose`, now ([`RunIdentity`]), of the source
/// state `tree_sha256` and the loop-bound policy `loop_policy_sha256` its
/// validated execution bound ([`crate::process::KaniRun`]).
pub fn run_identity(
    purpose: &RunPurpose,
    tree_sha256: &str,
    loop_policy_sha256: &str,
) -> Result<RunIdentity, String> {
    let id = std::fs::read_to_string("/proc/sys/kernel/random/uuid")
        .map_err(|error| format!("/proc/sys/kernel/random/uuid: {error}"))?
        .trim()
        .to_string();
    let started = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|error| format!("the clock is before the Unix epoch: {error}"))?;
    RunIdentityRecord {
        version: RUNTIME_VERSION,
        id,
        purpose: purpose.name().to_string(),
        revision: purpose.revision().to_string(),
        tree_sha256: tree_sha256.to_string(),
        build: arguments().join(" "),
        loop_policy_sha256: loop_policy_sha256.to_string(),
        started: Instant {
            seconds: started.as_secs(),
            nanoseconds: started.subsec_nanos(),
        },
    }
    .validate()
}

/// What a run's log was when its manifest was written.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "state", rename_all = "kebab-case", deny_unknown_fields)]
pub enum LogRecord {
    /// A regular file, its digest.
    Present { sha256: String },
    /// No log: the run ended before it was created.
    Missing,
    /// A log that could not be inspected or digested, and why.
    Unreadable { error: String },
}

/// A run's records by digest (`LOG.evidence/manifest.json`, the last record
/// a run writes, whatever its judgement): the run's identifier when its
/// identity was made, `null` when it was not; its log ([`LogRecord`]); every
/// file of its evidence by its path relative to the evidence directory, but
/// the instrumented binaries (`artifact.out`), which their `artifact.json`
/// names by digest; every record it could not digest or enumerate, with why;
/// and whether it is complete: every record enumerated and digested and the
/// log present. Only a complete manifest is evidence a prediction may cite
/// ([`adopt`], [`expectations`]); an incomplete one is a failed run's
/// description.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestDocument {
    pub version: u64,
    pub run: Option<String>,
    pub complete: bool,
    pub log: LogRecord,
    pub files: BTreeMap<String, String>,
    pub unreadable: BTreeMap<String, String>,
}

/// Every file under `directory`, relative to it, refusing a symbolic link
/// or anything but a regular file or directory, every instrumented binary
/// (`artifact.out`) left out.
fn record_files(directory: &Path) -> Result<Vec<String>, String> {
    fn walk(base: &Path, at: &Path, found: &mut Vec<String>) -> Result<(), String> {
        let entries =
            std::fs::read_dir(at).map_err(|error| format!("{}: {error}", at.display()))?;
        for entry in entries {
            let path = entry
                .map_err(|error| format!("{}: {error}", at.display()))?
                .path();
            let kind = std::fs::symlink_metadata(&path)
                .map_err(|error| format!("{}: {error}", path.display()))?
                .file_type();
            if kind.is_dir() {
                walk(base, &path, found)?;
            } else if kind.is_file() {
                if path.file_name().is_some_and(|name| name == "artifact.out") {
                    continue;
                }
                let relative = path
                    .strip_prefix(base)
                    .map_err(|_| format!("{}: outside {}", path.display(), base.display()))?;
                found.push(
                    relative
                        .to_str()
                        .ok_or_else(|| format!("{}: a path that is not UTF-8", path.display()))?
                        .to_string(),
                );
            } else {
                return Err(format!(
                    "{}: neither a regular file nor a directory",
                    path.display()
                ));
            }
        }
        Ok(())
    }
    let mut found = Vec::new();
    walk(directory, directory, &mut found)?;
    found.sort();
    Ok(found)
}

/// The manifest of the run whose evidence is `evidence` and whose log is
/// `log`, `None` when the run created none (a path another process holds is
/// never the run's log), of identifier `run` when one was made
/// ([`ManifestDocument`]): every evidence file but the manifest itself digested,
/// each that cannot be enumerated or digested recorded with why instead,
/// never omitted silently.
pub fn manifest_of(evidence: &Path, log: Option<&Path>, run: Option<&str>) -> ManifestDocument {
    let mut files = BTreeMap::new();
    let mut unreadable = BTreeMap::new();
    match record_files(evidence) {
        Ok(found) => {
            for relative in found {
                if relative == "manifest.json" {
                    continue;
                }
                match crate::process::sha256(&evidence.join(&relative)) {
                    Ok(digest) => {
                        files.insert(relative, digest);
                    }
                    Err(error) => {
                        unreadable.insert(relative, error);
                    }
                }
            }
        }
        Err(error) => {
            unreadable.insert(".".to_string(), error);
        }
    }
    let log = match log.map(|log| (log, std::fs::symlink_metadata(log))) {
        None => LogRecord::Missing,
        Some((log, metadata)) => match metadata {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => LogRecord::Missing,
            Err(error) => LogRecord::Unreadable {
                error: format!("{}: {error}", log.display()),
            },
            Ok(metadata) if metadata.file_type().is_file() => match crate::process::sha256(log) {
                Ok(sha256) => LogRecord::Present { sha256 },
                Err(error) => LogRecord::Unreadable { error },
            },
            Ok(_) => LogRecord::Unreadable {
                error: format!("{}: not a regular file", log.display()),
            },
        },
    };
    ManifestDocument {
        version: RUNTIME_VERSION,
        run: run.map(str::to_string),
        complete: unreadable.is_empty() && matches!(log, LogRecord::Present { .. }),
        log,
        files,
        unreadable,
    }
}

/// The manifest of the evidence directory `evidence` (`manifest.json`) and
/// the digest of its bytes, read once, both of the one version: required to
/// be of [`RUNTIME_VERSION`], to name run `run`, and to be complete with its
/// log present: only such a run is evidence a prediction or a control side
/// may cite.
pub fn read_manifest(evidence: &Path, run: Option<&str>) -> Result<ValidatedManifest, String> {
    let path = evidence.join("manifest.json");
    let bytes = std::fs::read(&path).map_err(|error| format!("{}: {error}", path.display()))?;
    let digest = crate::process::sha256_bytes(&bytes)?;
    let manifest: ManifestDocument = typed(
        strict_json(&bytes).map_err(|fault| format!("{}: {fault}", path.display()))?,
        "manifest.json",
    )?;
    let named = match (manifest.run.as_deref(), run) {
        (Some(found), Some(expected)) => found == expected,
        (Some(_), None) => true,
        (None, _) => false,
    };
    if manifest.version != RUNTIME_VERSION || !named {
        return Err(format!(
            "{}: a manifest of version {} for run {:?}, not of version {RUNTIME_VERSION} for run \
             {}",
            path.display(),
            manifest.version,
            manifest.run,
            run.unwrap_or("its identity names")
        ));
    }
    let run = manifest.run.as_deref().unwrap_or_default();
    if !manifest.complete || !matches!(manifest.log, LogRecord::Present { .. }) {
        return Err(format!(
            "{}: run {run}'s records are incomplete (log {:?}, unreadable {:?}): a failed run's \
             description, not timing evidence",
            path.display(),
            manifest.log,
            manifest.unreadable
        ));
    }
    let LogRecord::Present { sha256: log_sha256 } = manifest.log.clone() else {
        unreachable!("a complete manifest records its log present");
    };
    Ok(ValidatedManifest {
        run: run.to_string(),
        log_sha256,
        sha256: digest,
        document: manifest,
    })
}

/// A complete manifest ([`read_manifest`], its only maker): its run, its
/// log's digest, the digest of its own bytes, and the document read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedManifest {
    run: String,
    log_sha256: String,
    sha256: String,
    document: ManifestDocument,
}

impl ValidatedManifest {
    pub fn run(&self) -> &str {
        &self.run
    }

    pub fn log_sha256(&self) -> &str {
        &self.log_sha256
    }

    /// The digest of the manifest's own bytes.
    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    /// Every record it lists, by its path relative to the evidence, with its
    /// digest.
    pub fn files(&self) -> &BTreeMap<String, String> {
        &self.document.files
    }

    pub fn document(&self) -> &ManifestDocument {
        &self.document
    }

    /// The run's records read through this manifest, under `evidence`, its
    /// instrumented binaries `binaries` ([`Artifacts::Manifested`]).
    pub fn records<'a>(&'a self, evidence: &'a Path, binaries: Binaries) -> Artifacts<'a> {
        Artifacts::Manifested {
            evidence,
            files: &self.document.files,
            binaries,
        }
    }
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    version: u64,
    configuration: Configuration,
    environment: EnvironmentRecord,
    models: BTreeMap<String, Model>,
    harnesses: BTreeMap<String, Prediction>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Configuration {
    build: String,
    loop_policy_sha256: String,
    timing_boundary: String,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Model {
    rule: String,
    applicability: String,
    uncertainty: String,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Prediction {
    model: String,
    inputs: serde_json::Map<String, serde_json::Value>,
    calibration: Vec<Reference>,
    milliseconds: u64,
    transfer: String,
}

/// A calibration a prediction cites: an adopted run ([`CALIBRATION`]) by its
/// identifier and the digest of its manifest.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Reference {
    run: String,
    manifest_sha256: String,
}

/// One harness's prediction, as validated ([`expectations_of`]): the
/// predicted milliseconds; why its calibration applies (`transfer`); its
/// qualifying deadline, [`DEADLINE_MARGIN`] times the prediction; the runs it
/// was calibrated from, none of which may be the run it qualifies; and the
/// digest of the instrumented binary and the verifier every calibration ran,
/// which a qualifying execution must share for the prediction to apply.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Expectation {
    milliseconds: u64,
    transfer: String,
    deadline_milliseconds: u64,
    calibration_runs: BTreeSet<String>,
    artifact_sha256: String,
    verifier: serde_json::Value,
}

impl Expectation {
    pub fn milliseconds(&self) -> u64 {
        self.milliseconds
    }

    pub fn transfer(&self) -> &str {
        &self.transfer
    }

    pub fn deadline_milliseconds(&self) -> u64 {
        self.deadline_milliseconds
    }

    pub fn calibration_runs(&self) -> &BTreeSet<String> {
        &self.calibration_runs
    }

    pub fn artifact_sha256(&self) -> &str {
        &self.artifact_sha256
    }

    pub fn verifier(&self) -> &serde_json::Value {
        &self.verifier
    }
}

/// The census's validated predictions ([`expectations_of`], their only
/// maker): the bytes of their document and those bytes' digest, the
/// established environment they apply in, and each harness's prediction.
#[derive(Clone, Debug, PartialEq)]
pub struct Expectations {
    sha256: String,
    bytes: Vec<u8>,
    environment: EstablishedEnvironment,
    harnesses: BTreeMap<String, Expectation>,
}

impl Expectations {
    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn environment(&self) -> &EstablishedEnvironment {
        &self.environment
    }

    pub fn harness(&self, harness: &str) -> Option<&Expectation> {
        self.harnesses.get(harness)
    }

    pub fn harnesses(&self) -> &BTreeMap<String, Expectation> {
        &self.harnesses
    }
}

/// The expectations of the tree at `root` ([`expectations_of`]), its
/// document read once.
pub fn expectations(root: &Path, declared: &BTreeSet<String>) -> Result<Expectations, String> {
    let path = root.join(EXPECTATIONS);
    let bytes = std::fs::read(&path).map_err(|error| format!("{}: {error}", path.display()))?;
    expectations_of(root, &bytes, declared).map_err(|fault| format!("{}: {fault}", path.display()))
}

/// Whether `run` is a run identifier as a run's identity mints it: the
/// kernel's random UUID, 8-4-4-4-12 lowercase hexadecimal digits. Checked
/// before any path is built from it.
fn run_identifier(run: &str) -> Result<(), String> {
    let groups: Vec<&str> = run.split('-').collect();
    let shaped = groups.iter().map(|group| group.len()).eq([8, 4, 4, 4, 12])
        && groups.iter().all(|group| {
            group
                .bytes()
                .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
        });
    if shaped {
        Ok(())
    } else {
        Err(format!("{run:?} is not a run identifier"))
    }
}

/// `relative` under `root`, every component from the root down a directory
/// or file of its own and no symbolic link, the whole inside the root.
fn contained(root: &Path, relative: &Path) -> Result<std::path::PathBuf, String> {
    let base =
        std::fs::canonicalize(root).map_err(|error| format!("{}: {error}", root.display()))?;
    let mut at = base.clone();
    for component in relative.components() {
        let std::path::Component::Normal(part) = component else {
            return Err(format!(
                "{}: not a plain path beneath the tree",
                relative.display()
            ));
        };
        at.push(part);
        let kind = std::fs::symlink_metadata(&at)
            .map_err(|error| format!("{}: {error}", at.display()))?
            .file_type();
        if kind.is_symlink() {
            return Err(format!(
                "{}: a symbolic link, where an adopted run's path holds none",
                at.display()
            ));
        }
    }
    if !at.starts_with(&base) {
        return Err(format!("{}: outside {}", at.display(), base.display()));
    }
    Ok(at)
}

/// A duration rounded up to whole milliseconds; `None` past `u64`.
fn ceiling_milliseconds(duration: std::time::Duration) -> Option<u64> {
    u64::try_from(duration.as_nanos().div_ceil(1_000_000)).ok()
}

/// The predictions of `bytes` (digest `sha256`) of the tree at `root`,
/// exactly one per harness of `declared`. The document is exactly `version`
/// ([`RUNTIME_VERSION`]); `configuration`, the build's arguments as
/// [`arguments`] states them, the tree's loop-bound policy digest and
/// [`TIMING_BOUNDARY`]; `environment`, every fact known; `models`, each
/// [`RULE`] with its applicability and its uncertainty treatment; and
/// `harnesses`, each a model, its non-empty domain inputs, [`SAMPLES`]
/// calibration references, its predicted milliseconds and why its
/// calibration applies (`transfer`). No key appears twice at any depth and
/// none is unknown. Each reference is an adopted run whose raw records
/// establish a verified execution of that harness ([`calibration_sample`]);
/// a harness's samples are of distinct runs and share one artifact, and
/// every sample of the document shares one verifier, the document's build
/// and policy, and its environment. The prediction is recomputed from the
/// samples by [`RULE`] and must equal the stated milliseconds: no duration
/// is taken from the document.
pub fn expectations_of(
    root: &Path,
    bytes: &[u8],
    declared: &BTreeSet<String>,
) -> Result<Expectations, String> {
    let sha256 = crate::process::sha256_bytes(bytes)?;
    let document: Document = typed(strict_json(bytes)?, "not an expectation document")?;
    if document.version != RUNTIME_VERSION {
        return Err(format!(
            "version {}, the gate reads {RUNTIME_VERSION}",
            document.version
        ));
    }
    let build = arguments().join(" ");
    if document.configuration.build != build {
        return Err(format!(
            "its build is {:?}, the proof build is {build:?}",
            document.configuration.build
        ));
    }
    let policy = crate::process::sha256(&root.join(POLICY))?;
    if document.configuration.loop_policy_sha256 != policy {
        return Err(format!(
            "its loop-bound policy digest is {}, the tree's is {policy}",
            document.configuration.loop_policy_sha256
        ));
    }
    if document.configuration.timing_boundary != TIMING_BOUNDARY {
        return Err(format!(
            "its timing boundary is {:?}, the gate measures {TIMING_BOUNDARY:?}",
            document.configuration.timing_boundary
        ));
    }
    let environment = document.environment.establish()?;
    for (name, model) in &document.models {
        if model.rule != RULE {
            return Err(format!(
                "model {name}: rule {:?}, the one rule is {RULE}",
                model.rule
            ));
        }
        if model.applicability.trim().is_empty() || model.uncertainty.trim().is_empty() {
            return Err(format!(
                "model {name}: no applicability or no uncertainty treatment"
            ));
        }
    }
    let predicted: BTreeSet<String> = document.harnesses.keys().cloned().collect();
    let missing: Vec<&String> = declared.difference(&predicted).collect();
    if !missing.is_empty() {
        return Err(format!("harnesses with no prediction: {missing:?}"));
    }
    let extra: Vec<&String> = predicted.difference(declared).collect();
    if !extra.is_empty() {
        return Err(format!(
            "predictions of harnesses no #[kani::proof] of the source declares: {extra:?}"
        ));
    }
    let mut verifier: Option<serde_json::Value> = None;
    let mut sampled: BTreeMap<String, Vec<CalibrationSample>> = BTreeMap::new();
    for (harness, prediction) in &document.harnesses {
        let fault = |fault: String| format!("harness {harness}: {fault}");
        if !document.models.contains_key(&prediction.model) {
            return Err(fault(format!("no model {}", prediction.model)));
        }
        if prediction.inputs.is_empty() {
            return Err(fault("it states no domain input".to_string()));
        }
        if prediction.transfer.trim().is_empty() {
            return Err(fault("it gives no transfer justification".to_string()));
        }
        if prediction.calibration.len() != SAMPLES {
            return Err(fault(format!(
                "{} calibration references, {RULE} takes {SAMPLES}",
                prediction.calibration.len()
            )));
        }
        let mut samples: Vec<CalibrationSample> = Vec::with_capacity(SAMPLES);
        for reference in &prediction.calibration {
            run_identifier(&reference.run).map_err(fault)?;
            let directory =
                contained(root, &Path::new(CALIBRATION).join(&reference.run)).map_err(fault)?;
            let records = RunRecords::adopted(&directory).map_err(fault)?;
            let sample = eligible_sample(&records, &reference.run, declared).map_err(fault)?;
            if sample.manifest_sha256 != reference.manifest_sha256 {
                return Err(fault(format!(
                    "{}: its bytes have digest {}, the prediction cites {}",
                    directory.join("evidence/manifest.json").display(),
                    sample.manifest_sha256,
                    reference.manifest_sha256
                )));
            }
            // The document's envelope, then the harness's: each sample of
            // another run than every earlier one and of their envelope
            // ([`CalibrationSample::compatible`], the one comparison).
            let mismatch = if sample.harness != *harness {
                Some("a sample of another harness")
            } else if sample.build != document.configuration.build {
                Some("of another build")
            } else if sample.loop_policy_sha256 != document.configuration.loop_policy_sha256 {
                Some("under another loop-bound policy")
            } else if !sample.environment.equivalent(&environment) {
                Some("of another environment")
            } else {
                None
            };
            if let Some(mismatch) = mismatch {
                return Err(fault(format!("run {} is {mismatch}", sample.run)));
            }
            for earlier in &samples {
                earlier.compatible(&sample).map_err(fault)?;
            }
            match &verifier {
                Some(first) if *first != sample.verifier => {
                    return Err(fault(format!(
                        "run {} ran under {}, another sample under {first}",
                        sample.run, sample.verifier
                    )));
                }
                Some(_) => {}
                None => verifier = Some(sample.verifier.clone()),
            }
            samples.push(sample);
        }
        sampled.insert(harness.clone(), samples);
    }
    let fitted = fit(&sampled)?;
    let mut harnesses = BTreeMap::new();
    for (harness, prediction) in document.harnesses {
        let samples = sampled
            .remove(&harness)
            .expect("every harness's samples were read");
        let computed = fitted[&harness];
        if prediction.milliseconds != computed {
            return Err(format!(
                "harness {harness}: predicts {} ms, its calibration gives {computed} ms by {RULE}",
                prediction.milliseconds
            ));
        }
        let deadline_milliseconds = computed
            .checked_mul(DEADLINE_MARGIN)
            .ok_or_else(|| format!("harness {harness}: its deadline does not fit"))?;
        let first = &samples[0];
        harnesses.insert(
            harness,
            Expectation {
                milliseconds: computed,
                transfer: prediction.transfer,
                deadline_milliseconds,
                artifact_sha256: first.artifact_sha256.clone(),
                verifier: first.verifier.clone(),
                calibration_runs: samples.iter().map(|sample| sample.run.clone()).collect(),
            },
        );
    }
    Ok(Expectations {
        sha256,
        bytes: bytes.to_vec(),
        environment,
        harnesses,
    })
}

/// The one prediction arithmetic of [`RULE`], which the predictions' reader
/// checks a document by and a fitting writes one by: for each harness's
/// [`SAMPLES`] eligible samples with durations `t`, `max(t)` plus the larger
/// of its own spread `max(t) - min(t)` and the envelope's, the largest spread
/// of any harness given, in checked integer seconds and nanoseconds, rounded
/// up to whole milliseconds once, at the end. Refused when a harness has not
/// exactly [`SAMPLES`] samples or a prediction does not fit in `u64`.
pub fn fit(
    sampled: &BTreeMap<String, Vec<CalibrationSample>>,
) -> Result<BTreeMap<String, u64>, String> {
    let mut spreads = BTreeMap::new();
    for (harness, samples) in sampled {
        if samples.len() != SAMPLES {
            return Err(format!(
                "harness {harness}: {} samples, {RULE} takes {SAMPLES}",
                samples.len()
            ));
        }
        let durations = samples.iter().map(|sample| sample.elapsed);
        let longest = durations.clone().max().expect("SAMPLES is not zero");
        let shortest = durations.min().expect("SAMPLES is not zero");
        spreads.insert(harness.as_str(), (longest, longest - shortest));
    }
    let envelope = spreads
        .values()
        .map(|(_, spread)| *spread)
        .max()
        .unwrap_or_default();
    spreads
        .into_iter()
        .map(|(harness, (longest, own))| {
            longest
                .checked_add(own.max(envelope))
                .and_then(ceiling_milliseconds)
                .filter(|milliseconds| *milliseconds > 0)
                .map(|milliseconds| (harness.to_string(), milliseconds))
                .ok_or_else(|| format!("harness {harness}: its prediction does not fit"))
        })
        .collect()
}

/// A calibration's launcher termination reconciled with its report: Kani
/// exits 0 exactly when every harness it checked verified and 1 when some
/// did not; any other ending, a signal included, leaves the run's
/// observations unestablished, so none of them is a sample.
pub fn check_calibration_termination(termination: Termination, report: &str) -> Result<(), String> {
    let outcomes = checked(report)?;
    let all_verified = !outcomes.is_empty()
        && outcomes
            .iter()
            .all(|(_, outcome)| *outcome == Outcome::Pass);
    let expected = if all_verified { 0 } else { 1 };
    if termination != Termination::Exited(expected) {
        return Err(format!(
            "the calibration's Kani ended {termination:?}, where its harnesses' outcomes call for \
             exit {expected}: none of its observations is established"
        ));
    }
    Ok(())
}

/// A run held to its predictions, applicability first: the run must not be
/// one its predictions were calibrated from; its environment must be known
/// and the predictions'; and every completed harness must have run under its
/// calibration's verifier and, for a qualification in the calibrated tree
/// ([`Applicability::Calibrated`]), on its calibration's instrumented binary,
/// or its prediction does not apply. Then each completed harness's
/// recorded CBMC run must not exceed its prediction: equality passes, a
/// nanosecond more fails, though it met its deadline. A harness killed at its
/// deadline has no completed duration and is its own fault
/// ([`outcome::kani`]). A failed prediction shows that the harness is wrongly
/// sized for it, that the prediction is wrong, or that the code it checks
/// regressed; a prediction is never revised solely to turn a run green.
pub fn check_expectations(
    identity: &RunIdentity,
    launch: &Launch,
    reconciled: &Reconciled,
    expectations: &Expectations,
    applicability: Applicability<'_>,
) -> Result<(), String> {
    let established = launch
        .environment
        .establish()
        .map_err(|fault| format!("run {}: {fault}: no prediction applies", identity.id()))?;
    if !established.equivalent(&expectations.environment) {
        return Err(format!(
            "run {}: its environment {:?} is not the predictions' {:?}: no prediction applies",
            identity.id(),
            launch.environment,
            expectations.environment.record()
        ));
    }
    // A control side runs what its authorization binds and nothing else: the
    // frozen predictions, the source state the side was validated against,
    // and its one harness.
    if let Applicability::Control(authorization) = applicability {
        let record = authorization.record();
        if identity.revision() != record.expectations_sha256
            || expectations.sha256() != record.expectations_sha256
        {
            return Err(format!(
                "run {}: given the predictions {}, its {} authorization froze {}",
                identity.id(),
                identity.revision(),
                record.side.name(),
                record.expectations_sha256
            ));
        }
        if identity.tree_sha256() != record.source_sha256 {
            return Err(format!(
                "run {}: ran the source state {}, its {} authorization binds {}",
                identity.id(),
                identity.tree_sha256(),
                record.side.name(),
                record.source_sha256
            ));
        }
        if let Some(other) = reconciled
            .launched
            .keys()
            .find(|name| **name != record.harness)
        {
            return Err(format!(
                "harness {other}: launched, but the {} side authorizes {} alone",
                record.side.name(),
                record.harness
            ));
        }
    }
    for (name, elapsed) in &reconciled.completed {
        let expectation = expectations
            .harnesses
            .get(name)
            .ok_or_else(|| format!("harness {name}: checked, but has no prediction"))?;
        if expectation.calibration_runs.contains(identity.id()) {
            return Err(format!(
                "harness {name}: run {} is one its prediction was calibrated from",
                identity.id()
            ));
        }
        let launched = reconciled
            .launched
            .get(name)
            .ok_or_else(|| format!("harness {name}: completed, but recorded as never launched"))?;
        match applicability {
            Applicability::Calibrated => {
                if launched.artifact_sha256 != expectation.artifact_sha256 {
                    return Err(format!(
                        "harness {name}: ran on artifact {}, its prediction was calibrated on {}: \
                         the prediction does not apply",
                        launched.artifact_sha256, expectation.artifact_sha256
                    ));
                }
            }
            // A baseline's build of the copy is recorded beside the
            // calibration's (its authorization's transfer); a red side's is
            // the mutation's own; a restored green side's must be its verified
            // baseline's, the same source built at the same location.
            Applicability::Control(authorization) => {
                if let Some(baseline) = authorization.restored_baseline()
                    && launched.artifact_sha256 != baseline.artifact_sha256
                {
                    return Err(format!(
                        "harness {name}: the restored copy built artifact {}, its verified \
                         baseline (run {}) built {}: the same source at the same location built \
                         another binary; investigate the build, no exception applies",
                        launched.artifact_sha256, baseline.run, baseline.artifact_sha256
                    ));
                }
            }
        }
        if reconciled.verifier != expectation.verifier {
            return Err(format!(
                "harness {name}: ran under {}, its prediction was calibrated under {}: the \
                 prediction does not apply",
                reconciled.verifier, expectation.verifier
            ));
        }
        let expected = std::time::Duration::from_millis(expectation.milliseconds);
        if *elapsed > expected {
            return Err(format!(
                "harness {name}: its CBMC run took {elapsed:?}, more than its predicted {} ms \
                 ({}): the harness is wrongly sized for its prediction, the prediction is \
                 wrong, or the code it checks regressed",
                expectation.milliseconds, expectation.transfer
            ));
        }
    }
    Ok(())
}

/// How one recorded solver execution ended (`solver.execution.json`'s
/// `termination`, kani-driver `loop_bounds.rs` `SolverTermination`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ended {
    Exited,
    Signaled,
    Deadline,
    ExecutionError,
}

/// A recorded duration: an object of exactly integer `seconds` and
/// `nanoseconds` below one second.
fn duration(value: &serde_json::Value) -> Option<std::time::Duration> {
    let object = value.as_object()?;
    if object.len() != 2 {
        return None;
    }
    let seconds = object.get("seconds")?.as_u64()?;
    let nanoseconds = u32::try_from(object.get("nanoseconds")?.as_u64()?)
        .ok()
        .filter(|nanoseconds| *nanoseconds < 1_000_000_000)?;
    Some(std::time::Duration::new(seconds, nanoseconds))
}

/// A harness's solver execution record under `at` (`solver.execution.json`):
/// exactly its `deadline_milliseconds`, which must be `deadline`, the one the
/// run's policy gave the harness; its `elapsed` duration; and its
/// `termination`, one of the driver's kinds with exactly that kind's fields.
fn execution(
    at: &Path,
    deadline: u64,
    records: Artifacts<'_>,
) -> Result<(std::time::Duration, Ended), String> {
    let path = at.join("solver.execution.json");
    let text = records.read(&path)?;
    let record: serde_json::Value =
        strict_json(&text).map_err(|fault| format!("{}: {fault}", path.display()))?;
    let keys = |value: &serde_json::Value| -> Vec<String> {
        value
            .as_object()
            .map(|object| object.keys().cloned().collect())
            .unwrap_or_default()
    };
    let malformed = || {
        format!(
            "{}: not a solver execution record: {record}",
            path.display()
        )
    };
    if keys(&record) != ["deadline_milliseconds", "elapsed", "termination"] {
        return Err(malformed());
    }
    let elapsed = duration(&record["elapsed"]).ok_or_else(malformed)?;
    let recorded = record["deadline_milliseconds"]
        .as_u64()
        .ok_or_else(malformed)?;
    if recorded != deadline {
        return Err(format!(
            "{}: records the deadline {recorded} ms, the run's policy gave {deadline} ms",
            path.display()
        ));
    }
    let termination = &record["termination"];
    let text_or_null = |value: &serde_json::Value| value.is_string() || value.is_null();
    let ended = match (termination["kind"].as_str(), keys(termination).as_slice()) {
        (Some("exited"), [a, b]) if a == "code" && b == "kind" && termination["code"].is_i64() => {
            Ended::Exited
        }
        (Some("signaled"), [a, b])
            if a == "kind" && b == "signal" && termination["signal"].is_i64() =>
        {
            Ended::Signaled
        }
        (Some("deadline"), [a, b, c, d])
            if a == "cleanup_elapsed"
                && b == "cleanup_error"
                && c == "kind"
                && d == "last_status_message"
                && duration(&termination["cleanup_elapsed"]).is_some()
                && text_or_null(&termination["cleanup_error"])
                && text_or_null(&termination["last_status_message"]) =>
        {
            Ended::Deadline
        }
        (Some("execution_error"), [a, b, c])
            if a == "diagnostic"
                && b == "kind"
                && c == "operation"
                && termination["diagnostic"].is_string()
                && termination["operation"].is_string() =>
        {
            Ended::ExecutionError
        }
        _ => return Err(malformed()),
    };
    Ok((elapsed, ended))
}

/// The proof suite's loop-bound policy, relative to the root a run verifies:
/// the one maintained declaration of loop bounds, read from the tree being
/// verified (a control's copy included, so a planted change to a bound reaches
/// its run). Function-scoped bounds (`loops`) are properties of the code that
/// holds the loop and apply in every harness whose binary holds its function;
/// harness-scoped bounds (`harnesses`) rest on one harness's domain. Their
/// selectors, bounds and reasons are Kani's to validate and resolve against
/// each harness's instrumented binary (nix/kani-driver-loop-bounds.patch,
/// `kani-driver/src/loop_bounds.rs`); the gate reads which harnesses and
/// functions they bound, to select a run's policy and to reconcile its
/// evidence.
pub const POLICY: &str = "tests/data/proofs/loop-bounds.json";

/// A loop-bound policy as the gate reads it: the function-scoped selectors,
/// and each bounded harness with its entry as the file holds it.
#[derive(Clone, Debug, PartialEq)]
pub struct Policy {
    pub loops: Vec<serde_json::Value>,
    pub harnesses: BTreeMap<String, serde_json::Value>,
}

/// The policy of the tree at `root` ([`read_policy`]).
pub fn policy(root: &Path, declared: &BTreeSet<String>) -> Result<Policy, String> {
    read_policy(root, declared).map(|(_, policy)| policy)
}

/// The policy file of the tree at `root` read once: its bytes, whose digest
/// is a run's loop-bound policy identity and which a run retains, and the
/// policy those same bytes hold ([`policy_of`]).
pub fn read_policy(root: &Path, declared: &BTreeSet<String>) -> Result<(Vec<u8>, Policy), String> {
    let path = root.join(POLICY);
    let bytes = std::fs::read(&path).map_err(|error| format!("{}: {error}", path.display()))?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|error| format!("{}: not UTF-8: {error}", path.display()))?;
    let policy =
        policy_of(text, declared).map_err(|fault| format!("{}: {fault}", path.display()))?;
    Ok((bytes, policy))
}

/// The policy of the text `text`. Refused when it is not an object of
/// exactly `loops` and `harnesses`, both lists; when a function-scoped
/// selector names no function; when a harness entry names no harness or
/// declares no bound; when a harness is named twice; or when one is not a
/// `#[kani::proof]` of `declared`: a renamed or removed harness would
/// otherwise lose its bounds without notice.
pub fn policy_of(text: &str, declared: &BTreeSet<String>) -> Result<Policy, String> {
    let document = strict_json(text.as_bytes())?;
    let object = document
        .as_object()
        .filter(|object| object.len() == 2)
        .ok_or("not an object of two keys, `loops` and `harnesses`")?;
    let list = |key: &str| {
        object
            .get(key)
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| format!("its `{key}` is not a list"))
    };
    let loops = list("loops")?.clone();
    if let Some(selector) = loops
        .iter()
        .find(|selector| selector["function"].as_str().is_none())
    {
        return Err(format!(
            "a function-scoped selector names no function: {selector}"
        ));
    }
    let mut harnesses = BTreeMap::new();
    for entry in list("harnesses")? {
        let harness = entry["harness"]
            .as_str()
            .ok_or_else(|| format!("an entry names no harness: {entry}"))?;
        if bounds_of(entry) == 0 {
            return Err(format!("harness {harness}: no loop bound"));
        }
        if !declared.contains(harness) {
            return Err(format!(
                "harness {harness}: bounded, but declared by no #[kani::proof] of the source"
            ));
        }
        if harnesses
            .insert(harness.to_string(), entry.clone())
            .is_some()
        {
            return Err(format!("harness {harness}: named twice"));
        }
    }
    Ok(Policy { loops, harnesses })
}

/// How many loop bounds `entry` declares.
fn bounds_of(entry: &serde_json::Value) -> usize {
    entry["loops"].as_array().map_or(0, Vec::len)
}

/// The policy of a run that checks `selection`: every function-scoped
/// selector, the entries of the harnesses it checks, and each one's deadline
/// from `deadlines` ([`RunPurpose::deadlines`], built once for the run's
/// purpose). Kani's compiler keeps only the harnesses a run's filters select,
/// and Kani refuses a policy naming one it does not verify, so a run of some
/// harnesses carries their entries alone. Refused when a selected harness of
/// `declared` has no deadline: none runs unbounded or under another's.
pub fn selected(
    policy: &Policy,
    deadlines: &BTreeMap<String, Deadline>,
    selection: &Selection,
    declared: &BTreeSet<String>,
) -> Result<serde_json::Value, String> {
    let harnesses: Vec<&serde_json::Value> = policy
        .harnesses
        .iter()
        .filter(|(harness, _)| selection.contains(harness))
        .map(|(_, entry)| entry)
        .collect();
    let undated: Vec<&String> = declared
        .iter()
        .filter(|harness| selection.contains(harness) && !deadlines.contains_key(*harness))
        .collect();
    if !undated.is_empty() {
        return Err(format!(
            "selected harnesses the run's purpose gives no deadline: {undated:?}"
        ));
    }
    let deadlines: Vec<serde_json::Value> = deadlines
        .iter()
        .filter(|(harness, _)| selection.contains(harness))
        .map(|(harness, deadline)| {
            serde_json::json!({
                "harness": harness,
                "milliseconds": deadline.milliseconds,
                "reason": deadline.reason,
            })
        })
        .collect();
    Ok(serde_json::json!({ "loops": policy.loops, "harnesses": harnesses, "deadlines": deadlines }))
}

/// The functions a harness's discovered loop inventory (`discovery.stdout`,
/// `goto-instrument --show-loops --json-ui`, CBMC `show_loop_ids_json`
/// framed by `ui_message_handlert`) holds loops of. The document is a list
/// of records, each exactly one of: the program banner (`program`), a
/// message (`messageType`, `messageText`), or the inventory (`loops`, each
/// loop with its `name` and its `sourceLocation`'s `function`). Refused
/// when it holds any other record, a reported error, or not exactly one
/// inventory: an empty or substituted document would otherwise remove the
/// function-scoped bounds the harness owes.
fn inventory_functions(text: &[u8]) -> Result<BTreeSet<String>, String> {
    let document: serde_json::Value = serde_json::from_slice(text)
        .map_err(|error| format!("the loop inventory is not JSON: {error}"))?;
    let records = document
        .as_array()
        .ok_or("the loop inventory is not a list of records")?;
    let mut inventories = Vec::new();
    for record in records {
        let keys: BTreeSet<&str> = record
            .as_object()
            .ok_or_else(|| {
                format!("the loop inventory holds a record that is no object: {record}")
            })?
            .keys()
            .map(String::as_str)
            .collect();
        match keys.iter().copied().collect::<Vec<_>>().as_slice() {
            ["program"] => {}
            ["messageText", "messageType"] => {
                if record["messageType"] == "ERROR" {
                    return Err(format!(
                        "the loop discovery reported an error: {}",
                        record["messageText"]
                    ));
                }
            }
            ["loops"] => {
                inventories.push(record["loops"].as_array().ok_or_else(|| {
                    format!("the loop inventory's loops are not a list: {record}")
                })?)
            }
            _ => {
                return Err(format!(
                    "the loop inventory holds a record of no known kind: {record}"
                ));
            }
        }
    }
    let [loops] = inventories.as_slice() else {
        return Err(format!(
            "the loop discovery holds {} loop inventories, not one",
            inventories.len()
        ));
    };
    let mut functions = BTreeSet::new();
    for listed in loops.iter() {
        let function = listed["sourceLocation"]["function"]
            .as_str()
            .filter(|_| listed["name"].is_string())
            .ok_or_else(|| format!("a listed loop names no loop or no function: {listed}"))?;
        functions.insert(function.to_string());
    }
    Ok(functions)
}

/// The loop discovery of a harness, from its evidence under `at`: it
/// exited successfully (`discovery.status`, the driver's rendering of its
/// exit status), it ran as `goto-instrument --show-loops --json-ui` on
/// `artifact`, the harness's preserved binary (`discovery.arguments`,
/// [`command_record`]), its stderr was kept, and its stdout holds one valid
/// inventory ([`inventory_functions`]), whose functions are returned.
fn discovered(
    at: &Path,
    artifact: &str,
    records: Artifacts<'_>,
) -> Result<BTreeSet<String>, String> {
    let read = |file: &str| records.read(&at.join(file));
    let status = read("discovery.status")?;
    if status != b"exit status: 0\n" {
        return Err(format!(
            "the loop discovery did not exit successfully: {}",
            String::from_utf8_lossy(&status).trim_end()
        ));
    }
    let arguments = read("discovery.arguments")?;
    let command = command_record(&arguments)?;
    let expected: [&[u8]; 4] = [
        b"goto-instrument",
        b"--show-loops",
        b"--json-ui",
        artifact.as_bytes(),
    ];
    if command != expected {
        return Err(format!(
            "the loop discovery ran as {:?}, not goto-instrument --show-loops --json-ui on the \
             preserved {artifact}",
            command
                .iter()
                .map(|part| String::from_utf8_lossy(part))
                .collect::<Vec<_>>()
        ));
    }
    read("discovery.stderr")?;
    inventory_functions(&read("discovery.stdout")?)
}

/// Harness `name`'s instrumented binary as its evidence under `at` preserves
/// it, the driver's copy made before anything read it: its record
/// (`artifact.json`) names that copy (`artifact.out`) and an absolute build
/// path, and records a digest, which the copy's bytes have where the run's
/// binaries are held, and which an adopted run, whose binaries are absent,
/// records alone. The copy's recorded path and its digest.
fn preserved_artifact(
    name: &str,
    at: &Path,
    artifacts: Artifacts<'_>,
) -> Result<(String, String), String> {
    let preserved = at.join("artifact.out");
    let path = at.join("artifact.json");
    let record = strict_json(
        &artifacts
            .read(&path)
            .map_err(|fault| format!("harness {name}: {fault}"))?,
    )
    .map_err(|fault| format!("harness {name}: artifact.json: {fault}"))?;
    let recorded_path = record["path"]
        .as_str()
        .ok_or_else(|| format!("harness {name}: artifact.json names no path"))?;
    let names_the_copy = match artifacts.binaries() {
        Binaries::Held => {
            Path::new(recorded_path) == preserved
                || std::fs::canonicalize(recorded_path)
                    .ok()
                    .zip(std::fs::canonicalize(&preserved).ok())
                    .is_some_and(|(recorded, copy)| recorded == copy)
        }
        // The copy was the run's own, at its evidence path then; its
        // harness's directory and file name are what moved with it.
        Binaries::Absent => recorded_path.ends_with(&format!(
            "/loop-bounds/{}/artifact.out",
            name.replace("::", ".")
        )),
    };
    if !names_the_copy {
        return Err(format!(
            "harness {name}: artifact.json names {recorded_path}, not its preserved \
             artifact.out {}",
            preserved.display()
        ));
    }
    if !record["source"]
        .as_str()
        .is_some_and(|source| source.starts_with('/'))
    {
        return Err(format!(
            "harness {name}: artifact.json records no absolute build path"
        ));
    }
    let recorded_digest = record["sha256"]
        .as_str()
        .filter(|digest| sha256_text(digest))
        .ok_or_else(|| format!("harness {name}: artifact.json records no digest"))?;
    match artifacts.binaries() {
        Binaries::Held => {
            let actual = crate::process::sha256(&preserved)
                .map_err(|fault| format!("harness {name}: {fault}"))?;
            if actual != recorded_digest {
                return Err(format!(
                    "harness {name}: the preserved artifact's bytes have digest {actual}, \
                     artifact.json records {recorded_digest}"
                ));
            }
        }
        Binaries::Absent => match std::fs::symlink_metadata(&preserved) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(format!(
                    "harness {name}: {}: {error}: whether the adopted run holds its \
                     instrumented binary is unknown",
                    preserved.display()
                ));
            }
            Ok(_) => {
                return Err(format!(
                    "harness {name}: an adopted run holds its instrumented binary {}; \
                     adoption records it by digest alone",
                    preserved.display()
                ));
            }
        },
    }
    Ok((recorded_path.to_string(), recorded_digest.to_string()))
}

/// What a discovery run's evidence under `directory` (its
/// `--loop-bounds-evidence`) must hold, its own judgement: for every harness
/// `discovery` selects, a directory of the driver's, its preserved
/// instrumented binary ([`preserved_artifact`]) and a loop discovery of that
/// binary that exited successfully and holds one valid inventory
/// ([`discovered`], the one validator of a discovery, which every other run's
/// reconciliation applies too). A discovery's solver is stopped at its
/// deadline ([`DISCOVERY_MILLISECONDS`]), so its report, its termination, its
/// solver records and its function scope are no part of it. Each harness's
/// artifact digest, by harness.
pub fn check_discovery(
    directory: &Path,
    discovery: &Discovery,
    artifacts: Artifacts<'_>,
) -> Result<BTreeMap<String, String>, String> {
    let mut found = BTreeMap::new();
    for name in &discovery.selection {
        let at = harness_evidence(directory, name);
        let kind = match std::fs::symlink_metadata(&at) {
            Ok(metadata) => metadata.file_type(),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(format!(
                    "harness {name}: the run left no evidence of it ({})",
                    at.display()
                ));
            }
            Err(error) => return Err(format!("harness {name}: {}: {error}", at.display())),
        };
        if !kind.is_dir() {
            return Err(format!(
                "harness {name}: {} is not a directory of the driver's",
                at.display()
            ));
        }
        let (path, digest) = preserved_artifact(name, &at, artifacts)?;
        discovered(&at, &path, artifacts).map_err(|fault| format!("harness {name}: {fault}"))?;
        found.insert(name.clone(), digest);
    }
    Ok(found)
}

/// What a run's evidence reconciles to ([`check_execution_evidence`]): the
/// verifier its harnesses ran, `solver.identity`'s value (`null` when no
/// harness reached verification), and, for each function-scoped selector of
/// the run's policy in its order, the harnesses whose reconciled resolution
/// applied it; each harness whose CBMC run ended by itself, with its
/// recorded duration from immediately after spawn to its end
/// (`solver.execution.json`), what [`check_expectations`] compares; and every
/// launched harness's execution ([`Launched`]).
#[derive(Debug, PartialEq)]
pub struct Reconciled {
    pub verifier: serde_json::Value,
    pub applied: Vec<BTreeSet<String>>,
    pub completed: BTreeMap<String, std::time::Duration>,
    pub launched: BTreeMap<String, Launched>,
}

/// Where a run's instrumented binaries are when its records are read: held
/// beside each harness's records, as the run left them, each held to its
/// recorded digest; or absent, recorded by digest alone, as an adopted run
/// keeps them ([`adopt`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Binaries {
    Held,
    Absent,
}

/// How a run's records are read when its evidence is reconciled: live, as
/// the run that is writing them left them, before it has a manifest, its
/// binaries held; or through its complete manifest
/// ([`ValidatedManifest::records`]), every record read once and its bytes
/// held to the digest the manifest lists under `evidence` before they are
/// interpreted, so a record changed between two opens is never checked in
/// one version and read in another, its binaries held or absent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Artifacts<'a> {
    Live,
    Manifested {
        evidence: &'a Path,
        files: &'a BTreeMap<String, String>,
        binaries: Binaries,
    },
}

impl Artifacts<'_> {
    /// Where the run's instrumented binaries are.
    fn binaries(&self) -> Binaries {
        match self {
            Self::Live => Binaries::Held,
            Self::Manifested { binaries, .. } => *binaries,
        }
    }

    /// The bytes of the record at `path`, read once: a run's read through its
    /// manifest held to the manifest's digest, a record the manifest does not
    /// list refused.
    pub(crate) fn read(&self, path: &Path) -> Result<Vec<u8>, String> {
        let bytes = std::fs::read(path).map_err(|error| format!("{}: {error}", path.display()))?;
        if let Self::Manifested {
            evidence, files, ..
        } = self
        {
            let relative = self.relative(evidence, path)?;
            let listed = files.get(&relative).ok_or_else(|| {
                format!(
                    "{}: a record its run's manifest does not list",
                    path.display()
                )
            })?;
            let digest = crate::process::sha256_bytes(&bytes)?;
            if digest != *listed {
                return Err(format!(
                    "{}: its bytes have digest {digest}, the manifest records {listed}",
                    path.display()
                ));
            }
        }
        Ok(bytes)
    }

    /// Whether the record at `path` is one of the run's: on disk, for a live
    /// run, only `NotFound` counting as its absence and every other failure
    /// to inspect it refused; or listed by its manifest.
    fn holds(&self, path: &Path) -> Result<bool, String> {
        match self {
            Self::Live => match std::fs::symlink_metadata(path) {
                Ok(_) => Ok(true),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
                Err(error) => Err(format!("{}: {error}", path.display())),
            },
            Self::Manifested {
                evidence, files, ..
            } => Ok(files.contains_key(&self.relative(evidence, path)?)),
        }
    }

    fn relative(&self, evidence: &Path, path: &Path) -> Result<String, String> {
        path.strip_prefix(evidence)
            .ok()
            .and_then(Path::to_str)
            .map(str::to_string)
            .ok_or_else(|| format!("{}: not a record of {}", path.display(), evidence.display()))
    }
}

/// One launched harness's reconciled execution: its recorded duration, how
/// its solver ended, and the digest of the instrumented binary it ran on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Launched {
    pub elapsed: std::time::Duration,
    pub ended: Ended,
    pub artifact_sha256: String,
}

/// The evidence Kani writes for one harness of a run with a policy
/// (`--loop-bounds-evidence`, `kani-driver/src/loop_bounds.rs`
/// `HarnessEvidence`): the harness's directory, its pretty name with `::`
/// written `.`.
fn harness_evidence(directory: &Path, harness: &str) -> std::path::PathBuf {
    directory.join(harness.replace("::", "."))
}

/// A command record of Kani's evidence (`solver.arguments`,
/// `discovery.arguments`): the program, then each argument, each ended by a
/// NUL byte. Refused when it is empty or its last part is unterminated.
fn command_record(bytes: &[u8]) -> Result<Vec<&[u8]>, String> {
    let Some(parts) = bytes.strip_suffix(&[0]) else {
        return Err("a command record whose last part is not NUL-terminated".to_string());
    };
    Ok(parts.split(|byte| *byte == 0).collect())
}

/// Whether `text` is a SHA-256 digest as Kani records one: 64 lowercase
/// hexadecimal digits.
pub(crate) fn sha256_text(text: &str) -> bool {
    text.len() == 64
        && text
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

/// What one run's evidence must hold for its verdicts to be ones under its
/// policy: for every harness `report` shows verified, failed or refused by
/// CBMC (a `VERIFICATION:-` line), under `directory` (the run's
/// `--loop-bounds-evidence`): its launch attempt (`solver.attempt`,
/// `spawning\n`), the solver command it was spawned as (`solver.arguments`,
/// [`command_record`]), the executables that ran (`solver.identity`, the
/// driver's and the solver's path and SHA-256, the command's program the
/// solver), and the instrumented binary it ran on, preserved before
/// anything read it (`artifact.out`, recorded in `artifact.json` with its
/// absolute build path and digest): the record names that file, its bytes
/// have the recorded digest (`sha256sum`, [`crate::process::sha256`]), and
/// the solver command names it, and its loop discovery's invocation, status
/// and streams. For a harness `selected` (the run's policy, [`selected`])
/// bounds: its resolution (`resolution.json`) naming the harness, holding
/// exactly its selected entry as its policy, every selector of the entry
/// resolved once and to a distinct loop, and the preserved artifact as its
/// artifact; and the solver command carrying one `--unwindset`, the
/// resolved `LOOP:BOUND` pairs in their order. A harness with no bounds
/// carries no `--unwindset`. A harness whose report ends before
/// verification is left to its outcome ([`checked`]). Kani's resolution is
/// not repeated: only the correspondence between the policy given, the
/// resolution recorded and the command spawned is checked.
///
/// Every harness's loop discovery is validated ([`discovered`]) before the
/// function-scoped selectors it owes are derived from its inventory.
pub fn check_execution_evidence(
    directory: &Path,
    selected: &serde_json::Value,
    report: &str,
    artifacts: Artifacts<'_>,
) -> Result<Reconciled, String> {
    let entries: BTreeMap<&str, &serde_json::Value> = selected["harnesses"]
        .as_array()
        .ok_or("the run's policy holds no `harnesses` list")?
        .iter()
        .map(|entry| (entry["harness"].as_str().unwrap_or_default(), entry))
        .collect();
    let function_scope: &[serde_json::Value] = selected["loops"]
        .as_array()
        .map(Vec::as_slice)
        .ok_or("the run's policy holds no `loops` list")?;
    let deadlines: BTreeMap<&str, u64> = selected["deadlines"]
        .as_array()
        .ok_or("the run's policy holds no `deadlines` list")?
        .iter()
        .map(|deadline| {
            match (
                deadline["harness"].as_str(),
                deadline["milliseconds"].as_u64(),
            ) {
                (Some(harness), Some(milliseconds)) => Ok((harness, milliseconds)),
                _ => Err(format!(
                    "the run's policy holds a malformed deadline: {deadline}"
                )),
            }
        })
        .collect::<Result<_, String>>()?;
    let mut verifier: Option<serde_json::Value> = None;
    let mut applied = vec![BTreeSet::new(); function_scope.len()];
    let mut completed = BTreeMap::new();
    let mut executions = BTreeMap::new();
    for (name, block) in blocks(report)? {
        let at = harness_evidence(directory, &name);
        let deadline = *deadlines
            .get(name.as_str())
            .ok_or_else(|| format!("harness {name}: checked, but the run gave it no deadline"))?;
        let verified = block.iter().any(|line| line.starts_with("VERIFICATION:- "));
        // Whether the harness's solver was launched decides what evidence it
        // owes. One refused before launch (its policy's resolution) owes none
        // and may report no verification result; one launched owes all of it,
        // verdict or not, validated before its report is read.
        if !artifacts
            .holds(&at.join("solver.attempt"))
            .map_err(|fault| format!("harness {name}: {fault}"))?
        {
            if verified {
                return Err(format!(
                    "harness {name}: its report has a verification result, but its solver was \
                     never launched"
                ));
            }
            continue;
        }
        let (elapsed, ended) = execution(&at, deadline, artifacts)
            .map_err(|fault| format!("harness {name}: {fault}"))?;
        let read = |file: &str| {
            artifacts
                .read(&at.join(file))
                .map_err(|fault| format!("harness {name}: {fault}"))
        };
        let json = |file: &str| -> Result<serde_json::Value, String> {
            strict_json(&read(file)?).map_err(|fault| format!("harness {name}: {file}: {fault}"))
        };
        if read("solver.attempt")? != b"spawning\n" {
            return Err(format!(
                "harness {name}: solver.attempt is not a launch attempt"
            ));
        }
        let launched = read("solver.arguments")?;
        let command =
            command_record(&launched).map_err(|fault| format!("harness {name}: {fault}"))?;
        let identity = json("solver.identity")?;
        for executable in ["driver", "solver"] {
            let recorded = &identity[executable];
            if !recorded["path"]
                .as_str()
                .is_some_and(|path| path.starts_with('/'))
                || !recorded["sha256"].as_str().is_some_and(sha256_text)
            {
                return Err(format!(
                    "harness {name}: solver.identity records no absolute {executable} path and \
                     digest"
                ));
            }
        }
        if identity["solver"]["path"].as_str().map(str::as_bytes) != command.first().copied() {
            return Err(format!(
                "harness {name}: the solver spawned is not the solver solver.identity records"
            ));
        }
        match &verifier {
            Some(previous) if *previous != identity => {
                return Err(format!(
                    "harness {name}: ran under {identity}, another harness under {previous}"
                ));
            }
            Some(_) => {}
            None => verifier = Some(identity),
        }
        // The binary the harness ran on: the copy its evidence preserves
        // ([`preserved_artifact`]), and the solver's command naming it.
        let (recorded_path, recorded_digest) = preserved_artifact(&name, &at, artifacts)?;
        let recorded_path = recorded_path.as_str();
        let recorded_digest = recorded_digest.as_str();
        if !command.contains(&recorded_path.as_bytes()) {
            return Err(format!(
                "harness {name}: the solver ran on another binary than the preserved \
                 {recorded_path}"
            ));
        }
        let unwindsets: Vec<usize> = command
            .iter()
            .enumerate()
            .filter(|(_, part)| **part == b"--unwindset")
            .map(|(at, _)| at)
            .collect();
        // Every harness's loops were discovered on its preserved artifact,
        // bounded or not; the function-scoped selectors that apply to it are
        // those whose function its validated inventory holds.
        let functions = discovered(&at, recorded_path, artifacts)
            .map_err(|fault| format!("harness {name}: {fault}"))?;
        let scoped_indices: Vec<usize> = function_scope
            .iter()
            .enumerate()
            .filter(|(_, selector)| {
                selector["function"]
                    .as_str()
                    .is_some_and(|function| functions.contains(function))
            })
            .map(|(index, _)| index)
            .collect();
        let scoped: Vec<&serde_json::Value> = scoped_indices
            .iter()
            .map(|&index| &function_scope[index])
            .collect();
        let entry = entries.get(name.as_str()).copied();
        if entry.is_none() && scoped.is_empty() {
            if !unwindsets.is_empty() {
                return Err(format!(
                    "harness {name}: its policy bounds no loop, its solver ran with --unwindset"
                ));
            }
        } else {
            check_resolution(
                &name,
                &json("resolution.json")?,
                entry,
                &scoped,
                serde_json::json!({ "path": recorded_path, "sha256": recorded_digest }),
                &command,
                &unwindsets,
            )?;
            for index in scoped_indices {
                applied[index].insert(name.clone());
            }
        }
        // The execution's termination decides what the report may claim, and
        // only a normal exit is a completed run whose duration meets its
        // expectation.
        if termination_agrees(&name, &block, ended)? {
            completed.insert(name.clone(), elapsed);
        }
        executions.insert(
            name.clone(),
            Launched {
                elapsed,
                ended,
                artifact_sha256: recorded_digest.to_string(),
            },
        );
    }
    Ok(Reconciled {
        verifier: verifier.unwrap_or(serde_json::Value::Null),
        applied,
        completed,
        launched: executions,
    })
}

/// Whether harness `name`'s report `block` agrees with how its recorded
/// solver execution `ended`, and so whether the run completed. Only a normal
/// exit permits a verification result read from properties, whatever its
/// code; it carries neither the deadline's nor the signal's header, and is
/// the one completed run. A signal gives no verdict whatever CBMC printed: its
/// report carries the driver's signal header ([`outcome::KANI_SIGNAL`]), is
/// classified as no verdict ([`outcome::kani_without_verdict`]), and claims
/// neither a verification nor an attributable failed property, so it can
/// never qualify a proof or a control's detection. A deadline likewise, under
/// the deadline's header. A driver's execution error, and a launched harness
/// whose report reaches no verification result, are refused.
fn termination_agrees(name: &str, block: &[&str], ended: Ended) -> Result<bool, String> {
    let verified = block.iter().any(|line| line.starts_with("VERIFICATION:- "));
    let successful = block.contains(&"VERIFICATION:- SUCCESSFUL");
    let header = |marker: &str| {
        block
            .iter()
            .any(|line| line.trim_start().starts_with(marker))
    };
    let (killed, signaled) = (header(outcome::KANI_DEADLINE), header(outcome::KANI_SIGNAL));
    let no_verdict = || {
        !successful && !failed_properties(block) && outcome::kani_without_verdict(&block.join("\n"))
    };
    let (agrees, completed) = match ended {
        Ended::Exited => (verified && !killed && !signaled, true),
        Ended::Signaled => (verified && signaled && !killed && no_verdict(), false),
        Ended::Deadline => (verified && killed && !signaled && no_verdict(), false),
        Ended::ExecutionError => (false, false),
    };
    if !agrees {
        return Err(format!(
            "harness {name}: its solver execution ended {ended:?}, its report {}",
            if !verified {
                "reaches no verification result"
            } else if successful {
                "verified it"
            } else if failed_properties(block) {
                "reports failed properties"
            } else if killed {
                "reports its deadline"
            } else if signaled {
                "reports a signal"
            } else {
                "reports a result"
            }
        ));
    }
    Ok(completed)
}

/// Harness `name`'s resolution (`resolution.json`, `resolution`) against the
/// run's policy and its execution: it names the harness, holds exactly its
/// `entry` as its policy and its `scoped` selectors as its function scope,
/// names the preserved `artifact`, resolves each declared selector once and to
/// a distinct loop, and the solver's `command` carries the one `--unwindset`
/// (at `unwindsets`) of the resolved `LOOP:BOUND` pairs in their order.
fn check_resolution(
    name: &str,
    resolution: &serde_json::Value,
    entry: Option<&serde_json::Value>,
    scoped: &[&serde_json::Value],
    artifact: serde_json::Value,
    command: &[&[u8]],
    unwindsets: &[usize],
) -> Result<(), String> {
    if resolution["harness"] != *name {
        return Err(format!(
            "harness {name}: resolution.json names {}",
            resolution["harness"]
        ));
    }
    let harness_scope = entry.cloned().unwrap_or(serde_json::Value::Null);
    if resolution["policy"] != harness_scope {
        return Err(format!(
            "harness {name}: resolution.json resolved {}, the run's policy is {harness_scope}",
            resolution["policy"]
        ));
    }
    if resolution["function_scope"] != serde_json::json!(scoped) {
        return Err(format!(
            "harness {name}: resolution.json applied the function scope {}, its inventory \
                 holds the functions of {}",
            resolution["function_scope"],
            serde_json::json!(scoped)
        ));
    }
    if resolution["artifact"] != artifact {
        return Err(format!(
            "harness {name}: resolution.json resolved the artifact {}, the preserved \
                 artifact is {artifact}",
            resolution["artifact"]
        ));
    }
    let declared: Vec<&serde_json::Value> = entry
        .and_then(|entry| entry["loops"].as_array())
        .into_iter()
        .flatten()
        .chain(scoped.iter().copied())
        .collect();
    let resolved = resolution["resolved"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or_default();
    if resolved.len() != declared.len()
        || declared.iter().any(|selector| {
            resolved
                .iter()
                .filter(|found| found["selector"] == **selector)
                .count()
                != 1
        })
    {
        return Err(format!(
            "harness {name}: resolution.json does not resolve each of its {} selectors once",
            declared.len()
        ));
    }
    let mut pairs = Vec::new();
    let mut loops = BTreeSet::new();
    for found in resolved {
        let id = found["loop"]
            .as_str()
            .ok_or_else(|| format!("harness {name}: a resolved selector names no loop"))?;
        let bound = found["selector"]["bound"]
            .as_u64()
            .ok_or_else(|| format!("harness {name}: a resolved selector has no bound"))?;
        if !loops.insert(id) {
            return Err(format!("harness {name}: loop {id} resolved twice"));
        }
        resolved_in_its_file(name, id, found)?;
        pairs.push(format!("{id}:{bound}"));
    }
    let expected = pairs.join(",");
    match unwindsets {
        [at] if command.get(at + 1) == Some(&expected.as_bytes()) => {}
        _ => {
            return Err(format!(
                "harness {name}: its solver did not run with the one --unwindset {expected}"
            ));
        }
    }
    Ok(())
}

/// Whether harness `name`'s resolved loop `id` (`found`, one entry of its
/// resolution's `resolved`) lies in the file its selector names: the
/// recorded `file` is the loop's own location's, and it is the selector's
/// `file` exactly, or, for a selector naming its `package` (a dependency the
/// solver locates at its absolute path in the host's Cargo home), an absolute
/// path ending in `/` and the selector's file, the package's root, which only
/// the run's `cargo metadata` knows, before it.
fn resolved_in_its_file(name: &str, id: &str, found: &serde_json::Value) -> Result<(), String> {
    let selector = &found["selector"];
    let declared = selector["file"]
        .as_str()
        .ok_or_else(|| format!("harness {name}: loop {id}'s selector names no file"))?;
    let file = found["file"]
        .as_str()
        .ok_or_else(|| format!("harness {name}: loop {id} records no file"))?;
    if found["location"]["file"].as_str() != Some(file) {
        return Err(format!(
            "harness {name}: loop {id} is located in {}, its resolution records {file}",
            found["location"]["file"]
        ));
    }
    let placed = if selector.get("package").is_some() {
        file.starts_with('/') && file.ends_with(&format!("/{declared}"))
    } else {
        file == declared
    };
    if placed {
        Ok(())
    } else {
        Err(format!(
            "harness {name}: loop {id} resolved in {file}, its selector names {declared}{}",
            if selector.get("package").is_some() {
                format!(" of {}", selector["package"])
            } else {
                String::new()
            }
        ))
    }
}

/// Kani's record of the function scope (`function-scope.json` under
/// `directory`, the run's `--loop-bounds-evidence`), checked against the
/// run's reconciled evidence: one entry per function-scoped selector of
/// `selected` in its order, each exactly `selector` and `harnesses`, the
/// selector the run's and the harnesses exactly those whose reconciled
/// resolution applied it (`applied`, [`Reconciled::applied`]). A run of the
/// whole `suite` must apply each selector in at least one harness: one no
/// harness resolved bounds a function that was renamed, removed or is no
/// longer reached, and its bound would otherwise be lost without notice. A
/// run of one harness owes no coverage: a function-scoped loop need not be
/// in every harness.
pub fn check_function_scope(
    directory: &Path,
    selected: &serde_json::Value,
    applied: &[BTreeSet<String>],
    suite: bool,
    records: Artifacts<'_>,
) -> Result<(), String> {
    let path = directory.join("function-scope.json");
    let fault = |fault: String| format!("{}: {fault}", path.display());
    let text = records.read(&path)?;
    let record: Vec<serde_json::Value> = typed(
        strict_json(&text).map_err(fault)?,
        "a function-scope record",
    )
    .map_err(fault)?;
    let declared = selected["loops"]
        .as_array()
        .ok_or("the run's policy holds no `loops` list")?;
    if record.len() != declared.len() || applied.len() != declared.len() {
        return Err(fault(format!(
            "records {} function-scoped selectors, the run's policy has {} and its evidence \
             reconciles {}",
            record.len(),
            declared.len(),
            applied.len()
        )));
    }
    for ((entry, selector), reconciled) in record.iter().zip(declared).zip(applied) {
        let keys: Vec<&str> = entry
            .as_object()
            .map(|object| object.keys().map(String::as_str).collect())
            .unwrap_or_default();
        if keys != ["harnesses", "selector"] {
            return Err(fault(format!(
                "an entry is not exactly `selector` and `harnesses`: {entry}"
            )));
        }
        if entry["selector"] != *selector {
            return Err(fault(format!(
                "records the function-scoped selector {}, the run's is {selector}",
                entry["selector"]
            )));
        }
        let recorded: Option<BTreeSet<&str>> = entry["harnesses"].as_array().and_then(|names| {
            names
                .iter()
                .map(serde_json::Value::as_str)
                .collect::<Option<BTreeSet<&str>>>()
                .filter(|set| set.len() == names.len())
        });
        let expected: BTreeSet<&str> = reconciled.iter().map(String::as_str).collect();
        if recorded.as_ref() != Some(&expected) {
            return Err(fault(format!(
                "records {selector} applied in {}, the run's evidence reconciles it in \
                 {expected:?}",
                entry["harnesses"]
            )));
        }
        if suite && expected.is_empty() {
            return Err(fault(format!(
                "no harness of the suite applied the function-scoped selector {selector}"
            )));
        }
    }
    Ok(())
}

/// The Kani a run selected (`proofs-identity`): the absolute path the file
/// `launcher` holds, which must still name that canonical executable. Every
/// Kani run of the run launches it; none resolves `PATH` again.
pub fn selected_launcher(launcher: &Path) -> Result<std::path::PathBuf, String> {
    let text = std::fs::read_to_string(launcher)
        .map_err(|error| format!("{}: {error}", launcher.display()))?;
    let path = std::path::PathBuf::from(
        text.strip_suffix('\n')
            .ok_or_else(|| format!("{}: not one line", launcher.display()))?,
    );
    let canonical = std::fs::canonicalize(&path)
        .map_err(|error| format!("{}: {}: {error}", launcher.display(), path.display()))?;
    if !path.is_absolute() || canonical != path || !path.is_file() {
        return Err(format!(
            "{}: {} is not the canonical path of an executable",
            launcher.display(),
            path.display()
        ));
    }
    Ok(path)
}

/// Every `#[kani::proof]` function of the Rust sources under `src` (the
/// library's `src/`), by its path from the crate root: a file's module path
/// from its file path (`src/a/b.rs` and `src/a/b/mod.rs` are `a::b`,
/// `src/lib.rs` the root), then every inline module it nests the function
/// in. Parsed, never matched as text. And every generated instance
/// ([`instances::FAMILIES`], expanded by [`instances::instances`], the
/// expansion `build.rs` generates them by) in its family's module, the
/// family's file required to include them exactly once
/// ([`instances::inclusion`]); an instance whose name a written harness
/// also declares is refused.
pub fn harnesses(src: &Path) -> Result<BTreeSet<String>, String> {
    fn proof(attrs: &[syn::Attribute]) -> bool {
        attrs.iter().any(|attribute| {
            let segments: Vec<String> = attribute
                .path()
                .segments
                .iter()
                .map(|segment| segment.ident.to_string())
                .collect();
            segments == ["kani", "proof"]
        })
    }
    fn collect(items: &[syn::Item], module: &[String], found: &mut BTreeSet<String>) {
        for item in items {
            match item {
                syn::Item::Fn(function) if proof(&function.attrs) => {
                    let mut path = module.to_vec();
                    path.push(function.sig.ident.to_string());
                    found.insert(path.join("::"));
                }
                syn::Item::Mod(nested) => {
                    if let Some((_, inner)) = &nested.content {
                        let mut path = module.to_vec();
                        path.push(nested.ident.to_string());
                        collect(inner, &path, found);
                    }
                }
                _ => {}
            }
        }
    }
    fn walk(root: &Path, directory: &Path, found: &mut BTreeSet<String>) -> Result<(), String> {
        let entries = std::fs::read_dir(directory)
            .map_err(|error| format!("{}: {error}", directory.display()))?;
        let mut paths = Vec::new();
        for entry in entries {
            paths.push(
                entry
                    .map_err(|error| format!("{}: {error}", directory.display()))?
                    .path(),
            );
        }
        paths.sort();
        for path in paths {
            if path.is_dir() {
                walk(root, &path, found)?;
                continue;
            }
            if path.extension().and_then(|extension| extension.to_str()) != Some("rs") {
                continue;
            }
            let text = std::fs::read_to_string(&path)
                .map_err(|error| format!("{}: {error}", path.display()))?;
            if !text.contains("kani::proof") {
                continue;
            }
            let file = syn::parse_file(&text)
                .map_err(|error| format!("{}: does not parse: {error}", path.display()))?;
            let relative = path
                .strip_prefix(root)
                .map_err(|_| format!("{}: outside {}", path.display(), root.display()))?;
            let mut module: Vec<String> = relative
                .with_extension("")
                .components()
                .map(|component| component.as_os_str().to_string_lossy().into_owned())
                .collect();
            if matches!(
                module.last().map(String::as_str),
                Some("mod" | "lib" | "main")
            ) {
                module.pop();
            }
            collect(&file.items, &module, found);
        }
        Ok(())
    }
    let mut found = BTreeSet::new();
    walk(src, src, &mut found)?;
    let root = src
        .parent()
        .ok_or_else(|| format!("{}: has no package root", src.display()))?;
    for family in instances::FAMILIES {
        let path = root.join(family.file);
        let text = std::fs::read_to_string(&path)
            .map_err(|error| format!("{}: {error}", path.display()))?;
        let inclusion = instances::inclusion(family);
        if text.matches(inclusion.as_str()).count() != 1 {
            return Err(format!(
                "{}: does not include its generated instances exactly once ({inclusion})",
                path.display()
            ));
        }
        for instance in instances::instances(family)? {
            let name = format!("{}::{}", family.module, instance.name);
            if !found.insert(name.clone()) {
                return Err(format!(
                    "{name}: a generated instance whose name a written harness declares"
                ));
            }
        }
    }
    Ok(found)
}

/// Each harness a run's report checked, in order, with its outcome: the
/// block its `Checking harness` line opens classed by Kani's own report
/// ([`outcome::kani`]'s fundamental failures, then its verification line).
/// A failed verification requires a positive, consistent property summary;
/// a failure label alone supplies no verdict.
/// Refused when a block never reaches its verification line, or when the
/// final summary disagrees with the blocks.
pub fn checked(report: &str) -> Result<Vec<(String, Outcome)>, String> {
    let found = blocks(report)?;
    let mut results = Vec::new();
    for (name, block) in &found {
        let text = block.join("\n");
        let mut verification = block
            .iter()
            .filter_map(|line| line.strip_prefix("VERIFICATION:- "));
        let reported = match (verification.next(), verification.next()) {
            (Some("SUCCESSFUL"), None) => Outcome::Pass,
            (Some("FAILED"), None) => {
                if failed_properties(block) {
                    Outcome::Failed
                } else {
                    Outcome::NoVerdict
                }
            }
            (None, _) => {
                return Err(format!(
                    "harness {name}: its block reports no verification result"
                ));
            }
            _ => {
                return Err(format!(
                    "harness {name}: its block reports ambiguous or invalid verification results"
                ));
            }
        };
        let result = if outcome::kani_without_verdict(&text) {
            Outcome::NoVerdict
        } else if text.contains(outcome::KANI_UNSUPPORTED) {
            Outcome::Unsupported
        } else if text.contains(outcome::KANI_UNWINDING) {
            Outcome::BoundRefused
        } else {
            reported
        };
        results.push((name.clone(), result));
    }
    let Some((verified, failed, total)) = outcome::kani_summary(report) else {
        return Err("the report has no unique, well-formed final summary".to_string());
    };
    let passes = results
        .iter()
        .filter(|(_, result)| *result == Outcome::Pass)
        .count();
    if total != results.len() || verified != passes || failed != results.len() - passes {
        return Err(format!(
            "the summary counts {verified} verified, {failed} failed, {total} total; the report \
             checked {} harnesses, {passes} verified",
            results.len()
        ));
    }
    Ok(results)
}

/// Each harness's block of a run's report: its `Checking harness NAME...`
/// line opens it, and every line up to the next such line is its own.
/// Refused when a name is empty or repeated. The one division of a report
/// into harnesses, read by [`checked`] and [`check_execution_evidence`].
fn blocks(report: &str) -> Result<Vec<(String, Vec<&str>)>, String> {
    let mut found: Vec<(String, Vec<&str>)> = Vec::new();
    let mut names = BTreeSet::new();
    for line in report.lines() {
        if let Some(name) = line
            .strip_prefix("Checking harness ")
            .and_then(|rest| rest.strip_suffix("..."))
        {
            if name.is_empty() || !names.insert(name) {
                return Err(format!("harness {name:?}: empty or repeated harness name"));
            }
            found.push((name.to_string(), Vec::new()));
        } else if let Some((_, block)) = found.last_mut() {
            block.push(line);
        }
    }
    Ok(found)
}

/// Positive failure evidence from Kani's property summary, which its
/// renderer emits in both regular and terse output before the verification
/// result. A harness-level failure count is not a property verdict.
fn failed_properties(block: &[&str]) -> bool {
    let mut summaries = block
        .iter()
        .take_while(|line| !line.starts_with("VERIFICATION:- "))
        .filter_map(|line| line.trim().strip_prefix("** "))
        .filter(|line| line.contains(" failed"));
    let Some(summary) = summaries.next() else {
        return false;
    };
    if summaries.next().is_some() {
        return false;
    }
    let Some((counts, suffix)) = summary.split_once(" failed") else {
        return false;
    };
    let unreachable = if suffix.is_empty() {
        0
    } else {
        let Some(statuses) = suffix
            .strip_prefix(" (")
            .and_then(|rest| rest.strip_suffix(')'))
        else {
            return false;
        };
        // Undetermined checks cannot establish a complete failure verdict.
        // The renderer can also report unreachable checks, which are valid.
        let Some(unreachable) = statuses.strip_suffix(" unreachable") else {
            return false;
        };
        let Ok(unreachable) = unreachable.parse::<usize>() else {
            return false;
        };
        unreachable
    };
    let Some((failed, total)) = counts.split_once(" of ") else {
        return false;
    };
    matches!(
        (failed.parse::<usize>(), total.parse::<usize>()),
        (Ok(failed), Ok(total))
            if failed > 0 && failed <= total && unreachable <= total - failed
    )
}

/// The proof suite's rows from a run's `report` that ended in
/// `termination`, against the harnesses of the library's source (`src`):
/// one row per source harness, planned to verify, its outcome the run's,
/// never run when the run did not check it; and every fault: a harness
/// checked that the source does not declare, a report that does not read,
/// an exit status that disagrees with the outcomes. The run's execution
/// evidence is reconciled before its report is read
/// ([`check_execution_evidence`], `process::kani`).
pub fn rows(
    termination: Termination,
    report: &str,
    declared: &BTreeSet<String>,
) -> (Vec<Row>, Vec<String>) {
    let mut faults = Vec::new();
    let results = match checked(report) {
        Ok(results) => results,
        Err(fault) => {
            faults.push(fault);
            Vec::new()
        }
    };
    for (name, _) in &results {
        if !declared.contains(name) {
            faults.push(format!(
                "harness {name}: checked, but declared by no #[kani::proof] of the source"
            ));
        }
    }
    let all_verified =
        !results.is_empty() && results.iter().all(|(_, result)| *result == Outcome::Pass);
    let expected_exit = if all_verified { 0 } else { 1 };
    if termination != Termination::Exited(expected_exit) {
        faults.push(format!(
            "Kani ended {termination:?}, where its harnesses' outcomes call for exit {expected_exit}"
        ));
    }
    let rows = declared
        .iter()
        .map(|name| {
            let outcome = results
                .iter()
                .find(|(checked, _)| checked == name)
                .map_or(Outcome::NotRun, |(_, result)| *result);
            Row {
                domain: RUNNER.to_string(),
                line: NAME.to_string(),
                runner: RUNNER.to_string(),
                test: name.clone(),
                seed: None,
                purpose: Purpose::Normal,
                bound: None,
                stack: None,
                expected: Some(Outcome::Pass),
                outcome,
                seconds: None,
                peak_kb: None,
                physical: Physical::NotApplicable,
                evidence: Evidence::Unverified,
            }
            .classified()
        })
        .collect();
    (rows, faults)
}

/// One run of every harness of the library under `root` ([`arguments`]),
/// under the policy of `root` ([`policy`]), its artifacts in `target_dir`,
/// its report logged to `log`, read into the suite's rows against the
/// source's harnesses and the policy ([`rows`]).
pub fn run(
    root: &Path,
    target_dir: &Path,
    log: &Path,
    launcher: &Path,
) -> Result<(Vec<Row>, Vec<String>), String> {
    let declared = harnesses(&root.join("src"))?;
    let purpose = RunPurpose::Qualification(expectations(root, &declared)?);
    let workload = crate::process::Workload::exported()?;
    let run = crate::process::KaniRequest {
        root,
        purpose: &purpose,
        selection: &Selection::All,
        declared: &declared,
        target_dir,
        launcher,
        workload: &workload,
        log,
    }
    .validate()?;
    let (termination, report) = crate::process::execute_kani(run)?;
    Ok(rows(termination, &report, &declared))
}

/// One discovery run of `selection`, harnesses of the library under `root`
/// ([`discovery_of`]), through the one Kani invocation under the tree's
/// policy, its artifacts in `target_dir`, its report logged to `log`, judged
/// by its discovery records alone ([`check_discovery`]). The directory the
/// driver wrote each harness's records into (`LOG.evidence/loop-bounds`).
pub fn discover(
    root: &Path,
    target_dir: &Path,
    log: &Path,
    launcher: &Path,
    selection: &[String],
) -> Result<std::path::PathBuf, String> {
    let declared = harnesses(&root.join("src"))?;
    let discovery = discovery_of(selection, &declared)?;
    let only = Selection::Only(discovery.selection.clone());
    let purpose = RunPurpose::Discovery(discovery);
    let workload = crate::process::Workload::exported()?;
    let run = crate::process::KaniRequest {
        root,
        purpose: &purpose,
        selection: &only,
        declared: &declared,
        target_dir,
        launcher,
        workload: &workload,
        log,
    }
    .validate()?;
    let bounds = run.evidence().join("loop-bounds");
    crate::process::execute_kani(run)?;
    Ok(bounds)
}

/// Select the Kani a run launches: [`crate::process::kani_launcher`]'s one
/// resolution of `cargo-kani`, written to the new file `launcher` that every
/// Kani run of the run is given ([`selected_launcher`]); then its identity
/// as receipts record it: that path, and the version that executable
/// reports. The path is a Nix store path, input-addressed: it changes when
/// an input of the bundle's build changes, its driver and CBMC patches among
/// them. The driver and solver each harness ran are recorded by the run
/// itself (`solver.identity`, [`check_execution_evidence`]).
pub fn identity(launcher_file: &Path) -> Result<Vec<(String, String)>, String> {
    use std::io::Write;
    let launcher = crate::process::kani_launcher()?;
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(launcher_file)
        .and_then(|mut file| file.write_all(format!("{}\n", launcher.display()).as_bytes()))
        .map_err(|error| format!("{}: {error}", launcher_file.display()))?;
    let output = std::process::Command::new(&launcher)
        .args(["kani", "--version"])
        .output()
        .map_err(|error| format!("{}: {error}", launcher.display()))?;
    if !output.status.success() {
        return Err(format!(
            "{} kani --version: {}\n{}",
            launcher.display(),
            output.status,
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let version = String::from_utf8_lossy(&output.stdout);
    let mut lines = vec![("kani-launcher".to_string(), launcher.display().to_string())];
    lines.extend(
        version
            .lines()
            .filter(|line| !line.is_empty())
            .map(|line| ("kani-version".to_string(), line.to_string())),
    );
    Ok(lines)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// The invocation builds exactly the census's build: the library, its
    /// features those the census resolves, and no test target.
    #[test]
    fn the_invocation_is_the_census_build() {
        let arguments = arguments();
        assert_eq!(
            arguments,
            [
                "kani",
                "--package",
                "dcbor",
                "--lib",
                "--no-default-features",
                "--features",
                "std",
                "-Z",
                "stubbing",
                "-Z",
                "unstable-options"
            ]
        );
        assert!(!arguments.contains(&"--tests"));
        assert!(!arguments.contains(&"--harness-timeout"));
        assert!(NAMES.contains(&"kani") && !NAMES.contains(&"test"));
    }

    fn block(name: &str, result: &str) -> String {
        let failed = usize::from(result == "FAILED");
        format!(
            "Checking harness {name}...\nRESULTS:\nSUMMARY:\n ** {failed} of 3 failed\n\nVERIFICATION:- {result}\n"
        )
    }

    #[test]
    fn failure_requires_a_completed_positive_property_summary() {
        for properties in [
            "",
            " ** 0 of 3 failed\n",
            " ** 4 of 3 failed\n",
            " ** 1 of 3 failed\n ** 1 of 3 failed\n",
            " ** 1 of 3 failed (1 undetermined)\n",
            " ** 1 of 3 failed trailing text\n",
            " ** 1 of 3 failed (3 unreachable)\n",
            " ** invalid of 3 failed\n",
            " - Status: FAILURE\n",
        ] {
            let report = format!(
                "Checking harness x...\n{properties}VERIFICATION:- FAILED\n{}",
                summary(0, 1)
            );
            assert_eq!(
                checked(&report).unwrap(),
                [("x".to_string(), Outcome::NoVerdict)],
                "{report}"
            );
        }
        let late = format!(
            "Checking harness x...\nVERIFICATION:- FAILED\n ** 1 of 3 failed\n{}",
            summary(0, 1)
        );
        assert_eq!(
            checked(&late).unwrap(),
            [("x".to_string(), Outcome::NoVerdict)],
            "property evidence after the verdict is not its summary"
        );
        for properties in [" ** 1 of 3 failed\n", " ** 1 of 3 failed (1 unreachable)\n"] {
            let report = format!(
                "Checking harness x...\n{properties}VERIFICATION:- FAILED\n{}",
                summary(0, 1)
            );
            assert_eq!(
                checked(&report).unwrap(),
                [("x".to_string(), Outcome::Failed)],
                "{report}"
            );
        }
    }

    fn summary(verified: usize, failed: usize) -> String {
        format!(
            "Manual Harness Summary:\nComplete - {verified} successfully verified harnesses, \
             {failed} failures, {} total.\n",
            verified + failed
        )
    }

    /// The refusal `result` must be, named `case`: a planted defect that lets
    /// the case be accepted fails here by the case's name, so a control's red
    /// names the case it broke.
    fn refused<T: std::fmt::Debug>(case: &str, result: Result<T, String>) -> String {
        match result {
            Err(found) => found,
            Ok(accepted) => panic!("{case}: accepted: {accepted:?}"),
        }
    }

    fn declared(names: &[&str]) -> BTreeSet<String> {
        names.iter().map(ToString::to_string).collect()
    }

    const POLICY_TEXT: &str = r#"{"loops": [], "harnesses": [
        {"harness": "a::x", "loops": [
            {"function": "f", "file": "a.rs", "loops_in_function": 1, "loop": 0, "bound": 0,
             "reason": "r"}
        ]}
    ]}"#;

    /// The deadlines the fixture's harnesses are given, as their execution
    /// records state them.
    fn deadlines() -> BTreeMap<String, Deadline> {
        BTreeMap::from([
            (
                "a::x".to_string(),
                Deadline {
                    milliseconds: 2000,
                    reason: "twice x".to_string(),
                },
            ),
            (
                "a::y".to_string(),
                Deadline {
                    milliseconds: 4000,
                    reason: "twice y".to_string(),
                },
            ),
        ])
    }

    /// The policy of a run of the fixture under [`deadlines`].
    fn run_policy(read: &Policy, selection: &Selection) -> serde_json::Value {
        selected(read, &deadlines(), selection, &declared(&["a::x", "a::y"])).unwrap()
    }

    /// The evidence under `root` reconciled with `policy` and `report`, its
    /// instrumented binaries preserved beside it, as a run leaves them.
    fn reconcile(
        root: &Path,
        policy: &serde_json::Value,
        report: &str,
    ) -> Result<Reconciled, String> {
        check_execution_evidence(root, policy, report, Artifacts::Live)
    }

    /// The verifier the fixture's evidence records ([`RunEvidence::new`]).
    fn fixture_verifier() -> serde_json::Value {
        serde_json::json!({
            "driver": {"path": "/kani/kani-driver", "sha256": DIGEST},
            "solver": {"path": "/kani/cbmc", "sha256": DIGEST},
        })
    }

    /// An environment every fact of which is established: a scope whose
    /// limits are values, under the root, whose limits are verified absent.
    fn fixture_environment() -> EnvironmentRecord {
        let value = |value: &str| LimitObservation::Value {
            value: value.to_string(),
        };
        EnvironmentRecord {
            cpu_model: Some("cpu".to_string()),
            cpus_allowed: Some("0-15".to_string()),
            cpuset_effective: Some("0-15".to_string()),
            levels: vec![
                Level {
                    path: "/user.slice/run.scope".to_string(),
                    cpu_max: value("max 100000"),
                    memory_max: value("8589934592"),
                },
                Level {
                    path: "/user.slice".to_string(),
                    cpu_max: value("max 100000"),
                    memory_max: value("max"),
                },
                Level {
                    path: "/".to_string(),
                    cpu_max: LimitObservation::Absent {
                        reason: "cgroup v2 keeps no cpu.max in the root group".to_string(),
                    },
                    memory_max: LimitObservation::Absent {
                        reason: "cgroup v2 keeps no memory.max in the root group".to_string(),
                    },
                },
            ],
        }
    }

    /// The per-path digests of the fixture tree at `root` as a run retains
    /// them (`sources.json`): its loop-bound policy file alone.
    fn fixture_sources(root: &Path) -> BTreeMap<String, String> {
        let policy = std::fs::read(root.join(POLICY)).unwrap();
        BTreeMap::from([(
            POLICY.to_string(),
            file_entry_digest(POLICY, &policy, false).unwrap(),
        )])
    }

    /// A run's identity record of `purpose` and identifier `id`, of the
    /// document of digest `revision`, of the tree at `root`'s source state
    /// ([`fixture_sources`]) and policy.
    fn fixture_identity(root: &Path, id: &str, purpose: &str, revision: &str) -> RunIdentityRecord {
        RunIdentityRecord {
            version: RUNTIME_VERSION,
            id: id.to_string(),
            purpose: purpose.to_string(),
            revision: revision.to_string(),
            tree_sha256: tree_digest_of(&fixture_sources(root)).unwrap(),
            build: arguments().join(" "),
            loop_policy_sha256: crate::process::sha256(&root.join(POLICY)).unwrap(),
            started: Instant {
                seconds: 1,
                nanoseconds: 0,
            },
        }
    }

    /// The identifier of the qualifying run the post-validation fixtures use.
    const QUALIFYING: &str = "00000000-0000-0000-0000-000000000009";

    /// The identifier of the calibration run the post-validation fixtures'
    /// predictions cite.
    const CALIBRATING: &str = "00000000-0000-0000-0000-000000000001";

    /// Predictions of the fixture's harnesses in hand, `x` milliseconds for
    /// `a::x` and twice it for `a::y`, each calibrated on its fixture
    /// artifact under the fixture verifier in run [`CALIBRATING`]: a
    /// post-validation fixture of the owning module, for the checks that
    /// consume validated predictions ([`check_expectations`]); the reader
    /// itself is held by its own tests to valid evidence.
    fn predicted(x: u64) -> Expectations {
        let entry = |milliseconds: u64, artifact: &str| Expectation {
            milliseconds,
            transfer: "t".to_string(),
            deadline_milliseconds: milliseconds * DEADLINE_MARGIN,
            calibration_runs: BTreeSet::from([CALIBRATING.to_string()]),
            artifact_sha256: artifact.to_string(),
            verifier: fixture_verifier(),
        };
        Expectations {
            sha256: DIGEST.to_string(),
            bytes: Vec::new(),
            environment: fixture_environment().establish().unwrap(),
            harnesses: BTreeMap::from([
                ("a::x".to_string(), entry(x, ARTIFACTS[0].2)),
                ("a::y".to_string(), entry(2 * x, ARTIFACTS[1].2)),
            ]),
        }
    }

    /// A qualifying run's identity and launch in the fixture environment.
    fn qualifying(root: &Path) -> (RunIdentity, Launch) {
        (
            fixture_identity(root, QUALIFYING, "qualification", DIGEST)
                .validate()
                .unwrap(),
            Launch {
                environment: fixture_environment(),
                workload_cgroup: Some("/user.slice/run-9.scope".to_string()),
                load_before: None,
                load_after: None,
            },
        )
    }

    /// A tree holding the fixture's loop-bound policy, for identities and
    /// predictions to be checked against.
    fn policy_tree(test: &str) -> std::path::PathBuf {
        let root = std::env::temp_dir().join(format!("dcbor-gate-{test}-{}", std::process::id()));
        if root.exists() {
            std::fs::remove_dir_all(&root).unwrap();
        }
        std::fs::create_dir_all(root.join(POLICY).parent().unwrap()).unwrap();
        std::fs::write(root.join(POLICY), POLICY_TEXT).unwrap();
        root
    }

    /// A recorded duration equal to its prediction passes and one nanosecond
    /// more fails, though the run met its deadline; a harness the run did not
    /// complete is not compared.
    #[test]
    fn a_harness_over_its_expectation_fails_at_one_nanosecond() {
        let root = policy_tree("one-nanosecond");
        let (identity, launch) = qualifying(&root);
        let reconciled = |elapsed: std::time::Duration| Reconciled {
            verifier: fixture_verifier(),
            applied: Vec::new(),
            completed: BTreeMap::from([("a::x".to_string(), elapsed)]),
            launched: BTreeMap::from([(
                "a::x".to_string(),
                Launched {
                    elapsed,
                    ended: Ended::Exited,
                    artifact_sha256: ARTIFACTS[0].2.to_string(),
                },
            )]),
        };
        let expected_x = std::time::Duration::from_millis(1000);
        check_expectations(
            &identity,
            &launch,
            &reconciled(expected_x),
            &predicted(1000),
            Applicability::Calibrated,
        )
        .unwrap();
        let found = refused(
            "one-nanosecond-over",
            check_expectations(
                &identity,
                &launch,
                &reconciled(expected_x + std::time::Duration::from_nanos(1)),
                &predicted(1000),
                Applicability::Calibrated,
            ),
        );
        assert!(
            found.contains(
                "harness a::x: its CBMC run took 1.000000001s, more than its predicted 1000 ms"
            ),
            "{found}"
        );
        let none = Reconciled {
            verifier: fixture_verifier(),
            applied: Vec::new(),
            completed: BTreeMap::new(),
            launched: BTreeMap::new(),
        };
        check_expectations(
            &identity,
            &launch,
            &none,
            &predicted(1000),
            Applicability::Calibrated,
        )
        .unwrap();
        std::fs::remove_dir_all(&root).unwrap();
    }

    /// A prediction applies only to a qualifying execution of its own
    /// calibration's artifact and verifier, in its environment, in a run it
    /// was not calibrated from; each disagreement is refused by name.
    #[test]
    fn a_prediction_applies_only_where_it_was_calibrated() {
        let root = policy_tree("applicability");
        let (identity, launch) = qualifying(&root);
        let within = std::time::Duration::from_millis(500);
        let run = |artifact: &str, verifier: serde_json::Value| Reconciled {
            verifier,
            applied: Vec::new(),
            completed: BTreeMap::from([("a::x".to_string(), within)]),
            launched: BTreeMap::from([(
                "a::x".to_string(),
                Launched {
                    elapsed: within,
                    ended: Ended::Exited,
                    artifact_sha256: artifact.to_string(),
                },
            )]),
        };
        let matching = run(ARTIFACTS[0].2, fixture_verifier());
        check_expectations(
            &identity,
            &launch,
            &matching,
            &predicted(1000),
            Applicability::Calibrated,
        )
        .unwrap();
        let mut other = fixture_environment();
        other.levels[0].memory_max = LimitObservation::Value {
            value: "1".to_string(),
        };
        let other_environment = Launch {
            environment: other,
            ..launch.clone()
        };
        let unknown_environment = Launch {
            environment: EnvironmentRecord {
                cpu_model: None,
                ..fixture_environment()
            },
            ..launch.clone()
        };
        let calibrating = RunIdentityRecord {
            id: CALIBRATING.to_string(),
            ..identity.record().clone()
        }
        .validate()
        .unwrap();
        for (name, identity, launch, reconciled, fault) in [
            (
                "artifact",
                &identity,
                &launch,
                run(ARTIFACTS[1].2, fixture_verifier()),
                "ran on artifact 81a1a003",
            ),
            (
                "verifier",
                &identity,
                &launch,
                run(ARTIFACTS[0].2, serde_json::json!({"solver": "other"})),
                "its prediction was calibrated under",
            ),
            (
                "environment",
                &identity,
                &other_environment,
                matching_clone(&matching),
                "is not the predictions'",
            ),
            (
                "unknown-environment",
                &identity,
                &unknown_environment,
                matching_clone(&matching),
                "the environment is not established",
            ),
            (
                "calibration-run",
                &calibrating,
                &launch,
                matching_clone(&matching),
                "run 00000000-0000-0000-0000-000000000001 is one its prediction was calibrated from",
            ),
        ] {
            let found = refused(
                name,
                check_expectations(
                    identity,
                    launch,
                    &reconciled,
                    &predicted(1000),
                    Applicability::Calibrated,
                ),
            );
            assert!(found.contains(fault), "{name}: {found}");
        }
        std::fs::remove_dir_all(&root).unwrap();
    }

    fn matching_clone(reconciled: &Reconciled) -> Reconciled {
        Reconciled {
            verifier: reconciled.verifier.clone(),
            applied: reconciled.applied.clone(),
            completed: reconciled.completed.clone(),
            launched: reconciled.launched.clone(),
        }
    }

    /// The report's rendered verification time has no effect: the recorded
    /// duration alone is compared, so a report that rounds or misstates it
    /// changes nothing.
    #[test]
    fn the_rendered_time_cannot_change_the_classification() {
        let evidence = RunEvidence::new("rendered-time");
        let root = policy_tree("rendered-time-policy");
        let (identity, launch) = qualifying(&root);
        evidence.execution(
            "a.x",
            2000,
            (1, 1),
            serde_json::json!({"kind": "exited", "code": 0}),
        );
        let read = policy_of(POLICY_TEXT, &declared(&["a::x", "a::y"])).unwrap();
        for shown in ["1s", "0.9s", "1000000s"] {
            let report = format!(
                "{}Verification Time: {shown}\n{}{}",
                block("a::x", "SUCCESSFUL"),
                block("a::y", "SUCCESSFUL"),
                summary(2, 0)
            );
            let reconciled =
                reconcile(&evidence.root, &run_policy(&read, &Selection::All), &report).unwrap();
            assert_eq!(reconciled.completed["a::x"], std::time::Duration::new(1, 1));
            let found = check_expectations(
                &identity,
                &launch,
                &reconciled,
                &predicted(1000),
                Applicability::Calibrated,
            )
            .unwrap_err();
            assert!(
                found.contains("harness a::x: its CBMC run took"),
                "{shown}: {found}"
            );
        }
        std::fs::remove_dir_all(&root).unwrap();
    }

    /// `count` readings of a settled system under the production policy
    /// ([`settling_policy`]), one interval apart from `from` on the wall
    /// clock and from 0 on the monotonic clock.
    fn settled_readings(from: Instant, count: usize) -> Vec<Settled> {
        let policy = settling_policy();
        (0..count)
            .map(|at| Settled {
                at: Instant {
                    seconds: from.seconds + 5 * at as u64,
                    nanoseconds: from.nanoseconds,
                },
                monotonic_milliseconds: at as u64 * policy.interval_milliseconds,
                loadavg: "0.10 0.10 0.10 1/100 1".to_string(),
                load1_hundredths: 10,
                running: 1,
                within: true,
            })
            .collect()
    }

    /// A readiness the one validator accepts ([`Readiness::validate`]): of
    /// commit `c`; the workload lock acquired; the production policy; and
    /// the seven readings after it that settle it, spanning thirty seconds.
    pub(crate) fn valid_readiness() -> Readiness {
        static VALID: std::sync::OnceLock<Readiness> = std::sync::OnceLock::new();
        VALID
            .get_or_init(|| {
                let acquired = now().unwrap();
                Readiness {
                    version: RUNTIME_VERSION,
                    commit: "c".to_string(),
                    workload_lock: Some(LockRecord {
                        path: "/checkout/target/gate-workload.lock".to_string(),
                        acquired,
                    }),
                    policy: settling_policy(),
                    observations: settled_readings(acquired, settling_policy().consecutive),
                    ready: true,
                    error: None,
                }
            })
            .clone()
    }

    /// A tree of adopted calibration runs of the fixture's two harnesses, as
    /// `adopt` lays them out and the gate writes their records: each run a
    /// calibration of one harness, given the plan both share
    /// ([`CalibrationTree::PLAN`]) and a ready readiness. The tree the
    /// predictions' reader and the control sides' tests read valid evidence
    /// from.
    pub(crate) struct CalibrationTree {
        pub(crate) root: std::path::PathBuf,
    }

    impl CalibrationTree {
        /// The plan every fixture calibration was given.
        const PLAN: &'static str = r#"{"version": 1, "purpose": "calibration", "harnesses": {
            "a::x": {"limit_milliseconds": 60000, "reason": "the calibration's limit"},
            "a::y": {"limit_milliseconds": 60000, "reason": "the calibration's limit"}}}"#;

        pub(crate) fn new(test: &str) -> Self {
            let root = policy_tree(&format!("calibration-{test}"));
            // The source the census of the tree is read from: the fixture's
            // two harnesses, beside every family's inclusion of its
            // instances.
            let write = |relative: &str, text: &str| {
                let path = root.join(relative);
                std::fs::create_dir_all(path.parent().unwrap()).unwrap();
                std::fs::write(path, text).unwrap();
            };
            write(
                "src/a.rs",
                "#[kani::proof]\nfn x() {}\n#[kani::proof]\nfn y() {}\n",
            );
            for family in instances::FAMILIES {
                write(family.file, &format!("{}\n", instances::inclusion(family)));
            }
            Self { root }
        }

        /// The census of the tree: the fixture's two harnesses.
        pub(crate) fn census() -> BTreeSet<String> {
            declared(&["a::x", "a::y"])
        }

        /// The readiness every fixture calibration was given: one the one
        /// validator accepts ([`valid_readiness`]).
        fn readiness() -> Vec<u8> {
            serde_json::to_vec(&valid_readiness()).unwrap()
        }

        /// The adopted run `id` of purpose `purpose`, a calibration of
        /// `harness` alone that ran for `elapsed` (seconds and nanoseconds),
        /// its report block reading `result`, on artifact `artifact`: the
        /// digest of its manifest.
        pub(crate) fn run(
            &self,
            id: &str,
            purpose: &str,
            harness: &str,
            elapsed: (u64, u32),
            result: &str,
            artifact: &str,
        ) -> String {
            let directory = self.root.join(CALIBRATION).join(id);
            let evidence = directory.join("evidence");
            let write = |relative: &str, bytes: &[u8]| {
                let path = evidence.join(relative);
                std::fs::create_dir_all(path.parent().unwrap()).unwrap();
                std::fs::write(path, bytes).unwrap();
            };
            std::fs::create_dir_all(&evidence).unwrap();
            let failed = usize::from(result == "FAILED");
            std::fs::write(
                directory.join("kani.log"),
                format!("{}{}", block(harness, result), summary(1 - failed, failed)),
            )
            .unwrap();
            write(PLAN_RECORD, Self::PLAN.as_bytes());
            write(READINESS_RECORD, &Self::readiness());
            // The inputs the run's identity binds, as `process::kani` keeps
            // them: its launcher, the tree's policy file, its per-path
            // digests, and its invocation, its evidence at its own path then.
            let then = format!("/runs/{id}.log.evidence");
            write(LAUNCHER_RECORD, b"/kani/cargo-kani\n");
            write(
                LOOP_POLICY_RECORD,
                &std::fs::read(self.root.join(POLICY)).unwrap(),
            );
            write(
                SOURCES_RECORD,
                &serde_json::to_vec(&fixture_sources(&self.root)).unwrap(),
            );
            let invocation = invocation_arguments(
                &Selection::one(harness),
                "/runs/target",
                &format!("{then}/loop-bounds.json"),
                &format!("{then}/loop-bounds"),
            );
            write(
                INVOCATION_RECORD,
                &serde_json::to_vec(&serde_json::json!({
                    "launcher": "/kani/cargo-kani",
                    "arguments": invocation,
                }))
                .unwrap(),
            );
            let revision = crate::process::sha256_bytes(Self::PLAN.as_bytes()).unwrap();
            let identity = fixture_identity(&self.root, id, purpose, &revision);
            write("run.json", &serde_json::to_vec(&identity).unwrap());
            let launch = Launch {
                environment: fixture_environment(),
                workload_cgroup: Some(format!("/user.slice/run-{id}.scope")),
                load_before: None,
                load_after: None,
            };
            write("launch.json", &serde_json::to_vec(&launch).unwrap());
            let read = policy_of(POLICY_TEXT, &Self::census()).unwrap();
            let plan = plan_of(Self::PLAN.as_bytes(), &Self::census()).unwrap();
            let policy = selected(
                &read,
                plan.deadlines(),
                &Selection::one(harness),
                &Self::census(),
            )
            .unwrap();
            write("loop-bounds.json", &serde_json::to_vec(&policy).unwrap());
            // The harness's records as the driver writes them in the run's
            // evidence, at the run's own path then.
            let at_then = format!("/runs/{id}.log.evidence/loop-bounds");
            let name = harness.replace("::", ".");
            let function = if harness == "a::x" { "f" } else { "g" };
            let copy = format!("{at_then}/{name}/artifact.out");
            let record = |parts: &[&str]| {
                parts
                    .iter()
                    .flat_map(|part| part.bytes().chain([0]))
                    .collect::<Vec<u8>>()
            };
            let at = |file: &str| format!("loop-bounds/{name}/{file}");
            write(&at("solver.attempt"), b"spawning\n");
            let mut command = vec!["/kani/cbmc"];
            if harness == "a::x" {
                command.extend(["--unwindset", "f.0:0"]);
            }
            command.extend([copy.as_str(), "--json-ui"]);
            write(&at("solver.arguments"), &record(&command));
            write(
                &at("solver.identity"),
                fixture_verifier().to_string().as_bytes(),
            );
            write(
                &at("artifact.json"),
                serde_json::json!({"source": "/build/x", "path": copy, "sha256": artifact})
                    .to_string()
                    .as_bytes(),
            );
            write(
                &at("discovery.arguments"),
                &record(&["goto-instrument", "--show-loops", "--json-ui", &copy]),
            );
            write(&at("discovery.status"), b"exit status: 0\n");
            write(&at("discovery.stderr"), b"");
            write(
                &at("discovery.stdout"),
                serde_json::json!([
                    {"program": "goto-instrument"},
                    {"loops": [{
                        "name": format!("{function}.0"),
                        "sourceLocation": {"function": function, "file": "a.rs"},
                    }]},
                ])
                .to_string()
                .as_bytes(),
            );
            let (seconds, nanoseconds) = elapsed;
            write(
                &at("solver.execution.json"),
                serde_json::json!({
                    "deadline_milliseconds": 60000,
                    "elapsed": {"seconds": seconds, "nanoseconds": nanoseconds},
                    "termination": {"kind": "exited", "code": 0},
                })
                .to_string()
                .as_bytes(),
            );
            if harness == "a::x" {
                let entry = read.harnesses["a::x"].clone();
                write(
                    &at("resolution.json"),
                    serde_json::json!({
                        "harness": "a::x",
                        "policy": entry,
                        "function_scope": [],
                        "artifact": {"path": copy, "sha256": artifact},
                        "warnings": [],
                        "resolved": [{
                            "selector": entry["loops"][0],
                            "file": entry["loops"][0]["file"],
                            "loop": "f.0",
                            "location": {"file": entry["loops"][0]["file"]},
                        }],
                    })
                    .to_string()
                    .as_bytes(),
                );
            }
            write("loop-bounds/function-scope.json", b"[]");
            write(
                "execution.json",
                serde_json::json!({
                    "launcher": "/kani/cargo-kani",
                    "verifier": fixture_verifier(),
                    "artifacts": {harness: artifact},
                })
                .to_string()
                .as_bytes(),
            );
            write(
                "launcher.execution.json",
                serde_json::json!({"exit_code": failed, "signal": null})
                    .to_string()
                    .as_bytes(),
            );
            write(
                "judgement.json",
                serde_json::json!({"status": "accepted"})
                    .to_string()
                    .as_bytes(),
            );
            readopted(&directory)
        }

        /// Three verified calibrations of each harness, each a run of its
        /// own: `a::x` in 1.0, 1.1 and 1.2 s (runs 1 to 3), `a::y` in 2.0,
        /// 2.05 and 2.1 s (runs 4 to 6); each harness's references.
        pub(crate) fn three(&self) -> (Vec<serde_json::Value>, Vec<serde_json::Value>) {
            let runs = |harness: &str, first: u32, seconds: u64, spreads: [u32; 3]| {
                spreads
                    .into_iter()
                    .zip(first..)
                    .map(|(nanoseconds, number)| {
                        let id = format!("00000000-0000-0000-0000-{number:012}");
                        let digest = self.run(
                            &id,
                            "calibration",
                            harness,
                            (seconds, nanoseconds),
                            "SUCCESSFUL",
                            if harness == "a::x" {
                                ARTIFACTS[0].2
                            } else {
                                ARTIFACTS[1].2
                            },
                        );
                        serde_json::json!({"run": id, "manifest_sha256": digest})
                    })
                    .collect::<Vec<_>>()
            };
            (
                runs("a::x", 1, 1, [0, 100_000_000, 200_000_000]),
                runs("a::y", 4, 2, [0, 50_000_000, 100_000_000]),
            )
        }

        /// The prediction document citing `x_references` for `a::x` and
        /// `y_references` for `a::y`, predicting `x` and `y` milliseconds.
        pub(crate) fn document(
            &self,
            (x_references, y_references): &(Vec<serde_json::Value>, Vec<serde_json::Value>),
            x: u64,
            y: u64,
        ) -> serde_json::Value {
            let prediction = |references: &[serde_json::Value], milliseconds: u64| {
                serde_json::json!({
                    "model": "m",
                    "inputs": {"length": 1},
                    "calibration": references,
                    "milliseconds": milliseconds,
                    "transfer": "the harness's own calibrations",
                })
            };
            serde_json::json!({
                "version": RUNTIME_VERSION,
                "configuration": {
                    "build": arguments().join(" "),
                    "loop_policy_sha256": crate::process::sha256(&self.root.join(POLICY)).unwrap(),
                    "timing_boundary": TIMING_BOUNDARY,
                },
                "environment": fixture_environment(),
                "models": {"m": {"rule": RULE, "applicability": "this machine", "uncertainty": "spread"}},
                "harnesses": {
                    "a::x": prediction(x_references, x),
                    "a::y": prediction(y_references, y),
                },
            })
        }

        pub(crate) fn read(&self, document: &[u8]) -> Result<Expectations, String> {
            expectations_of(&self.root, document, &Self::census())
        }
    }

    impl Drop for CalibrationTree {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    /// The adopted run at `directory` given its manifest and acceptance
    /// receipt anew, as adoption leaves them: its records' digests, then the
    /// receipt naming the run and that manifest. The manifest's digest.
    fn readopted(directory: &Path) -> String {
        let evidence = directory.join("evidence");
        let identity: RunIdentityRecord =
            serde_json::from_slice(&std::fs::read(evidence.join("run.json")).unwrap()).unwrap();
        let _ = std::fs::remove_file(evidence.join("manifest.json"));
        let manifest = manifest_of(
            &evidence,
            Some(&directory.join("kani.log")),
            Some(&identity.id),
        );
        std::fs::write(
            evidence.join("manifest.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        let digest = crate::process::sha256(&evidence.join("manifest.json")).unwrap();
        std::fs::write(
            directory.join(ADOPTION_RECORD),
            serde_json::to_vec(&AdoptionReceipt {
                version: RUNTIME_VERSION,
                run: identity.id,
                manifest_sha256: digest.clone(),
            })
            .unwrap(),
        )
        .unwrap();
        digest
    }

    /// The JSON record at `path` rewritten by `change`.
    fn edited(path: &Path, change: impl Fn(&mut serde_json::Value)) {
        let mut value: serde_json::Value =
            serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        change(&mut value);
        std::fs::write(path, serde_json::to_vec(&value).unwrap()).unwrap();
    }

    /// An adopted calibration is a sample only when its identity is bound to
    /// the records it kept of its inputs. Each relationship broken alone,
    /// every digest, manifest and receipt made anew so only that
    /// relationship is wrong, is refused by its own fault: a build the
    /// invocation did not run, a loop-bound policy digest of another file, a
    /// policy file whose selection is not the run's policy, a source state
    /// its per-path digests do not digest to, per-path digests that do not
    /// hold the policy file it read, an invocation of another harness, and a
    /// launcher the records disagree on.
    #[test]
    fn a_sample_binds_its_identity_to_its_records() {
        const RUN: &str = "00000000-0000-0000-0000-0000000000e1";
        type Plant = fn(&Path);
        /// The source state of the per-path digests `sources.json` holds,
        /// recorded as the run's identity's.
        fn rebind_tree(evidence: &Path) {
            let sources: BTreeMap<String, String> =
                serde_json::from_slice(&std::fs::read(evidence.join(SOURCES_RECORD)).unwrap())
                    .unwrap();
            let tree = tree_digest_of(&sources).unwrap();
            edited(&evidence.join("run.json"), |identity| {
                identity["tree_sha256"] = serde_json::json!(tree);
            });
        }
        let cases: [(&str, Plant, &str); 7] = [
            (
                "build-unbound",
                |evidence| {
                    edited(&evidence.join("run.json"), |identity| {
                        identity["build"] = serde_json::json!("kani --package other");
                    })
                },
                "is not the invocation's build",
            ),
            (
                "policy-digest-unbound",
                |evidence| {
                    edited(&evidence.join("run.json"), |identity| {
                        identity["loop_policy_sha256"] = serde_json::json!(DIGEST);
                    })
                },
                "its loop-policy.json has digest",
            ),
            (
                // Another policy file, every digest that names it made
                // consistent: only its selection is not the run's policy.
                "policy-selection-unbound",
                |evidence| {
                    let other = br#"{"loops": [], "harnesses": []}"#;
                    std::fs::write(evidence.join(LOOP_POLICY_RECORD), other).unwrap();
                    edited(&evidence.join(SOURCES_RECORD), |sources| {
                        sources[POLICY] =
                            serde_json::json!(file_entry_digest(POLICY, other, false).unwrap());
                    });
                    let digest = crate::process::sha256_bytes(other).unwrap();
                    edited(&evidence.join("run.json"), |identity| {
                        identity["loop_policy_sha256"] = serde_json::json!(digest);
                    });
                    rebind_tree(evidence);
                },
                "is not the selection of its loop-policy.json",
            ),
            (
                "tree-unbound",
                |evidence| {
                    edited(&evidence.join("run.json"), |identity| {
                        identity["tree_sha256"] = serde_json::json!(DIGEST);
                    })
                },
                "its sources.json digests to",
            ),
            (
                "sources-policy-unbound",
                |evidence| {
                    edited(&evidence.join(SOURCES_RECORD), |sources| {
                        sources[POLICY] = serde_json::json!(DIGEST);
                    });
                    rebind_tree(evidence);
                },
                "records the tree's loop-bound policy",
            ),
            (
                "invocation-unbound",
                |evidence| {
                    edited(&evidence.join(INVOCATION_RECORD), |invocation| {
                        let arguments = invocation["arguments"].as_array_mut().unwrap();
                        let at = arguments.iter().position(|part| part == "a::x").unwrap();
                        arguments[at] = serde_json::json!("a::y");
                    })
                },
                "which are not the proof build's run of a::x alone",
            ),
            (
                "launcher-unbound",
                |evidence| {
                    edited(&evidence.join("execution.json"), |execution| {
                        execution["launcher"] = serde_json::json!("/other/cargo-kani");
                    })
                },
                "its launcher record names /kani/cargo-kani",
            ),
        ];
        for (name, plant, fault) in cases {
            let tree = CalibrationTree::new(&format!("bound-{name}"));
            tree.run(
                RUN,
                "calibration",
                "a::x",
                (1, 0),
                "SUCCESSFUL",
                ARTIFACTS[0].2,
            );
            let directory = tree.root.join(CALIBRATION).join(RUN);
            let sample = || {
                RunRecords::adopted(&directory)
                    .and_then(|records| eligible_sample(&records, RUN, &CalibrationTree::census()))
            };
            sample().unwrap_or_else(|why| panic!("{name}: the fixture itself is refused: {why}"));
            plant(&directory.join("evidence"));
            readopted(&directory);
            let found = refused(name, sample());
            assert!(found.contains(fault), "{name}: {found}");
        }
    }

    /// Predictions are recomputed from the adopted calibrations' raw records
    /// by the rule: `a::x`'s 1.0, 1.1 and 1.2 s give 1.2 s and the envelope's
    /// spread 0.2 s, 1400 ms; `a::y`'s 2.0 to 2.1 s give 2.1 s and the
    /// envelope's 0.2 s, its own being 0.1 s, 2300 ms; each deadline twice
    /// its prediction.
    #[test]
    fn a_prediction_is_its_calibrations_by_the_rule() {
        let tree = CalibrationTree::new("fit");
        let references = tree.three();
        let read = tree
            .read(&serde_json::to_vec(&tree.document(&references, 1400, 2300)).unwrap())
            .unwrap();
        assert_eq!(read.environment().record(), &fixture_environment());
        let x = read.harness("a::x").unwrap();
        assert_eq!(
            (x.milliseconds(), x.deadline_milliseconds()),
            (1400, 1400 * DEADLINE_MARGIN)
        );
        assert_eq!(x.artifact_sha256(), ARTIFACTS[0].2);
        assert_eq!(x.verifier(), &fixture_verifier());
        assert_eq!(x.calibration_runs().len(), SAMPLES);
        assert_eq!(read.harness("a::y").unwrap().milliseconds(), 2300);
        let found = refused(
            "predicted-otherwise",
            tree.read(&serde_json::to_vec(&tree.document(&references, 1399, 2300)).unwrap()),
        );
        assert!(
            found.contains("harness a::x: predicts 1399 ms, its calibration gives 1400 ms"),
            "{found}"
        );
    }

    /// One disagreement planted into a valid prediction tree: its name, the
    /// plant (given the tree and the valid document, returning the document
    /// to read), and the fault its refusal must name.
    type Unsupported = (
        &'static str,
        fn(&CalibrationTree, serde_json::Value) -> Vec<u8>,
        &'static str,
    );

    /// Every way a prediction can lack support is refused by its own fault:
    /// a key repeated at any depth, an unknown field, a census harness left
    /// out, an unknown or another environment, a run cited twice, a run whose
    /// records were changed, extended or linked, a run identifier that
    /// leaves the calibration directory, a cited digest that is not the
    /// manifest's, a qualification run cited, an unverified execution, a
    /// harness's samples of different artifacts, a sample of another
    /// harness, a kept plan that is not the identity's revision, a policy
    /// deadline that is not the plan's limit, a malformed deadline beside a
    /// valid one, a readiness with no reading, and a readiness that held no
    /// workload lock.
    #[test]
    fn an_unsupported_prediction_is_refused() {
        const FIRST: &str = "00000000-0000-0000-0000-000000000001";
        /// The evidence of the first run, its record `relative` rewritten by
        /// `change` and its manifest and receipt re-made ([`readopted`]), so
        /// every digest still holds and only the relationship planted is
        /// wrong: the new manifest digest.
        fn rewritten(
            tree: &CalibrationTree,
            relative: &str,
            change: impl Fn(&mut Vec<u8>),
        ) -> String {
            let directory = tree.root.join(CALIBRATION).join(FIRST);
            let path = directory.join("evidence").join(relative);
            let mut bytes = std::fs::read(&path).unwrap();
            change(&mut bytes);
            std::fs::write(&path, bytes).unwrap();
            readopted(&directory)
        }
        /// The document citing the first run by the manifest digest `digest`.
        fn cited(mut document: serde_json::Value, digest: String) -> Vec<u8> {
            document["harnesses"]["a::x"]["calibration"][0]["manifest_sha256"] =
                serde_json::json!(digest);
            serde_json::to_vec(&document).unwrap()
        }
        let cases: [Unsupported; 20] = [
            (
                "nested-duplicate-key",
                |_, document| {
                    document
                        .to_string()
                        .replace(
                            r#""inputs":{"length":1}"#,
                            r#""inputs":{"length":1,"length":2}"#,
                        )
                        .into_bytes()
                },
                "the key \"length\" appears twice in one object",
            ),
            (
                "unknown-field",
                |_, mut document| {
                    document["harnesses"]["a::x"]["extra"] = serde_json::json!(1);
                    serde_json::to_vec(&document).unwrap()
                },
                "unknown field `extra`",
            ),
            (
                "census-incomplete",
                |_, mut document| {
                    document["harnesses"]
                        .as_object_mut()
                        .unwrap()
                        .remove("a::y");
                    serde_json::to_vec(&document).unwrap()
                },
                "harnesses with no prediction: [\"a::y\"]",
            ),
            (
                "environment-unknown",
                |_, mut document| {
                    document["environment"]["cpu_model"] = serde_json::Value::Null;
                    serde_json::to_vec(&document).unwrap()
                },
                "the environment is not established",
            ),
            (
                "environment-other",
                |_, mut document| {
                    document["environment"]["levels"][0]["memory_max"] =
                        serde_json::json!({"state": "value", "value": "1"});
                    serde_json::to_vec(&document).unwrap()
                },
                "is of another environment",
            ),
            (
                "run-cited-twice",
                |_, mut document| {
                    let first = document["harnesses"]["a::x"]["calibration"][0].clone();
                    document["harnesses"]["a::x"]["calibration"][1] = first;
                    serde_json::to_vec(&document).unwrap()
                },
                "is a second sample of one run",
            ),
            (
                // A change every other check accepts: only the manifest's
                // digest of the record refuses it.
                "record-changed",
                |tree, document| {
                    let path = tree
                        .root
                        .join(CALIBRATION)
                        .join(FIRST)
                        .join("evidence/loop-bounds/a.x/artifact.json");
                    let mut record: serde_json::Value =
                        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
                    record["source"] = serde_json::json!("/build/elsewhere");
                    std::fs::write(&path, record.to_string()).unwrap();
                    serde_json::to_vec(&document).unwrap()
                },
                "the manifest records",
            ),
            (
                "record-added",
                |tree, document| {
                    std::fs::write(
                        tree.root
                            .join(CALIBRATION)
                            .join(FIRST)
                            .join("evidence/extra"),
                        "",
                    )
                    .unwrap();
                    serde_json::to_vec(&document).unwrap()
                },
                "holds [\"extra\"] its manifest does not list",
            ),
            (
                "record-linked",
                |tree, document| {
                    std::os::unix::fs::symlink(
                        "/etc/hostname",
                        tree.root
                            .join(CALIBRATION)
                            .join(FIRST)
                            .join("evidence/link"),
                    )
                    .unwrap();
                    serde_json::to_vec(&document).unwrap()
                },
                "neither a regular file nor a directory",
            ),
            (
                "run-outside",
                |_, mut document| {
                    document["harnesses"]["a::x"]["calibration"][0]["run"] =
                        serde_json::json!("../../../../etc");
                    serde_json::to_vec(&document).unwrap()
                },
                "is not a run identifier",
            ),
            (
                "manifest-digest",
                |_, mut document| {
                    document["harnesses"]["a::x"]["calibration"][0]["manifest_sha256"] =
                        serde_json::json!(DIGEST);
                    serde_json::to_vec(&document).unwrap()
                },
                "the prediction cites",
            ),
            (
                "qualification-cited",
                |tree, mut document| {
                    let id = "00000000-0000-0000-0000-00000000000a";
                    let digest = tree.run(
                        id,
                        "qualification",
                        "a::x",
                        (1, 0),
                        "SUCCESSFUL",
                        ARTIFACTS[0].2,
                    );
                    document["harnesses"]["a::x"]["calibration"][0] =
                        serde_json::json!({"run": id, "manifest_sha256": digest});
                    serde_json::to_vec(&document).unwrap()
                },
                "of purpose qualification",
            ),
            (
                "unverified-cited",
                |tree, mut document| {
                    let id = "00000000-0000-0000-0000-00000000000b";
                    let digest =
                        tree.run(id, "calibration", "a::x", (1, 0), "FAILED", ARTIFACTS[0].2);
                    document["harnesses"]["a::x"]["calibration"][0] =
                        serde_json::json!({"run": id, "manifest_sha256": digest});
                    serde_json::to_vec(&document).unwrap()
                },
                "a calibration sample is one verified execution of a::x alone",
            ),
            (
                "artifacts-differ",
                |tree, mut document| {
                    let id = "00000000-0000-0000-0000-00000000000c";
                    let digest = tree.run(id, "calibration", "a::x", (1, 0), "SUCCESSFUL", DIGEST);
                    document["harnesses"]["a::x"]["calibration"][2] =
                        serde_json::json!({"run": id, "manifest_sha256": digest});
                    serde_json::to_vec(&document).unwrap()
                },
                "of another instrumented binary than the harness's other samples",
            ),
            (
                "another-harness-cited",
                |_, mut document| {
                    let y = document["harnesses"]["a::y"]["calibration"][0].clone();
                    document["harnesses"]["a::x"]["calibration"][0] = y;
                    serde_json::to_vec(&document).unwrap()
                },
                "is a sample of another harness",
            ),
            (
                "plan-not-the-revision",
                |tree, document| {
                    let digest = rewritten(tree, PLAN_RECORD, |bytes| bytes.push(b'\n'));
                    cited(document, digest)
                },
                "its plan.json has digest",
            ),
            (
                "policy-deadline-not-the-plans",
                |tree, document| {
                    let digest = rewritten(tree, "loop-bounds.json", |bytes| {
                        let mut policy: serde_json::Value = serde_json::from_slice(bytes).unwrap();
                        policy["deadlines"][0]["milliseconds"] = serde_json::json!(1);
                        *bytes = serde_json::to_vec(&policy).unwrap();
                    });
                    cited(document, digest)
                },
                "its policy gives a::x 1 ms",
            ),
            (
                // A receipt that only says it is ready, with no reading.
                "readiness-fabricated",
                |tree, document| {
                    let digest = rewritten(tree, READINESS_RECORD, |bytes| {
                        let mut readiness = valid_readiness();
                        readiness.observations.clear();
                        *bytes = serde_json::to_vec(&readiness).unwrap();
                    });
                    cited(document, digest)
                },
                "its 0 readings settle at None, not at its last",
            ),
            (
                "readiness-unlocked",
                |tree, document| {
                    let digest = rewritten(tree, READINESS_RECORD, |bytes| {
                        let mut readiness = valid_readiness();
                        readiness.workload_lock = None;
                        *bytes = serde_json::to_vec(&readiness).unwrap();
                    });
                    cited(document, digest)
                },
                "it held no workload lock",
            ),
            (
                // One valid deadline beside a malformed one: never read as
                // a selection of one harness.
                "deadline-malformed-beside",
                |tree, document| {
                    let digest = rewritten(tree, "loop-bounds.json", |bytes| {
                        let mut policy: serde_json::Value = serde_json::from_slice(bytes).unwrap();
                        policy["deadlines"]
                            .as_array_mut()
                            .unwrap()
                            .push(serde_json::json!({"harness": "a::y"}));
                        *bytes = serde_json::to_vec(&policy).unwrap();
                    });
                    cited(document, digest)
                },
                "missing field `milliseconds`",
            ),
        ];
        for (name, plant, fault) in cases {
            let tree = CalibrationTree::new(name);
            let references = tree.three();
            let document = tree.document(&references, 1400, 2300);
            tree.read(&serde_json::to_vec(&document).unwrap())
                .unwrap_or_else(|fault| panic!("{name}: the fixture itself is refused: {fault}"));
            let planted = plant(&tree, document);
            let found = refused(name, tree.read(&planted));
            assert!(found.contains(fault), "{name}: {found}");
        }
    }

    /// A calibration plan selects declared harnesses, each with a positive
    /// operational limit and its reason; every other plan is refused before
    /// anything runs.
    #[test]
    fn a_calibration_plan_is_validated_before_any_run() {
        let valid = r#"{"version": 1, "purpose": "calibration", "harnesses": {
            "a::x": {"limit_milliseconds": 1800000, "reason": "the previous window"}
        }}"#;
        let plan = plan_of(valid.as_bytes(), &declared(&["a::x", "a::y"])).unwrap();
        let digest = crate::process::sha256_bytes(valid.as_bytes()).unwrap();
        assert_eq!(plan.bytes(), valid.as_bytes());
        assert_eq!(plan.sha256(), digest);
        assert_eq!(
            plan.deadlines()["a::x"],
            Deadline {
                milliseconds: 1_800_000,
                reason: "the previous window".to_string(),
            }
        );
        let ready = Ready {
            sha256: DIGEST.to_string(),
            bytes: b"ready".to_vec(),
        };
        let purpose = RunPurpose::Calibration { plan, ready };
        assert_eq!(
            (purpose.name(), purpose.revision()),
            ("calibration", digest.as_str())
        );
        assert_eq!(
            purpose.documents(),
            [
                (PLAN_RECORD, valid.as_bytes()),
                (READINESS_RECORD, b"ready".as_slice())
            ]
        );
        for (text, fault) in [
            (
                valid.replace("a::x", "a::z"),
                "harness a::z: planned, but declared by no",
            ),
            (
                valid.replace("1800000", "0"),
                "harness a::x: a limit of 0 ms",
            ),
            (
                valid.replace("the previous window", " "),
                "its limit gives no reason",
            ),
            (
                valid.replace("\"calibration\"", "\"qualification\""),
                "its purpose is \"qualification\"",
            ),
            (
                valid.replace("\"version\": 1", "\"version\": 2"),
                "version 2, the gate reads 1",
            ),
            (
                valid.replace(
                    r#""reason": "the previous window""#,
                    r#""reason": "r", "reason": "s""#,
                ),
                "the key \"reason\" appears twice in one object",
            ),
            (
                valid.replace(
                    r#""reason": "the previous window""#,
                    r#""reason": "r", "x": 1"#,
                ),
                "unknown field `x`",
            ),
            (
                r#"{"version": 1, "purpose": "calibration", "harnesses": {}}"#.to_string(),
                "it selects no harness",
            ),
        ] {
            let found = refused(
                fault,
                plan_of(text.as_bytes(), &declared(&["a::x", "a::y"])),
            );
            assert!(found.contains(fault), "{fault}: {found}");
        }
    }

    /// A run's policy gives every selected harness its purpose's deadline and
    /// names no other; a selected harness its purpose gives none is refused.
    #[test]
    fn every_selected_harness_has_its_purposes_deadline() {
        let read = policy_of(POLICY_TEXT, &declared(&["a::x", "a::y"])).unwrap();
        let only_x = run_policy(&read, &Selection::one("a::x"));
        assert_eq!(
            only_x["deadlines"],
            serde_json::json!([{"harness": "a::x", "milliseconds": 2000, "reason": "twice x"}])
        );
        let mut partial = deadlines();
        partial.remove("a::y");
        let found = refused(
            "undated",
            selected(
                &read,
                &partial,
                &Selection::All,
                &declared(&["a::x", "a::y"]),
            ),
        );
        assert!(
            found.contains("selected harnesses the run's purpose gives no deadline: [\"a::y\"]"),
            "{found}"
        );
    }

    /// The finished run `id` of `harness`, of `purpose`, its report reading
    /// `result`, laid out as `process::kani` leaves it: its log at
    /// `RUNS/ID.log` and its evidence beside it, the instrumented binary
    /// preserved. Its evidence directory.
    pub(crate) fn finished_run(
        tree: &CalibrationTree,
        id: &str,
        purpose: &str,
        harness: &str,
        result: &str,
    ) -> std::path::PathBuf {
        let built = CalibrationTree::new(&format!("finished-{id}"));
        let artifact = if harness == "a::x" {
            ARTIFACTS[0].2
        } else {
            ARTIFACTS[1].2
        };
        built.run(id, purpose, harness, (1, 0), result, artifact);
        let adopted = built.root.join(CALIBRATION).join(id);
        let runs = tree.root.join("runs");
        std::fs::create_dir_all(&runs).unwrap();
        let evidence = runs.join(format!("{id}.evidence"));
        std::fs::copy(adopted.join("kani.log"), runs.join(format!("{id}.log"))).unwrap();
        std::fs::rename(adopted.join("evidence"), &evidence).unwrap();
        std::fs::write(
            evidence
                .join("loop-bounds")
                .join(harness.replace("::", "."))
                .join("artifact.out"),
            "binary",
        )
        .unwrap();
        evidence
    }

    /// The record `relative` of the run whose evidence is `evidence`
    /// rewritten by `change`, its manifest re-made, so every digest holds
    /// and only the record's content is planted.
    fn remanifested(evidence: &Path, relative: &str, change: impl Fn(&mut Vec<u8>)) {
        let path = evidence.join(relative);
        let mut bytes = std::fs::read(&path).unwrap();
        change(&mut bytes);
        std::fs::write(&path, bytes).unwrap();
        let identity: RunIdentityRecord =
            serde_json::from_slice(&std::fs::read(evidence.join("run.json")).unwrap()).unwrap();
        std::fs::remove_file(evidence.join("manifest.json")).unwrap();
        let manifest = manifest_of(
            evidence,
            Some(&evidence.with_extension("log")),
            Some(&identity.id),
        );
        std::fs::write(
            evidence.join("manifest.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
    }

    /// A finished calibration that is a sample is adopted whole into the
    /// tree, every instrumented binary left out, by the one eligibility
    /// authority ([`eligible_sample`]); a qualification, a second adoption,
    /// a rejected run, a run whose harness failed verification though its
    /// execution was recorded and accepted, an identifier that is no run's,
    /// and records that no longer match their manifest are refused, and
    /// nothing is left of a refused one.
    #[test]
    fn a_calibration_is_adopted_whole_and_once() {
        /// The refusal `result` must be, named `case`: refused outright,
        /// nothing published.
        fn refused(case: &str, result: Result<std::path::PathBuf, Adoption>) -> String {
            match result {
                Err(Adoption::Refused(why)) => why,
                other => panic!("{case}: {other:?}, not a refusal"),
            }
        }
        let tree = CalibrationTree::new("adopt");
        let calibration = finished_run(
            &tree,
            "00000000-0000-0000-0000-0000000000a1",
            "calibration",
            "a::x",
            "SUCCESSFUL",
        );
        let adopted = adopt(&calibration, &tree.root).unwrap();
        assert!(adopted.join("kani.log").is_file());
        assert!(
            adopted
                .join("evidence/loop-bounds/a.x/artifact.json")
                .is_file()
        );
        assert!(
            !adopted
                .join("evidence/loop-bounds/a.x/artifact.out")
                .exists()
        );
        eligible_sample(
            &RunRecords::adopted(&adopted).unwrap(),
            "00000000-0000-0000-0000-0000000000a1",
            &CalibrationTree::census(),
        )
        .unwrap();
        let again = refused("adopted-twice", adopt(&calibration, &tree.root));
        assert!(again.contains("already adopted"), "{again}");
        let qualification = finished_run(
            &tree,
            "00000000-0000-0000-0000-0000000000a2",
            "qualification",
            "a::x",
            "SUCCESSFUL",
        );
        let found = refused("qualification-adopted", adopt(&qualification, &tree.root));
        assert!(found.contains("only a calibration is adopted"), "{found}");
        let rejected = finished_run(
            &tree,
            "00000000-0000-0000-0000-0000000000a4",
            "calibration",
            "a::x",
            "SUCCESSFUL",
        );
        remanifested(&rejected, "judgement.json", |bytes| {
            *bytes = br#"{"status": "rejected", "error": "e"}"#.to_vec();
        });
        let found = refused("rejected-adopted", adopt(&rejected, &tree.root));
        assert!(found.contains("not accepted"), "{found}");
        let failed = finished_run(
            &tree,
            "00000000-0000-0000-0000-0000000000a5",
            "calibration",
            "a::x",
            "FAILED",
        );
        let found = refused("failed-verification-adopted", adopt(&failed, &tree.root));
        assert!(
            found.contains("a calibration sample is one verified execution of a::x alone"),
            "{found}"
        );
        // An identifier that is no run's names no path: refused before any
        // directory is made from it.
        let outside = tree.root.join("runs/outside.evidence");
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(
            outside.join("run.json"),
            serde_json::to_vec(&fixture_identity(
                &tree.root,
                "../outside",
                "calibration",
                DIGEST,
            ))
            .unwrap(),
        )
        .unwrap();
        let found = refused("adopted-outside", adopt(&outside, &tree.root));
        assert!(
            found.contains("\"../outside\" is not a run identifier"),
            "adopted-outside: {found}"
        );
        assert!(!tree.root.join("tests/data/proofs/outside").exists());
        let changed = finished_run(
            &tree,
            "00000000-0000-0000-0000-0000000000a3",
            "calibration",
            "a::x",
            "SUCCESSFUL",
        );
        std::fs::write(changed.join("loop-bounds/a.x/artifact.json"), "changed").unwrap();
        let found = refused("changed-adopted", adopt(&changed, &tree.root));
        assert!(found.contains("the manifest records"), "{found}");
        for refused_run in ["a2", "a3", "a4", "a5"] {
            let id = format!("00000000-0000-0000-0000-0000000000{refused_run}");
            assert!(!tree.root.join(CALIBRATION).join(&id).exists(), "{id}");
        }
        let staging: Vec<String> = std::fs::read_dir(tree.root.join(CALIBRATION))
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|name| name.starts_with(".adopting-"))
            .collect();
        assert!(
            staging.is_empty(),
            "a refused adoption left its staging: {staging:?}"
        );
    }

    /// A calibration's observations are established only when its launcher
    /// ended as its harnesses' outcomes call for: exit 0 when every one
    /// verified, exit 1 when one did not. Any other ending, a signal after a
    /// complete report included, establishes none of them.
    #[test]
    fn a_calibration_ending_otherwise_is_no_observation() {
        let passed = format!(
            "{}{}{}",
            block("a::x", "SUCCESSFUL"),
            block("a::y", "SUCCESSFUL"),
            summary(2, 0)
        );
        let failed = format!(
            "{}{}{}",
            block("a::x", "FAILED"),
            block("a::y", "SUCCESSFUL"),
            summary(1, 1)
        );
        check_calibration_termination(Termination::Exited(0), &passed).unwrap();
        check_calibration_termination(Termination::Exited(1), &failed).unwrap();
        for (name, termination, report) in [
            ("exit-1-all-verified", Termination::Exited(1), &passed),
            ("exit-0-one-failed", Termination::Exited(0), &failed),
            ("signal-after-report", Termination::Signaled(9), &passed),
        ] {
            let found = refused(name, check_calibration_termination(termination, report));
            assert!(
                found.contains("none of its observations is established"),
                "{name}: {found}"
            );
        }
    }

    /// A key repeated in the loop-bound policy, at any depth, is refused.
    #[test]
    fn a_repeated_policy_key_is_refused() {
        let repeated = POLICY_TEXT.replace(r#""bound": 0,"#, r#""bound": 0, "bound": 9,"#);
        let found = refused(
            "policy-duplicate-key",
            policy_of(&repeated, &declared(&["a::x", "a::y"])),
        );
        assert!(found.contains("the key \"bound\" appears twice"), "{found}");
    }

    /// `a::x`'s report block as the driver renders a run a signal terminated.
    fn signaled_block() -> String {
        format!(
            "Checking harness a::x...\n\n{}9\nVERIFICATION:- FAILED\nThe signal's sender is not \
             established by its number; the harness has no verdict.\n",
            outcome::KANI_SIGNAL
        )
    }

    /// A recorded signal gives no verdict whatever the report claims: beside a
    /// verified report, a failed-property summary, or a report that omits the
    /// signal's header, the evidence is refused; beside the driver's signal
    /// report it reconciles as no verdict, is no completed run, and is never a
    /// control's detection. A normal exit, its code 10, verifies.
    #[test]
    fn a_signal_is_no_verdict_whatever_the_report_claims() {
        let read = policy_of(POLICY_TEXT, &declared(&["a::x", "a::y"])).unwrap();
        let signal = serde_json::json!({"kind": "signaled", "signal": 9});
        let y = block("a::y", "SUCCESSFUL");
        let check = |evidence: &RunEvidence, x: &str, verified: usize| {
            let report = format!("{x}{y}{}", summary(verified, 2 - verified));
            let reconciled =
                reconcile(&evidence.root, &run_policy(&read, &Selection::All), &report);
            (report, reconciled)
        };
        for (name, x, verified, fault) in [
            (
                "signal-beside-success",
                block("a::x", "SUCCESSFUL"),
                2,
                "harness a::x: its solver execution ended Signaled, its report verified it",
            ),
            (
                "signal-beside-failure",
                block("a::x", "FAILED"),
                1,
                "harness a::x: its solver execution ended Signaled, its report reports failed \
                 properties",
            ),
            (
                "signal-header-omitted",
                "Checking harness a::x...\nVERIFICATION:- FAILED\n".to_string(),
                1,
                "harness a::x: its solver execution ended Signaled, its report reports a result",
            ),
        ] {
            let evidence = RunEvidence::new(name);
            evidence.execution("a.x", 2000, (0, 5), signal.clone());
            let found = refused(name, check(&evidence, &x, verified).1);
            assert!(found.contains(fault), "{name}: {found}");
        }
        let evidence = RunEvidence::new("signal-reported");
        evidence.execution("a.x", 2000, (0, 5), signal);
        let (report, reconciled) = check(&evidence, &signaled_block(), 1);
        let reconciled = reconciled.unwrap();
        assert!(!reconciled.completed.contains_key("a::x"));
        assert!(reconciled.completed.contains_key("a::y"));
        assert_eq!(
            checked(&report).unwrap()[0],
            ("a::x".to_string(), Outcome::NoVerdict)
        );
        assert_eq!(
            outcome::kani(Termination::Exited(1), &report),
            Outcome::NoVerdict
        );
        let exited = RunEvidence::new("exit-10");
        exited.execution(
            "a.x",
            2000,
            (0, 5),
            serde_json::json!({"kind": "exited", "code": 10}),
        );
        let (_, reconciled) = check(&exited, &block("a::x", "SUCCESSFUL"), 2);
        assert!(reconciled.unwrap().completed.contains_key("a::x"));
    }

    /// A launched harness owes all its evidence whether or not its report
    /// reaches a verdict: a verdictless report with its preserved artifact
    /// missing, or with a malformed discovery, is refused by that evidence's
    /// own fault, and one with every record valid by its missing verdict. A
    /// harness refused before its launch owes none.
    #[test]
    fn a_verdictless_launched_harness_owes_its_evidence() {
        let read = policy_of(POLICY_TEXT, &declared(&["a::x", "a::y"])).unwrap();
        let report = format!(
            "Checking harness a::x...\n{}{}",
            block("a::y", "SUCCESSFUL"),
            summary(1, 0)
        );
        let check = |evidence: &RunEvidence| {
            reconcile(&evidence.root, &run_policy(&read, &Selection::All), &report)
        };
        type Plant = fn(&RunEvidence);
        let cases: [(&str, Plant, &str); 3] = [
            (
                "verdictless-artifact-missing",
                |evidence| std::fs::remove_file(evidence.artifact("a.x")).unwrap(),
                "a.x/artifact.out",
            ),
            (
                "verdictless-discovery-malformed",
                |evidence| evidence.write("a.x", "discovery.stdout", b"[]"),
                "harness a::x: the loop discovery holds 0 loop inventories, not one",
            ),
            (
                "verdictless-evidence-whole",
                |_| {},
                "harness a::x: its solver execution ended Exited, its report reaches no \
                 verification result",
            ),
        ];
        for (name, plant, fault) in cases {
            let evidence = RunEvidence::new(name);
            plant(&evidence);
            let found = refused(name, check(&evidence));
            assert!(found.contains(fault), "{name}: {found}");
        }
        let unlaunched = RunEvidence::new("unlaunched");
        std::fs::remove_file(unlaunched.root.join("a.x").join("solver.attempt")).unwrap();
        check(&unlaunched).unwrap();
    }

    /// A harness's execution record must exist, be well formed, carry the
    /// deadline the run's policy gave it, and agree with its report: a
    /// deadline beside a verified report, or an exit beside a deadline
    /// report, is refused.
    #[test]
    fn the_execution_record_reconciles_with_its_report() {
        type Plant = fn(&RunEvidence);
        let cases: [(&str, Plant, bool, &str); 6] = [
            (
                "record-missing",
                |evidence| {
                    std::fs::remove_file(evidence.root.join("a.x").join("solver.execution.json"))
                        .unwrap();
                },
                false,
                "a.x/solver.execution.json",
            ),
            (
                "deadline-disagrees",
                |evidence| {
                    evidence.execution(
                        "a.x",
                        9999,
                        (0, 0),
                        serde_json::json!({"kind": "exited", "code": 0}),
                    );
                },
                false,
                "records the deadline 9999 ms, the run's policy gave 2000 ms",
            ),
            (
                "nanoseconds-out-of-range",
                |evidence| {
                    evidence.execution(
                        "a.x",
                        2000,
                        (0, 1_000_000_000),
                        serde_json::json!({"kind": "exited", "code": 0}),
                    );
                },
                false,
                "not a solver execution record",
            ),
            (
                "unknown-termination",
                |evidence| {
                    evidence.execution("a.x", 2000, (0, 0), serde_json::json!({"kind": "oom"}));
                },
                false,
                "not a solver execution record",
            ),
            (
                "deadline-beside-success",
                |evidence| {
                    evidence.execution(
                        "a.x",
                        2000,
                        (2, 0),
                        serde_json::json!({
                            "kind": "deadline",
                            "last_status_message": null,
                            "cleanup_elapsed": {"seconds": 0, "nanoseconds": 5},
                            "cleanup_error": null,
                        }),
                    );
                },
                false,
                "harness a::x: its solver execution ended Deadline, its report verified it",
            ),
            (
                "exit-beside-deadline-report",
                |_| {},
                true,
                "harness a::x: its solver execution ended Exited, its report reports its deadline",
            ),
        ];
        let read = policy_of(POLICY_TEXT, &declared(&["a::x", "a::y"])).unwrap();
        for (name, plant, killed, fault) in cases {
            let evidence = RunEvidence::new(name);
            let x = if killed {
                format!(
                    "Checking harness a::x...\n{}2000 ms\nVERIFICATION:- FAILED\n",
                    outcome::KANI_DEADLINE
                )
            } else {
                block("a::x", "SUCCESSFUL")
            };
            let report = format!("{x}{}{}", block("a::y", "SUCCESSFUL"), summary(1, 1));
            plant(&evidence);
            let found = refused(
                name,
                reconcile(&evidence.root, &run_policy(&read, &Selection::All), &report),
            );
            assert!(found.contains(fault), "{name}: {found}");
        }
    }

    /// A function-scoped selector of `g`, the function of `a::y`'s loop.
    const SCOPED: &str = r#"{"function": "g", "file": "a.rs", "loops_in_function": 1,
        "loop": 0, "bound": 257, "reason": "a fixed table"}"#;

    /// The policy is read for its function scope and its harnesses, each
    /// declared and named once with at least one bound; a run of one harness
    /// carries its entry alone and every run the whole function scope.
    #[test]
    fn the_policy_names_declared_harnesses_and_selects_per_run() {
        let read = policy_of(
            &POLICY_TEXT.replace(r#""loops": [], "#, &format!(r#""loops": [{SCOPED}], "#)),
            &declared(&["a::x", "a::y"]),
        )
        .unwrap();
        assert_eq!(read.harnesses.keys().collect::<Vec<_>>(), ["a::x"]);
        assert_eq!(read.loops[0]["function"], "g");
        assert_eq!(
            run_policy(&read, &Selection::All)["harnesses"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            run_policy(&read, &Selection::one("a::x"))["harnesses"][0]["harness"],
            "a::x"
        );
        let alone = run_policy(&read, &Selection::one("a::y"));
        assert!(alone["harnesses"].as_array().unwrap().is_empty());
        assert_eq!(alone["loops"], serde_json::json!(read.loops));
        assert_eq!(
            alone["deadlines"],
            serde_json::json!([{
                "harness": "a::y",
                "milliseconds": 4000,
                "reason": "twice y",
            }])
        );
        assert_eq!(
            run_policy(&read, &Selection::All)["deadlines"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
        for (text, fault) in [
            (
                POLICY_TEXT.replace("a::x", "a::z"),
                "declared by no #[kani::proof]",
            ),
            (
                POLICY_TEXT.replace(
                    "]}\n    ]}",
                    "]}, {\"harness\": \"a::x\", \"loops\": [{}]}\n    ]}",
                ),
                "named twice",
            ),
            (
                r#"{"loops": [], "harnesses": [{"harness": "a::x", "loops": []}]}"#.to_string(),
                "no loop bound",
            ),
            (
                r#"{"loops": [], "harnesses": [{"loops": [{}]}]}"#.to_string(),
                "names no harness",
            ),
            (
                r#"{"loops": [{"bound": 1}], "harnesses": []}"#.to_string(),
                "a function-scoped selector names no function",
            ),
            (
                r#"{"loops": [], "harnesses": [], "x": 1}"#.to_string(),
                "not an object of two keys",
            ),
            (
                r#"{"harnesses": []}"#.to_string(),
                "not an object of two keys",
            ),
            (
                r#"{"loops": {}, "harnesses": []}"#.to_string(),
                "its `loops` is not a list",
            ),
            ("[".to_string(), "not JSON"),
        ] {
            let found = policy_of(&text, &declared(&["a::x", "a::y"])).unwrap_err();
            assert!(found.contains(fault), "{fault}: {found}");
        }
    }

    /// One run's evidence, laid out as Kani writes it (`--loop-bounds-
    /// evidence`): every harness's instrumented binary preserved as its
    /// `artifact.out` ([`ARTIFACTS`]) and recorded in its `artifact.json`;
    /// `a::x` bounded by [`POLICY_TEXT`]'s one selector, resolved to `f.0` on
    /// its artifact, and `a::y` unbounded; each launched on the solver
    /// `/kani/cbmc` with its own artifact.
    struct RunEvidence {
        root: std::path::PathBuf,
    }

    const DIGEST: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    /// Each harness's preserved bytes, and their SHA-256 digest computed apart
    /// from the gate (`printf %s BYTES | sha256sum`).
    const ARTIFACTS: [(&str, &[u8], &str); 2] = [
        (
            "a.x",
            b"a.x instrumented binary",
            "d96c7f46b0c37d43d5f7d38282b95dc4856d342d2b43e9a2f28adddcb2a528a7",
        ),
        (
            "a.y",
            b"a.y instrumented binary",
            "81a1a00387a63812de53900c0ae6e332b3d52fd2cc9a7b31e421abd7d674f76f",
        ),
    ];

    impl RunEvidence {
        fn new(test: &str) -> Self {
            let root = std::env::temp_dir()
                .join(format!("dcbor-gate-evidence-{test}-{}", std::process::id()));
            if root.exists() {
                std::fs::remove_dir_all(&root).unwrap();
            }
            let evidence = Self { root };
            let identity = format!(
                r#"{{"driver": {{"path": "/kani/kani-driver", "sha256": "{DIGEST}"}},
                     "solver": {{"path": "/kani/cbmc", "sha256": "{DIGEST}"}}}}"#
            );
            for (harness, bytes, digest) in ARTIFACTS {
                evidence.write(harness, "artifact.out", bytes);
                evidence.artifact_record(harness, &evidence.artifact(harness), digest);
                evidence.write(harness, "solver.attempt", b"spawning\n");
                evidence.write(harness, "solver.identity", identity.as_bytes());
            }
            evidence.command("a.x", Some("f.0:0"), &evidence.artifact("a.x"));
            evidence.command("a.y", None, &evidence.artifact("a.y"));
            let exited = serde_json::json!({"kind": "exited", "code": 0});
            evidence.execution("a.x", 2000, (0, 500_000_000), exited.clone());
            evidence.execution("a.y", 4000, (0, 500_000_000), exited);
            for (harness, function) in [("a.x", "f"), ("a.y", "g")] {
                evidence.discovery(harness, &evidence.artifact(harness));
                evidence.write(harness, "discovery.status", b"exit status: 0\n");
                evidence.write(harness, "discovery.stderr", b"");
                let inventory = serde_json::json!([
                    {"program": "goto-instrument"},
                    {"loops": [{
                        "name": format!("{function}.0"),
                        "sourceLocation": {"function": function, "file": "a.rs"},
                    }]},
                ]);
                evidence.write(
                    harness,
                    "discovery.stdout",
                    inventory.to_string().as_bytes(),
                );
            }
            evidence.resolution(&evidence.entry(), &[("f.0", 0)]);
            evidence
        }

        fn write(&self, harness: &str, file: &str, bytes: &[u8]) {
            std::fs::create_dir_all(self.root.join(harness)).unwrap();
            std::fs::write(self.root.join(harness).join(file), bytes).unwrap();
        }

        /// The preserved artifact of `harness`, where Kani writes it.
        fn artifact(&self, harness: &str) -> std::path::PathBuf {
            self.root.join(harness).join("artifact.out")
        }

        /// `harness`'s `artifact.json`, naming `path` with `digest`, copied
        /// from its build path.
        fn artifact_record(&self, harness: &str, path: &Path, digest: &str) {
            let record = serde_json::json!({
                "source": format!("/build/{harness}.out"),
                "path": path,
                "sha256": digest,
            });
            self.write(harness, "artifact.json", record.to_string().as_bytes());
        }

        /// `harness`'s solver command: the solver, `--unwindset SET` when
        /// given, the binary at `artifact`, then `--json-ui`, NUL-ended.
        fn command(&self, harness: &str, unwindset: Option<&str>, artifact: &Path) {
            let mut parts: Vec<&[u8]> = vec![b"/kani/cbmc"];
            if let Some(set) = unwindset {
                parts.extend([&b"--unwindset"[..], set.as_bytes()]);
            }
            parts.extend([artifact.as_os_str().as_encoded_bytes(), b"--json-ui"]);
            self.write(harness, "solver.arguments", &nul_ended(&parts));
        }

        /// `harness`'s solver execution record, as the driver writes it: the
        /// deadline it was given, its elapsed seconds and nanoseconds, and how
        /// it ended.
        fn execution(
            &self,
            harness: &str,
            deadline: u64,
            (seconds, nanoseconds): (u64, u64),
            termination: serde_json::Value,
        ) {
            let record = serde_json::json!({
                "deadline_milliseconds": deadline,
                "elapsed": {"seconds": seconds, "nanoseconds": nanoseconds},
                "termination": termination,
            });
            self.write(
                harness,
                "solver.execution.json",
                record.to_string().as_bytes(),
            );
        }

        /// `harness`'s loop discovery command, as the driver records it:
        /// `goto-instrument --show-loops --json-ui` on `artifact`, NUL-ended.
        fn discovery(&self, harness: &str, artifact: &Path) {
            let parts: [&[u8]; 4] = [
                b"goto-instrument",
                b"--show-loops",
                b"--json-ui",
                artifact.as_os_str().as_encoded_bytes(),
            ];
            self.write(harness, "discovery.arguments", &nul_ended(&parts));
        }

        fn entry(&self) -> serde_json::Value {
            policy_of(POLICY_TEXT, &declared(&["a::x", "a::y"]))
                .unwrap()
                .harnesses["a::x"]
                .clone()
        }

        /// `a::x`'s resolution of `policy`, each of `loops` its first
        /// selector's resolution at its bound.
        fn resolution(&self, policy: &serde_json::Value, loops: &[(&str, u64)]) {
            let resolved: Vec<serde_json::Value> = loops
                .iter()
                .map(|(id, bound)| {
                    let mut selector = policy["loops"][0].clone();
                    selector["bound"] = serde_json::json!(bound);
                    let file = selector["file"].clone();
                    serde_json::json!({
                        "selector": selector,
                        "file": file,
                        "loop": id,
                        "location": {"file": file},
                    })
                })
                .collect();
            let record = serde_json::json!({
                "harness": "a::x",
                "policy": policy,
                "function_scope": [],
                "artifact": {"path": self.artifact("a.x"), "sha256": ARTIFACTS[0].2},
                "warnings": [],
                "resolved": resolved,
            });
            self.write("a.x", "resolution.json", record.to_string().as_bytes());
        }

        /// The evidence checked against [`POLICY_TEXT`].
        fn check(&self) -> Result<Reconciled, String> {
            self.check_under(POLICY_TEXT)
        }

        /// The evidence checked against the policy `text`, both harnesses
        /// verified.
        fn check_under(&self, text: &str) -> Result<Reconciled, String> {
            let read = policy_of(text, &declared(&["a::x", "a::y"])).unwrap();
            let report = format!(
                "{}{}{}",
                block("a::x", "SUCCESSFUL"),
                block("a::y", "SUCCESSFUL"),
                summary(2, 0)
            );
            reconcile(&self.root, &run_policy(&read, &Selection::All), &report)
        }

        /// `a::y` bounded by [`SCOPED`] alone, as Kani applies a
        /// function-scoped selector whose function `a::y`'s inventory holds.
        fn scope_a_y(&self) {
            let scoped: serde_json::Value = serde_json::from_str(SCOPED).unwrap();
            let record = serde_json::json!({
                "harness": "a::y",
                "policy": null,
                "function_scope": [scoped],
                "artifact": {"path": self.artifact("a.y"), "sha256": ARTIFACTS[1].2},
                "warnings": [],
                "resolved": [{
                    "selector": scoped,
                    "file": scoped["file"],
                    "loop": "g.0",
                    "location": {"file": scoped["file"]},
                }],
            });
            self.write("a.y", "resolution.json", record.to_string().as_bytes());
            self.command("a.y", Some("g.0:257"), &self.artifact("a.y"));
        }
    }

    /// `parts` as a command record: each part ended by a NUL byte.
    fn nul_ended(parts: &[&[u8]]) -> Vec<u8> {
        parts
            .iter()
            .flat_map(|part| part.iter().copied().chain([0]))
            .collect()
    }

    impl Drop for RunEvidence {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.root).unwrap();
        }
    }

    /// Complete evidence that matches the run's policy is accepted, and names
    /// the one verifier its harnesses ran.
    #[test]
    fn matching_evidence_is_accepted() {
        let evidence = RunEvidence::new("matching");
        let reconciled = evidence.check().unwrap();
        assert_eq!(reconciled.verifier["solver"]["path"], "/kani/cbmc");
        assert!(reconciled.applied.is_empty());
    }

    /// A function-scoped selector applies in exactly the harnesses whose
    /// inventory holds its function: `a::y`, bounded by no entry of its own,
    /// must resolve it and run with its bound; omitting it, applying it where
    /// its function is absent, or resolving it without its record is refused.
    #[test]
    fn a_function_scope_applies_where_its_function_is() {
        let scoped = POLICY_TEXT.replace(r#""loops": [], "#, &format!(r#""loops": [{SCOPED}], "#));
        let evidence = RunEvidence::new("function-scope");
        let unapplied = evidence.check_under(&scoped).unwrap_err();
        assert!(
            unapplied.contains("harness a::y: ") && unapplied.contains("resolution.json"),
            "{unapplied}"
        );
        evidence.scope_a_y();
        assert_eq!(
            evidence.check_under(&scoped).unwrap().applied,
            [BTreeSet::from(["a::y".to_string()])]
        );
        let elsewhere = scoped.replace(r#""function": "g""#, r#""function": "h""#);
        let applied_elsewhere = evidence.check_under(&elsewhere).unwrap_err();
        assert!(
            applied_elsewhere.contains("harness a::y: its policy bounds no loop"),
            "{applied_elsewhere}"
        );
        let path = evidence.root.join("a.y").join("resolution.json");
        let mut record: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        record["function_scope"] = serde_json::json!([]);
        std::fs::write(&path, record.to_string()).unwrap();
        let unrecorded = evidence.check_under(&scoped).unwrap_err();
        assert!(
            unrecorded.contains("applied the function scope []"),
            "{unrecorded}"
        );
    }

    /// Kani's function-scope record must match the run's reconciled evidence
    /// exactly: each selector's harnesses those whose resolution reconciled
    /// it, nothing named that did not, and in a suite run every selector
    /// applied somewhere. A claimed harness the evidence does not support, a
    /// name that is no harness, a missing or extra selector, or an empty
    /// application in a suite is refused.
    #[test]
    fn the_function_scope_record_matches_the_reconciled_evidence() {
        let root =
            std::env::temp_dir().join(format!("dcbor-gate-function-scope-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let read = policy_of(
            &POLICY_TEXT.replace(r#""loops": [], "#, &format!(r#""loops": [{SCOPED}], "#)),
            &declared(&["a::x", "a::y"]),
        )
        .unwrap();
        let run = run_policy(&read, &Selection::All);
        let write = |record: serde_json::Value| {
            std::fs::write(root.join("function-scope.json"), record.to_string()).unwrap();
        };
        let entry = |harnesses: serde_json::Value| serde_json::json!([{"selector": read.loops[0], "harnesses": harnesses}]);
        let a_y = [BTreeSet::from(["a::y".to_string()])];
        let none = [BTreeSet::new()];
        write(entry(serde_json::json!(["a::y"])));
        check_function_scope(&root, &run, &a_y, true, Artifacts::Live).unwrap();
        check_function_scope(&root, &run, &a_y, false, Artifacts::Live).unwrap();
        for (record, applied, suite, fault) in [
            (
                entry(serde_json::json!(["nonexistent"])),
                &a_y,
                true,
                "the run's evidence reconciles it in",
            ),
            (
                entry(serde_json::json!([null])),
                &a_y,
                true,
                "the run's evidence reconciles it in",
            ),
            (
                entry(serde_json::json!(["a::y", "a::y"])),
                &a_y,
                true,
                "the run's evidence reconciles it in",
            ),
            (
                entry(serde_json::json!(["a::y"])),
                &none,
                false,
                "the run's evidence reconciles it in",
            ),
            (
                entry(serde_json::json!([])),
                &none,
                true,
                "no harness of the suite applied",
            ),
            (
                serde_json::json!([]),
                &a_y,
                true,
                "records 0 function-scoped selectors",
            ),
            (
                serde_json::json!([{"selector": {"function": "h"}, "harnesses": ["a::y"]}]),
                &a_y,
                true,
                "records the function-scoped selector",
            ),
            (
                serde_json::json!([{"selector": read.loops[0], "harnesses": ["a::y"], "x": 1}]),
                &a_y,
                true,
                "not exactly `selector` and `harnesses`",
            ),
        ] {
            write(record.clone());
            let found = refused(
                &format!("function scope {record}"),
                check_function_scope(&root, &run, applied, suite, Artifacts::Live),
            );
            assert!(found.contains(fault), "{record}: {found}");
        }
        write(entry(serde_json::json!([])));
        check_function_scope(&root, &run, &none, false, Artifacts::Live).unwrap();
        std::fs::remove_file(root.join("function-scope.json")).unwrap();
        let missing = check_function_scope(&root, &run, &a_y, true, Artifacts::Live).unwrap_err();
        assert!(missing.contains("function-scope.json"), "{missing}");
        std::fs::remove_dir_all(&root).unwrap();
    }

    /// A harness whose binary holds no loop has an inventory all the same:
    /// one inventory of no loops, beside the banner and a warning, is valid
    /// evidence, and owes no function-scoped bound.
    #[test]
    fn an_empty_inventory_is_valid_evidence() {
        let evidence = RunEvidence::new("empty-inventory");
        evidence.write(
            "a.y",
            "discovery.stdout",
            br#"[{"program": "goto-instrument"}, {"messageType": "WARNING", "messageText": "w"}, {"loops": []}]"#,
        );
        let scoped = POLICY_TEXT.replace(r#""loops": [], "#, &format!(r#""loops": [{SCOPED}], "#));
        let reconciled = evidence.check_under(&scoped).unwrap();
        assert_eq!(reconciled.applied, [BTreeSet::new()]);
    }

    /// The declared instances are each family's complete product: as many
    /// distinct instances as lengths times nesting limits times policies,
    /// each length's unwind and the family's stubs carried into the
    /// generated source, which asserts the file's domain constants.
    #[test]
    fn the_declared_instances_are_each_family_s_complete_product() {
        let counts: Vec<(&str, usize)> = instances::FAMILIES
            .iter()
            .map(|family| {
                let found = instances::instances(family).unwrap();
                assert_eq!(
                    found.len(),
                    family.lengths.len() * family.depths.len() * family.policies.len(),
                    "{}",
                    family.file
                );
                let names: BTreeSet<&str> = found.iter().map(|i| i.name.as_str()).collect();
                assert_eq!(names.len(), found.len(), "{}", family.file);
                let source = instances::generated(family).unwrap();
                assert_eq!(source.matches("#[kani::proof]").count(), found.len());
                assert_eq!(
                    source.matches("#[kani::stub(").count(),
                    found.len() * family.stubs.len()
                );
                for (len, unwind) in family.lengths {
                    let named: Vec<&instances::Instance> = found
                        .iter()
                        .filter(|i| i.call.starts_with(&format!("check::<{len}>(")))
                        .collect();
                    assert!(named.iter().all(|i| i.unwind == *unwind), "{}", family.file);
                }
                assert!(source.contains(&format!(
                    "assert!({} == {}",
                    family.longest,
                    family.lengths.len() - 1
                )));
                (family.generated, found.len())
            })
            .collect();
        assert_eq!(
            counts,
            [("decode.rs", 30), ("string.rs", 30), ("header.rs", 10)]
        );
        let decode = instances::instances(&instances::FAMILIES[0]).unwrap();
        assert_eq!(
            decode[0].name,
            "the_decode_bound_covers_inputs_of_0_bytes_at_depth_0_normalized"
        );
        assert_eq!(decode[0].call, "check::<0>(0, Normalize)");
        assert_eq!(decode[29].call, "check::<4>(2, QuickOnly)");
        assert_eq!(decode[29].unwind, 6);
    }

    /// A declaration whose axes do not cover their domain exactly, or whose
    /// names do not distinguish its instances, is refused.
    #[test]
    fn a_declaration_that_does_not_cover_its_domain_is_refused() {
        const BASE: instances::Family = instances::Family {
            file: "f.rs",
            module: "m",
            generated: "g.rs",
            name: "x_{len}_{depth}_{policy}",
            call: "check::<{len}>({depth}, {policy})",
            stubs: &[],
            lengths: &[(0, 2), (1, 3)],
            depths: &[0, 1],
            policies: &[("a", "A"), ("b", "B")],
            longest: "INPUT",
            deepest: Some("DEPTH"),
        };
        assert_eq!(instances::instances(&BASE).unwrap().len(), 8);
        for (family, fault) in [
            (
                instances::Family {
                    lengths: &[(0, 2), (2, 4)],
                    ..BASE
                },
                "its lengths [0, 2] are not every value",
            ),
            (
                instances::Family {
                    lengths: &[(1, 3)],
                    ..BASE
                },
                "its lengths [1] are not every value",
            ),
            (
                instances::Family {
                    depths: &[0, 0],
                    ..BASE
                },
                "its nesting limits [0, 0] are not every value",
            ),
            (
                instances::Family {
                    depths: &[0, 1],
                    deepest: None,
                    ..BASE
                },
                "it has no nesting axis but declares the limits [0, 1]",
            ),
            (
                instances::Family {
                    policies: &[],
                    ..BASE
                },
                "no text policy",
            ),
            (
                instances::Family {
                    name: "x_{len}_{depth}",
                    ..BASE
                },
                "the instance name x_0_0 is not distinct",
            ),
        ] {
            let found = refused(
                &format!("declaration {fault}"),
                instances::instances(&family)
                    .map(|found| found.into_iter().map(|i| i.name).collect::<Vec<_>>()),
            );
            assert!(found.contains(fault), "{fault}: {found}");
        }
    }

    /// The census finds every written harness and every generated instance,
    /// each family's file including its instances once; a missing or
    /// doubled inclusion, or a written harness that shares an instance's
    /// name, is refused.
    #[test]
    fn the_census_expects_every_declared_instance() {
        let root =
            std::env::temp_dir().join(format!("dcbor-gate-instances-{}", std::process::id()));
        let src = root.join("src");
        let write = |file: &str, text: &str| {
            let path = root.join(file);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, text).unwrap();
        };
        for family in instances::FAMILIES {
            write(family.file, &format!("{}\n", instances::inclusion(family)));
        }
        write("src/written.rs", "#[kani::proof]\nfn written() {}\n");
        let found = harnesses(&src).unwrap();
        assert_eq!(found.len(), 71);
        assert!(found.contains("written::written"));
        assert!(
            found.contains(
                "bounded::decode::header::proofs::the_header_bound_covers_heads_of_9_bytes"
            )
        );
        let header = instances::FAMILIES[2].file;
        write(header, "");
        let missing = refused("inclusion-missing", harnesses(&src));
        assert!(
            missing.contains("does not include its generated instances exactly once"),
            "{missing}"
        );
        let inclusion = instances::inclusion(&instances::FAMILIES[2]);
        write(header, &format!("{inclusion}\n{inclusion}\n"));
        let doubled = refused("inclusion-doubled", harnesses(&src));
        assert!(
            doubled.contains("does not include its generated instances exactly once"),
            "{doubled}"
        );
        write(
            header,
            &format!(
                "{inclusion}\n#[kani::proof]\nfn the_header_bound_covers_heads_of_0_bytes() {{}}\n"
            ),
        );
        let collision = refused("instance-name-collision", harnesses(&src));
        assert!(
            collision.contains("a generated instance whose name a written harness declares"),
            "{collision}"
        );
        std::fs::remove_dir_all(&root).unwrap();
    }

    /// One disagreement planted into matching [`RunEvidence`]: its name, the
    /// plant, and the fault its refusal must name.
    type Disagreement = (&'static str, fn(&RunEvidence), &'static str);

    /// Every completed harness, bounded or not, ran on the artifact its
    /// evidence preserves: its `artifact.out` and `artifact.json` exist, the
    /// preserved bytes have the recorded digest, the record names that file,
    /// the solver ran on it, and a bounded harness's resolution names the same
    /// artifact. Each disagreement is refused by its own fault.
    #[test]
    fn every_completed_harness_ran_on_its_preserved_artifact() {
        let cases: [Disagreement; 14] = [
            (
                "unbounded-discovery-missing",
                |evidence| {
                    std::fs::remove_file(evidence.root.join("a.y").join("discovery.stdout"))
                        .unwrap();
                },
                "a.y/discovery.stdout",
            ),
            (
                "discovery-failed",
                |evidence| evidence.write("a.y", "discovery.status", b"exit status: 1\n"),
                "harness a::y: the loop discovery did not exit successfully: exit status: 1",
            ),
            (
                "discovery-on-the-build-path",
                |evidence| evidence.discovery("a.y", Path::new("/build/a.y.out")),
                "harness a::y: the loop discovery ran as",
            ),
            (
                "inventory-missing",
                |evidence| evidence.write("a.y", "discovery.stdout", b"[]"),
                "harness a::y: the loop discovery holds 0 loop inventories, not one",
            ),
            (
                "inventory-twice",
                |evidence| {
                    evidence.write(
                        "a.y",
                        "discovery.stdout",
                        br#"[{"loops": []}, {"loops": []}]"#,
                    );
                },
                "harness a::y: the loop discovery holds 2 loop inventories, not one",
            ),
            (
                "inventory-error",
                |evidence| {
                    evidence.write(
                        "a.y",
                        "discovery.stdout",
                        br#"[{"messageType": "ERROR", "messageText": "no goto binary"}, {"loops": []}]"#,
                    );
                },
                "harness a::y: the loop discovery reported an error",
            ),
            (
                "inventory-unknown-record",
                |evidence| {
                    evidence.write("a.y", "discovery.stdout", br#"[{"loops": [], "extra": 1}]"#);
                },
                "harness a::y: the loop inventory holds a record of no known kind",
            ),
            (
                "unbounded-artifact-missing",
                |evidence| std::fs::remove_file(evidence.artifact("a.y")).unwrap(),
                "a.y/artifact.out",
            ),
            (
                "bounded-record-missing",
                |evidence| {
                    std::fs::remove_file(evidence.root.join("a.x").join("artifact.json")).unwrap();
                },
                "a.x/artifact.json",
            ),
            (
                "unbounded-bytes-rewritten",
                |evidence| evidence.write("a.y", "artifact.out", b"rewritten by a later run"),
                "harness a::y: the preserved artifact's bytes have digest",
            ),
            (
                "bounded-bytes-rewritten",
                |evidence| evidence.write("a.x", "artifact.out", b"rewritten by a later run"),
                "harness a::x: the preserved artifact's bytes have digest",
            ),
            (
                "record-names-the-build-path",
                |evidence| {
                    evidence.artifact_record("a.y", Path::new("/build/a.y.out"), ARTIFACTS[1].2);
                },
                "harness a::y: artifact.json names /build/a.y.out, not its preserved artifact.out",
            ),
            (
                "unbounded-solver-on-the-build-path",
                |evidence| evidence.command("a.y", None, Path::new("/build/a.y.out")),
                "harness a::y: the solver ran on another binary than the preserved",
            ),
            (
                "resolution-names-another-artifact",
                |evidence| {
                    let path = evidence.root.join("a.x").join("resolution.json");
                    let mut record: serde_json::Value =
                        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
                    record["artifact"]["path"] = serde_json::json!("/build/a.x.out");
                    std::fs::write(&path, record.to_string()).unwrap();
                },
                "harness a::x: resolution.json resolved the artifact",
            ),
        ];
        for (name, plant, fault) in cases {
            let evidence = RunEvidence::new(name);
            assert!(
                evidence.check().is_ok(),
                "{name}: the fixture itself is refused"
            );
            plant(&evidence);
            let found = refused(name, evidence.check());
            assert!(found.contains(fault), "{name}: {found}");
        }
    }

    /// A discovery selects declared harnesses, each once, and at least one:
    /// its record is the selection sorted, one harness per line, its digest
    /// the run's revision, and each harness's deadline the discovery's own.
    /// An empty, a repeated and an undeclared selection are each refused.
    #[test]
    fn a_discovery_selects_declared_harnesses_once() {
        let census = declared(&["a::x", "a::y"]);
        let discovery = discovery_of(&["a::y".to_string(), "a::x".to_string()], &census).unwrap();
        assert_eq!(discovery.bytes, b"a::x\na::y\n");
        assert_eq!(
            discovery.sha256(),
            crate::process::sha256_bytes(b"a::x\na::y\n").unwrap()
        );
        let purpose = RunPurpose::Discovery(discovery.clone());
        assert_eq!(
            (purpose.name(), purpose.revision()),
            (PURPOSE_DISCOVERY, discovery.sha256())
        );
        assert_eq!(
            purpose.documents(),
            [(DISCOVERY_RECORD, b"a::x\na::y\n".as_slice())]
        );
        let deadlines = purpose.deadlines();
        assert_eq!(deadlines.keys().collect::<Vec<_>>(), ["a::x", "a::y"]);
        assert!(deadlines.values().all(|deadline| {
            deadline.milliseconds() == DISCOVERY_MILLISECONDS
                && deadline.reason() == DISCOVERY_REASON
        }));
        for (name, selection, fault) in [
            ("discovery-empty", vec![], "a discovery selects no harness"),
            (
                "discovery-duplicate",
                vec!["a::x".to_string(), "a::x".to_string()],
                "harness a::x: selected for discovery twice",
            ),
            (
                "discovery-undeclared",
                vec!["a::z".to_string()],
                "harness a::z: selected for discovery, but declared by no #[kani::proof]",
            ),
        ] {
            let found = refused(name, discovery_of(&selection, &census));
            assert!(found.contains(fault), "{name}: {found}");
        }
    }

    /// A discovery is judged by its discovery records alone: every selected
    /// harness's directory, its preserved artifact and its discovery of that
    /// artifact, exited successfully and holding one inventory. A missing
    /// `discovery.stdout`, a nonzero `discovery.status`, a `discovery.stdout`
    /// that is not JSON and a harness the run left no directory for are each
    /// refused by their own fault.
    #[test]
    fn a_discovery_is_judged_by_its_discovery_records() {
        let discovery = discovery_of(
            &["a::x".to_string(), "a::y".to_string()],
            &declared(&["a::x", "a::y"]),
        )
        .unwrap();
        let evidence = RunEvidence::new("discovery-records");
        assert_eq!(
            check_discovery(&evidence.root, &discovery, Artifacts::Live).unwrap(),
            BTreeMap::from([
                ("a::x".to_string(), ARTIFACTS[0].2.to_string()),
                ("a::y".to_string(), ARTIFACTS[1].2.to_string()),
            ])
        );
        let cases: [Disagreement; 4] = [
            (
                "discovery-stdout-missing",
                |evidence| {
                    std::fs::remove_file(evidence.root.join("a.x").join("discovery.stdout"))
                        .unwrap();
                },
                "a.x/discovery.stdout",
            ),
            (
                "discovery-status-nonzero",
                |evidence| evidence.write("a.y", "discovery.status", b"exit status: 1\n"),
                "harness a::y: the loop discovery did not exit successfully: exit status: 1",
            ),
            (
                "discovery-stdout-not-json",
                |evidence| evidence.write("a.x", "discovery.stdout", b"no inventory"),
                "harness a::x: the loop inventory is not JSON",
            ),
            (
                "discovery-harness-missing",
                |evidence| std::fs::remove_dir_all(evidence.root.join("a.y")).unwrap(),
                "harness a::y: the run left no evidence of it",
            ),
        ];
        for (name, plant, fault) in cases {
            let evidence = RunEvidence::new(name);
            plant(&evidence);
            let found = refused(
                name,
                check_discovery(&evidence.root, &discovery, Artifacts::Live),
            );
            assert!(found.contains(fault), "{name}: {found}");
        }
    }

    /// Every disagreement between the policy given, the resolution recorded
    /// and the command spawned is refused, though the report's lines are
    /// unchanged.
    #[test]
    fn evidence_that_does_not_match_its_policy_is_refused() {
        let cases: [Disagreement; 6] = [
            (
                "policy-bound",
                |evidence| {
                    let mut policy = evidence.entry();
                    policy["loops"][0]["bound"] = serde_json::json!(7);
                    evidence.resolution(&policy, &[("f.0", 7)]);
                },
                "the run's policy is",
            ),
            (
                "solver-bound",
                |evidence| evidence.command("a.x", Some("f.0:9"), &evidence.artifact("a.x")),
                "did not run with the one --unwindset f.0:0",
            ),
            (
                "artifact",
                |evidence| evidence.command("a.x", Some("f.0:0"), Path::new("/run/other.out")),
                "harness a::x: the solver ran on another binary than the preserved",
            ),
            (
                "launch",
                |evidence| {
                    std::fs::remove_file(evidence.root.join("a.x").join("solver.attempt")).unwrap();
                },
                "harness a::x: its report has a verification result, but its solver was never \
                 launched",
            ),
            (
                "unbounded-with-unwindset",
                |evidence| evidence.command("a.y", Some("g.0:1"), &evidence.artifact("a.y")),
                "bounds no loop, its solver ran with --unwindset",
            ),
            (
                "unterminated",
                |evidence| {
                    evidence.write("a.x", "solver.arguments", b"/kani/cbmc\0--json-ui");
                },
                "not NUL-terminated",
            ),
        ];
        for (name, plant, fault) in cases {
            let evidence = RunEvidence::new(name);
            assert!(
                evidence.check().is_ok(),
                "{name}: the fixture itself is refused"
            );
            plant(&evidence);
            let found = refused(name, evidence.check());
            assert!(found.contains(fault), "{name}: {found}");
        }
    }

    /// A resolution that maps one loop twice is refused even when the
    /// recorded policy matches: each selector resolves to its own loop.
    #[test]
    fn a_loop_resolved_twice_is_refused() {
        let evidence = RunEvidence::new("twice");
        let mut policy = evidence.entry();
        let mut second = policy["loops"][0].clone();
        second["loop"] = serde_json::json!(1);
        second["loops_in_function"] = serde_json::json!(2);
        policy["loops"].as_array_mut().unwrap().push(second.clone());
        let text = serde_json::json!({ "loops": [], "harnesses": [policy.clone()] }).to_string();
        let record = serde_json::json!({
            "harness": "a::x",
            "policy": policy,
            "function_scope": [],
            "artifact": {"path": evidence.artifact("a.x"), "sha256": ARTIFACTS[0].2},
            "resolved": [
                {
                    "selector": policy["loops"][0],
                    "file": policy["loops"][0]["file"],
                    "loop": "f.0",
                    "location": {"file": policy["loops"][0]["file"]},
                },
                {
                    "selector": second,
                    "file": second["file"],
                    "loop": "f.0",
                    "location": {"file": second["file"]},
                },
            ],
        });
        evidence.write("a.x", "resolution.json", record.to_string().as_bytes());
        let found = evidence.check_under(&text).unwrap_err();
        assert!(found.contains("loop f.0 resolved twice"), "{found}");
    }

    /// The launcher a run selected is read from its file, whatever `PATH`
    /// holds afterwards; a path that is not canonical is refused.
    #[test]
    fn the_selected_launcher_is_the_file_s_not_path_s() {
        let root = std::env::temp_dir().join(format!("dcbor-gate-launcher-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let executable = std::fs::canonicalize(std::env::current_exe().unwrap()).unwrap();
        let file = root.join("kani-launcher");
        std::fs::write(&file, format!("{}\n", executable.display())).unwrap();
        assert_eq!(selected_launcher(&file).unwrap(), executable);
        let indirect = root.join("link");
        std::os::unix::fs::symlink(&executable, &indirect).unwrap();
        std::fs::write(&file, format!("{}\n", indirect.display())).unwrap();
        assert!(
            selected_launcher(&file)
                .unwrap_err()
                .contains("not the canonical path")
        );
        std::fs::remove_dir_all(&root).unwrap();
    }

    /// A run that verified every declared harness is a proved row each.
    #[test]
    fn every_declared_harness_verified_is_proved() {
        let report = format!(
            "{}{}{}",
            block("a::x", "SUCCESSFUL"),
            block("a::y", "SUCCESSFUL"),
            summary(2, 0)
        );
        let (found, faults) = rows(
            Termination::Exited(0),
            &report,
            &declared(&["a::x", "a::y"]),
        );
        assert_eq!(faults, Vec::<String>::new());
        assert!(
            found
                .iter()
                .all(|row| row.evidence == Evidence::Proved && row.outcome == Outcome::Pass)
        );
        assert_eq!(crate::rows::verdict(&found), Vec::<String>::new());
    }

    /// The planted cases: a harness the run never checked (compiled out) is
    /// not run and fails the verdict; one the source does not declare is
    /// named; an unsupported construct and a short unwind are their own
    /// outcomes; a summary that disagrees, a block without its result and an
    /// exit status that disagrees are named.
    #[test]
    fn every_harness_unchecked_or_misreported_is_named() {
        let report = format!("{}{}", block("a::x", "SUCCESSFUL"), summary(1, 0));
        let (found, faults) = rows(
            Termination::Exited(0),
            &report,
            &declared(&["a::x", "a::y"]),
        );
        assert_eq!(faults, Vec::<String>::new());
        assert_eq!(found[1].outcome, Outcome::NotRun);
        assert_eq!(
            crate::rows::verdict(&found).len(),
            1,
            "a harness never checked fails the verdict"
        );
        let (_, faults) = rows(Termination::Exited(0), &report, &declared(&["a::y"]));
        assert!(
            faults[0].contains("declared by no #[kani::proof]"),
            "{faults:?}"
        );
        let unsupported = format!(
            "Checking harness a::x...\nVERIFICATION:- FAILED\n** WARNING: {}. Check the results\n{}",
            outcome::KANI_UNSUPPORTED,
            summary(0, 1)
        );
        assert_eq!(
            checked(&unsupported).unwrap(),
            [("a::x".to_string(), Outcome::Unsupported)]
        );
        let unwound = format!(
            "Checking harness a::x...\nVERIFICATION:- FAILED\n[Kani] info: {}.\n{}",
            outcome::KANI_UNWINDING,
            summary(0, 1)
        );
        assert_eq!(
            checked(&unwound).unwrap(),
            [("a::x".to_string(), Outcome::BoundRefused)]
        );
        for incomplete_block in outcome::fixtures::kani_no_verdict_blocks("a::x") {
            let incomplete = format!(
                "{incomplete_block}{}{}",
                block("a::y", "SUCCESSFUL"),
                summary(1, 1)
            );
            assert_eq!(
                checked(&incomplete).unwrap(),
                [
                    ("a::x".to_string(), Outcome::NoVerdict),
                    ("a::y".to_string(), Outcome::Pass),
                ],
                "a harness whose CBMC run produced no results was given a verdict"
            );
            let (found, faults) = rows(
                Termination::Exited(1),
                &incomplete,
                &declared(&["a::x", "a::y"]),
            );
            assert!(faults.is_empty(), "{faults:?}");
            assert_eq!(found[0].evidence, Evidence::Unverified);
            assert_eq!(found[1].evidence, Evidence::Proved);
            assert_eq!(
                crate::rows::verdict(&found).len(),
                1,
                "the incomplete harness must fail qualification independently of the verified one"
            );
        }
        let disagree = format!("{}{}", block("a::x", "SUCCESSFUL"), summary(2, 0));
        assert!(checked(&disagree).unwrap_err().contains("summary counts"));
        assert!(
            checked("Checking harness a::x...\n")
                .unwrap_err()
                .contains("no verification result")
        );
        let (_, faults) = rows(Termination::Exited(1), &report, &declared(&["a::x"]));
        assert!(faults[0].contains("call for exit 0"), "{faults:?}");
        for malformed in [
            format!(
                "{}{}{}",
                block("a::x", "SUCCESSFUL"),
                block("a::x", "SUCCESSFUL"),
                summary(2, 0)
            ),
            format!("{}{}", block("", "SUCCESSFUL"), summary(1, 0)),
            format!("{report}{}", summary(1, 0)),
            format!("{report}VERIFICATION:- FAILED\n"),
            format!("{}{}", block("a::x", "UNKNOWN"), summary(0, 1)),
        ] {
            assert!(checked(&malformed).is_err(), "{malformed}");
            for code in [0, 1] {
                assert_eq!(
                    outcome::kani(Termination::Exited(code), &malformed),
                    Outcome::NoVerdict,
                    "an ambiguous report supplied a verdict: {malformed}"
                );
            }
        }
    }

    /// The census reads written harnesses by module path, nested inline
    /// modules included, and nothing that is not a `#[kani::proof]` function,
    /// beside every declared instance of the package's families.
    #[test]
    fn the_harness_census_reads_paths_from_files_and_modules() {
        let root = std::env::temp_dir().join(format!("dcbor-gate-proofs-{}", std::process::id()));
        if root.exists() {
            std::fs::remove_dir_all(&root).unwrap();
        }
        let src = root.join("src");
        std::fs::create_dir_all(src.join("a/b")).unwrap();
        std::fs::write(
            src.join("a/b/proofs.rs"),
            "#[kani::proof]\nfn x() {}\nmod inner { #[kani::proof] fn y() {} fn helper() {} }\n\
             // kani::proof in a comment\n#[test]\nfn not_a_harness() {}\n",
        )
        .unwrap();
        std::fs::write(src.join("a/mod.rs"), "#[kani::proof]\nfn z() {}\n").unwrap();
        std::fs::write(src.join("lib.rs"), "fn none() {}\n").unwrap();
        let mut expected = declared(&["a::b::proofs::inner::y", "a::b::proofs::x", "a::z"]);
        for family in instances::FAMILIES {
            let path = root.join(family.file);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, format!("{}\n", instances::inclusion(family))).unwrap();
            for instance in instances::instances(family).unwrap() {
                expected.insert(format!("{}::{}", family.module, instance.name));
            }
        }
        assert_eq!(harnesses(&src).unwrap(), expected);
        std::fs::remove_dir_all(&root).unwrap();
    }

    /// A directory of its own under the system's temporary directory,
    /// removed when dropped.
    struct Scratch(std::path::PathBuf);

    impl Scratch {
        fn new(test: &str) -> Self {
            let root =
                std::env::temp_dir().join(format!("dcbor-gate-{test}-{}", std::process::id()));
            if root.exists() {
                make_writable(&root);
                std::fs::remove_dir_all(&root).unwrap();
            }
            std::fs::create_dir_all(&root).unwrap();
            Self(std::fs::canonicalize(&root).unwrap())
        }

        fn write(&self, relative: &str, text: &str) -> std::path::PathBuf {
            let path = self.0.join(relative);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, text).unwrap();
            path
        }
    }

    /// Every entry under `root` made readable and writable again, so a test
    /// that removed a permission can remove its tree.
    fn make_writable(root: &Path) {
        use std::os::unix::fs::PermissionsExt;
        for entry in std::fs::read_dir(root).into_iter().flatten().flatten() {
            let path = entry.path();
            let directory = std::fs::symlink_metadata(&path).is_ok_and(|kind| kind.is_dir());
            let mode = if directory { 0o755 } else { 0o644 };
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode));
            if directory {
                make_writable(&path);
            }
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            make_writable(&self.0);
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// A cgroup hierarchy at `scratch`: the root, `/a` and `/a/b`, every
    /// controller enabled for each group's children, `/a` and `/a/b` holding
    /// `cpu.max` and `memory.max`, as a kernel's cgroup v2 mount lays them.
    fn hierarchy(scratch: &Scratch, leaf: &str) {
        scratch.write("cgroup.subtree_control", "cpuset cpu io memory pids\n");
        for group in ["a", &format!("a/{leaf}")] {
            scratch.write(
                &format!("{group}/cgroup.subtree_control"),
                "cpu memory pids\n",
            );
            scratch.write(&format!("{group}/cpu.max"), "max 100000\n");
            scratch.write(&format!("{group}/memory.max"), "1073741824\n");
        }
        scratch.write("cpuset.cpus.effective", "0-15\n");
    }

    /// An environment of the processor, affinity and cpuset of the fixture
    /// with the limits of the group `leaf` of `scratch`.
    fn observed(scratch: &Scratch, leaf: &str) -> EnvironmentRecord {
        EnvironmentRecord {
            cpu_model: Some("cpu".to_string()),
            cpus_allowed: Some("0-15".to_string()),
            cpuset_effective: effective_cpuset(&scratch.0, leaf),
            levels: limits(&scratch.0, leaf),
        }
    }

    /// Every level of a workload's hierarchy through the root is observed,
    /// innermost first, each with its path; the root's limits are absent by
    /// cgroup v2's own rule, every other level's read and validated; scopes
    /// of other names under the same limits are equivalent.
    #[test]
    fn a_workloads_every_ancestor_through_the_root_is_observed() {
        let scratch = Scratch::new("cgroup-levels");
        hierarchy(&scratch, "b");
        hierarchy(&scratch, "c");
        let environment = observed(&scratch, "/a/b");
        let paths: Vec<&str> = environment
            .levels
            .iter()
            .map(|level| level.path.as_str())
            .collect();
        assert_eq!(paths, ["/a/b", "/a", "/"]);
        assert_eq!(
            environment.levels[0].cpu_max,
            LimitObservation::Value {
                value: "max 100000".to_string()
            }
        );
        assert!(matches!(
            environment.levels[2].memory_max,
            LimitObservation::Absent { .. }
        ));
        assert_eq!(environment.cpuset_effective.as_deref(), Some("0-15"));
        assert!(environment.establish().is_ok(), "{environment:#?}");
        let other = observed(&scratch, "/a/c");
        assert_ne!(environment, other, "the scopes' paths are recorded");
        assert!(
            equivalent(&environment, &other),
            "scopes of other names under equal limits are not equivalent"
        );
    }

    /// A limit that cannot be read, a group that disappeared, a file missing
    /// though its controller is enabled, a malformed limit and an empty CPU
    /// set each leave the environment unestablished and equivalent to none;
    /// a verified absence stays distinct from an unreadable file.
    #[test]
    fn an_unestablished_limit_prevents_equivalence() {
        use std::os::unix::fs::PermissionsExt;
        let baseline = Scratch::new("cgroup-baseline");
        hierarchy(&baseline, "b");
        let reference = observed(&baseline, "/a/b");
        assert!(reference.establish().is_ok());
        type Plant = fn(&Scratch);
        let cases: [(&str, Plant, &str); 5] = [
            (
                "unreadable-parent-limit",
                |scratch| {
                    std::fs::set_permissions(
                        scratch.0.join("a/memory.max"),
                        std::fs::Permissions::from_mode(0o000),
                    )
                    .unwrap();
                },
                "Permission denied",
            ),
            (
                "disappeared-parent",
                |scratch| std::fs::remove_dir_all(scratch.0.join("a")).unwrap(),
                "the group no longer exists",
            ),
            (
                "missing-though-enabled",
                |scratch| std::fs::remove_file(scratch.0.join("a/cpu.max")).unwrap(),
                "missing, though / enables the cpu controller",
            ),
            (
                "parent-controls-unreadable",
                |scratch| {
                    std::fs::remove_file(scratch.0.join("a/b/cpu.max")).unwrap();
                    std::fs::set_permissions(
                        scratch.0.join("a/cgroup.subtree_control"),
                        std::fs::Permissions::from_mode(0o000),
                    )
                    .unwrap();
                },
                "whether its controller is enabled is unknown",
            ),
            (
                "malformed-limit",
                |scratch| {
                    scratch.write("a/b/cpu.max", "max -1\n");
                },
                "malformed",
            ),
        ];
        for (name, plant, fault) in cases {
            let scratch = Scratch::new(&format!("cgroup-{name}"));
            hierarchy(&scratch, "b");
            plant(&scratch);
            let environment = observed(&scratch, "/a/b");
            let unavailable: Vec<&str> = environment
                .levels
                .iter()
                .flat_map(|level| [&level.cpu_max, &level.memory_max])
                .filter_map(|observation| match observation {
                    LimitObservation::Unavailable { error } => Some(error.as_str()),
                    _ => None,
                })
                .collect();
            assert!(
                unavailable.iter().any(|error| error.contains(fault)),
                "{name}: no unavailable limit naming {fault:?}: {environment:#?}"
            );
            assert!(
                environment.establish().is_err(),
                "{name}: established: {environment:#?}"
            );
            assert!(
                !equivalent(&environment, &reference) && !equivalent(&reference, &environment),
                "{name}: an unestablished environment was equivalent"
            );
        }
        // A controller its parent does not enable: the file is absent by
        // rule, an established fact distinct from an unreadable file.
        let absent = Scratch::new("cgroup-not-enabled");
        hierarchy(&absent, "b");
        absent.write("a/cgroup.subtree_control", "memory pids\n");
        std::fs::remove_file(absent.0.join("a/b/cpu.max")).unwrap();
        let environment = observed(&absent, "/a/b");
        assert!(
            matches!(&environment.levels[0].cpu_max, LimitObservation::Absent { reason }
                if reason.contains("/a does not enable the cpu controller")),
            "{environment:#?}"
        );
        assert!(environment.establish().is_ok(), "{environment:#?}");
        assert!(
            !equivalent(&environment, &reference),
            "an absent limit compared equal to a value"
        );
        for (cpus_allowed, cpuset) in [("", "0-15"), ("0-15", ""), ("3-1", "0-15")] {
            let environment = EnvironmentRecord {
                cpus_allowed: Some(cpus_allowed.to_string()),
                cpuset_effective: Some(cpuset.to_string()),
                ..reference.clone()
            };
            assert!(
                environment.establish().is_err(),
                "the CPU sets {cpus_allowed:?}, {cpuset:?} established"
            );
        }
        let blank = EnvironmentRecord {
            cpu_model: Some(" ".to_string()),
            ..reference.clone()
        };
        assert!(
            blank.establish().is_err(),
            "a blank processor model established"
        );
        let rootless = EnvironmentRecord {
            levels: reference.levels[..2].to_vec(),
            ..reference.clone()
        };
        assert!(
            rootless.establish().is_err(),
            "a hierarchy without its root established"
        );
        // A stored record is held to what a live observation is: a value
        // that is no valid limit, or a hierarchy that is no ancestry, read
        // back from evidence, establishes nothing.
        let mut forged = reference.clone();
        forged.levels[0].cpu_max = LimitObservation::Value {
            value: "garbage".to_string(),
        };
        let found = refused("stored-limit-malformed", forged.establish());
        assert!(found.contains("/a/b cpu.max is Value"), "{found}");
        let mut reordered = reference.clone();
        reordered.levels.swap(0, 1);
        let found = refused("stored-ancestry-reordered", reordered.establish());
        assert!(found.contains("are not the ancestry of"), "{found}");
    }

    /// Whether the environments `one` and `other` are both established and
    /// equivalent.
    fn equivalent(one: &EnvironmentRecord, other: &EnvironmentRecord) -> bool {
        matches!((one.establish(), other.establish()), (Ok(one), Ok(other)) if one.equivalent(&other))
    }

    /// The source digest distinguishes what a delimiter-only framing or a
    /// content-only digest would not, and is the same for the same state
    /// however its entries were enumerated.
    #[test]
    fn the_source_digest_distinguishes_kinds_modes_and_partitions() {
        let file = |contents: &[u8], executable: bool| TreeEntry::File {
            executable,
            contents: contents.to_vec(),
        };
        let digest = |entries: Vec<(&str, TreeEntry)>| {
            let state = SourceState(
                entries
                    .into_iter()
                    .map(|(path, entry)| (path.as_bytes().to_vec(), entry))
                    .collect(),
            );
            let digest = state.digest().unwrap();
            assert_eq!(
                digest,
                tree_digest_of(&state.digests().unwrap()).unwrap(),
                "a state's digest is not the digest of its paths' digests"
            );
            digest
        };
        for (name, one, other) in [
            (
                "file-or-link",
                vec![("p", file(b"target", false))],
                vec![("p", TreeEntry::Link(b"target".to_vec()))],
            ),
            (
                "executable",
                vec![("p", file(b"x", true))],
                vec![("p", file(b"x", false))],
            ),
            (
                "empty-or-deleted",
                vec![("p", file(b"", false))],
                vec![("p", TreeEntry::Deleted)],
            ),
            (
                "partition",
                vec![("a", file(b"bc", false))],
                vec![("ab", file(b"c", false))],
            ),
            (
                "entry-boundary",
                vec![("a", file(b"x", false)), ("b", file(b"y", false))],
                vec![
                    ("a", file(b"x\0\0\0\0\0\0\0\x01b", false)),
                    ("b", file(b"y", false)),
                ],
            ),
        ] {
            assert_ne!(
                digest(one),
                digest(other),
                "{name}: one digest for two states"
            );
        }
        assert_eq!(
            digest(vec![("b", file(b"2", false)), ("a", file(b"1", true))]),
            digest(vec![("a", file(b"1", true)), ("b", file(b"2", false))]),
            "the enumeration's order changed the digest"
        );
        assert!(tree_stream(&BTreeMap::new()).starts_with(ENTRY_DOMAIN));
        assert_ne!(ENTRY_DOMAIN, TREE_DOMAIN);
        // Read from a tree: a link is its target, never followed; a deletion
        // is recorded only against a listing of another state.
        let scratch = Scratch::new("source-state");
        scratch.write("a", "target");
        std::os::unix::fs::symlink("target", scratch.0.join("l")).unwrap();
        let state = SourceState::read(&scratch.0).unwrap();
        assert_eq!(
            state.0[b"l".as_slice()],
            TreeEntry::Link(b"target".to_vec())
        );
        let listed = state.paths();
        std::fs::remove_file(scratch.0.join("a")).unwrap();
        let after = SourceState::read(&scratch.0)
            .unwrap()
            .with_deletions(&listed);
        assert_eq!(after.0[b"a".as_slice()], TreeEntry::Deleted);
        assert_eq!(state.changed(&after), BTreeSet::from([b"a".to_vec()]));
        std::os::unix::net::UnixListener::bind(scratch.0.join("socket")).unwrap();
        assert!(
            SourceState::read(&scratch.0)
                .unwrap_err()
                .contains("neither a regular file nor a symbolic link")
        );
    }

    /// A live run's record is absent only when the system says it is not
    /// found: one under a directory that cannot be searched is a fault, never
    /// taken for a harness that was never launched.
    #[test]
    fn a_live_record_is_absent_only_when_not_found() {
        use std::os::unix::fs::PermissionsExt;
        let scratch = Scratch::new("live-holds");
        let path = scratch.write("a.x/solver.attempt", "spawning\n");
        assert_eq!(Artifacts::Live.holds(&path), Ok(true));
        assert_eq!(
            Artifacts::Live.holds(&scratch.0.join("a.x/none")),
            Ok(false)
        );
        std::fs::set_permissions(
            scratch.0.join("a.x"),
            std::fs::Permissions::from_mode(0o000),
        )
        .unwrap();
        let found = refused("record-uninspectable", Artifacts::Live.holds(&path));
        assert!(found.contains("Permission denied"), "{found}");
    }

    /// A document is the bytes read once: its digest and its interpretation
    /// are of that buffer, whatever its path holds afterwards.
    #[test]
    fn a_document_is_the_byte_snapshot_it_was_read_as() {
        let scratch = Scratch::new("snapshot");
        let first = r#"{"version": 1, "purpose": "calibration", "harnesses": {
            "a::x": {"limit_milliseconds": 1000, "reason": "r"}}}"#;
        let path = scratch.write("plan.json", first);
        let read = plan(&path, &declared(&["a::x", "a::y"])).unwrap();
        scratch.write("plan.json", &first.replace("1000", "2000"));
        assert_eq!(read.bytes, first.as_bytes());
        assert_eq!(
            read.sha256,
            crate::process::sha256_bytes(first.as_bytes()).unwrap()
        );
        assert_ne!(read.sha256, crate::process::sha256(&path).unwrap());
        assert_eq!(read.deadlines["a::x"].milliseconds, 1000);
    }

    /// A resolved loop lies in its selector's file: a workspace selector's
    /// file exactly, a packaged selector's under an absolute package root,
    /// and in either the loop's own location. Each other placement is
    /// refused, named.
    #[test]
    fn a_resolved_loop_lies_in_its_selectors_file() {
        let workspace = serde_json::json!({"function": "f", "file": "src/a.rs"});
        let packaged = serde_json::json!({
            "function": "d",
            "package": {"name": "dep", "version": "1.0.0"},
            "file": "src/normalize.rs",
        });
        let found = |selector: &serde_json::Value, file: &str, located: &str| {
            serde_json::json!({
                "selector": selector,
                "file": file,
                "loop": "x.0",
                "location": {"file": located},
            })
        };
        let root = "/home/a/.cargo/registry/src/i/dep-1.0.0";
        let inside = format!("{root}/src/normalize.rs");
        for accepted in [
            found(&workspace, "src/a.rs", "src/a.rs"),
            found(&packaged, &inside, &inside),
        ] {
            assert_eq!(
                resolved_in_its_file("h", "x.0", &accepted),
                Ok(()),
                "{accepted}"
            );
        }
        let mut unfiled = found(&workspace, "src/a.rs", "src/a.rs");
        unfiled.as_object_mut().unwrap().remove("file");
        for (case, planted, fault) in [
            ("file-unrecorded", unfiled, "records no file"),
            (
                "file-unlocated",
                found(&workspace, "src/a.rs", "src/b.rs"),
                "is located in \"src/b.rs\", its resolution records src/a.rs",
            ),
            (
                "file-other",
                found(&workspace, "src/b.rs", "src/b.rs"),
                "resolved in src/b.rs, its selector names src/a.rs",
            ),
            (
                "package-unrooted",
                found(&packaged, "src/normalize.rs", "src/normalize.rs"),
                "resolved in src/normalize.rs, its selector names src/normalize.rs of",
            ),
            (
                "package-other-file",
                found(
                    &packaged,
                    &format!("{root}/src/other.rs"),
                    &format!("{root}/src/other.rs"),
                ),
                "its selector names src/normalize.rs of {\"name\":\"dep\",\"version\":\"1.0.0\"}",
            ),
        ] {
            let error = refused(case, resolved_in_its_file("h", "x.0", &planted));
            assert!(error.contains(fault), "{case}: {error}");
        }
    }

    /// The fixture registry's rows: a native control of each channel, a
    /// Miri control of the nightly channel and a Kani control, the last two
    /// outside a native run's selection.
    const REGISTRY: &[&str] = &[
        "n\ttests/data/controls/n.patch\tnative\tnightly\tdcbor\tall\tfast\tlib\ta::b\t-\tfailed\tboom",
        "s\ttests/data/controls/s.patch\tnative\tstable\tdcbor\tall\tfast\tlib\ta::c\t-\tfailed\tboom",
        "m\ttests/data/controls/m.patch\ttree\tnightly\tdcbor\tcustom-std-collections\tfast\tlib\ta::d\t-\tundefined_behavior\tUndefined Behavior",
        "k\ttests/data/controls/k.patch\tkani\tkani\tdcbor\t-\t-\tlib\ta::x\t-\tfailed\ta planted failure",
    ];

    /// The native control runs of commit `c`, laid out as
    /// `tests/controls.sh` leaves them: the registry ([`REGISTRY`]) under
    /// `root`, and under `logs` the nightly run's log directory, with its
    /// commit, its identity, every selected control's evidence seen red and
    /// green in a restored copy, and its final record made by the one maker
    /// ([`control_verdict`]).
    pub(crate) struct ControlRuns {
        pub(crate) nightly: std::path::PathBuf,
    }

    impl ControlRuns {
        pub(crate) fn new(root: &Path, logs: &Path) -> Self {
            let write = |path: &Path, text: &str| {
                std::fs::create_dir_all(path.parent().unwrap()).unwrap();
                std::fs::write(path, text).unwrap();
            };
            let mut table = REGISTRY.join("\n");
            table.push('\n');
            write(&root.join(crate::controls::TABLE), &table);
            for name in ["n", "s", "m", "k"] {
                write(
                    &root.join(format!("tests/data/controls/{name}.patch")),
                    "--- src/a.rs\n+++ src/a.rs\n@@ -1 +1 @@\n-pub fn a() {}\n+pub fn a() { panic!() }\n",
                );
            }
            let controls = crate::controls::registry(root).unwrap().controls;
            let run = |channel: &str| {
                let directory = logs.join(format!("controls-{channel}"));
                write(&directory.join("commit.txt"), "c\n");
                write(
                    &directory.join("identity.txt"),
                    &format!("identity-{channel}\n"),
                );
                for control in crate::controls::selected(
                    &controls,
                    channel,
                    &[crate::controls::Runner::Native],
                ) {
                    let evidence = crate::controls::directory(&directory, control);
                    for (file, text) in [
                        ("red.judged", "refused\n"),
                        ("green.judged", "restored\n"),
                        ("before.sha256", "a\n"),
                        ("planted.sha256", "b\n"),
                        ("after.sha256", "a\n"),
                    ] {
                        write(&evidence.join(file), text);
                    }
                }
                Self::record(root, &directory, channel);
                directory
            };
            Self {
                nightly: run("nightly"),
            }
        }

        /// The final record of the native run of `channel` at `directory`,
        /// written again by the one maker.
        pub(crate) fn record(root: &Path, directory: &Path, channel: &str) {
            let verdict = control_verdict(root, directory, channel, &["native"]).unwrap();
            let _ = std::fs::remove_file(directory.join("verdict.json"));
            std::fs::write(
                directory.join("verdict.json"),
                serde_json::to_vec_pretty(&verdict).unwrap(),
            )
            .unwrap();
        }
    }

    /// A control run's final record, made by the one maker
    /// ([`control_verdict`]), judges exactly the controls the registry
    /// selects for its channel and runners, in order, with its commit and
    /// identity as its runner recorded them; a control not seen red is that
    /// result's fault and the record's.
    #[test]
    fn a_control_verdict_judges_the_registrys_selection() {
        let scratch = Scratch::new("control-verdict");
        let root = scratch.0.join("tree");
        let runs = ControlRuns::new(&root, &scratch.0);
        let registry = crate::controls::registry(&root).unwrap();
        let verdict = control_verdict(&root, &runs.nightly, "nightly", &["native"]).unwrap();
        assert_eq!(
            verdict
                .results
                .iter()
                .map(|result| (result.control.as_str(), result.runner.as_str()))
                .collect::<Vec<_>>(),
            [("n", "native")],
            "the nightly native run judges its one native control, not the Miri or the Kani one"
        );
        assert_eq!(
            (verdict.commit.as_str(), verdict.identity.as_str()),
            ("c", "identity-nightly")
        );
        assert_eq!(verdict.registry_sha256, registry.sha256);
        assert!(verdict.faults.is_empty(), "{verdict:#?}");
        std::fs::write(runs.nightly.join("n/red.judged"), "n: pass\n").unwrap();
        let failed = control_verdict(&root, &runs.nightly, "nightly", &["native"]).unwrap();
        assert!(
            !failed.faults.is_empty() && failed.faults == crate::controls::faults(&failed.results),
            "control-failed: a control not seen red left no fault: {failed:#?}"
        );
    }

    /// A calibration is ready only with the workload lock held, once the
    /// system settled; its receipt is kept whether ready or not, and a ready
    /// one's bytes are the [`Ready`] every calibration run keeps. It reads no
    /// planted-control run. Another holder of the workload lock and an
    /// unsettled system each refuse it.
    #[test]
    fn a_calibration_is_ready_only_with_the_workload_lock_and_settling() {
        let scratch = Scratch::new("readiness");
        let lock_path = scratch.0.join("gate-workload.lock");
        let lock = WorkloadLock::acquire(&lock_path).unwrap();
        let found = refused("lock-held", WorkloadLock::acquire(&lock_path).map(|_| ()));
        assert!(found.contains("another gate workload holds it"), "{found}");
        let policy = SettlingPolicy {
            interval_milliseconds: 10,
            consecutive: 2,
            min_span_milliseconds: 10,
            limit: 4,
            max_running: 2,
            max_load1_hundredths: 100,
            justification: "test".to_string(),
        };
        let calm = || Ok::<_, String>("0.10 0.10 0.10 1/100 1".to_string());
        let prerequisites = Prerequisites {
            commit: "c",
            lock: &lock,
        };
        let ready = readiness(
            &scratch.0.join("ready.json"),
            &prerequisites,
            &policy,
            &mut { calm },
            &mut TestClocks::stepping(10),
        )
        .unwrap();
        assert_eq!(
            ready.bytes,
            std::fs::read(scratch.0.join("ready.json")).unwrap()
        );
        assert_eq!(
            ready.sha256,
            crate::process::sha256(&scratch.0.join("ready.json")).unwrap()
        );
        let receipt: Readiness = serde_json::from_slice(&ready.bytes).unwrap();
        receipt.validate(Some("c")).unwrap();
        assert_eq!(receipt.commit, "c");
        assert_eq!(receipt.observations.len(), 2);
        assert_eq!(
            receipt
                .workload_lock
                .as_ref()
                .map(|lock| lock.path.as_str()),
            lock_path.to_str()
        );
        let found = refused("readiness-other-commit", receipt.validate(Some("d")));
        assert!(
            found.contains("it is of commit c, the calibration's is d"),
            "{found}"
        );
        // An unsettled system: the receipt kept with every reading.
        let found = refused(
            "readiness-unsettled",
            readiness(
                &scratch.0.join("unsettled.json"),
                &prerequisites,
                &policy,
                &mut || Ok("3.00 1 1 1/1 1".to_string()),
                &mut TestClocks::stepping(10),
            ),
        );
        assert!(found.contains("is not ready"), "{found}");
        let kept: Readiness =
            serde_json::from_slice(&std::fs::read(scratch.0.join("unsettled.json")).unwrap())
                .unwrap();
        assert!(!kept.ready && kept.observations.len() == 4 && kept.commit == "c");
    }

    /// A kept readiness establishes nothing by saying it is ready. A receipt
    /// not ready or with no reading; one of no commit; one whose lock was
    /// acquired after settling began, or that held none; and one with a
    /// reading that does not read as recorded, a reading early, a window
    /// short of the minimum span, more readings than its limit, readings
    /// past its settling point or an unjustified policy is each refused.
    #[test]
    fn a_kept_readiness_is_held_to_the_one_validator() {
        valid_readiness().validate(Some("c")).unwrap();
        type Plant = fn(&mut Readiness);
        let cases: [(&str, Plant, &str); 11] = [
            ("not-ready", |r| r.ready = false, "not ready"),
            ("no-reading", |r| r.observations.clear(), "settle at None"),
            ("no-commit", |r| r.commit.clear(), "it names no commit"),
            (
                "lock-after-settling",
                |r| {
                    if let Some(lock) = r.workload_lock.as_mut() {
                        lock.acquired.seconds += 3600;
                    }
                },
                "after its first reading",
            ),
            (
                "no-lock",
                |r| r.workload_lock = None,
                "it held no workload lock",
            ),
            (
                "reading-misrecorded",
                |r| r.observations[3].loadavg = "3.00 1 1 9/100 1".to_string(),
                "reading 3 records load 10 hundredths",
            ),
            (
                "reading-early",
                |r| r.observations[4].monotonic_milliseconds -= 1,
                "reading 4 came 4999 ms after",
            ),
            (
                "span-unreachable",
                |r| r.policy.min_span_milliseconds = 30_001,
                "cannot span its minimum span",
            ),
            (
                "beyond-limit",
                |r| {
                    r.observations = settled_readings(r.observations[0].at, 8);
                    r.policy.limit = 7;
                },
                "8 readings, its policy's limit is 7",
            ),
            (
                "past-settling",
                |r| r.observations = settled_readings(r.observations[0].at, 8),
                "settle at Some(6), not at its last",
            ),
            (
                "policy-unjustified",
                |r| r.policy.justification = " ".to_string(),
                "no justification",
            ),
        ];
        for (name, plant, fault) in cases {
            let mut readiness = valid_readiness();
            plant(&mut readiness);
            let found = refused(name, readiness.validate(Some("c")));
            assert!(found.contains(fault), "{name}: {found}");
        }
    }

    /// Settling reads the system until a window of consecutive readings, all
    /// within the policy and spanning its minimum span, ends, each reading
    /// at least an interval after the one before it on the monotonic clock;
    /// a policy that can establish nothing reads nothing, its arithmetic
    /// checked.
    #[test]
    fn settling_holds_its_interval_its_window_and_its_span() {
        let policy = SettlingPolicy {
            interval_milliseconds: 10,
            consecutive: 2,
            min_span_milliseconds: 10,
            limit: 4,
            max_running: 2,
            max_load1_hundredths: 100,
            justification: "test".to_string(),
        };
        let readings = |loads: &'static [&'static str]| {
            let mut at = 0;
            move || {
                let reading = loads
                    .get(at)
                    .map(|load| load.to_string())
                    .ok_or("no reading".to_string());
                at += 1;
                reading
            }
        };
        let mut clocks = TestClocks::stepping(10);
        let (observations, settled) = settle(
            &policy,
            &mut readings(&[
                "3.00 1.00 1.00 9/100 1",
                "0.50 1.00 1.00 1/100 1",
                "0.40 1.00 1.00 2/100 1",
            ]),
            &mut clocks,
        );
        assert_eq!(settled, Ok(()));
        assert_eq!(
            observations
                .iter()
                .map(|settled| (settled.within, settled.monotonic_milliseconds))
                .collect::<Vec<_>>(),
            [(false, 0), (true, 10), (true, 20)]
        );
        assert_eq!(clocks.waited, 2);
        // Four consecutive readings within the policy and spanning thirty:
        // settled at the fourth, never earlier.
        let (observations, spanned) = settle(
            &SettlingPolicy {
                consecutive: 4,
                min_span_milliseconds: 30,
                ..policy.clone()
            },
            &mut readings(&["0.10 1 1 1/1 1"; 4]),
            &mut TestClocks::stepping(10),
        );
        assert_eq!(spanned, Ok(()));
        assert_eq!(
            observations
                .last()
                .map(|settled| settled.monotonic_milliseconds),
            Some(30)
        );
        let (observations, unsettled) = settle(
            &policy,
            &mut readings(&["3.00 1 1 1/1 1"; 4]),
            &mut TestClocks::stepping(10),
        );
        assert_eq!(observations.len(), 4);
        let found = refused("settling-unsettled", unsettled);
        assert!(
            found.contains("did not settle within 4 readings"),
            "{found}"
        );
        let (_, early) = settle(
            &policy,
            &mut readings(&["0.10 1 1 1/1 1"; 4]),
            &mut TestClocks::stepping(3),
        );
        let found = refused("settling-early", early);
        assert!(found.contains("reading 1 came 3 ms after"), "{found}");
        let (_, unreadable) = settle(
            &policy,
            &mut readings(&["garbage"]),
            &mut TestClocks::stepping(10),
        );
        let found = refused("settling-unreadable", unreadable);
        assert!(found.contains("not a /proc/loadavg reading"), "{found}");
        for (name, invalid, fault) in [
            (
                "one-reading",
                SettlingPolicy {
                    consecutive: 1,
                    ..policy.clone()
                },
                "span no time",
            ),
            (
                "no-interval",
                SettlingPolicy {
                    interval_milliseconds: 0,
                    ..policy.clone()
                },
                "no interval",
            ),
            (
                "limit-short",
                SettlingPolicy {
                    limit: 1,
                    ..policy.clone()
                },
                "below its consecutive",
            ),
            (
                "no-span",
                SettlingPolicy {
                    min_span_milliseconds: 0,
                    ..policy.clone()
                },
                "no minimum span",
            ),
            (
                "span-unreachable",
                SettlingPolicy {
                    min_span_milliseconds: 11,
                    ..policy.clone()
                },
                "cannot span its minimum span",
            ),
            (
                "span-overflow",
                SettlingPolicy {
                    interval_milliseconds: u64::MAX,
                    consecutive: 3,
                    ..policy.clone()
                },
                "does not fit in u64",
            ),
            (
                "unjustified",
                SettlingPolicy {
                    justification: " ".to_string(),
                    ..policy.clone()
                },
                "no justification",
            ),
        ] {
            let (observations, settled) = settle(
                &invalid,
                &mut readings(&["0.10 1 1 1/1 1"; 4]),
                &mut TestClocks::stepping(10),
            );
            assert!(observations.is_empty(), "{name}");
            let found = refused(name, settled);
            assert!(
                found.contains("establishes nothing") && found.contains(fault),
                "{name}: {found}"
            );
        }
        settling_policy().validate().unwrap();
        assert!(
            !settling_policy()
                .justification
                .contains("no other workload"),
            "the policy claims what it cannot establish"
        );
    }

    /// A test's clocks: the system's wall clock, so its readings follow the
    /// control runs and the lock they are ordered against, and a monotonic
    /// clock that a wait advances by `step` milliseconds, every wait counted.
    pub(crate) struct TestClocks {
        step: u64,
        monotonic: u64,
        waited: usize,
    }

    impl TestClocks {
        pub(crate) fn stepping(step: u64) -> Self {
            Self {
                step,
                monotonic: 0,
                waited: 0,
            }
        }
    }

    impl Clocks for TestClocks {
        fn now(&mut self) -> Result<Instant, String> {
            now()
        }

        fn monotonic_milliseconds(&mut self) -> Result<u64, String> {
            Ok(self.monotonic)
        }

        fn wait(&mut self, _: std::time::Duration) {
            self.monotonic += self.step;
            self.waited += 1;
        }
    }

    /// A tree, a Kani launcher standing in for `cargo kani` and the
    /// repository's confinement, for runs through the one Kani invocation
    /// (`process::kani`): the tree's library declares `x` and `y`; the
    /// launcher writes each checked harness's records as the driver does,
    /// verifies every harness but those `failing` names, and first runs
    /// `plant`, shell given the run's evidence directory as `$evidence`.
    struct KaniFixture {
        scratch: Scratch,
        root: std::path::PathBuf,
        logs: std::path::PathBuf,
        target: std::path::PathBuf,
        workload: crate::process::Workload,
    }

    impl KaniFixture {
        fn new(test: &str) -> Self {
            let scratch = Scratch::new(&format!("kani-{test}"));
            let root = scratch.0.join("tree");
            let write = |relative: &str, text: &str| {
                let path = root.join(relative);
                std::fs::create_dir_all(path.parent().unwrap()).unwrap();
                std::fs::write(path, text).unwrap();
            };
            write(
                "src/lib.rs",
                "#[kani::proof]\nfn x() {}\n#[kani::proof]\nfn y() {}\n",
            );
            for family in instances::FAMILIES {
                write(family.file, &format!("{}\n", instances::inclusion(family)));
            }
            write(POLICY, r#"{"loops": [], "harnesses": []}"#);
            let confine = scratch.write(
                "bin/confine",
                &format!(
                    "#!/bin/sh\nDCBOR_GATE_MEMORY=1G exec {} \"$@\"\n",
                    Path::new(env!("CARGO_MANIFEST_DIR"))
                        .join("../workload.sh")
                        .display()
                ),
            );
            executable(&confine);
            std::fs::create_dir_all(scratch.0.join("logs")).unwrap();
            Self {
                logs: scratch.0.join("logs"),
                target: scratch.0.join("target"),
                workload: crate::process::Workload::at(confine),
                root,
                scratch,
            }
        }

        /// Predictions of every harness of the fixture's census, each
        /// calibrated on its own fixture artifact under `verifier` in
        /// `environment`, `milliseconds` predicting each: a post-validation
        /// fixture for runs of the whole census.
        fn census_predictions(
            &self,
            environment: EstablishedEnvironment,
            verifier: &serde_json::Value,
            milliseconds: impl Fn(&str) -> u64,
        ) -> Expectations {
            Expectations {
                sha256: crate::process::sha256_bytes(b"predictions").unwrap(),
                bytes: b"predictions".to_vec(),
                environment,
                harnesses: self
                    .declared()
                    .into_iter()
                    .map(|harness| {
                        let expectation = Expectation {
                            milliseconds: milliseconds(&harness),
                            transfer: "t".to_string(),
                            deadline_milliseconds: 1000,
                            calibration_runs: BTreeSet::new(),
                            artifact_sha256: crate::process::sha256_bytes(
                                format!("{harness} instrumented binary").as_bytes(),
                            )
                            .unwrap(),
                            verifier: verifier.clone(),
                        };
                        (harness, expectation)
                    })
                    .collect(),
            }
        }

        /// The launcher of this fixture's runs: each harness it is given,
        /// or every harness of the census when it is given none, given
        /// `deadline` milliseconds, those of `failing` failing.
        fn launcher(
            &self,
            name: &str,
            deadline: u64,
            failing: &str,
            plant: &str,
        ) -> std::path::PathBuf {
            let census = self.declared().into_iter().collect::<Vec<_>>().join(" ");
            let path = self.scratch.write(
                &format!("bin/{name}"),
                &format!(
                    r#"#!/bin/sh
set -eu
sleep 0.3
harnesses= bounds=
while [ $# -gt 0 ]; do
  case "$1" in
    --harness) harnesses="$harnesses $2"; shift ;;
    --loop-bounds-evidence) bounds=$2; shift ;;
  esac
  shift
done
[ -n "$harnesses" ] || harnesses="{census}"
evidence=$(dirname "$bounds")
{plant}
verified=0 failures=0
for harness in $harnesses; do
d="$bounds/$(printf %s "$harness" | sed 's/::/./g')"
mkdir -p "$d"
printf '%s instrumented binary' "$harness" > "$d/artifact.out"
sha=$(sha256sum < "$d/artifact.out" | cut -d' ' -f1)
printf '{{"source": "/build/%s.out", "path": "%s", "sha256": "%s"}}' "$harness" "$d/artifact.out" "$sha" > "$d/artifact.json"
printf 'spawning\n' > "$d/solver.attempt"
printf '/fixture/cbmc\000%s\000--json-ui\000' "$d/artifact.out" > "$d/solver.arguments"
printf '{{"driver": {{"path": "/fixture/kani-driver", "sha256": "{DIGEST}"}}, "solver": {{"path": "/fixture/cbmc", "sha256": "{DIGEST}"}}}}' > "$d/solver.identity"
printf 'goto-instrument\000--show-loops\000--json-ui\000%s\000' "$d/artifact.out" > "$d/discovery.arguments"
printf 'exit status: 0\n' > "$d/discovery.status"
: > "$d/discovery.stderr"
printf '[{{"program": "goto-instrument"}}, {{"loops": []}}]' > "$d/discovery.stdout"
printf '{{"deadline_milliseconds": {deadline}, "elapsed": {{"seconds": 0, "nanoseconds": 5000000}}, "termination": {{"kind": "exited", "code": 0}}}}' > "$d/solver.execution.json"
case "$harness" in
  {failing}) result=FAILED failed=1 ;;
  *) result=SUCCESSFUL failed=0 ;;
esac
printf 'Checking harness %s...\nSUMMARY:\n ** %s of 3 failed\n\nVERIFICATION:- %s\n' "$harness" "$failed" "$result"
verified=$((verified + 1 - failed)) failures=$((failures + failed))
done
printf '[]' > "$bounds/function-scope.json"
printf 'Manual Harness Summary:\nComplete - %s successfully verified harnesses, %s failures, %s total.\n' "$verified" "$failures" $((verified + failures))
exit $((failures > 0))
"#
                ),
            );
            executable(&path);
            path
        }

        fn declared(&self) -> BTreeSet<String> {
            harnesses(&self.root.join("src")).unwrap()
        }

        /// The calibration purpose of a plan giving `x` and `y` each
        /// `limit` milliseconds.
        fn plan(&self, limit: u64) -> (std::path::PathBuf, Plan) {
            let path = self.scratch.write(
                "plan.json",
                &format!(
                    r#"{{"version": 1, "purpose": "calibration", "harnesses": {{
                        "x": {{"limit_milliseconds": {limit}, "reason": "fixture"}},
                        "y": {{"limit_milliseconds": {limit}, "reason": "fixture"}}}}}}"#
                ),
            );
            let read = plan(&path, &self.declared()).unwrap();
            (path, read)
        }

        /// A settling policy the fixture's readings meet at once: two
        /// readings one millisecond apart.
        fn settling() -> SettlingPolicy {
            SettlingPolicy {
                interval_milliseconds: 1,
                consecutive: 2,
                min_span_milliseconds: 1,
                limit: 2,
                max_running: u64::MAX,
                max_load1_hundredths: u64::MAX,
                justification: "test".to_string(),
            }
        }

        /// The commit `c` recorded in the fixture's logs, as
        /// tests/proofs.sh records the clean commit a calibration runs on.
        fn commit(&self) {
            self.scratch.write("logs/commit.txt", "c\n");
        }

        /// The fixture's workload lock.
        fn lock_path(&self) -> std::path::PathBuf {
            self.scratch.0.join("gate-workload.lock")
        }

        /// The fixture's load reading: `scratch/loadavg` when a test wrote
        /// one, a calm system otherwise.
        fn loadavg(&self) -> Result<String, String> {
            let path = self.scratch.0.join("loadavg");
            match std::fs::read_to_string(&path) {
                Ok(text) => Ok(text),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    Ok("0.10 0.10 0.10 1/100 1".to_string())
                }
                Err(error) => Err(format!("{}: {error}", path.display())),
            }
        }

        /// The readiness of a calibration of commit `c`, made by the one
        /// maker ([`readiness`]) with the workload lock held.
        fn ready(&self) -> Ready {
            self.commit();
            let lock = WorkloadLock::acquire(&self.lock_path()).unwrap();
            readiness(
                &self.scratch.0.join("ready.json"),
                &Prerequisites {
                    commit: "c",
                    lock: &lock,
                },
                &Self::settling(),
                &mut || self.loadavg(),
                &mut TestClocks::stepping(1),
            )
            .unwrap()
        }

        /// A calibration of the fixture's plan at `plan` by `launcher`, of
        /// commit `c`, its records under the fixture's logs, its last record
        /// written as in operation.
        fn calibrate(&self, plan: &Path, launcher: &Path) -> Result<Schedule, String> {
            self.calibrate_recording(plan, launcher, &crate::process::create_evidence)
        }

        /// A calibration as [`Self::calibrate`] runs one, its last record
        /// written by `record`.
        fn calibrate_recording(
            &self,
            plan: &Path,
            launcher: &Path,
            record: &calibration::RecordWriter<'_>,
        ) -> Result<Schedule, String> {
            self.commit();
            calibration(
                CalibrationRequest {
                    root: &self.root,
                    plan,
                    target_dir: &self.target,
                    logs: &self.logs,
                    launcher,
                    workload_lock: &self.lock_path(),
                },
                Runtime {
                    workload: &self.workload,
                    settling: &Self::settling(),
                    sample: &mut || self.loadavg(),
                    clocks: &mut TestClocks::stepping(1),
                    record,
                },
            )
        }

        /// The schedule the calibration kept (`calibration.json`).
        fn schedule(&self) -> Schedule {
            typed(
                strict_json(&std::fs::read(self.logs.join("calibration.json")).unwrap()).unwrap(),
                "calibration.json",
            )
            .unwrap()
        }

        /// One run of `purpose` checking `selection`, logged at `log`.
        fn run(
            &self,
            purpose: &RunPurpose,
            selection: &Selection,
            log: &str,
            launcher: &Path,
            workload: &crate::process::Workload,
        ) -> Result<(Termination, String), String> {
            self.execute(purpose, selection, log, launcher, workload, &|_| {})
        }

        /// One run of `purpose` checking `selection`, logged at `log`: its
        /// request validated, `between` given its reserved evidence before
        /// the one invocation executes it.
        fn execute(
            &self,
            purpose: &RunPurpose,
            selection: &Selection,
            log: &str,
            launcher: &Path,
            workload: &crate::process::Workload,
            between: &dyn Fn(&Path),
        ) -> Result<(Termination, String), String> {
            let declared = self.declared();
            let log = self.logs.join(log);
            let run = crate::process::KaniRequest {
                root: &self.root,
                purpose,
                selection,
                declared: &declared,
                target_dir: &self.target,
                launcher,
                workload,
                log: &log,
            }
            .validate()?;
            between(run.evidence());
            crate::process::execute_kani(run)
        }

        /// The JSON record `relative` of the run logged at `log`.
        fn record(&self, log: &str, relative: &str) -> serde_json::Value {
            let path = self
                .logs
                .join(log)
                .with_extension("evidence")
                .join(relative);
            strict_json(
                &std::fs::read(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display())),
            )
            .unwrap()
        }

        /// The manifest of the run logged at `log`.
        fn manifest(&self, log: &str) -> ManifestDocument {
            typed(self.record(log, "manifest.json"), "manifest.json").unwrap()
        }
    }

    fn executable(path: &Path) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    /// A calibration runs each planned harness alone, one Kani run each with
    /// its own identity, plan snapshot, launch environment and load; repeats
    /// only a harness that verified, to its samples; and keeps its readiness
    /// and its schedule. The document each run was given is kept beside its
    /// identity, its digest the identity's revision, and a change to it
    /// fails its manifest.
    #[test]
    fn a_calibration_runs_each_harness_alone_and_repeats_only_the_verified() {
        let fixture = KaniFixture::new("calibration");
        let launcher = fixture.launcher("cargo-kani", 60000, "y", "");
        let (plan_path, _) = fixture.plan(60000);
        let schedule = fixture.calibrate(&plan_path, &launcher).unwrap();
        assert_eq!(
            schedule,
            fixture.schedule(),
            "the kept schedule is not the one returned"
        );
        let ran: Vec<(&str, usize, &Observed)> = schedule
            .executions
            .iter()
            .map(|run| (run.harness.as_str(), run.pass, &run.observed))
            .collect();
        assert_eq!(ran.len(), 2 * SAMPLES, "{ran:#?}");
        let mut sampled = BTreeSet::new();
        for at in [0, 2, 4] {
            match ran[at] {
                (
                    "x",
                    pass,
                    Observed::Sample {
                        run,
                        manifest_sha256,
                    },
                ) if pass == at / 2 + 1 => {
                    assert!(
                        sampled.insert((run, manifest_sha256)),
                        "a sample reused: {ran:#?}"
                    );
                }
                _ => panic!("a verified harness was not sampled at every pass: {ran:#?}"),
            }
        }
        assert!(
            matches!(ran[1], ("y", 1, Observed::Ineligible { reason })
                if reason.contains("a calibration sample is one verified execution of y alone")),
            "a failed execution was a sample: {ran:#?}"
        );
        for at in [3, 5] {
            assert!(
                matches!(ran[at], ("y", _, Observed::Withheld { reason }) if reason.contains("pass 1 of y")),
                "a failed first observation was repeated, or its repetition went unrecorded: \
                 {ran:#?}"
            );
        }
        assert_eq!(
            schedule.incomplete,
            BTreeSet::from(["y".to_string()]),
            "an incomplete calibration was reported complete"
        );
        assert!(schedule.faults.is_empty(), "{:?}", schedule.faults);
        assert!(!schedule.complete());
        let journal = std::fs::read_to_string(fixture.logs.join("calibration.jsonl")).unwrap();
        assert_eq!(journal.lines().count(), 2 * SAMPLES, "{journal}");
        let logs = ["calibration/x.1.log", "calibration/y.1.log"];
        let identities: Vec<RunIdentityRecord> = logs
            .iter()
            .map(|log| typed(fixture.record(log, "run.json"), "run.json").unwrap())
            .collect();
        assert_ne!(
            identities[0].id, identities[1].id,
            "two runs shared one identity"
        );
        let readiness = std::fs::read(fixture.logs.join(READINESS_RECORD)).unwrap();
        for (log, identity) in logs.iter().zip(&identities) {
            let launch: Launch = typed(fixture.record(log, "launch.json"), "launch.json").unwrap();
            assert!(
                launch.load_before.is_some() && launch.load_after.is_some(),
                "{log}: {launch:?}"
            );
            assert!(
                launch.environment.establish().is_ok(),
                "{log}: {:#?}",
                launch.environment
            );
            let evidence = fixture.logs.join(log).with_extension("evidence");
            assert_eq!(
                std::fs::read(evidence.join(READINESS_RECORD)).unwrap(),
                readiness,
                "{log}: a calibration run did not keep its readiness"
            );
            let kept = std::fs::read(
                fixture
                    .logs
                    .join(log)
                    .with_extension("evidence")
                    .join("plan.json"),
            )
            .unwrap_or_else(|error| {
                panic!("document-unretained: {log} kept no plan.json: {error}")
            });
            assert_eq!(kept, std::fs::read(&plan_path).unwrap());
            assert_eq!(
                crate::process::sha256_bytes(&kept).unwrap(),
                identity.revision
            );
            assert!(fixture.manifest(log).complete, "{log}");
        }
        assert!(fixture.logs.join("readiness.json").is_file());
        assert!(fixture.logs.join("calibration.json").is_file());
        // A kept document changed afterwards fails its manifest.
        let evidence = fixture.logs.join("calibration/x.1.evidence");
        let manifest = read_manifest(&evidence, Some(&identities[0].id)).unwrap();
        std::fs::write(evidence.join("plan.json"), b"{}").unwrap();
        let records = manifest.records(&evidence, Binaries::Held);
        let found = refused(
            "document-mutated",
            records.read(&evidence.join("plan.json")),
        );
        assert!(found.contains("the manifest records"), "{found}");
    }

    /// A Kani run's request is validated, and every input it binds read,
    /// before anything of the run is reserved: a selection of no harness, a
    /// harness no `#[kani::proof]` declares, a launcher that no longer
    /// resolves to itself, an empty census, a calibration of more than one
    /// harness, a qualification of less than the whole census, a harness
    /// its purpose gives no deadline, a discovery run of another selection
    /// than the one it was made for, and a tree whose policy cannot be read
    /// are each refused with nothing reserved; a valid request reserves its
    /// evidence, and its validation binds the tree's policy and source state.
    #[test]
    fn a_kani_request_is_validated_before_anything_is_reserved() {
        let fixture = KaniFixture::new("request");
        let launcher = fixture.launcher("cargo-kani", 60000, "none", "");
        let (_, plan) = fixture.plan(60000);
        let ready = fixture.ready();
        let purpose = RunPurpose::Calibration {
            plan,
            ready: ready.clone(),
        };
        let only_x = RunPurpose::Calibration {
            plan: plan_of(
                br#"{"version": 1, "purpose": "calibration", "harnesses": {
                    "x": {"limit_milliseconds": 60000, "reason": "fixture"}}}"#,
                &fixture.declared(),
            )
            .unwrap(),
            ready,
        };
        let qualification = RunPurpose::Qualification(fixture.census_predictions(
            fixture_environment().establish().unwrap(),
            &fixture_verifier(),
            |_| 1000,
        ));
        let declared = fixture.declared();
        let discovering =
            RunPurpose::Discovery(discovery_of(&["x".to_string()], &declared).unwrap());
        let none = BTreeSet::new();
        let validated = |purpose: &RunPurpose,
                         selection: &Selection,
                         declared: &BTreeSet<String>,
                         launcher: &Path,
                         log: &str| {
            crate::process::KaniRequest {
                root: &fixture.root,
                purpose,
                selection,
                declared,
                target_dir: &fixture.target,
                launcher,
                workload: &fixture.workload,
                log: &fixture.logs.join(log),
            }
            .validate()
            .map(|_| ())
        };
        let linked = fixture.scratch.0.join("bin/linked-kani");
        std::os::unix::fs::symlink(&launcher, &linked).unwrap();
        let both = Selection::Only(declared.clone());
        for (name, purpose, selection, census, launcher, fault) in [
            (
                "selects-nothing",
                &purpose,
                Selection::Only(BTreeSet::new()),
                &declared,
                launcher.as_path(),
                "selects no harness",
            ),
            (
                "undeclared",
                &purpose,
                Selection::one("z"),
                &declared,
                launcher.as_path(),
                "harness z: declared by no #[kani::proof]",
            ),
            (
                "launcher-moved",
                &purpose,
                Selection::one("x"),
                &declared,
                linked.as_path(),
                "now resolves to",
            ),
            (
                "census-empty",
                &purpose,
                Selection::All,
                &none,
                launcher.as_path(),
                "declares no #[kani::proof] harness",
            ),
            (
                "calibration-two",
                &purpose,
                both.clone(),
                &declared,
                launcher.as_path(),
                "a calibration run checks exactly one harness",
            ),
            (
                "qualification-partial",
                &qualification,
                Selection::one("x"),
                &declared,
                launcher.as_path(),
                "a qualification checks the whole census",
            ),
            (
                "unplanned",
                &only_x,
                Selection::one("y"),
                &declared,
                launcher.as_path(),
                "the run's purpose gives no deadline: [\"y\"]",
            ),
            (
                "discovery-foreign",
                &discovering,
                Selection::one("y"),
                &declared,
                launcher.as_path(),
                "a discovery checks exactly the harnesses it was made for",
            ),
        ] {
            let found = refused(name, validated(purpose, &selection, census, launcher, name));
            assert!(found.contains(fault), "{name}: {found}");
        }
        let policy_path = fixture.root.join(POLICY);
        let policy_text = std::fs::read(&policy_path).unwrap();
        std::fs::remove_file(&policy_path).unwrap();
        let found = refused(
            "policy-unreadable",
            validated(
                &purpose,
                &Selection::one("x"),
                &declared,
                &launcher,
                "policy",
            ),
        );
        std::fs::write(&policy_path, &policy_text).unwrap();
        assert!(found.contains("loop-bounds.json"), "{found}");
        let reserved = || -> Vec<String> {
            let mut found: Vec<String> = std::fs::read_dir(&fixture.logs)
                .unwrap()
                .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
                .filter(|name| name.ends_with(".evidence"))
                .collect();
            found.sort();
            found
        };
        assert!(
            reserved().is_empty(),
            "a refused request reserved {:?}",
            reserved()
        );
        validated(
            &purpose,
            &Selection::one("x"),
            &declared,
            &launcher,
            "valid.log",
        )
        .unwrap();
        validated(
            &qualification,
            &Selection::All,
            &declared,
            &launcher,
            "census.log",
        )
        .unwrap();
        assert_eq!(reserved(), ["census.evidence", "valid.evidence"]);
        let found = refused(
            "reserved-twice",
            validated(
                &purpose,
                &Selection::one("x"),
                &declared,
                &launcher,
                "valid.log",
            ),
        );
        assert!(found.contains("valid.evidence: File exists"), "{found}");
        // What validation bound is what the run records: the policy file's
        // bytes as read, and the source state its per-path digests are of.
        fixture
            .execute(
                &purpose,
                &Selection::one("x"),
                "bound.log",
                &launcher,
                &fixture.workload,
                &|_| std::fs::write(fixture.root.join("src/other.rs"), "").unwrap(),
            )
            .map(|_| ())
            .unwrap_err();
        std::fs::remove_file(fixture.root.join("src/other.rs")).unwrap();
        let identity: RunIdentityRecord =
            typed(fixture.record("bound.log", "run.json"), "run.json").unwrap();
        let sources: BTreeMap<String, String> =
            typed(fixture.record("bound.log", SOURCES_RECORD), SOURCES_RECORD).unwrap();
        assert_eq!(identity.tree_sha256, tree_digest_of(&sources).unwrap());
        assert!(!sources.contains_key("src/other.rs"));
        assert_eq!(
            std::fs::read(fixture.logs.join("bound.evidence").join(LOOP_POLICY_RECORD)).unwrap(),
            policy_text
        );
        assert_eq!(
            identity.loop_policy_sha256,
            crate::process::sha256_bytes(&policy_text).unwrap()
        );
    }

    /// A calibration holds the checkout's workload lock until its last
    /// record is written: while `calibration.json` is being written another
    /// acquisition is refused, and once the calibration returned one
    /// succeeds.
    #[test]
    fn a_calibration_holds_the_workload_lock_through_its_last_record() {
        let fixture = KaniFixture::new("lock-through-last-record");
        let launcher = fixture.launcher("cargo-kani", 60000, "none", "");
        let (plan_path, _) = fixture.plan(60000);
        let lock_path = fixture.lock_path();
        let attempts = std::cell::RefCell::new(Vec::new());
        let record = |path: &Path, bytes: &[u8]| {
            attempts
                .borrow_mut()
                .push(WorkloadLock::acquire(&lock_path).map(|_| ()));
            crate::process::create_evidence(path, bytes)
        };
        let schedule = fixture
            .calibrate_recording(&plan_path, &launcher, &record)
            .unwrap();
        assert!(schedule.complete(), "{schedule:#?}");
        let attempts = attempts.into_inner();
        assert!(
            matches!(attempts.as_slice(), [Err(fault)] if fault.contains("another gate workload holds it")),
            "lock-released-early: another workload acquired the lock while the calibration wrote \
             its last record: {attempts:?}"
        );
        WorkloadLock::acquire(&lock_path).unwrap();
    }

    /// A calibration's schedule is its last record whatever failed: its
    /// readiness refused (a load reading failed, another gate workload
    /// holding the lock, or the receipt unpreservable beside a refused
    /// prerequisite, both faults kept), or its journal not reservable, each
    /// records every planned execution as never run, keeps every fault,
    /// writes `calibration.json`, and reports the calibration failed;
    /// nothing runs.
    #[test]
    fn a_failed_calibration_still_records_its_schedule() {
        let planned = |schedule: &Schedule| {
            schedule
                .executions
                .iter()
                .map(|run| (run.harness.clone(), run.pass))
                .collect::<Vec<_>>()
        };
        let expected: Vec<(String, usize)> = (1..=SAMPLES)
            .flat_map(|pass| [("x".to_string(), pass), ("y".to_string(), pass)])
            .collect();
        type Plant = fn(&KaniFixture) -> Option<std::fs::File>;
        // The fixture's policy admits every load (`KaniFixture::settling`):
        // a reading that is no `/proc/loadavg` reading refuses settling.
        const UNREADABLE: &str = "no load reading";
        let cases: [(&str, Plant, &[&str], bool); 4] = [
            (
                "load-unreadable",
                |fixture| {
                    fixture.scratch.write("loadavg", UNREADABLE);
                    None
                },
                &["a load reading failed"],
                false,
            ),
            (
                "workload-competing",
                |fixture| {
                    let held = std::fs::File::create(fixture.lock_path()).unwrap();
                    held.try_lock().unwrap();
                    Some(held)
                },
                &["another gate workload holds it"],
                false,
            ),
            (
                // The prerequisite refused and its receipt unpreservable:
                // neither fault hides the other.
                "readiness-unrecordable",
                |fixture| {
                    fixture.scratch.write("loadavg", UNREADABLE);
                    std::fs::write(fixture.logs.join(READINESS_RECORD), "another run's\n").unwrap();
                    None
                },
                &[
                    "a load reading failed",
                    "the readiness was not preserved either",
                    "readiness.json: File exists",
                ],
                false,
            ),
            (
                "journal-unreservable",
                |fixture| {
                    std::fs::write(fixture.logs.join("calibration.jsonl"), "another run's\n")
                        .unwrap();
                    None
                },
                &["calibration.jsonl: File exists"],
                true,
            ),
        ];
        for (name, plant, faults, ready) in cases {
            let fixture = KaniFixture::new(&format!("failed-{name}"));
            let launcher = fixture.launcher("cargo-kani", 60000, "none", "exit 99");
            let (plan_path, _) = fixture.plan(60000);
            fixture.commit();
            let _held = plant(&fixture);
            let found = refused(name, fixture.calibrate(&plan_path, &launcher));
            let kept = fixture.schedule();
            for fault in faults {
                assert!(found.contains(fault), "{name}: {fault}: {found}");
                assert!(
                    kept.faults.iter().any(|recorded| recorded.contains(fault)),
                    "{name}: {fault}: {kept:#?}"
                );
            }
            assert_eq!(planned(&kept), expected, "{name}: {kept:#?}");
            assert!(
                kept.executions
                    .iter()
                    .all(|run| matches!(run.observed, Observed::NotRun { .. })),
                "{name}: an execution ran: {kept:#?}"
            );
            assert_eq!(kept.readiness_sha256.is_some(), ready, "{name}");
            assert!(kept.plan_sha256.is_some() && !kept.complete(), "{name}");
            assert!(
                !fixture.logs.join("calibration").exists(),
                "{name}: a run was scheduled"
            );
            if name == "journal-unreservable" {
                assert_eq!(
                    std::fs::read_to_string(fixture.logs.join("calibration.jsonl")).unwrap(),
                    "another run's\n",
                    "another run's journal was written to"
                );
            }
        }
    }

    /// Every failure after a run's evidence directory exists leaves its
    /// judgement and a manifest describing exactly what it recorded: setup
    /// failing before the identity, before the log, at the spawn, at
    /// reconciliation and at the predictions, and its own receipts failing
    /// to be written. None is a calibration sample, and a manifest that
    /// could not be written fails a run that would otherwise be accepted.
    #[test]
    fn every_failed_run_keeps_its_judgement_and_its_manifest() {
        let fixture = KaniFixture::new("finalization");
        let launcher = fixture.launcher("cargo-kani", 60000, "none", "");
        let (_, plan) = fixture.plan(60000);
        let ready = fixture.ready();
        let purpose = RunPurpose::Calibration {
            plan,
            ready: ready.clone(),
        };
        let judged = |log: &str| fixture.record(log, "judgement.json");
        let x = Selection::one("x");
        // An accepted calibration, whose environment the predictions below
        // are of.
        fixture
            .run(&purpose, &x, "accepted.log", &launcher, &fixture.workload)
            .unwrap();
        assert_eq!(
            judged("accepted.log"),
            serde_json::json!({"status": "accepted"})
        );
        let launch: Launch =
            typed(fixture.record("accepted.log", "launch.json"), "launch.json").unwrap();
        let verifier = fixture.record("accepted.log", "execution.json")["verifier"].clone();
        let declared = fixture.declared();
        // Before the identity: the run's own plan record unwritable once
        // its evidence was reserved.
        let found = refused(
            "before-identity",
            fixture.execute(
                &purpose,
                &x,
                "identity.log",
                &launcher,
                &fixture.workload,
                &|evidence| std::fs::create_dir(evidence.join(PLAN_RECORD)).unwrap(),
            ),
        );
        assert!(found.contains(PLAN_RECORD), "{found}");
        let manifest = fixture.manifest("identity.log");
        assert_eq!(judged("identity.log")["status"], "rejected");
        assert_eq!(
            (manifest.run.as_deref(), &manifest.log),
            (None, &LogRecord::Missing)
        );
        assert!(!manifest.complete);
        assert!(
            manifest.files.contains_key(LAUNCHER_RECORD)
                && !manifest.files.contains_key("run.json")
        );
        // Before the log: the run's invocation record unwritable.
        let found = refused(
            "before-log",
            fixture.execute(
                &purpose,
                &x,
                "log.log",
                &launcher,
                &fixture.workload,
                &|evidence| std::fs::create_dir(evidence.join(INVOCATION_RECORD)).unwrap(),
            ),
        );
        assert!(found.contains(INVOCATION_RECORD), "{found}");
        let manifest = fixture.manifest("log.log");
        assert!(manifest.run.is_some() && manifest.log == LogRecord::Missing && !manifest.complete);
        assert!(!fixture.logs.join("log.log").exists());
        // A harness the plan gives no limit is refused before anything of
        // the run is reserved.
        let only_x = plan_of(
            br#"{"version": 1, "purpose": "calibration", "harnesses": {
                "x": {"limit_milliseconds": 60000, "reason": "fixture"}}}"#,
            &declared,
        )
        .unwrap();
        let unplanned = RunPurpose::Calibration {
            plan: only_x,
            ready,
        };
        let found = refused(
            "unplanned",
            fixture.run(
                &unplanned,
                &Selection::one("y"),
                "unplanned.log",
                &launcher,
                &fixture.workload,
            ),
        );
        assert!(found.contains("gives no deadline"), "{found}");
        assert!(!fixture.logs.join("unplanned.evidence").exists());
        // At the spawn: no confinement to launch it.
        let found = refused(
            "at-spawn",
            fixture.run(
                &purpose,
                &x,
                "spawn.log",
                &launcher,
                &crate::process::Workload::at("/nonexistent/confine"),
            ),
        );
        assert!(
            found.contains("/nonexistent/confine") || found.contains("No such file"),
            "{found}"
        );
        assert!(fixture.record("spawn.log", "launcher.execution.json")["spawn_error"].is_string());
        let manifest = fixture.manifest("spawn.log");
        assert!(matches!(manifest.log, LogRecord::Present { .. }));
        assert_eq!(judged("spawn.log")["status"], "rejected");
        // At reconciliation: a report with no driver records.
        let unrecorded = fixture.launcher(
            "unrecorded",
            60000,
            "none",
            "printf 'Checking harness x...\\nVERIFICATION:- SUCCESSFUL\\n'; exit 0",
        );
        let found = refused(
            "at-reconciliation",
            fixture.run(
                &purpose,
                &x,
                "reconcile.log",
                &unrecorded,
                &fixture.workload,
            ),
        );
        assert!(
            found.contains("summary") || found.contains("solver"),
            "{found}"
        );
        assert_eq!(judged("reconcile.log")["status"], "rejected");
        assert!(
            fixture
                .manifest("reconcile.log")
                .files
                .contains_key("launch.json")
        );
        // At the predictions: a qualification of the whole census whose `x`
        // ran over its prediction keeps its reconciled execution, its
        // rejection and its manifest.
        let predicted = fixture.census_predictions(
            launch.environment.establish().unwrap(),
            &verifier,
            |harness| if harness == "x" { 0 } else { 1000 },
        );
        let qualifying = fixture.launcher("qualifying", 1000, "none", "");
        let found = refused(
            "over-prediction",
            fixture.run(
                &RunPurpose::Qualification(predicted),
                &Selection::All,
                "overrun.log",
                &qualifying,
                &fixture.workload,
            ),
        );
        assert!(found.contains("more than its predicted 0 ms"), "{found}");
        assert!(fixture.record("overrun.log", "execution.json")["verifier"].is_object());
        assert_eq!(judged("overrun.log")["status"], "rejected");
        assert!(
            fixture
                .manifest("overrun.log")
                .files
                .contains_key("execution.json")
        );
        // Its own judgement unwritable: the manifest is still attempted.
        let judgement = fixture.launcher(
            "judgement",
            60000,
            "none",
            ": > \"$evidence/judgement.json\"",
        );
        let found = refused(
            "judgement-unwritable",
            fixture.run(&purpose, &x, "judgement.log", &judgement, &fixture.workload),
        );
        assert!(found.contains("judgement.json"), "{found}");
        assert!(
            fixture
                .manifest("judgement.log")
                .files
                .contains_key("judgement.json")
        );
        // Its manifest unwritable: an otherwise accepted run fails.
        let manifest = fixture.launcher(
            "manifest",
            60000,
            "none",
            "mkdir \"$evidence/manifest.json\"",
        );
        let found = refused(
            "manifest-unwritable",
            fixture.run(&purpose, &x, "manifest.log", &manifest, &fixture.workload),
        );
        assert!(
            found.contains("the run's manifest was not written"),
            "{found}"
        );
        assert_eq!(
            judged("manifest.log"),
            serde_json::json!({"status": "accepted"})
        );
        // Its source changed while it ran: the run is of no one source.
        let library = fixture.root.join("src/lib.rs");
        let source = std::fs::read(&library).unwrap();
        let moving = fixture.launcher("moving", 60000, "none", "printf '// x\\n' >> src/lib.rs");
        let found = refused(
            "source-moved",
            fixture.run(&purpose, &x, "moved.log", &moving, &fixture.workload),
        );
        std::fs::write(&library, source).unwrap();
        assert!(found.contains("the run is of no one source"), "{found}");
        assert_eq!(judged("moved.log")["status"], "rejected");
        // The accepted calibration is a sample by the one authority; none of
        // the failed runs is one, and adoption refuses each outright.
        ran_sample(&fixture.logs.join("accepted.log"), &declared).unwrap();
        for log in [
            "log.log",
            "spawn.log",
            "reconcile.log",
            "overrun.log",
            "judgement.log",
            "manifest.log",
            "moved.log",
        ] {
            let sample = ran_sample(&fixture.logs.join(log), &declared);
            assert!(
                sample.is_err(),
                "{log}: a failed run is a sample: {sample:?}"
            );
            let evidence = fixture.logs.join(log).with_extension("evidence");
            let adopted = adopt(&evidence, &fixture.root);
            assert!(
                matches!(adopted, Err(Adoption::Refused(_))),
                "{log}: a failed run was adopted: {adopted:?}"
            );
        }
        let adopted = adopt(&fixture.logs.join("identity.evidence"), &fixture.root);
        assert!(
            matches!(&adopted, Err(Adoption::Refused(why)) if why.contains("run.json")),
            "before-identity-adopted: {adopted:?}"
        );
    }

    /// A discovery runs through the one Kani invocation: it keeps its
    /// selection beside its identity, of purpose discovery and that
    /// selection's digest; gives each harness the discovery's deadline; is
    /// accepted on its discovery records with its manifest complete; and is
    /// never a calibration sample, nor adopted.
    #[test]
    fn a_discovery_run_is_kept_and_is_never_a_sample() {
        let fixture = KaniFixture::new("discovery");
        let launcher = fixture.launcher("cargo-kani", DISCOVERY_MILLISECONDS, "none", "");
        let declared = fixture.declared();
        let discovery = discovery_of(&["x".to_string()], &declared).unwrap();
        let purpose = RunPurpose::Discovery(discovery.clone());
        fixture
            .run(
                &purpose,
                &Selection::one("x"),
                "discovery.log",
                &launcher,
                &fixture.workload,
            )
            .unwrap();
        assert_eq!(
            fixture.record("discovery.log", "judgement.json"),
            serde_json::json!({"status": "accepted"})
        );
        let identity: RunIdentityRecord =
            typed(fixture.record("discovery.log", "run.json"), "run.json").unwrap();
        assert_eq!(
            (identity.purpose.as_str(), identity.revision.as_str()),
            (PURPOSE_DISCOVERY, discovery.sha256())
        );
        let evidence = fixture.logs.join("discovery.evidence");
        assert_eq!(
            std::fs::read(evidence.join(DISCOVERY_RECORD)).unwrap(),
            b"x\n"
        );
        assert_eq!(
            fixture.record("discovery.log", "loop-bounds.json")["deadlines"],
            serde_json::json!([{
                "harness": "x",
                "milliseconds": DISCOVERY_MILLISECONDS,
                "reason": DISCOVERY_REASON,
            }])
        );
        assert!(evidence.join("loop-bounds/x/discovery.stdout").is_file());
        assert!(fixture.manifest("discovery.log").complete);
        let sample = ran_sample(&fixture.logs.join("discovery.log"), &declared);
        let found = refused("discovery-sampled", sample);
        assert!(
            found.contains("of purpose discovery"),
            "discovery-sampled: {found}"
        );
        let adopted = adopt(&evidence, &fixture.root);
        assert!(
            matches!(&adopted, Err(Adoption::Refused(why)) if why.contains("only a calibration is adopted")),
            "discovery-adopted: {adopted:?}"
        );
    }
}
