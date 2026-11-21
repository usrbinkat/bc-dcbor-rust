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

/// Each harness's expected verification time, relative to the root a run
/// verifies: an object of one entry per `#[kani::proof]` of the census
/// ([`harnesses`]), each exactly `milliseconds`, the expected wall-clock time
/// of its CBMC run, and `derivation`, why its domain costs that, from the
/// instance's own size, loops and formula, scrutinized against that domain,
/// never a measurement copied in as it stands. A run gives each harness a
/// deadline of [`DEADLINE_MARGIN`] times its expectation ([`selected`]); a
/// harness whose recorded CBMC run, from immediately after its spawn to its
/// end, took longer than its expectation fails the run though it met its
/// deadline ([`check_expectations`]). A run that exceeds either shows that the
/// harness is wrongly sized for its expectation, that the expectation is
/// wrong, or that the code it checks regressed. An expectation is never
/// raised solely to turn a failed run green: a correction needs its own
/// justification, the failed run's evidence is kept, and the run is
/// repeated.
pub const EXPECTATIONS: &str = "tests/data/proofs/expectations.json";

/// The operational margin of every deadline over its expectation: the operator's direction that a
/// harness's deadline is twice its expected wall-clock time. A policy value, not a derivation;
/// defined here once, applied once ([`expectations_of`]).
pub const DEADLINE_MARGIN: u64 = 2;

/// One harness's expectation ([`EXPECTATIONS`]) and the deadline it gives the harness,
/// [`DEADLINE_MARGIN`] times it, computed once when the expectation is read.
#[derive(Clone, Debug, PartialEq)]
pub struct Expectation {
    pub milliseconds: u64,
    pub derivation: String,
    pub deadline_milliseconds: u64,
}

/// The expectations of the tree at `root` ([`expectations_of`]).
pub fn expectations(
    root: &Path,
    declared: &BTreeSet<String>,
) -> Result<BTreeMap<String, Expectation>, String> {
    let path = root.join(EXPECTATIONS);
    let text =
        std::fs::read_to_string(&path).map_err(|error| format!("{}: {error}", path.display()))?;
    expectations_of(&text, declared).map_err(|fault| format!("{}: {fault}", path.display()))
}

/// The expectations of the text `text`, exactly one of every harness of
/// `declared`. Refused when it is not an object, when an entry is not
/// exactly `milliseconds`, a positive integer whose double fits, and
/// `derivation`, a non-blank text; when a harness of `declared` has none; or
/// when an entry names a harness that is not one.
pub fn expectations_of(
    text: &str,
    declared: &BTreeSet<String>,
) -> Result<BTreeMap<String, Expectation>, String> {
    let document: serde_json::Value =
        serde_json::from_str(text).map_err(|error| format!("not JSON: {error}"))?;
    let object = document
        .as_object()
        .ok_or("not an object of one expectation per harness")?;
    let mut found = BTreeMap::new();
    for (harness, entry) in object {
        if !declared.contains(harness) {
            return Err(format!(
                "harness {harness}: an expectation, but declared by no #[kani::proof] of the source"
            ));
        }
        let keys: Vec<&str> = entry
            .as_object()
            .map(|object| object.keys().map(String::as_str).collect())
            .unwrap_or_default();
        let milliseconds = entry["milliseconds"]
            .as_u64()
            .filter(|milliseconds| *milliseconds > 0);
        let deadline_milliseconds =
            milliseconds.and_then(|milliseconds| milliseconds.checked_mul(DEADLINE_MARGIN));
        let derivation = entry["derivation"]
            .as_str()
            .filter(|derivation| !derivation.trim().is_empty());
        let (
            ["derivation", "milliseconds"],
            Some(milliseconds),
            Some(deadline_milliseconds),
            Some(derivation),
        ) = (
            keys.as_slice(),
            milliseconds,
            deadline_milliseconds,
            derivation,
        )
        else {
            return Err(format!(
                "harness {harness}: its expectation is not exactly a positive `milliseconds`, \
                 whose deadline fits, and a non-blank `derivation`: {entry}"
            ));
        };
        found.insert(
            harness.clone(),
            Expectation {
                milliseconds,
                derivation: derivation.to_string(),
                deadline_milliseconds,
            },
        );
    }
    let missing: Vec<&String> = declared
        .iter()
        .filter(|harness| !found.contains_key(*harness))
        .collect();
    if !missing.is_empty() {
        return Err(format!("harnesses with no expectation: {missing:?}"));
    }
    Ok(found)
}

/// Each harness's solver execution as its record states it, reconciled
/// ([`check_execution_evidence`]), checked against its expectation: a
/// harness whose CBMC run, from immediately after its spawn to its end, took
/// longer than its expectation fails the run though it met its deadline.
/// Equality passes; any excess fails. The report's rendered time is not
/// read: its precision cannot change the classification. A harness killed at
/// its deadline has no completed duration and is its own fault
/// ([`outcome::kani`]). A harness over its expectation shows that it is
/// wrongly sized for it, that the expectation is wrong, or that the code it
/// checks regressed; an expectation is never raised solely to turn the run
/// green.
pub fn check_expectations(
    reconciled: &Reconciled,
    expectations: &BTreeMap<String, Expectation>,
) -> Result<(), String> {
    for (name, elapsed) in &reconciled.completed {
        let expectation = expectations
            .get(name)
            .ok_or_else(|| format!("harness {name}: checked, but has no expectation"))?;
        let expected = std::time::Duration::from_millis(expectation.milliseconds);
        if *elapsed > expected {
            return Err(format!(
                "harness {name}: its CBMC run took {elapsed:?}, more than its expected {} ms \
                 ({}): the harness is wrongly sized for its expectation, the expectation is \
                 wrong, or the code it checks regressed",
                expectation.milliseconds, expectation.derivation
            ));
        }
    }
    Ok(())
}

/// How one recorded solver execution ended (`solver.execution.json`'s
/// `termination`, kani-driver `loop_bounds.rs` `SolverTermination`).
#[derive(Clone, Copy, Debug, PartialEq)]
enum Ended {
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
fn execution(at: &Path, deadline: u64) -> Result<(std::time::Duration, Ended), String> {
    let path = at.join("solver.execution.json");
    let text = std::fs::read(&path).map_err(|error| format!("{}: {error}", path.display()))?;
    let record: serde_json::Value =
        serde_json::from_slice(&text).map_err(|error| format!("{}: {error}", path.display()))?;
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

/// The policy of the tree at `root` ([`policy_of`]).
pub fn policy(root: &Path, declared: &BTreeSet<String>) -> Result<Policy, String> {
    let path = root.join(POLICY);
    let text =
        std::fs::read_to_string(&path).map_err(|error| format!("{}: {error}", path.display()))?;
    policy_of(&text, declared).map_err(|fault| format!("{}: {fault}", path.display()))
}

/// The policy of the text `text`. Refused when it is not an object of
/// exactly `loops` and `harnesses`, both lists; when a function-scoped
/// selector names no function; when a harness entry names no harness or
/// declares no bound; when a harness is named twice; or when one is not a
/// `#[kani::proof]` of `declared`: a renamed or removed harness would
/// otherwise lose its bounds without notice.
pub fn policy_of(text: &str, declared: &BTreeSet<String>) -> Result<Policy, String> {
    let document: serde_json::Value =
        serde_json::from_str(text).map_err(|error| format!("not JSON: {error}"))?;
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

/// The policy of a run that checks `selected`: every function-scoped
/// selector, and the entries of the harnesses it checks, every one when it
/// checks the whole suite (`None`). Kani's compiler keeps only the harnesses a
/// run's filters select, and Kani refuses a policy naming one it does not
/// verify, so a run of one harness carries that harness's entry alone.
///
/// Each harness the run checks is given its deadline, twice its expectation
/// ([`EXPECTATIONS`]), the derivation its reason.
pub fn selected(
    policy: &Policy,
    expectations: &BTreeMap<String, Expectation>,
    selected: Option<&str>,
) -> serde_json::Value {
    let chosen = |harness: &str| selected.is_none_or(|selected| selected == harness);
    let harnesses: Vec<&serde_json::Value> = policy
        .harnesses
        .iter()
        .filter(|(harness, _)| chosen(harness))
        .map(|(_, entry)| entry)
        .collect();
    let deadlines: Vec<serde_json::Value> = expectations
        .iter()
        .filter(|(harness, _)| chosen(harness))
        .map(|(harness, expectation)| {
            serde_json::json!({
                "harness": harness,
                "milliseconds": expectation.deadline_milliseconds,
                "reason": format!(
                    "{DEADLINE_MARGIN} times the expected {} ms: {}",
                    expectation.milliseconds, expectation.derivation
                ),
            })
        })
        .collect();
    serde_json::json!({ "loops": policy.loops, "harnesses": harnesses, "deadlines": deadlines })
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
fn discovered(at: &Path, artifact: &str) -> Result<BTreeSet<String>, String> {
    let read = |file: &str| {
        let path = at.join(file);
        std::fs::read(&path).map_err(|error| format!("{}: {error}", path.display()))
    };
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

/// What a run's evidence reconciles to ([`check_execution_evidence`]): the
/// verifier its harnesses ran, `solver.identity`'s value (`null` when no
/// harness reached verification), and, for each function-scoped selector of
/// the run's policy in its order, the harnesses whose reconciled resolution
/// applied it; and each harness whose CBMC run ended by itself, with its
/// recorded duration from immediately after spawn to its end
/// (`solver.execution.json`), what [`check_expectations`] compares.
#[derive(Debug, PartialEq)]
pub struct Reconciled {
    pub verifier: serde_json::Value,
    pub applied: Vec<BTreeSet<String>>,
    pub completed: BTreeMap<String, std::time::Duration>,
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
        if !at.join("solver.attempt").exists() {
            if verified {
                return Err(format!(
                    "harness {name}: its report has a verification result, but its solver was \
                     never launched"
                ));
            }
            continue;
        }
        let (elapsed, ended) =
            execution(&at, deadline).map_err(|fault| format!("harness {name}: {fault}"))?;
        let read = |file: &str| {
            let path = at.join(file);
            std::fs::read(&path)
                .map_err(|error| format!("harness {name}: {}: {error}", path.display()))
        };
        let json = |file: &str| -> Result<serde_json::Value, String> {
            serde_json::from_slice(&read(file)?)
                .map_err(|error| format!("harness {name}: {file}: {error}"))
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
        // The binary the harness ran on: the copy its evidence preserves, its
        // record naming that file, its bytes the recorded digest, and the
        // solver's command naming it.
        let preserved = at.join("artifact.out");
        let record = json("artifact.json")?;
        let recorded_path = record["path"]
            .as_str()
            .ok_or_else(|| format!("harness {name}: artifact.json names no path"))?;
        let names_the_copy = Path::new(recorded_path) == preserved
            || std::fs::canonicalize(recorded_path)
                .ok()
                .zip(std::fs::canonicalize(&preserved).ok())
                .is_some_and(|(recorded, copy)| recorded == copy);
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
        let actual = crate::process::sha256(&preserved)
            .map_err(|fault| format!("harness {name}: {fault}"))?;
        if actual != recorded_digest {
            return Err(format!(
                "harness {name}: the preserved artifact's bytes have digest {actual}, \
                 artifact.json records {recorded_digest}"
            ));
        }
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
        let functions =
            discovered(&at, recorded_path).map_err(|fault| format!("harness {name}: {fault}"))?;
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
    }
    Ok(Reconciled {
        verifier: verifier.unwrap_or(serde_json::Value::Null),
        applied,
        completed,
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
) -> Result<(), String> {
    let path = directory.join("function-scope.json");
    let fault = |fault: String| format!("{}: {fault}", path.display());
    let text = std::fs::read(&path).map_err(|error| fault(error.to_string()))?;
    let record: Vec<serde_json::Value> =
        serde_json::from_slice(&text).map_err(|error| fault(error.to_string()))?;
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
    if declared.is_empty() {
        return Err("the library declares no #[kani::proof] harness".to_string());
    }
    let loop_bounds = policy(root, &declared)?;
    let expected = expectations(root, &declared)?;
    let (termination, report) =
        crate::process::run_kani_suite(root, &loop_bounds, &expected, target_dir, log, launcher)?;
    Ok(rows(termination, &report, &declared))
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
mod tests {
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

    /// The expectations of the fixture's two harnesses.
    const EXPECTATIONS_TEXT: &str = r#"{
        "a::x": {"milliseconds": 1000, "derivation": "one loop of f"},
        "a::y": {"milliseconds": 2000, "derivation": "one loop of g"}
    }"#;

    fn expected() -> BTreeMap<String, Expectation> {
        expectations_of(EXPECTATIONS_TEXT, &declared(&["a::x", "a::y"])).unwrap()
    }

    /// Every declared harness has exactly one expectation, a positive time
    /// and a derivation; anything else is refused.
    #[test]
    fn every_harness_has_one_derived_expectation() {
        assert_eq!(
            expected()["a::y"],
            Expectation {
                milliseconds: 2000,
                derivation: "one loop of g".to_string(),
                deadline_milliseconds: 2000 * DEADLINE_MARGIN,
            }
        );
        for (text, fault) in [
            (
                r#"{"a::x": {"milliseconds": 1, "derivation": "d"}}"#.to_string(),
                "harnesses with no expectation: [\"a::y\"]",
            ),
            (
                EXPECTATIONS_TEXT.replace("a::y", "a::z"),
                "harness a::z: an expectation, but declared by no #[kani::proof]",
            ),
            (
                EXPECTATIONS_TEXT.replace("1000", "0"),
                "harness a::x: its expectation is not exactly",
            ),
            (
                EXPECTATIONS_TEXT.replace("1000", "18446744073709551615"),
                "harness a::x: its expectation is not exactly",
            ),
            (
                EXPECTATIONS_TEXT.replace("one loop of f", " "),
                "harness a::x: its expectation is not exactly",
            ),
            (
                EXPECTATIONS_TEXT.replace(
                    r#""derivation": "one loop of f""#,
                    r#""derivation": "d", "x": 1"#,
                ),
                "harness a::x: its expectation is not exactly",
            ),
            (
                "[]".to_string(),
                "not an object of one expectation per harness",
            ),
            ("{".to_string(), "not JSON"),
        ] {
            let found = expectations_of(&text, &declared(&["a::x", "a::y"])).unwrap_err();
            assert!(found.contains(fault), "{fault}: {found}");
        }
    }

    /// A recorded duration equal to its expectation passes and one nanosecond
    /// more fails, though the run met its deadline; a harness the run did not
    /// complete is not compared.
    #[test]
    fn a_harness_over_its_expectation_fails_at_one_nanosecond() {
        let reconciled = |elapsed: std::time::Duration| Reconciled {
            verifier: serde_json::Value::Null,
            applied: Vec::new(),
            completed: BTreeMap::from([("a::x".to_string(), elapsed)]),
        };
        let expected_x = std::time::Duration::from_millis(1000);
        check_expectations(&reconciled(expected_x), &expected()).unwrap();
        let found = refused(
            "one-nanosecond-over",
            check_expectations(
                &reconciled(expected_x + std::time::Duration::from_nanos(1)),
                &expected(),
            ),
        );
        assert!(
            found.contains(
                "harness a::x: its CBMC run took 1.000000001s, more than its expected 1000 ms"
            ),
            "{found}"
        );
        let none = Reconciled {
            verifier: serde_json::Value::Null,
            applied: Vec::new(),
            completed: BTreeMap::new(),
        };
        check_expectations(&none, &expected()).unwrap();
    }

    /// The report's rendered verification time has no effect: the recorded
    /// duration alone is compared, so a report that rounds or misstates it
    /// changes nothing.
    #[test]
    fn the_rendered_time_cannot_change_the_classification() {
        let evidence = RunEvidence::new("rendered-time");
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
            let reconciled = check_execution_evidence(
                &evidence.root,
                &selected(&read, &expected(), None),
                &report,
            )
            .unwrap();
            assert_eq!(reconciled.completed["a::x"], std::time::Duration::new(1, 1));
            let found = check_expectations(&reconciled, &expected()).unwrap_err();
            assert!(
                found.contains("harness a::x: its CBMC run took"),
                "{shown}: {found}"
            );
        }
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
            let reconciled = check_execution_evidence(
                &evidence.root,
                &selected(&read, &expected(), None),
                &report,
            );
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
            check_execution_evidence(&evidence.root, &selected(&read, &expected(), None), &report)
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
                check_execution_evidence(
                    &evidence.root,
                    &selected(&read, &expected(), None),
                    &report,
                ),
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
            selected(&read, &expected(), None)["harnesses"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            selected(&read, &expected(), Some("a::x"))["harnesses"][0]["harness"],
            "a::x"
        );
        let alone = selected(&read, &expected(), Some("a::y"));
        assert!(alone["harnesses"].as_array().unwrap().is_empty());
        assert_eq!(alone["loops"], serde_json::json!(read.loops));
        assert_eq!(
            alone["deadlines"],
            serde_json::json!([{
                "harness": "a::y",
                "milliseconds": 4000,
                "reason": "2 times the expected 2000 ms: one loop of g",
            }])
        );
        assert_eq!(
            selected(&read, &expected(), None)["deadlines"]
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
                    serde_json::json!({"selector": selector, "loop": id, "location": {}})
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
            check_execution_evidence(&self.root, &selected(&read, &expected(), None), &report)
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
                "resolved": [{"selector": scoped, "loop": "g.0", "location": {}}],
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
        let run = selected(&read, &expected(), None);
        let write = |record: serde_json::Value| {
            std::fs::write(root.join("function-scope.json"), record.to_string()).unwrap();
        };
        let entry = |harnesses: serde_json::Value| serde_json::json!([{"selector": read.loops[0], "harnesses": harnesses}]);
        let a_y = [BTreeSet::from(["a::y".to_string()])];
        let none = [BTreeSet::new()];
        write(entry(serde_json::json!(["a::y"])));
        check_function_scope(&root, &run, &a_y, true).unwrap();
        check_function_scope(&root, &run, &a_y, false).unwrap();
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
                check_function_scope(&root, &run, applied, suite),
            );
            assert!(found.contains(fault), "{record}: {found}");
        }
        write(entry(serde_json::json!([])));
        check_function_scope(&root, &run, &none, false).unwrap();
        std::fs::remove_file(root.join("function-scope.json")).unwrap();
        let missing = check_function_scope(&root, &run, &a_y, true).unwrap_err();
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
                {"selector": policy["loops"][0], "loop": "f.0"},
                {"selector": second, "loop": "f.0"},
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
}
