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
/// [`HARNESS_TIMEOUT`], which Kani 0.68.0 accepts only with it
/// (kani-driver `args/mod.rs`, `harness-timeout`).
pub const UNSTABLE: &[&str] = &["-Z", "stubbing", "-Z", "unstable-options"];

/// The bound on each harness's CBMC run (kani-driver 0.68.0 `call_cbmc.rs`
/// `run_cbmc_piped`: the run is killed when it is reached). A harness that
/// reaches it ends without a verdict ([`Outcome::NoVerdict`]), never a pass
/// nor a refusal, so a symbolic execution that does not terminate fails its
/// run instead of holding the gate. This operational deadline does not
/// establish a proof bound or turn an incomplete check into evidence.
pub const HARNESS_TIMEOUT: &[&str] = &["--harness-timeout", "30m"];

/// The `cargo` arguments that make the build and run every harness in it:
/// the package's library alone, under [`FEATURES`], with [`UNSTABLE`] and
/// [`HARNESS_TIMEOUT`]. Each
/// option is one `cargo kani` declares (kani-driver/src/args/cargo.rs:
/// `--package`, and `--no-default-features`, `--features` in
/// `CargoCommonArgs`; `--lib` in `CargoTargetArgs`, which with `--lib`
/// includes the library and no test target, `include_lib`, `include_tests`;
/// `-Z` in the common options).
pub fn arguments() -> Vec<&'static str> {
    let mut arguments = vec!["kani", "--package", "dcbor", "--lib"];
    arguments.extend_from_slice(FEATURES);
    arguments.extend_from_slice(UNSTABLE);
    arguments.extend_from_slice(HARNESS_TIMEOUT);
    arguments
}

/// The proof suite's loop-bound policy, relative to the root a run verifies:
/// the one maintained declaration of harness-scoped loop bounds, read from the
/// tree being verified (a control's copy included, so a planted change to a
/// bound reaches its run). Its selectors, bounds and reasons are Kani's to
/// validate and resolve against each harness's instrumented binary
/// (nix/kani-driver-loop-bounds.patch, `kani-driver/src/loop_bounds.rs`);
/// the gate reads only which harnesses it bounds and how many bounds each
/// declares, to select a run's entries and to check its report.
pub const POLICY: &str = "tests/data/proofs/loop-bounds.json";

/// The policy's entries: each harness it bounds, with its entry as the file
/// holds it. Refused when the file is not `{"harnesses": [...]}`, when an
/// entry names no harness or declares no bound, when a harness is named
/// twice, or when one is not a `#[kani::proof]` of `declared`: a renamed or
/// removed harness would otherwise lose its bounds without notice.
pub fn policy(
    root: &Path,
    declared: &BTreeSet<String>,
) -> Result<BTreeMap<String, serde_json::Value>, String> {
    let path = root.join(POLICY);
    let text =
        std::fs::read_to_string(&path).map_err(|error| format!("{}: {error}", path.display()))?;
    policy_of(&text, declared).map_err(|fault| format!("{}: {fault}", path.display()))
}

/// [`policy`] of the policy text `text`.
pub fn policy_of(
    text: &str,
    declared: &BTreeSet<String>,
) -> Result<BTreeMap<String, serde_json::Value>, String> {
    let document: serde_json::Value =
        serde_json::from_str(text).map_err(|error| format!("not JSON: {error}"))?;
    let entries = match document.as_object() {
        Some(object) if object.len() == 1 => object
            .get("harnesses")
            .and_then(serde_json::Value::as_array)
            .ok_or("its one key is not `harnesses`, a list")?,
        _ => return Err("not an object of one key, `harnesses`".to_string()),
    };
    let mut found = BTreeMap::new();
    for entry in entries {
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
        if found.insert(harness.to_string(), entry.clone()).is_some() {
            return Err(format!("harness {harness}: named twice"));
        }
    }
    Ok(found)
}

/// How many loop bounds `entry` declares.
fn bounds_of(entry: &serde_json::Value) -> usize {
    entry["loops"].as_array().map_or(0, Vec::len)
}

/// The policy of a run that checks `selected`: the entries of the harnesses
/// it checks, every one when it checks the whole suite (`None`). Kani's
/// compiler keeps only the harnesses a run's filters select, and Kani refuses
/// a policy naming one it does not verify, so a run of one harness carries
/// that harness's entry alone.
pub fn selected(
    entries: &BTreeMap<String, serde_json::Value>,
    selected: Option<&str>,
) -> serde_json::Value {
    let harnesses: Vec<&serde_json::Value> = entries
        .iter()
        .filter(|(harness, _)| selected.is_none_or(|selected| selected == harness.as_str()))
        .map(|(_, entry)| entry)
        .collect();
    serde_json::json!({ "harnesses": harnesses })
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
/// the solver command names it. For a harness `selected` (the run's policy,
/// [`selected`]) bounds: its loop discovery's invocation, status and
/// streams; its resolution (`resolution.json`) naming the harness, holding
/// exactly its selected entry as its policy, every selector of the entry
/// resolved once and to a distinct loop, and the preserved artifact as its
/// artifact; and the solver command carrying one `--unwindset`, the
/// resolved `LOOP:BOUND` pairs in their order. A harness with no bounds
/// carries no `--unwindset`. A harness whose report ends before
/// verification is left to its outcome ([`checked`]). Kani's resolution is
/// not repeated: only the correspondence between the policy given, the
/// resolution recorded and the command spawned is checked.
///
/// The verifier the run's harnesses ran, `solver.identity`'s value, one for
/// every harness; `null` when no harness reached verification.
pub fn check_execution_evidence(
    directory: &Path,
    selected: &serde_json::Value,
    report: &str,
) -> Result<serde_json::Value, String> {
    let entries: BTreeMap<&str, &serde_json::Value> = selected["harnesses"]
        .as_array()
        .ok_or("the run's policy holds no `harnesses` list")?
        .iter()
        .map(|entry| (entry["harness"].as_str().unwrap_or_default(), entry))
        .collect();
    let mut verifier: Option<serde_json::Value> = None;
    for (name, block) in blocks(report)? {
        if !block.iter().any(|line| line.starts_with("VERIFICATION:- ")) {
            continue;
        }
        let at = harness_evidence(directory, &name);
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
        let Some(entry) = entries.get(name.as_str()) else {
            if !unwindsets.is_empty() {
                return Err(format!(
                    "harness {name}: its policy bounds no loop, its solver ran with --unwindset"
                ));
            }
            continue;
        };
        for file in [
            "discovery.arguments",
            "discovery.status",
            "discovery.stdout",
            "discovery.stderr",
        ] {
            read(file)?;
        }
        let resolution = json("resolution.json")?;
        if resolution["harness"] != *name {
            return Err(format!(
                "harness {name}: resolution.json names {}",
                resolution["harness"]
            ));
        }
        if resolution["policy"] != **entry {
            return Err(format!(
                "harness {name}: resolution.json resolved {}, the run's policy is {entry}",
                resolution["policy"]
            ));
        }
        let artifact = serde_json::json!({ "path": recorded_path, "sha256": recorded_digest });
        if resolution["artifact"] != artifact {
            return Err(format!(
                "harness {name}: resolution.json resolved the artifact {}, the preserved \
                 artifact is {artifact}",
                resolution["artifact"]
            ));
        }
        let declared = entry["loops"]
            .as_array()
            .map(Vec::as_slice)
            .unwrap_or_default();
        let resolved = resolution["resolved"]
            .as_array()
            .map(Vec::as_slice)
            .unwrap_or_default();
        if resolved.len() != declared.len()
            || declared.iter().any(|selector| {
                resolved
                    .iter()
                    .filter(|found| found["selector"] == *selector)
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
        match unwindsets.as_slice() {
            [at] if command.get(at + 1) == Some(&expected.as_bytes()) => {}
            _ => {
                return Err(format!(
                    "harness {name}: its solver did not run with the one --unwindset {expected}"
                ));
            }
        }
    }
    Ok(verifier.unwrap_or(serde_json::Value::Null))
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
/// in. Parsed, never matched as text.
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
    let entries = policy(root, &declared)?;
    let (termination, report) =
        crate::process::run_kani_suite(root, &entries, target_dir, log, launcher)?;
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
                "unstable-options",
                "--harness-timeout",
                "30m"
            ]
        );
        assert!(!arguments.contains(&"--tests"));
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

    fn declared(names: &[&str]) -> BTreeSet<String> {
        names.iter().map(ToString::to_string).collect()
    }

    const POLICY_TEXT: &str = r#"{"harnesses": [
        {"harness": "a::x", "loops": [
            {"function": "f", "file": "a.rs", "loops_in_function": 1, "loop": 0, "bound": 0,
             "reason": "r"}
        ]}
    ]}"#;

    /// The policy is read for its harnesses alone, each declared and named
    /// once with at least one bound; a run of one harness carries its entry
    /// alone, a suite run every entry.
    #[test]
    fn the_policy_names_declared_harnesses_and_selects_per_run() {
        let entries = policy_of(POLICY_TEXT, &declared(&["a::x", "a::y"])).unwrap();
        assert_eq!(entries.keys().collect::<Vec<_>>(), ["a::x"]);
        assert_eq!(
            selected(&entries, None)["harnesses"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            selected(&entries, Some("a::x"))["harnesses"][0]["harness"],
            "a::x"
        );
        assert!(
            selected(&entries, Some("a::y"))["harnesses"]
                .as_array()
                .unwrap()
                .is_empty()
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
                r#"{"harnesses": [{"harness": "a::x", "loops": []}]}"#.to_string(),
                "no loop bound",
            ),
            (
                r#"{"harnesses": [{"loops": [{}]}]}"#.to_string(),
                "names no harness",
            ),
            (
                r#"{"harnesses": [], "x": 1}"#.to_string(),
                "not an object of one key",
            ),
            (
                r#"{"loops": []}"#.to_string(),
                "its one key is not `harnesses`",
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
            for file in [
                "discovery.arguments",
                "discovery.status",
                "discovery.stdout",
                "discovery.stderr",
            ] {
                evidence.write("a.x", file, b"");
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
            let bytes: Vec<u8> = parts
                .iter()
                .flat_map(|part| part.iter().copied().chain([0]))
                .collect();
            self.write(harness, "solver.arguments", &bytes);
        }

        fn entry(&self) -> serde_json::Value {
            policy_of(POLICY_TEXT, &declared(&["a::x", "a::y"])).unwrap()["a::x"].clone()
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
                "artifact": {"path": self.artifact("a.x"), "sha256": ARTIFACTS[0].2},
                "warnings": [],
                "resolved": resolved,
            });
            self.write("a.x", "resolution.json", record.to_string().as_bytes());
        }

        fn check(&self) -> Result<serde_json::Value, String> {
            let entries = policy_of(POLICY_TEXT, &declared(&["a::x", "a::y"])).unwrap();
            let report = format!(
                "{}{}{}",
                block("a::x", "SUCCESSFUL"),
                block("a::y", "SUCCESSFUL"),
                summary(2, 0)
            );
            check_execution_evidence(&self.root, &selected(&entries, None), &report)
        }
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
        let verifier = evidence.check().unwrap();
        assert_eq!(verifier["solver"]["path"], "/kani/cbmc");
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
        let cases: [Disagreement; 7] = [
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
            let found = evidence.check().unwrap_err();
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
                "solver.attempt",
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
            let found = evidence.check().unwrap_err();
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
        let text = serde_json::json!({ "harnesses": [policy.clone()] }).to_string();
        let entries = policy_of(&text, &declared(&["a::x", "a::y"])).unwrap();
        let record = serde_json::json!({
            "harness": "a::x",
            "policy": policy,
            "artifact": {"path": evidence.artifact("a.x"), "sha256": ARTIFACTS[0].2},
            "resolved": [
                {"selector": policy["loops"][0], "loop": "f.0"},
                {"selector": second, "loop": "f.0"},
            ],
        });
        evidence.write("a.x", "resolution.json", record.to_string().as_bytes());
        let report = format!(
            "{}{}{}",
            block("a::x", "SUCCESSFUL"),
            block("a::y", "SUCCESSFUL"),
            summary(2, 0)
        );
        let found = check_execution_evidence(&evidence.root, &selected(&entries, None), &report)
            .unwrap_err();
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

    /// The census reads harnesses by module path, nested inline modules
    /// included, and nothing that is not a `#[kani::proof]` function.
    #[test]
    fn the_harness_census_reads_paths_from_files_and_modules() {
        let root = std::env::temp_dir().join(format!("dcbor-gate-proofs-{}", std::process::id()));
        if root.exists() {
            std::fs::remove_dir_all(&root).unwrap();
        }
        std::fs::create_dir_all(root.join("a/b")).unwrap();
        std::fs::write(
            root.join("a/b/proofs.rs"),
            "#[kani::proof]\nfn x() {}\nmod inner { #[kani::proof] fn y() {} fn helper() {} }\n\
             // kani::proof in a comment\n#[test]\nfn not_a_harness() {}\n",
        )
        .unwrap();
        std::fs::write(root.join("a/mod.rs"), "#[kani::proof]\nfn z() {}\n").unwrap();
        std::fs::write(root.join("lib.rs"), "fn none() {}\n").unwrap();
        assert_eq!(
            harnesses(&root).unwrap(),
            declared(&["a::b::proofs::inner::y", "a::b::proofs::x", "a::z"])
        );
        std::fs::remove_dir_all(&root).unwrap();
    }
}
