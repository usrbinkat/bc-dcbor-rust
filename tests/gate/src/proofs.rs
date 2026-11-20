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

use std::collections::BTreeSet;
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
/// an exit status that disagrees with the outcomes.
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
/// its artifacts in `target_dir`, its report logged to `log`, read into the
/// suite's rows against the source's harnesses ([`rows`]).
pub fn run(root: &Path, target_dir: &Path, log: &Path) -> Result<(Vec<Row>, Vec<String>), String> {
    let declared = harnesses(&root.join("src"))?;
    if declared.is_empty() {
        return Err("the library declares no #[kani::proof] harness".to_string());
    }
    let (termination, report) = crate::process::run_kani_suite(root, target_dir, log)?;
    Ok(rows(termination, &report, &declared))
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
