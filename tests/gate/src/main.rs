//! The `gate` binary the gate scripts launch.
//!
//! Exit status 0 when the evidence holds, 1 when it does not (each fault
//! named on standard error), 2 for a usage or environment error.
//!
//! Subcommands:
//!   evidence ROOT   every trace and tightness record the configuration must
//!                   hold under the repository ROOT, present and current
//!                   (`records::evidence`)
//!   current FILE    FILE is a record of this configuration with a row
//!                   (`records::current_file`)
//!   ours FILE       FILE is a record of this configuration, rows or not;
//!                   status 1, silently, when it is another configuration's
//!                   or no record (`records::ours`)
//!   variants        each record variant, a line of its features and its
//!                   suffix, tab-separated (`records::VARIANTS`)
//!   manifest FEATURES DIGESTS OUT
//!                   publish to OUT the cost inventory of the projection
//!                   FEATURES whose digests, one per line, are DIGESTS
//!                   (`records::manifest`)
//!   models derive ROOT PAGE LOGS
//!                   derive every model's bound and stack under ROOT, stacks
//!                   in multiples of PAGE, and publish the bounds record
//!                   (`models::derive`)
//!   models evidence ROOT PAGE LOGS
//!                   run every model's evidence rows at its recorded values
//!                   and give the verdict (`models::plan`, `models::verdict`)
//!   models control ROOT LOGS CHECKER PATTERN
//!                   a planted defect in ROOT: refused when CHECKER's build
//!                   or one of its models fails with PATTERN in its log
//!   classify RUNNER KIND STATUS LOG
//!                   the outcome of a run of KIND (`test`, `race` or
//!                   `abort`) that exited with STATUS as a shell reports it,
//!                   from its LOG: a `cargo miri test` run (RUNNER `miri`,
//!                   `outcome::miri`), a native `cargo test` run, its
//!                   binary's end read from cargo's report (`cargo`,
//!                   `outcome::under_cargo`), or a test binary run directly
//!                   (`binary`, `outcome::native`)
//!   miri inventory LOG OUT
//!                   the inventory the run's LOG reports, written to OUT;
//!                   status 1 when a line of it is malformed
//!                   (`inventory::of`)
//!   miri coverage NATIVE OUT DIFF RUN...
//!                   the union of a model's RUN inventories over a line,
//!                   written to OUT, against the NATIVE run's: status 1, the
//!                   difference written to DIFF, unless they are equal
//!                   (`inventory::coverage`)
//!   miri results LOGS MODEL...
//!                   publish the Miri gate's rows under its identity, then
//!                   its verdict over them as published (`miri::results`,
//!                   `rows::verdict`)
//!   miri baseline BASELINE TESTS RUNS VERDICTS NAME MODEL...
//!                   the runs in the gate run BASELINE of each test of TESTS
//!                   (`base<TAB>test` lines), written to RUNS; status 1, the
//!                   mutant NAME appended to VERDICTS as `no_baseline`, when
//!                   any has no pass under every model (`miri::baseline`)
//!   miri judge DIRECTORY VERDICTS NAME MODEL...
//!                   the judgement of mutant NAME from its runs under
//!                   DIRECTORY, appended to VERDICTS and printed; status 2
//!                   when a run never started (`miri::judgement`)
//!   domains         each build domain's name (`domains::DOMAINS`)
//!   domain NAME features|files|tests
//!                   the domain's cargo features, its mutated files or its
//!                   mutation test selection, one argument per line
//!   mutation compare FAST EXHAUSTIVE REGISTRY DOMAIN OUTPUT
//!                   one domain's native comparison of its two layers,
//!                   published to OUTPUT (`mutation::compare`)
//!   mutation miri-plan COMPARISON FAST SNAPSHOT REACH PLAN
//!                   the survivors of tainted modules, each with the tests
//!                   reaching it and its diff, written to PLAN
//!                   (`mutation::miri_plan`)
//!   mutation miri-verdict COMPARISON PLAN VERDICTS OUTPUT
//!                   the domain's verdict over its native comparison and its
//!                   Miri judgements, published to OUTPUT
//!                   (`mutation::miri_verdict`)
//!   reach executable MESSAGES
//!                   the one test executable a cargo build's JSON MESSAGES
//!                   name (`reach::executable`)
//!   reach regions ROOT EXPORT
//!                   the code regions under ROOT/src an llvm-cov EXPORT
//!                   records executed, as JSON (`reach::regions`)
//!   reach functions ROOT EXPORT
//!                   every instrumented function under ROOT/src, as JSON
//!                   (`reach::functions`)
//!   reach index OUT BASE...
//!                   the reach map of the run in OUT, published as
//!                   OUT/reach.json, and its verdict (`reach::index`)
//!   costs check|record ROOT [RESUME]
//!                   the matrix cost evidence of the repository ROOT,
//!                   checked or recorded, reusing the completed run RESUME;
//!                   TMPDIR is where its logs are made, DCBOR_COST_BASELINE
//!                   the baseline a check reads when not the repository's
//!                   (`costs::costs`)
//!
//! The configuration is the development shell's `DCBOR_CONFIGURATION`; a
//! run's identity is the `identity.txt` its script wrote in LOGS.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use std::io::Write as _;

use dcbor_gate::costs::{self, Action, Request};
use dcbor_gate::domains;
use dcbor_gate::inventory;
use dcbor_gate::miri;
use dcbor_gate::models::{self, Listed};
use dcbor_gate::mutation;
use dcbor_gate::outcome::{self, Judgement, Kind, Outcome, Termination};
use dcbor_gate::process;
use dcbor_gate::reach;
use dcbor_gate::records;
use dcbor_gate::rows::{self, Physical, Purpose, Row};
use dcbor_model_bounds::{Bounds, Checker, PATH, RECORD_WITH};

const USAGE: &str = "usage: gate evidence ROOT | current FILE | ours FILE | variants | \
                     manifest FEATURES DIGESTS OUT | models derive ROOT PAGE LOGS | \
                     models evidence ROOT PAGE LOGS | \
                     models control ROOT LOGS CHECKER PATTERN | \
                     classify miri|cargo|binary KIND STATUS LOG | miri inventory LOG OUT | \
                     miri coverage NATIVE OUT DIFF RUN... | miri results LOGS MODEL... | \
                     miri baseline BASELINE TESTS RUNS VERDICTS NAME MODEL... | \
                     miri judge DIRECTORY VERDICTS NAME MODEL... | domains | \
                     domain NAME features|files|tests | \
                     mutation compare FAST EXHAUSTIVE REGISTRY DOMAIN OUTPUT | \
                     mutation miri-plan COMPARISON FAST SNAPSHOT REACH PLAN | \
                     mutation miri-verdict COMPARISON PLAN VERDICTS OUTPUT | \
                     reach executable MESSAGES | reach regions ROOT EXPORT | \
                     reach functions ROOT EXPORT | reach index OUT BASE... | \
                     costs check|record ROOT [RESUME]";

/// The profile every model is built and derived under.
const PROFILE: &str = "release";

/// A failure of the gate itself, not of the evidence: status 2.
struct Broken(String);

impl From<String> for Broken {
    fn from(text: String) -> Self {
        Self(text)
    }
}

/// The contents of `path`.
fn contents(path: &Path) -> Result<String, Broken> {
    std::fs::read_to_string(path).map_err(|error| Broken(format!("{}: {error}", path.display())))
}

/// A positive number from `text`, naming `what`.
fn positive(text: &str, what: &str) -> Result<usize, Broken> {
    text.parse::<usize>()
        .ok()
        .filter(|value| *value > 0)
        .ok_or_else(|| Broken(format!("{what} {text:?}: a positive number")))
}

/// The status of a verdict: its faults named, 1 when there are any.
fn verdict(faults: &[String]) -> ExitCode {
    for fault in faults {
        eprintln!("{fault}");
    }
    if faults.is_empty() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

/// Every model of every checker build of `root`: each checker's binaries
/// built, their models listed.
fn models_of(
    root: &Path,
    logs: &Path,
    checkers: &[Checker],
) -> Result<Vec<(Listed, PathBuf)>, Broken> {
    let mut found = Vec::new();
    for &checker in checkers {
        let executables = process::build(root, checker, &logs.join(format!("build-{checker}.log")))
            .map_err(|log| Broken(format!("the {checker} build failed:\n{log}")))?;
        for (target, executable) in &executables {
            for listed in process::list(checker, target, executable)? {
                found.push((listed, executable.clone()));
            }
        }
    }
    if found.is_empty() {
        return Err(Broken("no model is listed".to_string()));
    }
    Ok(found)
}

/// A results row of a model run, planned to produce `expected`.
fn row(
    listed: &Listed,
    purpose: Purpose,
    (bound, stack): (Option<usize>, Option<usize>),
    expected: Option<Outcome>,
    ran: &models::Ran,
) -> Row {
    Row {
        domain: "all-features".to_string(),
        line: listed.target.clone(),
        runner: listed.checker.name().to_string(),
        test: listed.test.clone(),
        seed: None,
        purpose,
        bound,
        stack,
        expected,
        outcome: ran.outcome,
        seconds: ran.seconds.clone(),
        peak_kb: ran.peak_kb,
        physical: Physical::NotApplicable,
    }
}

/// Publish `rows` as the results of the run whose logs are `logs`.
fn publish_results(logs: &Path, configuration: &str, rows: &[Row]) -> Result<(), Broken> {
    let identity = contents(&logs.join("identity.txt"))?;
    let path = logs.join("results.tsv");
    dcbor_record::publish(
        path.to_str()
            .ok_or_else(|| Broken("the logs' path is not UTF-8".to_string()))?,
        &rows::render(configuration, identity.trim(), rows),
    );
    Ok(())
}

/// A file of `logs` for `listed`'s run `at` of kind `what`.
fn log_of(logs: &Path, index: usize, at: usize, what: &str) -> PathBuf {
    logs.join(format!("{index}-{at}-{what}.log"))
}

fn derive(root: &Path, page: usize, logs: &Path, configuration: &str) -> Result<ExitCode, Broken> {
    let found = models_of(root, logs, &Checker::ALL)?;
    let mut bounds = Bounds {
        profile: PROFILE.to_string(),
        page,
        models: Vec::new(),
    };
    let mut results = Vec::new();
    let mut faults = Vec::new();
    for (index, (listed, executable)) in found.iter().enumerate() {
        let sized = process::sized(executable, listed, &log_of(logs, index, 0, "describe"))?;
        let mut broken = None;
        let mut at = 0;
        let derived = models::derive(listed.checker, sized, page, |bound, stack| {
            at += 1;
            match process::run(
                executable,
                listed,
                Some(bound),
                stack,
                &log_of(logs, index, at, "derive"),
            ) {
                Ok(ran) => ran,
                Err(error) => {
                    broken.get_or_insert(error);
                    models::Ran {
                        outcome: Outcome::NotRun,
                        schedules: None,
                        seconds: None,
                        peak_kb: None,
                    }
                }
            }
        });
        if let Some(error) = broken {
            return Err(Broken(error));
        }
        match derived {
            Ok(derived) => {
                for (bound, stack, ran) in &derived.runs {
                    results.push(row(
                        listed,
                        Purpose::Derive,
                        (Some(*bound), *stack),
                        None,
                        ran,
                    ));
                }
                bounds.models.push(models::bound_of(listed, &derived));
            }
            Err(fault) => faults.push(format!(
                "{} {} {}: {fault}",
                listed.checker, listed.target, listed.test
            )),
        }
    }
    publish_results(logs, configuration, &results)?;
    if faults.is_empty() {
        let path = root.join(PATH);
        dcbor_record::publish(
            path.to_str()
                .ok_or_else(|| Broken("the root's path is not UTF-8".to_string()))?,
            &bounds.render(configuration),
        );
    }
    Ok(verdict(&faults))
}

fn evidence(
    root: &Path,
    page: usize,
    logs: &Path,
    configuration: &str,
) -> Result<ExitCode, Broken> {
    let data = contents(&root.join(PATH))?;
    let (recorded_under, bounds) = Bounds::parse(&data)?;
    let mut faults = Vec::new();
    if recorded_under != configuration {
        faults.push(format!(
            "{PATH}: derived under another configuration; derive it with {RECORD_WITH}"
        ));
    }
    if bounds.profile != PROFILE {
        faults.push(format!(
            "{PATH}: derived under the {} profile, not {PROFILE}",
            bounds.profile
        ));
    }
    if bounds.page != page {
        faults.push(format!(
            "{PATH}: stacks in pages of {}, this host's are {page}",
            bounds.page
        ));
    }
    if !faults.is_empty() {
        return Ok(verdict(&faults));
    }
    let found = models_of(root, logs, &Checker::ALL)?;
    let listed: Vec<Listed> = found.iter().map(|(listed, _)| listed.clone()).collect();
    let mut results = Vec::new();
    for (index, planned) in models::plan(&listed, &bounds).into_iter().enumerate() {
        let executable = found
            .iter()
            .find(|(listed, _)| *listed == planned.listed)
            .map(|(_, executable)| executable)
            .ok_or_else(|| Broken(format!("{}: planned but not built", planned.listed.test)))?;
        let ran = process::run(
            executable,
            &planned.listed,
            planned.bound,
            planned.stack,
            &log_of(logs, index, 0, planned.purpose.name()),
        )?;
        results.push(row(
            &planned.listed,
            planned.purpose,
            (planned.bound, planned.stack),
            Some(planned.expected),
            &ran,
        ));
    }
    publish_results(logs, configuration, &results)?;
    // The verdict reads the results as published, not the rows in memory.
    let (_, _, published) = rows::parse(&contents(&logs.join("results.tsv"))?)?;
    Ok(verdict(&models::verdict(&listed, &bounds, &published)))
}

fn control(
    root: &Path,
    logs: &Path,
    checker: Checker,
    pattern: &str,
    configuration: &str,
) -> Result<ExitCode, Broken> {
    let found = match models_of(root, logs, &[checker]) {
        Ok(found) => found,
        // A defect refused where the build evaluates it: the build's log names it.
        Err(Broken(log)) if log.contains(pattern) => {
            println!("refused by the {checker} build: {pattern}");
            return Ok(ExitCode::SUCCESS);
        }
        Err(broken) => return Err(broken),
    };
    let mut results = Vec::new();
    let mut refused = false;
    for (index, (listed, executable)) in found.iter().enumerate() {
        let log = log_of(logs, index, 0, "control");
        let ran = process::run(executable, listed, None, None, &log)?;
        refused |= ran.outcome != Outcome::Pass && contents(&log)?.contains(pattern);
        results.push(row(listed, Purpose::Control, (None, None), None, &ran));
    }
    publish_results(logs, configuration, &results)?;
    if refused {
        Ok(ExitCode::SUCCESS)
    } else {
        Ok(verdict(&[format!(
            "no {checker} model refused the planted defect with {pattern:?}"
        )]))
    }
}

/// What a suite of the Miri selection's kind requires of a run: a `test`
/// or `race` suite's tests pass, an `abort` suite's scenarios abort.
fn suite_kind(kind: &str) -> Result<Kind, Broken> {
    match kind {
        "test" | "race" => Ok(Kind::Test),
        "abort" => Ok(Kind::Abort),
        other => Err(Broken(format!(
            "no suite kind {other}; the kinds are test, race and abort"
        ))),
    }
}

/// A process's exit status as a shell reports it.
fn exit_status(status: &str) -> Result<i32, Broken> {
    status
        .parse()
        .map_err(|_| Broken(format!("no exit status {status}")))
}

/// Append `row` to the file at `path`, created when absent.
fn append(path: &Path, row: &str) -> Result<(), Broken> {
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .and_then(|mut file| file.write_all(row.as_bytes()))
        .map_err(|error| Broken(format!("{}: {error}", path.display())))
}

/// `value` as JSON on standard output.
fn print_json(value: &impl serde::Serialize) -> Result<(), Broken> {
    let text = serde_json::to_string_pretty(value).map_err(|error| Broken(error.to_string()))?;
    println!("{text}");
    Ok(())
}

/// Each line of `lines` on standard output.
fn print_lines(lines: &[&str]) {
    for line in lines {
        println!("{line}");
    }
}

/// The domain's `what`, one argument per line.
fn domain(name: &str, what: &str) -> Result<ExitCode, Broken> {
    let domain = domains::domain(name)?;
    let lines = match what {
        "features" => domain.features,
        "files" => domain.files,
        "tests" => domain.tests,
        other => {
            return Err(Broken(format!(
                "no domain list {other}; the lists are features, files and tests"
            )));
        }
    };
    print_lines(lines);
    Ok(ExitCode::SUCCESS)
}

/// The cost evidence of `root`, checked or recorded.
fn cost_evidence(
    action: &str,
    root: &Path,
    resume: Option<&Path>,
    configuration: &str,
) -> Result<ExitCode, Broken> {
    let action = Action::parse(action)
        .ok_or_else(|| Broken(format!("no cost action {action}; check or record")))?;
    let temporary = std::env::var_os("TMPDIR")
        .filter(|directory| !directory.is_empty())
        .map(PathBuf::from)
        .ok_or_else(|| {
            Broken("TMPDIR is required: the cost recorder's staging directory".to_string())
        })?;
    let baseline = std::env::var_os("DCBOR_COST_BASELINE")
        .filter(|directory| !directory.is_empty())
        .map(PathBuf::from);
    let request = Request {
        action,
        root,
        configuration,
        temporary: &temporary,
        baseline: baseline.as_deref(),
        resume,
    };
    match costs::costs(&request, |leg| costs::run(root, leg)) {
        Ok(report) => {
            print_lines(&report.notes.iter().map(String::as_str).collect::<Vec<_>>());
            Ok(verdict(&report.faults))
        }
        Err(fault) => Ok(verdict(&[fault])),
    }
}

/// Write `text` to the file at `path`.
fn write(path: &Path, text: &str) -> Result<(), Broken> {
    std::fs::write(path, text).map_err(|error| Broken(format!("{}: {error}", path.display())))
}

/// The inventory a run's `log` reports, written to `out`: status 1, naming
/// the line, when one is malformed.
fn miri_inventory(log: &Path, out: &Path) -> Result<ExitCode, Broken> {
    match inventory::of(&contents(log)?) {
        Ok(found) => {
            write(out, &inventory::render(&found))?;
            Ok(ExitCode::SUCCESS)
        }
        Err(fault) => Ok(verdict(&[format!("{}: {fault}", log.display())])),
    }
}

/// A model's inventory over a line, the union of its `runs`, written to
/// `out`, against the `native` run's: status 1, the difference written to
/// `diff` and named, unless they are equal.
fn miri_coverage(
    native: &Path,
    out: &Path,
    diff: &Path,
    runs: &[&str],
) -> Result<ExitCode, Broken> {
    let read = |path: &Path| {
        inventory::parse(&contents(path)?)
            .map_err(|fault| Broken(format!("{}: {fault}", path.display())))
    };
    let native = read(native)?;
    let runs = runs
        .iter()
        .map(|run| read(Path::new(run)))
        .collect::<Result<Vec<_>, _>>()?;
    let (union, difference) = inventory::coverage(&native, &runs);
    write(out, &inventory::render(&union))?;
    write(
        diff,
        &difference
            .iter()
            .map(|line| format!("{line}\n"))
            .collect::<String>(),
    )?;
    Ok(verdict(&difference))
}

/// The Miri gate's results, published, and its verdict over them as
/// published.
fn miri_results(logs: &Path, models: &[&str], configuration: &str) -> Result<ExitCode, Broken> {
    if models.is_empty() {
        return Err(Broken("no Miri model is named".to_string()));
    }
    let rows = miri::results(logs, models)?;
    publish_results(logs, configuration, &rows)?;
    let (_, _, published) = rows::parse(&contents(&logs.join("results.tsv"))?)?;
    Ok(verdict(&rows::verdict(&published)))
}

fn run(arguments: &[&str], configuration: &str) -> Result<ExitCode, Broken> {
    match arguments {
        ["evidence", root] => Ok(verdict(&records::evidence(Path::new(root), configuration))),
        ["current", file] => {
            let path = Path::new(file);
            Ok(match records::current_file(path, configuration) {
                Ok(()) => ExitCode::SUCCESS,
                Err(fault) => verdict(&[fault.describe(path, configuration)]),
            })
        }
        // Another configuration's evidence and a file of no record are a
        // classification, not a fault: nothing is reported for them.
        ["ours", file] => Ok(
            if records::ours(&contents(Path::new(file))?, configuration) {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            },
        ),
        // The features first: a shell's `read` collapses a leading tab, and
        // the default variant's suffix is empty.
        ["variants"] => {
            for (suffix, features) in records::VARIANTS {
                println!("{features}\t{suffix}");
            }
            Ok(ExitCode::SUCCESS)
        }
        ["manifest", features, digests, out] => {
            let data = contents(Path::new(digests))?;
            let digests: Vec<&str> = data.lines().collect();
            dcbor_record::publish(out, &records::manifest(configuration, features, &digests));
            Ok(ExitCode::SUCCESS)
        }
        ["models", "derive", root, page, logs] => derive(
            Path::new(root),
            positive(page, "page")?,
            Path::new(logs),
            configuration,
        ),
        ["models", "evidence", root, page, logs] => evidence(
            Path::new(root),
            positive(page, "page")?,
            Path::new(logs),
            configuration,
        ),
        ["models", "control", root, logs, checker, pattern] => {
            let checker =
                Checker::parse(checker).ok_or_else(|| Broken(format!("no checker {checker}")))?;
            control(
                Path::new(root),
                Path::new(logs),
                checker,
                pattern,
                configuration,
            )
        }
        ["classify", runner, kind, status, log] => {
            let kind = suite_kind(kind)?;
            let status = exit_status(status)?;
            let log = contents(Path::new(log))?;
            // A shell reports a process killed by signal N as 128 + N.
            let shell = if status > 128 {
                Termination::Signaled(status - 128)
            } else {
                Termination::Exited(status)
            };
            let outcome = match *runner {
                "miri" => outcome::miri(kind, shell, &log),
                "cargo" => outcome::native(kind, outcome::under_cargo(status, &log), &log),
                "binary" => outcome::native(kind, shell, &log),
                other => {
                    return Err(Broken(format!(
                        "no runner {other}; the runners are miri, cargo and binary"
                    )));
                }
            };
            println!("{outcome}");
            Ok(ExitCode::SUCCESS)
        }
        ["miri", "inventory", log, out] => miri_inventory(Path::new(log), Path::new(out)),
        ["miri", "coverage", native, out, diff, runs @ ..] if !runs.is_empty() => {
            miri_coverage(Path::new(native), Path::new(out), Path::new(diff), runs)
        }
        ["miri", "results", logs, models @ ..] => {
            miri_results(Path::new(logs), models, configuration)
        }
        [
            "miri",
            "baseline",
            baseline,
            tests,
            runs,
            verdicts,
            name,
            models @ ..,
        ] if !models.is_empty() => {
            match miri::baseline(Path::new(baseline), &contents(Path::new(tests))?, models)? {
                Some(found) => {
                    std::fs::write(runs, miri::render_runs(&found))
                        .map_err(|error| Broken(format!("{runs}: {error}")))?;
                    Ok(ExitCode::SUCCESS)
                }
                None => {
                    append(
                        Path::new(verdicts),
                        &miri::verdict_row(name, Judgement::NoBaseline),
                    )?;
                    Ok(ExitCode::from(1))
                }
            }
        }
        ["miri", "judge", directory, verdicts, name, models @ ..] if !models.is_empty() => {
            let judgement = miri::judgement(Path::new(directory), models)?
                .ok_or_else(|| Broken(format!("{name}: a run under {directory} never started")))?;
            append(Path::new(verdicts), &miri::verdict_row(name, judgement))?;
            println!("{judgement}");
            Ok(ExitCode::SUCCESS)
        }
        ["domains"] => {
            print_lines(
                &domains::DOMAINS
                    .iter()
                    .map(|domain| domain.name)
                    .collect::<Vec<_>>(),
            );
            Ok(ExitCode::SUCCESS)
        }
        ["domain", name, what] => domain(name, what),
        [
            "mutation",
            "compare",
            fast,
            exhaustive,
            registry,
            domain,
            output,
        ] => {
            let comparison = mutation::compare(
                Path::new(fast),
                Path::new(exhaustive),
                Path::new(registry),
                domain,
            )?;
            mutation::publish(Path::new(output), &comparison)?;
            let mut summary = comparison.clone();
            summary.outcomes.clear();
            print_json(&summary)?;
            // The native comparison alone is not the run's verdict: survivors
            // in tainted modules are decided under Miri (`miri-verdict`).
            println!(
                "native comparison {}",
                if comparison.passed() {
                    "passed"
                } else {
                    "failed"
                }
            );
            Ok(ExitCode::SUCCESS)
        }
        [
            "mutation",
            "miri-plan",
            comparison,
            fast,
            snapshot,
            reach_dir,
            plan,
        ] => {
            let plan = mutation::miri_plan(
                Path::new(comparison),
                Path::new(fast),
                Path::new(snapshot),
                Path::new(reach_dir),
                Path::new(plan),
                configuration,
            )?;
            println!(
                "planned under Miri: {}, unreached under Miri: {}",
                plan.planned.len(),
                plan.unreached_under_miri.len()
            );
            Ok(ExitCode::SUCCESS)
        }
        [
            "mutation",
            "miri-verdict",
            comparison,
            plan,
            verdicts,
            output,
        ] => {
            let (result, passed) = mutation::miri_verdict(
                Path::new(comparison),
                Path::new(plan),
                Path::new(verdicts),
            )?;
            mutation::publish(Path::new(output), &result)?;
            print_json(&result)?;
            Ok(if passed {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            })
        }
        ["reach", "executable", messages] => {
            println!("{}", reach::executable(&contents(Path::new(messages))?)?);
            Ok(ExitCode::SUCCESS)
        }
        ["reach", "regions", root, export] => {
            let regions = reach::regions(Path::new(root), &contents(Path::new(export))?)?;
            println!(
                "{}",
                serde_json::to_string(&regions).map_err(|error| Broken(error.to_string()))?
            );
            Ok(ExitCode::SUCCESS)
        }
        ["reach", "functions", root, export] => {
            let functions = reach::functions(Path::new(root), &contents(Path::new(export))?)?;
            println!(
                "{}",
                serde_json::to_string(&functions).map_err(|error| Broken(error.to_string()))?
            );
            Ok(ExitCode::SUCCESS)
        }
        ["reach", "index", out, bases @ ..] if !bases.is_empty() => {
            let (_, faults) = reach::index(
                Path::new(out),
                bases,
                configuration,
                dcbor_gate::cfgs::EXEMPTIONS,
            )?;
            Ok(verdict(&faults))
        }
        ["costs", action, root] => cost_evidence(action, Path::new(root), None, configuration),
        ["costs", action, root, resume] => cost_evidence(
            action,
            Path::new(root),
            Some(Path::new(resume)),
            configuration,
        ),
        _ => Err(Broken(USAGE.to_string())),
    }
}

fn main() -> ExitCode {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let arguments: Vec<&str> = arguments.iter().map(String::as_str).collect();
    let Some(configuration) = dcbor_record::configuration() else {
        eprintln!(
            "{} is unset: run in the configured development shell",
            dcbor_record::CONFIGURATION
        );
        return ExitCode::from(2);
    };
    match run(&arguments, &configuration) {
        Ok(status) => status,
        Err(Broken(text)) => {
            eprintln!("{text}");
            ExitCode::from(2)
        }
    }
}
