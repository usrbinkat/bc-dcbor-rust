//! The `gate` binary the gate scripts launch.
//!
//! Exit status 0 when the evidence holds, 1 when it does not (each fault
//! named on standard error), 2 for a usage or environment error.
//!
//! Subcommands:
//!   evidence ROOT   every trace and tightness record the configuration must
//!                   hold under the repository ROOT, present and current
//!                   (`records::evidence`), every admission-trace record's
//!                   rows accepted by the refinement machine
//!                   (`dcbor_refinement::parse_record`), and every normative
//!                   target compiling in its data (`rows::normative_faults`)
//!   refine FILE...  every row of each admission-trace record FILE accepted
//!                   by the refinement machine, its class the one its run
//!                   supports (`dcbor_refinement::parse_record`)
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
//!   models control ROOT LOGS NAME CHECKER
//!                   the planted control NAME (`controls::TABLE`) in ROOT,
//!                   under CHECKER: refused when CHECKER's build, or one of
//!                   its models, produced the control's planned outcome
//!                   naming its pattern (`controls::judge`)
//!   control list ROOT CHANNEL RUNNER...
//!                   each planted control of the RUNNERs (`loom`, `shuttle`,
//!                   `native`, `kani`, or a Miri model, `miri::MIRI_MODELS`)
//!                   of toolchain CHANNEL (`nightly`, `stable`, `kani`, `-`
//!                   for a model control) as its table row, after the table
//!                   is checked complete against the diffs under ROOT;
//!                   status 1, each fault named, when it is not
//!                   (`controls::read`)
//!   control run baseline|red|green ROOT TARGET LOGS NAME RUNNER LAUNCHER
//!                   the control NAME of RUNNER, `native` (its test, built
//!                   into TARGET from the copy ROOT and run alone; LAUNCHER
//!                   `-`) or `kani` (its harness, checked alone by the Kani
//!                   LAUNCHER names, the run's selection, `proofs-identity`,
//!                   its artifacts in TARGET), a Kani control's harness before
//!                   its diff is applied (baseline: it must verify,
//!                   `controls::verified`), its diff applied (red: the
//!                   run must refuse it by its own rule, `controls::judge`)
//!                   or reversed (green: `controls::restored`); the judgement
//!                   written to LOGS/NAME/SIDE.judged and the run's row to
//!                   LOGS/NAME/SIDE.tsv; status 1 unless it held
//!   control judge red|green ROOT LOGS NAME RUNNER OUTCOME LOG
//!                   the Miri control NAME under model RUNNER, run by the
//!                   script in the copy ROOT with the Miri gate's command,
//!                   its OUTCOME classified (`classify miri`) and its LOG
//!                   kept, judged as `control run` judges (red:
//!                   `controls::judge`, green: `controls::restored`), the
//!                   judgement and row written to its directory under LOGS
//!                   (`controls::directory`); status 1 unless it held
//!   control evidence ROOT LOGS CHANNEL
//!                   every control of CHANNEL that runs one test, natively,
//!                   under a Miri model or under Kani, a Kani control's
//!                   harness verified unmutated first, seen red, then green
//!                   again in the same copy, its source digests changed by
//!                   the diff and restored (`controls::evidence`)
//!   classify RUNNER KIND STATUS LOG
//!                   the outcome of a run of KIND (`test`, `race` or
//!                   `abort`) that exited with STATUS as a shell reports it,
//!                   from its LOG: a `cargo miri test` run (RUNNER `miri`,
//!                   `outcome::miri`), a native `cargo test` run, its
//!                   binary's end read from cargo's report (`cargo`,
//!                   `outcome::under_cargo`), or a test binary run directly
//!                   (`binary`, `outcome::native`)
//!   miri models     each aliasing model every Miri verdict is given under,
//!                   one per line (`miri::MIRI_MODELS`), the scripts' one
//!                   list of them
//!   proofs-build    the proof build's `cargo` arguments on one line
//!                   (`proofs::arguments`), an input of the proof gate's
//!                   identity
//!   proofs-identity LAUNCHER
//!                   select the Kani a run launches: `cargo-kani` resolved
//!                   once, its absolute path written to the new file
//!                   LAUNCHER, which every Kani run of the run is given;
//!                   then that Kani's identity, one `KEY<TAB>VALUE` line each
//!                   (`proofs::identity`), an input of the proof gate's and
//!                   the Kani controls' identities
//!   proofs ROOT TARGET LOGS LAUNCHER
//!                   every proof harness of the library under ROOT checked by
//!                   the Kani LAUNCHER names (`proofs::arguments`), its artifacts in
//!                   TARGET, its report LOGS/kani.log: one results row per
//!                   `#[kani::proof]` of the source, proved when it verified,
//!                   published under the identity in LOGS, then the verdict;
//!                   status 1, each fault named (`proofs::run`)
//!   miri inventory LOG OUT
//!                   the inventory the run's LOG reports, written to OUT;
//!                   status 1 when a line of it is malformed
//!                   (`inventory::of`)
//!   miri coverage NATIVE OUT DIFF RUN...
//!                   the union of a model's RUN inventories over a line,
//!                   written to OUT, against the NATIVE run's: status 1, the
//!                   difference written to DIFF, unless they are equal
//!                   (`inventory::coverage`)
//!   miri results ROOT LOGS MODEL...
//!                   publish the Miri gate's rows under its identity, the
//!                   binary16 conversion's branch obligations among them,
//!                   each a row checked against the build of the repository
//!                   ROOT (`conversion::rows`), then its verdict over them as
//!                   published (`miri::results`, `rows::verdict`), each
//!                   unmet obligation also named
//!   miri baseline BASELINE TESTS RUNS VERDICTS NAME MODEL...
//!                   the runs in the gate run BASELINE of each test of TESTS
//!                   (`base<TAB>test` lines), written to RUNS; status 1, the
//!                   mutant NAME appended to VERDICTS as `no_baseline`, when
//!                   any has no pass under every model (`miri::baseline`)
//!   miri judge DIRECTORY VERDICTS NAME MODEL...
//!                   the judgement of mutant NAME from its runs under
//!                   DIRECTORY, appended to VERDICTS and printed; status 2
//!                   when a run never started (`miri::judgement`)
//!   unicode-version the Unicode version dCBOR normalizes and stabilizes
//!                   text by, `X.Y.Z` (`dcbor::UNICODE_VERSION`), an input
//!                   of every run's identity
//!   dcbor-draft     the dCBOR Internet-Draft revision the library implements
//!                   and its conformance vectors are of, its full name
//!                   (`dcbor::DCBOR_DRAFT_REVISION`), an input of every run's
//!                   identity
//!   domains        each build domain's name (`domains::DOMAINS`)
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

use dcbor_gate::controls::{self, Runner};
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
use dcbor_gate::rows::{self, Evidence, Physical, Purpose, Row};
use dcbor_model_bounds::{Bounds, Checker, PATH, RECORD_WITH};

const USAGE: &str = "usage: gate evidence ROOT | refine FILE... | current FILE | ours FILE | variants | budgets | \
                     manifest FEATURES DIGESTS OUT | models derive ROOT PAGE LOGS | \
                     models evidence ROOT PAGE LOGS | \
                     models control ROOT LOGS NAME CHECKER | \
                     control list ROOT CHANNEL RUNNER... | \
                     control run baseline|red|green ROOT TARGET LOGS NAME native|kani LAUNCHER|- | \
                     control judge red|green ROOT LOGS NAME RUNNER OUTCOME LOG | \
                     control evidence ROOT LOGS CHANNEL | \
                     classify miri|cargo|binary KIND STATUS LOG | proofs-build | proofs-identity LAUNCHER | \
                     proofs ROOT TARGET LOGS LAUNCHER | \
                     miri models | \
                     miri inventory LOG OUT | \
                     miri coverage NATIVE OUT DIFF RUN... | miri results ROOT LOGS MODEL... | \
                     miri baseline BASELINE TESTS RUNS VERDICTS NAME MODEL... | \
                     miri judge DIRECTORY VERDICTS NAME MODEL... | unicode-version | dcbor-draft | \
                     domains | \
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

/// The admission-trace records under the repository `root`, every variant
/// (`tests/data/admission-traces*.txt`), in path order.
fn trace_records(root: &Path) -> Result<Vec<PathBuf>, Broken> {
    let data = root.join("tests").join("data");
    let entries =
        std::fs::read_dir(&data).map_err(|error| Broken(format!("{}: {error}", data.display())))?;
    let mut records = Vec::new();
    for entry in entries {
        let path = entry
            .map_err(|error| Broken(format!("{}: {error}", data.display())))?
            .path();
        let traces = path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with("admission-traces") && name.ends_with(".txt"));
        if traces {
            records.push(path);
        }
    }
    records.sort();
    if records.is_empty() {
        return Err(Broken(format!(
            "{}: no admission-trace record",
            data.display()
        )));
    }
    Ok(records)
}

/// Every fault of the admission-trace records `paths`: a record not read,
/// or a row the refinement machine refuses or that claims another class
/// than its run supports, each named by its line
/// (`dcbor_refinement::parse_record`).
fn refinement_faults(paths: &[PathBuf]) -> Result<Vec<String>, Broken> {
    let mut faults = Vec::new();
    for path in paths {
        let shown = path.display().to_string();
        if let Err(fault) = dcbor_refinement::parse_record(&shown, &contents(path)?) {
            faults.push(fault);
        }
    }
    Ok(faults)
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
        evidence: Evidence::Unverified,
    }
    .classified()
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

/// The planted model control `control` in `root` under `checker`: refused
/// when the checker's build failed as the control plans (`build_refused`,
/// judged by the build's log), or when one of its models ran to the planned
/// outcome naming the pattern in that model's own log (each model a process
/// of its own). One judgement for both, the native controls' too
/// (`controls::judge`).
fn control(
    root: &Path,
    logs: &Path,
    control: &controls::Control,
    checker: Checker,
    configuration: &str,
) -> Result<ExitCode, Broken> {
    let failed_build = format!("the {checker} build failed:\n");
    let found = match models_of(root, logs, &[checker]) {
        Ok(found) => found,
        Err(Broken(text)) => match text.strip_prefix(failed_build.as_str()) {
            Some(log) => {
                return Ok(match controls::judge(control, Outcome::BuildRefused, log) {
                    Ok(()) => {
                        println!("refused by the {checker} build");
                        ExitCode::SUCCESS
                    }
                    Err(fault) => verdict(&[fault]),
                });
            }
            None => return Err(Broken(text)),
        },
    };
    let mut results = Vec::new();
    let mut faults = Vec::new();
    let mut refused = false;
    for (index, (listed, executable)) in found.iter().enumerate() {
        let log = log_of(logs, index, 0, "control");
        let ran = process::run(executable, listed, None, None, &log)?;
        match controls::judge(control, ran.outcome, &contents(&log)?) {
            Ok(()) => refused = true,
            Err(fault) => faults.push(format!("{}: {fault}", listed.test)),
        }
        results.push(row(listed, Purpose::Control, (None, None), None, &ran));
    }
    publish_results(logs, configuration, &results)?;
    if refused {
        Ok(ExitCode::SUCCESS)
    } else {
        faults.insert(
            0,
            format!(
                "no {checker} model refused the planted defect {}",
                control.name
            ),
        );
        Ok(verdict(&faults))
    }
}

/// One run of the control `name` of `runner` in the copy `root`, `side`
/// `baseline` (a Kani control's harness before its diff is applied), `red`
/// (its diff applied) or `green` (reversed): built and run here, a native
/// test or a Kani harness (`controls::observe`), then judged and recorded
/// ([`judged`]). The runner is named, never inferred: a name may be a
/// control under more than one runner.
fn control_run(
    side: &str,
    root: &Path,
    target_dir: &Path,
    logs: &Path,
    (name, runner): (&str, Runner),
    launcher: Option<&Path>,
    configuration: &str,
) -> Result<ExitCode, Broken> {
    if !matches!(runner, Runner::Native | Runner::Kani) {
        return Err(Broken(format!(
            "{name}: a {} control is not run by `control run`",
            runner.name()
        )));
    }
    let table = controls::read(root).map_err(Broken)?;
    let control = controls::find(&table, name, runner).map_err(Broken)?;
    let directory = controls::directory(logs, control);
    std::fs::create_dir_all(&directory)
        .map_err(|error| Broken(format!("{}: {error}", directory.display())))?;
    let (outcome, report) =
        controls::observe(root, target_dir, &directory, control, side, launcher)?;
    judged(side, control, outcome, &report, &directory, configuration)
}

/// One run of the control `name` under `runner` in the copy `root` that a
/// script ran itself, its `outcome` classified (`gate classify`) and its
/// `log` kept: a Miri control's, run by `tests/controls.sh` with the Miri
/// gate's one command and flags (`tests/gate-common.sh`), judged and
/// recorded as a native run is ([`judged`]).
fn control_judge(
    side: &str,
    root: &Path,
    logs: &Path,
    (name, runner): (&str, Runner),
    (outcome, log): (Outcome, &Path),
    configuration: &str,
) -> Result<ExitCode, Broken> {
    let table = controls::read(root).map_err(Broken)?;
    let control = controls::find(&table, name, runner).map_err(Broken)?;
    if !matches!(control.runner, Runner::Miri(_)) {
        return Err(Broken(format!(
            "{name}: a {} control is run by the gate (`control run`), not judged from a script's run",
            control.runner.name()
        )));
    }
    let directory = controls::directory(logs, control);
    judged(
        side,
        control,
        outcome,
        &contents(log)?,
        &directory,
        configuration,
    )
}

/// The judgement of one run of `control` that ended in `outcome` with
/// `report`, `side` `baseline` (a Kani control's harness before its diff:
/// verified, `controls::verified`), `red` (its diff applied: refused by its
/// own rule, `controls::judge`) or `green` (reversed: `controls::restored`):
/// written to `directory/SIDE.judged`, and the run's results row to
/// `directory/SIDE.tsv` under the identity the script wrote there. The one
/// record of every control run of one test, native or under Miri.
fn judged(
    side: &str,
    control: &controls::Control,
    outcome: Outcome,
    report: &str,
    directory: &Path,
    configuration: &str,
) -> Result<ExitCode, Broken> {
    let (judged, purpose, expected) = match side {
        "baseline" => (
            controls::verified(control, outcome, report),
            Purpose::Normal,
            Some(Outcome::Pass),
        ),
        "red" => (
            controls::judge(control, outcome, report),
            Purpose::Control,
            None,
        ),
        "green" => (
            controls::restored(control, outcome, report),
            Purpose::Normal,
            Some(Outcome::Pass),
        ),
        other => return Err(Broken(format!("no side {other}; baseline, red or green"))),
    };
    let written = match (&judged, side) {
        (Ok(()), "baseline") => "verified".to_string(),
        (Ok(()), "red") => "refused".to_string(),
        (Ok(()), _) => "restored".to_string(),
        (Err(fault), _) => fault.clone(),
    };
    write(
        &directory.join(format!("{side}.judged")),
        &format!("{written}\n"),
    )?;
    let row = Row {
        domain: control
            .features
            .clone()
            .unwrap_or_else(|| "default".to_string()),
        line: control.name.clone(),
        runner: control.runner.name().to_string(),
        test: control.test.clone().unwrap_or_default(),
        seed: None,
        purpose,
        bound: None,
        stack: None,
        expected,
        outcome,
        seconds: None,
        peak_kb: None,
        physical: Physical::NotApplicable,
        evidence: Evidence::Unverified,
    }
    .classified();
    let identity = contents(&directory.join("identity.txt"))?;
    let path = directory.join(format!("{side}.tsv"));
    dcbor_record::publish(
        path.to_str()
            .ok_or_else(|| Broken("the logs' path is not UTF-8".to_string()))?,
        &rows::render(configuration, identity.trim(), &[row]),
    );
    Ok(match judged {
        Ok(()) => ExitCode::SUCCESS,
        Err(fault) => verdict(&[fault]),
    })
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

/// The Miri gate's results, the binary16 conversion's branch obligations
/// among them (`conversion::rows`, checked against the build of `root`),
/// published, and its verdict over them as published; each unmet
/// obligation's faults named beside it, so an execution that passed
/// everywhere still fails the evidence when an obligation is unmet.
fn miri_results(
    root: &Path,
    logs: &Path,
    models: &[&str],
    configuration: &str,
) -> Result<ExitCode, Broken> {
    if models.is_empty() {
        return Err(Broken("no Miri model is named".to_string()));
    }
    let mut rows = miri::results(logs, models)?;
    let (branches, faults) = dcbor_gate::conversion::rows(root, logs, models)?;
    rows.extend(branches);
    publish_results(logs, configuration, &rows)?;
    let (_, _, published) = rows::parse(&contents(&logs.join("results.tsv"))?)?;
    let mut found = rows::verdict(&published);
    found.extend(faults);
    Ok(verdict(&found))
}

fn run(arguments: &[&str], configuration: &str) -> Result<ExitCode, Broken> {
    match arguments {
        // The repository's static evidence facts: every record present and
        // current, and every normative target compiling in its data.
        ["evidence", root] => {
            let root = Path::new(root);
            let mut faults = records::evidence(root, configuration);
            faults.extend(refinement_faults(&trace_records(root)?)?);
            faults.extend(rows::normative_faults(root));
            Ok(verdict(&faults))
        }
        ["refine", files @ ..] if !files.is_empty() => {
            let paths: Vec<PathBuf> = files.iter().map(PathBuf::from).collect();
            Ok(verdict(&refinement_faults(&paths)?))
        }
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
        // Every recording budget to record and check, one per line: its
        // file name, its projection's features, its test target and exact
        // test, and its layer and witness sizes.
        ["budgets"] => {
            for selection in dcbor_record::budgets::inventory() {
                println!(
                    "{}\t{}\t{}\t{}\t{}\t{}",
                    selection.name,
                    selection.features,
                    selection.target,
                    selection.test,
                    selection.rigor.name(),
                    selection.witness.name()
                );
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
        ["models", "control", root, logs, name, checker] => {
            let checker =
                Checker::parse(checker).ok_or_else(|| Broken(format!("no checker {checker}")))?;
            let table = controls::read(Path::new(root)).map_err(Broken)?;
            let planted = controls::find(&table, name, Runner::Model(checker)).map_err(Broken)?;
            control(
                Path::new(root),
                Path::new(logs),
                planted,
                checker,
                configuration,
            )
        }
        ["control", "list", root, channel, runners @ ..] if !runners.is_empty() => {
            let runners = runners
                .iter()
                .map(|runner| Runner::parse(runner).ok_or_else(|| Broken(Runner::unknown(runner))))
                .collect::<Result<Vec<_>, _>>()?;
            let channel = (*channel != "-").then_some(*channel);
            match controls::read(Path::new(root)) {
                Ok(table) => {
                    for control in table.iter().filter(|control| {
                        runners.contains(&control.runner) && control.toolchain.as_deref() == channel
                    }) {
                        println!("{}", control.render());
                    }
                    Ok(ExitCode::SUCCESS)
                }
                Err(fault) => Ok(verdict(&[fault])),
            }
        }
        [
            "control",
            "run",
            side,
            root,
            target_dir,
            logs,
            name,
            runner,
            launcher,
        ] => {
            let runner = Runner::parse(runner).ok_or_else(|| Broken(Runner::unknown(runner)))?;
            // A Kani control runs the run's selected Kani; a native one none.
            let launcher = match (runner, *launcher) {
                (Runner::Kani, "-") => {
                    return Err(Broken(format!(
                        "{name}: a kani control needs the run's launcher file"
                    )));
                }
                (Runner::Kani, file) => {
                    Some(dcbor_gate::proofs::selected_launcher(Path::new(file)).map_err(Broken)?)
                }
                (_, "-") => None,
                (_, file) => {
                    return Err(Broken(format!(
                        "{name}: a {} control launches no Kani, but names the launcher {file}",
                        runner.name()
                    )));
                }
            };
            control_run(
                side,
                Path::new(root),
                Path::new(target_dir),
                Path::new(logs),
                (name, runner),
                launcher.as_deref(),
                configuration,
            )
        }
        [
            "control",
            "judge",
            side,
            root,
            logs,
            name,
            runner,
            outcome,
            log,
        ] => {
            let runner = Runner::parse(runner).ok_or_else(|| Broken(Runner::unknown(runner)))?;
            let outcome =
                Outcome::parse(outcome).ok_or_else(|| Broken(format!("no outcome {outcome}")))?;
            control_judge(
                side,
                Path::new(root),
                Path::new(logs),
                (name, runner),
                (outcome, Path::new(log)),
                configuration,
            )
        }
        // The verdict over a control run, and its final record
        // (`verdict.json`, `proofs::ControlVerdict`), written once whatever
        // the verdict: what a calibration's readiness cites.
        ["control", "evidence", root, logs, channel] => {
            let logs = Path::new(logs);
            let table = controls::read(Path::new(root)).map_err(Broken)?;
            let faults = controls::evidence(&table, logs, channel);
            let counted = table
                .iter()
                .filter(|control| {
                    control.runner.runs_one_test() && control.toolchain.as_deref() == Some(*channel)
                })
                .count();
            let record = dcbor_gate::proofs::ControlVerdict {
                version: dcbor_gate::proofs::RUNTIME_VERSION,
                channel: channel.to_string(),
                commit: contents(&logs.join("commit.txt"))?.trim().to_string(),
                identity: contents(&logs.join("identity.txt"))?.trim().to_string(),
                controls: counted,
                faults: faults.clone(),
            };
            let encoded = serde_json::to_vec_pretty(&record)
                .map_err(|error| Broken(format!("{}: {error}", logs.display())))?;
            dcbor_gate::process::record(&logs.join("verdict.json"), &encoded).map_err(Broken)?;
            Ok(verdict(&faults))
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
        // The proof build's arguments, the identity's account of what the
        // proof gate builds: read from the one definition, never restated.
        ["proofs-build"] => {
            println!("{}", dcbor_gate::proofs::arguments().join(" "));
            Ok(ExitCode::SUCCESS)
        }
        // The Kani every proof and Kani-control run launches, as their
        // identities record it: the one resolution of the launcher.
        ["proofs-identity", launcher] => {
            for (key, value) in dcbor_gate::proofs::identity(Path::new(launcher)).map_err(Broken)? {
                println!("{key}\t{value}");
            }
            Ok(ExitCode::SUCCESS)
        }
        ["proofs", root, target_dir, logs, launcher] => {
            let logs = Path::new(logs);
            let launcher =
                dcbor_gate::proofs::selected_launcher(Path::new(launcher)).map_err(Broken)?;
            let (rows, faults) = dcbor_gate::proofs::run(
                Path::new(root),
                Path::new(target_dir),
                &logs.join("kani.log"),
                &launcher,
            )?;
            publish_results(logs, configuration, &rows)?;
            let (_, _, published) = rows::parse(&contents(&logs.join("results.tsv"))?)?;
            let mut found = rows::verdict(&published);
            found.extend(faults);
            Ok(verdict(&found))
        }
        // A calibration of the harnesses a plan names, after the control run
        // whose logs are `control_logs`: each harness checked alone under its
        // plan's operational limit, qualifying nothing and writing no results
        // row (`proofs::calibration`). Each scheduled execution is printed;
        // the command fails unless every one verified, since only a verified
        // execution is a calibration sample.
        [
            "proofs-calibrate",
            root,
            target_dir,
            logs,
            launcher,
            plan,
            control_logs,
        ] => {
            let launcher =
                dcbor_gate::proofs::selected_launcher(Path::new(launcher)).map_err(Broken)?;
            let schedule = dcbor_gate::proofs::calibrate(
                Path::new(root),
                Path::new(plan),
                Path::new(target_dir),
                Path::new(logs),
                &launcher,
                Path::new(control_logs),
            )
            .map_err(Broken)?;
            let mut unverified = Vec::new();
            for execution in &schedule.executions {
                let observed = match &execution.observed {
                    dcbor_gate::proofs::Observed::Outcome { outcome } => outcome.clone(),
                    dcbor_gate::proofs::Observed::Rejected { error } => {
                        format!("rejected: {error}")
                    }
                    dcbor_gate::proofs::Observed::NotRun { reason } => format!("not run: {reason}"),
                };
                println!(
                    "{}\tpass {}\t{observed}\t{}",
                    execution.harness, execution.pass, execution.log
                );
                if observed != dcbor_gate::outcome::Outcome::Pass.name() {
                    unverified.push(format!(
                        "harness {} pass {}: {observed}, not a sample",
                        execution.harness, execution.pass
                    ));
                }
            }
            Ok(verdict(&unverified))
        }
        // The source state of the copy at `root` (`copy_of`), the one digest
        // of a tree's kinds, modes, link targets and bytes
        // (`proofs::SourceState`) every script and run records.
        ["tree-digest", root] => {
            println!(
                "{}",
                dcbor_gate::proofs::tree_digest(Path::new(root)).map_err(Broken)?
            );
            Ok(ExitCode::SUCCESS)
        }
        // A finished calibration's records copied into the tree, where a
        // prediction may cite them.
        ["proofs-adopt", evidence, root] => {
            let adopted =
                dcbor_gate::proofs::adopt(Path::new(evidence), Path::new(root)).map_err(Broken)?;
            println!("{}", adopted.display());
            Ok(ExitCode::SUCCESS)
        }
        ["miri", "models"] => {
            print_lines(&miri::MIRI_MODELS);
            Ok(ExitCode::SUCCESS)
        }
        ["miri", "inventory", log, out] => miri_inventory(Path::new(log), Path::new(out)),
        ["miri", "coverage", native, out, diff, runs @ ..] if !runs.is_empty() => {
            miri_coverage(Path::new(native), Path::new(out), Path::new(diff), runs)
        }
        ["miri", "results", root, logs, models @ ..] => {
            miri_results(Path::new(root), Path::new(logs), models, configuration)
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
        // Read from the library the gate links, never written by hand: the
        // version its normalization and its stabilized-text table are of.
        ["unicode-version"] => {
            let (major, minor, update) = dcbor::UNICODE_VERSION;
            println!("{major}.{minor}.{update}");
            Ok(ExitCode::SUCCESS)
        }
        // Read from the library the gate links, never written by hand: the
        // revision its numeric profile and its Appendix A vectors are of.
        ["dcbor-draft"] => {
            println!("{}", dcbor::DCBOR_DRAFT_REVISION);
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
