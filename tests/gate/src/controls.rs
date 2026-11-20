//! The planted controls: their one table (`tests/data/controls/controls.tsv`),
//! the one judgement of whether a run refused a planted defect by its own
//! rule, and the evidence that every control was seen red, then green again
//! in the same copy.
//!
//! A control is a diff that plants one defect and the check that must refuse
//! it. Its row names the runner (a model checker, [`Checker`], judged by the
//! concurrency gate; `native`, one libtest test run alone; a Miri
//! aliasing model, [`crate::miri::MIRI_MODELS`], one libtest test run alone
//! under `cargo miri test` by `tests/controls.sh` with the Miri gate's own
//! command and flags; or `kani`, one proof harness checked alone in the
//! proof build, [`crate::proofs`]), the outcome the refusal must be ([`Outcome`]), and
//! the text it must name. The text counts only where it is the selected
//! execution's own: the whole report of a run of exactly one test
//! ([`outcome::ran_one`]; under Miri, a run that selected exactly its one
//! test and started it, since undefined behavior ends the interpreter before
//! libtest's summary), or a trybuild fixture's own block in its suite's
//! report.

use std::path::Path;

use dcbor_model_bounds::Checker;

use crate::outcome::{self, Kind, Outcome};

/// The table, relative to the repository root.
pub const TABLE: &str = "tests/data/controls/controls.tsv";
/// The development shell a Kani control runs in, its toolchain column.
pub const KANI_TOOLCHAIN: &str = "kani";
/// The directory every planted diff lives in, relative to the root.
pub const DIRECTORY: &str = "tests/data/controls";

/// What shows a control's refusal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Runner {
    /// A model checker's build, judged by `gate models control`.
    Model(Checker),
    /// One test of a cargo test target, run alone.
    Native,
    /// One test of a cargo test target, run alone under Miri's aliasing
    /// model of this name, one of [`crate::miri::MIRI_MODELS`].
    Miri(&'static str),
    /// One proof harness of the library, checked alone by `cargo kani` in
    /// the proof build ([`crate::proofs`]); its row's test is the
    /// harness's fully qualified name.
    Kani,
}

/// Every runner's name, as an error names the choices.
fn runner_names() -> String {
    let mut names = vec!["native", "kani"];
    names.extend(Checker::ALL.iter().map(|checker| checker.name()));
    names.extend(crate::miri::MIRI_MODELS);
    names.join(", ")
}

impl Runner {
    pub fn parse(text: &str) -> Option<Self> {
        if text == "native" {
            return Some(Self::Native);
        }
        if text == "kani" {
            return Some(Self::Kani);
        }
        if let Some(model) = crate::miri::MIRI_MODELS
            .iter()
            .find(|model| **model == text)
        {
            return Some(Self::Miri(model));
        }
        Checker::parse(text).map(Self::Model)
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Model(checker) => checker.name(),
            Self::Native => "native",
            Self::Miri(model) => model,
            Self::Kani => "kani",
        }
    }

    /// The runner of a control that runs one test of a cargo target alone,
    /// natively or under Miri, or one proof harness alone under Kani: its
    /// row names a toolchain, a package, a target and a test.
    pub fn runs_one_test(self) -> bool {
        matches!(self, Self::Native | Self::Miri(_) | Self::Kani)
    }

    /// The refusal message naming every runner, for a runner not parsed.
    pub fn unknown(text: &str) -> String {
        format!("no runner {text:?}; the runners are {}", runner_names())
    }
}

/// One row of the table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Control {
    pub name: String,
    /// The diff's path relative to the root.
    pub diff: String,
    pub runner: Runner,
    /// The channel of the development shell a native control runs in
    /// (`nightly`, `stable`); none for a model control.
    pub toolchain: Option<String>,
    pub package: Option<String>,
    /// `all`, a comma-separated feature list, or none for the defaults.
    pub features: Option<String>,
    /// `lib`, or an integration test binary's name.
    pub target: Option<String>,
    /// The exact libtest name run alone.
    pub test: Option<String>,
    /// The trybuild fixture whose block must name the pattern.
    pub fixture: Option<String>,
    /// The outcome the refusal must be.
    pub expected: Outcome,
    pub pattern: String,
}

const COLUMNS: usize = 11;

impl Control {
    /// The row as the table writes it, `-` for an absent column: what
    /// `gate control list` prints for the scripts.
    pub fn render(&self) -> String {
        let column = |value: &Option<String>| value.clone().unwrap_or_else(|| "-".to_string());
        [
            self.name.clone(),
            self.diff.clone(),
            self.runner.name().to_string(),
            column(&self.toolchain),
            column(&self.package),
            column(&self.features),
            column(&self.target),
            column(&self.test),
            column(&self.fixture),
            self.expected.name().to_string(),
            self.pattern.clone(),
        ]
        .join("\t")
    }
}

fn optional(value: &str, line: usize, what: &str) -> Result<Option<String>, String> {
    match value {
        "-" => Ok(None),
        "" => Err(format!("{TABLE}:{line}: an empty {what} column; write `-`")),
        other => Ok(Some(other.to_string())),
    }
}

/// The table's rows, each validated: eleven columns; a diff of the controls
/// directory; a known runner and expected outcome; a native row naming its
/// toolchain, package, target and test, a model row none of them; a pattern;
/// no (name, runner) twice; one diff per name.
pub fn parse(text: &str) -> Result<Vec<Control>, String> {
    let mut controls: Vec<Control> = Vec::new();
    for (index, raw) in text.lines().enumerate() {
        let line = index + 1;
        if raw.is_empty() || raw.starts_with('#') {
            continue;
        }
        let columns: Vec<&str> = raw.split('\t').collect();
        let [
            name,
            diff,
            runner,
            toolchain,
            package,
            features,
            target,
            test,
            fixture,
            expected,
            pattern,
        ] = columns[..]
        else {
            return Err(format!(
                "{TABLE}:{line}: {} columns, not the {COLUMNS} of a control",
                columns.len()
            ));
        };
        if name.is_empty() || name == "-" {
            return Err(format!("{TABLE}:{line}: a control without a name"));
        }
        let in_directory = diff
            .strip_prefix(DIRECTORY)
            .and_then(|rest| rest.strip_prefix('/'))
            .is_some_and(|file| !file.contains('/') && file.ends_with(".patch"));
        if !in_directory {
            return Err(format!(
                "{TABLE}:{line}: {diff:?} is no diff of {DIRECTORY}"
            ));
        }
        let runner = Runner::parse(runner)
            .ok_or_else(|| format!("{TABLE}:{line}: {}", Runner::unknown(runner)))?;
        let expected = Outcome::parse(expected)
            .filter(|outcome| {
                !matches!(
                    outcome,
                    Outcome::Pass | Outcome::NotRun | Outcome::NoVerdict
                )
            })
            .ok_or_else(|| format!("{TABLE}:{line}: {expected:?} is no refusal outcome"))?;
        let control = Control {
            name: name.to_string(),
            diff: diff.to_string(),
            runner,
            toolchain: optional(toolchain, line, "toolchain")?,
            package: optional(package, line, "package")?,
            features: optional(features, line, "features")?,
            target: optional(target, line, "target")?,
            test: optional(test, line, "test")?,
            fixture: optional(fixture, line, "fixture")?,
            expected,
            pattern: pattern.to_string(),
        };
        if control.pattern.is_empty() || control.pattern == "-" {
            return Err(format!(
                "{TABLE}:{line}: {name}: no pattern its refusal must name"
            ));
        }
        let shape = match runner {
            Runner::Native => {
                matches!(control.toolchain.as_deref(), Some("nightly" | "stable"))
                    && control.package.is_some()
                    && control.target.is_some()
                    && control.test.is_some()
            }
            // Miri is a component of the nightly toolchain alone, and runs
            // no trybuild suite.
            Runner::Miri(_) => {
                control.toolchain.as_deref() == Some("nightly")
                    && control.package.is_some()
                    && control.target.is_some()
                    && control.test.is_some()
                    && control.fixture.is_none()
            }
            // The proof build's own shell (Kani pins its toolchain), the
            // library alone, its features fixed by the build ([`crate::proofs`]).
            Runner::Kani => {
                control.toolchain.as_deref() == Some(KANI_TOOLCHAIN)
                    && control.package.is_some()
                    && control.features.is_none()
                    && control.target.as_deref() == Some(dcbor_model_bounds::LIBRARY)
                    && control.test.is_some()
                    && control.fixture.is_none()
            }
            Runner::Model(_) => {
                control.toolchain.is_none()
                    && control.package.is_none()
                    && control.features.is_none()
                    && control.target.is_none()
                    && control.test.is_none()
                    && control.fixture.is_none()
            }
        };
        if !shape {
            return Err(format!(
                "{TABLE}:{line}: {name}: the columns a {} control requires, and only those",
                runner.name()
            ));
        }
        if controls
            .iter()
            .any(|other| other.name == control.name && other.runner == runner)
        {
            return Err(format!(
                "{TABLE}:{line}: {name} under {} twice",
                runner.name()
            ));
        }
        if let Some(other) = controls
            .iter()
            .find(|other| other.name == control.name && other.diff != control.diff)
        {
            return Err(format!(
                "{TABLE}:{line}: {name} names {} and {}",
                other.diff, control.diff
            ));
        }
        controls.push(control);
    }
    if controls.is_empty() {
        return Err(format!("{TABLE}: no control"));
    }
    Ok(controls)
}

/// What the hunks of the diff `diff`, of text `text`, hold that an exact
/// application (`patch -p0 --fuzz=0`, tests/gate-common.sh `patch_diff`)
/// cannot place where they say: a header that is not `@@ -a[,b] +c[,d] @@`,
/// a header whose counts are not its body's, or leading and trailing context
/// of different lengths, since GNU patch places a hunk whose trailing context
/// is shorter only at the file's end, and one whose leading context is
/// shorter only at its start. A hunk at the file's first line may lead with
/// less.
pub fn hunk_faults(diff: &str, text: &str) -> Vec<String> {
    let range = |range: &str| -> Option<(usize, usize)> {
        match range.split_once(',') {
            Some((start, count)) => Some((start.parse().ok()?, count.parse().ok()?)),
            None => Some((range.parse().ok()?, 1)),
        }
    };
    fn context(line: &str) -> bool {
        line.starts_with(' ') || line.is_empty()
    }
    let lines: Vec<&str> = text.lines().collect();
    let mut faults = Vec::new();
    let mut at = 0;
    while at < lines.len() {
        let Some(header) = lines[at].strip_prefix("@@ -") else {
            at += 1;
            continue;
        };
        let number = at + 1;
        let ranges = header.split_once(" @@").and_then(|(ranges, _)| {
            let (old, new) = ranges.split_once(" +")?;
            Some((range(old)?, range(new)?))
        });
        at += 1;
        let start = at;
        while at < lines.len() && !lines[at].starts_with("@@ ") && !lines[at].starts_with("--- ") {
            at += 1;
        }
        let Some(((old_start, old_count), (_, new_count))) = ranges else {
            faults.push(format!(
                "{diff}:{number}: a hunk header that is not `@@ -a,b +c,d @@`"
            ));
            continue;
        };
        let body: Vec<&str> = lines[start..at]
            .iter()
            .copied()
            .filter(|line| !line.starts_with('\\'))
            .collect();
        let old = body
            .iter()
            .filter(|line| context(line) || line.starts_with('-'))
            .count();
        let new = body
            .iter()
            .filter(|line| context(line) || line.starts_with('+'))
            .count();
        // `take_while` borrows each item once more than `filter` does.
        let leading = body.iter().take_while(|line| context(line)).count();
        let trailing = body.iter().rev().take_while(|line| context(line)).count();
        if (old, new) != (old_count, new_count) {
            faults.push(format!(
                "{diff}:{number}: the header counts {old_count} old and {new_count} new \
                 lines, the body holds {old} and {new}"
            ));
        }
        if leading != trailing && !(old_start == 1 && leading < trailing) {
            faults.push(format!(
                "{diff}:{number}: {leading} lines of leading context and {trailing} of \
                 trailing: an exact application places it only at the file's start or end"
            ));
        }
    }
    faults
}

/// What the table and the diffs under `root` disagree on: a diff with no
/// row, a row whose diff does not exist, a diff whose hunks an exact
/// application cannot place ([`hunk_faults`]).
pub fn completeness(root: &Path, controls: &[Control]) -> Result<Vec<String>, String> {
    let directory = root.join(DIRECTORY);
    let entries = std::fs::read_dir(&directory)
        .map_err(|error| format!("{}: {error}", directory.display()))?;
    let mut diffs = Vec::new();
    for entry in entries {
        let path = entry
            .map_err(|error| format!("{}: {error}", directory.display()))?
            .path();
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| format!("{}: a name that is not UTF-8", path.display()))?;
        if name.ends_with(".patch") {
            diffs.push(format!("{DIRECTORY}/{name}"));
        }
    }
    diffs.sort();
    let mut faults = Vec::new();
    for diff in &diffs {
        if !controls.iter().any(|control| &control.diff == diff) {
            faults.push(format!(
                "{diff}: a planted diff no control runs; add its row to {TABLE}"
            ));
        }
        let path = root.join(diff);
        let text = std::fs::read_to_string(&path)
            .map_err(|error| format!("{}: {error}", path.display()))?;
        faults.extend(hunk_faults(diff, &text));
    }
    for control in controls {
        if !diffs.contains(&control.diff) {
            faults.push(format!(
                "{TABLE}: {} names {}, which does not exist",
                control.name, control.diff
            ));
        }
    }
    Ok(faults)
}

/// The table under `root`, parsed, and complete against its diffs.
pub fn read(root: &Path) -> Result<Vec<Control>, String> {
    let path = root.join(TABLE);
    let text =
        std::fs::read_to_string(&path).map_err(|error| format!("{}: {error}", path.display()))?;
    let controls = parse(&text)?;
    let faults = completeness(root, &controls)?;
    if faults.is_empty() {
        Ok(controls)
    } else {
        Err(faults.join("\n"))
    }
}

/// The control `name` under `runner`.
pub fn find<'c>(
    controls: &'c [Control],
    name: &str,
    runner: Runner,
) -> Result<&'c Control, String> {
    controls
        .iter()
        .find(|control| control.name == name && control.runner == runner)
        .ok_or_else(|| format!("{TABLE}: no control {name} under {}", runner.name()))
}

/// Trybuild's block for `fixture` in a suite's `report`: its header line
/// (`test FIXTURE ... `, with or without the expectation trybuild prints in
/// a suite of both pass and compile-fail fixtures, `[should fail to
/// compile]`), what follows it on that line, and every line after it up to
/// the next fixture's header (trybuild 1.0.122 `message.rs`, `begin_test`).
fn fixture_block<'r>(report: &'r str, fixture: &str) -> Option<Vec<&'r str>> {
    let plain = format!("test {fixture} ... ");
    let annotated = [
        format!("test {fixture} [should fail to compile] ... "),
        format!("test {fixture} [should pass] ... "),
    ];
    let lines: Vec<&str> = report.lines().collect();
    let (start, rest) = lines.iter().enumerate().find_map(|(at, line)| {
        line.strip_prefix(plain.as_str())
            .or_else(|| {
                annotated
                    .iter()
                    .find_map(|header| line.strip_prefix(header.as_str()))
            })
            .map(|rest| (at, rest))
    })?;
    let mut block = vec![rest];
    block.extend(
        lines[start + 1..]
            .iter()
            .take_while(|line| !line.starts_with("test "))
            .copied(),
    );
    Some(block)
}

/// Whether a Miri run's `report` is its one test's: libtest selected exactly
/// one test (`running 1 test`, printed before any test starts) and started
/// `test`, named whole (`test NAME ... `). A run undefined behavior ends
/// prints no summary, so [`outcome::ran_one`] cannot be asked of it.
fn started_alone(report: &str, test: &str) -> bool {
    let running: Vec<&str> = report
        .lines()
        .filter(|line| line.starts_with("running "))
        .collect();
    let header = format!("test {test} ... ");
    let started: Vec<&str> = report
        .lines()
        .filter(|line| line.starts_with("test ") && line.contains(" ... "))
        .collect();
    running == ["running 1 test"] && started.len() == 1 && started[0].starts_with(header.as_str())
}

/// Whether `report` is the one selected test's own: a native run executed
/// exactly one test ([`outcome::ran_one`]), or, when its process ended
/// by SIGABRT before libtest printed a summary, selected and started exactly its one test
/// ([`started_alone`]); a Miri run selected and started exactly its one test;
/// a model control's run is one model's process already.
fn alone(control: &Control, report: &str, outcome: Outcome) -> bool {
    match control.runner {
        Runner::Native => {
            if report.lines().any(|line| line.starts_with("test result: ")) {
                outcome::ran_one(report)
            } else {
                outcome == Outcome::AbnormalTermination
                    && control
                        .test
                        .as_deref()
                        .is_some_and(|test| started_alone(report, test))
            }
        }
        Runner::Miri(_) => control
            .test
            .as_deref()
            .is_some_and(|test| started_alone(report, test)),
        Runner::Kani => control
            .test
            .as_deref()
            .is_some_and(|harness| checked_alone(report, harness, outcome)),
        Runner::Model(_) => true,
    }
}

/// Whether the shared proof parser finds exactly the selected harness and
/// its reported outcome agrees with the classified run.
fn checked_alone(report: &str, harness: &str, outcome: Outcome) -> bool {
    crate::proofs::checked(report).is_ok_and(|checked| {
        matches!(checked.as_slice(), [(name, result)] if name == harness && *result == outcome)
    })
}

/// Whether a run of `control` with its diff applied refused it by its own
/// rule: the planned outcome; for a run of one test, natively or under
/// Miri, that test alone ([`alone`]) unless the planned outcome is a refused
/// build; and the pattern in that run's own report, or in its fixture's
/// block. Every other run is a fault naming why.
pub fn judge(control: &Control, outcome: Outcome, report: &str) -> Result<(), String> {
    if outcome == Outcome::NoVerdict || outcome != control.expected {
        return Err(format!(
            "{}: {outcome}, where the planted defect's refusal is {}",
            control.name, control.expected
        ));
    }
    if outcome != Outcome::BuildRefused && !alone(control, report, outcome) {
        return Err(format!(
            "{}: the run did not execute exactly its one test, so its report is not that test's",
            control.name
        ));
    }
    let named = match &control.fixture {
        Some(fixture) => fixture_block(report, fixture)
            .is_some_and(|block| block.iter().any(|line| line.contains(&control.pattern))),
        None => report.contains(&control.pattern),
    };
    if named {
        Ok(())
    } else {
        Err(format!(
            "{}: {outcome} without naming {:?} in its own report: refused by another rule than its own",
            control.name, control.pattern
        ))
    }
}

/// Whether a run of `control` in the same copy with its diff reversed
/// restored it: its one test ran and passed, natively or under Miri alike
/// (a passing run prints libtest's summary either way).
pub fn restored(control: &Control, outcome: Outcome, report: &str) -> Result<(), String> {
    let one = match control.runner {
        Runner::Kani => alone(control, report, outcome),
        Runner::Native | Runner::Miri(_) | Runner::Model(_) => outcome::ran_one(report),
    };
    if outcome == Outcome::Pass && one {
        Ok(())
    } else {
        Err(format!(
            "{}: with the diff reversed the test did not run alone and pass ({outcome})",
            control.name
        ))
    }
}

/// Whether a run of the Kani `control`'s harness in its copy before the diff
/// is applied verified it: the harness checked alone and passed. A control
/// planted into a harness with no verdict on the unmutated commit (no
/// result, a timeout, a solver out of memory: `NoVerdict`; a failure; an
/// unsupported construct or a short bound) shows nothing of its defect, so
/// its red side is never run ([`evidence`] requires this baseline).
pub fn verified(control: &Control, outcome: Outcome, report: &str) -> Result<(), String> {
    if control.runner != Runner::Kani {
        return Err(format!(
            "{}: a {} control has no baseline side; a Kani control's does",
            control.name,
            control.runner.name()
        ));
    }
    if outcome == Outcome::Pass && alone(control, report, outcome) {
        Ok(())
    } else {
        Err(format!(
            "{}: the unmutated harness did not verify alone ({outcome}), so no control is run against it",
            control.name
        ))
    }
}

/// One run of the native `control` in the copy `root`: its target built into
/// `target_dir`, its one test run alone, logged under `logs` by `side`. Its
/// outcome and report: a refused build's log, or the run's.
pub fn observe(
    root: &Path,
    target_dir: &Path,
    logs: &Path,
    control: &Control,
    side: &str,
) -> Result<(Outcome, String), String> {
    let missing = |what: &str| format!("{}: a native control without its {what}", control.name);
    if control.runner == Runner::Kani {
        let harness = control.test.as_deref().ok_or_else(|| missing("harness"))?;
        let (termination, text) =
            crate::process::run_kani(root, harness, target_dir, &logs.join(format!("{side}.log")))?;
        return Ok((outcome::kani(termination, &text), text));
    }
    let package = control
        .package
        .as_deref()
        .ok_or_else(|| missing("package"))?;
    let target = control.target.as_deref().ok_or_else(|| missing("target"))?;
    let test = control.test.as_deref().ok_or_else(|| missing("test"))?;
    let built = crate::process::build_target(
        root,
        package,
        control.features.as_deref(),
        target,
        target_dir,
        &logs.join(format!("{side}.build.log")),
    )?;
    let executable = match built {
        Ok(executable) => executable,
        Err(log) => return Ok((Outcome::BuildRefused, log)),
    };
    let (termination, text) =
        crate::process::run_test(&executable, test, &[], &logs.join(format!("{side}.log")))?;
    Ok((outcome::native(Kind::Test, termination, &text), text))
}

/// The directory of `control`'s run under `logs`: its name, and for a Miri
/// control its model too, since one diff may be a control under each model.
pub fn directory(logs: &Path, control: &Control) -> std::path::PathBuf {
    match control.runner {
        Runner::Miri(model) => logs.join(format!("{}-{model}", control.name)),
        Runner::Native | Runner::Model(_) => logs.join(&control.name),
        Runner::Kani => logs.join(format!("{}-kani", control.name)),
    }
}

/// The evidence of every control of `toolchain` under `logs` that runs one
/// test (native, or under a Miri model), one directory per control written
/// by `tests/controls.sh` ([`directory`]): a Kani control's harness verified
/// on the unmutated copy first ([`verified`]), its red judgement and its
/// restored judgement each passed, and the copy's source digest changed by
/// the diff and equal again once it was reversed.
pub fn evidence(controls: &[Control], logs: &Path, toolchain: &str) -> Vec<String> {
    let mut faults = Vec::new();
    for control in controls.iter().filter(|control| {
        control.runner.runs_one_test() && control.toolchain.as_deref() == Some(toolchain)
    }) {
        let directory = directory(logs, control);
        // The control as its runner runs it: a Miri control's model named.
        let label = format!("{} under {}", control.name, control.runner.name());
        let read = |file: &str| {
            std::fs::read_to_string(directory.join(file)).map(|text| text.trim().to_string())
        };
        if control.runner == Runner::Kani {
            match read("baseline.judged") {
                Ok(baseline) if baseline == "verified" => {}
                Ok(baseline) => faults.push(format!("{label}: no verified baseline: {baseline}")),
                Err(_) => faults.push(format!(
                    "{label}: its harness never ran unmutated ({})",
                    directory.display()
                )),
            }
        }
        match (read("red.judged"), read("green.judged")) {
            (Ok(red), Ok(green)) => {
                if red != "refused" {
                    faults.push(format!("{label}: not seen red: {red}"));
                }
                if green != "restored" {
                    faults.push(format!("{label}: not seen green again: {green}"));
                }
            }
            _ => faults.push(format!("{label}: never run ({})", directory.display())),
        }
        match (
            read("before.sha256"),
            read("planted.sha256"),
            read("after.sha256"),
        ) {
            (Ok(before), Ok(planted), Ok(after)) => {
                if before == planted {
                    faults.push(format!("{label}: the diff changed no source"));
                }
                if before != after {
                    faults.push(format!(
                        "{label}: the copy differs from its source once the diff is reversed"
                    ));
                }
            }
            _ => faults.push(format!("{label}: no source digests")),
        }
    }
    faults
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod kani_tests {
    use super::*;

    const HARNESS: &str = "bounded::proofs::checked_add_is_exact";

    fn row(toolchain: &str, features: &str, target: &str) -> String {
        format!(
            "x\ttests/data/controls/x.patch\tkani\t{toolchain}\tdcbor\t{features}\t{target}\t\
             {HARNESS}\t-\tfailed\ta planted failure"
        )
    }

    /// A Kani row names the proof shell, the library and a harness, and no
    /// features: the build fixes them. Any other shape is refused.
    #[test]
    fn a_kani_row_has_the_proof_builds_shape() {
        let parsed = parse(&row("kani", "-", "lib")).expect("a Kani row parses");
        assert_eq!(parsed[0].runner, Runner::Kani);
        assert_eq!(parsed[0].render(), row("kani", "-", "lib"));
        let inconclusive = row("kani", "-", "lib").replace("\tfailed\t", "\tno_verdict\t");
        assert!(
            parse(&inconclusive)
                .unwrap_err()
                .contains("is no refusal outcome"),
            "an inconclusive run cannot be a control's expected refusal"
        );
        for wrong in [
            row("nightly", "-", "lib"),
            row("kani", "all", "lib"),
            row("kani", "-", "encode"),
        ] {
            assert!(
                parse(&wrong)
                    .unwrap_err()
                    .contains("the columns a kani control requires")
            );
        }
    }

    /// A Kani report is its harness's alone only when exactly that harness
    /// was checked and the summary counts one; the pattern must be in it.
    #[test]
    fn a_kani_refusal_is_judged_by_its_one_harness() {
        let control = &parse(&row("kani", "-", "lib")).unwrap()[0];
        let report = format!(
            "Checking harness {HARNESS}...\n ** 1 of 3 failed\nFailed Checks: a planted failure\nVERIFICATION:- FAILED\n\
             Manual Harness Summary:\nVerification failed for - {HARNESS}\n\
             Complete - 0 successfully verified harnesses, 1 failures, 1 total.\n"
        );
        assert_eq!(judge(control, Outcome::Failed, &report), Ok(()));
        let two = format!("Checking harness other...\n{report}");
        assert!(
            judge(control, Outcome::Failed, &two).is_err(),
            "two harnesses checked"
        );
        let unnamed = report.replace("a planted failure", "another check");
        assert!(
            judge(control, Outcome::Failed, &unnamed).is_err(),
            "refused by another rule"
        );
        let passed = format!(
            "Checking harness {HARNESS}...\nVERIFICATION:- SUCCESSFUL\nManual Harness Summary:\n\
             Complete - 1 successfully verified harnesses, 0 failures, 1 total.\n"
        );
        assert_eq!(restored(control, Outcome::Pass, &passed), Ok(()));
        assert!(restored(control, Outcome::Pass, &two).is_err());
        assert!(judge(control, Outcome::Failed, &passed).is_err());
        assert!(restored(control, Outcome::Pass, &report).is_err());
        // The baseline: the unmutated harness verified alone, and only then;
        // a run with no verdict, a failure, or another harness's report
        // blocks the control before its diff is applied.
        assert_eq!(verified(control, Outcome::Pass, &passed), Ok(()));
        for (outcome, text) in [
            (Outcome::Failed, &report),
            (Outcome::Pass, &two),
            (Outcome::Pass, &report),
        ] {
            assert!(
                verified(control, outcome, text).is_err(),
                "a baseline was verified by {outcome}: {text}"
            );
        }
        for block in outcome::fixtures::kani_no_verdict_blocks(HARNESS) {
            let incomplete = format!(
                "{block}Complete - 0 successfully verified harnesses, 1 failures, 1 total.\n"
            );
            for classified in [Outcome::Pass, Outcome::NoVerdict, Outcome::Failed] {
                assert!(
                    verified(control, classified, &incomplete)
                        .is_err_and(|fault| fault.contains("did not verify")),
                    "a harness without a verdict was taken for a verified baseline"
                );
            }
        }
        let mut native = control.clone();
        native.runner = Runner::Native;
        assert!(
            verified(&native, Outcome::Pass, &passed)
                .is_err_and(|fault| fault.contains("has no baseline side")),
            "a native control was given a baseline side"
        );
        for block in outcome::fixtures::kani_no_verdict_blocks(HARNESS) {
            let incomplete = format!(
                "{block}Failed Checks: a planted failure\n\
                 Complete - 0 successfully verified harnesses, 1 failures, 1 total.\n"
            );
            for classified in [Outcome::Failed, Outcome::NoVerdict] {
                assert!(
                    judge(control, classified, &incomplete).is_err(),
                    "a control accepted a no-verdict report as its refusal"
                );
            }
        }
    }

    /// A Kani control's evidence requires its harness verified on the
    /// unmutated copy (`baseline.judged`, `verified`) beside its red and green
    /// judgements: one seen red and green with no baseline, or with a
    /// baseline that recorded no verdict, is no evidence.
    #[test]
    fn a_kani_control_is_evidence_only_over_a_verified_baseline() {
        let control = parse(&row("kani", "-", "lib")).unwrap();
        let logs = std::env::temp_dir().join(format!("dcbor-kani-baseline-{}", std::process::id()));
        let at = directory(&logs, &control[0]);
        std::fs::create_dir_all(&at).expect("a fixture directory");
        let write = |file: &str, text: &str| std::fs::write(at.join(file), text).unwrap();
        write("red.judged", "refused\n");
        write("green.judged", "restored\n");
        write("before.sha256", "a\n");
        write("planted.sha256", "b\n");
        write("after.sha256", "a\n");
        let unbased = evidence(&control, &logs, KANI_TOOLCHAIN);
        assert!(
            unbased
                .iter()
                .any(|fault| fault.contains("never ran unmutated")),
            "a Kani control without a baseline was evidence: {unbased:#?}"
        );
        write(
            "baseline.judged",
            "x: the unmutated harness did not verify alone (no_verdict), so no control is run against it\n",
        );
        let inconclusive = evidence(&control, &logs, KANI_TOOLCHAIN);
        assert!(
            inconclusive
                .iter()
                .any(|fault| fault.contains("no verified baseline")),
            "a Kani control without a baseline was evidence: {inconclusive:#?}"
        );
        write("baseline.judged", "verified\n");
        let based = evidence(&control, &logs, KANI_TOOLCHAIN);
        std::fs::remove_dir_all(&logs).expect("the fixture removed");
        assert_eq!(based, Vec::<String>::new());
    }
}
