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

use std::collections::{BTreeMap, BTreeSet};
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
    /// The verification layer a native or Miri control's test runs at
    /// ([`dcbor_record::Rigor`]), which its run sets as
    /// [`dcbor_record::RIGOR`] whatever the launcher's environment holds;
    /// none for a Kani or model control, whose run never reads it.
    pub rigor: Option<dcbor_record::Rigor>,
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

const COLUMNS: usize = 12;

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
            self.rigor
                .map_or_else(|| "-".to_string(), |rigor| rigor.name().to_string()),
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

/// The rigor column: `-`, or a layer by its name ([`dcbor_record::Rigor`]);
/// any other value is refused naming the layers.
fn rigor(value: &str, line: usize) -> Result<Option<dcbor_record::Rigor>, String> {
    if value == "-" {
        return Ok(None);
    }
    dcbor_record::Rigor::ALL
        .into_iter()
        .find(|rigor| rigor.name() == value)
        .map(Some)
        .ok_or_else(|| {
            let names: Vec<&str> = dcbor_record::Rigor::ALL
                .into_iter()
                .map(dcbor_record::Rigor::name)
                .collect();
            format!(
                "{TABLE}:{line}: no rigor {value:?}; the layers are {}, or `-`",
                names.join(", ")
            )
        })
}

/// The table's rows, each validated: twelve columns; a diff of the controls
/// directory; a known runner and expected outcome; a native row naming its
/// toolchain, package, rigor, target and test, a Miri row the same, a Kani
/// row no rigor, a model row none of them; a pattern; no (name, runner)
/// twice; one diff per name.
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
            layer,
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
            rigor: rigor(layer, line)?,
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
            // A test's layer decides what it selects, so its row states it.
            Runner::Native => {
                matches!(control.toolchain.as_deref(), Some("nightly" | "stable"))
                    && control.package.is_some()
                    && control.rigor.is_some()
                    && control.target.is_some()
                    && control.test.is_some()
            }
            // Miri is a component of the nightly toolchain alone, and runs
            // no trybuild suite.
            Runner::Miri(_) => {
                control.toolchain.as_deref() == Some("nightly")
                    && control.package.is_some()
                    && control.rigor.is_some()
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
                    && control.rigor.is_none()
                    && control.target.as_deref() == Some(dcbor_model_bounds::LIBRARY)
                    && control.test.is_some()
                    && control.fixture.is_none()
            }
            Runner::Model(_) => {
                control.toolchain.is_none()
                    && control.package.is_none()
                    && control.features.is_none()
                    && control.rigor.is_none()
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

/// The table under `root`, parsed, and complete against its diffs
/// ([`registry`]).
pub fn read(root: &Path) -> Result<Vec<Control>, String> {
    registry(root).map(|registry| registry.controls)
}

/// A registry of controls: the table's text, the digest of its bytes (the
/// registry's identity), and the table parsed from that same text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Registry {
    pub sha256: String,
    pub text: String,
    pub controls: Vec<Control>,
}

impl Registry {
    /// The registry of the table `text`, parsed alone, its diffs not read:
    /// what a kept readiness recomputes a control run's selection from,
    /// where the registry is retained as text.
    pub fn of_text(text: &str) -> Result<Self, String> {
        Ok(Self {
            sha256: crate::process::sha256_bytes(text.as_bytes())?,
            text: text.to_string(),
            controls: parse(text)?,
        })
    }
}

/// The registry under `root`: the table's bytes read once, their digest the
/// registry's identity, and those bytes parsed ([`Registry::of_text`]),
/// complete against its diffs.
pub fn registry(root: &Path) -> Result<Registry, String> {
    let path = root.join(TABLE);
    let bytes = std::fs::read(&path).map_err(|error| format!("{}: {error}", path.display()))?;
    let text = String::from_utf8(bytes)
        .map_err(|error| format!("{}: not UTF-8: {error}", path.display()))?;
    let registry = Registry::of_text(&text)?;
    let faults = completeness(root, &registry.controls)?;
    if faults.is_empty() {
        Ok(registry)
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

/// The side of a Kani control a run is: its harness on the unmutated copy,
/// with the registered diff applied, or with it reversed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Side {
    Baseline,
    Red,
    Green,
}

impl Side {
    pub fn parse(text: &str) -> Result<Self, String> {
        match text {
            "baseline" => Ok(Self::Baseline),
            "red" => Ok(Self::Red),
            "green" => Ok(Self::Green),
            other => Err(format!(
                "no control side {other:?}; the sides are baseline, red and green"
            )),
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Baseline => "baseline",
            Self::Red => "red",
            Self::Green => "green",
        }
    }
}

/// The version of a control side's authorization record.
pub const AUTHORIZATION_VERSION: u64 = 1;

/// Why a control copy's build is not the calibration's artifact: the
/// instrumented binary records its source paths, and a control's copy is
/// built at its own location (`target/control-copies/RUN`, built into
/// `target/control-builds`), the calibration at `target/proof-source`. The
/// baseline's artifact is recorded beside the calibration's, its timing held
/// to the calibration's prediction; the restored green side's must equal the
/// baseline's.
pub const TRANSFER: &str = "a control copy builds at its own location, whose source paths the \
     instrumented binary records; its baseline's artifact is recorded beside the calibration's \
     and its timing held to the calibration's prediction, and its restored side's artifact must \
     equal its baseline's";

/// How a side's source stands against its baseline's: the unplanted copy
/// itself; the baseline with the registered diff applied exactly, these
/// paths changed by it; or none changed.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Transition {
    Unplanted,
    Planted { paths: BTreeSet<String> },
    Restored,
}

/// A verified baseline as a red or green side cites it: its run, the digest
/// of its manifest, the artifact its harness ran on, and its source state.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BaselineReceipt {
    pub run: String,
    pub manifest_sha256: String,
    pub artifact_sha256: String,
    pub source_sha256: String,
}

/// What a control side's run is authorized for, as its evidence keeps it
/// (`authorization.json`, written before the run launches): the registry's
/// control and the digest of its diff's bytes, the harness, the side, the
/// digest of the predictions it is held to, the copy and the build
/// directory, the copy's source state and each path's digest
/// ([`crate::proofs::SourceState::digests`]), for a baseline the complete
/// state its copy must become with the diff applied ([`planted_state`]), the
/// source transition the side was validated for, the baseline a red or
/// green side cites, and the
/// calibration's artifact beside the transfer that explains why a copy's
/// build is not it ([`TRANSFER`]).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationRecord {
    pub version: u64,
    pub control: String,
    pub patch_sha256: String,
    pub harness: String,
    pub side: Side,
    pub expectations_sha256: String,
    pub copy: String,
    pub build: String,
    pub source_sha256: String,
    pub sources: BTreeMap<String, String>,
    pub planted: Option<BTreeMap<String, String>>,
    pub transition: Transition,
    pub baseline: Option<BaselineReceipt>,
    pub calibration_artifact_sha256: String,
    pub transfer: String,
}

/// A control side's validated authorization ([`AuthorizationRecord`]):
/// made only here, by the control runner's validation of the side
/// ([`authorize`]), so no run is a control side without it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Authorization {
    record: AuthorizationRecord,
}

impl Authorization {
    pub fn record(&self) -> &AuthorizationRecord {
        &self.record
    }

    /// The verified baseline a restored green side's artifact must equal.
    pub fn restored_baseline(&self) -> Option<&BaselineReceipt> {
        match self.record.side {
            Side::Green => self.record.baseline.as_ref(),
            Side::Baseline | Side::Red => None,
        }
    }
}

/// How a planted diff is run against a tree ([`patch`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    /// Plant it.
    Apply,
    /// Reverse it, exactly as it was applied.
    Reverse,
    /// Check that it would apply, changing nothing.
    Check,
}

impl Direction {
    pub fn parse(text: &str) -> Result<Self, String> {
        match text {
            "apply" => Ok(Self::Apply),
            "reverse" => Ok(Self::Reverse),
            "check" => Ok(Self::Check),
            other => Err(format!(
                "no patch direction {other:?}; the directions are apply, reverse and check"
            )),
        }
    }
}

/// The one invocation of a planted diff: the diff's `bytes` run against the
/// tree at `directory` by GNU patch, exactly (`-p0`, no fuzz, no backup),
/// in `direction`, the bytes given as its standard input so the diff run is
/// the diff digested. GNU patch places a hunk whose trailing context is
/// shorter than its leading context only at the file's end, and one whose
/// leading context is shorter only at its start, so every hunk carries
/// equal context on both sides ([`hunk_faults`]). Every applier, reverser
/// and preflight of a control is this one invocation (`gate patch`,
/// tests/gate-common.sh `patch_diff`); refused with patch's own output.
pub fn patch(bytes: &[u8], directory: &Path, direction: Direction) -> Result<(), String> {
    use std::io::Write;
    let mut command = std::process::Command::new("patch");
    command.arg("-d").arg(directory).args([
        "-p0",
        "--batch",
        "--fuzz=0",
        "--no-backup-if-mismatch",
        "--quiet",
    ]);
    match direction {
        Direction::Apply => {}
        Direction::Reverse => {
            command.arg("-R");
        }
        Direction::Check => {
            command.arg("--dry-run");
        }
    }
    let mut child = command
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|error| format!("patch: {error}"))?;
    let written = child
        .stdin
        .take()
        .ok_or("patch: no standard input")?
        .write_all(bytes);
    let output = child
        .wait_with_output()
        .map_err(|error| format!("patch: {error}"))?;
    written.map_err(|error| format!("patch: writing the diff: {error}"))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "patch -d {} ({direction:?}): {}: {}{}",
            directory.display(),
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ))
    }
}

/// The complete source state the verified baseline `state` must become
/// with the diff `bytes` applied, path by path
/// ([`crate::proofs::SourceState::digests`]): the baseline written out at
/// `at` (a directory of the control's own, created exclusively,
/// [`crate::proofs::SourceState::materialize`]), the diff applied there by
/// the one invocation ([`patch`]) exactly as a red side's runner applies it,
/// the result read back, and the directory removed. Every creation,
/// deletion, link and mode the diff makes is in the state as patch makes it;
/// a diff that does not apply to the baseline refuses it.
fn planted_state(
    state: &crate::proofs::SourceState,
    bytes: &[u8],
    at: &Path,
) -> Result<BTreeMap<String, String>, String> {
    state.materialize(at)?;
    let planted = patch(bytes, at, Direction::Apply)
        .map_err(|fault| format!("the diff does not apply to the baseline: {fault}"))
        .and_then(|()| crate::proofs::SourceState::read(at)?.digests());
    let removed = std::fs::remove_dir_all(at).map_err(|error| format!("{}: {error}", at.display()));
    let planted = planted?;
    removed?;
    Ok(planted)
}

/// The verified baseline of the Kani `control` under `directory`, as a red
/// or green side must cite it: judged verified (`baseline.judged`); its
/// evidence a finished run's whose manifest is complete
/// ([`crate::proofs::read_manifest`]), every record read through it; its
/// judgement accepted; and its authorization a baseline's of this control
/// and harness, of the diff whose bytes have digest `patch_sha256`, under the
/// predictions of digest `expectations_sha256`. The receipt and the
/// baseline's own authorization record.
fn baseline_receipt(
    directory: &Path,
    control: &Control,
    harness: &str,
    patch_sha256: &str,
    expectations_sha256: &str,
) -> Result<(BaselineReceipt, AuthorizationRecord), String> {
    let judged = std::fs::read_to_string(directory.join("baseline.judged"))
        .map_err(|_| format!("{}: no baseline was run", control.name))?;
    if judged.trim() != "verified" {
        return Err(format!(
            "{}: no verified baseline: {}",
            control.name,
            judged.trim()
        ));
    }
    let evidence = directory.join("baseline.evidence");
    let manifest = crate::proofs::read_manifest(&evidence, None)
        .map_err(|fault| format!("{}: its baseline: {fault}", control.name))?;
    let records = manifest.records(&evidence, crate::proofs::Binaries::Held);
    let json = |file: &str| -> Result<serde_json::Value, String> {
        crate::proofs::strict_json(&records.read(&evidence.join(file))?)
            .map_err(|fault| format!("{}: its baseline's {file}: {fault}", control.name))
    };
    if json("judgement.json")? != serde_json::json!({"status": "accepted"}) {
        return Err(format!(
            "{}: its baseline's judgement is not accepted",
            control.name
        ));
    }
    let record: AuthorizationRecord = serde_json::from_value(json("authorization.json")?)
        .map_err(|error| format!("{}: its baseline's authorization: {error}", control.name))?;
    let fault = if record.version != AUTHORIZATION_VERSION || record.side != Side::Baseline {
        Some("is no baseline's".to_string())
    } else if record.control != control.name || record.harness != harness {
        Some(format!(
            "is control {}'s, harness {}",
            record.control, record.harness
        ))
    } else if record.patch_sha256 != patch_sha256 {
        Some(format!(
            "is of the diff {}, whose bytes are now {patch_sha256}",
            record.patch_sha256
        ))
    } else if record.expectations_sha256 != expectations_sha256 {
        Some(format!(
            "froze the predictions {}, this side is given {expectations_sha256}",
            record.expectations_sha256
        ))
    } else {
        None
    };
    if let Some(fault) = fault {
        return Err(format!(
            "{}: the baseline authorization it cites {fault}",
            control.name
        ));
    }
    let artifact_sha256 = json("execution.json")?["artifacts"][harness]
        .as_str()
        .filter(|digest| crate::proofs::sha256_text(digest))
        .ok_or_else(|| {
            format!(
                "{}: its baseline recorded no artifact of {harness}",
                control.name
            )
        })?
        .to_string();
    Ok((
        BaselineReceipt {
            run: manifest.run().to_string(),
            manifest_sha256: manifest.sha256().to_string(),
            artifact_sha256,
            source_sha256: record.source_sha256.clone(),
        },
        record,
    ))
}

/// The authorization of the Kani `control`'s `side` in the copy `root`,
/// built into `target_dir`, its records under `directory`, held to
/// `expectations`: validated from the side's source and its records, never
/// assumed. A baseline's copy must be the unplanted source its runner
/// recorded once the copy was made (`before.sha256`). A red side must cite
/// its verified baseline ([`baseline_receipt`]) of the same diff bytes and
/// predictions, and its copy's complete source state must be, path for
/// path, the state its baseline's authorization computed by applying those
/// bytes to the baseline ([`planted_state`]), its source the one its runner
/// recorded with the diff applied (`planted.sha256`). A restored green side
/// must cite the
/// same baseline, and its copy must equal the baseline's in every path
/// (`after.sha256`).
fn authorize(
    root: &Path,
    target_dir: &Path,
    directory: &Path,
    control: &Control,
    side: Side,
    expectations: &crate::proofs::Expectations,
) -> Result<Authorization, String> {
    let harness = control
        .test
        .as_deref()
        .ok_or_else(|| format!("{}: a kani control without its harness", control.name))?;
    let diff = root.join(&control.diff);
    let patch = std::fs::read(&diff).map_err(|error| format!("{}: {error}", diff.display()))?;
    let patch_sha256 = crate::process::sha256_bytes(&patch)?;
    let calibration_artifact_sha256 = expectations
        .harness(harness)
        .ok_or_else(|| format!("{}: harness {harness} has no prediction", control.name))?
        .artifact_sha256()
        .to_string();
    let recorded = |file: &str| {
        std::fs::read_to_string(directory.join(file))
            .map(|text| text.trim().to_string())
            .map_err(|_| format!("{}: its runner recorded no {file}", control.name))
    };
    let state = crate::proofs::SourceState::read(root)?;
    let source_sha256 = state.digest()?;
    let (transition, baseline, sources, planted) = match side {
        Side::Baseline => {
            let before = recorded("before.sha256")?;
            if source_sha256 != before {
                return Err(format!(
                    "{}: the copy's source state is {source_sha256}, the unplanted copy was \
                     {before}: a baseline runs on the unplanted source alone",
                    control.name
                ));
            }
            let planted = planted_state(&state, &patch, &directory.join("baseline.planted"))
                .map_err(|fault| format!("{}: {fault}", control.name))?;
            (Transition::Unplanted, None, state.digests()?, Some(planted))
        }
        Side::Red | Side::Green => {
            let (receipt, base) = baseline_receipt(
                directory,
                control,
                harness,
                &patch_sha256,
                expectations.sha256(),
            )?;
            let listed: BTreeSet<Vec<u8>> = base
                .sources
                .keys()
                .map(|path| path.as_bytes().to_vec())
                .collect();
            let held = state.digests()?;
            let sources = state.with_deletions(&listed).digests()?;
            let changed: BTreeSet<String> = base
                .sources
                .keys()
                .chain(sources.keys())
                .filter(|path| base.sources.get(*path) != sources.get(*path))
                .cloned()
                .collect();
            if side == Side::Red {
                let expected = base.planted.as_ref().ok_or_else(|| {
                    format!(
                        "{}: the baseline authorization it cites records no planted state",
                        control.name
                    )
                })?;
                let differing: Vec<&String> = expected
                    .keys()
                    .chain(held.keys())
                    .filter(|path| expected.get(*path) != held.get(*path))
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect();
                if !differing.is_empty() {
                    return Err(format!(
                        "{}: the copy differs in {differing:?} from its baseline with the \
                         registered diff applied: the copy is not exactly the baseline with the \
                         diff applied",
                        control.name
                    ));
                }
                let planted = recorded("planted.sha256")?;
                if source_sha256 != planted {
                    return Err(format!(
                        "{}: the copy's source state is {source_sha256}, its runner recorded \
                         {planted} with the diff applied",
                        control.name
                    ));
                }
                (
                    Transition::Planted { paths: changed },
                    Some(receipt),
                    sources,
                    None,
                )
            } else {
                if !changed.is_empty() || source_sha256 != receipt.source_sha256 {
                    return Err(format!(
                        "{}: the restored copy differs from its baseline in {changed:?}: the \
                         restoration is incomplete",
                        control.name
                    ));
                }
                let after = recorded("after.sha256")?;
                if source_sha256 != after {
                    return Err(format!(
                        "{}: the copy's source state is {source_sha256}, its runner recorded \
                         {after} with the diff reversed",
                        control.name
                    ));
                }
                (Transition::Restored, Some(receipt), sources, None)
            }
        }
    };
    Ok(Authorization {
        record: AuthorizationRecord {
            version: AUTHORIZATION_VERSION,
            control: control.name.clone(),
            patch_sha256,
            harness: harness.to_string(),
            side,
            expectations_sha256: expectations.sha256().to_string(),
            copy: root.display().to_string(),
            build: target_dir.display().to_string(),
            source_sha256,
            sources,
            planted,
            transition,
            baseline,
            calibration_artifact_sha256,
            transfer: TRANSFER.to_string(),
        },
    })
}

/// One run of the native `control` in the copy `root`: its target built into
/// `target_dir`, its one test run alone, logged under `logs` by `side`; a
/// Kani control's harness checked alone by the run's selected `launcher`
/// (`proofs-identity`), its evidence reconciled with its policy
/// (`process::kani`). Its outcome and report: a refused build's log, or the
/// run's.
pub fn observe(
    root: &Path,
    target_dir: &Path,
    logs: &Path,
    control: &Control,
    side: &str,
    launcher: Option<&Path>,
) -> Result<(Outcome, String), String> {
    let missing = |what: &str| format!("{}: a native control without its {what}", control.name);
    if control.runner == Runner::Kani {
        let launcher = launcher.ok_or_else(|| {
            format!(
                "{}: a kani control without the run's launcher",
                control.name
            )
        })?;
        // Every side held to the census's predictions, under the
        // authorization validated for it: a calibration is never a side.
        let declared = crate::proofs::harnesses(&root.join("src"))?;
        let expectations = crate::proofs::expectations(root, &declared)?;
        let authorization = authorize(
            root,
            target_dir,
            logs,
            control,
            Side::parse(side)?,
            &expectations,
        )?;
        let harness = authorization.record().harness.clone();
        let purpose = crate::proofs::RunPurpose::Control {
            expectations,
            authorization: Box::new(authorization),
        };
        let selection = crate::proofs::Selection::one(&harness);
        let workload = crate::process::Workload::exported()?;
        let log = logs.join(format!("{side}.log"));
        let run = crate::process::KaniRequest {
            root,
            purpose: &purpose,
            selection: &selection,
            declared: &declared,
            target_dir,
            launcher,
            workload: &workload,
            log: &log,
        }
        .validate()?;
        let (termination, text) = crate::process::execute_kani(run)?;
        return Ok((outcome::kani(termination, &text), text));
    }
    let package = control
        .package
        .as_deref()
        .ok_or_else(|| missing("package"))?;
    let target = control.target.as_deref().ok_or_else(|| missing("target"))?;
    let test = control.test.as_deref().ok_or_else(|| missing("test"))?;
    let rigor = control.rigor.ok_or_else(|| missing("rigor"))?;
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
    // The test runs with the target directory it was built into, as under
    // `cargo test`: a test that builds (trybuild, through `cargo metadata`)
    // writes there, outside the copy, whose digest is its source alone
    // (`proofs::SourceState`). It runs at its row's layer, set here whatever
    // the launcher's environment holds: the layer decides what it selects.
    let target_dir = target_dir.to_str().ok_or_else(|| {
        format!(
            "{}: a target directory that is not UTF-8",
            target_dir.display()
        )
    })?;
    let (termination, text) = crate::process::run_test(
        &executable,
        test,
        &test_environment(target_dir, rigor),
        &logs.join(format!("{side}.log")),
    )?;
    Ok((outcome::native(Kind::Test, termination, &text), text))
}

/// What a native control's test runs with beside the controlled
/// environment: the target directory it was built into, and its row's
/// layer as [`dcbor_record::RIGOR`], which replaces whatever the launcher's
/// environment holds.
fn test_environment(target_dir: &str, rigor: dcbor_record::Rigor) -> Vec<(&'static str, String)> {
    vec![
        ("CARGO_TARGET_DIR", target_dir.to_string()),
        (dcbor_record::RIGOR, rigor.name().to_string()),
    ]
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

/// One selected control's result in a control run: the control, the runner
/// it ran under, and every fault of its evidence, none when it passed.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlResult {
    pub control: String,
    pub runner: String,
    pub faults: Vec<String>,
}

/// The controls a control run of `toolchain` under `runners` selects: every
/// control of the table that runs one test, of that toolchain, under one of
/// those runners, in the table's order. The one selection `tests/controls.sh`
/// lists (`gate control list`), the evidence judges ([`evidence`]) and a
/// calibration's readiness requires complete.
pub fn selected<'a>(
    controls: &'a [Control],
    toolchain: &str,
    runners: &[Runner],
) -> Vec<&'a Control> {
    controls
        .iter()
        .filter(|control| {
            control.runner.runs_one_test()
                && control.toolchain.as_deref() == Some(toolchain)
                && runners.contains(&control.runner)
        })
        .collect()
}

/// Every fault of `results`, in their order.
pub fn faults(results: &[ControlResult]) -> Vec<String> {
    results
        .iter()
        .flat_map(|result| result.faults.iter().cloned())
        .collect()
}

/// The evidence of every control of `toolchain` under `runners` ([`selected`])
/// under `logs`, one directory per control written by `tests/controls.sh`
/// ([`directory`]), one result each: a Kani control's harness verified on the
/// unmutated copy first ([`verified`]), its red judgement and its restored
/// judgement each passed, and the copy's source digest changed by the diff
/// and equal again once it was reversed.
pub fn evidence(
    controls: &[Control],
    logs: &Path,
    toolchain: &str,
    runners: &[Runner],
) -> Vec<ControlResult> {
    let mut results = Vec::new();
    for control in selected(controls, toolchain, runners) {
        let mut faults = Vec::new();
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
            // Its three sides ran one Kani: the launcher selected for the run,
            // and one verifier wherever a side's harness reached it (a side
            // refused before verification records none) (`process::kani`,
            // `execution.json`).
            let executions: Result<Vec<serde_json::Value>, String> = ["baseline", "red", "green"]
                .iter()
                .map(|side| {
                    let text = read(&format!("{side}.evidence/execution.json"))
                        .map_err(|_| format!("{label}: its {side} side recorded no execution"))?;
                    serde_json::from_str(&text)
                        .map_err(|error| format!("{label}: its {side} execution: {error}"))
                })
                .collect();
            match executions {
                Ok(executions) => {
                    let launchers: BTreeSet<String> = executions
                        .iter()
                        .map(|run| run["launcher"].to_string())
                        .collect();
                    let verifiers: BTreeSet<String> = executions
                        .iter()
                        .filter(|run| !run["verifier"].is_null())
                        .map(|run| run["verifier"].to_string())
                        .collect();
                    if launchers.len() != 1 || verifiers.len() > 1 {
                        faults.push(format!(
                            "{label}: its sides ran different launchers or verifiers"
                        ));
                    }
                }
                Err(fault) => faults.push(fault),
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
        results.push(ControlResult {
            control: control.name.clone(),
            runner: control.runner.name().to_string(),
            faults,
        });
    }
    results
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod kani_tests {
    use super::*;

    const HARNESS: &str = "bounded::proofs::checked_add_is_exact";

    fn row(toolchain: &str, features: &str, rigor: &str, target: &str) -> String {
        format!(
            "x\ttests/data/controls/x.patch\tkani\t{toolchain}\tdcbor\t{features}\t{rigor}\t\
             {target}\t{HARNESS}\t-\tfailed\ta planted failure"
        )
    }

    /// A Kani row names the proof shell, the library and a harness, and no
    /// features or rigor: the build fixes the one, a harness reads no layer.
    /// Any other shape is refused.
    #[test]
    fn a_kani_row_has_the_proof_builds_shape() {
        let parsed = parse(&row("kani", "-", "-", "lib")).expect("a Kani row parses");
        assert_eq!(parsed[0].runner, Runner::Kani);
        assert_eq!(parsed[0].render(), row("kani", "-", "-", "lib"));
        let inconclusive = row("kani", "-", "-", "lib").replace("\tfailed\t", "\tno_verdict\t");
        assert!(
            parse(&inconclusive)
                .unwrap_err()
                .contains("is no refusal outcome"),
            "an inconclusive run cannot be a control's expected refusal"
        );
        for wrong in [
            row("nightly", "-", "-", "lib"),
            row("kani", "all", "-", "lib"),
            row("kani", "-", "exhaustive", "lib"),
            row("kani", "-", "-", "encode"),
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
        let control = &parse(&row("kani", "-", "-", "lib")).unwrap()[0];
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
        let control = parse(&row("kani", "-", "-", "lib")).unwrap();
        let logs = std::env::temp_dir().join(format!("dcbor-kani-baseline-{}", std::process::id()));
        let at = directory(&logs, &control[0]);
        std::fs::create_dir_all(&at).expect("a fixture directory");
        let write = |file: &str, text: &str| std::fs::write(at.join(file), text).unwrap();
        write("red.judged", "refused\n");
        write("green.judged", "restored\n");
        write("before.sha256", "a\n");
        write("planted.sha256", "b\n");
        write("after.sha256", "a\n");
        let unbased = faults(&evidence(&control, &logs, KANI_TOOLCHAIN, &[Runner::Kani]));
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
        let inconclusive = faults(&evidence(&control, &logs, KANI_TOOLCHAIN, &[Runner::Kani]));
        assert!(
            inconclusive
                .iter()
                .any(|fault| fault.contains("no verified baseline")),
            "a Kani control without a baseline was evidence: {inconclusive:#?}"
        );
        write("baseline.judged", "verified\n");
        let unexecuted = faults(&evidence(&control, &logs, KANI_TOOLCHAIN, &[Runner::Kani]));
        assert!(
            unexecuted
                .iter()
                .any(|fault| fault.contains("recorded no execution")),
            "a Kani control without its sides' executions was evidence: {unexecuted:#?}"
        );
        let execution = |verifier: &str| {
            format!(r#"{{"launcher": "/kani/bin/cargo-kani", "verifier": {verifier}}}"#)
        };
        for side in ["baseline", "red", "green"] {
            std::fs::create_dir_all(at.join(format!("{side}.evidence"))).unwrap();
            write(
                &format!("{side}.evidence/execution.json"),
                &execution(r#"{"solver": "a"}"#),
            );
        }
        write(
            "red.evidence/execution.json",
            &execution(r#"{"solver": "b"}"#),
        );
        let mixed = faults(&evidence(&control, &logs, KANI_TOOLCHAIN, &[Runner::Kani]));
        assert!(
            mixed
                .iter()
                .any(|fault| fault.contains("different launchers or verifiers")),
            "sides that ran different verifiers were evidence: {mixed:#?}"
        );
        write(
            "red.evidence/execution.json",
            &execution(r#"{"solver": "a"}"#),
        );
        let based = faults(&evidence(&control, &logs, KANI_TOOLCHAIN, &[Runner::Kani]));
        std::fs::remove_dir_all(&logs).expect("the fixture removed");
        assert_eq!(based, Vec::<String>::new());
    }

    const DIFF: &str =
        "--- src/a.rs\n+++ src/a.rs\n@@ -1 +1 @@\n-pub fn a() {}\n+pub fn a() { panic!() }\n";

    /// A control copy, its control's directory, and the predictions its
    /// sides are held to: the copy holds `src/a.rs`, `src/b.rs` and the
    /// registered diff, which plants `src/a.rs`.
    struct Copy {
        root: std::path::PathBuf,
        copy: std::path::PathBuf,
        directory: std::path::PathBuf,
        control: Control,
        /// The tree of valid calibration evidence the predictions are read
        /// from, held while they are used.
        tree: crate::proofs::tests::CalibrationTree,
        references: (Vec<serde_json::Value>, Vec<serde_json::Value>),
        expectations: crate::proofs::Expectations,
    }

    /// The harness the authorization fixture's control checks: the
    /// calibration fixture's, whose predictions are read from valid evidence.
    const CONTROLLED: &str = "a::x";

    impl Copy {
        fn new(test: &str) -> Self {
            let root = std::env::temp_dir()
                .join(format!("dcbor-authorization-{test}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&root);
            let copy = root.join("copy");
            let directory = root.join("logs/x-kani");
            std::fs::create_dir_all(&directory).unwrap();
            let tree = crate::proofs::tests::CalibrationTree::new(&format!("authorization-{test}"));
            let references = tree.three();
            let row = row("kani", "-", "-", "lib").replace(HARNESS, CONTROLLED);
            let mut fixture = Self {
                control: parse(&row).unwrap().remove(0),
                expectations: tree
                    .read(&serde_json::to_vec(&tree.document(&references, 1400, 2300)).unwrap())
                    .unwrap(),
                tree,
                references,
                root,
                copy,
                directory,
            };
            fixture.expectations = fixture.predictions("the harness's own calibrations");
            fixture.write("src/a.rs", "pub fn a() {}\n");
            fixture.write("src/b.rs", "pub fn b() {}\n");
            fixture.write("tests/data/controls/x.patch", DIFF);
            fixture.record_digest("before.sha256");
            fixture
        }

        fn write(&self, relative: &str, text: &str) {
            let path = self.copy.join(relative);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, text).unwrap();
        }

        /// The copy's source digest recorded as its runner records it.
        fn record_digest(&self, file: &str) {
            std::fs::write(
                self.directory.join(file),
                format!("{}\n", crate::proofs::tree_digest(&self.copy).unwrap()),
            )
            .unwrap();
        }

        /// Valid predictions read from the fixture's valid evidence, the
        /// controlled harness's transfer reading `transfer`: another
        /// transfer is another revision of the document.
        fn predictions(&self, transfer: &str) -> crate::proofs::Expectations {
            let mut document = self.tree.document(&self.references, 1400, 2300);
            document["harnesses"][CONTROLLED]["transfer"] = serde_json::json!(transfer);
            self.tree
                .read(&serde_json::to_vec(&document).unwrap())
                .unwrap()
        }

        /// The side's authorization, validated by the control runner's one
        /// authority ([`authorize`]); a baseline's planting directory is
        /// never left behind.
        fn authorize(
            &self,
            side: Side,
            expectations: &crate::proofs::Expectations,
        ) -> Result<Authorization, String> {
            let authorized = authorize(
                &self.copy,
                &self.root.join("build"),
                &self.directory,
                &self.control,
                side,
                expectations,
            );
            assert!(
                !self.directory.join("baseline.planted").exists(),
                "the baseline's planting directory was left behind"
            );
            authorized
        }

        /// The copy's mode set to `mode`.
        fn mode(&self, relative: &str, mode: u32) {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(
                self.copy.join(relative),
                std::fs::Permissions::from_mode(mode),
            )
            .unwrap();
        }

        /// The baseline run's evidence as `process::kani` leaves an accepted
        /// one: its authorization, judgement and execution, its log and its
        /// manifest; its directory judged verified.
        fn baseline(&self, record: &AuthorizationRecord) {
            let evidence = self.directory.join("baseline.evidence");
            std::fs::create_dir_all(&evidence).unwrap();
            let write = |file: &str, value: serde_json::Value| {
                std::fs::write(evidence.join(file), value.to_string()).unwrap();
            };
            write("authorization.json", serde_json::to_value(record).unwrap());
            write("judgement.json", serde_json::json!({"status": "accepted"}));
            write(
                "execution.json",
                serde_json::json!({"launcher": "/k", "verifier": {}, "artifacts": {CONTROLLED: ARTIFACT}}),
            );
            let log = self.directory.join("baseline.log");
            std::fs::write(&log, "report\n").unwrap();
            let manifest = crate::proofs::manifest_of(
                &evidence,
                Some(&log),
                Some("00000000-0000-0000-0000-000000000001"),
            );
            std::fs::write(
                evidence.join("manifest.json"),
                serde_json::to_vec(&manifest).unwrap(),
            )
            .unwrap();
            std::fs::write(self.directory.join("baseline.judged"), "verified\n").unwrap();
        }
    }

    impl Drop for Copy {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    /// The controlled harness's artifact in the calibration fixture.
    const ARTIFACT: &str = "d96c7f46b0c37d43d5f7d38282b95dc4856d342d2b43e9a2f28adddcb2a528a7";

    /// A control side runs only under the authorization its runner validated:
    /// a baseline on the unplanted copy; a red side citing that verified
    /// baseline, of the same diff bytes and predictions, its copy's complete
    /// source state the baseline's with the registered diff applied; a
    /// restored side equal to the baseline in every path. A missing
    /// baseline, another control's baseline, changed diff bytes, another
    /// revision of the predictions, an edit beside the diff's in the file it
    /// touches or in another, an unplanted copy and an incomplete
    /// restoration are each refused.
    #[test]
    fn a_control_side_runs_only_under_its_validated_authorization() {
        let fixture = Copy::new("sides");
        let baseline = fixture
            .authorize(Side::Baseline, &fixture.expectations)
            .unwrap();
        let record = baseline.record().clone();
        assert_eq!(record.transition, Transition::Unplanted);
        assert_eq!(record.calibration_artifact_sha256, ARTIFACT);
        let missing = refused_by(
            "missing-baseline",
            fixture.authorize(Side::Red, &fixture.expectations),
        );
        assert!(
            missing.contains("no baseline was run"),
            "missing-baseline: {missing}"
        );
        fixture.baseline(&record);
        // The registered mutation, then its red side.
        fixture.write("src/a.rs", "pub fn a() { panic!() }\n");
        fixture.record_digest("planted.sha256");
        let red = fixture.authorize(Side::Red, &fixture.expectations).unwrap();
        assert_eq!(
            red.record().transition,
            Transition::Planted {
                paths: BTreeSet::from(["src/a.rs".to_string()])
            }
        );
        assert_eq!(
            red.record().baseline.as_ref().unwrap().artifact_sha256,
            ARTIFACT
        );
        let revised = refused_by(
            "revision-changed",
            fixture.authorize(Side::Red, &fixture.predictions("a revised transfer")),
        );
        assert!(
            revised.contains("froze the predictions"),
            "revision-changed: {revised}"
        );
        // An edit beside the diff's inside the file it touches: the paths
        // changed are the diff's own, but the copy is not the diff applied.
        fixture.write("src/a.rs", "pub fn a() { panic!() }\n// beside\n");
        fixture.record_digest("planted.sha256");
        let inside = refused_by(
            "extra-edit-in-touched-file",
            fixture.authorize(Side::Red, &fixture.expectations),
        );
        assert!(
            inside.contains("is not exactly the baseline with the diff applied"),
            "extra-edit-in-touched-file: {inside}"
        );
        fixture.write("src/a.rs", "pub fn a() { panic!() }\n");
        fixture.write("src/b.rs", "pub fn b() { panic!() }\n");
        fixture.record_digest("planted.sha256");
        let extra = refused_by(
            "extra-edit",
            fixture.authorize(Side::Red, &fixture.expectations),
        );
        assert!(
            extra.contains("is not exactly the baseline with the diff applied"),
            "extra-edit: {extra}"
        );
        // A copy the diff was never applied to: not the baseline with it.
        fixture.write("src/a.rs", "pub fn a() {}\n");
        fixture.write("src/b.rs", "pub fn b() {}\n");
        fixture.record_digest("planted.sha256");
        let unplanted = refused_by(
            "red-unplanted",
            fixture.authorize(Side::Red, &fixture.expectations),
        );
        assert!(
            unplanted.contains(
                "differs in [\"src/a.rs\"] from its baseline with the registered diff applied"
            ),
            "red-unplanted: {unplanted}"
        );
        // Restored but for one path, then whole.
        fixture.write("src/a.rs", "pub fn a() { panic!() }\n");
        fixture.write("src/b.rs", "pub fn b() {}\n");
        fixture.record_digest("after.sha256");
        let incomplete = refused_by(
            "incomplete-restoration",
            fixture.authorize(Side::Green, &fixture.expectations),
        );
        assert!(
            incomplete.contains("the restoration is incomplete"),
            "incomplete-restoration: {incomplete}"
        );
        fixture.write("src/a.rs", "pub fn a() {}\n");
        fixture.record_digest("after.sha256");
        let green = fixture
            .authorize(Side::Green, &fixture.expectations)
            .unwrap();
        assert_eq!(green.record().transition, Transition::Restored);
        assert_eq!(green.restored_baseline().unwrap().artifact_sha256, ARTIFACT);
        // Another control's baseline.
        let other = AuthorizationRecord {
            control: "other".to_string(),
            ..record.clone()
        };
        std::fs::remove_dir_all(fixture.directory.join("baseline.evidence")).unwrap();
        fixture.baseline(&other);
        let foreign = refused_by(
            "another-control",
            fixture.authorize(Side::Green, &fixture.expectations),
        );
        assert!(
            foreign.contains("is control other's"),
            "another-control: {foreign}"
        );
        // The diff's bytes changed since the baseline.
        std::fs::remove_dir_all(fixture.directory.join("baseline.evidence")).unwrap();
        fixture.baseline(&record);
        fixture.write(
            "tests/data/controls/x.patch",
            &DIFF.replace("panic!()", "todo!()"),
        );
        let changed = refused_by(
            "patch-changed",
            fixture.authorize(Side::Green, &fixture.expectations),
        );
        assert!(
            changed.contains("is of the diff"),
            "patch-changed: {changed}"
        );
        // A baseline on a copy that is not the unplanted source.
        let planted = refused_by(
            "baseline-planted",
            fixture.authorize(Side::Baseline, &fixture.expectations),
        );
        assert!(
            planted.contains("a baseline runs on the unplanted source alone"),
            "{planted}"
        );
    }

    /// A registered diff that creates a file, deletes one, changes a mode
    /// and adds a link, in the registry's `-p0` form: GNU patch's own
    /// application of it to the baseline is the one red state a copy may
    /// hold, in every kind the source state records. The diff planted by the
    /// one invocation ([`patch`]) is authorized; a mode left unchanged, a
    /// link to another target, a link made a file of its target's name, a
    /// deletion not made, a creation not made and a file added beside are
    /// each refused, naming the path; reversed, the copy is its baseline
    /// again. A diff that does not apply to the baseline refuses the
    /// baseline itself.
    #[test]
    fn a_red_side_is_its_baseline_with_the_diff_applied_in_every_kind() {
        const KINDS: &str = "diff --git src/new.rs src/new.rs\nnew file mode 100644\n\
            --- /dev/null\n+++ src/new.rs\n@@ -0,0 +1 @@\n+pub fn new() {}\n\
            diff --git src/b.rs src/b.rs\ndeleted file mode 100644\n\
            --- src/b.rs\n+++ /dev/null\n@@ -1 +0,0 @@\n-pub fn b() {}\n\
            diff --git script.sh script.sh\nold mode 100644\nnew mode 100755\n\
            diff --git link link\nnew file mode 120000\n\
            --- /dev/null\n+++ link\n@@ -0,0 +1 @@\n+src/a.rs\n\\ No newline at end of file\n";
        let fixture = Copy::new("kinds");
        fixture.write("script.sh", "#!/bin/sh\n");
        fixture.mode("script.sh", 0o644);
        fixture.write("tests/data/controls/x.patch", KINDS);
        fixture.record_digest("before.sha256");
        let baseline = fixture
            .authorize(Side::Baseline, &fixture.expectations)
            .unwrap();
        let planted = baseline.record().planted.clone().unwrap();
        assert!(planted.contains_key("src/new.rs") && planted.contains_key("link"));
        assert!(
            !planted.contains_key("src/b.rs"),
            "the deletion is not in the red state"
        );
        assert_ne!(planted["script.sh"], baseline.record().sources["script.sh"]);
        fixture.baseline(baseline.record());
        patch(KINDS.as_bytes(), &fixture.copy, Direction::Apply).unwrap();
        fixture.record_digest("planted.sha256");
        let red = fixture.authorize(Side::Red, &fixture.expectations).unwrap();
        assert_eq!(
            red.record().transition,
            Transition::Planted {
                paths: ["link", "script.sh", "src/b.rs", "src/new.rs"]
                    .into_iter()
                    .map(str::to_string)
                    .collect()
            }
        );
        type Plant = fn(&Copy);
        type Undo = fn(&Copy);
        let cases: [(&str, Plant, Undo, &str); 6] = [
            (
                "mode-unchanged",
                |copy| copy.mode("script.sh", 0o644),
                |copy| copy.mode("script.sh", 0o755),
                "script.sh",
            ),
            (
                "link-retargeted",
                |copy| {
                    std::fs::remove_file(copy.copy.join("link")).unwrap();
                    std::os::unix::fs::symlink("src/new.rs", copy.copy.join("link")).unwrap();
                },
                |copy| {
                    std::fs::remove_file(copy.copy.join("link")).unwrap();
                    std::os::unix::fs::symlink("src/a.rs", copy.copy.join("link")).unwrap();
                },
                "link",
            ),
            (
                "link-made-a-file",
                |copy| {
                    std::fs::remove_file(copy.copy.join("link")).unwrap();
                    copy.write("link", "src/a.rs");
                },
                |copy| {
                    std::fs::remove_file(copy.copy.join("link")).unwrap();
                    std::os::unix::fs::symlink("src/a.rs", copy.copy.join("link")).unwrap();
                },
                "link",
            ),
            (
                "deletion-unmade",
                |copy| copy.write("src/b.rs", "pub fn b() {}\n"),
                |copy| std::fs::remove_file(copy.copy.join("src/b.rs")).unwrap(),
                "src/b.rs",
            ),
            (
                "creation-unmade",
                |copy| std::fs::remove_file(copy.copy.join("src/new.rs")).unwrap(),
                |copy| copy.write("src/new.rs", "pub fn new() {}\n"),
                "src/new.rs",
            ),
            (
                "addition-beside",
                |copy| copy.write("src/extra.rs", ""),
                |copy| std::fs::remove_file(copy.copy.join("src/extra.rs")).unwrap(),
                "src/extra.rs",
            ),
        ];
        for (name, plant, undo, path) in cases {
            plant(&fixture);
            fixture.record_digest("planted.sha256");
            let found = refused_by(name, fixture.authorize(Side::Red, &fixture.expectations));
            assert!(
                found.contains(&format!("differs in [\"{path}\"]")),
                "{name}: {found}"
            );
            undo(&fixture);
            fixture.record_digest("planted.sha256");
            fixture
                .authorize(Side::Red, &fixture.expectations)
                .unwrap_or_else(|fault| panic!("{name}: not restored to the red state: {fault}"));
        }
        patch(KINDS.as_bytes(), &fixture.copy, Direction::Reverse).unwrap();
        fixture.record_digest("after.sha256");
        let green = fixture
            .authorize(Side::Green, &fixture.expectations)
            .unwrap();
        assert_eq!(green.record().transition, Transition::Restored);
        // A diff that does not apply to the baseline: no red state exists.
        let unapplied = Copy::new("kinds-unapplied");
        unapplied.write(
            "tests/data/controls/x.patch",
            &DIFF.replace("-pub fn a() {}", "-pub fn z() {}"),
        );
        unapplied.record_digest("before.sha256");
        let found = refused_by(
            "diff-unapplied",
            unapplied.authorize(Side::Baseline, &unapplied.expectations),
        );
        assert!(
            found.contains("the diff does not apply to the baseline"),
            "{found}"
        );
    }

    /// Held to its predictions, a restored side's artifact must be its
    /// baseline's and its one harness the only one launched.
    #[test]
    fn a_restored_side_runs_its_baselines_artifact_alone() {
        use crate::proofs::{
            Applicability, Ended, Launched, Reconciled, RunIdentityRecord, check_expectations,
        };
        let fixture = Copy::new("restored");
        let baseline = fixture
            .authorize(Side::Baseline, &fixture.expectations)
            .unwrap();
        fixture.baseline(baseline.record());
        fixture.record_digest("after.sha256");
        let green = fixture
            .authorize(Side::Green, &fixture.expectations)
            .unwrap();
        // The side's run selects its authorized harness alone: another is
        // refused before anything of the run is reserved.
        let purpose = crate::proofs::RunPurpose::Control {
            expectations: fixture.expectations.clone(),
            authorization: Box::new(green.clone()),
        };
        let launcher =
            std::fs::canonicalize(fixture.copy.join("tests/data/controls/x.patch")).unwrap();
        let foreign = refused_by(
            "foreign-harness",
            crate::process::KaniRequest {
                root: &fixture.copy,
                purpose: &purpose,
                selection: &crate::proofs::Selection::one("a::y"),
                declared: &crate::proofs::tests::CalibrationTree::census(),
                target_dir: &fixture.root.join("build"),
                launcher: &launcher,
                workload: &crate::process::Workload::at(launcher.clone()),
                log: &fixture.directory.join("foreign.log"),
            }
            .validate()
            .map(|_| ()),
        );
        assert!(
            foreign.contains("authorizes harness a::x alone"),
            "{foreign}"
        );
        assert!(
            !fixture.directory.join("foreign.evidence").exists(),
            "a refused side reserved its evidence"
        );
        let record = RunIdentityRecord {
            version: crate::proofs::RUNTIME_VERSION,
            id: "00000000-0000-0000-0000-000000000009".to_string(),
            purpose: crate::proofs::PURPOSE_CONTROL.to_string(),
            revision: fixture.expectations.sha256().to_string(),
            tree_sha256: green.record().source_sha256.clone(),
            build: crate::proofs::arguments().join(" "),
            loop_policy_sha256: ARTIFACT.to_string(),
            started: crate::proofs::Instant {
                seconds: 0,
                nanoseconds: 0,
            },
        };
        let identity = record.clone().validate().unwrap();
        // Launched in the predictions' own environment, under their
        // verifier: what the side's own rules are then held to.
        let launch = crate::proofs::Launch {
            environment: fixture.expectations.environment().record().clone(),
            workload_cgroup: None,
            load_before: None,
            load_after: None,
        };
        let verifier = fixture
            .expectations
            .harness(CONTROLLED)
            .unwrap()
            .verifier()
            .clone();
        let ran = |harness: &str, artifact: &str| Reconciled {
            verifier: verifier.clone(),
            applied: Vec::new(),
            completed: BTreeMap::from([(harness.to_string(), std::time::Duration::from_millis(1))]),
            launched: BTreeMap::from([(
                harness.to_string(),
                Launched {
                    elapsed: std::time::Duration::from_millis(1),
                    ended: Ended::Exited,
                    artifact_sha256: artifact.to_string(),
                },
            )]),
        };
        let expectations = fixture.expectations.clone();
        check_expectations(
            &identity,
            &launch,
            &ran(CONTROLLED, ARTIFACT),
            &expectations,
            Applicability::Control(&green),
        )
        .unwrap();
        let rebuilt = refused_by(
            "restored-rebuilt",
            check_expectations(
                &identity,
                &launch,
                &ran(CONTROLLED, "00"),
                &expectations,
                Applicability::Control(&green),
            ),
        );
        assert!(rebuilt.contains("investigate the build"), "{rebuilt}");
        let other = refused_by(
            "other-harness",
            check_expectations(
                &identity,
                &launch,
                &ran("other", ARTIFACT),
                &expectations,
                Applicability::Control(&green),
            ),
        );
        assert!(other.contains("authorizes"), "{other}");
        let moved = RunIdentityRecord {
            tree_sha256: "0".repeat(64),
            ..record
        }
        .validate()
        .unwrap();
        let source = refused_by(
            "source-moved",
            check_expectations(
                &moved,
                &launch,
                &ran(CONTROLLED, ARTIFACT),
                &expectations,
                Applicability::Control(&green),
            ),
        );
        assert!(source.contains("authorization binds"), "{source}");
    }

    /// The refusal `result` must be, named `case`: a planted defect that lets
    /// the case be accepted fails here by the case's name.
    fn refused_by<T>(case: &str, result: Result<T, String>) -> String {
        match result {
            Ok(_) => panic!("{case}: accepted"),
            Err(fault) => fault,
        }
    }
}
