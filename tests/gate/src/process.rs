//! Running what the gates judge: each checker build's test binaries, each
//! model's test a process of its own, its environment exactly the declared
//! inputs, its termination, log and measurement kept. Every run is a
//! workload ([`workload`]): confined to a memory-capped scope of its own,
//! while the gate tool recording its judgement stays outside.

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::Command;

use dcbor_model_bounds::Checker;

use crate::models::{Listed, Ran};
use crate::outcome::{self, Termination};

/// The variables a model run reads: set by the run's purpose alone.
const BOUND: &str = "DCBOR_MODEL_BOUND";
const STACK: &str = "DCBOR_MODEL_STACK";
const DESCRIBE: &str = "DCBOR_MODEL_DESCRIBE";
const SCHEDULES: &str = "DCBOR_MODEL_SCHEDULES";
const DESCRIPTION: &str = "DCBOR_MODEL";

/// The workload launcher a gate exports (tests/gate-common.sh,
/// `gate_confinement`): tests/workload.sh, the one confinement of every
/// workload, which reads the cap from `DCBOR_GATE_MEMORY`.
const WORKLOAD: &str = "DCBOR_GATE_WORKLOAD";

/// The workload launcher: tests/workload.sh, which runs its command in a
/// transient scope of its own of the user's systemd manager, its memory
/// capped with no swap, exec'd in place so the command's exit status or
/// signal is the launch's. The gate tool, which waits for each workload and
/// records its judgement, stays outside the scope: an out-of-memory kill
/// chooses its victim among the workload's processes alone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Workload(std::ffi::OsString);

impl Workload {
    /// The launcher the gate running this tool exported ([`WORKLOAD`]);
    /// refused when no gate defined its confinement.
    pub fn exported() -> Result<Self, String> {
        std::env::var_os(WORKLOAD).map(Self).ok_or_else(|| {
            format!(
                "{WORKLOAD} is unset: run the gate tool from a gate (tests/gate-common.sh, gate_confinement)"
            )
        })
    }

    /// The launcher at `path`.
    pub fn at(path: impl Into<std::ffi::OsString>) -> Self {
        Self(path.into())
    }

    /// `program` launched as a workload.
    pub fn command(&self, program: impl AsRef<OsStr>) -> Command {
        let mut command = Command::new(&self.0);
        command.arg(program);
        command
    }

    /// The launcher itself, for a measuring parent outside the workload's
    /// scope that runs it as its command ([`run_once`]).
    pub fn launcher(&self) -> &OsStr {
        &self.0
    }
}

/// `program` launched as a workload by the exported launcher
/// ([`Workload::exported`]).
pub fn workload(program: impl AsRef<OsStr>) -> Result<Command, String> {
    Ok(Workload::exported()?.command(program))
}

/// `command` with an environment that holds nothing a model run may not
/// read: no `LOOM_*`, `SHUTTLE_*`, or `DCBOR_RECORD_*` variable, backtraces
/// off, no model value. Control runs cannot inherit permission to rewrite
/// evidence.
fn isolated(mut command: Command) -> Command {
    isolate(&mut command, std::env::vars_os().map(|(name, _)| name));
    command.env("RUST_BACKTRACE", "0");
    command
}

/// `program` launched as an isolated ([`isolated`]) workload ([`workload`]).
fn controlled(program: impl AsRef<OsStr>) -> Result<Command, String> {
    Ok(isolated(workload(program)?))
}

/// Clear inherited execution and publication permissions before a run adds
/// its explicitly selected inputs.
fn isolate(command: &mut Command, names: impl IntoIterator<Item = std::ffi::OsString>) {
    for name in names {
        let text = name.to_string_lossy();
        if text.starts_with("LOOM_")
            || text.starts_with("SHUTTLE_")
            || text.starts_with("DCBOR_RECORD_")
            || [BOUND, STACK, DESCRIBE].contains(&text.as_ref())
        {
            command.env_remove(&name);
        }
    }
}

/// The RUSTFLAGS of `checker`'s build, the caller's own before them.
pub fn flags(checker: Checker) -> String {
    let own = std::env::var("RUSTFLAGS").unwrap_or_default();
    format!("{own} --cfg {checker}").trim_start().to_string()
}

/// Build `checker`'s test binaries of `root`, in release with every
/// feature, in its own target directory (each cfg rebuilds the library),
/// logging to `log`: the executable of each target holding models
/// ([`dcbor_model_bounds::targets`]). A build that fails returns its log's
/// contents.
pub fn build(
    root: &Path,
    checker: Checker,
    log: &Path,
) -> Result<BTreeMap<String, PathBuf>, String> {
    let targets = dcbor_model_bounds::targets();
    let mut command = controlled("cargo")?;
    command
        .current_dir(root)
        .env("RUSTFLAGS", flags(checker))
        .env("CARGO_TARGET_DIR", root.join("target").join(checker.name()))
        .args(["test", "--release", "--all-features", "--package", "dcbor"]);
    for target in &targets {
        if *target == dcbor_model_bounds::LIBRARY {
            command.arg("--lib");
        } else {
            command.args(["--test", target]);
        }
    }
    let output = command
        .args(["--no-run", "--message-format", "json"])
        .output()
        .map_err(|error| format!("cargo: {error}"))?;
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    std::fs::write(log, &stderr).map_err(|error| format!("{}: {error}", log.display()))?;
    if !output.status.success() {
        return Err(stderr);
    }
    let mut executables = BTreeMap::new();
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        let Ok(message) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        if message["reason"] != "compiler-artifact" || message["profile"]["test"] != true {
            continue;
        }
        let Some(executable) = message["executable"].as_str() else {
            continue;
        };
        let kinds = &message["target"]["kind"];
        let name = if kinds
            .as_array()
            .is_some_and(|kinds| kinds.iter().any(|kind| kind == "lib"))
        {
            dcbor_model_bounds::LIBRARY.to_string()
        } else {
            message["target"]["name"]
                .as_str()
                .unwrap_or_default()
                .to_string()
        };
        if targets.contains(&name.as_str())
            && executables
                .insert(name.clone(), PathBuf::from(executable))
                .is_some()
        {
            return Err(format!("two executables of target {name}"));
        }
    }
    for target in targets {
        if !executables.contains_key(target) {
            return Err(format!("no executable of target {target}"));
        }
    }
    Ok(executables)
}

/// Build the test target `target` (`lib`, or an integration test binary) of
/// `package` in `root`, with `features` (`all`, a comma-separated list, or
/// none for the package's defaults), into `target_dir`, logging the build's
/// diagnostics to `log`. Its test executable ([`crate::reach::executable`]),
/// or, when the build failed, its log: a compiler refusal is what a run
/// produced, not a failure of the gate. Colour is off (`TERM=dumb`), so a
/// report is read as its text.
pub fn build_target(
    root: &Path,
    package: &str,
    features: Option<&str>,
    target: &str,
    target_dir: &Path,
    log: &Path,
) -> Result<Result<PathBuf, String>, String> {
    let mut command = controlled("cargo")?;
    command
        .current_dir(root)
        .env("CARGO_TARGET_DIR", target_dir)
        .env("TERM", "dumb")
        .args(["test", "--package", package]);
    match features {
        Some("all") => {
            command.arg("--all-features");
        }
        Some(list) => {
            command.args(["--features", list]);
        }
        None => {}
    }
    if target == dcbor_model_bounds::LIBRARY {
        command.arg("--lib");
    } else {
        command.args(["--test", target]);
    }
    let output = command
        .args(["--no-run", "--message-format", "json"])
        .output()
        .map_err(|error| format!("cargo: {error}"))?;
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    std::fs::write(log, &stderr).map_err(|error| format!("{}: {error}", log.display()))?;
    if !output.status.success() {
        return Ok(Err(stderr));
    }
    crate::reach::executable(&String::from_utf8_lossy(&output.stdout))
        .map(|found| Ok(PathBuf::from(found)))
}

/// One run of `test` alone in `executable` (`--exact`, one thread, output
/// uncaptured), its environment `environment` beside the controlled one and
/// `TERM=dumb`, logged to `log`: its termination and its log's text.
pub fn run_test(
    executable: &Path,
    test: &str,
    environment: &[(&str, String)],
    log: &Path,
) -> Result<(Termination, String), String> {
    let mut environment = environment.to_vec();
    environment.push(("TERM", "dumb".to_string()));
    // A control's judgement reads its termination and log, not its
    // measurement, which is no part of a control's evidence; a run whose
    // test's termination is unavailable is not judged.
    let measured = run_once(&Workload::exported()?, executable, test, &environment, log)?;
    Ok((
        measured
            .termination
            .map_err(|error| format!("{test}: {error}"))?,
        measured.text,
    ))
}

/// One `cargo kani` run of harness `harness` alone in `root`
/// ([`crate::proofs::arguments`], then `--harness HARNESS --exact`, which
/// kani-driver's `VerificationArgs` declares: the filter matching only that
/// fully qualified name), its artifacts under `target_dir`, one thread
/// (no `-j`: `NumThreads::NoMultithreading`), colour off, its standard
/// output and error logged to `log`: its termination and its log's text.
pub fn run_kani(
    root: &Path,
    harness: &str,
    target_dir: &Path,
    log: &Path,
) -> Result<(Termination, String), String> {
    kani(root, &["--harness", harness, "--exact"], target_dir, log)
}

/// One `cargo kani` run of every harness of the library in `root`
/// ([`crate::proofs::arguments`], no harness filter), as [`run_kani`] runs
/// one: the proof suite's evidence run.
pub fn run_kani_suite(
    root: &Path,
    target_dir: &Path,
    log: &Path,
) -> Result<(Termination, String), String> {
    kani(root, &[], target_dir, log)
}

/// The one `cargo kani` invocation, `selection` after the build's own
/// arguments.
fn kani(
    root: &Path,
    selection: &[&str],
    target_dir: &Path,
    log: &Path,
) -> Result<(Termination, String), String> {
    let file = std::fs::File::create(log).map_err(|error| format!("{}: {error}", log.display()))?;
    let error = file
        .try_clone()
        .map_err(|error| format!("{}: {error}", log.display()))?;
    let status = controlled("cargo")?
        .current_dir(root)
        .env("TERM", "dumb")
        .args(crate::proofs::arguments())
        .args(selection)
        .arg("--target-dir")
        .arg(target_dir)
        .stdout(file)
        .stderr(error)
        .status()
        .map_err(|error| format!("cargo kani: {error}"))?;
    let termination = {
        use std::os::unix::process::ExitStatusExt;
        match status.signal() {
            Some(signal) => Termination::Signaled(signal),
            None => Termination::Exited(status.code().unwrap_or(-1)),
        }
    };
    let text =
        std::fs::read_to_string(log).map_err(|error| format!("{}: {error}", log.display()))?;
    Ok((termination, text))
}

/// The models of `checker` the `target` binary `executable` lists.
pub fn list(checker: Checker, target: &str, executable: &Path) -> Result<Vec<Listed>, String> {
    let output = controlled(executable)?
        .args(["--list", "--format", "terse"])
        .output()
        .map_err(|error| format!("{}: {error}", executable.display()))?;
    if !output.status.success() {
        return Err(format!(
            "{} --list: {}",
            executable.display(),
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| line.strip_suffix(": test"))
        .filter(|test| dcbor_model_bounds::is_model(checker, target, test))
        .map(|test| Listed {
            checker,
            target: target.to_string(),
            test: test.to_string(),
        })
        .collect())
}

/// What GNU time measured of a run: its peak resident kilobytes and wall
/// seconds, each read from time's report and validated (`%M %e`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Measurement {
    pub(crate) peak_kb: u64,
    pub(crate) seconds: String,
}

/// A measured run: how its child, the test, ended when GNU time's report
/// establishes it, its log's text, and its measurement, or why each is
/// unavailable. GNU time's own status (the wrapper's) is named in each such
/// error and never presented as the child's termination.
#[derive(Debug)]
struct Measured {
    termination: Result<Termination, String>,
    text: String,
    measurement: Result<Measurement, String>,
}

/// GNU time's report (`report`, the `-o` file of `-f '%M %e'`), as GNU time
/// 1.10 writes it: at most one line naming how its command ended
/// (`Command terminated by signal N`, `Command exited with non-zero status
/// N`, none for an exit of 0), then the measurement, a peak of resident
/// kilobytes and the elapsed seconds. The child's termination is the
/// report's, and only when time's own status (`wrapper`) agrees with it
/// (128 + N for a signal, N for an exit); the measurement only when its
/// line is exactly two validated values. GNU time always writes that line,
/// so a report whose measurement line is malformed is no report of time's,
/// and establishes no termination either. Anything else is the error that
/// says so.
fn report(
    report: &str,
    wrapper: std::process::ExitStatus,
) -> (Result<Termination, String>, Result<Measurement, String>) {
    let (parsed, measurement) = time_report(report);
    let termination = parsed.and_then(|termination| {
        let expected = match termination {
            Termination::Signaled(signal) => 128_i32.checked_add(signal),
            Termination::Exited(code) => Some(code),
        };
        if expected.is_some() && wrapper.code() == expected {
            Ok(termination)
        } else {
            Err(format!(
                "GNU time reported {termination:?} but itself ended with {wrapper}"
            ))
        }
    });
    (termination, measurement)
}

/// Parse the complete GNU time report without inventing a wrapper status.
/// Callers with a status additionally check agreement through [`report`].
pub(crate) fn time_report(
    report: &str,
) -> (Result<Termination, String>, Result<Measurement, String>) {
    let lines: Vec<&str> = report.lines().collect();
    let (ending, measured) = match lines[..] {
        [measured] => (None, measured),
        [ending, measured] => (Some(ending), measured),
        _ => {
            let error = format!("not a GNU time report: {report:?}");
            return (Err(error.clone()), Err(error));
        }
    };
    let measurement = measured
        .split_once(' ')
        .and_then(|(peak, seconds)| {
            let peak_kb = peak.parse::<u64>().ok()?;
            let elapsed = seconds.parse::<f64>().ok()?;
            (seconds
                .bytes()
                .all(|byte| byte.is_ascii_digit() || byte == b'.')
                && elapsed.is_finite())
            .then(|| Measurement {
                peak_kb,
                seconds: seconds.to_string(),
            })
        })
        .ok_or_else(|| format!("not a measurement of peak kilobytes and seconds: {measured:?}"));
    if let Err(error) = &measurement {
        return (Err(error.clone()), measurement);
    }
    // A signal is one Linux delivers (1 to SIGRTMAX, 64), a non-zero exit
    // one wait(2) reports (1 to 255); any other number is no ending.
    let parsed = match ending {
        None => Ok(Termination::Exited(0)),
        Some(line) => line
            .strip_prefix("Command terminated by signal ")
            .and_then(|number| number.parse::<i32>().ok())
            .filter(|signal| (1..=64).contains(signal))
            .map(Termination::Signaled)
            .or_else(|| {
                line.strip_prefix("Command exited with non-zero status ")
                    .and_then(|number| number.parse::<i32>().ok())
                    .filter(|code| (1..=255).contains(code))
                    .map(Termination::Exited)
            })
            .ok_or_else(|| format!("not GNU time's report of an ending: {line:?}")),
    };
    (parsed, measurement)
}

/// One run of `listed`'s test in `executable`, its own process, with
/// `environment` its model variables, logged to `log`: its termination, its
/// log, and GNU time's measurement or the error reading it.
///
/// GNU time is the workload launcher's parent, outside the workload's scope
/// (`time LAUNCHER EXECUTABLE ...`), so an out-of-memory kill inside the
/// scope never takes the measuring process or this recorder. Its child is
/// one process through an exec chain: the launcher's bash, `systemd-run`
/// registering the scope over D-Bus, then the test. The peak is that
/// process's maximum resident size over the whole chain (the test's, unless
/// the chain's setup exceeded it) and the wall seconds include the scope's
/// registration, so neither is the test's alone. The test's termination and
/// measurement are read from time's report ([`report`]); a report missing,
/// unreadable or malformed leaves each unavailable, its error naming time's
/// own status, which is kept beside them and never taken for the test's.
/// The exact libtest selection must acknowledge its start in the log before
/// the exec chain's termination is attributed to it. Failure before that
/// acknowledgement leaves termination unavailable, including early signals.
fn run_once(
    workload: &Workload,
    executable: &Path,
    test: &str,
    environment: &[(&str, String)],
    log: &Path,
) -> Result<Measured, String> {
    let measure = log.with_extension("measure");
    let file = std::fs::File::create(log).map_err(|error| format!("{}: {error}", log.display()))?;
    let error = file
        .try_clone()
        .map_err(|error| format!("{}: {error}", log.display()))?;
    let mut command = isolated(Command::new("time"));
    command
        .args(["-f", "%M %e", "-o"])
        .arg(&measure)
        .arg(workload.launcher())
        .arg(executable)
        .args(["--exact", test, "--nocapture", "--test-threads=1"])
        .stdout(file)
        .stderr(error);
    for (name, value) in environment {
        command.env(name, value);
    }
    let wrapper = command.status().map_err(|error| format!("time: {error}"))?;
    // Every unavailability names the report and GNU time's own status
    // (`exit status: N`, `signal: N`), which is never the test's.
    let located = |error: String| {
        format!(
            "{}: {error}; GNU time ended with {wrapper}",
            measure.display()
        )
    };
    let (termination, measurement) = match std::fs::read_to_string(&measure) {
        Ok(text) => report(&text, wrapper),
        Err(error) => (Err(error.to_string()), Err(error.to_string())),
    };
    let text =
        std::fs::read_to_string(log).map_err(|error| format!("{}: {error}", log.display()))?;
    // GNU time observes the launcher too. Only libtest's acknowledgement of
    // this exact selection establishes that execution reached the test.
    // A process dying before that acknowledgement has unavailable termination.
    let started = format!("test {test} ... ");
    let termination = termination.and_then(|ending| {
        if text.lines().any(|line| line.starts_with(&started)) {
            Ok(ending)
        } else {
            Err(format!("no execution acknowledgement for test {test:?}"))
        }
    });
    Ok(Measured {
        termination: termination
            .map_err(|error| located(format!("{error}; the test's termination is unavailable"))),
        text,
        measurement: measurement.map_err(located),
    })
}

/// The value a run printed after `marker` and a tab, on the first line that
/// holds them. Under `--nocapture` libtest writes `test <name> ... ` before
/// a test's own output on the same line, so a marker is found where it
/// stands in its line, never only at the line's start; the tab keeps one
/// marker from matching another it begins (`DCBOR_MODEL` and
/// `DCBOR_MODEL_SCHEDULES`).
fn marked<'a>(text: &'a str, marker: &str) -> Option<&'a str> {
    let marker = format!("{marker}\t");
    text.lines().find_map(|line| {
        line.find(&marker)
            .map(|at| line[at + marker.len()..].trim_end())
    })
}

/// Whether `listed` runs on a sized stack, by its runner's own description.
pub fn sized(executable: &Path, listed: &Listed, log: &Path) -> Result<bool, String> {
    // A description is read from its log; its measurement is no part of it.
    let Measured {
        termination, text, ..
    } = run_once(
        &Workload::exported()?,
        executable,
        &listed.test,
        &[(DESCRIBE, "1".to_string())],
        log,
    )?;
    let termination = termination.map_err(|error| format!("{}: {error}", listed.test))?;
    match (termination, marked(&text, DESCRIPTION)) {
        (Termination::Exited(0), Some("sized")) => Ok(true),
        (Termination::Exited(0), Some("unsized")) => Ok(false),
        _ => Err(format!(
            "{}: described no model ({}); is it a model's test?",
            listed.test,
            log.display()
        )),
    }
}

/// One run of `listed` at `bound` and `stack` (each unset when `None`),
/// classified ([`outcome::model`]).
pub fn run(
    executable: &Path,
    listed: &Listed,
    bound: Option<usize>,
    stack: Option<usize>,
    log: &Path,
) -> Result<Ran, String> {
    let mut environment = Vec::new();
    if let Some(bound) = bound {
        environment.push((BOUND, bound.to_string()));
    }
    if let Some(stack) = stack {
        environment.push((STACK, stack.to_string()));
    }
    let Measured {
        termination,
        text,
        measurement,
        ..
    } = run_once(
        &Workload::exported()?,
        executable,
        &listed.test,
        &environment,
        log,
    )?;
    let termination = termination.map_err(|error| format!("{}: {error}", listed.test))?;
    // A model run's row records its measurement: a run without one is
    // refused, its termination named beside the reason.
    let Measurement { peak_kb, seconds } = measurement.map_err(|error| {
        format!(
            "{}: ended {termination:?}, its measurement unavailable: {error}",
            listed.test
        )
    })?;
    let (peak_kb, seconds) = (Some(peak_kb), Some(seconds));
    let schedules = marked(&text, SCHEDULES).and_then(|count| count.parse().ok());
    Ok(Ran {
        outcome: outcome::model(listed.checker, termination, &text),
        schedules,
        seconds,
        peak_kb,
    })
}

#[cfg(test)]
mod tests {
    use super::{DESCRIPTION, SCHEDULES, Workload, isolate, marked};

    /// The cgroup v2 path of the process whose `/proc/PID/cgroup` is `text`.
    fn cgroup(text: &str) -> String {
        text.trim()
            .strip_prefix("0::")
            .expect("a cgroup v2 membership")
            .to_string()
    }

    /// A workload launched by the repository's launcher (tests/workload.sh)
    /// runs in a scope of its own, apart from its caller's cgroup, capped at
    /// DCBOR_GATE_MEMORY with no swap, and its exit status and terminating
    /// signal are the launch's own, which every run's classification reads.
    #[test]
    fn a_workload_runs_capped_apart_from_its_caller() {
        use std::os::unix::process::ExitStatusExt;
        let launcher =
            Workload::at(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../workload.sh"));
        let caller = cgroup(&std::fs::read_to_string("/proc/self/cgroup").unwrap());
        let output = launcher
            .command("sh")
            .env("DCBOR_GATE_MEMORY", "64M")
            .args([
                "-c",
                r#"cg="$(cut -d: -f3 /proc/self/cgroup)"; printf '%s\n%s\n%s\n' "$cg" "$(cat "/sys/fs/cgroup$cg/memory.max")" "$(cat "/sys/fs/cgroup$cg/memory.swap.max")""#,
            ])
            .output()
            .expect("launch the workload");
        assert!(output.status.success(), "{output:?}");
        let report = String::from_utf8(output.stdout).unwrap();
        let lines: Vec<&str> = report.lines().collect();
        let [scope, max, swap] = lines[..] else {
            panic!("the workload reported {report:?}");
        };
        assert!(
            scope != caller && scope.ends_with(".scope"),
            "a workload ran in its caller's cgroup {caller}: {scope}"
        );
        assert_eq!(
            max,
            (64_u64 << 20).to_string(),
            "a workload's scope is not capped"
        );
        assert_eq!(swap, "0", "a workload's scope may swap");
        let signalled = launcher
            .command("sh")
            .env("DCBOR_GATE_MEMORY", "64M")
            .args(["-c", "kill -TERM $$"])
            .status()
            .unwrap();
        assert_eq!(
            signalled.signal(),
            Some(15),
            "a workload's terminating signal was not its launch's"
        );
    }

    /// The recording path of every measured run ([`super::run_once`]): GNU
    /// time, in the caller's cgroup, is the parent of the process the
    /// launcher execs into the test inside the workload's scope, so the
    /// measuring process is never in the kill domain; the run keeps its
    /// measurement and the test's own termination, an exit status or the
    /// signal that killed it.
    #[test]
    fn a_measured_run_records_how_its_confined_test_ended() {
        use crate::outcome::Termination;
        let directory =
            std::env::temp_dir().join(format!("dcbor-gate-measured-run-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let script = directory.join("test.sh");
        std::fs::write(
            &script,
            "#!/bin/sh\n\
             printf 'test t ... \\n'\n\
             case \"$DCBOR_TEST_END\" in exit) exit 7 ;; kill) kill -KILL $$ ;; esac\n\
             cut -d: -f3 /proc/self/cgroup\n\
             cut -d: -f3 /proc/$PPID/cgroup\n",
        )
        .unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let launcher =
            Workload::at(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../workload.sh"));
        let caller = cgroup(&std::fs::read_to_string("/proc/self/cgroup").unwrap());
        let run = |end: &str| {
            super::run_once(
                &launcher,
                &script,
                "t",
                &[
                    ("DCBOR_GATE_MEMORY", "64M".to_string()),
                    ("DCBOR_TEST_END", end.to_string()),
                ],
                &directory.join(format!("{end}.log")),
            )
            .expect("record the run")
        };
        let missing = super::run_once(
            &launcher,
            &directory.join("nonexistent"),
            "t",
            &[("DCBOR_GATE_MEMORY", "64M".to_string())],
            &directory.join("missing.log"),
        )
        .expect("retain failed launch evidence");
        assert!(
            missing.termination.is_err(),
            "launcher became test: {missing:?}"
        );
        let super::Measured {
            termination,
            text,
            measurement,
            ..
        } = run("report");
        assert_eq!(termination, Ok(Termination::Exited(0)), "{text}");
        let lines: Vec<&str> = text.lines().skip(1).collect();
        let [test, parent] = lines[..] else {
            panic!("the test reported {text:?}");
        };
        assert!(
            test != caller && test.ends_with(".scope"),
            "a measured test ran in its caller's cgroup {caller}: {test}"
        );
        assert_eq!(parent, caller, "GNU time ran inside the workload's scope");
        assert!(
            measurement
                .as_ref()
                .is_ok_and(|measured| measured.peak_kb > 0),
            "a measured run lost its measurement: {measurement:?}"
        );
        assert_eq!(
            run("exit").termination,
            Ok(Termination::Exited(7)),
            "a measured run lost its test's exit status"
        );
        let killed = run("kill");
        assert_eq!(
            killed.termination,
            Ok(Termination::Signaled(9)),
            "a measured run lost the signal that killed its test"
        );
        assert!(
            killed.measurement.is_ok(),
            "a killed run lost its measurement: {:?}",
            killed.measurement
        );
        // An unreadable report: GNU time cannot open a directory as its
        // report, exits 125 and runs nothing. Its status is named; neither
        // the test's termination nor a measurement is made of it.
        std::fs::create_dir_all(directory.join("unreadable.measure")).unwrap();
        let unreadable = run("unreadable");
        assert!(
            unreadable
                .termination
                .as_ref()
                .is_err_and(|error| error.contains("unavailable")
                    && error.contains("GNU time ended with exit status: 125")),
            "GNU time's status was taken for the test's termination: {unreadable:?}"
        );
        assert!(
            unreadable.measurement.is_err(),
            "an unreadable report supplied a measurement: {unreadable:?}"
        );
        std::fs::remove_dir_all(&directory).unwrap();
    }

    /// GNU time's report ([`super::report`]) is read exactly as GNU time 1.10
    /// writes it, each form observed: a measurement alone for an exit of 0;
    /// `Command exited with non-zero status N` (time exiting N) or `Command
    /// terminated by signal N` (time exiting 128 + N) before it. A report
    /// that is missing a part, has another line, holds an invalid value or
    /// disagrees with time's own status supplies neither a termination nor a
    /// measurement it cannot establish.
    #[test]
    fn a_measurement_report_is_read_exactly() {
        use super::{Measurement, report};
        use crate::outcome::Termination;
        use std::os::unix::process::ExitStatusExt;
        let exited = |code: i32| std::process::ExitStatus::from_raw(code << 8);
        let measured = Ok(Measurement {
            peak_kb: 3476,
            seconds: "0.00".to_string(),
        });
        assert_eq!(
            report("3476 0.00\n", exited(0)),
            (Ok(Termination::Exited(0)), measured.clone())
        );
        assert_eq!(
            report(
                "Command exited with non-zero status 7\n3476 0.00\n",
                exited(7)
            ),
            (Ok(Termination::Exited(7)), measured.clone())
        );
        assert_eq!(
            report("Command terminated by signal 9\n3476 0.00\n", exited(137)),
            (Ok(Termination::Signaled(9)), measured.clone())
        );
        for (text, wrapper) in [
            ("", exited(0)),
            ("garbage nonsense\n", exited(0)),
            ("3476\n", exited(0)),
            ("Command terminated by signal 9\n", exited(137)),
            (
                "Command terminated by signal 9\nCommand exited with non-zero status 7\n3476 0.00\n",
                exited(137),
            ),
        ] {
            let (termination, measurement) = report(text, wrapper);
            assert!(
                termination.is_err() && measurement.is_err(),
                "a malformed report supplied {termination:?}, {measurement:?}: {text:?}"
            );
        }
        for measurement in [
            "-5 0.00",
            "3476 nonsense",
            "3476 inf",
            "3476 0.00 1",
            "x 0.00",
        ] {
            let (termination, measured) = report(&format!("{measurement}\n"), exited(0));
            assert!(
                measured.is_err() && termination.is_err(),
                "an invalid measurement supplied {termination:?}, {measured:?}: {measurement:?}"
            );
        }
        for (text, wrapper) in [
            ("Command terminated by signal 9\n3476 0.00\n", exited(0)),
            (
                "Command exited with non-zero status 7\n3476 0.00\n",
                exited(125),
            ),
            ("3476 0.00\n", exited(125)),
            (
                "Command exited with non-zero status 0\n3476 0.00\n",
                exited(0),
            ),
            (
                "Command exited with non-zero status 256\n3476 0.00\n",
                exited(0),
            ),
            (
                "Command exited with non-zero status -1\n3476 0.00\n",
                exited(255),
            ),
            ("Command terminated by signal x\n3476 0.00\n", exited(137)),
            ("Command terminated by signal 0\n3476 0.00\n", exited(128)),
            ("Command terminated by signal 65\n3476 0.00\n", exited(193)),
            ("Command terminated by signal -1\n3476 0.00\n", exited(127)),
            (
                "Command terminated by signal 2147483647\n3476 0.00\n",
                exited(0),
            ),
        ] {
            let (termination, _) = report(text, wrapper);
            assert!(
                termination.is_err(),
                "a report disagreeing with GNU time's status supplied {termination:?}: {text:?}"
            );
        }
    }

    #[test]
    fn controls_cannot_inherit_recording_authorization() {
        let names = [
            "DCBOR_RECORD_BUDGETS",
            "DCBOR_RECORD_FACTORS",
            "DCBOR_RECORD_TRACES",
        ];
        let mut command = std::process::Command::new("sh");
        for name in names {
            command.env(name, "planted");
        }
        isolate(&mut command, names.map(std::ffi::OsString::from));
        let output = command
            .args(["-c", "test -z \"${DCBOR_RECORD_BUDGETS+x}${DCBOR_RECORD_FACTORS+x}${DCBOR_RECORD_TRACES+x}\""])
            .output()
            .expect("run the isolated child");
        assert!(
            output.status.success(),
            "a control inherited recording authorization: {output:?}"
        );
    }

    /// A marker is found where libtest leaves it, after the test's name on
    /// its line, and at a line's start; each marker reads only its own
    /// line, not one it begins; no marker, no value.
    #[test]
    fn a_marker_is_found_where_libtest_leaves_it_and_nothing_else() {
        let described = "\nrunning 1 test\n\
                         test sync::models::loom_models::contended_queue_step::workers_1 ... \
                         DCBOR_MODEL\tunsized\nok\n";
        assert_eq!(marked(described, DESCRIPTION), Some("unsized"));
        assert_eq!(marked(described, SCHEDULES), None);
        let explored = "running 1 test\n\
                        test sync::models::shuttle_models::contended_queue_step::workers_5 ... \
                        DCBOR_MODEL_SCHEDULES\t120\nok\n";
        assert_eq!(marked(explored, SCHEDULES), Some("120"));
        assert_eq!(
            marked(explored, DESCRIPTION),
            None,
            "a schedule count is no description"
        );
        assert_eq!(marked("DCBOR_MODEL\tsized\n", DESCRIPTION), Some("sized"));
        assert_eq!(marked("test x ... ok\n", DESCRIPTION), None);
    }
}
