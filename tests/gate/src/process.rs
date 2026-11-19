//! Running what the gates judge: each checker build's test binaries, each
//! model's test a process of its own, its environment exactly the declared
//! inputs, its termination, log and measurement kept.

use std::collections::BTreeMap;
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

/// A command whose environment holds nothing a model run may not read: no
/// `LOOM_*`, `SHUTTLE_*`, or `DCBOR_RECORD_*` variable, backtraces off,
/// no model value. Control runs cannot inherit permission to rewrite evidence.
fn controlled(program: impl AsRef<std::ffi::OsStr>) -> Command {
    let mut command = Command::new(program);
    isolate(&mut command, std::env::vars_os().map(|(name, _)| name));
    command.env("RUST_BACKTRACE", "0");
    command
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
    let mut command = controlled("cargo");
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
    let mut command = controlled("cargo");
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
    let (termination, text, _, _) = run_once(executable, test, &environment, log)?;
    Ok((termination, text))
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
    let status = controlled("cargo")
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
    let output = controlled(executable)
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

/// One run of `listed`'s test in `executable`, its own process, with
/// `environment` its model variables, logged to `log`: its termination as
/// GNU time reports it, with its peak resident kilobytes and wall seconds.
fn run_once(
    executable: &Path,
    test: &str,
    environment: &[(&str, String)],
    log: &Path,
) -> Result<(Termination, String, Option<String>, Option<u64>), String> {
    let measure = log.with_extension("measure");
    let file = std::fs::File::create(log).map_err(|error| format!("{}: {error}", log.display()))?;
    let error = file
        .try_clone()
        .map_err(|error| format!("{}: {error}", log.display()))?;
    let mut command = controlled("time");
    command
        .args(["-f", "%M %e", "-o"])
        .arg(&measure)
        .arg(executable)
        .args(["--exact", test, "--nocapture", "--test-threads=1"])
        .stdout(file)
        .stderr(error);
    for (name, value) in environment {
        command.env(name, value);
    }
    let status = command.status().map_err(|error| format!("time: {error}"))?;
    let measured = std::fs::read_to_string(&measure).unwrap_or_default();
    // GNU time names a signal that ended its command, then reports the
    // measurement on its last line.
    let signal = measured.lines().find_map(|line| {
        line.strip_prefix("Command terminated by signal ")
            .and_then(|number| number.trim().parse::<i32>().ok())
    });
    let termination = match signal {
        Some(signal) => Termination::Signaled(signal),
        None => Termination::Exited(status.code().unwrap_or(-1)),
    };
    let (peak, seconds) = measured
        .lines()
        .last()
        .and_then(|line| line.split_once(' '))
        .map_or((None, None), |(peak, seconds)| {
            (peak.parse().ok(), Some(seconds.to_string()))
        });
    let text = std::fs::read_to_string(log).unwrap_or_default();
    Ok((termination, text, seconds, peak))
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
    let (termination, text, _, _) = run_once(
        executable,
        &listed.test,
        &[(DESCRIBE, "1".to_string())],
        log,
    )?;
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
    let (termination, text, seconds, peak_kb) =
        run_once(executable, &listed.test, &environment, log)?;
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
    use super::{DESCRIPTION, SCHEDULES, isolate, marked};

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
