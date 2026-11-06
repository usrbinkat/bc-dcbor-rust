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
/// `LOOM_*` or `SHUTTLE_*` variable, backtraces off, no model value.
fn controlled(program: impl AsRef<std::ffi::OsStr>) -> Command {
    let mut command = Command::new(program);
    for (name, _) in std::env::vars_os() {
        let text = name.to_string_lossy();
        if text.starts_with("LOOM_")
            || text.starts_with("SHUTTLE_")
            || [BOUND, STACK, DESCRIBE].contains(&text.as_ref())
        {
            command.env_remove(&name);
        }
    }
    command.env("RUST_BACKTRACE", "0");
    command
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

/// Whether `listed` runs on a sized stack, by its runner's own description.
pub fn sized(executable: &Path, listed: &Listed, log: &Path) -> Result<bool, String> {
    let (termination, text, _, _) = run_once(
        executable,
        &listed.test,
        &[(DESCRIBE, "1".to_string())],
        log,
    )?;
    let description = text.lines().find_map(|line| {
        line.strip_prefix(DESCRIPTION)
            .and_then(|rest| rest.strip_prefix('\t'))
    });
    match (termination, description) {
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
    let schedules = text.lines().find_map(|line| {
        line.strip_prefix(SCHEDULES)
            .and_then(|rest| rest.strip_prefix('\t'))
            .and_then(|count| count.parse().ok())
    });
    Ok(Ran {
        outcome: outcome::model(listed.checker, termination, &text),
        schedules,
        seconds,
        peak_kb,
    })
}
