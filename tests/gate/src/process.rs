//! Running what the gates judge: each checker build's test binaries, each
//! model's test a process of its own, its environment exactly the declared
//! inputs, its termination, log and measurement kept. Every run is a
//! workload ([`workload`]): confined to a memory-capped scope of its own,
//! while the gate tool recording its judgement stays outside.

use std::collections::BTreeMap;
// `PathBuf` is the launcher's resolved path ([`kani_launcher`]).
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
    /// The launcher the gate running this tool exported (`WORKLOAD`);
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
    /// scope that runs it as its command (`run_once`).
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

/// The variable through which a bounded workload's launcher learns its
/// deadline (tests/workload.sh): the scope's `RuntimeMaxSec`.
const DEADLINE: &str = "DCBOR_WORKLOAD_DEADLINE";

/// `program` launched by `workload` as an isolated workload whose scope the
/// manager stops, every process of it, `seconds` after it starts
/// (tests/workload.sh), colour off (`TERM=dumb`) as every recorded
/// workload's. The workload ends by a signal at its deadline; its caller
/// tells a deadline from another signal by the time it waited.
pub fn bounded(workload: &Workload, program: impl AsRef<OsStr>, seconds: u64) -> Command {
    let mut command = isolated(workload.command(program));
    command
        .env(DEADLINE, seconds.to_string())
        .env("TERM", "dumb");
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
            || [BOUND, STACK, DESCRIBE, DEADLINE].contains(&text.as_ref())
        {
            command.env_remove(&name);
        }
    }
}

/// The diagnostics of a `cargo ... --message-format json` build: every
/// compiler message's rendered text, in the order cargo printed them
/// (`reason` `compiler-message`, `message.rendered`, on standard output),
/// then cargo's own standard error. With a JSON message format the
/// compiler's errors and warnings are on standard output only; standard
/// error holds cargo's progress and its summary (`could not compile ...`).
/// The one report of a build, the log a refused build is judged by.
fn build_report(stdout: &[u8], stderr: &[u8]) -> String {
    let mut report = String::new();
    for line in String::from_utf8_lossy(stdout).lines() {
        let Ok(message) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        if message["reason"] != "compiler-message" {
            continue;
        }
        if let Some(rendered) = message["message"]["rendered"].as_str() {
            report.push_str(rendered);
            if !rendered.ends_with('\n') {
                report.push('\n');
            }
        }
    }
    report.push_str(&String::from_utf8_lossy(stderr));
    report
}

/// A test binary as `cargo test` built it, and the directory of the package
/// it is a target of: the working directory and `CARGO_MANIFEST_DIR` cargo
/// runs it with, which a test locating its own package reads (trybuild's
/// `cargo::manifest_dir`, then `cargo metadata` in that directory). The gate
/// runs every test binary as cargo would (`run_once`), so a test that
/// reads its package's directory reads the copy's, never the caller's.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TestExecutable {
    pub path: PathBuf,
    pub package: PathBuf,
}

impl TestExecutable {
    /// The test executable a `cargo test --message-format json` build
    /// message reports: a `compiler-artifact` of the test profile with an
    /// `executable`, its package the directory of its `manifest_path`.
    /// None for any other message; refused when such an artifact names no
    /// manifest path, since its test would run without its package.
    pub fn of_message(message: &serde_json::Value) -> Result<Option<Self>, String> {
        if message["reason"] != "compiler-artifact" || message["profile"]["test"] != true {
            return Ok(None);
        }
        let Some(path) = message["executable"].as_str() else {
            return Ok(None);
        };
        let manifest = message["manifest_path"].as_str().ok_or_else(|| {
            format!("test executable {path}: its build message names no manifest_path")
        })?;
        let package = Path::new(manifest).parent().ok_or_else(|| {
            format!("test executable {path}: manifest_path {manifest} names no directory")
        })?;
        Ok(Some(Self {
            path: PathBuf::from(path),
            package: package.to_path_buf(),
        }))
    }
}

/// The RUSTFLAGS of `checker`'s build, the caller's own before them.
pub fn flags(checker: Checker) -> String {
    let own = std::env::var("RUSTFLAGS").unwrap_or_default();
    format!("{own} --cfg {checker}").trim_start().to_string()
}

/// Build `checker`'s test binaries of `root`, in release with every
/// feature, in its own target directory (each cfg rebuilds the library),
/// logging its diagnostics to `log` (`build_report`): the executable of
/// each target holding models ([`dcbor_model_bounds::targets`]). A build
/// that fails returns its log's contents.
pub fn build(
    root: &Path,
    checker: Checker,
    log: &Path,
) -> Result<BTreeMap<String, TestExecutable>, String> {
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
    let report = build_report(&output.stdout, &output.stderr);
    std::fs::write(log, &report).map_err(|error| format!("{}: {error}", log.display()))?;
    if !output.status.success() {
        return Err(report);
    }
    let mut executables = BTreeMap::new();
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        let Ok(message) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        let Some(executable) = TestExecutable::of_message(&message)? else {
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
            && executables.insert(name.clone(), executable).is_some()
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
/// diagnostics to `log` (`build_report`: the compiler's own messages,
/// which a refused build's judgement reads, then cargo's standard error).
/// Its test executable ([`crate::reach::executable`]),
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
) -> Result<Result<TestExecutable, String>, String> {
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
    let report = build_report(&output.stdout, &output.stderr);
    std::fs::write(log, &report).map_err(|error| format!("{}: {error}", log.display()))?;
    if !output.status.success() {
        return Ok(Err(report));
    }
    crate::reach::executable(&String::from_utf8_lossy(&output.stdout)).map(Ok)
}

/// One run of `test` alone in `executable` (`--exact`, one thread, output
/// uncaptured), in its package as cargo runs it (`run_once`), its
/// environment `environment` beside the controlled one and `TERM=dumb`,
/// logged to `log`: its termination and its log's text.
pub fn run_test(
    executable: &TestExecutable,
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

/// What one `cargo kani` run is asked to execute: in the tree at `root`, for
/// `purpose`, the harnesses `selection` names of the census `declared`, its
/// artifacts under `target_dir`, by the run's selected `launcher`, launched
/// as a `workload`, its standard output and error logged to `log` and its
/// evidence reserved beside it (`LOG.evidence`). Data alone: only its
/// validation ([`KaniRequest::validate`]) makes the run the one invocation
/// executes ([`KaniRun`]).
#[derive(Clone, Copy)]
pub struct KaniRequest<'a> {
    pub root: &'a Path,
    pub purpose: &'a crate::proofs::RunPurpose,
    pub selection: &'a crate::proofs::Selection,
    pub declared: &'a std::collections::BTreeSet<String>,
    pub target_dir: &'a Path,
    pub launcher: &'a Path,
    pub workload: &'a Workload,
    pub log: &'a Path,
}

/// A validated Kani run ([`KaniRequest::validate`], its only maker), what
/// [`execute_kani`] consumes: the request, and every input its validation
/// bound once: the tree's loop-bound policy file as read and its digest; the
/// run's selected policy, every selected harness with its purpose's
/// deadline; every source path's own digest and the source state they are
/// the digest of; and its evidence directory, reserved exclusively.
pub struct KaniRun<'a> {
    request: KaniRequest<'a>,
    policy_bytes: Vec<u8>,
    policy_sha256: String,
    selected: serde_json::Value,
    sources: BTreeMap<String, String>,
    tree_sha256: String,
    evidence: PathBuf,
}

impl<'a> KaniRequest<'a> {
    /// The request validated, refused before anything of the run is
    /// reserved: its launcher still the canonical path it was selected as
    /// ([`crate::proofs::selected_launcher`]); a census that declares a
    /// harness; a selection the purpose admits, of declared harnesses alone
    /// (a qualification the whole census; a calibration exactly one
    /// harness; a control side exactly the one its authorization binds; a
    /// discovery exactly the harnesses it was made for);
    /// the tree's policy file read once ([`crate::proofs::read_policy`]) and
    /// every selected harness given its purpose's deadline
    /// ([`crate::proofs::selected`]); the tree's source state read once, and
    /// a control side's the state its authorization binds. Then, last, its
    /// evidence directory reserved: created exclusively, owned by the run.
    pub fn validate(self) -> Result<KaniRun<'a>, String> {
        use crate::proofs::{RunPurpose, Selection};
        let canonical = std::fs::canonicalize(self.launcher)
            .map_err(|error| format!("{}: {error}", self.launcher.display()))?;
        if canonical != self.launcher {
            return Err(format!(
                "the selected launcher {} now resolves to {}",
                self.launcher.display(),
                canonical.display()
            ));
        }
        if self.declared.is_empty() {
            return Err(format!(
                "the library of {} declares no #[kani::proof] harness",
                self.root.display()
            ));
        }
        if let Selection::Only(harnesses) = self.selection {
            if harnesses.is_empty() {
                return Err("a Kani run that selects no harness checks nothing".to_string());
            }
            if let Some(undeclared) = harnesses
                .iter()
                .find(|harness| !self.declared.contains(*harness))
            {
                return Err(format!(
                    "harness {undeclared}: declared by no #[kani::proof] of {}",
                    self.root.display()
                ));
            }
        }
        match (self.purpose, self.selection) {
            (RunPurpose::Qualification(_), Selection::All) => {}
            (RunPurpose::Qualification(_), selection) => {
                return Err(format!(
                    "a qualification checks the whole census, the run selects {selection:?}"
                ));
            }
            (RunPurpose::Calibration { .. }, Selection::Only(harnesses))
                if harnesses.len() == 1 => {}
            (RunPurpose::Calibration { .. }, selection) => {
                return Err(format!(
                    "a calibration run checks exactly one harness, the run selects {selection:?}"
                ));
            }
            (RunPurpose::Control { authorization, .. }, selection) => {
                let record = authorization.record();
                if *selection != Selection::one(&record.harness) {
                    return Err(format!(
                        "a {} side authorizes harness {} alone, the run selects {selection:?}",
                        record.side.name(),
                        record.harness
                    ));
                }
            }
            (RunPurpose::Discovery(discovery), selection) => {
                if *selection != Selection::Only(discovery.selection().clone()) {
                    return Err(format!(
                        "a discovery checks exactly the harnesses it was made for, {:?}, the run \
                         selects {selection:?}",
                        discovery.selection()
                    ));
                }
            }
        }
        let (policy_bytes, policy) = crate::proofs::read_policy(self.root, self.declared)?;
        let policy_sha256 = sha256_bytes(&policy_bytes)?;
        let selected = crate::proofs::selected(
            &policy,
            &self.purpose.deadlines(),
            self.selection,
            self.declared,
        )?;
        let sources = crate::proofs::SourceState::read(self.root)?.digests()?;
        let tree_sha256 = crate::proofs::tree_digest_of(&sources)?;
        if let RunPurpose::Control { authorization, .. } = self.purpose {
            let record = authorization.record();
            if tree_sha256 != record.source_sha256 {
                return Err(format!(
                    "{}: its source state is {tree_sha256}, the {} side was authorized on {}",
                    self.root.display(),
                    record.side.name(),
                    record.source_sha256
                ));
            }
        }
        let evidence = self.log.with_extension("evidence");
        std::fs::create_dir(&evidence)
            .map_err(|error| format!("{}: {error}", evidence.display()))?;
        Ok(KaniRun {
            request: self,
            policy_bytes,
            policy_sha256,
            selected,
            sources,
            tree_sha256,
            evidence,
        })
    }
}

impl KaniRun<'_> {
    /// The run's reserved evidence directory.
    pub fn evidence(&self) -> &Path {
        &self.evidence
    }
}

/// The one `cargo kani` invocation of the validated run `run`, consumed:
/// the proof suite's evidence run, one calibration execution, or one control
/// side (`kani`). Its termination and its log's text.
pub fn execute_kani(run: KaniRun<'_>) -> Result<(Termination, String), String> {
    kani(&run)
}

/// The Kani a run selects: `cargo-kani` as `PATH` resolves it, canonical
/// (the development shell's bundle, `flake.nix` `kaniBundle`). The one
/// resolution of the launcher, made once per run by `proofs-identity`
/// ([`crate::proofs::identity`]); every Kani run of the run is given the
/// path it selected ([`crate::proofs::selected_launcher`]).
pub fn kani_launcher() -> Result<PathBuf, String> {
    let found = std::env::var_os("PATH")
        .and_then(|path| {
            std::env::split_paths(&path)
                .map(|directory| directory.join("cargo-kani"))
                .find(|candidate| candidate.is_file())
        })
        .ok_or("cargo-kani is not on PATH: run the gate in the development shell")?;
    std::fs::canonicalize(&found).map_err(|error| format!("{}: {error}", found.display()))
}

/// A record of the gate's, `bytes` at the new file `path`, durable as every
/// run's evidence is (`create_evidence`).
pub fn record(path: &Path, bytes: &[u8]) -> Result<(), String> {
    create_evidence(path, bytes)
}

/// `bytes` written to a new file at `path`, refused when the path exists:
/// evidence is created once and never overwritten.
pub(crate) fn create_evidence(path: &Path, bytes: &[u8]) -> Result<(), String> {
    use std::io::Write;
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .and_then(|mut file| {
            file.write_all(bytes)?;
            file.sync_all()
        })
        .and_then(|()| {
            std::fs::File::open(path.parent().unwrap_or_else(|| Path::new(".")))?.sync_all()
        })
        .map_err(|error| format!("{}: {error}", path.display()))
}

/// Persist acceptance or rejection before propagating the judgement. A rejected
/// execution carries diagnostics, never a fabricated verifier identity.
fn record_judgement<T>(evidence: &Path, result: Result<T, String>) -> Result<T, String> {
    let receipt = match &result {
        Ok(_) => serde_json::json!({"status": "accepted"}),
        Err(error) => serde_json::json!({"status": "rejected", "error": error}),
    };
    let encoded = serde_json::to_vec_pretty(&receipt)
        .map_err(|error| format!("{}: {error}", evidence.display()))?;
    create_evidence(&evidence.join("judgement.json"), &encoded).map_err(|error| match &result {
        Ok(_) => error,
        Err(original) => format!("{original}; cannot preserve judgement: {error}"),
    })?;
    result
}

/// The SHA-256 digest of the file at `path`, as `sha256sum` computes it:
/// the gates' one digest tool (tests/gate-common.sh, every gate script's
/// prerequisite), independent of the Kani driver whose recorded digests it
/// checks. The file is opened here and given as `sha256sum`'s standard
/// input, so its one output line is `DIGEST  -` whatever the path holds.
/// Refused when the file cannot be opened, when `sha256sum` fails, or when
/// its output is not exactly that line.
pub fn sha256(path: &Path) -> Result<String, String> {
    let file = std::fs::File::open(path).map_err(|error| format!("{}: {error}", path.display()))?;
    let output = Command::new("sha256sum")
        .stdin(file)
        .output()
        .map_err(|error| format!("sha256sum < {}: {error}", path.display()))?;
    digest_of(&output, &path.display().to_string())
}

/// The SHA-256 digest of `bytes`, by the same tool and the same check of
/// its output as [`sha256`]: the digest of a byte snapshot a caller parses,
/// so its identity and its interpretation are of one version.
pub fn sha256_bytes(bytes: &[u8]) -> Result<String, String> {
    use std::io::Write;
    let mut child = Command::new("sha256sum")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|error| format!("sha256sum: {error}"))?;
    let written = child
        .stdin
        .take()
        .ok_or("sha256sum: no standard input")?
        .write_all(bytes);
    let output = child
        .wait_with_output()
        .map_err(|error| format!("sha256sum: {error}"))?;
    written.map_err(|error| format!("sha256sum: writing {} bytes: {error}", bytes.len()))?;
    digest_of(&output, &format!("{} bytes", bytes.len()))
}

/// The digest `sha256sum` printed for the standard input it read, `what`
/// naming it: exactly one `DIGEST  -` line of a successful run.
fn digest_of(output: &std::process::Output, what: &str) -> Result<String, String> {
    if !output.status.success() {
        return Err(format!(
            "sha256sum < {what}: {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim_end()
        ));
    }
    let text = String::from_utf8_lossy(&output.stdout);
    match text.strip_suffix("  -\n") {
        Some(digest) if crate::proofs::sha256_text(digest) => Ok(digest.to_string()),
        _ => Err(format!("sha256sum < {what}: not one digest line: {text:?}")),
    }
}

/// The one `cargo kani` invocation of the validated run `run`: its selected
/// launcher with the build's own arguments, then `--harness HARNESS
/// --exact` for each harness of an explicit selection, then the target
/// directory, then the run's loop-bound policy and its evidence. Into its
/// reserved evidence (`LOG.evidence/`, [`KaniRequest::validate`]), each
/// record created exclusively, as the log is: `launcher`, the program
/// spawned; the documents it was given; its identity (`run.json`) of the
/// source state and policy its validation bound; a control side's
/// authorization; `loop-policy.json`, the tree's policy file as read, and
/// `sources.json`, every source path's digest, the records its identity's
/// policy and source state digests are of; `loop-bounds.json`, its selected
/// policy, which Kani reads; `invocation.json`, the launcher and every
/// argument; `loop-bounds/`, the directory Kani writes each harness's loop
/// discovery, resolution, solver command, executables and launch into
/// (`--loop-bounds-evidence`); and, once the run ends, `execution.json`, the
/// launcher, the verifier and each launched harness's artifact. Refused
/// after the run when its source state moved, or when its evidence does not
/// reconcile with its policy and its report
/// ([`crate::proofs::check_execution_evidence`]), so neither the suite nor a
/// control can take a verdict the evidence does not support.
fn kani(run: &KaniRun<'_>) -> Result<(Termination, String), String> {
    let KaniRequest {
        root,
        purpose,
        selection,
        target_dir,
        launcher,
        workload,
        log,
        ..
    } = run.request;
    let evidence = &run.evidence;
    // From here every outcome, a setup failure included, leaves its
    // judgement and the manifest of what the run recorded.
    let mut identified: Option<String> = None;
    let mut log_created = false;
    let result = (|| {
        create_evidence(
            &evidence.join(crate::proofs::LAUNCHER_RECORD),
            format!("{}\n", launcher.display()).as_bytes(),
        )?;
        // The documents the run was given, the very bytes its revision is the
        // digest of (and a calibration's readiness); then its identity before
        // anything launches: what it is for, that revision, and the tree's
        // source state it ran.
        for (name, document) in purpose.documents() {
            create_evidence(&evidence.join(name), document)?;
        }
        let identity = crate::proofs::run_identity(purpose, &run.tree_sha256, &run.policy_sha256)?;
        identified = Some(identity.id().to_string());
        let encoded = serde_json::to_vec_pretty(identity.record())
            .map_err(|error| format!("{}: {error}", evidence.display()))?;
        create_evidence(&evidence.join("run.json"), &encoded)?;
        // A control side's authorization, kept before it launches (the source
        // state it binds and its one harness were held to by validation).
        if let crate::proofs::RunPurpose::Control { authorization, .. } = purpose {
            let encoded = serde_json::to_vec_pretty(authorization.record())
                .map_err(|error| format!("{}: {error}", evidence.display()))?;
            create_evidence(&evidence.join("authorization.json"), &encoded)?;
        }
        // The inputs the identity's digests are of, as validation read them.
        create_evidence(
            &evidence.join(crate::proofs::LOOP_POLICY_RECORD),
            &run.policy_bytes,
        )?;
        let encoded = serde_json::to_vec_pretty(&run.sources)
            .map_err(|error| format!("{}: {error}", evidence.display()))?;
        create_evidence(&evidence.join(crate::proofs::SOURCES_RECORD), &encoded)?;
        let policy = evidence.join("loop-bounds.json");
        let encoded = serde_json::to_vec_pretty(&run.selected)
            .map_err(|error| format!("{}: {error}", policy.display()))?;
        create_evidence(&policy, &encoded)?;
        let bounds = evidence.join("loop-bounds");
        std::fs::create_dir(&bounds).map_err(|error| format!("{}: {error}", bounds.display()))?;
        let text = |path: &Path| {
            path.to_str()
                .map(str::to_string)
                .ok_or_else(|| format!("{}: a path that is not UTF-8", path.display()))
        };
        let arguments = crate::proofs::invocation_arguments(
            selection,
            &text(target_dir)?,
            &text(&policy)?,
            &text(&bounds)?,
        );
        let invocation = serde_json::json!({
            "launcher": text(launcher)?,
            "arguments": arguments,
        });
        let encoded = serde_json::to_vec_pretty(&invocation)
            .map_err(|error| format!("{}: {error}", evidence.display()))?;
        create_evidence(&evidence.join(crate::proofs::INVOCATION_RECORD), &encoded)?;
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(log)
            .map_err(|error| format!("{}: {error}", log.display()))?;
        log_created = true;
        let error = file
            .try_clone()
            .map_err(|error| format!("{}: {error}", log.display()))?;
        let mut command = isolated(workload.command(launcher));
        command
            .current_dir(root)
            .env("TERM", "dumb")
            .args(&arguments)
            .stdout(file)
            .stderr(error);
        // Spawned, not run to its end, so the workload's own control group is
        // read once its confinement has moved it there; then waited for.
        let load_before = crate::proofs::load();
        let (launched, (environment, workload_cgroup)) = match command.spawn() {
            Ok(mut child) => {
                let found = crate::proofs::EnvironmentRecord::of_workload(&mut child);
                (child.wait(), found)
            }
            Err(error) => (
                Err(error),
                (crate::proofs::EnvironmentRecord::unknown(), None),
            ),
        };
        let launched = launched.map_err(|error| format!("{}: {error}", launcher.display()));
        let launch = crate::proofs::Launch {
            environment,
            workload_cgroup,
            load_before,
            load_after: crate::proofs::load(),
        };
        let encoded = serde_json::to_vec_pretty(&launch)
            .map_err(|error| format!("{}: {error}", evidence.display()))?;
        create_evidence(&evidence.join("launch.json"), &encoded)?;
        let launch_receipt = match &launched {
            Ok(status) => {
                use std::os::unix::process::ExitStatusExt;
                serde_json::json!({"exit_code": status.code(), "signal": status.signal()})
            }
            Err(error) => serde_json::json!({"spawn_error": error}),
        };
        let encoded = serde_json::to_vec_pretty(&launch_receipt)
            .map_err(|error| format!("{}: {error}", evidence.display()))?;
        create_evidence(&evidence.join("launcher.execution.json"), &encoded)?;
        // The source the run is attributed to, read again once it ended: a
        // tree that differs from the one its identity names ran no one
        // source. A change made and undone while it ran is not detected.
        let after = crate::proofs::tree_digest(root)?;
        if after != identity.tree_sha256() {
            return Err(format!(
                "{}: its source state was {} when the run began and {after} when it ended: the \
                 run is of no one source",
                root.display(),
                identity.tree_sha256()
            ));
        }
        let status = launched?;
        let termination = {
            use std::os::unix::process::ExitStatusExt;
            match status.signal() {
                Some(signal) => Termination::Signaled(signal),
                None => Termination::Exited(status.code().unwrap_or(-1)),
            }
        };
        let text =
            std::fs::read_to_string(log).map_err(|error| format!("{}: {error}", log.display()))?;
        // A discovery is judged by its discovery records alone: its solvers
        // were stopped at their deadline, so its report, termination and
        // solver records establish nothing and are not reconciled.
        if let crate::proofs::RunPurpose::Discovery(discovery) = purpose {
            crate::proofs::check_discovery(&bounds, discovery, crate::proofs::Artifacts::Live)
                .map_err(|fault| format!("{}: {fault}", log.display()))?;
            return Ok((termination, text));
        }
        let reconciled = crate::proofs::check_execution_evidence(
            &bounds,
            &run.selected,
            &text,
            crate::proofs::Artifacts::Live,
        )
        .map_err(|fault| format!("{}: {fault}", log.display()))?;
        crate::proofs::check_function_scope(
            &bounds,
            &run.selected,
            &reconciled.applied,
            *selection == crate::proofs::Selection::All,
            crate::proofs::Artifacts::Live,
        )
        .map_err(|fault| format!("{}: {fault}", log.display()))?;
        // The reconciled execution, written once reconciliation succeeded:
        // the launcher, the verifier, and each launched harness's artifact.
        let artifacts: BTreeMap<&str, &str> = reconciled
            .launched
            .iter()
            .map(|(harness, launched)| (harness.as_str(), launched.artifact_sha256.as_str()))
            .collect();
        let execution = serde_json::json!({
            "launcher": launcher,
            "verifier": reconciled.verifier,
            "artifacts": artifacts,
        });
        let encoded = serde_json::to_vec_pretty(&execution)
            .map_err(|error| format!("{}: {error}", evidence.display()))?;
        create_evidence(&evidence.join("execution.json"), &encoded)?;
        // The purpose's own judgement, once every record above is kept: a
        // calibration's launcher must have ended as its harnesses' outcomes
        // call for, and is held to nothing more; a qualification and a
        // control side to their predictions, a control side's artifact being
        // its copy's own build.
        match purpose {
            crate::proofs::RunPurpose::Calibration { .. } => {
                crate::proofs::check_calibration_termination(termination, &text)
                    .map_err(|fault| format!("{}: {fault}", log.display()))?;
            }
            crate::proofs::RunPurpose::Qualification(expectations) => {
                crate::proofs::check_expectations(
                    &identity,
                    &launch,
                    &reconciled,
                    expectations,
                    crate::proofs::Applicability::Calibrated,
                )
                .map_err(|fault| format!("{}: {fault}", log.display()))?;
            }
            crate::proofs::RunPurpose::Control {
                expectations,
                authorization,
            } => {
                crate::proofs::check_expectations(
                    &identity,
                    &launch,
                    &reconciled,
                    expectations,
                    crate::proofs::Applicability::Control(authorization),
                )
                .map_err(|fault| format!("{}: {fault}", log.display()))?;
            }
            // Judged, and returned, by its discovery records above.
            crate::proofs::RunPurpose::Discovery(_) => {}
        }
        Ok((termination, text))
    })();
    // The judgement, then the manifest, attempted whatever the judgement's own
    // write did: the run's last record, describing exactly what it holds, its
    // identity named only when one was made.
    let judged = record_judgement(evidence, result);
    let manifest =
        crate::proofs::manifest_of(evidence, log_created.then_some(log), identified.as_deref());
    let written = serde_json::to_vec_pretty(&manifest)
        .map_err(|error| format!("{}: {error}", evidence.display()))
        .and_then(|encoded| create_evidence(&evidence.join("manifest.json"), &encoded));
    match (judged, written) {
        (judged, Ok(())) => judged,
        (Ok(_), Err(error)) => Err(format!("the run's manifest was not written: {error}")),
        (Err(fault), Err(error)) => Err(format!(
            "{fault}; the run's manifest was not written either: {error}"
        )),
    }
}

/// The models of `checker` the `target` binary `executable` lists, listed
/// in its package as cargo runs it.
pub fn list(
    checker: Checker,
    target: &str,
    executable: &TestExecutable,
) -> Result<Vec<Listed>, String> {
    let output = controlled(&executable.path)?
        .current_dir(&executable.package)
        .env("CARGO_MANIFEST_DIR", &executable.package)
        .args(["--list", "--format", "terse"])
        .output()
        .map_err(|error| format!("{}: {error}", executable.path.display()))?;
    if !output.status.success() {
        return Err(format!(
            "{} --list: {}",
            executable.path.display(),
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
///
/// The test runs in its package as `cargo test` runs it: its working
/// directory and `CARGO_MANIFEST_DIR` the package's directory
/// ([`TestExecutable`]). GNU time opens its report from that directory, so
/// the report's path is made absolute first.
fn run_once(
    workload: &Workload,
    executable: &TestExecutable,
    test: &str,
    environment: &[(&str, String)],
    log: &Path,
) -> Result<Measured, String> {
    let measure = std::path::absolute(log.with_extension("measure"))
        .map_err(|error| format!("{}: {error}", log.display()))?;
    let file = std::fs::File::create(log).map_err(|error| format!("{}: {error}", log.display()))?;
    let error = file
        .try_clone()
        .map_err(|error| format!("{}: {error}", log.display()))?;
    let mut command = isolated(Command::new("time"));
    command
        .args(["-f", "%M %e", "-o"])
        .arg(&measure)
        .arg(workload.launcher())
        .arg(&executable.path)
        .current_dir(&executable.package)
        .env("CARGO_MANIFEST_DIR", &executable.package)
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
pub fn sized(executable: &TestExecutable, listed: &Listed, log: &Path) -> Result<bool, String> {
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
    executable: &TestExecutable,
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

    #[test]
    fn rejected_execution_retains_its_judgement_without_a_verifier() {
        let directory = std::env::temp_dir().join(format!(
            "dcbor-gate-rejected-execution-{}",
            std::process::id()
        ));
        std::fs::create_dir(&directory).unwrap();
        let rejected = super::record_judgement::<()>(
            &directory,
            Err("expectation exceeded by one nanosecond".to_string()),
        );
        assert_eq!(
            rejected,
            Err("expectation exceeded by one nanosecond".to_string())
        );
        let bytes = std::fs::read(directory.join("judgement.json"))
            .expect("rejection-unrecorded: a rejected execution left no judgement.json");
        let receipt: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(receipt["status"], "rejected");
        assert_eq!(receipt["error"], "expectation exceeded by one nanosecond");
        assert!(receipt.get("verifier").is_none());
        let replacement = super::record_judgement(&directory, Ok(()));
        assert!(replacement.is_err(), "existing rejection was overwritten");
        assert_eq!(
            std::fs::read(directory.join("judgement.json")).unwrap(),
            bytes
        );
        std::fs::remove_dir_all(directory).unwrap();
    }

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
    /// signal that killed it. The test runs in its package as `cargo test`
    /// runs it, its working directory and `CARGO_MANIFEST_DIR` the
    /// package's, whatever the caller's own directory is.
    #[test]
    fn a_measured_run_records_how_its_confined_test_ended() {
        use crate::outcome::Termination;
        let directory =
            std::env::temp_dir().join(format!("dcbor-gate-measured-run-{}", std::process::id()));
        let package = directory.join("package");
        std::fs::create_dir_all(&package).unwrap();
        let script = directory.join("test.sh");
        std::fs::write(
            &script,
            "#!/bin/sh\n\
             printf 'test t ... \\n'\n\
             case \"$DCBOR_TEST_END\" in exit) exit 7 ;; kill) kill -KILL $$ ;; esac\n\
             cut -d: -f3 /proc/self/cgroup\n\
             cut -d: -f3 /proc/$PPID/cgroup\n\
             pwd -P\n\
             printf '%s\\n' \"$CARGO_MANIFEST_DIR\"\n",
        )
        .unwrap();
        let executable = |path: std::path::PathBuf| super::TestExecutable {
            path,
            package: package.clone(),
        };
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
                &executable(script.clone()),
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
            &executable(directory.join("nonexistent")),
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
        let [test, parent, working, manifest] = lines[..] else {
            panic!("the test reported {text:?}");
        };
        let package_path = std::fs::canonicalize(&package).unwrap();
        assert_eq!(
            std::path::Path::new(working),
            package_path,
            "package-unentered: a test ran outside its package's directory"
        );
        assert_eq!(
            std::path::Path::new(manifest),
            package,
            "package-unnamed: a test ran without its package's CARGO_MANIFEST_DIR"
        );
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

    /// A refused build's report holds the compiler's own diagnostic: under
    /// `--message-format json` rustc's messages reach cargo's standard
    /// output only, each wrapped as a `compiler-message`, while standard
    /// error holds cargo's summary. The diagnostic here is rustc's own,
    /// produced by compiling a use of a moved value, wrapped as cargo wraps
    /// it; the report must hold its rendered text, then the summary.
    #[test]
    fn a_refused_build_reports_the_compilers_diagnostic() {
        let directory =
            std::env::temp_dir().join(format!("dcbor-gate-build-report-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let source = directory.join("moved.rs");
        std::fs::write(
            &source,
            "pub fn twice() { let held = String::new(); drop(held); drop(held); }\n",
        )
        .unwrap();
        let rustc = std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
        let compiled = std::process::Command::new(rustc)
            .args([
                "--edition",
                "2024",
                "--crate-type",
                "lib",
                "--error-format",
                "json",
            ])
            .arg("--out-dir")
            .arg(&directory)
            .arg(&source)
            .env("TERM", "dumb")
            .output()
            .expect("run rustc");
        std::fs::remove_dir_all(&directory).unwrap();
        assert!(!compiled.status.success(), "the moved value compiled");
        let stdout: String = String::from_utf8_lossy(&compiled.stderr)
            .lines()
            .map(|message| format!("{{\"reason\":\"compiler-message\",\"message\":{message}}}\n"))
            .collect();
        let summary = "error: could not compile `moved` (lib) due to 1 previous error\n";
        let report = super::build_report(stdout.as_bytes(), summary.as_bytes());
        assert!(
            report.contains("use of moved value"),
            "a refused build's report lost the compiler's diagnostic: {report}"
        );
        assert!(
            report.ends_with(summary),
            "a refused build's report lost cargo's summary: {report}"
        );
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
