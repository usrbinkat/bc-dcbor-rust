//! The launchers' own contracts, where a launcher decides what it passes to
//! the gate: each run on a copy of the script in a scratch repository, with
//! the programs it launches replaced by recorders.

use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// The repository's tests directory.
fn tests() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..")
}

/// A scratch repository named for `test`, removed unless the test fails.
struct Scratch(PathBuf);

impl Scratch {
    fn new(test: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "dcbor-gate-launchers-{test}-{}",
            std::process::id()
        ));
        if root.exists() {
            std::fs::remove_dir_all(&root).unwrap();
        }
        std::fs::create_dir_all(root.join("tests")).unwrap();
        std::fs::create_dir_all(root.join("bin")).unwrap();
        Self(root)
    }

    fn executable(&self, relative: &str, text: &str) {
        let path = self.0.join(relative);
        std::fs::write(&path, text).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        if !std::thread::panicking() {
            std::fs::remove_dir_all(&self.0).unwrap();
        }
    }
}

/// The contribution gate checks the records, then the cost evidence, passing
/// a completed run to reuse when one is named, and fails when the cost
/// check fails.
#[test]
fn the_contribution_gate_forwards_a_reused_run_and_its_failure() {
    let scratch = Scratch::new("contribution");
    std::fs::copy(
        tests().join("run-contribution-contracts.sh"),
        scratch.0.join("tests/run-contribution-contracts.sh"),
    )
    .unwrap();
    scratch.executable("bin/cargo", "#!/bin/sh\nexit 0\n");
    scratch.executable(
        "tests/record-evidence.sh",
        "#!/bin/bash\nprintf '%s\\n' \"$*\" >> evidence-arguments\n\
         if [[ \"$1\" == check-costs ]]; then exit \"${REUSE_EXIT:-0}\"; fi\n",
    );
    let path = format!(
        "{}:{}",
        scratch.0.join("bin").display(),
        std::env::var("PATH").unwrap()
    );
    for status in [0, 1] {
        let arguments = scratch.0.join("evidence-arguments");
        if arguments.exists() {
            std::fs::remove_file(&arguments).unwrap();
        }
        let output = Command::new("bash")
            .arg("tests/run-contribution-contracts.sh")
            .current_dir(&scratch.0)
            .env("PATH", &path)
            .env("TMPDIR", &scratch.0)
            .env("DCBOR_COST_REUSE", "/completed run")
            .env("REUSE_EXIT", status.to_string())
            .env_remove("CONTRACT_LOG_DIR")
            .env_remove("DCBOR_RIGOR")
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(status),
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            std::fs::read_to_string(&arguments).unwrap(),
            "check\ncheck-costs /completed run\n"
        );
    }
}

/// A gate as the gates begin (tests/gate-common.sh, `own_process_group`)
/// holding what a gate holds while it runs: a child of its own, and a child
/// whose own child outlives nothing it started, as cargo runs a test binary.
/// Each process appends its identifier to `pids`. With `HOLD_NESTED=1` it
/// also starts a gate of its own, as a gate runs another (the mutation
/// campaign its Miri judge), which records its four processes beside these.
const HOLDING_GATE: &str = r#"#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
startup_boundary() {
    [[ "${HOLD_PHASE:-}" == "$1" ]] || return 0
    printf '%s\n' "$BASHPID" >boundary
    kill -STOP "$BASHPID"
}
if [[ -n "${HOLD_PHASE:-}" ]]; then
    set -T
    trap 'case "$BASH_COMMAND" in
        "unset DCBOR_GATE_SUPERVISOR") startup_boundary child ;;
        "trap stop_group TERM INT HUP") startup_boundary watcher ;;
        "printf "*ready) startup_boundary readiness ;;
    esac' DEBUG
fi
source tests/gate-common.sh
own_process_group "$@"
startup_boundary workload
if [[ "${HOLD_IGNORE_TERM:-0}" == 1 ]]; then trap '' TERM; fi
printf '%s\n' "$$" >>pids
sleep 600 &
printf '%s\n' "$!" >>pids
bash -c 'sleep 600 & printf "%s\n%s\n" "$$" "$!" >>pids; wait' &
if [[ "${HOLD_NESTED:-0}" == 1 ]]; then HOLD_NESTED=0 bash tests/hold.sh & fi
while [[ ! -e release ]]; do sleep 0.05; done
exit 0
"#;

/// A process's state, parent and session: proc_pid_stat(5) fields 3, 4 and
/// 6, which the ptrace access check does not suppress.
struct Stat {
    state: char,
    parent: u32,
    session: u32,
}

impl Stat {
    fn running(&self) -> bool {
        !matches!(self.state, 'Z' | 'X' | 'x')
    }
}

/// Read the kernel's process state; disappearance is distinct from an
/// unreadable or malformed record.
fn process_state(pid: u32) -> std::io::Result<Option<Stat>> {
    match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
        Ok(stat) => stat
            .rsplit_once(") ")
            .and_then(|(_, fields)| {
                let mut fields = fields.split_whitespace();
                let mut state = fields.next()?.chars();
                let (state, None) = (state.next()?, state.next()) else {
                    return None;
                };
                let parent = fields.next()?.parse().ok()?;
                fields.next()?.parse::<u32>().ok()?;
                let session = fields.next()?.parse().ok()?;
                "RSDZTtXxKWPI".contains(state).then_some(Stat {
                    state,
                    parent,
                    session,
                })
            })
            .map(Some)
            .ok_or_else(|| std::io::Error::other(format!("invalid /proc/{pid}/stat"))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

fn running(pid: u32) -> std::io::Result<bool> {
    Ok(process_state(pid)?.is_some_and(|stat| stat.running()))
}

/// Whether `pid` sleeps in read(2) on its standard input: the system call
/// and first argument a blocked task reports (proc_pid_syscall(5)). A
/// runnable task reports `running` instead, so an unscheduled process is
/// never taken for a blocked one. Reading it requires ptrace attach access,
/// which the test process, an ancestor of every fixture process, holds.
fn reading_stdin(pid: u32) -> std::io::Result<bool> {
    let text = std::fs::read_to_string(format!("/proc/{pid}/syscall"))?;
    let mut fields = text.split_whitespace();
    Ok(fields
        .next()
        .and_then(|number| number.parse::<libc::c_long>().ok())
        == Some(libc::SYS_read)
        && fields.next() == Some("0x0"))
}

/// All live members of the fixture's session, including nested groups and
/// reparented processes. Membership does not depend on cwd access or PID
/// recording. Fixture programs never create another session.
fn running_in(session: u32) -> std::io::Result<Vec<u32>> {
    let mut found = Vec::new();
    for entry in std::fs::read_dir("/proc")? {
        let entry = entry?;
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
        else {
            continue;
        };
        if process_state(pid)?.is_some_and(|stat| stat.session == session && stat.running()) {
            found.push(pid);
        }
    }
    Ok(found)
}

fn signal(signal: &str, target: &str) -> std::io::Result<std::process::ExitStatus> {
    Command::new("kill")
        .args(["-s", signal, "--", target])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
}

/// Reap the launcher and remove fixture processes even when readiness or a
/// shutdown assertion fails: every process in the fixture session
/// ([`running_in`]), so none survives into the next test or the
/// host, recorded or not.
struct HoldingGate {
    supervisor: std::process::Child,
    recorded: PathBuf,
    root: PathBuf,
}

impl HoldingGate {
    fn start(scratch: &Scratch, environment: &[(&str, &str)]) -> Self {
        std::fs::copy(
            tests().join("gate-common.sh"),
            scratch.0.join("tests/gate-common.sh"),
        )
        .unwrap();
        scratch.executable("tests/hold.sh", HOLDING_GATE);
        let mut command = Command::new("bash");
        command
            .arg("tests/hold.sh")
            .current_dir(&scratch.0)
            .env_remove("DCBOR_GATE_SUPERVISOR")
            .env_remove("HOLD_IGNORE_TERM")
            .env_remove("HOLD_NESTED")
            .env_remove("HOLD_PHASE")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        for (name, value) in environment {
            command.env(name, value);
        }
        // The child, a fresh fork in the test's process group and so no
        // group leader, starts a session of its own before it execs bash:
        // its PID is the session every fixture descendant inherits, nested
        // groups and reparented processes included.
        // SAFETY: `setsid(2)` is async-signal-safe (signal-safety(7)) and
        // touches no memory the parent shares; its failure fails the spawn.
        unsafe {
            command.pre_exec(|| {
                if libc::setsid() == -1 {
                    Err(std::io::Error::last_os_error())
                } else {
                    Ok(())
                }
            });
        }
        let root = std::fs::canonicalize(&scratch.0).unwrap();
        Self {
            supervisor: command.spawn().unwrap(),
            recorded: scratch.0.join("pids"),
            root,
        }
    }

    fn pids(&self) -> Vec<u32> {
        let text = match std::fs::read_to_string(&self.recorded) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Vec::new(),
            Err(error) => panic!("read {}: {error}", self.recorded.display()),
        };
        text.lines().map(|line| line.parse().unwrap()).collect()
    }

    /// The recorded processes once there are `count` of them, within the
    /// fixture deadline.
    fn started(&self, count: usize) -> Vec<u32> {
        let started = Instant::now();
        loop {
            let pids = self.pids();
            if pids.len() == count {
                return pids;
            }
            assert!(
                started.elapsed() < Duration::from_secs(30),
                "the gate started {pids:?}, not its {count} processes"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// The boundary is reached only once its reporting process is stopped.
    /// Recording its PID alone is insufficient: SIGCONT could otherwise
    /// arrive before SIGSTOP and leave the fixture suspended. `qualifying`
    /// names the case a missing boundary leaves unqualified.
    fn boundary(&mut self, phase: &str, qualifying: &str) -> u32 {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            match std::fs::read_to_string(self.root.join("boundary")) {
                Ok(text) => {
                    if let Ok(pid) = text.trim().parse::<u32>() {
                        match process_state(pid) {
                            Ok(Some(Stat {
                                state: 'T',
                                session,
                                ..
                            })) if session == self.supervisor.id() => return pid,
                            Ok(_) => {}
                            Err(error) => panic!("inspect {phase} boundary process: {error}"),
                        }
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => panic!("read {phase} boundary: {error}"),
            }
            assert!(
                self.supervisor.try_wait().unwrap().is_none() && Instant::now() < deadline,
                "{qualifying} cannot be qualified: {phase} boundary was not reached"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// A gate whose watcher is held at `phase`, before its handler is
    /// installed or before readiness is published, waits for readiness: its
    /// leader, the held watcher's parent, is observed asleep in read(2) on
    /// its standard input ([`reading_stdin`]), the pipe the watcher's
    /// standard output writes. A leader past readiness never blocks on that
    /// pipe again and records its work, which fails at once.
    fn awaiting_readiness(&self, watcher: u32, phase: &str) {
        let leader = process_state(watcher)
            .expect("inspect the held watcher")
            .expect("the held watcher is running")
            .parent;
        let pipe = std::fs::read_link(format!("/proc/{watcher}/fd/1"))
            .expect("read the held watcher's standard output");
        assert!(
            pipe.to_str().is_some_and(|name| name.starts_with("pipe:")),
            "the held watcher writes {}, not the readiness pipe",
            pipe.display()
        );
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let pids = self.pids();
            assert!(
                pids.is_empty(),
                "a gate held at {phase} passed readiness while its watcher was held: it recorded {pids:?}"
            );
            let input = std::fs::read_link(format!("/proc/{leader}/fd/0"))
                .expect("read the leader's standard input");
            if input == pipe && reading_stdin(leader).expect("inspect the leader's system call") {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "a gate held at {phase} was never observed waiting on its watcher's readiness"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// Observe shutdown within the fixture deadline: the launcher's status
    /// and every process still running in the fixture session.
    fn stopped(&mut self) -> (Option<std::process::ExitStatus>, Vec<u32>) {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let status = self.supervisor.try_wait().unwrap();
            let left = running_in(self.supervisor.id()).expect("inspect fixture processes");
            if (left.is_empty() && status.is_some()) || Instant::now() >= deadline {
                return (status, left);
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}

impl Drop for HoldingGate {
    fn drop(&mut self) {
        let _ = self.supervisor.kill();
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let observation = running_in(self.supervisor.id());
            let status = self.supervisor.try_wait();
            if let (Ok(left), Ok(status)) = (&observation, &status) {
                if left.is_empty() && status.is_some() {
                    return;
                }
                for pid in left {
                    let _ = signal("KILL", &pid.to_string());
                }
            }
            if Instant::now() >= deadline {
                let failure = format!(
                    "fixture cleanup incomplete at {}: processes={observation:?}, supervisor={status:?}",
                    self.root.display()
                );
                if !std::thread::panicking() {
                    panic!("{failure}");
                }
                eprintln!("{failure}");
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

/// A gate stopped by its caller ends every process it started, its
/// children's included: the caller's termination is forwarded to the gate's
/// process group, and a supervisor killed outright (SIGKILL, which no trap
/// sees) is noticed by the group's watcher, which ends the group.
#[test]
fn a_stopped_gate_leaves_no_process_running() {
    for (action, ignore_term) in [
        ("TERM", false),
        ("INT", false),
        ("HUP", false),
        ("KILL", false),
        ("exit", false),
        ("TERM", true),
        ("INT", true),
        ("HUP", true),
        ("KILL", true),
        ("exit", true),
    ] {
        let scratch = Scratch::new(&format!(
            "process-group-{}-{ignore_term}",
            action.to_lowercase()
        ));
        let mut gate = HoldingGate::start(
            &scratch,
            &[("HOLD_IGNORE_TERM", if ignore_term { "1" } else { "0" })],
        );
        let pids = gate.started(4);
        if action == "exit" {
            std::fs::write(scratch.0.join("release"), "").unwrap();
        } else {
            let signalled = signal(action, &gate.supervisor.id().to_string()).unwrap();
            assert!(signalled.success(), "kill -s {action} failed");
        }
        let (status, left) = gate.stopped();
        assert!(status.is_some(), "{action}: supervisor did not exit");
        if action == "exit" {
            assert!(status.unwrap().success(), "normal gate exit changed status");
        }
        assert!(
            left.is_empty(),
            "a gate stopped by SIG{action} left {left:?} of {pids:?} running (ignores TERM: {ignore_term})"
        );
    }
}

/// A gate a stopped gate started ends with it: the nested gate's supervisor
/// is a member of the outer group and its own group is not, so its group
/// ends either by the termination the nested supervisor forwards or, when
/// the outer group's escalation kills that supervisor first, by the nested
/// group's own watcher, which finds its gate's parent gone.
#[test]
fn a_stopped_gate_ends_the_gates_it_started() {
    for (action, ignore_term) in [
        ("TERM", false),
        ("KILL", false),
        ("TERM", true),
        ("KILL", true),
    ] {
        let scratch = Scratch::new(&format!(
            "process-group-nested-{}-{ignore_term}",
            action.to_lowercase()
        ));
        let mut gate = HoldingGate::start(
            &scratch,
            &[
                ("HOLD_IGNORE_TERM", if ignore_term { "1" } else { "0" }),
                ("HOLD_NESTED", "1"),
            ],
        );
        let pids = gate.started(8);
        let signalled = signal(action, &gate.supervisor.id().to_string()).unwrap();
        assert!(signalled.success(), "kill -s {action} failed");
        let (status, left) = gate.stopped();
        assert!(status.is_some(), "{action}: supervisor did not exit");
        assert!(
            left.is_empty(),
            "a nested gate stopped by SIG{action} left {left:?} of {pids:?} running (ignores TERM: {ignore_term})"
        );
    }
}

/// Interrupt at observed, stopped startup boundaries rather than inferring
/// execution phases from elapsed time. DEBUG tracing is fixture-only; the
/// supervisor source copied into the fixture remains unchanged.
#[test]
fn a_gate_stopped_while_it_starts_leaves_no_process_running() {
    for action in ["TERM", "KILL"] {
        for ignore_term in [false, true] {
            for phase in ["child", "watcher", "readiness", "workload"] {
                let scratch = Scratch::new(&format!(
                    "process-group-starting-{}-{ignore_term}-{phase}",
                    action.to_lowercase()
                ));
                let mut gate = HoldingGate::start(
                    &scratch,
                    &[
                        ("HOLD_IGNORE_TERM", if ignore_term { "1" } else { "0" }),
                        ("HOLD_PHASE", phase),
                    ],
                );
                let paused = gate.boundary(
                    phase,
                    &format!("a gate stopped while starting by SIG{action}"),
                );
                if matches!(phase, "watcher" | "readiness") {
                    gate.awaiting_readiness(paused, phase);
                }
                assert!(
                    gate.pids().is_empty(),
                    "work started before release of the {phase} startup boundary"
                );
                let signalled = signal(action, &gate.supervisor.id().to_string()).unwrap();
                assert!(signalled.success(), "kill -s {action} failed");
                let resumed = signal("CONT", &paused.to_string()).unwrap();
                assert!(
                    resumed.success() || !running(paused).unwrap(),
                    "resume {phase} boundary process {paused}"
                );
                let (status, left) = gate.stopped();
                assert!(
                    status.is_some(),
                    "{action} at {phase}: supervisor did not exit"
                );
                assert!(
                    left.is_empty(),
                    "a gate stopped while starting by SIG{action} at {phase} left {left:?} \
                     running (ignores TERM: {ignore_term})"
                );
            }
        }
    }
}

/// A gate whose watcher is held before installing its handler, or before
/// publishing readiness, waits on that watcher ([`HoldingGate::awaiting_readiness`]);
/// released, the watcher publishes readiness, and the gate starts its work
/// and exits normally with nothing left running.
#[test]
fn a_gate_starts_its_work_once_its_watcher_is_ready() {
    for phase in ["watcher", "readiness"] {
        let scratch = Scratch::new(&format!("process-group-ready-{phase}"));
        let mut gate = HoldingGate::start(&scratch, &[("HOLD_PHASE", phase)]);
        let watcher = gate.boundary(phase, "a gate released by its watcher");
        gate.awaiting_readiness(watcher, phase);
        let resumed = signal("CONT", &watcher.to_string()).unwrap();
        assert!(resumed.success(), "resume the {phase} watcher {watcher}");
        let pids = gate.started(4);
        std::fs::write(scratch.0.join("release"), "").unwrap();
        let (status, left) = gate.stopped();
        assert!(
            status.is_some_and(|status| status.success()),
            "a gate released at {phase} did not exit normally: {status:?}"
        );
        assert!(
            left.is_empty(),
            "a gate released at {phase} left {left:?} of {pids:?} running"
        );
    }
}

/// A supervised launch whose parent is already gone must not become a new
/// top-level supervisor and start the workload.
#[test]
fn an_orphaned_supervised_launch_starts_no_work() {
    let scratch = Scratch::new("orphaned-launch");
    let mut gate = HoldingGate::start(&scratch, &[("DCBOR_GATE_SUPERVISOR", "0")]);
    let (status, left) = gate.stopped();
    let status = status.expect("orphaned launch did not exit");
    assert_eq!(status.code(), Some(143));
    assert!(left.is_empty(), "an orphaned launch left {left:?} running");
    assert!(gate.pids().is_empty(), "an orphaned launch started work");
}

/// Every script that sources the gates' common definitions owns its process
/// group: `own_process_group "$@"` on the line after the `source`. A gate
/// that does not leaves every process it started running when it is
/// stopped.
#[test]
fn every_gate_owns_its_process_group() {
    let root = tests().join("..");
    let mut scripts = Vec::new();
    for directory in ["tests", "fuzz"] {
        for entry in std::fs::read_dir(root.join(directory)).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().is_some_and(|extension| extension == "sh") {
                scripts.push(path);
            }
        }
    }
    scripts.sort();
    let mut gates = Vec::new();
    let mut unowned = Vec::new();
    for path in &scripts {
        let text = std::fs::read_to_string(path).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        for (index, line) in lines.iter().enumerate() {
            if line.trim() == "source tests/gate-common.sh" {
                gates.push(path.display().to_string());
                if lines.get(index + 1).map(|next| next.trim()) != Some("own_process_group \"$@\"")
                {
                    unowned.push(path.display().to_string());
                }
            }
        }
    }
    assert!(!gates.is_empty(), "no script sources tests/gate-common.sh");
    assert!(
        unowned.is_empty(),
        "gates owning no process group: {unowned:?}"
    );
}
