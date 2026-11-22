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
/// With `HOLD_ALLOCATE=1` it then runs, as a workload of the gate's
/// (`confined`, tests/gate-common.sh `gate_confinement`), a child that
/// records its own scope's cgroup, `memory.max`, `memory.swap.max` and
/// `OOMPolicy` and `oom_kill` count in `confinement`, leaves a holder
/// process in the scope (its PID in `holder`) to keep the scope's cgroup
/// for an outside reader, and then doubles a string toward 256 MiB, as a
/// runaway checker grows; the gate records the workload's exit status in
/// `allocated` before it waits to be released.
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
if [[ "${HOLD_ALLOCATE:-0}" == 1 ]]; then
    grown=0
    "${confined[@]}" bash -c '
        sleep 600 &
        printf "%s\n" "$!" >holder
        cg="$(cut -d: -f3 /proc/self/cgroup)"
        printf "%s\n%s\n%s\n%s\n%s\n" "$cg" "$(cat "/sys/fs/cgroup$cg/memory.max")" \
            "$(cat "/sys/fs/cgroup$cg/memory.swap.max")" \
            "$(systemctl --user show "${cg##*/}" --property=OOMPolicy --value)" \
            "$(grep "^oom_kill " "/sys/fs/cgroup$cg/memory.events")" >confinement
        grown=a
        while ((${#grown} < 268435456)); do grown+=$grown; done' || grown=$?
    printf '%s\n' "$grown" >allocated
fi
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
/// unreadable or malformed record. A process gone before its record is
/// opened is `NotFound`; one that exits while its record is read fails the
/// read with `ESRCH` (proc_pid_stat reads a released task): both are its
/// disappearance.
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
        Err(error)
            if error.kind() == std::io::ErrorKind::NotFound
                || error.raw_os_error() == Some(libc::ESRCH) =>
        {
            Ok(None)
        }
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
        scratch.executable(
            "tests/workload.sh",
            &std::fs::read_to_string(tests().join("workload.sh")).unwrap(),
        );
        scratch.executable("tests/hold.sh", HOLDING_GATE);
        let mut command = Command::new("bash");
        command
            .arg("tests/hold.sh")
            .current_dir(&scratch.0)
            .env_remove("DCBOR_GATE_SUPERVISOR")
            .env_remove("DCBOR_GATE_MEMORY")
            .env_remove("DCBOR_GATE_WORKLOAD")
            .env_remove("HOLD_ALLOCATE")
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

/// A gate's workload runs confined (tests/gate-common.sh,
/// `gate_confinement`; tests/workload.sh): in a transient scope of its own,
/// apart from the gate's own cgroup, capped at `DCBOR_GATE_MEMORY` with no
/// swap. A workload growing past the cap is killed by the kernel among the
/// workload scope's processes alone, so the gate, outside that scope, runs
/// to its end whatever the kernel chooses inside it. The kill is observed
/// from outside: the kernel's `oom_kill` count of the workload's scope,
/// kept by a holder process the workload leaves in it, is read at 1 where
/// the workload read 0 before growing. The scope's `OOMPolicy` is read, not
/// observed: systemd applies it after the fact and under `continue` records
/// nothing; it only keeps systemd from ending the rest of the workload's
/// tree, every process of which remains an eligible victim.
#[test]
fn a_gate_survives_its_workload_killed_for_memory() {
    const CAP: u64 = 64 << 20;
    let scratch = Scratch::new("process-group-confined");
    let mut gate = HoldingGate::start(
        &scratch,
        &[("DCBOR_GATE_MEMORY", "64M"), ("HOLD_ALLOCATE", "1")],
    );
    let pids = gate.started(4);
    let leader = pids[0];
    let allocated = scratch.0.join("allocated");
    let deadline = Instant::now() + Duration::from_secs(30);
    let grown = loop {
        match std::fs::read_to_string(&allocated) {
            Ok(text) if text.ends_with('\n') => break text.trim().to_string(),
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => panic!("read {}: {error}", allocated.display()),
        }
        let status = gate.supervisor.try_wait().unwrap();
        assert!(
            status.is_none() && Instant::now() < deadline,
            "a gate whose workload exceeded its memory cap did not run to its end: {status:?}"
        );
        std::thread::sleep(Duration::from_millis(50));
    };
    let membership = std::fs::read_to_string(format!("/proc/{leader}/cgroup"))
        .expect("read the gate's cgroup membership");
    let own = membership
        .trim()
        .strip_prefix("0::")
        .expect("a cgroup v2 membership");
    let report = std::fs::read_to_string(scratch.0.join("confinement"))
        .expect("the workload reported its confinement");
    let lines: Vec<&str> = report.lines().collect();
    let [scope, max, swap, policy, before] = lines[..] else {
        panic!("the workload reported {report:?}");
    };
    assert!(
        scope != own && scope.ends_with(".scope"),
        "a gate's workload ran in the gate's own cgroup {own}: {scope}"
    );
    assert_eq!(
        max,
        CAP.to_string(),
        "a gate's workload is not capped at DCBOR_GATE_MEMORY"
    );
    assert_eq!(swap, "0", "a gate's workload may swap");
    assert_eq!(
        policy, "continue",
        "a workload's scope does not continue past an out-of-memory kill"
    );
    // The kernel's own count, read outside the scope while the holder keeps
    // its cgroup: the grown process's SIGKILL was the scope's OOM kill.
    let events = std::fs::read_to_string(format!("/sys/fs/cgroup{scope}/memory.events"))
        .expect("read the workload scope's memory events while its holder keeps it");
    let after: Vec<&str> = events
        .lines()
        .filter(|line| line.starts_with("oom_kill "))
        .collect();
    assert_eq!(
        (before, after.as_slice()),
        ("oom_kill 0", ["oom_kill 1"].as_slice()),
        "the kernel did not kill the grown workload inside its scope for memory"
    );
    assert_eq!(
        grown, "137",
        "a workload past the gate's memory cap was not killed inside its scope"
    );
    let holder = std::fs::read_to_string(scratch.0.join("holder")).unwrap();
    let ended = signal("KILL", holder.trim()).unwrap();
    assert!(ended.success(), "end the workload scope's holder {holder}");
    std::fs::write(scratch.0.join("release"), "").unwrap();
    let (status, left) = gate.stopped();
    assert!(
        status.is_some_and(|status| status.success()),
        "a gate whose workload exceeded its memory cap did not run to its end: {status:?}"
    );
    assert!(
        left.is_empty(),
        "a gate whose workload was killed left {left:?} of {pids:?} running"
    );
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

/// The control runner's order for a Kani control (tests/controls.sh): its
/// harness is checked on the unmutated copy first, and only a verified
/// baseline lets the diff be planted and the red and green sides run; a
/// baseline that did not verify fails the control by name with neither run.
/// The committed script runs in a scratch repository of one file and one
/// Kani control, its own ownership, confinement, clean-commit check,
/// preflight and copies real; the gate tool, recording each side it is
/// asked to run and failing the baseline as told, and the toolchain are
/// recorders.
#[test]
fn a_kani_control_runs_only_over_a_verified_baseline() {
    const GATE: &str = r#"#!/usr/bin/env bash
printf '%s\n' "$*" >>"$GATE_CALLS"
case "$1" in
unicode-version) echo 17.0.0 ;;
dcbor-draft) echo draft ;;
miri) echo stacked ;;
tree-digest) exec "$REAL_GATE" "$@" ;;
proofs-identity)
	(set -o noclobber && printf '%s\n' /fixture/cargo-kani >"$2") || exit 2
	printf 'kani-launcher\t/fixture/cargo-kani\nkani-version\tcargo-kani 0.0.0-fixture\n'
	;;
control)
	case "$2" in
	list) printf 'x\ttests/data/controls/x.patch\tkani\tkani\tdcbor\t-\tlib\ta::h\t-\tfailed\tp\n' ;;
	run) if [[ "$3" == baseline ]]; then exit "$BASELINE_EXIT"; fi ;;
	evidence) ;;
	*) exit 2 ;;
	esac
	;;
*) exit 2 ;;
esac
"#;
    const RUSTC: &str = "#!/bin/sh\n\
        case \"$*\" in\n\
        -vV) printf 'rustc 0.0.0-fixture\\nhost: fixturehost\\n' ;;\n\
        '--print sysroot') echo /fixture/sysroot ;;\n\
        *) echo rustc 0.0.0-fixture ;;\n\
        esac\n";
    let scratch = Scratch::new("controls-baseline");
    let repo = scratch.0.join("repo");
    let write = |relative: &str, text: &str, mode: u32| {
        let path = repo.join(relative);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, text).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
    };
    for script in ["controls.sh", "gate-common.sh", "workload.sh"] {
        write(
            &format!("tests/{script}"),
            &std::fs::read_to_string(tests().join(script)).unwrap(),
            0o755,
        );
    }
    write(".gitignore", "target/\n", 0o644);
    write("file.txt", "a\nb\nd\n", 0o644);
    write(
        "tests/data/controls/x.patch",
        "--- file.txt\n+++ file.txt\n@@ -1,3 +1,3 @@\n a\n-b\n+c\n d\n",
        0o644,
    );
    write("target/gate-tool/fixturehost/debug/gate", GATE, 0o755);
    scratch.executable("bin/cargo", "#!/bin/sh\nexit 0\n");
    scratch.executable("bin/cargo-kani", "#!/bin/sh\nexit 0\n");
    scratch.executable("bin/rustc", RUSTC);
    let git = |arguments: &[&str]| {
        let status = Command::new("git")
            .arg("-C")
            .arg(&repo)
            .args([
                "-c",
                "user.name=fixture",
                "-c",
                "user.email=fixture@localhost",
            ])
            .args(arguments)
            .stdout(Stdio::null())
            .status()
            .unwrap();
        assert!(status.success(), "git {arguments:?}");
    };
    git(&["init", "-q"]);
    git(&["add", "-A"]);
    git(&["commit", "-q", "-m", "fixture"]);
    let path = format!(
        "{}:{}",
        scratch.0.join("bin").display(),
        std::env::var("PATH").unwrap()
    );
    let run = |baseline: &str| {
        let calls = scratch.0.join(format!("calls-{baseline}"));
        let output = Command::new("bash")
            .args(["tests/controls.sh", "kani"])
            .current_dir(&repo)
            .env("PATH", &path)
            .env("DCBOR_CONFIGURATION", "fixture")
            .env("CONTROL_LOG_DIR", repo.join("target/logs").join(baseline))
            .env("GATE_CALLS", &calls)
            .env("REAL_GATE", env!("CARGO_BIN_EXE_gate"))
            .env("BASELINE_EXIT", baseline)
            .env_remove("DCBOR_GATE_SUPERVISOR")
            .env_remove("DCBOR_GATE_MEMORY")
            .env_remove("DCBOR_GATE_WORKLOAD")
            .stdin(Stdio::null())
            .output()
            .unwrap();
        let recorded = std::fs::read_to_string(&calls).unwrap_or_default();
        let sides: Vec<String> = recorded
            .lines()
            .filter(|line| line.starts_with("control run "))
            .filter_map(|line| line.split_whitespace().nth(2).map(str::to_string))
            .collect();
        let report = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        (output.status, sides, report)
    };
    let (status, sides, report) = run("1");
    assert_eq!(
        sides,
        ["baseline"],
        "a Kani control's red side ran over a baseline that did not verify: {sides:?}\n{report}"
    );
    assert!(
        report
            .contains("FAIL x-kani: the unmutated harness did not verify; the control is not run"),
        "a baseline that did not verify was not named: {report}"
    );
    assert_eq!(status.code(), Some(1), "{report}");
    let (status, sides, report) = run("0");
    assert_eq!(
        sides,
        ["baseline", "red", "green"],
        "a verified baseline was not followed by the control's red and green sides: {report}"
    );
    assert!(
        report.contains("PASS x-kani: the unmutated harness verified"),
        "{report}"
    );
    assert_eq!(status.code(), Some(0), "{report}");
}

/// Budget recording requires exactly one receipt in each phase, including
/// when multiple receipts share libtest's output line. The fixture gate
/// accepts the test outcome so receipt validation is exercised independently.
#[test]
fn budget_recording_requires_one_receipt_in_each_phase() {
    let scratch = Scratch::new("budget-receipts");
    std::fs::copy(
        tests().join("record-evidence.sh"),
        scratch.0.join("tests/record-evidence.sh"),
    )
    .unwrap();
    scratch.executable(
        "tests/gate-common.sh",
        r#"own_process_group() { :; }
gate_prepare() { confined=(); }
gate() {
    case "$1" in
    variants) printf 'std\tfixture\n' ;;
    budgets) printf 'fixture.txt\tstd\tfixture\tone\tfast\twitness\n' ;;
    classify) echo pass ;;
    current) printf 'current\n' >>"$CALLS" ;;
    *) return 2 ;;
    esac
}
"#,
    );
    scratch.executable(
        "bin/cargo",
        r#"#!/usr/bin/env bash
set -euo pipefail
if [[ -v DCBOR_RECORD_BUDGETS ]]; then
    [[ "$DCBOR_RECORD_BUDGETS" == fixture.txt ]] || exit 2
    phase=record
else
    phase=check
fi
printf '%s\n' "$phase" >>"$CALLS"
if [[ "$phase" == "$RECEIPT_PHASE" ]]; then
    printf '%s\n' "$RECEIPT"
else
    printf 'test one ... budget finalized: fixture.txt\n'
fi
"#,
    );
    let path = format!(
        "{}:{}",
        scratch.0.join("bin").display(),
        std::env::var("PATH").unwrap()
    );
    let calls = scratch.0.join("calls");
    for phase in ["record", "check"] {
        for (receipt, accepted) in [
            ("test one ... budget finalized: fixture.txt", true),
            ("test one ... ok", false),
            ("budget finalized: other.txt", false),
            (
                "budget finalized: fixture.txt\nbudget finalized: fixture.txt",
                false,
            ),
            (
                "budget finalized: fixture.txt budget finalized: fixture.txt",
                false,
            ),
            (
                "budget finalized: other.txt budget finalized: fixture.txt",
                false,
            ),
        ] {
            std::fs::write(&calls, "").unwrap();
            let output = Command::new("bash")
                .args(["tests/record-evidence.sh", "record-budgets"])
                .current_dir(&scratch.0)
                .env("PATH", &path)
                .env("TMPDIR", &scratch.0)
                .env("DCBOR_CONFIGURATION", "fixture")
                .env("DCBOR_RIGOR", "fast")
                .env("DCBOR_RECORD_BUDGETS", "inherited-must-be-cleared")
                .env("CALLS", &calls)
                .env("RECEIPT_PHASE", phase)
                .env("RECEIPT", receipt)
                .output()
                .unwrap();
            let report = format!(
                "{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            assert_eq!(
                output.status.success(),
                accepted,
                "{phase}, receipt {receipt:?}: {report}"
            );
            let expected = if accepted || phase == "check" {
                "record\ncurrent\ncheck\n"
            } else {
                "record\n"
            };
            assert_eq!(
                std::fs::read_to_string(&calls).unwrap(),
                expected,
                "{phase}, receipt {receipt:?}: {report}"
            );
            if !accepted {
                assert!(
                    report.contains("expected fixture.txt alone"),
                    "receipt rejected for another reason: {report}"
                );
            }
        }
    }
}

/// Every shell script of the repository's `tests` and `fuzz` directories,
/// by path.
fn scripts() -> Vec<PathBuf> {
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
    scripts
}

/// Every script that sources the gates' common definitions owns its process
/// group: `own_process_group "$@"` on the line after the `source`. A gate
/// that does not leaves every process it started running when it is
/// stopped.
#[test]
fn every_gate_owns_its_process_group() {
    let scripts = scripts();
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

/// A regression check of the gates' workload launches, of limited
/// coverage: each line of a gate, or of the gates' common definitions,
/// holding one of the literal workload spellings below (a cargo test,
/// build, run, Miri or fuzz command, a mutation campaign, a coverage tool)
/// holds the `confined` prefix (tests/gate-common.sh, `gate_confinement`).
/// It parses no shell: another spelling, a program named by a variable, a
/// command split across lines or a second command on a confined line
/// escapes it. The gate tool's classifier argument `gate classify cargo
/// KIND`, which names a kind of run and runs nothing, is not taken for one.
/// The gate tool's runs are confined by `process::Workload`.
#[test]
fn every_gate_workload_is_confined() {
    const WORKLOADS: [&str; 9] = [
        "cargo test",
        "cargo build",
        "cargo run",
        "cargo miri",
        "cargo fuzz build",
        "cargo fuzz run",
        "cargo-mutants mutants",
        "llvm-profdata\" merge",
        "llvm-cov\" export",
    ];
    let mut checked = 0;
    let mut unconfined = Vec::new();
    for path in scripts() {
        let text = std::fs::read_to_string(&path).unwrap();
        let common = path.ends_with("tests/gate-common.sh");
        if !common
            && !text
                .lines()
                .any(|line| line.trim() == "source tests/gate-common.sh")
        {
            continue;
        }
        for (index, line) in text.lines().enumerate() {
            let code = line.trim();
            let launched = code.replace("gate classify cargo", "gate classify");
            if code.starts_with('#')
                || !WORKLOADS.iter().any(|workload| launched.contains(workload))
            {
                continue;
            }
            checked += 1;
            if !code.contains("\"${confined[@]}\"") {
                unconfined.push(format!("{}:{}: {code}", path.display(), index + 1));
            }
        }
    }
    assert!(checked > 0, "no gate runs a workload");
    assert!(
        unconfined.is_empty(),
        "gate workloads launched unconfined: {unconfined:#?}"
    );
}
