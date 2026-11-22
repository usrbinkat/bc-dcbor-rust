//! A calibration's readiness: the control runs it follows, each complete
//! against the registry; no other gate workload running (the workload lock
//! held); the settling of the system it waited on; and the one validator of
//! the receipt ([`Readiness::validate`]), which the live calibration and every
//! reader of a kept receipt apply alike, recomputing every control run from
//! the registry and verdict bytes the receipt retains.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use super::{Instant, RUNTIME_VERSION, Ready, strict_json, typed};
use crate::controls::{ControlResult, Registry, Runner};

/// The control runs a calibration must follow, each by its channel and the
/// runners it ran: the native controls of the nightly and the stable
/// toolchains. The Kani controls are not among them, since they run under
/// the predictions a calibration produces; the Miri controls are obligations
/// of their own, not this prerequisite.
pub const REQUIRED_CONTROLS: &[(&str, &[&str])] =
    &[("nightly", &["native"]), ("stable", &["native"])];

/// The lock every gate workload holds exclusively while it runs, relative to
/// the checkout (`tests/controls.sh`, `tests/proofs.sh`, and a calibration's
/// own [`WorkloadLock`]): a calibration that holds it has no control run or
/// proof run of this checkout competing with it.
pub const WORKLOAD_LOCK: &str = "target/gate-workload.lock";

/// The workload lock ([`WORKLOAD_LOCK`]) held exclusively by this
/// calibration for as long as the value lives, and when it was acquired:
/// acquired without waiting, refused when any other gate workload holds it.
pub struct WorkloadLock {
    path: PathBuf,
    acquired: Instant,
    _file: std::fs::File,
}

impl WorkloadLock {
    pub fn acquire(path: &Path) -> Result<Self, String> {
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)
            .map_err(|error| format!("{}: {error}", path.display()))?;
        match file.try_lock() {
            Ok(()) => Ok(Self {
                path: path.to_path_buf(),
                acquired: super::now()?,
                _file: file,
            }),
            Err(std::fs::TryLockError::WouldBlock) => Err(format!(
                "{}: another gate workload holds it: a control run or a proof run is still \
                 running",
                path.display()
            )),
            Err(std::fs::TryLockError::Error(error)) => Err(format!("{}: {error}", path.display())),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn acquired(&self) -> Instant {
        self.acquired
    }
}

/// The workload lock a readiness was established under, as the gate records
/// it: its path and when the calibration acquired it. The record is the
/// gate's attestation; what it is checked against is the order of the
/// records around it ([`Readiness::validate`]): every control run finished
/// before it was acquired, and it was acquired before settling began.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LockRecord {
    pub path: String,
    pub acquired: Instant,
}

/// The operational policy a calibration waits on before its first run, after
/// the control runs that preceded it: the system's load read every
/// `interval_milliseconds` at least (`/proc/loadavg`), settled once
/// `consecutive` readings in a row each show at most `max_running` runnable
/// tasks and a one-minute load of at most `max_load1_hundredths`
/// hundredths and together span at least `min_span_milliseconds` of the
/// monotonic clock; refused when `limit` readings pass without it. A declared
/// criterion with its justification; meeting it does not establish that
/// nothing else contends.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SettlingPolicy {
    pub interval_milliseconds: u64,
    pub consecutive: usize,
    pub min_span_milliseconds: u64,
    pub limit: usize,
    pub max_running: u64,
    pub max_load1_hundredths: u64,
    pub justification: String,
}

/// The one settling policy of a calibration ([`SettlingPolicy`]): seven
/// readings at least five seconds apart, spanning at least thirty seconds.
pub fn settling_policy() -> SettlingPolicy {
    SettlingPolicy {
        interval_milliseconds: 5_000,
        consecutive: 7,
        min_span_milliseconds: 30_000,
        limit: 180,
        max_running: 2,
        max_load1_hundredths: 100,
        justification: "a calibration's harness is one solver process; a run queue of at most \
                        the sampler and one other task and a one-minute load of at most 1.00, \
                        held over seven readings spanning at least thirty seconds, is the \
                        operational criterion that the control runs' workload has decayed; \
                        fifteen minutes without it refuses the calibration"
            .to_string(),
    }
}

impl SettlingPolicy {
    /// Whether the policy can establish anything: a positive interval, at
    /// least two consecutive readings (one reading spans no time), an attempt
    /// limit no smaller than them, a positive minimum span no longer than
    /// its consecutive readings span when each follows the one before it by
    /// the interval [`settle`] waits, and a justification. Its arithmetic is
    /// checked, never saturated.
    pub fn validate(&self) -> Result<(), String> {
        let fault = |what: &str| {
            Err(format!(
                "a settling policy of {} consecutive readings {} ms apart spanning {} ms within \
                 {}, justified {:?}, establishes nothing: {what}",
                self.consecutive,
                self.interval_milliseconds,
                self.min_span_milliseconds,
                self.limit,
                self.justification
            ))
        };
        if self.interval_milliseconds == 0 {
            return fault("no interval");
        }
        if self.consecutive < 2 {
            return fault("fewer than two consecutive readings span no time");
        }
        if self.limit < self.consecutive {
            return fault("its limit is below its consecutive readings");
        }
        if self.min_span_milliseconds == 0 {
            return fault("no minimum span");
        }
        let spanned = u64::try_from(self.consecutive - 1)
            .ok()
            .and_then(|gaps| gaps.checked_mul(self.interval_milliseconds));
        match spanned {
            None => return fault("its consecutive readings' span does not fit in u64"),
            Some(spanned) if spanned < self.min_span_milliseconds => {
                return fault(
                    "its consecutive readings, an interval apart, cannot span its minimum span",
                );
            }
            Some(_) => {}
        }
        if self.justification.trim().is_empty() {
            return fault("no justification");
        }
        Ok(())
    }
}

/// One reading of the system's load while a calibration settles: when it was
/// taken, by the wall clock and as milliseconds of the monotonic clock since
/// settling began, `/proc/loadavg` as read, its one-minute load in
/// hundredths and its runnable tasks, and whether it is within the policy.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Settled {
    pub at: Instant,
    pub monotonic_milliseconds: u64,
    pub loadavg: String,
    pub load1_hundredths: u64,
    pub running: u64,
    pub within: bool,
}

/// The clocks and the waiting a calibration's settling reads, given by its
/// caller: the system's in operation ([`SystemClocks`]), a test's own in a
/// test.
pub trait Clocks {
    /// The wall clock now.
    fn now(&mut self) -> Result<Instant, String>;
    /// The monotonic clock's milliseconds since its first reading.
    fn monotonic_milliseconds(&mut self) -> Result<u64, String>;
    /// Wait about `duration`.
    fn wait(&mut self, duration: std::time::Duration);
}

/// The system's clocks: the wall clock, the monotonic clock from when the
/// value was made, and a sleep.
pub struct SystemClocks(std::time::Instant);

impl SystemClocks {
    pub fn new() -> Self {
        Self(std::time::Instant::now())
    }
}

impl Default for SystemClocks {
    fn default() -> Self {
        Self::new()
    }
}

impl Clocks for SystemClocks {
    fn now(&mut self) -> Result<Instant, String> {
        super::now()
    }

    fn monotonic_milliseconds(&mut self) -> Result<u64, String> {
        u64::try_from(self.0.elapsed().as_millis())
            .map_err(|_| "the monotonic clock's milliseconds do not fit in u64".to_string())
    }

    fn wait(&mut self, duration: std::time::Duration) {
        std::thread::sleep(duration);
    }
}

/// The one-minute load in hundredths and the runnable tasks of a
/// `/proc/loadavg` reading (`0.52 0.58 0.59 1/1234 5678`).
fn loadavg_of(text: &str) -> Result<(u64, u64), String> {
    let fields: Vec<&str> = text.split_whitespace().collect();
    let malformed = || format!("not a /proc/loadavg reading: {text:?}");
    let [load1, _, _, tasks, _] = fields[..] else {
        return Err(malformed());
    };
    let (whole, fraction) = load1.split_once('.').ok_or_else(malformed)?;
    if fraction.len() != 2 {
        return Err(malformed());
    }
    let hundredths = whole
        .parse::<u64>()
        .ok()
        .and_then(|whole| whole.checked_mul(100))
        .zip(fraction.parse::<u64>().ok())
        .and_then(|(whole, fraction)| whole.checked_add(fraction))
        .ok_or_else(malformed)?;
    let running = tasks
        .split_once('/')
        .and_then(|(running, _)| running.parse::<u64>().ok())
        .ok_or_else(malformed)?;
    Ok((hundredths, running))
}

/// The one evaluation of a settling's readings under `policy`, whether they
/// were just taken or read back from a receipt: every reading's load and run
/// queue re-read from its `/proc/loadavg` text and its verdict recomputed,
/// every reading at least the policy's interval after the one before it on
/// the monotonic clock; then the index of the first reading that ends a
/// window of `consecutive` readings all within the policy and spanning at
/// least its minimum span, or none. Refused naming the first reading that
/// does not hold.
fn settled_at(policy: &SettlingPolicy, observations: &[Settled]) -> Result<Option<usize>, String> {
    for (at, reading) in observations.iter().enumerate() {
        let (load1_hundredths, running) = loadavg_of(&reading.loadavg)?;
        let within =
            load1_hundredths <= policy.max_load1_hundredths && running <= policy.max_running;
        if (load1_hundredths, running, within)
            != (reading.load1_hundredths, reading.running, reading.within)
        {
            return Err(format!(
                "reading {at} records load {} hundredths, {} runnable, within {}, its \
                 /proc/loadavg {:?} reads {load1_hundredths}, {running}, {within}",
                reading.load1_hundredths, reading.running, reading.within, reading.loadavg
            ));
        }
        if at > 0 {
            let previous = observations[at - 1].monotonic_milliseconds;
            let due = previous
                .checked_add(policy.interval_milliseconds)
                .ok_or("the monotonic clock's interval does not fit in u64")?;
            if reading.monotonic_milliseconds < due {
                return Err(format!(
                    "reading {at} came {} ms after the one before it, the policy's interval is \
                     {} ms",
                    reading.monotonic_milliseconds.saturating_sub(previous),
                    policy.interval_milliseconds
                ));
            }
        }
        if at + 1 >= policy.consecutive {
            let window = &observations[at + 1 - policy.consecutive..=at];
            let span = reading
                .monotonic_milliseconds
                .checked_sub(window[0].monotonic_milliseconds)
                .ok_or("the monotonic clock went backwards")?;
            if window.iter().all(|settled| settled.within) && span >= policy.min_span_milliseconds {
                return Ok(Some(at));
            }
        }
    }
    Ok(None)
}

/// The settling of the system under `policy` ([`SettlingPolicy::validate`]
/// first): readings from `sample`, each timed by `clocks`, the policy's
/// interval waited between them, until the readings settle
/// ([`settled_at`], the one evaluation), or `limit` have been read, or a
/// reading cannot be taken or does not hold. Every reading taken, and
/// whether it settled.
pub fn settle(
    policy: &SettlingPolicy,
    sample: &mut dyn FnMut() -> Result<String, String>,
    clocks: &mut dyn Clocks,
) -> (Vec<Settled>, Result<(), String>) {
    let mut observations: Vec<Settled> = Vec::new();
    if let Err(fault) = policy.validate() {
        return (observations, Err(fault));
    }
    while observations.len() < policy.limit {
        if !observations.is_empty() {
            clocks.wait(std::time::Duration::from_millis(
                policy.interval_milliseconds,
            ));
        }
        let reading = sample().and_then(|loadavg| {
            let (load1_hundredths, running) = loadavg_of(&loadavg)?;
            Ok(Settled {
                at: clocks.now()?,
                monotonic_milliseconds: clocks.monotonic_milliseconds()?,
                within: load1_hundredths <= policy.max_load1_hundredths
                    && running <= policy.max_running,
                loadavg: loadavg.trim().to_string(),
                load1_hundredths,
                running,
            })
        });
        match reading {
            Ok(settled) => observations.push(settled),
            Err(fault) => return (observations, Err(format!("a load reading failed: {fault}"))),
        }
        match settled_at(policy, &observations) {
            Err(fault) => return (observations, Err(fault)),
            Ok(Some(_)) => return (observations, Ok(())),
            Ok(None) => {}
        }
    }
    let count = observations.len();
    (
        observations,
        Err(format!(
            "the system did not settle within {count} readings: {} consecutive within {} \
             hundredths of load and {} runnable tasks, spanning {} ms, were required",
            policy.consecutive,
            policy.max_load1_hundredths,
            policy.max_running,
            policy.min_span_milliseconds
        )),
    )
}

/// A control run's final record, as `gate control evidence` writes it once
/// every selected control of its channel and runners was judged: the
/// registry's identity (the digest of `controls.tsv`'s bytes), every
/// selected control's result in the registry's order, every fault, and when
/// it was written, the run's last act before its runner released the
/// workload lock.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlVerdict {
    pub version: u64,
    pub channel: String,
    pub runners: Vec<String>,
    pub commit: String,
    pub identity: String,
    pub registry_sha256: String,
    pub results: Vec<ControlResult>,
    pub faults: Vec<String>,
    pub finished: Instant,
}

/// The final record of the control run of `channel` under `runners` whose
/// logs are `logs`, of the copy `root`: the registry read once
/// ([`crate::controls::registry`]), every selected control's result judged
/// from its evidence ([`crate::controls::evidence`]), the run's commit and
/// identity as its runner recorded them, every fault, a run that selected
/// nothing among them, and the time it was made. The one maker of the record
/// [`control_run`] reads (`gate control evidence`).
pub fn control_verdict(
    root: &Path,
    logs: &Path,
    channel: &str,
    runners: &[&str],
) -> Result<ControlVerdict, String> {
    let parsed: Vec<Runner> = runners
        .iter()
        .map(|runner| Runner::parse(runner).ok_or_else(|| Runner::unknown(runner)))
        .collect::<Result<_, _>>()?;
    let registry = crate::controls::registry(root)?;
    let results = crate::controls::evidence(&registry.controls, logs, channel, &parsed);
    let mut faults = crate::controls::faults(&results);
    if results.is_empty() {
        faults.push(format!(
            "no control of one test runs under {channel} with the runners {runners:?}"
        ));
    }
    let recorded = |file: &str| {
        std::fs::read_to_string(logs.join(file))
            .map(|text| text.trim().to_string())
            .map_err(|error| format!("{}: {error}", logs.join(file).display()))
    };
    Ok(ControlVerdict {
        version: RUNTIME_VERSION,
        channel: channel.to_string(),
        runners: runners.iter().map(|runner| runner.to_string()).collect(),
        commit: recorded("commit.txt")?,
        identity: recorded("identity.txt")?,
        registry_sha256: registry.sha256,
        results,
        faults,
        finished: super::now()?,
    })
}

/// A control run a calibration follows ([`verified_run`], its only maker):
/// its logs (provenance), and its final record's text as read (`verdict`)
/// with its digest, and every fact of it the readiness relies on, each as
/// that text records it: its identity, commit, channel and runners, the
/// registry it ran, every selected control's result, and when it finished.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlRun {
    pub logs: String,
    pub identity: String,
    pub commit: String,
    pub channel: String,
    pub runners: Vec<String>,
    pub registry_sha256: String,
    pub results: Vec<ControlResult>,
    pub finished: Instant,
    pub verdict: String,
    pub verdict_sha256: String,
}

impl ControlRun {
    /// Whether the run's own record establishes a completed, passed run:
    /// an identity; a registry and a verdict digest; at least one result,
    /// each of a control named once under one of the run's runners, and
    /// every one passed.
    fn complete(&self) -> Result<(), String> {
        let fault = |what: String| {
            Err(format!(
                "the {} control run {} {what}",
                self.channel, self.identity
            ))
        };
        if self.identity.trim().is_empty() {
            return fault("names no identity".to_string());
        }
        if !super::sha256_text(&self.registry_sha256) || !super::sha256_text(&self.verdict_sha256) {
            return fault("records no registry or verdict digest".to_string());
        }
        if self.results.is_empty() {
            return fault("judged no control".to_string());
        }
        let mut named = BTreeSet::new();
        for result in &self.results {
            if !named.insert((result.control.as_str(), result.runner.as_str())) {
                return fault(format!(
                    "judged {} under {} twice",
                    result.control, result.runner
                ));
            }
            if !self.runners.contains(&result.runner) {
                return fault(format!(
                    "judged {} under {}, which it did not run",
                    result.control, result.runner
                ));
            }
            if !result.faults.is_empty() {
                return fault(format!(
                    "did not pass {} under {}: {:?}",
                    result.control, result.runner, result.faults
                ));
            }
        }
        Ok(())
    }
}

/// The one validation of a control run's final record, live or retained:
/// `verdict` (its text, the logs at `logs` naming its run) read and digested
/// from those bytes, of [`RUNTIME_VERSION`], naming the run's `identity`, of
/// `commit` when one is given, of the `registry`'s digest; its results
/// exactly the registry's selection for its channel and runners
/// ([`crate::controls::selected`]), in order; its faults exactly its
/// results' faults, and none; complete ([`ControlRun::complete`]).
fn verified_run(
    logs: String,
    verdict: &str,
    identity: &str,
    commit: Option<&str>,
    registry: &Registry,
) -> Result<ControlRun, String> {
    let fail = |what: String| Err(format!("{logs}/verdict.json: {what}"));
    let verdict_sha256 = crate::process::sha256_bytes(verdict.as_bytes())?;
    let record: ControlVerdict = typed(
        strict_json(verdict.as_bytes()).map_err(|fault| format!("{logs}/verdict.json: {fault}"))?,
        "verdict.json",
    )?;
    if record.version != RUNTIME_VERSION {
        return fail(format!("is of version {}", record.version));
    }
    if record.identity != identity {
        return fail(format!(
            "names the identity {}, the run's is {identity}",
            record.identity
        ));
    }
    if let Some(commit) = commit
        && record.commit != commit
    {
        return fail(format!(
            "is of commit {}, the calibration's is {commit}",
            record.commit
        ));
    }
    if record.registry_sha256 != registry.sha256 {
        return fail(format!(
            "ran the registry {}, the calibration's is {}",
            record.registry_sha256, registry.sha256
        ));
    }
    let runners: Vec<Runner> = record
        .runners
        .iter()
        .map(|runner| Runner::parse(runner).ok_or_else(|| Runner::unknown(runner)))
        .collect::<Result<_, _>>()?;
    let expected: Vec<(&str, &str)> =
        crate::controls::selected(&registry.controls, &record.channel, &runners)
            .into_iter()
            .map(|control| (control.name.as_str(), control.runner.name()))
            .collect();
    let judged: Vec<(&str, &str)> = record
        .results
        .iter()
        .map(|result| (result.control.as_str(), result.runner.as_str()))
        .collect();
    if judged != expected {
        return fail(format!(
            "judged {judged:?}, the registry selects {expected:?} for {} under {:?}",
            record.channel, record.runners
        ));
    }
    if record.faults != crate::controls::faults(&record.results) || !record.faults.is_empty() {
        return fail(format!(
            "records the faults {:?}: the control run did not pass",
            record.faults
        ));
    }
    let run = ControlRun {
        logs,
        identity: record.identity,
        commit: record.commit,
        channel: record.channel,
        runners: record.runners,
        registry_sha256: record.registry_sha256,
        results: record.results,
        finished: record.finished,
        verdict: verdict.to_string(),
        verdict_sha256,
    };
    run.complete()?;
    Ok(run)
}

/// The control run whose logs are `logs`, of `commit`, against the
/// `registry` ([`crate::controls::registry`]): its final record read once
/// and held, with the identity its runner recorded (`identity.txt`), to the
/// one validation ([`verified_run`]). A run unfinished (no final record), of
/// another registry, short of a selected control or failed is refused.
pub fn control_run(logs: &Path, commit: &str, registry: &Registry) -> Result<ControlRun, String> {
    let path = logs.join("verdict.json");
    let bytes = std::fs::read(&path).map_err(|error| {
        format!(
            "{}: {error}: the control run has not finished",
            path.display()
        )
    })?;
    let verdict = String::from_utf8(bytes)
        .map_err(|error| format!("{}: not UTF-8: {error}", path.display()))?;
    let identity_path = logs.join("identity.txt");
    let identity = std::fs::read_to_string(&identity_path)
        .map_err(|error| format!("{}: {error}", identity_path.display()))?;
    verified_run(
        logs.display().to_string(),
        &verdict,
        identity.trim(),
        Some(commit),
        registry,
    )
}

/// A calibration's readiness, preserved before its first run
/// (`readiness.json`): the registry's text the control runs are recomputed
/// against; the control runs it follows, each with its final record's text;
/// the workload lock it held ([`WORKLOAD_LOCK`], [`LockRecord`]); the
/// settling policy, every reading taken under it, and whether the
/// calibration was ready, or why not.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Readiness {
    pub version: u64,
    pub registry: String,
    pub controls: Vec<ControlRun>,
    pub workload_lock: Option<LockRecord>,
    pub policy: SettlingPolicy,
    pub observations: Vec<Settled>,
    pub ready: bool,
    pub error: Option<String>,
}

impl Readiness {
    /// The one validator of a readiness, live or read back from a run's
    /// evidence: of [`RUNTIME_VERSION`]; ready, with no error; every control
    /// run recomputed from the retained registry text and its retained final
    /// record by the one validation ([`verified_run`], of `commit` when
    /// given), and its recorded facts exactly what that record states; its
    /// control runs exactly [`REQUIRED_CONTROLS`], one each, all of one
    /// commit; the workload lock recorded, acquired after every control run
    /// finished and before the first reading; its policy valid
    /// ([`SettlingPolicy::validate`]); and its readings settled by the one
    /// evaluation ([`settled_at`]) at its last reading, within its limit.
    /// Refused naming the first that does not hold: a receipt that only says
    /// it is ready establishes nothing.
    pub fn validate(&self, commit: Option<&str>) -> Result<(), String> {
        let invalid = |what: String| {
            format!(
                "{} is not a valid readiness: {what}",
                super::READINESS_RECORD
            )
        };
        let fault = |what: String| Err(invalid(what));
        if self.version != RUNTIME_VERSION {
            return fault(format!("version {}", self.version));
        }
        if !self.ready || self.error.is_some() {
            return fault(format!("not ready: {:?}", self.error));
        }
        let registry = Registry::of_text(&self.registry).map_err(invalid)?;
        for run in &self.controls {
            let recomputed = verified_run(
                run.logs.clone(),
                &run.verdict,
                &run.identity,
                commit,
                &registry,
            )
            .map_err(invalid)?;
            if recomputed != *run {
                return fault(format!(
                    "the {} control run's recorded facts are not what its verdict records",
                    run.channel
                ));
            }
        }
        let mut scopes: Vec<(&str, Vec<&str>)> = self
            .controls
            .iter()
            .map(|run| {
                (
                    run.channel.as_str(),
                    run.runners.iter().map(String::as_str).collect(),
                )
            })
            .collect();
        scopes.sort();
        let mut required: Vec<(&str, Vec<&str>)> = REQUIRED_CONTROLS
            .iter()
            .map(|(channel, runners)| (*channel, runners.to_vec()))
            .collect();
        required.sort();
        if scopes != required {
            return fault(format!(
                "its control runs are {scopes:?}, a calibration follows exactly {required:?}"
            ));
        }
        let commits: BTreeSet<&str> = self
            .controls
            .iter()
            .map(|run| run.commit.as_str())
            .collect();
        if commits.len() != 1 {
            return fault(format!(
                "its control runs are of the commits {commits:?}, not of one commit"
            ));
        }
        let Some(lock) = self
            .workload_lock
            .as_ref()
            .filter(|lock| lock.path.starts_with('/'))
        else {
            return fault(format!(
                "it held no workload lock ({:?}): a competing gate workload was not excluded",
                self.workload_lock
            ));
        };
        if let Some(running) = self
            .controls
            .iter()
            .find(|run| run.finished > lock.acquired)
        {
            return fault(format!(
                "the {} control run finished at {:?}, after the workload lock was acquired at \
                 {:?}: it was still running",
                running.channel, running.finished, lock.acquired
            ));
        }
        if let Some(first) = self.observations.first()
            && first.at < lock.acquired
        {
            return fault(format!(
                "its workload lock was acquired at {:?}, after its first reading at {:?}",
                lock.acquired, first.at
            ));
        }
        self.policy.validate()?;
        if self.observations.len() > self.policy.limit {
            return fault(format!(
                "{} readings, its policy's limit is {}",
                self.observations.len(),
                self.policy.limit
            ));
        }
        match settled_at(&self.policy, &self.observations)? {
            Some(at) if at + 1 == self.observations.len() => Ok(()),
            found => fault(format!(
                "its {} readings settle at {found:?}, not at its last",
                self.observations.len()
            )),
        }
    }
}

/// What a calibration's readiness is established from: the copy `root`
/// whose registry the control runs must have run, the calibration's
/// `commit`, the control runs' logs `control_logs`, and the workload lock
/// the calibration holds.
pub struct Prerequisites<'a> {
    pub root: &'a Path,
    pub commit: &'a str,
    pub control_logs: &'a [&'a Path],
    pub lock: &'a WorkloadLock,
}

/// The readiness of a calibration ([`Prerequisites`]): every control run
/// established against the copy's registry ([`control_run`]), the system
/// settled under `policy` ([`settle`]), the receipt validated by the one
/// validator ([`Readiness::validate`]), and preserved at `path` whether
/// ready or not, every reading beside why. The receipt's bytes, as
/// preserved, are what every calibration run of it keeps ([`Ready`]). A
/// receipt that cannot be preserved fails the readiness, its own rejection,
/// if any, kept beside the failure to preserve it.
pub fn readiness(
    path: &Path,
    prerequisites: &Prerequisites<'_>,
    policy: &SettlingPolicy,
    sample: &mut dyn FnMut() -> Result<String, String>,
    clocks: &mut dyn Clocks,
) -> Result<Ready, String> {
    let registry = crate::controls::registry(prerequisites.root);
    let controls: Result<Vec<ControlRun>, String> = registry
        .as_ref()
        .map_err(Clone::clone)
        .and_then(|registry| {
            prerequisites
                .control_logs
                .iter()
                .map(|logs| control_run(logs, prerequisites.commit, registry))
                .collect()
        });
    let (controls, observations, mut error) = match controls {
        Err(fault) => (
            Vec::new(),
            Vec::new(),
            Some(format!("no finished, passed control run: {fault}")),
        ),
        Ok(controls) => {
            let (observations, settled) = settle(policy, sample, clocks);
            (controls, observations, settled.err())
        }
    };
    let mut receipt = Readiness {
        version: RUNTIME_VERSION,
        registry: registry.map(|registry| registry.text).unwrap_or_default(),
        controls,
        workload_lock: Some(LockRecord {
            path: prerequisites.lock.path().display().to_string(),
            acquired: prerequisites.lock.acquired(),
        }),
        policy: policy.clone(),
        observations,
        ready: error.is_none(),
        error: error.clone(),
    };
    if error.is_none()
        && let Err(fault) = receipt.validate(Some(prerequisites.commit))
    {
        error = Some(fault);
        receipt.ready = false;
        receipt.error = error.clone();
    }
    let preserved = serde_json::to_vec_pretty(&receipt)
        .map_err(|fault| format!("{}: {fault}", path.display()))
        .and_then(|encoded| crate::process::create_evidence(path, &encoded).map(|()| encoded));
    match (error, preserved) {
        (None, Ok(encoded)) => Ok(Ready {
            sha256: crate::process::sha256_bytes(&encoded)?,
            bytes: encoded,
        }),
        (Some(fault), Ok(_)) => Err(format!(
            "{}: the calibration is not ready: {fault}",
            path.display()
        )),
        (None, Err(unrecorded)) => Err(format!(
            "{}: the readiness was not preserved: {unrecorded}",
            path.display()
        )),
        (Some(fault), Err(unrecorded)) => Err(format!(
            "{}: the calibration is not ready: {fault}; the readiness was not preserved \
             either: {unrecorded}",
            path.display()
        )),
    }
}
