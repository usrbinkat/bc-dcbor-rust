//! A calibration: its plan validated once, its readiness established, each
//! planned harness checked alone by the one Kani run, every planned
//! execution's outcome recorded as it ends, counted only when the one
//! eligibility authority finds it an independent sample
//! ([`super::eligible_sample`]), and its schedule attempted as its last
//! record whatever failed.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::path::{Path, PathBuf};

use super::{
    CalibrationSample, Clocks, Prerequisites, READINESS_RECORD, RUNTIME_VERSION, RunPurpose,
    SAMPLES, Selection, SettlingPolicy, SystemClocks, WorkloadLock, harnesses, plan, policy,
    ran_sample, readiness, settling_policy,
};

/// How one scheduled calibration execution of one harness ended: a sample,
/// by the one authority, independent of every earlier one and of its
/// harness's envelope; ran, but no sample, with why (a failed or refused
/// verification, an incompatible envelope, a reused run, records that do not
/// hold); its run rejected by its own judgement, with why; withheld, a
/// repetition not run because an earlier execution of the harness was no
/// sample, with why; or never run, the schedule having halted or never
/// begun, with why.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "state", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Observed {
    Sample {
        run: String,
        manifest_sha256: String,
    },
    Ineligible {
        reason: String,
    },
    Rejected {
        error: String,
    },
    Withheld {
        reason: String,
    },
    NotRun {
        reason: String,
    },
}

/// One scheduled execution of a calibration: its harness, its pass (the
/// first observation of every harness is pass 1, each repetition the next),
/// its log, and how it ended.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scheduled {
    pub harness: String,
    pub pass: usize,
    pub log: String,
    pub observed: Observed,
}

/// A calibration's schedule as it ran (`calibration.json`, its last record,
/// attempted whatever failed): the plan's digest and the readiness's, each
/// absent when it was never established; the planned harnesses; every
/// scheduled execution, one per planned harness and pass; the harnesses
/// that did not reach [`SAMPLES`] independent samples; and every fault of
/// the calibration itself, its inputs, its readiness, an execution that
/// could not be scheduled and its own records among them. Complete only
/// when a plan was established, no harness fell short and nothing failed.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Schedule {
    pub version: u64,
    pub plan_sha256: Option<String>,
    pub readiness_sha256: Option<String>,
    pub planned: Vec<String>,
    pub executions: Vec<Scheduled>,
    pub incomplete: BTreeSet<String>,
    pub faults: Vec<String>,
}

impl Schedule {
    pub fn complete(&self) -> bool {
        self.plan_sha256.is_some()
            && self.readiness_sha256.is_some()
            && self.incomplete.is_empty()
            && self.faults.is_empty()
    }
}

/// A calibration's progress (`calibration.jsonl`), owned once it is
/// reserved: created exclusively, held for the whole calibration, each
/// scheduled execution's record appended to it as one JSON line once it
/// ended, and synchronized.
struct Journal {
    path: PathBuf,
    file: std::fs::File,
}

impl Journal {
    /// The journal at `path` reserved, and its directory entry made durable:
    /// the journal owned whenever it was created, whether or not its entry
    /// could be synchronized, beside why not.
    fn reserve(path: &Path) -> (Option<Self>, Result<(), String>) {
        let file = match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
        {
            Ok(file) => file,
            Err(error) => return (None, Err(format!("{}: {error}", path.display()))),
        };
        let synchronized = std::fs::File::open(path.parent().unwrap_or_else(|| Path::new(".")))
            .and_then(|directory| directory.sync_all())
            .map_err(|error| format!("{}: synchronizing its directory: {error}", path.display()));
        (
            Some(Self {
                path: path.to_path_buf(),
                file,
            }),
            synchronized,
        )
    }

    fn record(&mut self, scheduled: &Scheduled) -> Result<(), String> {
        let mut line = serde_json::to_vec(scheduled)
            .map_err(|error| format!("{}: {error}", self.path.display()))?;
        line.push(b'\n');
        self.file
            .write_all(&line)
            .and_then(|()| self.file.sync_data())
            .map_err(|error| format!("{}: {error}", self.path.display()))
    }
}

/// What a calibration is asked to run: in the copy `root` of the commit
/// `logs/commit.txt` names, the plan at `plan`, built into `target_dir`, its
/// records under `logs`, the run's selected `launcher`, holding the
/// checkout's workload lock at `workload_lock` ([`super::WORKLOAD_LOCK`]).
/// No planted-control run is a prerequisite: a calibration measures the
/// implementation alone.
#[derive(Clone, Copy, Debug)]
pub struct CalibrationRequest<'a> {
    pub root: &'a Path,
    pub plan: &'a Path,
    pub target_dir: &'a Path,
    pub logs: &'a Path,
    pub launcher: &'a Path,
    pub workload_lock: &'a Path,
}

/// What a calibration runs under, each at the boundary that consumes it: the
/// workload launcher its Kani runs are confined by, the settling policy, the
/// system's load readings, its clocks, and the writer of its last record
/// (`calibration.json`, `crate::process::create_evidence` in operation).
pub struct Runtime<'a> {
    pub workload: &'a crate::process::Workload,
    pub settling: &'a SettlingPolicy,
    pub sample: &'a mut dyn FnMut() -> Result<String, String>,
    pub clocks: &'a mut dyn Clocks,
    pub record: &'a RecordWriter<'a>,
}

/// A writer of one new record: the path and its bytes, refused when it
/// cannot be created and made durable (`crate::process::create_evidence`).
pub type RecordWriter<'a> = dyn Fn(&Path, &[u8]) -> Result<(), String> + 'a;

/// A calibration ([`calibration`]) under the system's load, its clocks and
/// the exported workload.
pub fn calibrate(request: CalibrationRequest<'_>) -> Result<Schedule, String> {
    calibration(
        request,
        Runtime {
            workload: &crate::process::Workload::exported()?,
            settling: &settling_policy(),
            sample: &mut || {
                std::fs::read_to_string("/proc/loadavg")
                    .map_err(|error| format!("/proc/loadavg: {error}"))
            },
            clocks: &mut SystemClocks::new(),
            record: &crate::process::create_evidence,
        },
    )
}

/// A calibration: the checkout's workload lock acquired
/// ([`WorkloadLock::acquire`]) and held until its last record is written, so
/// no other gate workload starts before the calibration has ended; its
/// schedule built by `schedule`; then the schedule attempted as its last
/// record (`calibration.json`) whatever failed, a failure to write it joining
/// the calibration's faults. The schedule when nothing failed, complete or
/// not; otherwise every fault, the record kept naming them.
pub fn calibration(
    request: CalibrationRequest<'_>,
    mut runtime: Runtime<'_>,
) -> Result<Schedule, String> {
    let lock = WorkloadLock::acquire(request.workload_lock);
    let mut built = Schedule {
        version: RUNTIME_VERSION,
        plan_sha256: None,
        readiness_sha256: None,
        planned: Vec::new(),
        executions: Vec::new(),
        incomplete: BTreeSet::new(),
        faults: Vec::new(),
    };
    schedule(request, &lock, &mut runtime, &mut built);
    built.incomplete = built
        .planned
        .iter()
        .filter(|harness| {
            built
                .executions
                .iter()
                .filter(|scheduled| {
                    scheduled.harness == **harness
                        && matches!(scheduled.observed, Observed::Sample { .. })
                })
                .count()
                != SAMPLES
        })
        .cloned()
        .collect();
    let path = request.logs.join("calibration.json");
    let written = serde_json::to_vec_pretty(&built)
        .map_err(|error| format!("{}: {error}", path.display()))
        .and_then(|encoded| (runtime.record)(&path, &encoded));
    drop(lock);
    let mut faults = built.faults.clone();
    if let Err(error) = written {
        faults.push(format!(
            "the calibration's schedule was not written: {error}"
        ));
    }
    if faults.is_empty() {
        Ok(built)
    } else {
        Err(faults.join("; "))
    }
}

/// The schedule of a calibration, built into `built`, every failure pushed
/// to its faults rather than returned: the census, the policy and the plan
/// validated once, the plan's harnesses recorded as planned; readiness
/// established before any run ([`readiness`]), its failure recording every
/// planned execution as never run; the journal reserved, its failure halting
/// the schedule; then each planned harness, in the plan's order, checked
/// alone by one invocation of the one Kani run (`process::kani`), its log
/// `LOGS/calibration/HARNESS.PASS.log` and its evidence beside it. Two
/// passes: the first observes every harness once; the second repeats, to
/// [`SAMPLES`] executions in all, only a harness whose every execution was
/// a sample by the one authority ([`super::eligible_sample`]) of a run and
/// manifest no earlier execution of the calibration was, in its harness's
/// envelope by [`CalibrationSample::compatible`] against every earlier
/// sample of it. An execution that could not be scheduled (no evidence was
/// created), or a progress record that could not be written, halts the
/// schedule, its cause a fault and every execution after it recorded as
/// never run. Nothing is retried. The workload lock is the calibration's
/// own ([`calibration`]), its acquisition's failure a readiness failure.
fn schedule(
    request: CalibrationRequest<'_>,
    lock: &Result<WorkloadLock, String>,
    runtime: &mut Runtime<'_>,
    built: &mut Schedule,
) {
    let CalibrationRequest {
        root,
        plan: plan_path,
        target_dir,
        logs,
        launcher,
        ..
    } = request;
    let workload = runtime.workload;
    let inputs = (|| {
        let declared = harnesses(&root.join("src"))?;
        policy(root, &declared)?;
        let plan = plan(plan_path, &declared)?;
        Ok::<_, String>((declared, plan))
    })();
    let (declared, plan) = match inputs {
        Ok(inputs) => inputs,
        Err(fault) => {
            built
                .faults
                .push(format!("the calibration has no plan: {fault}"));
            return;
        }
    };
    built.plan_sha256 = Some(plan.sha256.clone());
    built.planned = plan.deadlines.keys().cloned().collect();
    let directory = logs.join("calibration");
    let log_of = |harness: &str, pass: usize| {
        directory.join(format!("{}.{pass}.log", harness.replace("::", ".")))
    };
    let never_run = |built: &mut Schedule, reason: &str| {
        for pass in 1..=SAMPLES {
            for harness in built.planned.clone() {
                built.executions.push(Scheduled {
                    log: log_of(&harness, pass).display().to_string(),
                    harness,
                    pass,
                    observed: Observed::NotRun {
                        reason: reason.to_string(),
                    },
                });
            }
        }
    };
    // No other gate workload runs while this calibration does: the lock is
    // held until its last record is written ([`calibration`]).
    let ready = lock.as_ref().map_err(Clone::clone).and_then(|lock| {
        let commit = std::fs::read_to_string(logs.join("commit.txt"))
            .map_err(|error| format!("{}: {error}", logs.join("commit.txt").display()))?;
        readiness(
            &logs.join(READINESS_RECORD),
            &Prerequisites {
                commit: commit.trim(),
                lock,
            },
            runtime.settling,
            runtime.sample,
            runtime.clocks,
        )
    });
    let ready = match ready {
        Ok(ready) => ready,
        Err(fault) => {
            never_run(built, &format!("the calibration is not ready: {fault}"));
            built.faults.push(fault);
            return;
        }
    };
    built.readiness_sha256 = Some(ready.sha256.clone());
    let (mut journal, reserved) = Journal::reserve(&logs.join("calibration.jsonl"));
    let mut halted: Option<String> = None;
    if let Err(fault) = reserved {
        halted = Some(format!(
            "the calibration's progress cannot be recorded: {fault}"
        ));
        built.faults.push(fault);
    }
    if halted.is_none()
        && let Err(error) = std::fs::create_dir(&directory)
    {
        let fault = format!("{}: {error}", directory.display());
        halted = Some(fault.clone());
        built.faults.push(fault);
    }
    let purpose = RunPurpose::Calibration { plan, ready };
    // Every sample of the calibration so far, by harness, and every run and
    // manifest any execution of it was; why a harness may no longer be
    // repeated.
    let mut samples: BTreeMap<String, Vec<CalibrationSample>> = BTreeMap::new();
    let mut seen_runs: BTreeSet<String> = BTreeSet::new();
    let mut seen_manifests: BTreeSet<String> = BTreeSet::new();
    let mut withheld: BTreeMap<String, String> = BTreeMap::new();
    for pass in 1..=SAMPLES {
        for harness in built.planned.clone() {
            let log = log_of(&harness, pass);
            let observed = if let Some(reason) = &halted {
                Observed::NotRun {
                    reason: reason.clone(),
                }
            } else if let Some(reason) = withheld.get(&harness) {
                Observed::Withheld {
                    reason: reason.clone(),
                }
            } else {
                let selection = Selection::one(&harness);
                let ran = crate::process::KaniRequest {
                    root,
                    purpose: &purpose,
                    selection: &selection,
                    declared: &declared,
                    target_dir,
                    launcher,
                    workload,
                    log: &log,
                }
                .validate()
                .and_then(crate::process::execute_kani);
                let observed = match ran {
                    Err(error) => Observed::Rejected { error },
                    Ok(_) => match ran_sample(&log, &declared) {
                        Err(reason) => Observed::Ineligible { reason },
                        Ok(sample) => {
                            let independent = if sample.harness() != harness {
                                Err(format!(
                                    "run {} is a sample of {}, not of {harness}",
                                    sample.run(),
                                    sample.harness()
                                ))
                            } else if !seen_runs.insert(sample.run().to_string())
                                || !seen_manifests.insert(sample.manifest_sha256().to_string())
                            {
                                Err(format!(
                                    "run {} (manifest {}) is one an earlier execution of the \
                                     calibration was",
                                    sample.run(),
                                    sample.manifest_sha256()
                                ))
                            } else {
                                samples
                                    .get(&harness)
                                    .into_iter()
                                    .flatten()
                                    .try_for_each(|earlier| earlier.compatible(&sample))
                            };
                            match independent {
                                Err(reason) => Observed::Ineligible { reason },
                                Ok(()) => {
                                    let observed = Observed::Sample {
                                        run: sample.run().to_string(),
                                        manifest_sha256: sample.manifest_sha256().to_string(),
                                    };
                                    samples.entry(harness.clone()).or_default().push(sample);
                                    observed
                                }
                            }
                        }
                    },
                };
                if !matches!(observed, Observed::Sample { .. }) {
                    withheld.insert(
                        harness.clone(),
                        format!("pass {pass} of {harness} was {observed:?}"),
                    );
                }
                // A run that left no evidence directory could not be
                // scheduled: the schedule halts there, its cause a fault.
                let evidence = log.with_extension("evidence");
                let scheduled = match std::fs::symlink_metadata(&evidence) {
                    Ok(metadata) if metadata.is_dir() => Ok(()),
                    Ok(_) => Err(format!("{}: not a directory", evidence.display())),
                    Err(error) => Err(format!("{}: {error}", evidence.display())),
                };
                if let Err(missing) = scheduled {
                    let fault = match &observed {
                        Observed::Rejected { error } => {
                            format!("pass {pass} of {harness} could not be scheduled: {error}")
                        }
                        _ => format!("pass {pass} of {harness} created no evidence: {missing}"),
                    };
                    halted = Some(fault.clone());
                    built.faults.push(fault);
                }
                observed
            };
            let scheduled = Scheduled {
                harness: harness.clone(),
                pass,
                log: log.display().to_string(),
                observed,
            };
            // A progress record that cannot be written halts the schedule:
            // every execution after it is recorded as never run in the
            // schedule, though the journal holds none of them.
            if let Some(open) = journal.as_mut()
                && let Err(fault) = open.record(&scheduled)
            {
                halted.get_or_insert_with(|| {
                    format!("the calibration's progress was not recorded: {fault}")
                });
                built.faults.push(fault);
                journal = None;
            }
            built.executions.push(scheduled);
        }
    }
}
