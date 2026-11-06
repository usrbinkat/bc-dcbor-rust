//! The matrix cost evidence (`tests/data/costs`, `tests/support/rigor.rs`
//! `ratchet`): every test target run single-threaded under each layer
//! (fast, exhaustive) for each record variant ([`VARIANTS`]), eight legs,
//! each emitting the digest of every cost record it checked or recorded.
//!
//! A leg's inventory is a record (`records::manifest`): its feature
//! projection, then its digests. Checking compares each leg's inventory with
//! the baseline's and the records with the baseline's records; recording
//! stages every leg's records and publishes them, then the inventories, only
//! after all eight legs and every collision check pass, so a failed leg
//! changes nothing. A completed run's legs are reused, never rerun: resuming
//! a recording reruns only the legs it did not complete, and checking against
//! a completed run launches no cargo at all. Every record must be some
//! matrix's: a record of this configuration no inventory names is removed by
//! a complete recording and fails a check. Another configuration's records
//! and files of no record are never touched.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::records::{self, VARIANTS};

/// What a run does with the cost evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Check,
    Record,
}

impl Action {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Check => "check",
            Self::Record => "record",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        [Self::Check, Self::Record]
            .into_iter()
            .find(|action| action.name() == text)
    }
}

/// The verification layers, each a leg per variant.
pub const LAYERS: [&str; 2] = ["fast", "exhaustive"];

/// The variables a leg never inherits: a cost run must not rewrite the
/// independent trace and tightness baselines, nor run at minimal witness
/// sizes, which record another selection under the same identity.
pub const UNINHERITED: [&str; 4] = [
    "DCBOR_RECORD_FACTORS",
    "DCBOR_RECORD_TRACES",
    "DCBOR_CLASS_COVERAGE",
    "DCBOR_WITNESS",
];

/// The marker each checked or recorded cost record's digest follows in a
/// leg's log.
const MARKER: &str = "DCBOR_COST\t";

/// One leg to run.
#[derive(Debug)]
pub struct Leg<'a> {
    pub action: Action,
    /// The variant's features, comma-separated as `--features` takes them.
    pub features: &'a str,
    pub layer: &'static str,
    /// Where the leg's records are checked or staged.
    pub directory: &'a Path,
    /// Where the leg's output is written.
    pub log: &'a Path,
}

/// A run's request.
#[derive(Clone, Copy, Debug)]
pub struct Request<'a> {
    pub action: Action,
    /// The repository.
    pub root: &'a Path,
    pub configuration: &'a str,
    /// Where a run's log directory is made.
    pub temporary: &'a Path,
    /// The baseline to check against, when not the repository's.
    pub baseline: Option<&'a Path>,
    /// A run to reuse.
    pub resume: Option<&'a Path>,
}

/// What a run reports: its log directory, what it did, and every record of
/// this configuration no matrix produces.
#[derive(Debug)]
pub struct Report {
    pub logs: PathBuf,
    pub notes: Vec<String>,
    pub faults: Vec<String>,
}

fn read(path: &Path) -> Result<String, String> {
    std::fs::read_to_string(path).map_err(|error| format!("{}: {error}", path.display()))
}

fn write(path: &Path, text: &str) -> Result<(), String> {
    std::fs::write(path, text).map_err(|error| format!("{}: {error}", path.display()))
}

fn nonempty(path: &Path) -> bool {
    std::fs::metadata(path).is_ok_and(|metadata| metadata.is_file() && metadata.len() > 0)
}

fn digest(text: &str) -> bool {
    text.len() == 16
        && text
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

/// `path` with `.complete` appended: a leg's inventory as a record.
fn complete(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(".complete");
    PathBuf::from(name)
}

/// A new directory under `temporary` named from `prefix`.
fn fresh(temporary: &Path, prefix: &str) -> Result<PathBuf, String> {
    for attempt in 0_u32.. {
        let path = temporary.join(format!("{prefix}.{}.{attempt}", std::process::id()));
        match std::fs::create_dir(&path) {
            Ok(()) => return Ok(path),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(format!("{}: {error}", path.display())),
        }
    }
    Err(format!("{}: no fresh directory", temporary.display()))
}

/// The digests a leg's `log` names, sorted and distinct.
pub fn observed(log: &str) -> Vec<String> {
    log.lines()
        .filter_map(|line| {
            line.split_once(MARKER)
                .map(|(_, digest)| digest.to_string())
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

/// A baseline inventory at `manifest` of the projection `features`: a
/// current record, its first row the projection, then at least one digest,
/// each a current record of the baseline.
fn check_manifest(
    manifest: &Path,
    baseline: &Path,
    features: &str,
    configuration: &str,
) -> Result<(), String> {
    let shown = manifest.display();
    records::current_file(manifest, configuration)
        .map_err(|fault| fault.describe(manifest, configuration))?;
    let data = read(manifest)?;
    let mut rows = data.lines().skip(1);
    if rows.next() != Some(format!("#\tfeatures\t{features}").as_str()) {
        return Err(format!("{shown}: not the inventory of {features}"));
    }
    let mut count = 0;
    for row in rows {
        if !digest(row) {
            return Err(format!("{shown}: {row:?} is no digest"));
        }
        let record = baseline.join(format!("{row}.txt"));
        if !nonempty(&record) {
            return Err(format!("{row}: missing cost baseline"));
        }
        records::current_file(&record, configuration)
            .map_err(|fault| fault.describe(&record, configuration))?;
        count += 1;
    }
    if count == 0 {
        return Err(format!("{shown}: an inventory of no record"));
    }
    Ok(())
}

/// The command that runs `leg` in the repository `root`: every test target,
/// single-threaded, its records checked against or staged in the leg's
/// directory, nothing of [`UNINHERITED`] inherited.
pub fn command(root: &Path, leg: &Leg<'_>) -> Command {
    let mut command = Command::new("cargo");
    command
        .current_dir(root)
        .args([
            "test",
            "-p",
            "dcbor",
            "--no-default-features",
            "--features",
            leg.features,
        ])
        .args(["--tests", "--", "--nocapture", "--test-threads=1"])
        .env("DCBOR_COST_MODE", leg.action.name())
        .env("DCBOR_COST_VARIANT", leg.features)
        .env("DCBOR_COST_DIRECTORY", leg.directory)
        .env("DCBOR_RIGOR", leg.layer);
    for name in UNINHERITED {
        command.env_remove(name);
    }
    command
}

/// Run `leg` in `root`, its output to its log: whether it passed.
pub fn run(root: &Path, leg: &Leg<'_>) -> Result<bool, String> {
    let log = std::fs::File::create(leg.log)
        .map_err(|error| format!("{}: {error}", leg.log.display()))?;
    let errors = log
        .try_clone()
        .map_err(|error| format!("{}: {error}", leg.log.display()))?;
    command(root, leg)
        .stdin(std::process::Stdio::null())
        .stdout(log)
        .stderr(errors)
        .status()
        .map(|status| status.success())
        .map_err(|error| format!("cargo: {error}"))
}

/// The cost evidence checked or recorded as `request` asks, each leg run by
/// `run_leg` ([`run`] in the gate).
pub fn costs(
    request: &Request<'_>,
    mut run_leg: impl FnMut(&Leg<'_>) -> Result<bool, String>,
) -> Result<Report, String> {
    let action = request.action;
    let configuration = request.configuration;
    let published = request.root.join("tests").join("data").join("costs");
    let mut baseline = request
        .baseline
        .map_or_else(|| published.clone(), Path::to_path_buf);
    let mut notes = Vec::new();
    if let Some(resume) = request.resume
        && !resume.is_dir()
    {
        return Err(format!("{}: no completed run to reuse", resume.display()));
    }
    if action == Action::Check {
        // Baselines are local artifacts. A fresh checkout supplies an
        // approved directory explicitly; checking never manufactures its own.
        if !baseline.is_dir() {
            return Err(format!("{}: no cost baseline", baseline.display()));
        }
        for (suffix, features) in VARIANTS {
            for layer in LAYERS {
                let manifest = baseline.join(format!("inventory{suffix}.{layer}.txt"));
                if !nonempty(&manifest) {
                    return Err(format!(
                        "{}: missing baseline inventory",
                        manifest.display()
                    ));
                }
                check_manifest(&manifest, &baseline, features, configuration)?;
            }
        }
    }
    let (logs, reused) = match (request.resume, action) {
        (Some(resume), Action::Check) => {
            let logs = fresh(request.temporary, "dcbor-cost-reuse")?;
            notes.push(format!(
                "Reuse completed qualification: {} (artifact verification; no source-equivalence claim)",
                resume.display()
            ));
            (logs, Some(resume.to_path_buf()))
        }
        (Some(resume), Action::Record) => (resume.to_path_buf(), None),
        (None, _) => (fresh(request.temporary, "dcbor-costs")?, None),
    };
    notes.push(format!("Cost evidence logs: {}", logs.display()));
    let mut staged: BTreeMap<String, String> = BTreeMap::new();
    let mut referenced = BTreeSet::new();
    for (variant, (suffix, features)) in VARIANTS.iter().enumerate() {
        for layer in LAYERS {
            notes.push(format!(
                "matrix costs: {features}, rigor={layer}, mode={}",
                action.name()
            ));
            let leg = format!("{variant}-{layer}");
            let inventory = logs.join(format!("{leg}.inventory"));
            let (log, checkpoint) = match &reused {
                Some(reused) => {
                    let checkpoint = reused.join(format!("{leg}.inventory"));
                    if !nonempty(&complete(&checkpoint)) {
                        return Err(format!(
                            "{}: missing completed leg; reuse never launches Cargo",
                            complete(&checkpoint).display()
                        ));
                    }
                    (reused.join(format!("{leg}.log")), checkpoint)
                }
                None => (logs.join(format!("{leg}.log")), inventory.clone()),
            };
            let directory = match action {
                Action::Check => baseline.clone(),
                Action::Record => {
                    let directory = logs.join(format!("{leg}.records"));
                    std::fs::create_dir_all(&directory)
                        .map_err(|error| format!("{}: {error}", directory.display()))?;
                    directory
                }
            };
            // A leg completed in the reused run: its checkpoint was written
            // only after its cargo run passed. Its inventory is rebuilt from
            // its retained log and compared below.
            let resumed = request.resume.is_some() && nonempty(&complete(&checkpoint));
            if resumed {
                if !nonempty(&log) || !nonempty(&checkpoint) {
                    return Err(format!(
                        "{leg}: a completed leg without its log or inventory"
                    ));
                }
                notes.push(format!("reuse completed leg: {leg}"));
            } else {
                let passed = run_leg(&Leg {
                    action,
                    features,
                    layer,
                    directory: &directory,
                    log: &log,
                })?;
                if !passed {
                    return Err(format!(
                        "{leg}: the matrices failed ({})\n{}",
                        log.display(),
                        read(&log)?
                    ));
                }
            }
            let found = observed(&read(&log)?);
            if found.is_empty() {
                return Err(format!("{}: no matrix cost evidence", log.display()));
            }
            let listed: String = found.iter().map(|digest| format!("{digest}\n")).collect();
            let digests: Vec<&str> = found.iter().map(String::as_str).collect();
            let manifest = records::manifest(configuration, features, &digests);
            if resumed {
                if read(&checkpoint)? != listed {
                    return Err(format!(
                        "{}: the completed leg's inventory is not its log's",
                        checkpoint.display()
                    ));
                }
                if read(&complete(&checkpoint))? != manifest {
                    return Err(format!(
                        "{}: the completed leg's inventory is not this run's",
                        complete(&checkpoint).display()
                    ));
                }
            }
            write(&inventory, &listed)?;
            match action {
                // Preflight every staged record now; publication waits until
                // every leg and every collision check has passed.
                Action::Record => {
                    for found in &found {
                        if !digest(found) {
                            return Err(format!("{leg}: {found:?} is no digest"));
                        }
                        let path = directory.join(format!("{found}.txt"));
                        if !nonempty(&path) {
                            return Err(format!("{}: missing staged record", path.display()));
                        }
                        let data = read(&path)?;
                        let identity = data.lines().nth(1).unwrap_or_default().to_string();
                        if records::current(&data, configuration).is_err() || identity.is_empty() {
                            return Err(format!(
                                "{}: invalid staged configuration or identity",
                                path.display()
                            ));
                        }
                        if staged
                            .get(found)
                            .is_some_and(|previous| *previous != identity)
                        {
                            return Err(format!(
                                "{found}: staged cost filename identity collision"
                            ));
                        }
                        let existing = published.join(format!("{found}.txt"));
                        if existing.exists()
                            && read(&existing)?.lines().nth(1) != Some(identity.as_str())
                        {
                            return Err(format!("{found}: cost filename identity collision"));
                        }
                        staged.insert(found.clone(), identity);
                    }
                }
                Action::Check => {
                    let recorded = baseline.join(format!("inventory{suffix}.{layer}.txt"));
                    if read(&recorded)? != manifest {
                        return Err(format!(
                            "{}: the matrices' inventory changed",
                            recorded.display()
                        ));
                    }
                    if let Some(reused) = &reused {
                        for found in &found {
                            let staged_record = reused
                                .join(format!("{leg}.records"))
                                .join(format!("{found}.txt"));
                            let record = baseline.join(format!("{found}.txt"));
                            if read(&staged_record)? != read(&record)? {
                                return Err(format!(
                                    "{}: not the baseline's {}",
                                    staged_record.display(),
                                    record.display()
                                ));
                            }
                        }
                    }
                }
            }
            write(&complete(&inventory), &manifest)?;
            referenced.extend(found);
        }
    }
    if action == Action::Record {
        std::fs::create_dir_all(&published)
            .map_err(|error| format!("{}: {error}", published.display()))?;
        // Records before any inventory can name them.
        for (variant, _) in VARIANTS.iter().enumerate() {
            for layer in LAYERS {
                let leg = format!("{variant}-{layer}");
                for found in read(&logs.join(format!("{leg}.inventory")))?.lines() {
                    let data = read(
                        &logs
                            .join(format!("{leg}.records"))
                            .join(format!("{found}.txt")),
                    )?;
                    publish(&published.join(format!("{found}.txt")), &data)?;
                }
            }
        }
        for (variant, (suffix, _)) in VARIANTS.iter().enumerate() {
            for layer in LAYERS {
                let data = read(&complete(
                    &logs.join(format!("{variant}-{layer}.inventory")),
                ))?;
                publish(
                    &published.join(format!("inventory{suffix}.{layer}.txt")),
                    &data,
                )?;
            }
        }
        baseline = published;
    }
    // Every record must be some matrix's. Configuration is part of a
    // record's identity: this run has no authority over another
    // configuration's evidence or files of no record.
    let mut faults = Vec::new();
    let entries =
        std::fs::read_dir(&baseline).map_err(|error| format!("{}: {error}", baseline.display()))?;
    let mut candidates = Vec::new();
    for entry in entries {
        let path = entry
            .map_err(|error| format!("{}: {error}", baseline.display()))?
            .path();
        let named = path
            .file_name()
            .and_then(|name| name.to_str())
            .and_then(|name| name.strip_suffix(".txt"))
            .is_some_and(digest);
        if named {
            candidates.push(path);
        }
    }
    candidates.sort();
    for path in candidates {
        let stem = path
            .file_stem()
            .and_then(|stem| stem.to_str())
            .unwrap_or_default()
            .to_string();
        let ours =
            std::fs::read_to_string(&path).is_ok_and(|data| records::ours(&data, configuration));
        if !ours || referenced.contains(&stem) {
            continue;
        }
        match action {
            Action::Record => {
                std::fs::remove_file(&path)
                    .map_err(|error| format!("{}: {error}", path.display()))?;
                notes.push(format!(
                    "{}: removed, no matrix of this configuration records it",
                    path.display()
                ));
            }
            Action::Check => faults.push(format!(
                "{}: no matrix of this configuration records it",
                path.display()
            )),
        }
    }
    notes.push(format!("Cost evidence logs: {}", logs.display()));
    Ok(Report {
        logs,
        notes,
        faults,
    })
}

fn publish(path: &Path, data: &str) -> Result<(), String> {
    dcbor_record::publish(
        path.to_str()
            .ok_or_else(|| format!("{}: not UTF-8", path.display()))?,
        data,
    );
    Ok(())
}

#[cfg(test)]
mod tests;
