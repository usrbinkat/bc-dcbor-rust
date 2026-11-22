//! Whether a finished calibration run is a sample: the one authority
//! ([`eligible_sample`]), which a calibration's schedule counts by, adoption
//! adopts by, and the predictions' reader reads by, over a run as it ran,
//! as adoption staged it, or as it was adopted and accepted.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use super::{
    ADOPTION_RECORD, Binaries, EstablishedEnvironment, INVOCATION_RECORD, LAUNCHER_RECORD,
    LOOP_POLICY_RECORD, Launch, Outcome, PLAN_RECORD, POLICY, PURPOSE_CALIBRATION,
    READINESS_RECORD, RUNTIME_VERSION, Readiness, RunIdentityRecord, SOURCES_RECORD, Selection,
    Termination, arguments, check_calibration_termination, check_execution_evidence,
    check_function_scope, checked, file_entry_digest, invocation_arguments, plan_of, policy_of,
    read_manifest, record_files, run_identifier, selected, strict_json, tree_digest_of, typed,
};

/// One eligible calibration sample ([`eligible_sample`], its only maker):
/// the one harness its run checked and verified, the run, its manifest's
/// digest, the recorded duration of the harness's CBMC run, the artifact and
/// verifier it ran on, its established environment, its build and loop-bound
/// policy, and the digests of the plan and readiness the run was given.
#[derive(Clone, Debug, PartialEq)]
pub struct CalibrationSample {
    pub(super) harness: String,
    pub(super) run: String,
    pub(super) manifest_sha256: String,
    pub(super) elapsed: std::time::Duration,
    pub(super) artifact_sha256: String,
    pub(super) verifier: serde_json::Value,
    pub(super) environment: EstablishedEnvironment,
    pub(super) build: String,
    pub(super) loop_policy_sha256: String,
    pub(super) plan_sha256: String,
    pub(super) readiness_sha256: String,
}

impl CalibrationSample {
    pub fn harness(&self) -> &str {
        &self.harness
    }

    pub fn run(&self) -> &str {
        &self.run
    }

    pub fn manifest_sha256(&self) -> &str {
        &self.manifest_sha256
    }

    pub fn elapsed(&self) -> std::time::Duration {
        self.elapsed
    }

    pub fn plan_sha256(&self) -> &str {
        &self.plan_sha256
    }

    pub fn readiness_sha256(&self) -> &str {
        &self.readiness_sha256
    }

    /// Whether `other` is a sample of this one's applicability envelope: of
    /// the same harness, build, loop-bound policy, instrumented binary and
    /// verifier, in an equivalent environment, and of another run. The one
    /// comparison a calibration repeats a harness by and the predictions'
    /// reader fits a harness's samples by; refused naming the first that
    /// differs.
    pub fn compatible(&self, other: &Self) -> Result<(), String> {
        let differs = if other.harness != self.harness {
            Some("a sample of another harness")
        } else if other.run == self.run {
            Some("a second sample of one run")
        } else if other.build != self.build {
            Some("of another build")
        } else if other.loop_policy_sha256 != self.loop_policy_sha256 {
            Some("under another loop-bound policy")
        } else if other.artifact_sha256 != self.artifact_sha256 {
            Some("of another instrumented binary than the harness's other samples")
        } else if other.verifier != self.verifier {
            Some("under another verifier than the harness's other samples")
        } else if !other.environment.equivalent(&self.environment) {
            Some("of another environment than the harness's other samples")
        } else {
            None
        };
        match differs {
            Some(differs) => Err(format!("run {} is {differs}", other.run)),
            None => Ok(()),
        }
    }
}

/// An adopted run's acceptance receipt (`adoption.json`, beside its log and
/// evidence): the run and the digest of the manifest it accepted, written by
/// adoption alone and only once the publication's durability was
/// established ([`super::adopt`]). A published run without it is no adopted
/// run any reader accepts.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdoptionReceipt {
    pub version: u64,
    pub run: String,
    pub manifest_sha256: String,
}

/// The adoption receipt at `path`: a regular file, strictly the receipt's
/// fields, of [`RUNTIME_VERSION`].
fn adoption_receipt(path: &Path) -> Result<AdoptionReceipt, String> {
    let fault = |what: String| {
        format!(
            "{}: {what}: its publication was never accepted",
            path.display()
        )
    };
    let metadata = std::fs::symlink_metadata(path).map_err(|error| fault(error.to_string()))?;
    if !metadata.file_type().is_file() {
        return Err(fault("not a regular file".to_string()));
    }
    let bytes = std::fs::read(path).map_err(|error| fault(error.to_string()))?;
    let receipt: AdoptionReceipt =
        typed(strict_json(&bytes).map_err(fault)?, ADOPTION_RECORD).map_err(fault)?;
    if receipt.version != RUNTIME_VERSION {
        return Err(fault(format!("version {}", receipt.version)));
    }
    Ok(receipt)
}

/// Where a finished calibration run's records are: its log, its evidence
/// directory, whether its instrumented binaries are beside its records (a
/// run as it ran) or recorded by digest alone (staged or adopted), and an
/// adopted run's acceptance receipt.
#[derive(Clone, Debug)]
pub struct RunRecords {
    log: PathBuf,
    evidence: PathBuf,
    binaries: Binaries,
    receipt: Option<AdoptionReceipt>,
}

impl RunRecords {
    /// A run as `process::kani` left it: its log at `log`, its evidence
    /// beside it (`LOG.evidence`), its binaries held.
    pub fn ran(log: &Path) -> Self {
        Self {
            log: log.to_path_buf(),
            evidence: log.with_extension("evidence"),
            binaries: Binaries::Held,
            receipt: None,
        }
    }

    /// A run as adoption lays it out before it is accepted: `kani.log` and
    /// `evidence/` under `directory` and nothing else, its binaries recorded
    /// by digest alone.
    pub fn staged(directory: &Path) -> Result<Self, String> {
        let (records, top) = Self::laid_out(directory)?;
        if top != Self::layout() {
            return Err(format!(
                "{}: holds {top:?}, a staged run is exactly kani.log and evidence/",
                directory.display()
            ));
        }
        Ok(records)
    }

    /// A run as adoption published and accepted it: the staged layout under
    /// `directory`, beside its acceptance receipt ([`ADOPTION_RECORD`]),
    /// which is required: a publication whose durability adoption never
    /// established is no adopted run.
    pub fn adopted(directory: &Path) -> Result<Self, String> {
        let _publication = super::adoption::publication_read_lock(directory)?;
        let (mut records, mut top) = Self::laid_out(directory)?;
        top.remove(ADOPTION_RECORD);
        if top != Self::layout() {
            return Err(format!(
                "{}: holds {top:?} beside its receipt, an adopted run is exactly kani.log and \
                 evidence/",
                directory.display()
            ));
        }
        let receipt_path = directory.join(ADOPTION_RECORD);
        records.receipt = Some(adoption_receipt(&receipt_path)?);
        Ok(records)
    }

    fn layout() -> BTreeSet<String> {
        BTreeSet::from(["evidence".to_string(), "kani.log".to_string()])
    }

    /// The records under `directory` as adoption lays them out, and every
    /// name the directory holds.
    fn laid_out(directory: &Path) -> Result<(Self, BTreeSet<String>), String> {
        let kind = std::fs::symlink_metadata(directory)
            .map_err(|error| format!("{}: {error}", directory.display()))?
            .file_type();
        if !kind.is_dir() {
            return Err(format!(
                "{}: a publication must be a directory of its own, not a link",
                directory.display()
            ));
        }
        let top: BTreeSet<String> = std::fs::read_dir(directory)
            .map_err(|error| format!("{}: {error}", directory.display()))?
            .map(|entry| {
                entry
                    .map(|entry| entry.file_name().to_string_lossy().into_owned())
                    .map_err(|error| format!("{}: {error}", directory.display()))
            })
            .collect::<Result<_, String>>()?;
        Ok((
            Self {
                log: directory.join("kani.log"),
                evidence: directory.join("evidence"),
                binaries: Binaries::Absent,
                receipt: None,
            },
            top,
        ))
    }
}

/// A calibration run's selected policy (`loop-bounds.json`), as the gate
/// wrote it ([`super::selected`]), read strictly: exactly its function
/// scope, its harnesses' entries and its deadlines, each deadline exactly a
/// harness, a number of milliseconds and a reason.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SelectedPolicy {
    #[expect(
        dead_code,
        reason = "read to refuse a policy without it; check_execution_evidence reconciles it"
    )]
    loops: Vec<serde_json::Value>,
    #[expect(
        dead_code,
        reason = "read to refuse a policy without it; check_execution_evidence reconciles it"
    )]
    harnesses: Vec<serde_json::Value>,
    deadlines: Vec<SelectedDeadline>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SelectedDeadline {
    harness: String,
    milliseconds: u64,
    reason: String,
}

/// A run's invocation (`invocation.json`), as `process::kani` wrote it: the
/// launcher spawned and every argument it was given.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Invocation {
    launcher: String,
    arguments: Vec<String>,
}

/// The one authority over whether the finished calibration run `run` whose
/// records are `records` is a sample, the census `declared`. Its
/// relationships are checked, never inferred from the files' presence:
///
/// - its manifest complete and naming the run ([`read_manifest`]), an
///   adopted run's acceptance receipt naming that run and manifest, its
///   log's bytes its recorded digest, and its evidence exactly the files it
///   lists, every one read once and held to its digest
///   ([`super::Artifacts::Manifested`]), its instrumented binaries held to
///   their recorded digests or, staged and adopted, absent;
/// - its identity valid ([`RunIdentityRecord::validate`]), this run's, a
///   calibration's;
/// - the plan it kept (`plan.json`) the bytes its identity's revision is the
///   digest of, a valid plan of the census ([`plan_of`]); its readiness
///   (`readiness.json`) valid by the one validator ([`Readiness::validate`]);
/// - its run's policy (`loop-bounds.json`) read strictly, selecting exactly
///   one harness, one the plan names, under exactly the plan's limit and
///   reason, the deadline every execution record of it carries;
/// - its identity's inputs bound to the records the run kept of them: the
///   loop-bound policy digest to the policy file it read
///   (`loop-policy.json`), whose selection for the harness under the plan is
///   its run's policy; the source state to its per-path digests
///   (`sources.json`, [`tree_digest_of`]), which hold that policy file at
///   its path; its build to its invocation (`invocation.json`), the proof
///   build ([`arguments`]) of that one harness, its loop-bound policy and
///   evidence beside one another and its artifact beneath them; and its
///   launcher record, its invocation's and its reconciled execution's
///   launcher one program;
/// - its judgement accepted, its launcher's ending the one its report calls
///   for ([`check_calibration_termination`]), its report checking that one
///   harness alone and verifying it ([`checked`]);
/// - its evidence reconciled with its policy and report, the harness the one
///   launched, ended by a normal exit, and `execution.json` naming the
///   reconciled verifier and exactly that harness's artifact;
/// - its launch's environment established ([`super::EnvironmentRecord::establish`]).
///
/// A run that fails any of them, a reconciled property failure or a bound
/// refused among them, is no sample, however its execution was recorded.
pub fn eligible_sample(
    records: &RunRecords,
    run: &str,
    declared: &BTreeSet<String>,
) -> Result<CalibrationSample, String> {
    let fault = |what: String| format!("run {run}: {what}: not a calibration sample");
    run_identifier(run)?;
    let evidence = &records.evidence;
    if !std::fs::symlink_metadata(evidence)
        .map_err(|error| format!("{}: {error}", evidence.display()))?
        .file_type()
        .is_dir()
    {
        return Err(format!(
            "{}: its evidence is not a directory",
            evidence.display()
        ));
    }
    let manifest = read_manifest(evidence, Some(run))?;
    if let Some(receipt) = &records.receipt
        && (receipt.run != run || receipt.manifest_sha256 != manifest.sha256())
    {
        return Err(fault(format!(
            "its adoption receipt accepted run {} of manifest {}, its records are run {run}'s of \
             manifest {}",
            receipt.run,
            receipt.manifest_sha256,
            manifest.sha256()
        )));
    }
    let log = &records.log;
    if !std::fs::symlink_metadata(log)
        .map_err(|error| format!("{}: {error}", log.display()))?
        .file_type()
        .is_file()
    {
        return Err(format!("{}: not a regular file", log.display()));
    }
    let log_bytes = std::fs::read(log).map_err(|error| format!("{}: {error}", log.display()))?;
    let log_digest = crate::process::sha256_bytes(&log_bytes)?;
    if log_digest != manifest.log_sha256() {
        return Err(format!(
            "{}: its bytes have digest {log_digest}, the manifest records {}",
            log.display(),
            manifest.log_sha256()
        ));
    }
    let held: BTreeSet<String> = record_files(evidence)?
        .into_iter()
        .filter(|relative| relative != "manifest.json")
        .collect();
    let listed: BTreeSet<String> = manifest.files().keys().cloned().collect();
    if held != listed {
        return Err(fault(format!(
            "it holds {:?} its manifest does not list, and lacks {:?} it lists",
            held.difference(&listed).collect::<Vec<_>>(),
            listed.difference(&held).collect::<Vec<_>>()
        )));
    }
    // Every record read once and held to its manifest's digest, those bytes
    // the ones interpreted below; each listed record checked whether read
    // again or not.
    let records_read = manifest.records(evidence, records.binaries);
    for relative in manifest.files().keys() {
        records_read.read(&evidence.join(relative))?;
    }
    let bytes = |relative: &str| records_read.read(&evidence.join(relative));
    let json = |relative: &str| -> Result<serde_json::Value, String> {
        strict_json(&bytes(relative)?).map_err(|error| format!("{relative}: {error}"))
    };
    let identity = typed::<RunIdentityRecord>(json("run.json")?, "run.json")?.validate()?;
    if identity.id() != run || identity.purpose() != PURPOSE_CALIBRATION {
        return Err(fault(format!(
            "run.json names run {} of purpose {}",
            identity.id(),
            identity.purpose()
        )));
    }
    let plan_bytes = bytes(PLAN_RECORD)?;
    let plan_sha256 = crate::process::sha256_bytes(&plan_bytes)?;
    if plan_sha256 != identity.revision() {
        return Err(fault(format!(
            "its {PLAN_RECORD} has digest {plan_sha256}, its identity's revision is {}",
            identity.revision()
        )));
    }
    let plan =
        plan_of(&plan_bytes, declared).map_err(|error| fault(format!("{PLAN_RECORD}: {error}")))?;
    let readiness_bytes = bytes(READINESS_RECORD)?;
    let readiness: Readiness = typed(strict_json(&readiness_bytes)?, READINESS_RECORD)?;
    readiness.validate(None).map_err(fault)?;
    // Its run's policy, read strictly, selected exactly one planned harness,
    // under the plan's limit and reason.
    let policy = json("loop-bounds.json")?;
    let selection: SelectedPolicy = typed(policy.clone(), "loop-bounds.json").map_err(fault)?;
    let [deadline] = selection.deadlines.as_slice() else {
        return Err(fault(format!(
            "its policy selects {} harnesses, a calibration run checks exactly one",
            selection.deadlines.len()
        )));
    };
    let harness = deadline.harness.clone();
    match plan.deadlines().get(&harness) {
        Some(limit)
            if limit.milliseconds() == deadline.milliseconds
                && limit.reason() == deadline.reason => {}
        found => {
            return Err(fault(format!(
                "its policy gives {harness} {} ms ({:?}), its plan gives {found:?}",
                deadline.milliseconds, deadline.reason
            )));
        }
    }
    // The loop-bound policy its identity names: the policy file it read,
    // whose selection for the harness under its plan is its run's policy.
    let loop_policy = bytes(LOOP_POLICY_RECORD)?;
    let loop_policy_sha256 = crate::process::sha256_bytes(&loop_policy)?;
    if loop_policy_sha256 != identity.loop_policy_sha256() {
        return Err(fault(format!(
            "its {LOOP_POLICY_RECORD} has digest {loop_policy_sha256}, its identity names the \
             loop-bound policy {}",
            identity.loop_policy_sha256()
        )));
    }
    // The source state its identity names: the digest of its per-path
    // digests, which hold that policy file at its path.
    let sources: BTreeMap<String, String> = typed(json(SOURCES_RECORD)?, SOURCES_RECORD)?;
    let tree_sha256 = tree_digest_of(&sources)?;
    if tree_sha256 != identity.tree_sha256() {
        return Err(fault(format!(
            "its {SOURCES_RECORD} digests to {tree_sha256}, its identity names the source state \
             {}",
            identity.tree_sha256()
        )));
    }
    let policy_entry = file_entry_digest(POLICY, &loop_policy, false)?;
    if sources.get(POLICY) != Some(&policy_entry) {
        return Err(fault(format!(
            "its {SOURCES_RECORD} records the tree's loop-bound policy {POLICY} as {:?}, its \
             {LOOP_POLICY_RECORD} is {policy_entry}",
            sources.get(POLICY)
        )));
    }
    let text = String::from_utf8(loop_policy)
        .map_err(|error| fault(format!("{LOOP_POLICY_RECORD}: not UTF-8: {error}")))?;
    let read = policy_of(&text, declared)
        .map_err(|error| fault(format!("{LOOP_POLICY_RECORD}: {error}")))?;
    let reselected =
        selected(&read, plan.deadlines(), &Selection::one(&harness), declared).map_err(fault)?;
    if reselected != policy {
        return Err(fault(format!(
            "its loop-bounds.json is not the selection of its {LOOP_POLICY_RECORD} for {harness} \
             under its plan"
        )));
    }
    // The build its identity names: its invocation's, exactly the one layout
    // of the proof build's run of that one harness ([`invocation_arguments`]),
    // its target directory absolute, its selected policy and its evidence
    // beside one another.
    let invocation: Invocation = typed(json(INVOCATION_RECORD)?, INVOCATION_RECORD)?;
    let structured = match invocation.arguments.as_slice() {
        [.., target, _, policy_path, _, bounds]
            if invocation.arguments
                == invocation_arguments(&Selection::one(&harness), target, policy_path, bounds)
                && target.starts_with('/')
                && policy_path
                    .strip_suffix("/loop-bounds.json")
                    .is_some_and(|directory| {
                        directory.starts_with('/')
                            && bounds.strip_suffix("/loop-bounds") == Some(directory)
                    }) =>
        {
            Some(bounds.clone())
        }
        _ => None,
    };
    let Some(bounds) = structured else {
        return Err(fault(format!(
            "its {INVOCATION_RECORD} records the arguments {:?}, which are not the proof build's \
             run of {harness} alone",
            invocation.arguments
        )));
    };
    let build = arguments().join(" ");
    if identity.build() != build {
        return Err(fault(format!(
            "its identity's build {:?} is not the invocation's build {build:?}",
            identity.build()
        )));
    }
    let artifact = json(&format!(
        "loop-bounds/{}/artifact.json",
        harness.replace("::", ".")
    ))?;
    let preserved = format!("{bounds}/{}/artifact.out", harness.replace("::", "."));
    if artifact["path"] != preserved.as_str() {
        return Err(fault(format!(
            "its artifact.json names {}, its invocation's evidence holds {preserved}",
            artifact["path"]
        )));
    }
    // The program it launched: its launcher record, its invocation's and its
    // reconciled execution's launcher, one path.
    let launcher_bytes = bytes(LAUNCHER_RECORD)?;
    let launcher = std::str::from_utf8(&launcher_bytes)
        .ok()
        .and_then(|text| text.strip_suffix('\n'))
        .ok_or_else(|| fault(format!("its {LAUNCHER_RECORD} record is not one line")))?;
    let execution = json("execution.json")?;
    if invocation.launcher != launcher || execution["launcher"] != launcher {
        return Err(fault(format!(
            "its launcher record names {launcher}, {INVOCATION_RECORD} {} and execution.json {}",
            invocation.launcher, execution["launcher"]
        )));
    }
    // The run's own judgement, as it was recorded when it ended.
    let judgement = json("judgement.json")?;
    if judgement != serde_json::json!({"status": "accepted"}) {
        return Err(fault(format!("its judgement is {judgement}, not accepted")));
    }
    // Its launcher's termination, reconciled with its report.
    let ended = json("launcher.execution.json")?;
    let termination = match (ended["exit_code"].as_i64(), ended["signal"].as_i64()) {
        (Some(code), None) if ended["signal"].is_null() => Termination::Exited(
            i32::try_from(code)
                .map_err(|_| fault(format!("launcher.execution.json records exit {code}")))?,
        ),
        (None, Some(signal)) if ended["exit_code"].is_null() => Termination::Signaled(
            i32::try_from(signal)
                .map_err(|_| fault(format!("launcher.execution.json records signal {signal}")))?,
        ),
        _ => {
            return Err(fault(format!(
                "launcher.execution.json is not one exit or one signal: {ended}"
            )));
        }
    };
    let report = String::from_utf8(log_bytes)
        .map_err(|error| format!("{}: not UTF-8: {error}", log.display()))?;
    check_calibration_termination(termination, &report).map_err(fault)?;
    match checked(&report)?.as_slice() {
        [(name, Outcome::Pass)] if *name == harness => {}
        found => {
            return Err(fault(format!(
                "its report classes {found:?}: a calibration sample is one verified execution of \
                 {harness} alone"
            )));
        }
    }
    // The whole run reconciled again from its records: the harness's
    // command, executables, artifact record, discovery, resolution,
    // execution and report, and the function scope it applied.
    let bounds = evidence.join("loop-bounds");
    let reconciled =
        check_execution_evidence(&bounds, &policy, &report, records_read).map_err(fault)?;
    check_function_scope(&bounds, &policy, &reconciled.applied, false, records_read)
        .map_err(fault)?;
    let launched: Vec<&String> = reconciled.launched.keys().collect();
    if launched != [&harness] {
        return Err(fault(format!(
            "it launched {launched:?}, not {harness} alone"
        )));
    }
    let elapsed = *reconciled
        .completed
        .get(&harness)
        .ok_or_else(|| fault(format!("{harness}'s solver did not end by a normal exit")))?;
    let artifact_sha256 = reconciled.launched[&harness].artifact_sha256.clone();
    if execution["verifier"] != reconciled.verifier
        || execution["artifacts"] != serde_json::json!({ harness.clone(): artifact_sha256 })
    {
        return Err(fault(format!(
            "execution.json records {execution}, its evidence reconciles the verifier {} and \
             {harness}'s artifact {artifact_sha256}",
            reconciled.verifier
        )));
    }
    let launch: Launch = typed(json("launch.json")?, "launch.json")?;
    let environment = launch.environment.establish().map_err(fault)?;
    Ok(CalibrationSample {
        harness,
        run: run.to_string(),
        manifest_sha256: manifest.sha256().to_string(),
        elapsed,
        artifact_sha256,
        verifier: reconciled.verifier,
        environment,
        build: identity.build().to_string(),
        loop_policy_sha256: identity.loop_policy_sha256().to_string(),
        plan_sha256,
        readiness_sha256: crate::process::sha256_bytes(&readiness_bytes)?,
    })
}

/// The sample of the run logged at `log`, as `process::kani` left it
/// ([`RunRecords::ran`]): its identifier the one its evidence names, held to
/// by the one authority ([`eligible_sample`]).
pub fn ran_sample(log: &Path, declared: &BTreeSet<String>) -> Result<CalibrationSample, String> {
    let records = RunRecords::ran(log);
    let path = records.evidence.join("run.json");
    let bytes = std::fs::read(&path).map_err(|error| format!("{}: {error}", path.display()))?;
    let identity: RunIdentityRecord = typed(strict_json(&bytes)?, "run.json")?;
    eligible_sample(&records, &identity.id, declared)
}
