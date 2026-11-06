//! The recorder's publication controls over a fake leg runner, which
//! records and checks what a matrix would without compiling anything: each
//! failing scenario beside its passing one.

use std::cell::Cell;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use super::*;

const CONFIGURATION: &str = "recorder-control";

/// A record no inventory names: its digest is no leg's.
const STALE: &str = "00000000000000ff.txt";

fn stale_content() -> String {
    dcbor_record::render(CONFIGURATION, ["identity\trenamed", "measurement"])
}

/// The leg number of `leg`: its variant's index, then its layer.
fn number(leg: &Leg<'_>) -> usize {
    let features: Vec<&str> = leg.features.split(',').collect();
    let variant = usize::from(features.contains(&"num-bigint"))
        + 2 * usize::from(features.contains(&"custom-std-collections"));
    2 * variant + usize::from(leg.layer == "exhaustive")
}

/// The record a leg's matrix writes under `configuration`.
fn record_of(configuration: &str, number: usize) -> String {
    dcbor_record::render(
        configuration,
        [format!("identity\tleg-{number}").as_str(), "measurement"],
    )
}

/// What a leg's cargo would do: fail when it is `fail`; otherwise record its
/// one cost record (every leg's under one digest when `collide`), or check
/// it, then name it in its log.
struct Fake {
    configuration: &'static str,
    fail: Option<usize>,
    collide: bool,
    runs: Cell<usize>,
}

impl Fake {
    fn new() -> Self {
        Self {
            configuration: CONFIGURATION,
            fail: None,
            collide: false,
            runs: Cell::new(0),
        }
    }

    fn failing(leg: usize) -> Self {
        Self {
            fail: Some(leg),
            ..Self::new()
        }
    }

    fn run(&self, leg: &Leg<'_>) -> Result<bool, String> {
        self.runs.set(self.runs.get() + 1);
        let number = number(leg);
        if self.fail == Some(number) {
            write(leg.log, "the matrix failed\n")?;
            return Ok(false);
        }
        let key = format!("{:016x}", if self.collide { 0 } else { number });
        let path = leg.directory.join(format!("{key}.txt"));
        let expected = record_of(self.configuration, number);
        match leg.action {
            Action::Record => write(&path, &expected)?,
            Action::Check => {
                if std::fs::read_to_string(&path).ok().as_deref() != Some(expected.as_str()) {
                    write(leg.log, "the cost record changed\n")?;
                    return Ok(false);
                }
            }
        }
        write(leg.log, &format!("running\n{MARKER}{key}\n"))?;
        Ok(true)
    }
}

/// A repository holding existing evidence and the old inventories.
struct Repository {
    root: PathBuf,
}

impl Repository {
    fn new(name: &str) -> Self {
        let root =
            std::env::temp_dir().join(format!("dcbor-gate-costs-{name}-{}", std::process::id()));
        if root.exists() {
            std::fs::remove_dir_all(&root).unwrap();
        }
        let repository = Self { root };
        std::fs::create_dir_all(repository.costs()).unwrap();
        repository.put("existing.txt", "existing evidence\n");
        for (suffix, _) in VARIANTS {
            for layer in LAYERS {
                repository.put(&format!("inventory{suffix}.{layer}.txt"), "old inventory\n");
            }
        }
        repository
    }

    fn costs(&self) -> PathBuf {
        self.root.join("tests").join("data").join("costs")
    }

    fn put(&self, name: &str, text: &str) {
        std::fs::write(self.costs().join(name), text).unwrap();
    }

    fn snapshot_of(directory: &Path) -> BTreeMap<String, Vec<u8>> {
        std::fs::read_dir(directory)
            .unwrap()
            .map(|entry| {
                let path = entry.unwrap().path();
                (
                    path.file_name().unwrap().to_str().unwrap().to_string(),
                    std::fs::read(&path).unwrap(),
                )
            })
            .collect()
    }

    fn snapshot(&self) -> BTreeMap<String, Vec<u8>> {
        Self::snapshot_of(&self.costs())
    }

    fn request<'a>(
        &'a self,
        action: Action,
        baseline: Option<&'a Path>,
        resume: Option<&'a Path>,
    ) -> Request<'a> {
        Request {
            action,
            root: &self.root,
            configuration: CONFIGURATION,
            temporary: &self.root,
            baseline,
            resume,
        }
    }

    fn run(&self, action: Action, fake: &Fake) -> Result<Report, String> {
        costs(&self.request(action, None, None), |leg| fake.run(leg))
    }

    fn record(&self) -> Report {
        self.run(Action::Record, &Fake::new()).unwrap()
    }

    /// The one log directory a recording made.
    fn logs(&self) -> PathBuf {
        let made: Vec<PathBuf> = std::fs::read_dir(&self.root)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with("dcbor-costs."))
            })
            .collect();
        assert_eq!(made.len(), 1, "{made:?}");
        made[0].clone()
    }

    /// A recording whose second leg failed: its logs.
    fn interrupted(&self) -> PathBuf {
        assert!(self.run(Action::Record, &Fake::failing(1)).is_err());
        self.logs()
    }
}

impl Drop for Repository {
    fn drop(&mut self) {
        if !std::thread::panicking() {
            std::fs::remove_dir_all(&self.root).unwrap();
        }
    }
}

/// Every file under `directory`, by its path relative to it.
fn tree(directory: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    let mut files = BTreeMap::new();
    let mut pending = vec![directory.to_path_buf()];
    while let Some(at) = pending.pop() {
        for entry in std::fs::read_dir(&at).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                pending.push(path);
            } else {
                files.insert(
                    path.strip_prefix(directory).unwrap().to_path_buf(),
                    std::fs::read(&path).unwrap(),
                );
            }
        }
    }
    files
}

#[test]
fn a_complete_matrix_publishes_every_record_and_inventory() {
    let repository = Repository::new("complete");
    let report = repository.record();
    assert!(report.faults.is_empty());
    for (variant, (suffix, features)) in VARIANTS.iter().enumerate() {
        for (layer_index, layer) in LAYERS.iter().enumerate() {
            let number = 2 * variant + layer_index;
            let key = format!("{number:016x}");
            let inventory = std::fs::read_to_string(
                repository
                    .costs()
                    .join(format!("inventory{suffix}.{layer}.txt")),
            )
            .unwrap();
            assert_eq!(
                inventory,
                records::manifest(CONFIGURATION, features, &[key.as_str()])
            );
            assert_eq!(
                std::fs::read_to_string(repository.costs().join(format!("{key}.txt"))).unwrap(),
                record_of(CONFIGURATION, number)
            );
        }
    }
    assert_eq!(
        std::fs::read_to_string(repository.costs().join("existing.txt")).unwrap(),
        "existing evidence\n"
    );
    let checked = repository.run(Action::Check, &Fake::new()).unwrap();
    assert!(checked.faults.is_empty(), "{:?}", checked.faults);
}

#[test]
fn a_complete_recording_removes_the_records_no_matrix_produces() {
    let repository = Repository::new("prune");
    repository.put(STALE, &stale_content());
    let report = repository.record();
    assert!(!repository.costs().join(STALE).exists());
    assert!(
        report
            .notes
            .iter()
            .any(|note| note.contains(STALE) && note.contains("removed"))
    );
    assert!(repository.costs().join("existing.txt").exists());
}

#[test]
fn a_failed_recording_changes_nothing_and_its_staged_legs_stay_staged() {
    let repository = Repository::new("failed");
    repository.put(STALE, &stale_content());
    let before = repository.snapshot();
    assert!(repository.run(Action::Record, &Fake::failing(7)).is_err());
    assert_eq!(repository.snapshot(), before);
    let staged = tree(&repository.logs())
        .keys()
        .filter(|path| {
            path.parent()
                .and_then(|parent| parent.to_str())
                .is_some_and(|parent| parent.ends_with(".records"))
        })
        .count();
    assert_eq!(staged, 7);
}

#[test]
fn a_check_names_and_keeps_a_record_no_matrix_produces() {
    let repository = Repository::new("check-stale");
    repository.record();
    repository.put(STALE, &stale_content());
    let checked = repository.run(Action::Check, &Fake::new()).unwrap();
    assert_eq!(checked.faults.len(), 1);
    assert!(checked.faults[0].ends_with(&format!(
        "{STALE}: no matrix of this configuration records it"
    )));
    assert!(repository.costs().join(STALE).exists());
}

#[test]
fn foreign_and_unrecognized_records_are_preserved() {
    let repository = Repository::new("foreign");
    let protected = [
        (
            "00000000000000fe.txt",
            dcbor_record::render("another-fork", ["identity\told"]),
        ),
        (
            "00000000000000fd.txt",
            "unrecognized evidence\n".to_string(),
        ),
    ];
    for (name, content) in &protected {
        repository.put(name, content);
    }
    repository.record();
    let checked = repository.run(Action::Check, &Fake::new()).unwrap();
    assert!(checked.faults.is_empty(), "{:?}", checked.faults);
    for (name, content) in &protected {
        assert_eq!(
            &std::fs::read_to_string(repository.costs().join(name)).unwrap(),
            content
        );
    }
}

#[test]
fn a_check_does_not_repair_a_missing_record() {
    let repository = Repository::new("missing-record");
    repository.record();
    std::fs::remove_file(repository.costs().join("0000000000000000.txt")).unwrap();
    let before = repository.snapshot();
    assert!(
        repository
            .run(Action::Check, &Fake::new())
            .unwrap_err()
            .contains("missing cost baseline")
    );
    assert_eq!(repository.snapshot(), before);
}

#[test]
fn an_external_baseline_is_checked_without_local_records() {
    let repository = Repository::new("external");
    repository.record();
    let external = repository.root.join("approved-baseline");
    std::fs::rename(repository.costs(), &external).unwrap();
    let before = Repository::snapshot_of(&external);
    let fake = Fake::new();
    let report = costs(
        &repository.request(Action::Check, Some(&external), None),
        |leg| fake.run(leg),
    )
    .unwrap();
    assert!(report.faults.is_empty(), "{:?}", report.faults);
    assert!(!repository.costs().exists());
    assert_eq!(Repository::snapshot_of(&external), before);
    std::fs::write(external.join(STALE), stale_content()).unwrap();
    let report = costs(
        &repository.request(Action::Check, Some(&external), None),
        |leg| fake.run(leg),
    )
    .unwrap();
    assert_eq!(report.faults.len(), 1);
    std::fs::create_dir_all(repository.costs()).unwrap();
}

#[test]
fn a_missing_inventory_fails_before_any_leg_runs() {
    let repository = Repository::new("missing-inventory");
    repository.record();
    std::fs::remove_file(
        repository
            .costs()
            .join("inventory.custom-std.num-bigint.exhaustive.txt"),
    )
    .unwrap();
    let fake = Fake::new();
    let error = repository.run(Action::Check, &fake).unwrap_err();
    assert!(error.contains("missing baseline inventory"), "{error}");
    assert_eq!(fake.runs.get(), 0);
}

#[test]
fn a_cross_leg_identity_collision_publishes_nothing() {
    let repository = Repository::new("collision");
    let before = repository.snapshot();
    let fake = Fake {
        collide: true,
        ..Fake::new()
    };
    let error = repository.run(Action::Record, &fake).unwrap_err();
    assert!(
        error.contains("staged cost filename identity collision"),
        "{error}"
    );
    assert_eq!(repository.snapshot(), before);
}

#[test]
fn a_record_of_another_identity_under_a_staged_name_is_a_collision() {
    let repository = Repository::new("published-collision");
    repository.put("0000000000000000.txt", &record_of(CONFIGURATION, 9));
    let before = repository.snapshot();
    let error = repository.run(Action::Record, &Fake::new()).unwrap_err();
    assert!(
        error.contains("0000000000000000: cost filename identity collision"),
        "{error}"
    );
    assert_eq!(repository.snapshot(), before);
}

/// A leg is run with its mode, projection, directory and layer set, and
/// none of the other recording modes, nor minimal witnesses, inherited.
#[test]
fn a_leg_inherits_no_other_recording_mode() {
    let directory = Path::new("/staged");
    let log = Path::new("/leg.log");
    let leg = Leg {
        action: Action::Check,
        features: "std,derive",
        layer: "exhaustive",
        directory,
        log,
    };
    let command = command(Path::new("/repo"), &leg);
    let environment: BTreeMap<String, Option<String>> = command
        .get_envs()
        .map(|(name, value)| {
            (
                name.to_str().unwrap().to_string(),
                value.map(|value| value.to_str().unwrap().to_string()),
            )
        })
        .collect();
    let set = |value: &str| Some(value.to_string());
    let mut expected: BTreeMap<String, Option<String>> = BTreeMap::from([
        ("DCBOR_COST_MODE".to_string(), set("check")),
        ("DCBOR_COST_VARIANT".to_string(), set("std,derive")),
        ("DCBOR_COST_DIRECTORY".to_string(), set("/staged")),
        ("DCBOR_RIGOR".to_string(), set("exhaustive")),
    ]);
    for name in [
        "DCBOR_RECORD_FACTORS",
        "DCBOR_RECORD_TRACES",
        "DCBOR_CLASS_COVERAGE",
        "DCBOR_WITNESS",
    ] {
        expected.insert(name.to_string(), None);
    }
    assert_eq!(environment, expected);
    assert_eq!(command.get_current_dir(), Some(Path::new("/repo")));
    let arguments: Vec<&str> = command
        .get_args()
        .map(|argument| argument.to_str().unwrap())
        .collect();
    assert_eq!(
        arguments,
        [
            "test",
            "-p",
            "dcbor",
            "--no-default-features",
            "--features",
            "std,derive",
            "--tests",
            "--",
            "--nocapture",
            "--test-threads=1"
        ]
    );
}

#[test]
fn a_resumed_recording_reuses_its_completed_leg_and_completes_the_rest() {
    let repository = Repository::new("resume");
    let logs = repository.interrupted();
    let before = std::fs::read(logs.join("0-fast.log")).unwrap();
    // Leg 0 would fail if it were run again.
    let fake = Fake::failing(0);
    let report = costs(
        &repository.request(Action::Record, None, Some(&logs)),
        |leg| fake.run(leg),
    )
    .unwrap();
    assert!(
        report
            .notes
            .contains(&"reuse completed leg: 0-fast".to_string())
    );
    assert_eq!(fake.runs.get(), 7);
    assert_eq!(std::fs::read(logs.join("0-fast.log")).unwrap(), before);
    for leg in 0..8 {
        assert!(repository.costs().join(format!("{leg:016x}.txt")).exists());
    }
}

#[test]
fn a_resumed_recording_refuses_a_changed_or_damaged_run_and_publishes_nothing() {
    type Damage = fn(&Path);
    let cases: [(&str, Damage, &'static str); 3] = [
        ("configuration", |_| {}, "different"),
        (
            "staged-record",
            |logs| {
                std::fs::remove_file(logs.join("0-fast.records").join("0000000000000000.txt"))
                    .unwrap()
            },
            CONFIGURATION,
        ),
        (
            "log",
            |logs| {
                let log = logs.join("0-fast.log");
                let mut text = std::fs::read_to_string(&log).unwrap();
                text.push_str(&format!("{MARKER}ffffffffffffffff\n"));
                std::fs::write(log, text).unwrap();
            },
            CONFIGURATION,
        ),
    ];
    for (name, damage, configuration) in cases {
        let repository = Repository::new(&format!("resume-{name}"));
        let logs = repository.interrupted();
        damage(&logs);
        let before = repository.snapshot();
        let fake = Fake {
            configuration,
            ..Fake::new()
        };
        let request = Request {
            configuration,
            ..repository.request(Action::Record, None, Some(&logs))
        };
        assert!(costs(&request, |leg| fake.run(leg)).is_err(), "{name}");
        assert_eq!(repository.snapshot(), before, "{name}");
    }
}

/// Checking against a completed recording reuses all eight legs and runs
/// no matrix, writing nothing to the evidence or the reused run.
#[test]
fn a_check_against_a_completed_run_launches_no_matrix() {
    let repository = Repository::new("reuse");
    repository.record();
    let logs = repository.logs();
    let before = repository.snapshot();
    let staged = tree(&logs);
    let fake = Fake::new();
    let report = costs(
        &repository.request(Action::Check, None, Some(&logs)),
        |leg| fake.run(leg),
    )
    .unwrap();
    assert!(report.faults.is_empty(), "{:?}", report.faults);
    assert_eq!(
        report
            .notes
            .iter()
            .filter(|note| note.starts_with("reuse completed leg:"))
            .count(),
        8
    );
    assert_eq!(fake.runs.get(), 0);
    assert_eq!(repository.snapshot(), before);
    assert_eq!(tree(&logs), staged);
}

#[test]
fn a_check_against_an_incomplete_or_corrupt_run_fails_without_running() {
    let repository = Repository::new("reuse-corrupt");
    repository.record();
    let logs = repository.logs();
    let costs_dir = repository.costs();
    let cases: Vec<(PathBuf, Option<Vec<u8>>)> = vec![
        (logs.join("3-exhaustive.inventory.complete"), None),
        (
            logs.join("0-fast.log"),
            Some(format!("{MARKER}ffffffffffffffff\n").into_bytes()),
        ),
        (
            logs.join("0-fast.inventory"),
            Some(b"ffffffffffffffff\n".to_vec()),
        ),
        (
            logs.join("0-fast.inventory.complete"),
            Some(b"wrong configuration\n".to_vec()),
        ),
        (
            logs.join("0-fast.records").join("0000000000000000.txt"),
            None,
        ),
        (
            logs.join("0-fast.records").join("0000000000000000.txt"),
            Some(b"changed measurement\n".to_vec()),
        ),
        (
            costs_dir.join("0000000000000000.txt"),
            Some(
                dcbor_record::render(CONFIGURATION, ["identity\tleg-0", "changed measurement"])
                    .into_bytes(),
            ),
        ),
    ];
    for (path, replacement) in cases {
        let original = std::fs::read(&path).unwrap();
        match &replacement {
            None => std::fs::remove_file(&path).unwrap(),
            Some(bytes) => std::fs::write(&path, bytes).unwrap(),
        }
        let fake = Fake::new();
        let result = costs(
            &repository.request(Action::Check, None, Some(&logs)),
            |leg| fake.run(leg),
        );
        assert!(result.is_err(), "{}: {replacement:?}", path.display());
        assert_eq!(fake.runs.get(), 0);
        std::fs::write(&path, original).unwrap();
    }
}

#[test]
fn a_check_against_a_completed_run_checks_an_external_baseline_and_its_orphans() {
    let repository = Repository::new("reuse-external");
    repository.record();
    let logs = repository.logs();
    let external = repository.root.join("approved-baseline");
    std::fs::rename(repository.costs(), &external).unwrap();
    let fake = Fake::new();
    let request = repository.request(Action::Check, Some(&external), Some(&logs));
    assert!(
        costs(&request, |leg| fake.run(leg))
            .unwrap()
            .faults
            .is_empty()
    );
    std::fs::write(external.join(STALE), stale_content()).unwrap();
    let report = costs(&request, |leg| fake.run(leg)).unwrap();
    assert!(report.faults[0].contains("no matrix of this configuration"));
    assert_eq!(fake.runs.get(), 0);
    std::fs::create_dir_all(repository.costs()).unwrap();
}

#[test]
fn an_action_reads_back_its_name() {
    for action in [Action::Check, Action::Record] {
        assert_eq!(Action::parse(action.name()), Some(action));
    }
    assert_eq!(Action::parse("check-costs"), None);
}
