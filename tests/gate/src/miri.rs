//! The Miri gate's results and the mutation campaign's Miri judgements,
//! read from the files each run leaves (`tests/miri-owned.sh`):
//!
//! - `lines.tsv`: each selection line's base name, domain and suite kind,
//!   written as the lines are listed;
//! - `<base>.runs`: each run of the line's tests, `test<TAB>seed`, `-` for
//!   Miri's default seed, written for every listed line before any runs;
//! - `<base>-<runner>.verdict`: the native run's and each model's verdict
//!   over the line, `pass` or `fail`;
//! - `<base>-<model>/<index>.outcome`, `.measure` and `.verdict`: each run's
//!   outcome ([`Outcome`]), its GNU time measurement (`peak_kB seconds` on
//!   its last line), and whether it passed with its inventory read
//!   (`inventory`).
//!
//! A run that left no outcome never started: it is [`Outcome::NotRun`],
//! never a pass.

use std::path::Path;

use crate::outcome::{self, Judgement, Outcome};
use crate::rows::{Physical, Purpose, Row};

/// One selection line of the gate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Line {
    pub base: String,
    pub domain: String,
    pub kind: String,
}

/// One run of a line's test: its test and its seed, none for Miri's
/// default.
type Run = (String, Option<u64>);

/// One run a mutant is judged on: its line's base, its test and its seed,
/// none for Miri's default ([`baseline`], [`render_runs`]).
pub type JudgedRun = (String, String, Option<u64>);

fn read(path: &Path) -> Result<Option<String>, String> {
    match std::fs::read_to_string(path) {
        Ok(text) => Ok(Some(text)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(format!("{}: {error}", path.display())),
    }
}

fn required(path: &Path) -> Result<String, String> {
    read(path)?.ok_or_else(|| format!("{}: missing", path.display()))
}

/// The selection lines `logs/lines.tsv` names.
pub fn lines(logs: &Path) -> Result<Vec<Line>, String> {
    let path = logs.join("lines.tsv");
    required(&path)?
        .lines()
        .map(|row| match row.split('\t').collect::<Vec<_>>()[..] {
            [base, domain, kind] => Ok(Line {
                base: base.to_string(),
                domain: domain.to_string(),
                kind: kind.to_string(),
            }),
            _ => Err(format!("{}: not a line: {row:?}", path.display())),
        })
        .collect()
}

/// The outcome the file at `path` records, or [`Outcome::NotRun`] when the
/// run left none.
fn outcome_at(path: &Path) -> Result<Outcome, String> {
    match read(path)? {
        None => Ok(Outcome::NotRun),
        Some(text) => Outcome::parse(text.trim())
            .ok_or_else(|| format!("{}: no outcome {:?}", path.display(), text.trim())),
    }
}

/// The verdict file at `path` as an outcome: a pass, a failure, or a
/// runner that never reached its verdict.
fn verdict_at(path: &Path) -> Result<Outcome, String> {
    match read(path)?.as_deref().map(str::trim) {
        None => Ok(Outcome::NotRun),
        Some("pass") => Ok(Outcome::Pass),
        Some("fail") => Ok(Outcome::Failed),
        Some(other) => Err(format!("{}: no verdict {other:?}", path.display())),
    }
}

/// The wall seconds and peak kilobytes GNU time wrote at `path`, none for a
/// run that never started. A process killed by a signal has GNU time write
/// the signal first; the measurement is always its last line.
fn measured(path: &Path) -> Result<(Option<String>, Option<u64>), String> {
    let Some(text) = read(path)? else {
        return Ok((None, None));
    };
    let last = text.lines().last().unwrap_or_default();
    match last.split_once(' ') {
        Some((peak, seconds)) if !seconds.contains(' ') => {
            let peak = peak
                .parse()
                .map_err(|_| format!("{}: no peak kilobytes in {last:?}", path.display()))?;
            Ok((Some(seconds.to_string()), Some(peak)))
        }
        _ => Err(format!("{}: no measurement in {last:?}", path.display())),
    }
}

fn seed_of(text: &str, at: &Path) -> Result<Option<u64>, String> {
    if text == "-" {
        Ok(None)
    } else {
        text.parse()
            .map(Some)
            .map_err(|_| format!("{}: no seed {text:?}", at.display()))
    }
}

/// The runs `logs/<base>.runs` lists. Every listed line has its runs
/// written before any runs, so a line without them is a broken gate.
fn runs(logs: &Path, base: &str) -> Result<Vec<Run>, String> {
    let path = logs.join(format!("{base}.runs"));
    required(&path)?
        .lines()
        .map(|row| match row.split_once('\t') {
            Some((test, seed)) => Ok((test.to_string(), seed_of(seed, &path)?)),
            None => Err(format!("{}: not a run: {row:?}", path.display())),
        })
        .collect()
}

/// Every row of the gate whose logs are `logs`, under the aliasing
/// `models`: each line's verdict per runner, then each run under each
/// model.
pub fn results(logs: &Path, models: &[&str]) -> Result<Vec<Row>, String> {
    let mut rows = Vec::new();
    for line in lines(logs)? {
        for runner in core::iter::once("native").chain(models.iter().copied()) {
            rows.push(Row {
                domain: line.domain.clone(),
                line: line.base.clone(),
                runner: runner.to_string(),
                test: "(suite)".to_string(),
                seed: None,
                purpose: Purpose::Suite,
                bound: None,
                stack: None,
                expected: Some(Outcome::Pass),
                outcome: verdict_at(&logs.join(format!("{}-{runner}.verdict", line.base)))?,
                seconds: None,
                peak_kb: None,
                physical: Physical::Witnessed,
            });
        }
        for (index, (test, seed)) in runs(logs, &line.base)?.into_iter().enumerate() {
            for model in models {
                let directory = logs.join(format!("{}-{model}", line.base));
                let (seconds, peak_kb) = measured(&directory.join(format!("{index}.measure")))?;
                rows.push(Row {
                    domain: line.domain.clone(),
                    line: line.base.clone(),
                    runner: (*model).to_string(),
                    test: test.clone(),
                    seed,
                    purpose: Purpose::Normal,
                    bound: None,
                    stack: None,
                    // A run's kind is in its classification: an abort
                    // scenario that aborted is a pass (`outcome::miri`).
                    expected: Some(Outcome::Pass),
                    outcome: outcome_at(&directory.join(format!("{index}.outcome")))?,
                    seconds,
                    peak_kb,
                    physical: Physical::Witnessed,
                });
            }
        }
    }
    Ok(rows)
}

/// Every run, under every model, of each test `tests` names (each line
/// `base<TAB>test`) in the gate run whose logs are `baseline`, each
/// `(base, test, seed)`: what a mutant reaching those tests is judged on.
/// None when any of those tests has no run there or any run did not pass
/// under every model: nothing can then be judged. A mutant judged on no
/// test is a broken plan, refused.
pub fn baseline(
    baseline: &Path,
    tests: &str,
    models: &[&str],
) -> Result<Option<Vec<JudgedRun>>, String> {
    let mut judged = Vec::new();
    if tests.lines().all(str::is_empty) {
        return Err("a judged mutant names no test that reaches it".to_string());
    }
    for row in tests.lines().filter(|row| !row.is_empty()) {
        let Some((base, test)) = row.split_once('\t') else {
            return Err(format!("not a judged test: {row:?}"));
        };
        let mut found = false;
        for (index, (listed, seed)) in runs(baseline, base)?.into_iter().enumerate() {
            if listed != test {
                continue;
            }
            found = true;
            for model in models {
                let verdict = baseline
                    .join(format!("{base}-{model}"))
                    .join(format!("{index}.verdict"));
                if verdict_at(&verdict)? != Outcome::Pass {
                    return Ok(None);
                }
            }
            judged.push((base.to_string(), test.to_string(), seed));
        }
        if !found {
            return Ok(None);
        }
    }
    Ok(Some(judged))
}

/// The runs [`baseline`] found, one `base<TAB>test<TAB>seed` line each.
pub fn render_runs(runs: &[JudgedRun]) -> String {
    runs.iter()
        .map(|(base, test, seed)| {
            let seed = seed.map_or_else(|| "-".to_string(), |seed| seed.to_string());
            format!("{base}\t{test}\t{seed}\n")
        })
        .collect()
}

/// The judgement of the mutant whose runs are under `directory`, a
/// directory per model holding each run's `<index>.test` and its outcome;
/// none when a model has no runs or a run never started
/// ([`outcome::judged`]).
pub fn judgement(directory: &Path, models: &[&str]) -> Result<Option<Judgement>, String> {
    let mut outcomes = Vec::new();
    for model in models {
        let dir = directory.join(model);
        let entries = match std::fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(format!("{}: {error}", dir.display())),
        };
        let mut indices = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|error| format!("{}: {error}", dir.display()))?;
            let name = entry.file_name();
            let Some(index) = name.to_str().and_then(|name| name.strip_suffix(".test")) else {
                continue;
            };
            indices.push(
                index
                    .parse::<usize>()
                    .map_err(|_| format!("{}: no run index {index:?}", dir.display()))?,
            );
        }
        if indices.is_empty() {
            return Ok(None);
        }
        indices.sort_unstable();
        for index in indices {
            outcomes.push(outcome_at(&dir.join(format!("{index}.outcome")))?);
        }
    }
    Ok(outcome::judged(outcomes))
}

/// A row of the mutation campaign's Miri verdicts: the mutant's name and
/// its judgement.
pub fn verdict_row(name: &str, judgement: Judgement) -> String {
    format!("{name}\t{judgement}\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(path: &Path, text: &str) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }

    fn logs(name: &str) -> std::path::PathBuf {
        let root =
            std::env::temp_dir().join(format!("dcbor-gate-miri-{name}-{}", std::process::id()));
        if root.exists() {
            std::fs::remove_dir_all(&root).unwrap();
        }
        root
    }

    /// A line's suite verdicts and each run under each model become rows; a
    /// run that left no outcome is not run, never passed; every row that is
    /// not a pass is named by the verdict.
    #[test]
    fn every_run_and_verdict_is_a_row() {
        let root = logs("results");
        write(
            &root.join("lines.tsv"),
            "all-features-x\tall-features\trace\n",
        );
        write(&root.join("all-features-x.runs"), "t\t0\nt\t1\n");
        write(&root.join("all-features-x-native.verdict"), "pass\n");
        write(&root.join("all-features-x-stacked.verdict"), "fail\n");
        write(&root.join("all-features-x-stacked/0.outcome"), "pass\n");
        write(
            &root.join("all-features-x-stacked/0.measure"),
            "2048 1.50\n",
        );
        write(
            &root.join("all-features-x-stacked/1.outcome"),
            "undefined_behavior\n",
        );
        write(
            &root.join("all-features-x-stacked/1.measure"),
            "Command terminated by signal 6\n4096 2.25\n",
        );
        let rows = results(&root, &["stacked"]).unwrap();
        let shape: Vec<(&str, &str, Option<u64>, Outcome)> = rows
            .iter()
            .map(|row| {
                (
                    row.runner.as_str(),
                    row.test.as_str(),
                    row.seed,
                    row.outcome,
                )
            })
            .collect();
        assert_eq!(
            shape,
            vec![
                ("native", "(suite)", None, Outcome::Pass),
                ("stacked", "(suite)", None, Outcome::Failed),
                ("stacked", "t", Some(0), Outcome::Pass),
                ("stacked", "t", Some(1), Outcome::UndefinedBehavior),
            ]
        );
        assert_eq!(
            (rows[2].seconds.as_deref(), rows[2].peak_kb),
            (Some("1.50"), Some(2048))
        );
        assert_eq!(
            (rows[3].seconds.as_deref(), rows[3].peak_kb),
            (Some("2.25"), Some(4096))
        );
        assert_eq!(
            crate::rows::verdict(&rows),
            vec![
                "all-features-x stacked (suite) (suite): failed, where pass was planned".to_string(),
                "all-features-x stacked t, seed 1 (normal): undefined_behavior, where pass was planned"
                    .to_string(),
            ]
        );
        std::fs::remove_file(root.join("all-features-x-stacked/1.outcome")).unwrap();
        std::fs::remove_file(root.join("all-features-x-stacked/1.measure")).unwrap();
        let rows = results(&root, &["stacked"]).unwrap();
        assert_eq!((rows[3].outcome, rows[3].peak_kb), (Outcome::NotRun, None));
        std::fs::remove_dir_all(&root).unwrap();
    }

    /// A listed line without its runs, a malformed measurement and an
    /// unknown outcome are a broken gate, never a row.
    #[test]
    fn missing_or_malformed_run_files_are_refused() {
        let root = logs("malformed");
        write(&root.join("lines.tsv"), "b\tall-features\ttest\n");
        assert!(
            results(&root, &["stacked"])
                .unwrap_err()
                .contains("b.runs: missing")
        );
        write(&root.join("b.runs"), "t\t-\n");
        write(&root.join("b-stacked/0.measure"), "garbage\n");
        assert!(
            results(&root, &["stacked"])
                .unwrap_err()
                .contains("no measurement")
        );
        write(&root.join("b-stacked/0.measure"), "1 2\n");
        write(&root.join("b-stacked/0.outcome"), "caught\n");
        assert!(
            results(&root, &["stacked"])
                .unwrap_err()
                .contains("no outcome")
        );
        write(&root.join("b.runs"), "t\tx\n");
        assert!(
            results(&root, &["stacked"])
                .unwrap_err()
                .contains("no seed")
        );
        std::fs::remove_dir_all(&root).unwrap();
    }

    /// A mutant is judged over every model's runs, and not at all when a run
    /// never started; a baseline lacking a pass of any run of a judged test
    /// under any model, or lacking the test, decides nothing; every seed of
    /// a judged test is judged.
    #[test]
    fn a_mutant_is_judged_only_against_a_complete_baseline() {
        let root = logs("judge");
        let models = ["stacked", "tree"];
        for model in models {
            write(&root.join(format!("mutant/{model}/0.test")), "b\tt\t-\n");
            write(&root.join(format!("mutant/{model}/0.outcome")), "pass\n");
            write(
                &root.join(format!("baseline/b-{model}/0.verdict")),
                "pass\n",
            );
            write(
                &root.join(format!("baseline/b-{model}/1.verdict")),
                "pass\n",
            );
        }
        write(&root.join("baseline/b.runs"), "t\t0\nt\t1\n");
        assert_eq!(
            judgement(&root.join("mutant"), &models).unwrap(),
            Some(Judgement::MissedUnderMiri)
        );
        write(&root.join("mutant/tree/0.outcome"), "failed\n");
        assert_eq!(
            judgement(&root.join("mutant"), &models).unwrap(),
            Some(Judgement::CaughtUnderMiri)
        );
        std::fs::remove_file(root.join("mutant/tree/0.outcome")).unwrap();
        assert_eq!(judgement(&root.join("mutant"), &models).unwrap(), None);
        let found = baseline(&root.join("baseline"), "b\tt\n", &models).unwrap();
        assert_eq!(
            render_runs(&found.unwrap()),
            "b\tt\t0\nb\tt\t1\n".to_string()
        );
        write(&root.join("baseline/b-tree/1.verdict"), "fail\n");
        assert_eq!(
            baseline(&root.join("baseline"), "b\tt\n", &models).unwrap(),
            None
        );
        assert_eq!(
            baseline(&root.join("baseline"), "b\tother\n", &models).unwrap(),
            None
        );
        assert!(baseline(&root.join("baseline"), "\n", &models).is_err());
        assert_eq!(
            verdict_row("m", Judgement::NoBaseline),
            "m\tno_baseline\n".to_string()
        );
        std::fs::remove_dir_all(&root).unwrap();
    }
}
