//! The binary16 conversion's branch obligations (register item 4, the
//! numeric reduction): the Kani reduction proofs assume a conversion
//! contract (`src/float/proofs.rs`), and each production branch of half's
//! dispatch must be checked against it, exhaustively, by a run that took
//! that branch. The contract test ([`CONTRACT_TEST`]) prints one marker
//! line once its whole enumeration has passed:
//!
//! `DCBOR_F16_BRANCH<TAB>branch<TAB>target_arch<TAB>f16c at compile time<TAB>half`
//!
//! A marker is a report of dispatch conditions: it is evidence only when
//! those conditions agree with the build that produced it ([`Domain`]): a
//! recognized architecture, the host's, which every gated run (native, and
//! Miri interpreting the host target) is built for; a branch half 2.7.1
//! has on that architecture (`binary16/arch.rs` 14-83: `f16c` or `software`
//! on x86 and x86_64, `fp16` or `software` on aarch64, `software` on any
//! other); the compile-time f16c feature off, as in every gated build (no
//! gate passes `-C target-feature`; `tests/gate/src/cfgs.rs`); and the
//! `half` release `Cargo.lock` resolves, the one pin, which the contract
//! test itself asserts against (`the_branch_marker_names_the_resolved_half`).
//!
//! The obligations: the accelerated branch, `f16c`, from the native run;
//! the software branch, from the run under every Miri model the gate
//! selects. Each run must have passed and printed exactly one valid marker
//! naming its branch. A native run marked software leaves the accelerated
//! obligation unmet, named as unmet: it is never filled by another software
//! run. The obligations are rows of the gate's results ([`rows`]), so an
//! unmet one fails the persisted evidence, whatever the execution rows say.

use std::path::Path;

use crate::outcome::Outcome;
use crate::rows::{Evidence, Physical, Purpose, Row};

/// The marker the contract test prints.
pub const MARKER: &str = "DCBOR_F16_BRANCH";

/// The branch the accelerated obligation requires, and the software one's.
pub const ACCELERATED: &str = "f16c";
pub const SOFTWARE: &str = "software";

/// The contract test's fully qualified name in the library's test binary,
/// the Miri gate's line for it (`tests/miri-suites.txt`).
pub const CONTRACT_TEST: &str =
    "float::tests::every_f16_reduces_as_its_reference_and_decodes_only_if_canonical";

/// The branches half 2.7.1 dispatches to on `arch` (`binary16/arch.rs`
/// 14-83), or none for an architecture this table does not name.
fn branches(arch: &str) -> &'static [&'static str] {
    match arch {
        "x86" | "x86_64" => &[ACCELERATED, SOFTWARE],
        "aarch64" => &["fp16", SOFTWARE],
        _ => &[SOFTWARE],
    }
}

/// The architectures Rust names (`std::env::consts::ARCH`) that the marker
/// may report: any other string is no architecture.
const ARCHITECTURES: &[&str] = &[
    "x86",
    "x86_64",
    "arm",
    "aarch64",
    "loongarch64",
    "m68k",
    "csky",
    "mips",
    "mips32r6",
    "mips64",
    "mips64r6",
    "powerpc",
    "powerpc64",
    "riscv32",
    "riscv64",
    "s390x",
    "sparc",
    "sparc64",
    "hexagon",
    "wasm32",
    "wasm64",
];

/// What every marker of a gated run must report besides its branch: the
/// build domain the run was made in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Domain {
    /// The host's architecture, every gated run's target.
    pub arch: String,
    /// The `half` release `Cargo.lock` resolves.
    pub half: String,
}

impl Domain {
    /// The domain of a gate run under the repository `root`: the gate's own
    /// architecture, the host's, and the one `half` release `root`'s
    /// `Cargo.lock` resolves.
    pub fn of(root: &Path) -> Result<Self, String> {
        let path = root.join("Cargo.lock");
        let lock = std::fs::read_to_string(&path)
            .map_err(|error| format!("{}: {error}", path.display()))?;
        Ok(Self {
            arch: std::env::consts::ARCH.to_string(),
            half: resolved(&lock, "half")?,
        })
    }
}

/// The one version of `package` a `Cargo.lock` resolves: refused when it
/// resolves none or more than one, since a marker then names no one release.
pub fn resolved(lock: &str, package: &str) -> Result<String, String> {
    let named = format!("name = \"{package}\"");
    let mut versions = Vec::new();
    let mut lines = lock.lines();
    while let Some(line) = lines.next() {
        if line.trim() == named
            && let Some(version) = lines
                .next()
                .and_then(|next| next.trim().strip_prefix("version = \""))
                .and_then(|rest| rest.strip_suffix('"'))
        {
            versions.push(version.to_string());
        }
    }
    match &versions[..] {
        [version] => Ok(version.clone()),
        [] => Err(format!("Cargo.lock resolves no {package}")),
        _ => Err(format!(
            "Cargo.lock resolves {package} {}: a marker names one release",
            versions.join(", ")
        )),
    }
}

/// One marker line: the branch the run took and the conditions that chose
/// it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Branch {
    pub branch: String,
    pub arch: String,
    pub compiled_f16c: String,
    pub half: String,
}

impl Branch {
    /// Every way this marker disagrees with `domain`: an empty field, an
    /// architecture Rust does not name or not the build's, a branch half
    /// does not have there, the compile-time feature on, another release.
    fn faults(&self, domain: &Domain) -> Vec<String> {
        let mut faults = Vec::new();
        for (field, value) in [
            ("branch", &self.branch),
            ("architecture", &self.arch),
            ("compile-time f16c", &self.compiled_f16c),
            ("half release", &self.half),
        ] {
            if value.is_empty() {
                faults.push(format!("the marker's {field} is empty"));
            }
        }
        if !ARCHITECTURES.contains(&self.arch.as_str()) {
            faults.push(format!("{:?} is no architecture", self.arch));
        } else if self.arch != domain.arch {
            faults.push(format!(
                "the run reports {}, the gated build is {}",
                self.arch, domain.arch
            ));
        }
        if !branches(&self.arch).contains(&self.branch.as_str()) {
            faults.push(format!(
                "half has no {} branch on {}",
                self.branch, self.arch
            ));
        }
        if self.compiled_f16c != "off" {
            faults.push(format!(
                "compile-time f16c is {:?}; every gated build has it off",
                self.compiled_f16c
            ));
        }
        if self.half != domain.half {
            faults.push(format!(
                "the run reports half {}, Cargo.lock resolves {}",
                self.half, domain.half
            ));
        }
        faults
    }
}

/// The one marker of `log`: none when it printed none; refused when it
/// printed more than one or one not of five fields.
pub fn marker(log: &str) -> Result<Option<Branch>, String> {
    let lines: Vec<&str> = log
        .lines()
        .filter_map(|line| line.find(MARKER).map(|at| &line[at..]))
        .collect();
    match lines[..] {
        [] => Ok(None),
        [line] => match line.split('\t').collect::<Vec<_>>()[..] {
            [MARKER, branch, arch, compiled, half] => Ok(Some(Branch {
                branch: branch.to_string(),
                arch: arch.to_string(),
                compiled_f16c: compiled.to_string(),
                half: half.to_string(),
            })),
            _ => Err(format!("a malformed {MARKER} line: {line:?}")),
        },
        _ => Err(format!(
            "{} {MARKER} lines: one run prints one",
            lines.len()
        )),
    }
}

/// The faults of one obligation: `name`, its `branch`, its run (`outcome`,
/// `log`) in `domain`. Empty when it is met.
pub fn obligation(
    name: &str,
    branch: &str,
    (outcome, log): (Outcome, &str),
    domain: &Domain,
) -> Vec<String> {
    if outcome != Outcome::Pass {
        return vec![format!(
            "the {name} obligation is unmet: its run was {outcome}, not a pass"
        )];
    }
    let found = match marker(log) {
        Err(fault) => return vec![format!("the {name} obligation: {fault}")],
        Ok(None) => {
            return vec![format!(
                "the {name} obligation is unmet: the run printed no {MARKER}"
            )];
        }
        Ok(Some(found)) => found,
    };
    let mut faults: Vec<String> = found
        .faults(domain)
        .into_iter()
        .map(|fault| format!("the {name} obligation: {fault}"))
        .collect();
    if found.branch != branch {
        faults.push(format!(
            "the {name} obligation is unmet: the run took the {} branch, not {branch}",
            found.branch
        ));
    }
    faults
}

/// The obligations of the Miri gate run whose logs are `logs`
/// (`tests/miri-owned.sh`) under `root`, as rows of its results: the one
/// selection line whose runs name [`CONTRACT_TEST`]; its native run
/// (`<base>-native.verdict`, `.log`) held once to the accelerated
/// obligation, a row of runner `native`; its run under each of `models`
/// (`<base>-<model>/<index>.outcome`, `.log`) held to the software one, a
/// row of that model. A row passes exactly when its obligation is met;
/// every fault is returned beside the rows. Refused when no model is
/// selected, a model is not the gate's ([`crate::miri::MIRI_MODELS`]), or
/// the selection names the test on no line or on two.
pub fn rows(root: &Path, logs: &Path, models: &[&str]) -> Result<(Vec<Row>, Vec<String>), String> {
    if models.is_empty() {
        return Err("the branch obligations need the software run of at least one model".into());
    }
    if let Some(unknown) = models
        .iter()
        .find(|model| !crate::miri::MIRI_MODELS.contains(model))
    {
        return Err(format!(
            "no Miri model {unknown}; the models are {}",
            crate::miri::MIRI_MODELS.join(", ")
        ));
    }
    let domain = Domain::of(root)?;
    let mut found = Vec::new();
    for line in crate::miri::lines(logs)? {
        for (index, (test, _)) in crate::miri::runs(logs, &line.base)?.into_iter().enumerate() {
            if test == CONTRACT_TEST {
                found.push((line.clone(), index));
            }
        }
    }
    let [(line, index)] = &found[..] else {
        return Err(format!(
            "{} selection lines run {CONTRACT_TEST}; its branch obligations need exactly one",
            found.len()
        ));
    };
    let read = |path: std::path::PathBuf| -> Result<String, String> {
        match std::fs::read_to_string(&path) {
            Ok(text) => Ok(text),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
            Err(error) => Err(format!("{}: {error}", path.display())),
        }
    };
    let row = |runner: &str, met: bool| {
        Row {
            domain: line.domain.clone(),
            line: format!("{}-branch", line.base),
            runner: runner.to_string(),
            test: CONTRACT_TEST.to_string(),
            seed: None,
            purpose: Purpose::Normal,
            bound: None,
            stack: None,
            expected: Some(Outcome::Pass),
            outcome: if met { Outcome::Pass } else { Outcome::Failed },
            seconds: None,
            peak_kb: None,
            physical: Physical::NotApplicable,
            evidence: Evidence::Unverified,
        }
        .classified()
    };
    let mut rows = Vec::new();
    let mut faults = Vec::new();
    let native = (
        crate::miri::verdict_at(&logs.join(format!("{}-native.verdict", line.base)))?,
        read(logs.join(format!("{}-native.log", line.base)))?,
    );
    let accelerated = obligation("accelerated", ACCELERATED, (native.0, &native.1), &domain);
    rows.push(row("native", accelerated.is_empty()));
    faults.extend(
        accelerated
            .into_iter()
            .map(|fault| format!("native: {fault}")),
    );
    for model in models {
        let directory = logs.join(format!("{}-{model}", line.base));
        let outcome = crate::miri::outcome_at(&directory.join(format!("{index}.outcome")))?;
        let log = read(directory.join(format!("{index}.log")))?;
        let software = obligation("software", SOFTWARE, (outcome, &log), &domain);
        rows.push(row(model, software.is_empty()));
        faults.extend(
            software
                .into_iter()
                .map(|fault| format!("{model}: {fault}")),
        );
    }
    Ok((rows, faults))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn domain() -> Domain {
        Domain {
            arch: "x86_64".to_string(),
            half: "2.7.1".to_string(),
        }
    }

    fn log(branch: &str, arch: &str, compiled: &str, half: &str) -> String {
        format!(
            "running 1 test\ntest {CONTRACT_TEST} ... {MARKER}\t{branch}\t{arch}\t{compiled}\t{half}\nok\n"
        )
    }

    fn met(branch: &str) -> String {
        log(branch, "x86_64", "off", "2.7.1")
    }

    /// Both obligations met on the gated build's domain.
    #[test]
    fn a_marker_of_the_gated_build_meets_its_obligation() {
        assert!(
            obligation(
                "accelerated",
                ACCELERATED,
                (Outcome::Pass, &met("f16c")),
                &domain()
            )
            .is_empty()
        );
        assert!(
            obligation(
                "software",
                SOFTWARE,
                (Outcome::Pass, &met("software")),
                &domain()
            )
            .is_empty()
        );
    }

    /// The planted cases, each refused: a native run on a host without
    /// f16c; a failed run; no marker; two markers; a malformed one; an
    /// impossible architecture and branch pair; an empty field; another
    /// architecture than the build's; compile-time f16c on; and a release
    /// both runs name alike but Cargo.lock does not resolve.
    #[test]
    fn every_marker_disagreeing_with_its_build_is_refused() {
        let d = domain();
        let unmet = obligation(
            "accelerated",
            ACCELERATED,
            (Outcome::Pass, &met("software")),
            &d,
        );
        assert_eq!(
            unmet,
            ["the accelerated obligation is unmet: the run took the software branch, not f16c"]
        );
        assert!(
            obligation(
                "accelerated",
                ACCELERATED,
                (Outcome::Failed, &met("f16c")),
                &d
            )[0]
            .contains("its run was failed")
        );
        assert!(
            obligation("software", SOFTWARE, (Outcome::Pass, "ok\n"), &d)[0].contains("printed no")
        );
        let twice = format!("{}{}", met("f16c"), met("f16c"));
        assert!(
            obligation("accelerated", ACCELERATED, (Outcome::Pass, &twice), &d)[0]
                .contains("2 DCBOR_F16_BRANCH")
        );
        let malformed = format!("{MARKER}\tf16c\tx86_64\n");
        assert!(
            obligation("accelerated", ACCELERATED, (Outcome::Pass, &malformed), &d)[0]
                .contains("malformed")
        );
        let impossible = Domain {
            arch: "aarch64".to_string(),
            ..d.clone()
        };
        let pair = obligation(
            "accelerated",
            ACCELERATED,
            (Outcome::Pass, &log("f16c", "aarch64", "off", "2.7.1")),
            &impossible,
        );
        assert!(
            pair.iter()
                .any(|fault| fault.contains("half has no f16c branch on aarch64")),
            "{pair:?}"
        );
        let empty = obligation(
            "software",
            SOFTWARE,
            (Outcome::Pass, &log("software", "", "off", "")),
            &d,
        );
        assert!(
            empty
                .iter()
                .any(|fault| fault.contains("architecture is empty")),
            "{empty:?}"
        );
        assert!(
            empty
                .iter()
                .any(|fault| fault.contains("half release is empty")),
            "{empty:?}"
        );
        let other = obligation(
            "software",
            SOFTWARE,
            (Outcome::Pass, &log("software", "x86", "off", "2.7.1")),
            &d,
        );
        assert!(
            other
                .iter()
                .any(|fault| fault.contains("the gated build is x86_64")),
            "{other:?}"
        );
        let compiled = obligation(
            "accelerated",
            ACCELERATED,
            (Outcome::Pass, &log("f16c", "x86_64", "on", "2.7.1")),
            &d,
        );
        assert!(
            compiled
                .iter()
                .any(|fault| fault.contains("every gated build has it off")),
            "{compiled:?}"
        );
        let wrong = log("software", "x86_64", "off", "2.6.0");
        for (name, branch, text) in [
            (
                "accelerated",
                ACCELERATED,
                wrong.replace("software", "f16c"),
            ),
            ("software", SOFTWARE, wrong),
        ] {
            let faults = obligation(name, branch, (Outcome::Pass, &text), &d);
            assert!(
                faults
                    .iter()
                    .any(|fault| fault.contains("Cargo.lock resolves 2.7.1")),
                "{faults:?}"
            );
        }
    }

    /// The release is read from a lock as Cargo writes it: one entry named,
    /// none, or two refused.
    #[test]
    fn the_resolved_release_is_the_locks_one_entry() {
        let lock = "[[package]]\nname = \"half\"\nversion = \"2.7.1\"\n\n[[package]]\nname = \"hex\"\nversion = \"0.4.3\"\n";
        assert_eq!(resolved(lock, "half"), Ok("2.7.1".to_string()));
        assert!(
            resolved(lock, "serde")
                .unwrap_err()
                .contains("resolves no serde")
        );
        let two = format!("{lock}\n[[package]]\nname = \"half\"\nversion = \"1.8.3\"\n");
        assert!(resolved(&two, "half").unwrap_err().contains("2.7.1, 1.8.3"));
    }

    /// The gate's run of the obligations, end to end over a logs tree: every
    /// execution row of the line passes, but the native run took the
    /// software branch, so the accelerated row fails and the verdict over
    /// the results names it; an empty model selection and a model the gate
    /// does not run are refused.
    #[test]
    fn an_unmet_obligation_fails_the_results_whatever_the_execution_rows() {
        let root = std::env::temp_dir().join(format!("dcbor-gate-branches-{}", std::process::id()));
        if root.exists() {
            std::fs::remove_dir_all(&root).unwrap();
        }
        let write = |path: &Path, text: &str| {
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, text).unwrap();
        };
        let logs = root.join("logs");
        write(
            &root.join("Cargo.lock"),
            "[[package]]\nname = \"half\"\nversion = \"2.7.1\"\n",
        );
        write(&logs.join("lines.tsv"), "f\tall-features\ttest\n");
        write(&logs.join("f.runs"), &format!("{CONTRACT_TEST}\t-\n"));
        write(&logs.join("f-native.verdict"), "pass\n");
        let host = std::env::consts::ARCH;
        write(
            &logs.join("f-native.log"),
            &log("software", host, "off", "2.7.1"),
        );
        write(&logs.join("f-stacked/0.outcome"), "pass\n");
        write(
            &logs.join("f-stacked/0.log"),
            &log("software", host, "off", "2.7.1"),
        );
        let (rows, faults) = rows(&root, &logs, &["stacked"]).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(
            (rows[0].runner.as_str(), rows[0].outcome),
            ("native", Outcome::Failed)
        );
        assert_eq!(
            (rows[1].runner.as_str(), rows[1].outcome),
            ("stacked", Outcome::Pass)
        );
        assert!(
            faults[0].starts_with("native: the accelerated obligation is unmet"),
            "{faults:?}"
        );
        assert_eq!(
            crate::rows::verdict(&rows).len(),
            1,
            "the unmet obligation fails the verdict"
        );
        assert!(
            super::rows(&root, &logs, &[])
                .unwrap_err()
                .contains("at least one model")
        );
        assert!(
            super::rows(&root, &logs, &["shadow"])
                .unwrap_err()
                .contains("no Miri model shadow")
        );
        std::fs::remove_dir_all(&root).unwrap();
    }
}
