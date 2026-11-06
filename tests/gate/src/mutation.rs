//! The mutation campaign's verdicts (`tests/mutation-evidence.sh`): the
//! complete cargo-mutants outcomes of one domain's two layers compared, the
//! Miri layer's plan, and the run's verdict.
//!
//! A mutant missed by both layers is a defect of the suite unless the
//! registry of equivalent mutants (`tests/mutation-equivalents.json`)
//! declares it: a declaration names one mutant by the domain it exists in,
//! its file, its mutation, the source text its diff removes and the text it
//! puts in its place, never by line and column, with the reason no behavior
//! distinguishes it and the scope of that reason. The mutated text carries
//! the tool's change marker, so a tool version that renders mutants
//! differently makes declarations stale rather than silently matching. A
//! declaration that matches no mutant (stale) or more than one (ambiguous),
//! a duplicate, and a declared mutant some layer does not miss are each
//! rejected: equivalence is a claim to reconcile, never a silent exemption.
//!
//! A native run cannot see undefined behavior, so a survivor in a module
//! that holds `unsafe`, or in a descendant of one (`dcbor_census`), is
//! judged under Miri, both aliasing models, on exactly the tests whose
//! execution reaches its mutated span (`reach`, `tests/miri-owned.sh
//! --judge`). Its judgement ([`Judgement`]) is caught or missed under Miri,
//! no baseline, or unreached under Miri; a planned mutant without a verdict
//! is undecided, a verdict for no planned mutant stale, two for one a
//! duplicate. Only caught and missed decide; every other fails the run.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::domains;
use crate::outcome::Judgement;
use crate::reach;

/// The fields of a declaration of an equivalent mutant, each nonempty text.
pub const FIELDS: [&str; 7] = [
    "domain",
    "file",
    "mutation",
    "source",
    "mutated",
    "rationale",
    "scope",
];

/// A mutant's outcome in one layer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Summary {
    CaughtMutant,
    MissedMutant,
    Unviable,
    Timeout,
}

impl Summary {
    fn parse(text: &str) -> Option<Self> {
        match text {
            "CaughtMutant" => Some(Self::CaughtMutant),
            "MissedMutant" => Some(Self::MissedMutant),
            "Unviable" => Some(Self::Unviable),
            "Timeout" => Some(Self::Timeout),
            _ => None,
        }
    }

    fn measured(self) -> bool {
        matches!(self, Self::CaughtMutant | Self::MissedMutant)
    }
}

/// One layer's complete run: every planned mutant, by name, as cargo-mutants
/// planned it, its outcome, and the tool's version.
#[derive(Debug, PartialEq)]
pub struct Layer {
    pub mutants: BTreeMap<String, Map<String, Value>>,
    pub outcomes: BTreeMap<String, Summary>,
    pub version: String,
}

fn read(path: &Path) -> Result<String, String> {
    std::fs::read_to_string(path).map_err(|error| format!("{}: {error}", path.display()))
}

fn json_file(path: &Path) -> Result<Value, String> {
    serde_json::from_str(&read(path)?).map_err(|error| format!("{}: {error}", path.display()))
}

fn text<'v>(object: &'v Map<String, Value>, field: &str, what: &str) -> Result<&'v str, String> {
    object
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{what} has no text {field}"))
}

/// Publish `value` as JSON at `path`, whole (`dcbor_record::publish`).
pub fn publish(path: &Path, value: &impl Serialize) -> Result<(), String> {
    let data = serde_json::to_string_pretty(value)
        .map_err(|error| format!("{}: {error}", path.display()))?;
    dcbor_record::publish(
        path.to_str()
            .ok_or_else(|| format!("{}: not UTF-8", path.display()))?,
        &format!("{data}\n"),
    );
    Ok(())
}

/// The layer cargo-mutants wrote to `directory` (`mutants.json`,
/// `outcomes.json` and each mutant's diff): complete, every result one of a
/// planned mutant with the plan's mutation and diff, one successful
/// unmutated baseline, and every outcome a known one.
pub fn load(directory: &Path) -> Result<Layer, String> {
    let shown = directory.display();
    let planned = json_file(&directory.join("mutants.json"))?;
    let planned = planned
        .as_array()
        .ok_or_else(|| format!("{shown}: the plan is no list"))?;
    let mut mutants = BTreeMap::new();
    for mutant in planned {
        let mutant = mutant
            .as_object()
            .ok_or_else(|| format!("{shown}: a planned mutant is no object"))?;
        let name = text(mutant, "name", "a planned mutant")?.to_string();
        text(mutant, "diff", "a planned mutant")?;
        if mutants.insert(name.clone(), mutant.clone()).is_some() {
            return Err(format!("{shown}: duplicate mutant {name}"));
        }
    }
    if mutants.is_empty() {
        return Err(format!("{shown}: empty mutation domain"));
    }
    let report = json_file(&directory.join("outcomes.json"))?;
    let report = report
        .as_object()
        .ok_or_else(|| format!("{shown}: the outcomes are no object"))?;
    let mut summaries: BTreeMap<String, String> = BTreeMap::new();
    let mut baselines = Vec::new();
    for outcome in report
        .get("outcomes")
        .and_then(Value::as_array)
        .ok_or_else(|| format!("{shown}: no outcomes"))?
    {
        let outcome = outcome
            .as_object()
            .ok_or_else(|| format!("{shown}: an outcome is no object"))?;
        let summary = text(outcome, "summary", "an outcome")?;
        let scenario = outcome
            .get("scenario")
            .ok_or_else(|| format!("{shown}: an outcome has no scenario"))?;
        if scenario.as_str() == Some("Baseline") {
            baselines.push(summary.to_string());
            continue;
        }
        let described = scenario
            .get("Mutant")
            .and_then(Value::as_object)
            .ok_or_else(|| format!("{shown}: a scenario is neither the baseline nor a mutant"))?;
        let name = text(described, "name", "a mutant scenario")?;
        let Some(planned) = mutants.get(name) else {
            return Err(format!("{shown}: duplicated or unplanned result {name}"));
        };
        if summaries.contains_key(name) {
            return Err(format!("{shown}: duplicated or unplanned result {name}"));
        }
        let mut descriptor = planned.clone();
        descriptor.remove("diff");
        if *described != descriptor {
            return Err(format!("{shown}: changed mutation for {name}"));
        }
        let diff = read(&directory.join(text(outcome, "diff_path", "a mutant outcome")?))?;
        if Some(diff.as_str()) != planned.get("diff").and_then(Value::as_str) {
            return Err(format!(
                "{shown}: mutation diff does not match its plan: {name}"
            ));
        }
        summaries.insert(name.to_string(), summary.to_string());
    }
    if baselines != ["Success"] {
        return Err(format!(
            "{shown}: a successful unmutated baseline is required"
        ));
    }
    let total = report.get("total_mutants").and_then(Value::as_u64);
    if !summaries.keys().eq(mutants.keys()) || total != u64::try_from(mutants.len()).ok() {
        return Err(format!("{shown}: incomplete mutation execution"));
    }
    let outcomes = summaries
        .into_iter()
        .map(|(name, summary)| {
            Summary::parse(&summary)
                .map(|summary| (name, summary))
                .ok_or_else(|| format!("{shown}: unknown or failed mutation outcome"))
        })
        .collect::<Result<_, _>>()?;
    let version = report
        .get("cargo_mutants_version")
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{shown}: no cargo_mutants_version"))?
        .to_string();
    Ok(Layer {
        mutants,
        outcomes,
        version,
    })
}

/// The trimmed lines of `diff` that `mark` (`-` or `+`) introduces, headers
/// excluded, joined by newlines.
fn changed(diff: &str, mark: char) -> String {
    let header: String = core::iter::repeat_n(mark, 3).collect();
    diff.lines()
        .filter(|line| line.starts_with(mark) && !line.starts_with(&header))
        .map(|line| line[mark.len_utf8()..].trim())
        .collect::<Vec<_>>()
        .join("\n")
}

/// A mutant's identity without its position: its file, its mutation as
/// named after the position, the source lines its diff removes, and the
/// lines it adds in their place.
fn identity(mutant: &Map<String, Value>) -> Result<[String; 4], String> {
    let name = text(mutant, "name", "a mutant")?;
    let (_, mutation) = name
        .split_once(": ")
        .ok_or_else(|| format!("unrecognized mutant name: {name}"))?;
    let diff = text(mutant, "diff", "a mutant")?;
    Ok([
        text(mutant, "file", "a mutant")?.to_string(),
        mutation.to_string(),
        changed(diff, '-'),
        changed(diff, '+'),
    ])
}

/// A declaration of an equivalent mutant.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Declaration {
    pub domain: String,
    pub file: String,
    pub mutation: String,
    pub source: String,
    pub mutated: String,
    pub rationale: String,
    pub scope: String,
}

/// The registry at `registry` read: every declaration complete, distinct and
/// of a known domain.
pub fn declarations(registry: &Path) -> Result<Vec<Declaration>, String> {
    let shown = registry.display();
    let value = json_file(registry)?;
    let list = value
        .as_array()
        .ok_or_else(|| format!("{shown}: the registry is a list of declarations"))?;
    let mut seen = BTreeSet::new();
    let mut declarations = Vec::new();
    for declaration in list {
        let complete = declaration.as_object().is_some_and(|object| {
            object.len() == FIELDS.len() && FIELDS.iter().all(|field| object.contains_key(*field))
        });
        if !complete {
            return Err(format!("{shown}: a declaration has exactly {FIELDS:?}"));
        }
        let declaration: Declaration = serde_json::from_value(declaration.clone())
            .map_err(|_| format!("{shown}: every declaration field is nonempty text"))?;
        let fields = [
            &declaration.domain,
            &declaration.file,
            &declaration.mutation,
            &declaration.source,
            &declaration.mutated,
            &declaration.rationale,
            &declaration.scope,
        ];
        if fields.iter().any(|field| field.is_empty()) {
            return Err(format!("{shown}: every declaration field is nonempty text"));
        }
        if domains::domain(&declaration.domain).is_err() {
            return Err(format!(
                "{shown}: unknown domain {:?}: the domains are {}",
                declaration.domain,
                domains::names()
            ));
        }
        let key = (
            declaration.domain.clone(),
            declaration.file.clone(),
            declaration.mutation.clone(),
            declaration.source.clone(),
            declaration.mutated.clone(),
        );
        if !seen.insert(key.clone()) {
            return Err(format!("{shown}: duplicate declaration {key:?}"));
        }
        declarations.push(declaration);
    }
    Ok(declarations)
}

/// The mutants of `mutants`, of the domain `name`, the registry declares
/// equivalent, by mutant name, each with its declaration. Each of this
/// domain's declarations must match exactly one mutant.
pub fn equivalents(
    registry: &Path,
    name: &str,
    mutants: &BTreeMap<String, Map<String, Value>>,
) -> Result<BTreeMap<String, Declaration>, String> {
    domains::domain(name).map_err(|_| {
        format!(
            "unknown mutation domain {name:?}: the domains are {}",
            domains::names()
        )
    })?;
    let mut by_identity: BTreeMap<[String; 4], Vec<&str>> = BTreeMap::new();
    for (mutant_name, mutant) in mutants {
        by_identity
            .entry(identity(mutant)?)
            .or_default()
            .push(mutant_name);
    }
    let shown = registry.display();
    let mut declared = BTreeMap::new();
    for declaration in declarations(registry)? {
        if declaration.domain != name {
            continue;
        }
        let key = [
            declaration.file.clone(),
            declaration.mutation.clone(),
            declaration.source.clone(),
            declaration.mutated.clone(),
        ];
        match by_identity.get(&key).map(Vec::as_slice) {
            None | Some([]) => {
                return Err(format!(
                    "{shown}: stale declaration, no mutant is {name} {key:?}"
                ));
            }
            Some([one]) => {
                declared.insert((*one).to_string(), declaration);
            }
            Some(many) => {
                return Err(format!(
                    "{shown}: ambiguous declaration {key:?} matches {many:?}"
                ));
            }
        }
    }
    Ok(declared)
}

/// A declared equivalent's reason and its scope.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Equivalent {
    pub rationale: String,
    pub scope: String,
}

/// A mutant's outcome in each layer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pair {
    pub fast: Summary,
    pub exhaustive: Summary,
}

/// One domain's native comparison: `comparison.json`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Comparison {
    pub cargo_mutants_version: String,
    pub domain: String,
    pub mutants: usize,
    pub comparable_viable: usize,
    pub fast_caught: usize,
    pub exhaustive_caught: usize,
    pub unviable: Vec<String>,
    pub fast_missed_exhaustive_caught: Vec<String>,
    pub fast_caught_exhaustive_missed: Vec<String>,
    pub timeouts: Vec<String>,
    pub viability_disagreements: Vec<String>,
    pub equivalent: BTreeMap<String, Equivalent>,
    pub equivalents_refuted: Vec<String>,
    pub undeclared_survivors: Vec<String>,
    pub outcomes: BTreeMap<String, Pair>,
}

impl Comparison {
    /// Whether the native layers agree on a nonempty measured domain, with no
    /// timeout, no viability disagreement and no refuted equivalent.
    pub fn native(&self) -> bool {
        self.comparable_viable > 0
            && self.timeouts.is_empty()
            && self.viability_disagreements.is_empty()
            && self.fast_missed_exhaustive_caught.is_empty()
            && self.fast_caught_exhaustive_missed.is_empty()
            && self.equivalents_refuted.is_empty()
    }

    /// The native comparison alone passes: [`Comparison::native`] and no
    /// undeclared survivor.
    pub fn passed(&self) -> bool {
        self.native() && self.undeclared_survivors.is_empty()
    }
}

/// The comparison of one domain's layers, `fast` and `exhaustive`, under
/// `registry`'s declarations of the domain `name`.
pub fn compare(
    fast: &Path,
    exhaustive: &Path,
    registry: &Path,
    name: &str,
) -> Result<Comparison, String> {
    let fast = load(fast)?;
    let exhaustive = load(exhaustive)?;
    if fast.mutants != exhaustive.mutants || fast.version != exhaustive.version {
        return Err("layers must run the same mutant diffs with the same tool version".to_string());
    }
    let declared = equivalents(registry, name, &fast.mutants)?;
    let outcomes: BTreeMap<String, Pair> = fast
        .mutants
        .keys()
        .map(|mutant| {
            let pair = Pair {
                fast: fast.outcomes[mutant],
                exhaustive: exhaustive.outcomes[mutant],
            };
            (mutant.clone(), pair)
        })
        .collect();
    let select = |keep: &dyn Fn(Pair) -> bool| -> Vec<String> {
        outcomes
            .iter()
            .filter(|(_, pair)| keep(**pair))
            .map(|(mutant, _)| mutant.clone())
            .collect()
    };
    let measured: Vec<Pair> = outcomes
        .values()
        .copied()
        .filter(|pair| pair.fast.measured() && pair.exhaustive.measured())
        .collect();
    let missed = select(&|pair| {
        pair.fast == Summary::MissedMutant && pair.exhaustive == Summary::MissedMutant
    });
    Ok(Comparison {
        cargo_mutants_version: fast.version.clone(),
        domain: name.to_string(),
        mutants: fast.mutants.len(),
        comparable_viable: measured.len(),
        fast_caught: measured
            .iter()
            .filter(|pair| pair.fast == Summary::CaughtMutant)
            .count(),
        exhaustive_caught: measured
            .iter()
            .filter(|pair| pair.exhaustive == Summary::CaughtMutant)
            .count(),
        unviable: select(&|pair| {
            pair.fast == Summary::Unviable && pair.exhaustive == Summary::Unviable
        }),
        fast_missed_exhaustive_caught: select(&|pair| {
            pair.exhaustive == Summary::CaughtMutant && pair.fast != Summary::CaughtMutant
        }),
        fast_caught_exhaustive_missed: select(&|pair| {
            pair.fast == Summary::CaughtMutant && pair.exhaustive != Summary::CaughtMutant
        }),
        timeouts: select(&|pair| {
            pair.fast == Summary::Timeout || pair.exhaustive == Summary::Timeout
        }),
        viability_disagreements: select(&|pair| {
            (pair.fast == Summary::Unviable) != (pair.exhaustive == Summary::Unviable)
        }),
        equivalent: declared
            .iter()
            .filter(|(name, _)| missed.contains(name))
            .map(|(name, declaration)| {
                (
                    name.clone(),
                    Equivalent {
                        rationale: declaration.rationale.clone(),
                        scope: declaration.scope.clone(),
                    },
                )
            })
            .collect(),
        // A declared equivalent compiles and no layer detects it; anything
        // else refutes the declaration.
        equivalents_refuted: declared
            .keys()
            .filter(|name| !missed.contains(name))
            .cloned()
            .collect(),
        undeclared_survivors: missed
            .iter()
            .filter(|name| !declared.contains_key(*name))
            .cloned()
            .collect(),
        outcomes,
    })
}

/// A survivor planned under Miri: its index in the plan, its module, and the
/// tests reaching it, each `[line, test]`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Planned {
    pub index: usize,
    pub module: String,
    pub tests: Vec<[String; 2]>,
}

/// One domain's Miri plan: `plan.json`, beside `plan.tsv` and `diffs/`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Plan {
    pub domain: String,
    pub reach_identity: String,
    pub planned: BTreeMap<String, Planned>,
    pub unreached_under_miri: Vec<String>,
}

fn position(mutant: &Map<String, Value>, end: &str) -> Result<[usize; 2], String> {
    let at = mutant
        .get("span")
        .and_then(|span| span.get(end))
        .ok_or_else(|| format!("a mutant has no span {end}"))?;
    let number = |field: &str| {
        at.get(field)
            .and_then(Value::as_u64)
            .and_then(|value| usize::try_from(value).ok())
            .ok_or_else(|| format!("a mutant's span {end} has no {field}"))
    };
    Ok([number("line")?, number("column")?])
}

/// The Miri layer's plan for one domain, written to `plan_dir`: every mutant
/// both native layers missed whose span lies in a tainted module, with the
/// tests of the reach map at `reach_dir` whose executed regions overlap the
/// span; those no test reaches are unreached under Miri. The reach map must
/// be of this run's sources: its identity inputs begin with the snapshot
/// the mutation run took.
pub fn miri_plan(
    comparison: &Path,
    fast: &Path,
    snapshot: &Path,
    reach_dir: &Path,
    plan_dir: &Path,
    configuration: &str,
) -> Result<Plan, String> {
    let comparison: Comparison = serde_json::from_str(&read(comparison)?)
        .map_err(|error| format!("{}: {error}", comparison.display()))?;
    let layer = load(fast)?;
    if !read(&reach_dir.join("identity-inputs.txt"))?.starts_with(&read(snapshot)?) {
        return Err(format!(
            "{}: the reach map is of other sources than this run",
            reach_dir.display()
        ));
    }
    let map = reach::load(reach_dir)?;
    let (census, _) = reach::census(reach_dir, configuration)?;
    std::fs::create_dir_all(plan_dir.join("diffs"))
        .map_err(|error| format!("{}: {error}", plan_dir.display()))?;
    let mut planned = BTreeMap::new();
    let mut unreached = Vec::new();
    let mut lines = String::new();
    for (name, pair) in &comparison.outcomes {
        if (pair.fast, pair.exhaustive) != (Summary::MissedMutant, Summary::MissedMutant) {
            continue;
        }
        let mutant = layer
            .mutants
            .get(name)
            .ok_or_else(|| format!("{name}: compared but not in the layer's plan"))?;
        let file = text(mutant, "file", name)?;
        let (start, end) = (position(mutant, "start")?, position(mutant, "end")?);
        let module = dcbor_census::module_of(&census, file, start[0]).ok_or_else(|| {
            format!(
                "{name}: {file}:{} lies in no module of the census",
                start[0]
            )
        })?;
        if !module.tainted {
            continue;
        }
        // Only the suites of this domain's build: another build compiles
        // other code at the same lines.
        let mut tests = Vec::new();
        for (base, suite) in &map.suites {
            if suite.domain != comparison.domain {
                continue;
            }
            if suite.tests.len() != suite.reach.len() {
                return Err(format!(
                    "{base}: its tests and their reach differ in number"
                ));
            }
            for (test, executed) in suite.tests.iter().zip(&suite.reach) {
                let reaches = executed.get(file).is_some_and(|regions| {
                    regions
                        .iter()
                        .any(|region| reach::overlaps(region, start, end))
                });
                if reaches {
                    tests.push([base.clone(), test.clone()]);
                }
            }
        }
        if tests.is_empty() {
            unreached.push(name.clone());
            continue;
        }
        if name.contains(['\t', '\n']) {
            return Err(format!("a mutant name holds a tab or newline: {name:?}"));
        }
        let index = planned.len();
        let diff = plan_dir.join("diffs").join(format!("{index}.diff"));
        std::fs::write(&diff, text(mutant, "diff", name)?)
            .map_err(|error| format!("{}: {error}", diff.display()))?;
        let diff =
            std::fs::canonicalize(&diff).map_err(|error| format!("{}: {error}", diff.display()))?;
        lines.push_str(&format!("mutant\t{index}\t{name}\t{}\n", diff.display()));
        for [base, test] in &tests {
            lines.push_str(&format!("test\t{index}\t{base}\t{test}\n"));
        }
        planned.insert(
            name.clone(),
            Planned {
                index,
                module: module.module.clone(),
                tests,
            },
        );
    }
    let plan = Plan {
        domain: comparison.domain.clone(),
        reach_identity: map.identity.clone(),
        planned,
        unreached_under_miri: unreached,
    };
    let tsv = plan_dir.join("plan.tsv");
    dcbor_record::publish(tsv.to_str().ok_or("the plan's path is not UTF-8")?, &lines);
    publish(&plan_dir.join("plan.json"), &plan)?;
    Ok(plan)
}

/// One domain's run verdict: `verdict.json`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MiriVerdict {
    pub domain: String,
    pub reach_identity: String,
    pub caught_under_miri: Vec<String>,
    pub missed_under_miri: Vec<String>,
    pub unreached_under_miri: Vec<String>,
    pub no_baseline: Vec<String>,
    pub undecided: Vec<String>,
    pub stale: Vec<String>,
    pub duplicate: Vec<String>,
    pub undeclared_survivors: Vec<String>,
    pub undeclared_survivors_outside_unsafe_modules: Vec<String>,
    pub equivalents_refuted_under_miri: Vec<String>,
}

/// The run's verdict for one domain: the native comparison at
/// `comparison`, its survivors in tainted modules decided by their Miri
/// judgements (`verdicts`, the judge's `verdicts.tsv`) under the plan in
/// `plan_dir`.
pub fn miri_verdict(
    comparison: &Path,
    plan_dir: &Path,
    verdicts: &Path,
) -> Result<(MiriVerdict, bool), String> {
    let comparison: Comparison = serde_json::from_str(&read(comparison)?)
        .map_err(|error| format!("{}: {error}", comparison.display()))?;
    let plan_path = plan_dir.join("plan.json");
    let plan: Plan = serde_json::from_str(&read(&plan_path)?)
        .map_err(|error| format!("{}: {error}", plan_path.display()))?;
    if plan.domain != comparison.domain {
        return Err("the Miri plan is of another domain than the comparison".to_string());
    }
    let mut judged: BTreeMap<String, Judgement> = BTreeMap::new();
    let mut duplicate = BTreeSet::new();
    let mut stale = BTreeSet::new();
    for line in read(verdicts)?
        .lines()
        .filter(|line| !line.trim().is_empty())
    {
        let judgement = line.rsplit_once('\t').and_then(|(name, judgement)| {
            Judgement::parse(judgement)
                .filter(|judgement| *judgement != Judgement::UnreachedUnderMiri)
                .map(|judgement| (name, judgement))
        });
        let Some((name, judgement)) = judgement else {
            return Err(format!(
                "{}: unrecognized verdict line {line:?}",
                verdicts.display()
            ));
        };
        if !plan.planned.contains_key(name) {
            stale.insert(name.to_string());
        } else if judged.contains_key(name) {
            duplicate.insert(name.to_string());
        } else {
            judged.insert(name.to_string(), judgement);
        }
    }
    let of = |wanted: Judgement| -> Vec<String> {
        judged
            .iter()
            .filter(|(_, judgement)| **judgement == wanted)
            .map(|(name, _)| name.clone())
            .collect()
    };
    let caught = of(Judgement::CaughtUnderMiri);
    let tainted: BTreeSet<&String> = plan
        .planned
        .keys()
        .chain(&plan.unreached_under_miri)
        .collect();
    // A survivor of a tainted module is decided under Miri: caught there, it
    // is detected; missed there, it survives as it did natively.
    let undeclared: Vec<String> = comparison
        .undeclared_survivors
        .iter()
        .filter(|name| !caught.contains(name))
        .cloned()
        .collect();
    let mut unreached = plan.unreached_under_miri.clone();
    unreached.sort();
    let verdict = MiriVerdict {
        domain: comparison.domain.clone(),
        reach_identity: plan.reach_identity.clone(),
        missed_under_miri: of(Judgement::MissedUnderMiri),
        no_baseline: of(Judgement::NoBaseline),
        undecided: plan
            .planned
            .keys()
            .filter(|name| !judged.contains_key(*name))
            .cloned()
            .collect(),
        stale: stale.into_iter().collect(),
        duplicate: duplicate.into_iter().collect(),
        undeclared_survivors_outside_unsafe_modules: undeclared
            .iter()
            .filter(|name| !tainted.contains(name))
            .cloned()
            .collect(),
        // A declared equivalent Miri distinguishes is refuted.
        equivalents_refuted_under_miri: comparison
            .equivalent
            .keys()
            .filter(|name| caught.contains(name))
            .cloned()
            .collect(),
        undeclared_survivors: undeclared,
        unreached_under_miri: unreached,
        caught_under_miri: caught,
    };
    let passed = comparison.native()
        && verdict.unreached_under_miri.is_empty()
        && verdict.no_baseline.is_empty()
        && verdict.undecided.is_empty()
        && verdict.stale.is_empty()
        && verdict.duplicate.is_empty()
        && verdict.undeclared_survivors.is_empty()
        && verdict.equivalents_refuted_under_miri.is_empty();
    Ok((verdict, passed))
}

#[cfg(test)]
mod tests;
