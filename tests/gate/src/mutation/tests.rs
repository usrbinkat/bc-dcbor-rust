//! Planted evidence defects must not become a successful comparison, plan
//! or verdict: each failing scenario beside its passing one.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use dcbor_census::CensusModule;
use serde_json::json;

use super::*;
use crate::reach::{ReachMap, Suite};

const DOMAIN: &str = "all-features";
const FILE: &str = "src/storage.rs";
const MUTATION: &str = "replace retain with release in Storage::grow";
const SOURCE: &str = "retain(permit)";
const CONFIGURATION: &str = "this";
const SNAPSHOT: &str = "0123  src/storage.rs\n";

fn name(line: usize) -> String {
    format!("{FILE}:{line}:9: {MUTATION}")
}

/// A temporary root holding layer reports, a registry, a reach map and a
/// plan; removed when the test ends without a failure.
struct Root(PathBuf);

impl Root {
    fn new(test: &str) -> Self {
        let path =
            std::env::temp_dir().join(format!("dcbor-gate-mutation-{test}-{}", std::process::id()));
        if path.exists() {
            std::fs::remove_dir_all(&path).unwrap();
        }
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    fn write(&self, relative: &str, text: &str) -> PathBuf {
        let path = self.0.join(relative);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, text).unwrap();
        path
    }

    /// A complete layer of one planned mutant per summary, mutant `i` at
    /// line `10 + i`, removing [`SOURCE`] unless `sources` says otherwise.
    fn report(&self, layer: &str, summaries: &[&str], sources: &[(usize, &str)]) -> PathBuf {
        let mut plan = Vec::new();
        let mut outcomes = vec![json!({"scenario": "Baseline", "summary": "Success"})];
        for (index, summary) in summaries.iter().enumerate() {
            let line = 10 + index;
            let source = sources
                .iter()
                .find(|(at, _)| *at == index)
                .map_or(SOURCE, |(_, source)| *source);
            let mutant = json!({
                "name": name(line),
                "file": FILE,
                "span": {"start": {"line": line, "column": 9}, "end": {"line": line, "column": 23}},
                "replacement": "release",
            });
            let diff = format!(
                "--- {FILE}\n+++ {MUTATION}\n@@ -1,1 +1,1 @@\n-    {source}\n+    release(permit)\n"
            );
            let mut planned = mutant.clone();
            planned["diff"] = json!(diff);
            plan.push(planned);
            let path = format!("mutation-{index}.diff");
            self.write(&format!("{layer}/{path}"), &diff);
            outcomes.push(
                json!({"scenario": {"Mutant": mutant}, "summary": summary, "diff_path": path}),
            );
        }
        self.write(&format!("{layer}/mutants.json"), &json!(plan).to_string());
        let report = json!({
            "cargo_mutants_version": "27.1.0",
            "total_mutants": summaries.len(),
            "outcomes": outcomes,
        });
        self.write(&format!("{layer}/outcomes.json"), &report.to_string());
        self.0.join(layer)
    }

    fn registry(&self, declarations: &[serde_json::Value]) -> PathBuf {
        self.write("equivalents.json", &json!(declarations).to_string())
    }

    fn compare(
        &self,
        fast: &[&str],
        exhaustive: &[&str],
        registry: &[serde_json::Value],
    ) -> Comparison {
        let fast = self.report("fast", fast, &[]);
        let exhaustive = self.report("exhaustive", exhaustive, &[]);
        compare(&fast, &exhaustive, &self.registry(registry), DOMAIN).unwrap()
    }

    fn refused(&self, fast: &[&str], registry: &[serde_json::Value]) -> String {
        let fast_dir = self.report("fast", fast, &[]);
        let exhaustive = self.report("exhaustive", fast, &[]);
        compare(&fast_dir, &exhaustive, &self.registry(registry), DOMAIN).unwrap_err()
    }
}

impl Drop for Root {
    fn drop(&mut self) {
        if !std::thread::panicking() {
            std::fs::remove_dir_all(&self.0).unwrap();
        }
    }
}

fn declaration(source: &str, domain: &str) -> serde_json::Value {
    json!({
        "domain": domain,
        "file": FILE,
        "mutation": MUTATION,
        "source": source,
        "mutated": "release(permit)",
        "rationale": "both release the same permit",
        "scope": "this storage",
    })
}

#[test]
fn equal_detection_passes() {
    let root = Root::new("equal");
    let result = root.compare(&["CaughtMutant"], &["CaughtMutant"], &[]);
    assert!(result.passed());
    assert_eq!((result.fast_caught, result.exhaustive_caught), (1, 1));
}

#[test]
fn a_fast_detection_gap_fails() {
    let root = Root::new("gap");
    let result = root.compare(&["MissedMutant"], &["CaughtMutant"], &[]);
    assert!(!result.passed());
    assert_eq!(result.fast_missed_exhaustive_caught, vec![name(10)]);
    let reverse = root.compare(&["CaughtMutant"], &["MissedMutant"], &[]);
    assert_eq!(reverse.fast_caught_exhaustive_missed, vec![name(10)]);
    assert!(!reverse.passed());
}

#[test]
fn a_timeout_is_not_detection() {
    let root = Root::new("timeout");
    let result = root.compare(&["Timeout"], &["CaughtMutant"], &[]);
    assert!(!result.passed());
    assert_eq!(
        (result.comparable_viable, result.timeouts.clone()),
        (0, vec![name(10)])
    );
}

#[test]
fn an_empty_viable_domain_and_a_viability_disagreement_fail() {
    let root = Root::new("unviable");
    let result = root.compare(&["Unviable"], &["Unviable"], &[]);
    assert!(!result.passed());
    assert_eq!(result.unviable, vec![name(10)]);
    let disagreeing = root.compare(
        &["Unviable", "CaughtMutant"],
        &["MissedMutant", "CaughtMutant"],
        &[],
    );
    assert_eq!(disagreeing.viability_disagreements, vec![name(10)]);
    assert!(!disagreeing.passed());
}

#[test]
fn partial_failed_or_changed_results_are_refused() {
    let root = Root::new("partial");
    let directory = root.report("fast", &["CaughtMutant"], &[]);
    assert!(load(&directory).is_ok());
    let path = directory.join("outcomes.json");
    let original = std::fs::read_to_string(&path).unwrap();
    let mut report: serde_json::Value = serde_json::from_str(&original).unwrap();
    report["outcomes"].as_array_mut().unwrap().pop();
    std::fs::write(&path, report.to_string()).unwrap();
    assert!(
        load(&directory)
            .unwrap_err()
            .contains("incomplete mutation execution")
    );
    let mut report: serde_json::Value = serde_json::from_str(&original).unwrap();
    report["outcomes"][0]["summary"] = json!("Failure");
    std::fs::write(&path, report.to_string()).unwrap();
    assert!(
        load(&directory)
            .unwrap_err()
            .contains("successful unmutated baseline")
    );
    let mut report: serde_json::Value = serde_json::from_str(&original).unwrap();
    report["outcomes"][1]["summary"] = json!("Failure");
    std::fs::write(&path, report.to_string()).unwrap();
    assert!(
        load(&directory)
            .unwrap_err()
            .contains("unknown or failed mutation outcome")
    );
    let mut report: serde_json::Value = serde_json::from_str(&original).unwrap();
    report["outcomes"][1]["scenario"]["Mutant"]["replacement"] = json!("keep");
    std::fs::write(&path, report.to_string()).unwrap();
    assert!(load(&directory).unwrap_err().contains("changed mutation"));
    std::fs::write(&path, &original).unwrap();
    std::fs::write(directory.join("mutation-0.diff"), "different defect\n").unwrap();
    assert!(
        load(&directory)
            .unwrap_err()
            .contains("diff does not match")
    );
}

#[test]
fn an_undeclared_survivor_fails() {
    let root = Root::new("undeclared");
    let result = root.compare(&["MissedMutant"], &["MissedMutant"], &[]);
    assert!(!result.passed());
    assert_eq!(result.undeclared_survivors, vec![name(10)]);
}

#[test]
fn a_declared_equivalent_passes() {
    let root = Root::new("declared");
    let sources = [(1, "keep(permit)")];
    let fast = root.report("fast", &["CaughtMutant", "MissedMutant"], &sources);
    let exhaustive = root.report("exhaustive", &["CaughtMutant", "MissedMutant"], &sources);
    let registry = root.registry(&[declaration("keep(permit)", DOMAIN)]);
    let result = compare(&fast, &exhaustive, &registry, DOMAIN).unwrap();
    assert!(result.passed());
    assert_eq!(
        result.equivalent.keys().cloned().collect::<Vec<_>>(),
        vec![name(11)]
    );
    assert_eq!(result.undeclared_survivors, Vec::<String>::new());
}

#[test]
fn a_caught_equivalent_is_refuted() {
    let root = Root::new("refuted");
    let result = root.compare(
        &["CaughtMutant"],
        &["CaughtMutant"],
        &[declaration(SOURCE, DOMAIN)],
    );
    assert!(!result.passed());
    assert_eq!(result.equivalents_refuted, vec![name(10)]);
}

#[test]
fn stale_ambiguous_duplicate_and_incomplete_declarations_are_refused() {
    let root = Root::new("declarations");
    // The code the declaration names changed: its source no longer matches,
    // however the mutant's position moved.
    assert!(
        root.refused(
            &["MissedMutant"],
            &[declaration("retain(permit, slot)", DOMAIN)]
        )
        .contains("stale declaration")
    );
    assert!(
        root.refused(
            &["MissedMutant", "MissedMutant"],
            &[declaration(SOURCE, DOMAIN)]
        )
        .contains("ambiguous declaration")
    );
    assert!(
        root.refused(
            &["MissedMutant"],
            &[declaration(SOURCE, DOMAIN), declaration(SOURCE, DOMAIN)]
        )
        .contains("duplicate declaration")
    );
    let mut incomplete = declaration(SOURCE, DOMAIN);
    incomplete.as_object_mut().unwrap().remove("rationale");
    assert!(
        root.refused(&["MissedMutant"], &[incomplete])
            .contains("a declaration has exactly")
    );
    let mut empty = declaration(SOURCE, DOMAIN);
    empty["scope"] = json!("");
    assert!(
        root.refused(&["MissedMutant"], &[empty])
            .contains("nonempty text")
    );
    // A domain the gate does not build (`domains::DOMAINS` has no `stable`).
    assert!(
        root.refused(&["MissedMutant"], &[declaration(SOURCE, "stable")])
            .contains("unknown domain")
    );
}

/// A declaration of the no_std domain names code this domain never
/// compiles: it is checked in its own domain, neither stale here nor an
/// exemption for this domain's survivor.
#[test]
fn another_domains_declaration_neither_matches_nor_goes_stale() {
    let root = Root::new("other-domain");
    let result = root.compare(
        &["MissedMutant"],
        &["MissedMutant"],
        &[declaration(SOURCE, "no_std")],
    );
    assert!(!result.passed());
    assert_eq!(result.undeclared_survivors, vec![name(10)]);
    assert!(result.equivalent.is_empty());
}

#[test]
fn an_unknown_run_domain_is_refused() {
    let root = Root::new("run-domain");
    let fast = root.report("fast", &["MissedMutant"], &[]);
    let exhaustive = root.report("exhaustive", &["MissedMutant"], &[]);
    let error = compare(&fast, &exhaustive, &root.registry(&[]), "stable").unwrap_err();
    assert!(error.contains("unknown mutation domain"), "{error}");
}

#[test]
fn the_repository_registry_declares_complete_distinct_entries() {
    let registry = Path::new(env!("CARGO_MANIFEST_DIR")).join("../mutation-equivalents.json");
    assert!(!declarations(&registry).unwrap().is_empty());
}

/// Two mutants of one source line with one mutation name: only the text
/// each puts in place tells them apart, so a declaration of one is neither
/// stale nor ambiguous.
#[test]
fn one_line_mutants_differ_by_their_mutated_text() {
    let root = Root::new("one-line");
    let mut mutants = BTreeMap::new();
    for (column, mutated) in [(32, "release(permit) + 1"), (63, "release(permit + 1)")] {
        let name = format!("{FILE}:10:{column}: {MUTATION}");
        let mutant = json!({
            "name": name,
            "file": FILE,
            "diff": format!("--- {FILE}\n+++ {MUTATION}\n-    {SOURCE}\n+    {mutated}\n"),
        });
        mutants.insert(name, mutant.as_object().unwrap().clone());
    }
    let mut declared = declaration(SOURCE, DOMAIN);
    declared["mutated"] = json!("release(permit + 1)");
    let found = equivalents(&root.registry(&[declared]), DOMAIN, &mutants).unwrap();
    assert_eq!(
        found.keys().cloned().collect::<Vec<_>>(),
        vec![format!("{FILE}:10:63: {MUTATION}")]
    );
}

/// The Miri layer decides survivors of tainted modules, and only by a
/// judgement it can stand behind.
impl Root {
    /// The native comparison of two layers that agree on `summaries`,
    /// written where the plan reads it.
    fn comparison(&self, summaries: &[&str], registry: &[serde_json::Value]) -> PathBuf {
        let result = self.compare(summaries, summaries, registry);
        self.write("comparison.json", &serde_json::to_string(&result).unwrap())
    }

    /// A reach map whose census taints `tainted` lines of FILE (one module,
    /// nested in an untainted root) and whose one test executes a region on
    /// each of `reached` lines; another build's suite reaches every line.
    fn reach(&self, tainted: &[usize], reached: &[usize], snapshot: &str) -> PathBuf {
        let module = |name: &str, start: usize, end: usize, tainted: bool| CensusModule {
            file: FILE.to_string(),
            module: name.to_string(),
            start,
            end,
            holds_unsafe: tainted,
            tainted,
            test: false,
            test_items: Vec::new(),
        };
        let mut census = vec![module("crate::storage", 1, 100, false)];
        if let (Some(first), Some(last)) = (tainted.iter().min(), tainted.iter().max()) {
            census.push(module("crate::storage::raw", *first, *last, true));
        }
        self.write(
            "reach/census.txt",
            &dcbor_census::render(CONFIGURATION, &census, &[]),
        );
        self.write(
            "reach/identity-inputs.txt",
            &format!("{snapshot}configuration\tx\n"),
        );
        let regions = |lines: &[usize]| -> crate::reach::Regions {
            BTreeMap::from([(
                FILE.to_string(),
                lines.iter().map(|&line| [line, 1, line, 40]).collect(),
            )])
        };
        let every: Vec<usize> = (1..100).collect();
        let map = ReachMap {
            identity: "reach-identity".to_string(),
            suites: BTreeMap::from([
                (
                    "all-features-owned_input".to_string(),
                    Suite {
                        domain: DOMAIN.to_string(),
                        kind: "test".to_string(),
                        tests: vec!["acquisition".to_string()],
                        reach: vec![regions(reached)],
                    },
                ),
                // Another build's suite reaching every line: never selected
                // for this domain's mutants.
                (
                    "no_std-abort_witness".to_string(),
                    Suite {
                        domain: "no_std".to_string(),
                        kind: "abort".to_string(),
                        tests: vec!["a_release_observer_that_panics".to_string()],
                        reach: vec![regions(&every)],
                    },
                ),
            ]),
            unreached_functions: Vec::new(),
            witness_loss: Vec::new(),
            valuation_loss: Vec::new(),
        };
        self.write("reach/reach.json", &serde_json::to_string(&map).unwrap());
        self.0.join("reach")
    }

    fn plan(&self, comparison: &Path, reach: &Path) -> Result<PathBuf, String> {
        let snapshot = self.write("source.sha256", SNAPSHOT);
        let plan_dir = self.0.join("plan");
        miri_plan(
            comparison,
            &self.0.join("fast"),
            &snapshot,
            reach,
            &plan_dir,
            CONFIGURATION,
        )?;
        Ok(plan_dir)
    }

    fn verdict(
        &self,
        comparison: &Path,
        plan: &Path,
        lines: &[String],
    ) -> Result<(MiriVerdict, bool), String> {
        let verdicts = self.write(
            "verdicts.tsv",
            &lines
                .iter()
                .map(|line| format!("{line}\n"))
                .collect::<String>(),
        );
        miri_verdict(comparison, plan, &verdicts)
    }
}

fn judged(line: usize, judgement: Judgement) -> String {
    crate::miri::verdict_row(&name(line), judgement)
        .trim_end()
        .to_string()
}

#[test]
fn only_survivors_of_tainted_modules_are_planned_on_the_tests_reaching_them() {
    let root = Root::new("planned");
    let comparison = root.comparison(&["MissedMutant", "MissedMutant", "CaughtMutant"], &[]);
    let plan_dir = root
        .plan(&comparison, &root.reach(&[10], &[10, 11, 12], SNAPSHOT))
        .unwrap();
    let plan: Plan =
        serde_json::from_str(&std::fs::read_to_string(plan_dir.join("plan.json")).unwrap())
            .unwrap();
    // Line 11 is in the untainted module: the native verdict stands.
    assert_eq!(
        plan.planned.keys().cloned().collect::<Vec<_>>(),
        vec![name(10)]
    );
    // Only this domain's suite: the no_std suite reaching every line is
    // another build's code.
    assert_eq!(
        plan.planned[&name(10)].tests,
        vec![[
            "all-features-owned_input".to_string(),
            "acquisition".to_string()
        ]]
    );
    assert!(plan.unreached_under_miri.is_empty());
    let tsv = std::fs::read_to_string(plan_dir.join("plan.tsv")).unwrap();
    let lines: Vec<&str> = tsv.lines().collect();
    assert_eq!(lines.len(), 2);
    let mutant: Vec<&str> = lines[0].split('\t').collect();
    assert_eq!(mutant[..3], ["mutant", "0", name(10).as_str()]);
    assert_eq!(lines[1], "test\t0\tall-features-owned_input\tacquisition");
    assert!(
        std::fs::read_to_string(mutant[3])
            .unwrap()
            .starts_with(&format!("--- {FILE}\n"))
    );
}

/// The no_std suite reaches the line; it is another domain's build, so no
/// test of this domain reaches the mutant.
#[test]
fn a_tainted_survivor_no_test_reaches_is_unreached_and_fails() {
    let root = Root::new("unreached");
    let comparison = root.comparison(&["MissedMutant"], &[]);
    let plan = root
        .plan(&comparison, &root.reach(&[10], &[], SNAPSHOT))
        .unwrap();
    let (result, passed) = root.verdict(&comparison, &plan, &[]).unwrap();
    assert!(!passed);
    assert_eq!(result.unreached_under_miri, vec![name(10)]);
}

/// Declared equivalent, so no undeclared survivor: unreached under Miri is
/// the only reason the run can fail.
#[test]
fn an_unreached_declared_equivalent_alone_fails() {
    let root = Root::new("unreached-equivalent");
    let comparison = root.comparison(&["MissedMutant"], &[declaration(SOURCE, DOMAIN)]);
    let plan = root
        .plan(&comparison, &root.reach(&[10], &[], SNAPSHOT))
        .unwrap();
    let (result, passed) = root.verdict(&comparison, &plan, &[]).unwrap();
    assert!(result.undeclared_survivors.is_empty());
    assert_eq!(result.unreached_under_miri, vec![name(10)]);
    assert!(!passed);
}

#[test]
fn a_reach_map_of_other_sources_or_configuration_is_refused() {
    let root = Root::new("other-sources");
    let comparison = root.comparison(&["MissedMutant"], &[]);
    let reach = root.reach(&[10], &[10], "4567  src/storage.rs\n");
    assert!(
        root.plan(&comparison, &reach)
            .unwrap_err()
            .contains("other sources")
    );
    let reach = root.reach(&[10], &[10], SNAPSHOT);
    root.write(
        "reach/census.txt",
        &dcbor_census::render(
            "that",
            &[CensusModule {
                file: FILE.to_string(),
                module: "crate".to_string(),
                start: 1,
                end: 100,
                holds_unsafe: false,
                tainted: false,
                test: false,
                test_items: Vec::new(),
            }],
            &[],
        ),
    );
    assert!(
        root.plan(&comparison, &reach)
            .unwrap_err()
            .contains("another configuration")
    );
}

#[test]
fn a_survivor_miri_catches_is_detected_and_one_it_misses_survives() {
    let root = Root::new("caught");
    let comparison = root.comparison(&["MissedMutant"], &[]);
    let plan = root
        .plan(&comparison, &root.reach(&[10], &[10], SNAPSHOT))
        .unwrap();
    let (result, passed) = root
        .verdict(
            &comparison,
            &plan,
            &[judged(10, Judgement::CaughtUnderMiri)],
        )
        .unwrap();
    assert!(passed);
    assert_eq!(result.caught_under_miri, vec![name(10)]);
    assert!(result.undeclared_survivors.is_empty());
    let (result, passed) = root
        .verdict(
            &comparison,
            &plan,
            &[judged(10, Judgement::MissedUnderMiri)],
        )
        .unwrap();
    assert!(!passed);
    assert_eq!(result.undeclared_survivors, vec![name(10)]);
}

#[test]
fn a_survivor_outside_unsafe_modules_is_not_decided_by_miri() {
    let root = Root::new("outside");
    let comparison = root.comparison(&["MissedMutant"], &[]);
    let plan = root
        .plan(&comparison, &root.reach(&[], &[10], SNAPSHOT))
        .unwrap();
    let (result, passed) = root.verdict(&comparison, &plan, &[]).unwrap();
    assert!(!passed);
    assert_eq!(
        result.undeclared_survivors_outside_unsafe_modules,
        vec![name(10)]
    );
}

#[test]
fn a_declared_equivalent_is_refuted_if_miri_distinguishes_it() {
    let root = Root::new("equivalent-miri");
    let comparison = root.comparison(&["MissedMutant"], &[declaration(SOURCE, DOMAIN)]);
    let plan = root
        .plan(&comparison, &root.reach(&[10], &[10], SNAPSHOT))
        .unwrap();
    let (result, passed) = root
        .verdict(
            &comparison,
            &plan,
            &[judged(10, Judgement::CaughtUnderMiri)],
        )
        .unwrap();
    assert!(!passed);
    assert_eq!(result.equivalents_refuted_under_miri, vec![name(10)]);
    let (_, passed) = root
        .verdict(
            &comparison,
            &plan,
            &[judged(10, Judgement::MissedUnderMiri)],
        )
        .unwrap();
    assert!(passed);
}

/// Each case leaves its own class as the only reason to fail: the survivor
/// is either caught under Miri (undeclared) or a declared equivalent left
/// uncaught, so neither an undeclared survivor nor a refuted equivalent can
/// mask the class under test.
#[test]
fn undecided_stale_duplicate_and_no_baseline_each_fail_alone() {
    let caught = judged(10, Judgement::CaughtUnderMiri);
    let cases: [(&str, Vec<serde_json::Value>, Vec<String>); 4] = [
        ("undecided", vec![declaration(SOURCE, DOMAIN)], vec![]),
        (
            "no_baseline",
            vec![declaration(SOURCE, DOMAIN)],
            vec![judged(10, Judgement::NoBaseline)],
        ),
        (
            "stale",
            vec![],
            vec![caught.clone(), judged(99, Judgement::CaughtUnderMiri)],
        ),
        ("duplicate", vec![], vec![caught.clone(), caught.clone()]),
    ];
    for (class, registry, lines) in cases {
        let root = Root::new(&format!("alone-{class}"));
        let comparison = root.comparison(&["MissedMutant"], &registry);
        let plan = root
            .plan(&comparison, &root.reach(&[10], &[10], SNAPSHOT))
            .unwrap();
        let (result, passed) = root.verdict(&comparison, &plan, &lines).unwrap();
        let classes = [
            ("unreached_under_miri", &result.unreached_under_miri),
            ("no_baseline", &result.no_baseline),
            ("undecided", &result.undecided),
            ("stale", &result.stale),
            ("duplicate", &result.duplicate),
            ("undeclared_survivors", &result.undeclared_survivors),
            (
                "equivalents_refuted_under_miri",
                &result.equivalents_refuted_under_miri,
            ),
        ];
        for (other, found) in classes {
            assert_eq!(
                found.is_empty(),
                other != class,
                "{class}: {other} {found:?}"
            );
        }
        assert!(!passed, "{class}");
    }
}

#[test]
fn an_unknown_or_unjudging_verdict_line_is_refused() {
    let root = Root::new("unknown-verdict");
    let comparison = root.comparison(&["MissedMutant"], &[]);
    let plan = root
        .plan(&comparison, &root.reach(&[10], &[10], SNAPSHOT))
        .unwrap();
    for line in [
        format!("{}\tcaught", name(10)),
        judged(10, Judgement::UnreachedUnderMiri),
        "no tab".to_string(),
    ] {
        let error = root
            .verdict(&comparison, &plan, std::slice::from_ref(&line))
            .unwrap_err();
        assert!(
            error.contains("unrecognized verdict line"),
            "{line}: {error}"
        );
    }
}
