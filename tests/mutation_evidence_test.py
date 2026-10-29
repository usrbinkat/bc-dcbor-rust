"""Planted evidence defects must not become a successful layer comparison."""

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location(
    "mutation_evidence", Path(__file__).with_name("mutation-evidence.py")
)
if spec is None or spec.loader is None:
    raise ImportError("mutation-evidence.py is not loadable beside this test")
evidence = importlib.util.module_from_spec(spec)
spec.loader.exec_module(evidence)
# The census's one row type, loaded as the plan loads it.
CensusModule = evidence.reach_map().CensusModule

DOMAIN = "all-features"
FILE = "src/storage.rs"
MUTATION = "replace retain with release in Storage::grow"
SOURCE = "retain(permit)"


def planned(line, source=SOURCE):
    """A planned mutant at `line` that removes `source`."""
    mutant = {
        "name": f"{FILE}:{line}:9: {MUTATION}",
        "file": FILE,
        "span": {"start": {"line": line, "column": 9}, "end": {"line": line, "column": 23}},
        "replacement": "release",
    }
    diff = f"--- {FILE}\n+++ {MUTATION}\n@@ -1,1 +1,1 @@\n-    {source}\n+    release(permit)\n"
    return mutant, diff


class Fixtures(unittest.TestCase):
    """Layer reports and registries written under a temporary root; it
    declares no test of its own."""

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def report(self, layer, summaries, sources=None):
        """A complete layer of one planned mutant per summary, each on its
        own line, removing `SOURCE` unless `sources` says otherwise."""
        directory = self.root / layer
        directory.mkdir()
        plan: list[dict[str, object]] = []
        outcomes: list[dict[str, object]] = [
            {"scenario": "Baseline", "summary": "Success"}
        ]
        for index, summary in enumerate(summaries):
            mutant, diff = planned(10 + index, (sources or {}).get(index, SOURCE))
            plan.append({**mutant, "diff": diff})
            path = f"mutation-{index}.diff"
            (directory / path).write_text(diff)
            outcomes.append(
                {"scenario": {"Mutant": mutant}, "summary": summary, "diff_path": path}
            )
        (directory / "mutants.json").write_text(json.dumps(plan))
        report = {
            "cargo_mutants_version": "27.1.0",
            "total_mutants": len(summaries),
            "outcomes": outcomes,
        }
        (directory / "outcomes.json").write_text(json.dumps(report))
        return directory

    def registry(self, *declarations):
        path = self.root / "equivalents.json"
        path.write_text(json.dumps(list(declarations)))
        return path

    def declaration(self, source=SOURCE, domain=DOMAIN):
        return {
            "domain": domain,
            "file": FILE,
            "mutation": MUTATION,
            "source": source,
            "mutated": "release(permit)",
            "rationale": "both release the same permit",
            "scope": "this storage",
        }


class EvidenceTests(Fixtures):
    def compare(self, fast, exhaustive, registry):
        """The comparison of `fast` and `exhaustive` in the all-features
        domain."""
        return evidence.compare(fast, exhaustive, registry, DOMAIN)

    def test_equal_detection_passes(self):
        result, passed = self.compare(
            self.report("fast", ["CaughtMutant"]),
            self.report("exhaustive", ["CaughtMutant"]),
            self.registry(),
        )
        self.assertTrue(passed)
        self.assertEqual(result["fast_caught"], 1)
        self.assertEqual(result["exhaustive_caught"], 1)

    def test_fast_detection_gap_fails(self):
        result, passed = self.compare(
            self.report("fast", ["MissedMutant"]),
            self.report("exhaustive", ["CaughtMutant"]),
            self.registry(),
        )
        self.assertFalse(passed)
        self.assertEqual(
            result["fast_missed_exhaustive_caught"], [f"{FILE}:10:9: {MUTATION}"]
        )

    def test_timeout_is_not_detection(self):
        result, passed = self.compare(
            self.report("fast", ["Timeout"]),
            self.report("exhaustive", ["CaughtMutant"]),
            self.registry(),
        )
        self.assertFalse(passed)
        self.assertEqual(result["comparable_viable"], 0)

    def test_empty_viable_domain_fails(self):
        _, passed = self.compare(
            self.report("fast", ["Unviable"]),
            self.report("exhaustive", ["Unviable"]),
            self.registry(),
        )
        self.assertFalse(passed)

    def test_partial_results_rejected(self):
        directory = self.report("fast", ["CaughtMutant"])
        path = directory / "outcomes.json"
        report = json.loads(path.read_text())
        report["outcomes"].pop()
        path.write_text(json.dumps(report))
        with self.assertRaisesRegex(ValueError, "incomplete mutation execution"):
            evidence.load(directory)

    def test_failed_baseline_rejected(self):
        directory = self.report("fast", ["CaughtMutant"])
        path = directory / "outcomes.json"
        report = json.loads(path.read_text())
        report["outcomes"][0]["summary"] = "Failure"
        path.write_text(json.dumps(report))
        with self.assertRaisesRegex(ValueError, "successful unmutated baseline"):
            evidence.load(directory)

    def test_changed_diff_rejected(self):
        directory = self.report("fast", ["CaughtMutant"])
        (directory / "mutation-0.diff").write_text("different defect\n")
        with self.assertRaisesRegex(ValueError, "diff does not match"):
            evidence.load(directory)

    def test_undeclared_survivor_fails(self):
        result, passed = self.compare(
            self.report("fast", ["MissedMutant"]),
            self.report("exhaustive", ["MissedMutant"]),
            self.registry(),
        )
        self.assertFalse(passed)
        self.assertEqual(result["undeclared_survivors"], [f"{FILE}:10:9: {MUTATION}"])

    def test_declared_equivalent_passes(self):
        result, passed = self.compare(
            self.report("fast", ["CaughtMutant", "MissedMutant"], {1: "keep(permit)"}),
            self.report(
                "exhaustive", ["CaughtMutant", "MissedMutant"], {1: "keep(permit)"}
            ),
            self.registry(self.declaration("keep(permit)")),
        )
        self.assertTrue(passed)
        self.assertEqual(list(result["equivalent"]), [f"{FILE}:11:9: {MUTATION}"])
        self.assertEqual(result["undeclared_survivors"], [])

    def test_caught_equivalent_is_refuted(self):
        result, passed = self.compare(
            self.report("fast", ["CaughtMutant"]),
            self.report("exhaustive", ["CaughtMutant"]),
            self.registry(self.declaration()),
        )
        self.assertFalse(passed)
        self.assertEqual(result["equivalents_refuted"], [f"{FILE}:10:9: {MUTATION}"])

    def test_stale_declaration_rejected(self):
        # The code the declaration names changed: its source no longer
        # matches, however the mutant's position moved.
        with self.assertRaisesRegex(ValueError, "stale declaration"):
            self.compare(
                self.report("fast", ["MissedMutant"]),
                self.report("exhaustive", ["MissedMutant"]),
                self.registry(self.declaration("retain(permit, slot)")),
            )

    def test_ambiguous_declaration_rejected(self):
        with self.assertRaisesRegex(ValueError, "ambiguous declaration"):
            self.compare(
                self.report("fast", ["MissedMutant", "MissedMutant"]),
                self.report("exhaustive", ["MissedMutant", "MissedMutant"]),
                self.registry(self.declaration()),
            )

    def test_duplicate_declaration_rejected(self):
        with self.assertRaisesRegex(ValueError, "duplicate declaration"):
            self.compare(
                self.report("fast", ["MissedMutant"]),
                self.report("exhaustive", ["MissedMutant"]),
                self.registry(self.declaration(), self.declaration()),
            )

    def test_incomplete_declaration_rejected(self):
        incomplete = self.declaration()
        del incomplete["rationale"]
        with self.assertRaisesRegex(ValueError, "a declaration has exactly"):
            self.compare(
                self.report("fast", ["MissedMutant"]),
                self.report("exhaustive", ["MissedMutant"]),
                self.registry(incomplete),
            )

    def test_another_domains_declaration_neither_matches_nor_goes_stale(self):
        # A declaration of the no_std domain names code this domain never
        # compiles: it is checked in its own domain, neither stale here nor
        # an exemption for this domain's survivor.
        result, passed = self.compare(
            self.report("fast", ["MissedMutant"]),
            self.report("exhaustive", ["MissedMutant"]),
            self.registry(self.declaration(domain="no_std")),
        )
        self.assertFalse(passed)
        self.assertEqual(result["undeclared_survivors"], [f"{FILE}:10:9: {MUTATION}"])
        self.assertEqual(result["equivalent"], {})

    def test_unknown_declaration_domain_rejected(self):
        with self.assertRaisesRegex(ValueError, "unknown domain"):
            self.compare(
                self.report("fast", ["MissedMutant"]),
                self.report("exhaustive", ["MissedMutant"]),
                self.registry(self.declaration(domain="std")),
            )

    def test_unknown_run_domain_rejected(self):
        with self.assertRaisesRegex(ValueError, "unknown mutation domain"):
            evidence.compare(
                self.report("fast", ["MissedMutant"]),
                self.report("exhaustive", ["MissedMutant"]),
                self.registry(),
                "std",
            )

    def test_the_repository_registry_declares_complete_distinct_entries(self):
        declarations = json.loads(
            Path(__file__).with_name("mutation-equivalents.json").read_text()
        )
        keys = set()
        for declaration in declarations:
            self.assertEqual(set(declaration), set(evidence.FIELDS))
            self.assertTrue(all(declaration[field] for field in evidence.FIELDS))
            self.assertIn(declaration["domain"], evidence.DOMAINS)
            key = tuple(
                declaration[field]
                for field in ("domain", "file", "mutation", "source", "mutated")
            )
            self.assertNotIn(key, keys)
            keys.add(key)

    def test_one_line_mutants_differ_by_their_mutated_text(self):
        # Two mutants of one source line with one mutation name: only the
        # text each puts in place tells them apart, so a declaration of one
        # is neither stale nor ambiguous.
        directory = self.root / "layer"
        directory.mkdir()
        plan = []
        for column, mutated in ((32, "release(permit) + 1"), (63, "release(permit + 1)")):
            plan.append(
                {
                    "name": f"{FILE}:10:{column}: {MUTATION}",
                    "file": FILE,
                    "diff": f"--- {FILE}\n+++ {MUTATION}\n-    {SOURCE}\n+    {mutated}\n",
                }
            )
        declaration = {**self.declaration(), "mutated": "release(permit + 1)"}
        declared = evidence.equivalents(
            self.registry(declaration),
            DOMAIN,
            {mutant["name"]: mutant for mutant in plan},
        )
        self.assertEqual(list(declared), [f"{FILE}:10:63: {MUTATION}"])


def name(line):
    return f"{FILE}:{line}:9: {MUTATION}"


SNAPSHOT = "0123  src/storage.rs\n"


class MiriLayerTests(Fixtures):
    """The Miri layer decides survivors of tainted modules, and only by an
    outcome it can stand behind."""

    def comparison(self, summaries, registry=()):
        """The native comparison of two layers that agree on `summaries`,
        mutant `i` at line `10 + i`, written where the plan reads it."""
        result, _ = evidence.compare(
            self.report("fast", summaries),
            self.report("exhaustive", summaries),
            self.registry(*registry),
            DOMAIN,
        )
        path = self.root / "comparison.json"
        path.write_text(json.dumps(result))
        return path

    def reach(self, tainted_lines, reached_lines, snapshot=SNAPSHOT):
        """A reach map whose census taints `tainted_lines` of FILE (one
        module, nested in an untainted root) and whose one test executes a
        region on each of `reached_lines`."""
        directory = self.root / "reach"
        directory.mkdir()
        (directory / "identity-inputs.txt").write_text(f"{snapshot}configuration\tx\n")
        census = [
            CensusModule(
                file=FILE,
                module="crate::storage",
                start=1,
                end=100,
                unsafe=False,
                tainted=False,
                test=False,
                test_items=(),
            )
        ]
        if tainted_lines:
            census.append(
                CensusModule(
                    file=FILE,
                    module="crate::storage::raw",
                    start=min(tainted_lines),
                    end=max(tainted_lines),
                    unsafe=True,
                    tainted=True,
                    test=False,
                    test_items=(),
                )
            )
        record = {
            "identity": "reach-identity",
            "census": [module.to_record() for module in census],
            "suites": {
                "all-features-owned_input": {
                    "domain": DOMAIN,
                    "kind": "test",
                    "tests": ["acquisition"],
                    "reach": [{FILE: [[line, 1, line, 40] for line in reached_lines]}],
                },
                # Another build's suite reaching every line: never selected
                # for this domain's mutants.
                "no_std-abort_witness": {
                    "domain": "no_std",
                    "kind": "abort",
                    "tests": ["a_release_observer_that_panics"],
                    "reach": [{FILE: [[line, 1, line, 40] for line in range(1, 100)]}],
                },
            },
        }
        (directory / "reach.json").write_text(json.dumps(record))
        return directory

    def plan(self, comparison, reach):
        snapshot = self.root / "source.sha256"
        snapshot.write_text(SNAPSHOT)
        plan_dir = self.root / "plan"
        evidence.miri_plan(comparison, self.root / "fast", snapshot, reach, plan_dir)
        return plan_dir

    def verdict(self, comparison, plan_dir, lines):
        verdicts = self.root / "verdicts.tsv"
        verdicts.write_text("".join(f"{line}\n" for line in lines))
        return evidence.miri_verdict(comparison, plan_dir, verdicts)

    def test_only_survivors_of_tainted_modules_are_planned_on_the_tests_reaching_them(self):
        comparison = self.comparison(["MissedMutant", "MissedMutant", "CaughtMutant"])
        plan_dir = self.plan(comparison, self.reach([10], [10, 11, 12]))
        plan = json.loads((plan_dir / "plan.json").read_text())
        # Line 11 is in the untainted module: the native verdict stands.
        self.assertEqual(list(plan["planned"]), [name(10)])
        # Only this domain's suite: the no_std suite reaching every line is
        # another build's code.
        self.assertEqual(
            plan["planned"][name(10)]["tests"], [["all-features-owned_input", "acquisition"]]
        )
        self.assertEqual(plan["unreached_under_miri"], [])
        lines = (plan_dir / "plan.tsv").read_text().splitlines()
        self.assertEqual(lines[0].split("\t")[:3], ["mutant", "0", name(10)])
        self.assertEqual(lines[1], "test\t0\tall-features-owned_input\tacquisition")
        self.assertEqual(len(lines), 2)
        diff = Path(lines[0].split("\t")[3]).read_text()
        self.assertTrue(diff.startswith(f"--- {FILE}\n"))

    def test_a_tainted_survivor_no_test_reaches_is_unreached_and_fails(self):
        # The no_std suite reaches the line; it is another domain's build,
        # so no test of this domain reaches the mutant.
        comparison = self.comparison(["MissedMutant"])
        plan_dir = self.plan(comparison, self.reach([10], []))
        result, passed = self.verdict(comparison, plan_dir, [])
        self.assertFalse(passed)
        self.assertEqual(result["unreached_under_miri"], [name(10)])

    def test_an_unreached_declared_equivalent_alone_fails(self):
        # Declared equivalent, so no undeclared survivor: unreached under
        # Miri is the only reason the run can fail.
        comparison = self.comparison(["MissedMutant"], [self.declaration()])
        plan_dir = self.plan(comparison, self.reach([10], []))
        result, passed = self.verdict(comparison, plan_dir, [])
        self.assertEqual(result["undeclared_survivors"], [])
        self.assertEqual(result["unreached_under_miri"], [name(10)])
        self.assertFalse(passed)

    def test_a_reach_map_of_other_sources_is_rejected(self):
        comparison = self.comparison(["MissedMutant"])
        with self.assertRaisesRegex(ValueError, "other sources"):
            self.plan(comparison, self.reach([10], [10], snapshot="4567  src/storage.rs\n"))

    def test_a_survivor_miri_catches_is_detected(self):
        comparison = self.comparison(["MissedMutant"])
        plan_dir = self.plan(comparison, self.reach([10], [10]))
        result, passed = self.verdict(comparison, plan_dir, [f"{name(10)}\tcaught_under_miri"])
        self.assertTrue(passed)
        self.assertEqual(result["caught_under_miri"], [name(10)])
        self.assertEqual(result["undeclared_survivors"], [])

    def test_a_survivor_miri_misses_still_survives(self):
        comparison = self.comparison(["MissedMutant"])
        plan_dir = self.plan(comparison, self.reach([10], [10]))
        result, passed = self.verdict(comparison, plan_dir, [f"{name(10)}\tmissed_under_miri"])
        self.assertFalse(passed)
        self.assertEqual(result["undeclared_survivors"], [name(10)])

    def test_a_survivor_outside_unsafe_modules_is_not_decided_by_miri(self):
        comparison = self.comparison(["MissedMutant"])
        plan_dir = self.plan(comparison, self.reach([], [10]))
        result, passed = self.verdict(comparison, plan_dir, [])
        self.assertFalse(passed)
        self.assertEqual(result["undeclared_survivors_outside_unsafe_modules"], [name(10)])

    def test_a_declared_equivalent_miri_distinguishes_is_refuted(self):
        comparison = self.comparison(["MissedMutant"], [self.declaration()])
        plan_dir = self.plan(comparison, self.reach([10], [10]))
        result, passed = self.verdict(comparison, plan_dir, [f"{name(10)}\tcaught_under_miri"])
        self.assertFalse(passed)
        self.assertEqual(result["equivalents_refuted_under_miri"], [name(10)])

    def test_a_declared_equivalent_miri_misses_passes(self):
        comparison = self.comparison(["MissedMutant"], [self.declaration()])
        plan_dir = self.plan(comparison, self.reach([10], [10]))
        _, passed = self.verdict(comparison, plan_dir, [f"{name(10)}\tmissed_under_miri"])
        self.assertTrue(passed)

    def test_undecided_stale_duplicate_and_no_baseline_each_fail_alone(self):
        # Each case leaves its own class as the only reason to fail: the
        # survivor is either caught under Miri (undeclared) or a declared
        # equivalent left uncaught, so neither an undeclared survivor nor a
        # refuted equivalent can mask the class under test.
        failing = (
            "unreached_under_miri",
            "no_baseline",
            "undecided",
            "stale",
            "duplicate",
            "undeclared_survivors",
            "equivalents_refuted_under_miri",
        )
        caught = f"{name(10)}\tcaught_under_miri"
        cases = {
            "undecided": ([self.declaration()], []),
            "no_baseline": ([self.declaration()], [f"{name(10)}\tno_baseline"]),
            "stale": ([], [caught, f"{name(99)}\tcaught_under_miri"]),
            "duplicate": ([], [caught, caught]),
        }
        for outcome, (registry, lines) in cases.items():
            with self.subTest(outcome):
                self.root = Path(tempfile.mkdtemp(dir=self.temporary.name))
                comparison = self.comparison(["MissedMutant"], registry)
                plan_dir = self.plan(comparison, self.reach([10], [10]))
                result, passed = self.verdict(comparison, plan_dir, lines)
                self.assertNotEqual(result[outcome], [])
                for other in failing:
                    if other != outcome:
                        self.assertEqual(result[other], [], other)
                self.assertFalse(passed)

    def test_an_unknown_miri_outcome_is_rejected(self):
        comparison = self.comparison(["MissedMutant"])
        plan_dir = self.plan(comparison, self.reach([10], [10]))
        with self.assertRaisesRegex(ValueError, "unrecognized verdict line"):
            self.verdict(comparison, plan_dir, [f"{name(10)}\tcaught"])


if __name__ == "__main__":
    unittest.main()
