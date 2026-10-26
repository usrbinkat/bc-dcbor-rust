"""Planted evidence defects must not become a successful layer comparison."""

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location(
    "mutation_evidence", Path(__file__).with_name("mutation-evidence.py")
)
evidence = importlib.util.module_from_spec(spec)
spec.loader.exec_module(evidence)


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def report(self, layer, summary):
        directory = self.root / layer
        directory.mkdir()
        mutant = {"name": "storage: retain old permit", "replacement": "false"}
        diff = "--- storage\n+++ storage\n-retain\n+release\n"
        (directory / "mutants.json").write_text(json.dumps([{**mutant, "diff": diff}]))
        (directory / "mutation.diff").write_text(diff)
        report = {
            "cargo_mutants_version": "27.1.0",
            "total_mutants": 1,
            "outcomes": [
                {"scenario": "Baseline", "summary": "Success"},
                {
                    "scenario": {"Mutant": mutant},
                    "summary": summary,
                    "diff_path": "mutation.diff",
                },
            ],
        }
        (directory / "outcomes.json").write_text(json.dumps(report))
        return directory

    def test_equal_detection_passes(self):
        result, passed = evidence.compare(
            self.report("fast", "CaughtMutant"),
            self.report("exhaustive", "CaughtMutant"),
        )
        self.assertTrue(passed)
        self.assertEqual(result["fast_caught"], 1)
        self.assertEqual(result["exhaustive_caught"], 1)

    def test_fast_detection_gap_fails(self):
        result, passed = evidence.compare(
            self.report("fast", "MissedMutant"),
            self.report("exhaustive", "CaughtMutant"),
        )
        self.assertFalse(passed)
        self.assertEqual(
            result["fast_missed_exhaustive_caught"], ["storage: retain old permit"]
        )

    def test_timeout_is_not_detection(self):
        result, passed = evidence.compare(
            self.report("fast", "Timeout"), self.report("exhaustive", "CaughtMutant")
        )
        self.assertFalse(passed)
        self.assertEqual(result["comparable_viable"], 0)

    def test_empty_viable_domain_fails(self):
        _, passed = evidence.compare(
            self.report("fast", "Unviable"), self.report("exhaustive", "Unviable")
        )
        self.assertFalse(passed)

    def test_partial_results_rejected(self):
        directory = self.report("fast", "CaughtMutant")
        path = directory / "outcomes.json"
        report = json.loads(path.read_text())
        report["outcomes"].pop()
        path.write_text(json.dumps(report))
        with self.assertRaisesRegex(ValueError, "incomplete mutation execution"):
            evidence.load(directory)

    def test_failed_baseline_rejected(self):
        directory = self.report("fast", "CaughtMutant")
        path = directory / "outcomes.json"
        report = json.loads(path.read_text())
        report["outcomes"][0]["summary"] = "Failure"
        path.write_text(json.dumps(report))
        with self.assertRaisesRegex(ValueError, "successful unmutated baseline"):
            evidence.load(directory)

    def test_changed_diff_rejected(self):
        directory = self.report("fast", "CaughtMutant")
        (directory / "mutation.diff").write_text("different defect\n")
        with self.assertRaisesRegex(ValueError, "diff does not match"):
            evidence.load(directory)


if __name__ == "__main__":
    unittest.main()
