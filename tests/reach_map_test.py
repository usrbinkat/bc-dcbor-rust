"""The reach map's census rows and index verdicts, each failing scenario
shipped beside its passing one."""

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location(
    "reach_map", Path(__file__).with_name("reach-map.py")
)
if spec is None or spec.loader is None:
    raise ImportError("reach-map.py is not loadable beside this test")
reach_map = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reach_map)
CensusModule = reach_map.CensusModule

FILE = "src/storage.rs"
BASE = "all-features-owned_input"
TEST = "acquisition"


def module(name, start, end, *, tainted, test=False, test_items=()):
    """A census module of FILE spanning `start..=end`."""
    return CensusModule(
        file=FILE,
        module=name,
        start=start,
        end=end,
        unsafe=tainted,
        tainted=tainted,
        test=test,
        test_items=test_items,
    )


# The crate root, holding no `unsafe`, around every fixture's module.
ROOT = module("crate", 1, 200, tainted=False)


def regions(*lines):
    """A test's executed regions: one on each of `lines` of FILE."""
    return {FILE: [[line, 1, line, 40] for line in lines]}


class CensusRows(unittest.TestCase):
    def test_a_row_round_trips_through_its_record(self):
        row = module("crate::storage", 10, 20, tainted=True, test=True)
        self.assertEqual(CensusModule.from_record(row.to_record()), row)
        items = module("crate::storage", 10, 20, tainted=True, test_items=((12, 14), (17, 17)))
        self.assertEqual(items.to_record()["test_items"], [[12, 14], [17, 17]])
        self.assertEqual(CensusModule.from_record(items.to_record()), items)
        self.assertTrue(items.holds_test_item(13))
        self.assertFalse(items.holds_test_item(15))

    def test_a_row_of_another_shape_is_rejected(self):
        record = module("crate::storage", 10, 20, tainted=True).to_record()
        cases = {
            "missing": ({k: v for k, v in record.items() if k != "test"}, "missing \\['test'\\]"),
            "unexpected": ({**record, "holds": True}, "unexpected \\['holds'\\]"),
            "integer for boolean": ({**record, "tainted": 1}, "tainted is int, not bool"),
            "boolean for integer": ({**record, "start": True}, "start is bool, not int"),
            "text for integer": ({**record, "end": "20"}, "end is str, not int"),
            "line zero": ({**record, "start": 0}, "not a range of lines"),
            "inverted span": ({**record, "start": 21}, "not a range of lines"),
            "not an object": ([record], "is an object"),
            "test items not a list": ({**record, "test_items": {}}, "test_items is not"),
            "test item of three lines": (
                {**record, "test_items": [[12, 13, 14]]},
                "test_items is not",
            ),
            "inverted test item": ({**record, "test_items": [[14, 12]]}, "test_items is not"),
            "boolean line": ({**record, "test_items": [[True, 12]]}, "test_items is not"),
        }
        for case, (row, message) in cases.items():
            with self.subTest(case):
                with self.assertRaisesRegex(ValueError, message):
                    CensusModule.from_record(row)

    def test_an_empty_census_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "nonempty list"):
            reach_map.census_of([])

    def test_the_innermost_module_holds_a_line(self):
        inner = module("crate::storage", 10, 20, tainted=True)
        census = [ROOT, inner]
        self.assertEqual(reach_map.module_of(census, FILE, 15), inner)
        self.assertEqual(reach_map.module_of(census, FILE, 30), ROOT)
        self.assertIsNone(reach_map.module_of(census, "src/other.rs", 15))


class Index(unittest.TestCase):
    """`index` over one suite of one test, its function at lines 12-14 of a
    module spanning lines 10-20."""

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.out = Path(temporary.name)

    def run_index(self, census_rows, minimal, full):
        """The index's exit status over a run of one test whose minimal and
        full runs executed `minimal` and `full`, its census `census_rows`."""
        (self.out / "census.jsonl").write_text(
            "".join(json.dumps(row) + "\n" for row in census_rows)
        )
        (self.out / "identity.txt").write_text("reach-identity\n")
        (self.out / f"{BASE}.tests").write_text(f"{TEST}\n")
        (self.out / f"{BASE}.domain").write_text("all-features\n")
        (self.out / f"{BASE}.kind").write_text("test\n")
        for layer, executed in (("reach", minimal), ("reach-full", full)):
            (self.out / layer / BASE).mkdir(parents=True)
            (self.out / layer / BASE / "0.json").write_text(json.dumps(executed))
        (self.out / "functions").mkdir()
        (self.out / "functions" / f"{BASE}.json").write_text(
            json.dumps(
                [{"name": "grow", "file": FILE, "start": [12, 5], "end": [14, 6]}]
            )
        )
        return reach_map.index(self.out, [BASE])

    def record(self):
        return json.loads((self.out / "reach.json").read_text())

    def test_a_reached_function_passes(self):
        inner = module("crate::storage", 10, 20, tainted=True)
        status = self.run_index([ROOT.to_record(), inner.to_record()], regions(13), regions(13))
        self.assertEqual(status, 0)
        self.assertEqual(self.record()["unreached_functions"], [])
        self.assertEqual(self.record()["witness_loss"], [])

    def test_a_tainted_function_no_test_reaches_fails(self):
        inner = module("crate::storage", 10, 20, tainted=True)
        status = self.run_index([ROOT.to_record(), inner.to_record()], regions(30), regions(30))
        self.assertEqual(status, 1)
        self.assertEqual(
            [(function["name"], function["module"]) for function in self.record()["unreached_functions"]],
            [("grow", "crate::storage")],
        )

    def test_test_code_need_not_be_reached(self):
        inner = module("crate::storage", 10, 20, tainted=True, test=True)
        status = self.run_index([ROOT.to_record(), inner.to_record()], regions(30), regions(30))
        self.assertEqual(status, 0)
        self.assertEqual(self.record()["unreached_functions"], [])

    def test_a_test_item_of_a_shipped_module_need_not_be_reached(self):
        # The function, at lines 12-14, inside a test-only item of a tainted,
        # shipped module; outside it, the same function is required.
        within = module("crate::storage", 10, 20, tainted=True, test_items=((11, 15),))
        status = self.run_index([ROOT.to_record(), within.to_record()], regions(30), regions(30))
        self.assertEqual(status, 0)
        self.assertEqual(self.record()["unreached_functions"], [])
        beside = module("crate::storage", 10, 20, tainted=True, test_items=((16, 18),))
        self.out = Path(tempfile.mkdtemp(dir=self.out))
        status = self.run_index([ROOT.to_record(), beside.to_record()], regions(30), regions(30))
        self.assertEqual(status, 1)

    def test_an_untainted_function_need_not_be_reached(self):
        inner = module("crate::storage", 10, 20, tainted=False)
        status = self.run_index([ROOT.to_record(), inner.to_record()], regions(30), regions(30))
        self.assertEqual(status, 0)

    def test_a_minimal_witness_dropping_a_full_region_fails(self):
        inner = module("crate::storage", 10, 20, tainted=True)
        status = self.run_index(
            [ROOT.to_record(), inner.to_record()], regions(13), regions(13, 16)
        )
        self.assertEqual(status, 1)
        self.assertEqual(
            self.record()["witness_loss"],
            [{"suite": BASE, "test": TEST, "regions": {FILE: [[16, 1, 16, 40]]}}],
        )

    def test_a_census_row_without_its_test_field_is_rejected(self):
        inner = module("crate::storage", 10, 20, tainted=True).to_record()
        del inner["test"]
        with self.assertRaisesRegex(ValueError, "missing \\['test'\\]"):
            self.run_index([ROOT.to_record(), inner], regions(13), regions(13))


if __name__ == "__main__":
    unittest.main()
