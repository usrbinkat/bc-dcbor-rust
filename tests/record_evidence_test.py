"""Recorder publication controls using a fake cargo, never compiling Rust."""

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("record-evidence.sh")
SUFFIXES = ("", ".num-bigint", ".custom-std", ".custom-std.num-bigint")
FAKE_CARGO = r"""#!/usr/bin/env python3
import os
from pathlib import Path
import sys

for variable, filename in (
    ("DCBOR_RECORD_FACTORS", "tightness-control.txt"),
    ("DCBOR_RECORD_TRACES", "traces-control.txt"),
):
    if variable in os.environ:
        Path("tests/data", filename).write_text("overwritten by inherited recording flag\n")

features = os.environ["DCBOR_COST_VARIANT"].split(",")
index = int("num-bigint" in features) + 2 * int("custom-std-collections" in features)
leg = 2 * index + int(os.environ["DCBOR_RIGOR"] == "exhaustive")
if str(leg) == os.environ.get("FAIL_LEG"):
    sys.exit(1)
key = f"{0 if os.environ.get('COLLIDE') else leg:016x}"
directory = Path(os.environ["DCBOR_COST_DIRECTORY"])
record = directory / (key + ".txt")
expected = f"#\tconfiguration\t{os.environ['DCBOR_CONFIGURATION']}\nidentity\tleg-{leg}\nmeasurement\n"
if os.environ["DCBOR_COST_MODE"] == "record":
    record.write_text(expected)
elif not record.exists() or record.read_text() != expected:
    sys.exit(1)
print("DCBOR_COST\t" + key)
"""


class RecorderPublication(unittest.TestCase):
    def setUp(self):
        # Honour the caller's session scratch directory through tempfile.
        self.temporary = tempfile.TemporaryDirectory(prefix="dcbor-recorder-control.")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        tests = self.root / "tests"
        tests.mkdir()
        shutil.copyfile(SCRIPT, tests / SCRIPT.name)
        self.costs = tests / "data" / "costs"
        self.costs.mkdir(parents=True)
        (self.costs / "existing.txt").write_text("existing evidence\n")
        for suffix in SUFFIXES:
            for layer in ("fast", "exhaustive"):
                (self.costs / f"inventory{suffix}.{layer}.txt").write_text(
                    "old inventory\n"
                )
        binaries = self.root / "bin"
        binaries.mkdir()
        cargo = binaries / "cargo"
        cargo.write_text(FAKE_CARGO)
        cargo.chmod(0o755)
        self.environment = {
            **os.environ,
            "PATH": str(binaries) + os.pathsep + os.environ["PATH"],
            "TMPDIR": str(self.root),
            "DCBOR_CONFIGURATION": "recorder-control",
            "DCBOR_COST_REASON": "publication control",
        }
        for variable in ("FAIL_LEG", "COLLIDE", "DCBOR_COST_BASELINE"):
            self.environment.pop(variable, None)

    def snapshot(self):
        return {path.name: path.read_bytes() for path in self.costs.iterdir()}

    def run_recorder(self, mode="record-costs", resume=None, **environment):
        return subprocess.run(
            ["bash", "tests/record-evidence.sh", mode]
            + ([str(resume)] if resume else []),
            cwd=self.root,
            env={**self.environment, **environment},
            capture_output=True,
            text=True,
            check=False,
        )

    # A record no inventory names: its digest is no leg's.
    STALE = "00000000000000ff.txt"
    STALE_CONTENT = (
        "#\tconfiguration\trecorder-control\nidentity\trenamed\nmeasurement\n"
    )

    def test_complete_recording_removes_records_no_matrix_produces(self):
        (self.costs / self.STALE).write_text(self.STALE_CONTENT)
        result = self.run_recorder()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse((self.costs / self.STALE).exists())
        self.assertIn(self.STALE, result.stdout)
        self.assertEqual(
            (self.costs / "existing.txt").read_text(), "existing evidence\n"
        )

    def test_failed_recording_removes_no_stale_record(self):
        (self.costs / self.STALE).write_text(self.STALE_CONTENT)
        before = self.snapshot()
        result = self.run_recorder(FAIL_LEG="7")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.snapshot(), before)

    def test_check_names_a_record_no_matrix_produces(self):
        recorded = self.run_recorder()
        self.assertEqual(recorded.returncode, 0, recorded.stdout + recorded.stderr)
        checked = self.run_recorder("check-costs")
        self.assertEqual(checked.returncode, 0, checked.stdout + checked.stderr)
        (self.costs / self.STALE).write_text(self.STALE_CONTENT)
        checked = self.run_recorder("check-costs")
        self.assertNotEqual(checked.returncode, 0)
        self.assertIn(
            f"{self.STALE}: no matrix of this configuration records it", checked.stderr
        )
        self.assertTrue((self.costs / self.STALE).exists())

    def test_final_leg_failure_preserves_every_existing_record_and_inventory(self):
        before = self.snapshot()
        result = self.run_recorder(FAIL_LEG="7")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(len(list(self.root.glob("dcbor-costs.*/*.records/*.txt"))), 7)

    def test_foreign_and_unrecognized_records_are_preserved(self):
        protected = {
            "00000000000000fe.txt": "#\tconfiguration\tanother-fork\nidentity\told\n",
            "00000000000000fd.txt": "unrecognized evidence\n",
        }
        for name, content in protected.items():
            (self.costs / name).write_text(content)
        for mode in ("record-costs", "check-costs"):
            result = self.run_recorder(mode)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            for name, content in protected.items():
                self.assertEqual((self.costs / name).read_text(), content)

    def test_check_does_not_repair_missing_records(self):
        recorded = self.run_recorder()
        self.assertEqual(recorded.returncode, 0, recorded.stdout + recorded.stderr)
        (self.costs / "0000000000000000.txt").unlink()
        before = self.snapshot()
        checked = self.run_recorder("check-costs")
        self.assertNotEqual(checked.returncode, 0)
        self.assertEqual(self.snapshot(), before)

    def test_external_baseline_checks_without_local_records(self):
        recorded = self.run_recorder()
        self.assertEqual(recorded.returncode, 0, recorded.stdout + recorded.stderr)
        external = self.root / "approved-baseline"
        shutil.move(self.costs, external)
        before = {p.name: p.read_bytes() for p in external.iterdir()}
        checked = self.run_recorder("check-costs", DCBOR_COST_BASELINE=str(external))
        self.assertEqual(checked.returncode, 0, checked.stdout + checked.stderr)
        self.assertFalse(self.costs.exists())
        self.assertEqual({p.name: p.read_bytes() for p in external.iterdir()}, before)

    def test_missing_final_inventory_fails_before_cargo(self):
        recorded = self.run_recorder()
        self.assertEqual(recorded.returncode, 0, recorded.stdout + recorded.stderr)
        (self.costs / "inventory.custom-std.num-bigint.exhaustive.txt").unlink()
        cargo = self.root / "bin" / "cargo"
        cargo.write_text("#!/bin/sh\ntouch cargo-was-run\nexit 1\n")
        checked = self.run_recorder("check-costs")
        self.assertNotEqual(checked.returncode, 0)
        self.assertIn("missing baseline inventory", checked.stderr)
        self.assertFalse((self.root / "cargo-was-run").exists())

    def test_cost_runs_do_not_inherit_other_recording_modes(self):
        protected = [
            self.costs.parent / name
            for name in ("tightness-control.txt", "traces-control.txt")
        ]
        for mode in ("record-costs", "check-costs"):
            with self.subTest(mode=mode):
                for path in protected:
                    path.write_text("existing independent evidence\n")
                result = self.run_recorder(
                    mode, DCBOR_RECORD_FACTORS="1", DCBOR_RECORD_TRACES="1"
                )
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                for path in protected:
                    self.assertEqual(
                        path.read_text(), "existing independent evidence\n"
                    )

    def test_cross_leg_identity_collision_preserves_existing_evidence(self):
        before = self.snapshot()
        result = self.run_recorder(COLLIDE="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("staged cost filename identity collision", result.stderr)
        self.assertEqual(self.snapshot(), before)

    def test_complete_matrix_publishes_all_records_and_inventories(self):
        result = self.run_recorder()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        for index, suffix in enumerate(SUFFIXES):
            for number, layer in enumerate(("fast", "exhaustive")):
                key = f"{2 * index + number:016x}"
                inventory = (self.costs / f"inventory{suffix}.{layer}.txt").read_text()
                self.assertIn("#\tconfiguration\trecorder-control\n", inventory)
                self.assertEqual(inventory.splitlines()[-1], key)
                self.assertIn(
                    f"identity\tleg-{2 * index + number}\n",
                    (self.costs / f"{key}.txt").read_text(),
                )
        self.assertEqual(
            (self.costs / "existing.txt").read_text(), "existing evidence\n"
        )

    def interrupted(self):
        result = self.run_recorder(FAIL_LEG="1")
        self.assertNotEqual(result.returncode, 0)
        return next(self.root.glob("dcbor-costs.*"))

    def test_resume_skips_successful_leg_and_completes_remaining_seven(self):
        logs = self.interrupted()
        before = (logs / "0-fast.log").read_bytes()
        result = self.run_recorder(resume=logs, FAIL_LEG="0")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("reuse completed leg: 0-fast", result.stdout)
        self.assertEqual((logs / "0-fast.log").read_bytes(), before)
        for leg in range(8):
            self.assertTrue((self.costs / f"{leg:016x}.txt").exists())

    def test_resume_rejects_changed_configuration_without_publication(self):
        logs = self.interrupted()
        before = self.snapshot()
        result = self.run_recorder(resume=logs, DCBOR_CONFIGURATION="different")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.snapshot(), before)

    def test_resume_rejects_missing_staged_record_without_publication(self):
        logs = self.interrupted()
        (logs / "0-fast.records/0000000000000000.txt").unlink()
        before = self.snapshot()
        result = self.run_recorder(resume=logs)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.snapshot(), before)

    def test_resume_rejects_log_inventory_mismatch_without_publication(self):
        logs = self.interrupted()
        with (logs / "0-fast.log").open("a") as log:
            log.write("DCBOR_COST\tffffffffffffffff\n")
        before = self.snapshot()
        result = self.run_recorder(resume=logs)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.snapshot(), before)

    def completed_with_cargo_disabled(self):
        result = self.run_recorder()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        logs = next(self.root.glob("dcbor-costs.*"))
        (self.root / "bin" / "cargo").write_text(
            "#!/bin/sh\ntouch cargo-was-run\nexit 99\n"
        )
        return logs

    def test_reuse_checks_all_eight_legs_without_cargo_or_artifact_writes(self):
        logs = self.completed_with_cargo_disabled()
        before = self.snapshot()
        staged = {
            str(p.relative_to(logs)): p.read_bytes()
            for p in logs.rglob("*")
            if p.is_file()
        }
        result = self.run_recorder("check-costs", resume=logs)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout.count("reuse completed leg:"), 8)
        self.assertFalse((self.root / "cargo-was-run").exists())
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(
            {
                str(p.relative_to(logs)): p.read_bytes()
                for p in logs.rglob("*")
                if p.is_file()
            },
            staged,
        )

    def test_reuse_rejects_incomplete_and_corrupt_artifacts_without_cargo(self):
        logs = self.completed_with_cargo_disabled()
        cases = [
            (logs / "3-exhaustive.inventory.complete", None),
            (logs / "0-fast.log", b"DCBOR_COST\tffffffffffffffff\n"),
            (logs / "0-fast.inventory", b"ffffffffffffffff\n"),
            (logs / "0-fast.inventory.complete", b"wrong configuration\n"),
            (logs / "0-fast.records/0000000000000000.txt", None),
            (logs / "0-fast.records/0000000000000000.txt", b"changed measurement\n"),
            (
                self.costs / "0000000000000000.txt",
                b"#\tconfiguration\trecorder-control\nidentity\tleg-0\nchanged measurement\n",
            ),
        ]
        for path, replacement in cases:
            with self.subTest(path=path, replacement=replacement):
                original = path.read_bytes()
                try:
                    if replacement is None:
                        path.unlink()
                    else:
                        path.write_bytes(replacement)
                    result = self.run_recorder("check-costs", resume=logs)
                    self.assertNotEqual(
                        result.returncode, 0, result.stdout + result.stderr
                    )
                    self.assertFalse((self.root / "cargo-was-run").exists())
                finally:
                    path.write_bytes(original)

    def test_reuse_checks_external_baseline_and_rejects_orphans(self):
        logs = self.completed_with_cargo_disabled()
        external = self.root / "approved-baseline"
        shutil.move(self.costs, external)
        result = self.run_recorder(
            "check-costs", resume=logs, DCBOR_COST_BASELINE=str(external)
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        (external / self.STALE).write_text(self.STALE_CONTENT)
        result = self.run_recorder(
            "check-costs", resume=logs, DCBOR_COST_BASELINE=str(external)
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("no matrix of this configuration", result.stderr)
        self.assertFalse((self.root / "cargo-was-run").exists())

    def test_contribution_gate_forwards_explicit_reuse_and_propagates_failure(self):
        script = SCRIPT.with_name("run-contribution-contracts.sh")
        shutil.copyfile(script, self.root / "tests" / script.name)
        (self.root / "bin" / "cargo").write_text("#!/bin/sh\nexit 0\n")
        (self.root / "tests" / SCRIPT.name).write_text(
            '#!/bin/bash\nprintf "%s\\n" "$*" >> evidence-arguments\n'
            'if [[ "$1" == check-costs ]]; then exit "${REUSE_EXIT:-0}"; fi\n'
        )
        for status in (0, 1):
            with self.subTest(status=status):
                arguments = self.root / "evidence-arguments"
                arguments.unlink(missing_ok=True)
                result = subprocess.run(
                    ["bash", "tests/run-contribution-contracts.sh"],
                    cwd=self.root,
                    env={
                        **self.environment,
                        "DCBOR_COST_REUSE": "/completed run",
                        "REUSE_EXIT": str(status),
                    },
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(
                    result.returncode, status, result.stdout + result.stderr
                )
                self.assertEqual(
                    arguments.read_text().splitlines(),
                    ["check", "check-costs /completed run"],
                )


if __name__ == "__main__":
    unittest.main()
