#!/usr/bin/env python3
"""The reach map's records (tests/reach-map.sh), from LLVM's coverage export.

`llvm-cov export -format=text` writes `llvm.coverage.json.export`: each
instrumented function with its execution count, its file names, and its
regions, `[line_start, col_start, line_end, col_end, count, file_id,
expanded_file_id, kind]`, where kind 0 is a code region (1 an expansion, 2
skipped, 3 a gap, 4 a branch). Only this crate's `src/` is kept: a mutant
lies there.

Subcommands:
  executable          the one test executable of a `cargo test --no-run
                      --message-format=json` run, read from standard input
  regions ROOT        the code regions a test executed, by file under ROOT
  functions ROOT      every instrumented function under ROOT/src and its span
  index OUT BASE...   reach.json from the run's records; fails when a
                      function of a tainted module outside test code is
                      reached by no test Miri runs, or when a test at minimal
                      witness sizes leaves unexecuted a region its full-size
                      run executes
"""

from dataclasses import asdict, dataclass
import json
from pathlib import Path
import sys
from typing import Any, Self, get_type_hints

CODE = 0


def lines(span: Any) -> bool:
    """Whether `span` is a nonempty range of lines from 1: a list of two
    integers, the first at most the second."""
    if type(span) is not list or len(span) != 2:
        return False
    start, end = span
    return type(start) is int and type(end) is int and 1 <= start <= end


@dataclass(frozen=True, slots=True, kw_only=True)
class CensusModule:
    """One module of the census tests/unsafe_census.rs writes: its file, path
    and line span, whether its own code holds `unsafe`, whether it or an
    ancestor does (tainted), whether it or an ancestor is compiled only under
    `cfg(test)` (test code), and the line spans of its own items so compiled
    (`test_items`), test code within a shipped module. The one shape the
    census's readers accept: a row is parsed through `from_record`, never
    read as a loose mapping."""

    file: str
    module: str
    start: int
    end: int
    unsafe: bool
    tainted: bool
    test: bool
    test_items: tuple[tuple[int, int], ...]

    @classmethod
    def from_record(cls, record: Any) -> Self:
        """The module a census row records: exactly this class's fields, each
        scalar of exactly its type (a boolean is no integer, nor an integer a
        boolean), its span and every test item's a nonempty range of lines
        from 1."""
        if not isinstance(record, dict):
            raise ValueError(f"a census row is an object, not {record!r}")
        types = get_type_hints(cls)
        missing = sorted(set(types) - set(record))
        unexpected = sorted(set(record) - set(types))
        if missing or unexpected:
            raise ValueError(
                f"census row {record!r}: missing {missing}, unexpected {unexpected}"
            )
        for field, expected in types.items():
            if field == "test_items":
                continue
            if type(record[field]) is not expected:
                raise ValueError(
                    f"census row {record!r}: {field} is {type(record[field]).__name__}, "
                    f"not {expected.__name__}"
                )
        if not 1 <= record["start"] <= record["end"]:
            raise ValueError(f"census row {record!r}: its span is not a range of lines")
        items = record["test_items"]
        if type(items) is not list or not all(lines(item) for item in items):
            raise ValueError(
                f"census row {record!r}: test_items is not a list of ranges of lines"
            )
        return cls(**{**record, "test_items": tuple(tuple(item) for item in items)})

    def to_record(self) -> dict[str, Any]:
        """The census row of this module."""
        record = asdict(self)
        record["test_items"] = [list(item) for item in self.test_items]
        return record

    def holds_test_item(self, line: int) -> bool:
        """Whether `line` lies in one of this module's test-only items."""
        return any(start <= line <= end for start, end in self.test_items)


def executable() -> str:
    """The one test executable a cargo build reported."""
    found: list[str] = []
    for line in sys.stdin:
        line = line.strip()
        if not line.startswith("{"):
            continue
        message = json.loads(line)
        if (
            message.get("reason") == "compiler-artifact"
            and message.get("executable")
            and message.get("profile", {}).get("test")
        ):
            found.append(message["executable"])
    if len(found) != 1:
        raise ValueError(f"expected one test executable, found {found}")
    return found[0]


def relative(root: Path, filename: str) -> str | None:
    """`filename` relative to `root` when it lies under `root/src`."""
    path = Path(filename)
    try:
        shown = path.relative_to(root)
    except ValueError:
        return None
    return str(shown) if shown.parts and shown.parts[0] == "src" else None


def export(stream: Any) -> list[dict[str, Any]]:
    data = json.load(stream)
    if data.get("type") != "llvm.coverage.json.export":
        raise ValueError(f"not an llvm-cov export: {data.get('type')!r}")
    functions: list[dict[str, Any]] = []
    for unit in data["data"]:
        functions.extend(unit["functions"])
    return functions


def regions(root: Path) -> dict[str, list[list[int]]]:
    """The code regions executed, by file under `root/src`, sorted and
    distinct."""
    executed: dict[str, set[tuple[int, int, int, int]]] = {}
    for function in export(sys.stdin):
        filenames = function["filenames"]
        for line_start, col_start, line_end, col_end, count, file_id, _, kind in function[
            "regions"
        ]:
            if kind != CODE or count == 0:
                continue
            shown = relative(root, filenames[file_id])
            if shown is None:
                continue
            executed.setdefault(shown, set()).add((line_start, col_start, line_end, col_end))
    return {
        file: [list(region) for region in sorted(spans)]
        for file, spans in sorted(executed.items())
    }


def functions(root: Path) -> list[dict[str, Any]]:
    """Every instrumented function under `root/src`: its name, its file
    and the span of its code regions there, sorted and distinct."""
    found: set[tuple[str, str, int, int, int, int]] = set()
    for function in export(sys.stdin):
        filenames = function["filenames"]
        code = [region for region in function["regions"] if region[7] == CODE]
        if not code:
            continue
        shown = relative(root, filenames[code[0][5]])
        if shown is None:
            continue
        own = [region for region in code if region[5] == code[0][5]]
        start = min((region[0], region[1]) for region in own)
        end = max((region[2], region[3]) for region in own)
        found.add((function["name"], shown, start[0], start[1], end[0], end[1]))
    return [
        {
            "name": name,
            "file": file,
            "start": [start_line, start_col],
            "end": [end_line, end_col],
        }
        for name, file, start_line, start_col, end_line, end_col in sorted(found)
    ]


def contains(region: list[int], line: int, col: int) -> bool:
    """Whether code region `region` contains the position `line:col`."""
    line_start, col_start, line_end, col_end = region
    return (line_start, col_start) <= (line, col) <= (line_end, col_end)


def overlaps(region: list[int], start: list[int], end: list[int]) -> bool:
    """Whether code region `region` overlaps the span `start..end`."""
    line_start, col_start, line_end, col_end = region
    return (line_start, col_start) <= (end[0], end[1]) and (start[0], start[1]) <= (
        line_end,
        col_end,
    )


def census_of(rows: Any) -> list[CensusModule]:
    """The census `rows` record, each row parsed; an empty census, or one
    that is no list, is rejected."""
    if not isinstance(rows, list) or not rows:
        raise ValueError(f"the census is a nonempty list of rows, not {rows!r}")
    return [CensusModule.from_record(row) for row in rows]


def load_census(out: Path) -> list[CensusModule]:
    """The census the reach map's run wrote to `out/census.jsonl`, one row
    per line."""
    path = out / "census.jsonl"
    return census_of(
        [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    )


def module_of(census: list[CensusModule], file: str, line: int) -> CensusModule | None:
    """The innermost module of the census containing `file:line`."""
    within = [
        module
        for module in census
        if module.file == file and module.start <= line <= module.end
    ]
    if not within:
        return None
    return min(within, key=lambda module: module.end - module.start)


def lost(
    minimal: dict[str, list[list[int]]], full: dict[str, list[list[int]]]
) -> dict[str, list[list[int]]]:
    """The regions a test's full-size run executed and its minimal run did
    not, by file."""
    missing: dict[str, list[list[int]]] = {}
    for file, spans in full.items():
        kept = {tuple(span) for span in minimal.get(file, [])}
        dropped = [span for span in spans if tuple(span) not in kept]
        if dropped:
            missing[file] = dropped
    return missing


def index(out: Path, bases: list[str]) -> int:
    """reach.json from the run's records; 1 when a function of a tainted
    module is reached by no test Miri runs, or when a test's minimal witness
    leaves unexecuted a region its full witness executes. Test code (a module
    the census finds compiled only under `cfg(test)`, or such an item of a
    shipped module) is never mutated, so it is no trust boundary and is not
    required reached."""
    census = load_census(out)
    suites: dict[str, Any] = {}
    reached_by: dict[str, list[list[int]]] = {}
    instrumented: dict[tuple[str, str, int, int, int, int], dict[str, Any]] = {}
    witness_loss: list[dict[str, Any]] = []
    for base in bases:
        tests = [
            line
            for line in (out / f"{base}.tests").read_text().splitlines()
            if line.strip()
        ]
        reach = [
            json.loads((out / "reach" / base / f"{at}.json").read_text())
            for at in range(len(tests))
        ]
        full = [
            json.loads((out / "reach-full" / base / f"{at}.json").read_text())
            for at in range(len(tests))
        ]
        for test, minimal_regions, full_regions in zip(tests, reach, full, strict=True):
            missing = lost(minimal_regions, full_regions)
            if missing:
                witness_loss.append({"suite": base, "test": test, "regions": missing})
        suites[base] = {
            "domain": (out / f"{base}.domain").read_text().strip(),
            "kind": (out / f"{base}.kind").read_text().strip(),
            "tests": tests,
            "reach": reach,
        }
        for executed in reach:
            for file, spans in executed.items():
                reached_by.setdefault(file, []).extend(spans)
        for function in json.loads((out / "functions" / f"{base}.json").read_text()):
            key = (
                function["name"],
                function["file"],
                *function["start"],
                *function["end"],
            )
            instrumented[key] = function
    unreached = []
    for function in instrumented.values():
        module = module_of(census, function["file"], function["start"][0])
        if module is None:
            raise ValueError(
                f"{function['file']}:{function['start'][0]} lies in no module of the census"
            )
        if (
            not module.tainted
            or module.test
            or module.holds_test_item(function["start"][0])
        ):
            continue
        if not any(
            overlaps(region, function["start"], function["end"])
            for region in reached_by.get(function["file"], [])
        ):
            unreached.append({**function, "module": module.module})
    unreached.sort(key=lambda function: (function["file"], function["start"]))
    record = {
        "identity": (out / "identity.txt").read_text().strip(),
        "census": [module.to_record() for module in census],
        "suites": suites,
        "unreached_functions": unreached,
        "witness_loss": witness_loss,
    }
    target = out / "reach.json"
    temporary = target.with_suffix(".tmp")
    temporary.write_text(json.dumps(record, sort_keys=True) + "\n")
    temporary.replace(target)
    for function in unreached:
        print(
            f"unreached under Miri: {function['file']}:{function['start'][0]} "
            f"{function['name']} ({function['module']})",
            file=sys.stderr,
        )
    for loss in witness_loss:
        for file, spans in sorted(loss["regions"].items()):
            for line_start, col_start, line_end, col_end in spans:
                print(
                    f"minimal witness drops a path: {loss['suite']} {loss['test']}: "
                    f"{file}:{line_start}:{col_start}-{line_end}:{col_end}",
                    file=sys.stderr,
                )
    return 1 if unreached or witness_loss else 0


def main() -> int:
    if len(sys.argv) < 2:
        raise ValueError(__doc__)
    command = sys.argv[1]
    if command == "executable" and len(sys.argv) == 2:
        print(executable())
        return 0
    if command == "regions" and len(sys.argv) == 3:
        json.dump(regions(Path(sys.argv[2])), sys.stdout, sort_keys=True)
        print()
        return 0
    if command == "functions" and len(sys.argv) == 3:
        json.dump(functions(Path(sys.argv[2])), sys.stdout, sort_keys=True)
        print()
        return 0
    if command == "index" and len(sys.argv) >= 4:
        return index(Path(sys.argv[2]), sys.argv[3:])
    raise ValueError(__doc__)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ValueError, KeyError, OSError, TypeError, json.JSONDecodeError) as error:
        sys.exit(f"reach map rejected: {error}")
