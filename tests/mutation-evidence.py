#!/usr/bin/env python3
"""Compare complete cargo-mutants outcomes on one identical mutation domain.

A mutant missed by both layers is a defect of the suite unless the registry
of equivalent mutants declares it: a declaration names one mutant by the
mutation domain it exists in (the feature set its code is compiled under),
its file, its mutation, the source text its diff removes and the text it
puts in its place, never by line and column, with the reason no behavior
distinguishes it and the scope of that reason. The mutated text carries the
tool's change marker, so a tool version that renders mutants differently
makes declarations stale rather than silently matching. A declaration that
matches no mutant (stale, as after a change to the code it names) or more
than one (ambiguous), a duplicate, and a declared mutant some layer does
not miss are each rejected: equivalence is a claim to reconcile, never a
silent exemption.

A native run cannot see undefined behavior, so a survivor in a module that
holds `unsafe`, or in a descendant of one (tests/unsafe_census.rs), is not
decided by it: it is judged under Miri, both aliasing models, on exactly
the tests whose execution reaches its mutated span (tests/reach-map.sh,
tests/miri-owned.sh --judge). Its outcome is `caught_under_miri`,
`missed_under_miri`, `no_baseline` (a selected test without an unmutated
pass under both models), or `unreached_under_miri` (no test Miri runs
reaches it); a planned mutant without a verdict is `undecided`, a verdict
for no planned mutant `stale`, two for one `duplicate`. Only the first two
decide; every other fails the run.

Subcommands:
  compare FAST EXHAUSTIVE REGISTRY DOMAIN OUTPUT
      the native comparison of one domain's two layers
  miri-plan COMPARISON FAST SNAPSHOT REACH PLAN
      the survivors of tainted modules, each with the Miri-run tests that
      reach it and its diff, written to PLAN (plan.json, plan.tsv, diffs/)
  miri-verdict COMPARISON PLAN VERDICTS OUTPUT
      the run's verdict over the native comparison and the Miri verdicts
"""

import importlib.util
import json
from pathlib import Path
import sys
from types import ModuleType
from typing import Any

FIELDS = ("domain", "file", "mutation", "source", "mutated", "rationale", "scope")

# The mutation domains tests/mutation-evidence.sh runs: every feature, and
# the no_std build, whose code without std the first never compiles.
DOMAINS = ("all-features", "no_std")


def changed(diff, mark):
    """The trimmed lines of `diff` that `mark` ('-' or '+') introduces,
    headers excluded, joined by newlines."""
    return "\n".join(
        line[1:].strip()
        for line in diff.splitlines()
        if line.startswith(mark) and not line.startswith(mark * 3)
    )


def identity(mutant):
    """A mutant's identity without its position: its file, its mutation as
    named after the position, the source lines its diff removes, and the
    lines it adds in their place."""
    _, separator, mutation = mutant["name"].partition(": ")
    if not separator:
        raise ValueError(f"unrecognized mutant name: {mutant['name']}")
    diff = mutant["diff"]
    return (mutant["file"], mutation, changed(diff, "-"), changed(diff, "+"))


def load(directory):
    directory = Path(directory)
    planned = json.loads((directory / "mutants.json").read_text())
    report = json.loads((directory / "outcomes.json").read_text())
    domain = {}
    for mutant in planned:
        name = mutant["name"]
        if name in domain:
            raise ValueError(f"{directory}: duplicate mutant {name}")
        domain[name] = mutant
    if not domain:
        raise ValueError(f"{directory}: empty mutation domain")
    outcomes = {}
    baselines = []
    for outcome in report["outcomes"]:
        scenario = outcome["scenario"]
        if scenario == "Baseline":
            baselines.append(outcome)
            continue
        name = scenario["Mutant"]["name"]
        if name in outcomes or name not in domain:
            raise ValueError(f"{directory}: duplicated or unplanned result {name}")
        descriptor = {
            key: value for key, value in domain[name].items() if key != "diff"
        }
        if scenario["Mutant"] != descriptor:
            raise ValueError(f"{directory}: changed mutation for {name}")
        if (directory / outcome["diff_path"]).read_text() != domain[name]["diff"]:
            raise ValueError(
                f"{directory}: mutation diff does not match its plan: {name}"
            )
        outcomes[name] = outcome["summary"]
    if len(baselines) != 1 or baselines[0]["summary"] != "Success":
        raise ValueError(f"{directory}: a successful unmutated baseline is required")
    if set(outcomes) != set(domain) or report["total_mutants"] != len(domain):
        raise ValueError(f"{directory}: incomplete mutation execution")
    allowed = {"CaughtMutant", "MissedMutant", "Unviable", "Timeout"}
    if not set(outcomes.values()) <= allowed:
        raise ValueError(f"{directory}: unknown or failed mutation outcome")
    return domain, outcomes, report["cargo_mutants_version"]


def equivalents(registry, name, domain):
    """The mutants of `domain`, the mutation domain `name`, the registry
    declares equivalent, by mutant name, each with its declaration. Every
    declaration must be complete, distinct and of a known domain, and each
    of this domain's must match exactly one mutant."""
    if name not in DOMAINS:
        raise ValueError(f"unknown mutation domain {name!r}: the domains are {DOMAINS}")
    declarations = json.loads(Path(registry).read_text())
    if not isinstance(declarations, list):
        raise ValueError(f"{registry}: the registry is a list of declarations")
    by_identity = {}
    for mutant_name, mutant in domain.items():
        by_identity.setdefault(identity(mutant), []).append(mutant_name)
    declared = {}
    seen = set()
    for declaration in declarations:
        if not isinstance(declaration, dict) or set(declaration) != set(FIELDS):
            raise ValueError(f"{registry}: a declaration has exactly {FIELDS}")
        if not all(
            isinstance(declaration[field], str) and declaration[field]
            for field in FIELDS
        ):
            raise ValueError(f"{registry}: every declaration field is nonempty text")
        if declaration["domain"] not in DOMAINS:
            raise ValueError(
                f"{registry}: unknown domain {declaration['domain']!r}: the domains are {DOMAINS}"
            )
        key = (
            declaration["domain"],
            declaration["file"],
            declaration["mutation"],
            declaration["source"],
            declaration["mutated"],
        )
        if key in seen:
            raise ValueError(f"{registry}: duplicate declaration {key}")
        seen.add(key)
        if declaration["domain"] != name:
            continue
        matches = by_identity.get(key[1:], [])
        if not matches:
            raise ValueError(f"{registry}: stale declaration, no mutant is {key}")
        if len(matches) > 1:
            raise ValueError(
                f"{registry}: ambiguous declaration {key} matches {sorted(matches)}"
            )
        declared[matches[0]] = declaration
    return declared


def compare(fast_dir, exhaustive_dir, registry, name):
    domain, fast, version = load(fast_dir)
    other_domain, exhaustive, other_version = load(exhaustive_dir)
    if domain != other_domain or version != other_version:
        raise ValueError(
            "layers must run the same mutant diffs with the same tool version"
        )
    declared = equivalents(registry, name, domain)
    uncertain = sorted(
        name for name in domain if "Timeout" in (fast[name], exhaustive[name])
    )
    viability = sorted(
        name
        for name in domain
        if (fast[name] == "Unviable") != (exhaustive[name] == "Unviable")
    )
    gaps = sorted(
        name
        for name in domain
        if exhaustive[name] == "CaughtMutant" and fast[name] != "CaughtMutant"
    )
    reverse = sorted(
        name
        for name in domain
        if fast[name] == "CaughtMutant" and exhaustive[name] != "CaughtMutant"
    )
    measured = [
        name
        for name in domain
        if fast[name] in {"CaughtMutant", "MissedMutant"}
        and exhaustive[name] in {"CaughtMutant", "MissedMutant"}
    ]
    missed = sorted(
        name for name in measured if fast[name] == exhaustive[name] == "MissedMutant"
    )
    # A declared equivalent compiles and no layer detects it; anything else
    # refutes the declaration.
    refuted = sorted(name for name in declared if name not in missed)
    undeclared = sorted(name for name in missed if name not in declared)
    result = {
        "cargo_mutants_version": version,
        "domain": name,
        "mutants": len(domain),
        "comparable_viable": len(measured),
        "fast_caught": sum(fast[name] == "CaughtMutant" for name in measured),
        "exhaustive_caught": sum(
            exhaustive[name] == "CaughtMutant" for name in measured
        ),
        "unviable": sorted(
            name
            for name in domain
            if fast[name] == exhaustive[name] == "Unviable"
        ),
        "fast_missed_exhaustive_caught": gaps,
        "fast_caught_exhaustive_missed": reverse,
        "timeouts": uncertain,
        "viability_disagreements": viability,
        "equivalent": {
            name: {
                "rationale": declared[name]["rationale"],
                "scope": declared[name]["scope"],
            }
            for name in sorted(declared)
            if name in missed
        },
        "equivalents_refuted": refuted,
        "undeclared_survivors": undeclared,
        "outcomes": {
            name: {"fast": fast[name], "exhaustive": exhaustive[name]}
            for name in sorted(domain)
        },
    }
    passed = bool(measured) and not (
        uncertain or viability or gaps or reverse or refuted or undeclared
    )
    return result, passed


# The outcomes the Miri layer records (tests/miri-owned.sh --judge).
MIRI_OUTCOMES = ("caught_under_miri", "missed_under_miri", "no_baseline")


def reach_map() -> ModuleType:
    """tests/reach-map.py, whose census and region helpers the plan uses:
    one definition of a tainted module and of a region's reach."""
    spec = importlib.util.spec_from_file_location(
        "reach_map", Path(__file__).with_name("reach-map.py")
    )
    if spec is None or spec.loader is None:
        raise ValueError("tests/reach-map.py is not loadable beside this script")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def write(output: Path, text: str) -> None:
    temporary = output.with_suffix(".tmp")
    temporary.write_text(text)
    temporary.replace(output)


def miri_plan(comparison_path, fast_dir, snapshot_path, reach_dir, plan_dir):
    """The Miri layer's plan for one domain: every mutant both native layers
    missed whose span lies in a tainted module, with the tests of the reach
    map whose executed regions overlap the span. Those no test reaches are
    `unreached_under_miri`. The reach map must be of this run's sources: its
    identity inputs begin with the snapshot the mutation run took."""
    reach_helpers = reach_map()
    comparison = json.loads(Path(comparison_path).read_text())
    domain, _, _ = load(fast_dir)
    snapshot = Path(snapshot_path).read_text()
    reach_dir = Path(reach_dir)
    if not (reach_dir / "identity-inputs.txt").read_text().startswith(snapshot):
        raise ValueError(f"{reach_dir}: the reach map is of other sources than this run")
    reach = json.loads((reach_dir / "reach.json").read_text())
    census = reach_helpers.census_of(reach["census"])
    plan_dir = Path(plan_dir)
    (plan_dir / "diffs").mkdir(parents=True, exist_ok=True)
    missed = sorted(
        name
        for name, outcome in comparison["outcomes"].items()
        if outcome["fast"] == outcome["exhaustive"] == "MissedMutant"
    )
    planned: dict[str, Any] = {}
    unreached: list[str] = []
    lines: list[str] = []
    for name in missed:
        mutant = domain[name]
        span = mutant["span"]
        start = [span["start"]["line"], span["start"]["column"]]
        end = [span["end"]["line"], span["end"]["column"]]
        module = reach_helpers.module_of(census, mutant["file"], start[0])
        if module is None:
            raise ValueError(f"{name}: {mutant['file']}:{start[0]} lies in no module of the census")
        if not module.tainted:
            continue
        # Only the suites of this domain's build: another build compiles
        # other code at the same lines.
        tests = [
            [base, test]
            for base, suite in sorted(reach["suites"].items())
            if suite["domain"] == comparison["domain"]
            for test, executed in zip(suite["tests"], suite["reach"], strict=True)
            if any(
                reach_helpers.overlaps(region, start, end)
                for region in executed.get(mutant["file"], [])
            )
        ]
        if not tests:
            unreached.append(name)
            continue
        index = len(planned)
        if "\t" in name or "\n" in name:
            raise ValueError(f"a mutant name holds a tab or newline: {name!r}")
        diff = plan_dir / "diffs" / f"{index}.diff"
        diff.write_text(mutant["diff"])
        planned[name] = {"index": index, "module": module.module, "tests": tests}
        lines.append(f"mutant\t{index}\t{name}\t{diff.resolve()}")
        lines.extend(f"test\t{index}\t{base}\t{test}" for base, test in tests)
    write(plan_dir / "plan.tsv", "".join(f"{line}\n" for line in lines))
    write(
        plan_dir / "plan.json",
        json.dumps(
            {
                "domain": comparison["domain"],
                "reach_identity": reach["identity"],
                "planned": planned,
                "unreached_under_miri": unreached,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
    )
    return planned, unreached


def miri_verdict(comparison_path, plan_dir, verdicts_path):
    """The run's verdict for one domain: the native comparison, its
    survivors in tainted modules decided by their Miri outcomes."""
    comparison = json.loads(Path(comparison_path).read_text())
    plan = json.loads((Path(plan_dir) / "plan.json").read_text())
    if plan["domain"] != comparison["domain"]:
        raise ValueError("the Miri plan is of another domain than the comparison")
    planned = plan["planned"]
    unreached = sorted(plan["unreached_under_miri"])
    verdicts: dict[str, str] = {}
    duplicate: list[str] = []
    stale: list[str] = []
    for line in Path(verdicts_path).read_text().splitlines():
        if not line.strip():
            continue
        name, separator, outcome = line.rpartition("\t")
        if not separator or outcome not in MIRI_OUTCOMES:
            raise ValueError(f"{verdicts_path}: unrecognized verdict line {line!r}")
        if name not in planned:
            stale.append(name)
        elif name in verdicts:
            duplicate.append(name)
        else:
            verdicts[name] = outcome
    undecided = sorted(name for name in planned if name not in verdicts)
    no_baseline = sorted(name for name, outcome in verdicts.items() if outcome == "no_baseline")
    caught = sorted(
        name for name, outcome in verdicts.items() if outcome == "caught_under_miri"
    )
    tainted = set(planned) | set(unreached)
    # A survivor of a tainted module is decided under Miri: caught there, it
    # is detected; missed there, it survives as it did natively.
    undeclared = sorted(
        name for name in comparison["undeclared_survivors"] if name not in caught
    )
    # A declared equivalent Miri distinguishes is refuted.
    refuted_under_miri = sorted(name for name in comparison["equivalent"] if name in caught)
    result = {
        "domain": comparison["domain"],
        "reach_identity": plan["reach_identity"],
        "caught_under_miri": caught,
        "missed_under_miri": sorted(
            name for name, outcome in verdicts.items() if outcome == "missed_under_miri"
        ),
        "unreached_under_miri": unreached,
        "no_baseline": no_baseline,
        "undecided": undecided,
        "stale": sorted(stale),
        "duplicate": sorted(duplicate),
        "undeclared_survivors": undeclared,
        "undeclared_survivors_outside_unsafe_modules": sorted(
            name for name in undeclared if name not in tainted
        ),
        "equivalents_refuted_under_miri": refuted_under_miri,
    }
    native = (
        comparison["comparable_viable"] > 0
        and not comparison["timeouts"]
        and not comparison["viability_disagreements"]
        and not comparison["fast_missed_exhaustive_caught"]
        and not comparison["fast_caught_exhaustive_missed"]
        and not comparison["equivalents_refuted"]
    )
    passed = native and not (
        unreached
        or no_baseline
        or undecided
        or stale
        or duplicate
        or undeclared
        or refuted_under_miri
    )
    return result, passed


def main():
    command = sys.argv[1] if len(sys.argv) > 1 else ""
    if command == "compare" and len(sys.argv) == 7:
        result, passed = compare(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5])
        write(Path(sys.argv[6]), json.dumps(result, indent=2, sort_keys=True) + "\n")
        print(
            json.dumps(
                {key: value for key, value in result.items() if key != "outcomes"},
                indent=2,
            )
        )
        # The native comparison alone is not the run's verdict: survivors in
        # tainted modules are decided under Miri (`miri-verdict`).
        print(f"native comparison {'passed' if passed else 'failed'}")
        return 0
    if command == "miri-plan" and len(sys.argv) == 7:
        planned, unreached = miri_plan(*sys.argv[2:7])
        print(f"planned under Miri: {len(planned)}, unreached under Miri: {len(unreached)}")
        return 0
    if command == "miri-verdict" and len(sys.argv) == 6:
        result, passed = miri_verdict(sys.argv[2], sys.argv[3], sys.argv[4])
        write(Path(sys.argv[5]), json.dumps(result, indent=2, sort_keys=True) + "\n")
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if passed else 1
    raise ValueError(__doc__)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ValueError, KeyError, OSError, TypeError, json.JSONDecodeError) as error:
        sys.exit(f"mutation evidence rejected: {error}")
