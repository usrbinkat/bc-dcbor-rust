#!/usr/bin/env python3
"""Compare complete cargo-mutants outcomes on one identical mutation domain."""

import json
from pathlib import Path
import sys


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


def compare(fast_dir, exhaustive_dir):
    domain, fast, version = load(fast_dir)
    other_domain, exhaustive, other_version = load(exhaustive_dir)
    if domain != other_domain or version != other_version:
        raise ValueError(
            "layers must run the same mutant diffs with the same tool version"
        )
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
    result = {
        "cargo_mutants_version": version,
        "domain": len(domain),
        "comparable_viable": len(measured),
        "fast_caught": sum(fast[name] == "CaughtMutant" for name in measured),
        "exhaustive_caught": sum(
            exhaustive[name] == "CaughtMutant" for name in measured
        ),
        "fast_missed_exhaustive_caught": gaps,
        "fast_caught_exhaustive_missed": reverse,
        "timeouts": uncertain,
        "viability_disagreements": viability,
        "missed_by_both": sorted(
            name
            for name in measured
            if fast[name] == exhaustive[name] == "MissedMutant"
        ),
        "outcomes": {
            name: {"fast": fast[name], "exhaustive": exhaustive[name]}
            for name in sorted(domain)
        },
    }
    return result, bool(measured) and not (uncertain or viability or gaps or reverse)


def main():
    if len(sys.argv) != 4:
        raise ValueError(
            "usage: mutation-evidence.py FAST_DIR EXHAUSTIVE_DIR OUTPUT_JSON"
        )
    result, passed = compare(sys.argv[1], sys.argv[2])
    output = Path(sys.argv[3])
    temporary = output.with_suffix(".tmp")
    temporary.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    temporary.replace(output)
    print(
        json.dumps(
            {key: value for key, value in result.items() if key != "outcomes"}, indent=2
        )
    )
    return 0 if passed else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ValueError, KeyError, OSError, TypeError) as error:
        sys.exit(f"mutation evidence rejected: {error}")
