#!/usr/bin/env python3
"""Publish completed coverage, mutation and fuzz command results."""
import argparse
import datetime
import hashlib
import json
import os
import pathlib
import re
import subprocess

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--coverage", type=pathlib.Path, required=True)
parser.add_argument("--mutation", type=pathlib.Path, required=True)
parser.add_argument("--fuzz", type=pathlib.Path, required=True)
parser.add_argument("--commit", required=True)
parser.add_argument("--mutation-timeout-coefficient", type=int, default=100)
args = parser.parse_args()
root = pathlib.Path(__file__).resolve().parents[1]
coverage = [line.split() for line in args.coverage.read_text().splitlines()[1:]]
mutation = args.mutation.read_text()
summary = re.search(r"Killed: (\d+), Lived: (\d+), Not covered: (\d+)\s+Timed out: (\d+), Not viable: (\d+), Skipped: (\d+)\s+Test efficacy: ([\d.]+)%\s+Mutator coverage: ([\d.]+)%", mutation)
if not summary or "Mutation testing completed" not in mutation:
    raise ValueError("mutation run must be complete")
fuzz_runs = []
for block in args.fuzz.read_text().split("go test ")[1:]:
    name = re.search(r"-fuzz '\^(Fuzz\w+)\$'", block)
    executions = re.findall(r"execs: (\d+)", block)
    if name is None or not executions or "\nPASS\n" not in block:
        raise ValueError("fuzz run must be complete")
    fuzz_runs.append({"target": name[1], "executions": int(executions[-1]), "seconds_requested": 10})
if len(fuzz_runs) != 6 or len({run["target"] for run in fuzz_runs}) != 6:
    raise ValueError("expected all six distinct fuzz targets")
snapshot = {
    "date": datetime.datetime.now(datetime.timezone.utc).date().isoformat(),
    "commit": args.commit,
    "covered_statements": sum(int(fields[1]) for fields in coverage if int(fields[2]) > 0),
    "total_statements": sum(int(fields[1]) for fields in coverage),
    "mutation": dict(zip(["killed", "lived", "uncovered", "timed_out", "not_viable", "skipped"], map(int, summary.groups()[:6]))),
    "efficacy": float(summary[7]),
    "mutation_timeout_coefficient": args.mutation_timeout_coefficient,
    "mutation_workers": 4,
    "mutator_coverage": float(summary[8]),
    "fuzz": fuzz_runs,
    "source_sha256": {name: hashlib.sha256(path.read_bytes()).hexdigest() for name, path in [("coverage", args.coverage), ("mutation", args.mutation), ("fuzz", args.fuzz)]},
}
(root / "doc/testing-metrics.json").write_text(json.dumps(snapshot, indent=2) + "\n")
subprocess.run(["go", "-C", "tests", "test", "-run", "^TestTestingMetrics$", "-count=1", "."], cwd=root, check=True, env=os.environ | {"UPDATE_DOCS": "1"})
