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
from mutation_gate import measurement_from_log

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--coverage", type=pathlib.Path, required=True)
parser.add_argument("--mutation", type=pathlib.Path, required=True)
parser.add_argument("--fuzz", type=pathlib.Path, required=True)
parser.add_argument("--mutation-timeout-coefficient", type=int, default=10)
parser.add_argument("--mutation-workers", type=int, default=2)
args = parser.parse_args()
root = pathlib.Path(__file__).resolve().parents[1]
coverage = [line.split() for line in args.coverage.read_text().splitlines()[1:]]
mutation = args.mutation.read_text()
measurement = measurement_from_log(mutation)
fuzz_runs = []
for block in args.fuzz.read_text().split("go test ")[1:]:
    name = re.search(r"-fuzz '\^(Fuzz\w+)\$'", block)
    executions = re.findall(r"execs: (\d+)", block)
    if name is None or not executions or "\nPASS\n" not in block:
        raise ValueError("fuzz run must be complete")
    fuzz_runs.append({"target": name[1], "executions": int(executions[-1]), "seconds_requested": 10})
expected_fuzz = set()
for source in root.rglob("*_test.go"):
    relative = source.relative_to(root)
    if relative.parts[0] in {"tests", "adapters"}:
        continue
    expected_fuzz.update(re.findall(r"^func (Fuzz\w+)\(f \*testing.F\)", source.read_text(encoding="utf-8"), re.M))
if len(fuzz_runs) != len(expected_fuzz) or {run["target"] for run in fuzz_runs} != expected_fuzz:
    raise ValueError("expected every distinct root-module fuzz target")
snapshot = {
    "date": datetime.datetime.now(datetime.timezone.utc).date().isoformat(),
    "covered_statements": sum(int(fields[1]) for fields in coverage if int(fields[2]) > 0),
    "total_statements": sum(int(fields[1]) for fields in coverage),
    "mutation": measurement['mutation'],
    "efficacy": measurement['efficacy'],
    "mutation_timeout_coefficient": args.mutation_timeout_coefficient,
    "mutation_workers": args.mutation_workers,
    "mutator_coverage": measurement['mutator_coverage'],
    "fuzz": fuzz_runs,
    "source_sha256": {name: hashlib.sha256(path.read_bytes()).hexdigest() for name, path in [("coverage", args.coverage), ("mutation", args.mutation), ("fuzz", args.fuzz)]},
}
(root / "doc/testing-metrics.json").write_text(json.dumps(snapshot, indent=2) + "\n")
subprocess.run(["go", "-C", "tests", "test", "-run", "^TestTestingMetrics$", "-count=1", "."], cwd=root, check=True, env=os.environ | {"UPDATE_DOCS": "1"})
