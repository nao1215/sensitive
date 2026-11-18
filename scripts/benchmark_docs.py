#!/usr/bin/env python3
"""Run the published Go benchmarks and store their medians and provenance."""
import datetime
import json
import os
import pathlib
import re
import statistics
import subprocess

root = pathlib.Path(__file__).resolve().parents[1]
# The parallel benchmarks run up to 16 goroutines with matching GOMAXPROCS;
# pinned to fewer CPUs they would publish a speed-up that does not exist.
PARALLEL_CPUS = 16
if hasattr(os, "sched_getaffinity") and len(os.sched_getaffinity(0)) < PARALLEL_CPUS:
    raise SystemExit(f"benchmark-doc needs at least {PARALLEL_CPUS} CPUs in its affinity for the parallel table; do not pin it with taskset")
command = ["go", "-C", "tests", "test", "-run", "^$", "-bench", "^BenchmarkPublished", "-benchmem", "-benchtime=200ms", "-count=10", "."]
environment = dict(os.environ, GOMAXPROCS="1", GOTOOLCHAIN="go1.26.11")
result = subprocess.run(command, cwd=root, env=environment, text=True, stdout=subprocess.PIPE, check=True)
(root / "doc/benchmarks.raw.txt").write_text(result.stdout)
rows = {}
for line in result.stdout.splitlines():
    match = re.match(r"(BenchmarkPublished\S+?)(?:-\d+)?\s+\d+\s+(.+)", line)
    if not match:
        continue
    values = {unit: float(value) for value, unit in re.findall(r"([\d.]+)\s+(ns/op|MB/s|B/op|allocs/op)", match[2])}
    rows.setdefault(match[1], []).append(values)
if not rows or any(len(values) != 10 for values in rows.values()):
    raise RuntimeError("each benchmark must have ten samples")
snapshot = {
    "date": datetime.datetime.now(datetime.timezone.utc).date().isoformat(),
    "go_version": subprocess.check_output(["go", "env", "GOVERSION"], env=environment, text=True).strip(),
    "os": re.search(r"^goos: (.+)$", result.stdout, re.M)[1].strip(),
    "arch": re.search(r"^goarch: (.+)$", result.stdout, re.M)[1].strip(),
    "cpu": re.search(r"^cpu: (.+)$", result.stdout, re.M)[1].strip(),
    "command": "GOMAXPROCS=1 GOTOOLCHAIN=go1.26.11 " + " ".join(command),
    "samples": 10,
    "cpu_affinity": sorted(os.sched_getaffinity(0)) if hasattr(os, "sched_getaffinity") else None,
    "background_load": os.environ.get("EMBARGO_BENCH_LOAD", "no intentional concurrent workload"),
    "benchmarks": {name: {unit: statistics.median(item[unit] for item in values) for unit in values[0]} for name, values in sorted(rows.items())},
}
(root / "doc/benchmarks.json").write_text(json.dumps(snapshot, indent=2) + "\n")
subprocess.run(["go", "-C", "tests", "test", "-run", "^TestBenchmarkTable$", "-count=1", "."], cwd=root, env=dict(environment, UPDATE_DOCS="1"), check=True)

subprocess.run(["python3", "scripts/doc_figures.py"], cwd=root, check=True)
