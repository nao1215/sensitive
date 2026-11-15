#!/usr/bin/env python3
"""Measure once, then deterministically render the comparison table and SVG."""
import argparse
import datetime
import hashlib
import html
import json
import os
import pathlib
import re
import shlex
import statistics
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
DOC = ROOT / "doc"
COMMAND = ["go", "-C", "tests", "test", "-run", "^$", "-bench", "^Benchmark(Comparison|StructuredPath)", "-benchmem", "-benchtime=200ms", "-count=10", "."]


def source_hash():
    paths = sorted(list(ROOT.glob("*.go")) + list((ROOT / "internal").rglob("*.go")) + list((ROOT / "tests").glob("comparison*_test.go")) + [ROOT / "go.mod", ROOT / "tests/go.mod", ROOT / "tests/go.sum"])
    digest = hashlib.sha256()
    for path in paths:
        digest.update(path.relative_to(ROOT).as_posix().encode() + b"\0" + path.read_text(encoding="utf-8").encode())
    return digest.hexdigest()


def parse(raw):
    rows = {}
    for line in raw.splitlines():
        match = re.match(r"(Benchmark\S+?)(?:-\d+)?\s+\d+\s+(.+)", line)
        if match:
            values = {unit: float(value) for value, unit in re.findall(r"([\d.]+)\s+(ns/op|B/op|allocs/op)", match[2])}
            rows.setdefault(match[1], []).append(values)
    if not rows or any(len(v) != 10 for v in rows.values()):
        raise ValueError("each benchmark requires ten samples")
    return {name: {unit: statistics.median(x[unit] for x in values) for unit in ("ns/op", "B/op", "allocs/op")} for name, values in sorted(rows.items())}


def measure():
    env = dict(os.environ, GOMAXPROCS="1", GOTOOLCHAIN="go1.26.11")
    subprocess.run(["go", "-C", "tests", "test", "-run", "^TestComparison(Correctness|OtherLibraries)$", "-count=1", "."], cwd=ROOT, env=dict(env, UPDATE_DOCS="1"), check=True)
    raw = subprocess.check_output(COMMAND, cwd=ROOT, env=env, text=True)
    (DOC / "comparison.raw.txt").write_text(raw, encoding="utf-8")
    with tempfile.TemporaryDirectory(prefix="embargo-benchstat-") as tmp:
        files = []
        for mode in ("masq", "embargo"):
            path = pathlib.Path(tmp) / (mode + ".txt")
            lines = []
            for line in raw.splitlines():
                if not line.startswith("Benchmark"):
                    if re.match(r"(goos|goarch|pkg|cpu):", line):
                        lines.append(line)
                    continue
                match = re.match(r"(BenchmarkComparison/[^/]+)/" + mode + r"(-\d+)?(\s.+)", line)
                if match:
                    lines.append(match[1] + (match[2] or "") + match[3])
            path.write_text("\n".join(lines) + "\n", encoding="utf-8")
            files.append(path.name)
        stats = subprocess.check_output(["benchstat", *files], cwd=tmp, text=True)
    (DOC / "comparison.benchstat.txt").write_text(stats, encoding="utf-8")
    meta = {
        "date": datetime.datetime.now(datetime.timezone.utc).date().isoformat(),
        "command": "GOMAXPROCS=1 GOTOOLCHAIN=go1.26.11 " + shlex.join(COMMAND),
        "go": subprocess.check_output(["go", "version"], env=env, text=True).strip(),
        "base_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        "source_sha256": source_hash(),
        "raw_sha256": hashlib.sha256(raw.encode()).hexdigest(),
        "benchstat_sha256": hashlib.sha256(stats.encode()).hexdigest(),
        "cpu": re.search(r"^cpu: (.+)$", raw, re.M)[1].strip(),
        "affinity": sorted(os.sched_getaffinity(0)) if hasattr(os, "sched_getaffinity") else None,
        "background_load": "no intentional concurrent workload",
        "versions": {"masq": "v0.2.3", "slog-formatter": "v1.3.0", "godlp": "v1.2.15", "go-mask": "v0.6.2"},
    }
    (DOC / "comparison.json").write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")


def rendered(raw, meta):
    rows = parse(raw)
    text = "| Benchmark | ns/op | B/op | allocs/op |\n|---|---:|---:|---:|\n"
    for name, values in rows.items():
        text += f"| {name.removeprefix('Benchmark')} | {values['ns/op']:,.1f} | {values['B/op']:,.0f} | {values['allocs/op']:,.0f} |\n"
    text += f"\nMeasured {meta['date']} with {meta['go']}, Linux/amd64, {meta['cpu']}; GOMAXPROCS=1, ten 200 ms samples per case. Construction is outside the timed loop; JSON encoding and masking are included. Source and dependency fingerprints, CPU affinity and command are in [comparison.json](comparison.json).\n"
    ratios = [rows[f"BenchmarkComparison/{event}/embargo"]["ns/op"] / rows[f"BenchmarkComparison/{event}/masq"]["ns/op"] for event in ("flat", "nested", "map", "clean", "large50")]
    shape_ratio = rows["BenchmarkStructuredPath/json_shape"]["ns/op"] / rows["BenchmarkStructuredPath/old_string"]["ns/op"]
    text += f"\nFor these five configured events, embargo/masq median time ranges from {min(ratios):.2f} to {max(ratios):.2f}; below 1 means less time for embargo. The structured JSON path uses {shape_ratio:.2f} times the old string-only time. These ratios are regenerated from the same samples as the table.\n"
    svg = ['<svg xmlns="http://www.w3.org/2000/svg" width="920" height="440" viewBox="0 0 920 440" role="img" aria-labelledby="title desc">', '<title id="title">JSON logging: median time per event</title>', '<desc id="desc">Identical events with masq regex and field rules, and embargo detectors and key rules. Lower is faster. See the adjacent measured table for numbers and allocations.</desc>', '<rect width="920" height="440" fill="#101923"/>', '<g font-family="sans-serif" fill="#eff6ff"><text x="24" y="32" font-size="22">JSON logging · median ns/op · lower is faster</text><text x="24" y="58" font-size="14">masq v0.2.3 (blue) / embargo (green) · ten samples</text>']
    events = ("flat", "nested", "map", "clean", "large50")
    maximum = max(rows[f"BenchmarkComparison/{e}/{m}"]["ns/op"] for e in events for m in ("masq", "embargo"))
    for index, event in enumerate(events):
        y = 90 + index * 64
        svg.append(f'<text x="24" y="{y+20}" font-size="16">{html.escape(event)}</text>')
        for offset, mode, color in ((0, "masq", "#68a6fa"), (25, "embargo", "#55d6b0")):
            value = rows[f"BenchmarkComparison/{event}/{mode}"]["ns/op"]
            width = value / maximum * 580
            svg.append(f'<rect x="130" y="{y+offset}" width="{width:.2f}" height="19" rx="3" fill="{color}"/><text x="{140+width:.2f}" y="{y+offset+15}" font-size="13">{value:,.1f}</text>')
    svg.append('</g></svg>\n')
    return text, "\n".join(svg)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--measure", action="store_true")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if args.measure:
        measure()
    raw = (DOC / "comparison.raw.txt").read_text(encoding="utf-8")
    meta = json.loads((DOC / "comparison.json").read_text(encoding="utf-8"))
    if meta["source_sha256"] != source_hash():
        raise SystemExit("comparison source changed: run make comparison-doc")
    for name, field in (("comparison.raw.txt", "raw_sha256"), ("comparison.benchstat.txt", "benchstat_sha256")):
        if hashlib.sha256((DOC / name).read_text(encoding="utf-8").encode()).hexdigest() != meta[field]:
            raise SystemExit("comparison evidence changed: " + name)
    table, svg = rendered(raw, meta)
    page = DOC / "comparison.md"
    original = page.read_text(encoding="utf-8")
    updated = re.sub(r"(?s)(<!-- comparison:start -->\n).*?(<!-- comparison:end -->)", lambda m: m[1] + table + m[2], original)
    correctness = (DOC / "comparison-correctness.md").read_text(encoding="utf-8")
    updated = re.sub(r"(?s)(<!-- correctness:start -->\n).*?(<!-- correctness:end -->)", lambda m: m[1] + correctness + m[2], updated)
    for path, content in ((page, updated), (DOC / "images/comparison.svg", svg)):
        if args.check:
            if path.read_text(encoding="utf-8") != content:
                raise SystemExit("stale generated comparison: " + str(path))
        else:
            path.write_text(content, encoding="utf-8")


if __name__ == "__main__":
    main()
