#!/usr/bin/env python3
"""Measure once, then deterministically render the comparison table and SVG."""
import argparse
import datetime
import hashlib
import json
import os
import pathlib
import re
import shlex
import statistics
import subprocess
import tempfile

from doc_figures import SVG

ROOT = pathlib.Path(__file__).resolve().parents[1]
DOC = ROOT / "doc"
COMMAND = ["go", "-C", "tests", "test", "-run", "^$", "-bench", "^Benchmark(Comparison|StructuredPath)", "-benchmem", "-benchtime=200ms", "-count=10", "."]


def full_source_hash():
    paths = sorted(list(ROOT.glob("*.go")) + list((ROOT / "internal").rglob("*.go")) + list((ROOT / "tests").glob("comparison*_test.go")) + [ROOT / "go.mod", ROOT / "tests/go.mod", ROOT / "tests/go.sum"])
    digest = hashlib.sha256()
    for path in paths:
        digest.update(path.relative_to(ROOT).as_posix().encode() + b"\0" + path.read_text(encoding="utf-8").encode())
    return digest.hexdigest()


# Modules reached by go list -deps on the compared libraries. A version
# change here invalidates timings; unrelated SDK/test dependencies do not.
MEASURED_MODULES = (
    "github.com/bytedance/godlp", "github.com/m-mizutani/masq", "github.com/icntswm/go-masker",
    "github.com/pii-shield/pii-shield/v3", "github.com/awslabs/ferret-scan/v2", "gopkg.in/yaml.v3",
    "github.com/samber/lo", "github.com/samber/slog-common",
    "github.com/samber/slog-formatter", "github.com/samber/slog-multi",
    "github.com/showa-93/go-mask", "golang.org/x/text", "gopkg.in/yaml.v2",
)


def source_hash():
    paths = sorted([p for p in ROOT.glob("*.go") if not p.name.endswith("_test.go")]
                   + [p for p in (ROOT / "internal").rglob("*.go") if not p.name.endswith("_test.go")]
                   + list((ROOT / "tests").glob("comparison*_test.go")) + [ROOT / "go.mod"])
    digest = hashlib.sha256()
    for path in paths:
        digest.update(path.relative_to(ROOT).as_posix().encode() + b"\0" + path.read_bytes())
    for name in ("go.mod", "go.sum"):
        for line in (ROOT / "tests" / name).read_text(encoding="utf-8").splitlines():
            words = line.split()
            if any(module in words for module in MEASURED_MODULES) or (words and words[0] in ("go", "toolchain")):
                digest.update(name.encode() + b"\0" + " ".join(words).encode() + b"\n")
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


def runtime_modules(env):
    packages = {"embargo": "github.com/nao1215/embargo", "masq": "github.com/m-mizutani/masq", "go-masker": "github.com/icntswm/go-masker/slogmask", "slog-formatter": "github.com/samber/slog-formatter", "go-mask": "github.com/showa-93/go-mask", "godlp": "github.com/bytedance/godlp", "pii-shield": "github.com/pii-shield/pii-shield/v3/pkg/scanner", "ferret-scan": "github.com/awslabs/ferret-scan/v2/pkg/redact"}
    result = {}
    for name, package in packages.items():
        own = package.removesuffix('/slogmask').removesuffix('/pkg/scanner').removesuffix('/pkg/redact')
        raw = subprocess.check_output(['go', '-C', 'tests', 'list', '-deps', '-f', '{{if not .Standard}}{{if .Module}}{{.Module.Path}}{{end}}{{end}}', package], cwd=ROOT, env=env, text=True)
        result[name] = sorted(set(raw.split()) - {own})
    return result


def measure():
    env = dict(os.environ, GOMAXPROCS="1", GOTOOLCHAIN="go1.26.11")
    subprocess.run(["go", "-C", "tests", "test", "-run", "^Test(Comparison(Correctness|OtherLibraries|Scenarios|MaskerAdapters)|LeakScenarios)$", "-count=1", "."], cwd=ROOT, env=dict(env, UPDATE_DOCS="1"), check=True)
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
        "runtime_modules": runtime_modules(env),
        "benchmarks": parse(raw),
        "scenarios_sha256": hashlib.sha256((DOC/"comparison-scenarios.json").read_bytes()).hexdigest(),
        "date": datetime.datetime.now(datetime.timezone.utc).date().isoformat(),
        "command": "GOMAXPROCS=1 GOTOOLCHAIN=go1.26.11 " + shlex.join(COMMAND),
        "go": subprocess.check_output(["go", "version"], env=env, text=True).strip(),
        "source_sha256": source_hash(),
        "full_source_sha256": full_source_hash(),
        "measured_modules": list(MEASURED_MODULES),
        "raw_sha256": hashlib.sha256(raw.encode()).hexdigest(),
        "benchstat_sha256": hashlib.sha256(stats.encode()).hexdigest(),
        "cpu": re.search(r"^cpu: (.+)$", raw, re.M)[1].strip(),
        "affinity": sorted(os.sched_getaffinity(0)) if hasattr(os, "sched_getaffinity") else None,
        "background_load": "no intentional concurrent workload",
        "versions": {"go-masker": "v0.6.1", "masq": "v0.2.3", "slog-formatter": "v1.3.0", "godlp": "v1.2.15", "go-mask": "v0.6.2", "pii-shield": "v3.0.0", "ferret-scan": "v2.4.3"},
    }
    (DOC / "comparison.json").write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")


def rendered(raw, meta):
    rows = parse(raw)
    text = "| Benchmark | ns/op | B/op | allocs/op |\n|---|---:|---:|---:|\n"
    for name, values in rows.items():
        text += f"| {name.removeprefix('Benchmark')} | {values['ns/op']:,.1f} | {values['B/op']:,.0f} | {values['allocs/op']:,.0f} |\n"
    text += f"\nMeasured {meta['date']} with {meta['go']}, Linux/amd64, {meta['cpu']}; GOMAXPROCS=1, ten 200 ms samples per case. Construction is outside the timed loop; JSON encoding and masking are included. Source and dependency fingerprints, CPU affinity and command are in [comparison.json](comparison.json).\n"
    def ratio_range(other, mine="embargo"):
        ratios = [rows[f"BenchmarkComparison/{event}/{mine}"]["ns/op"] / rows[f"BenchmarkComparison/{event}/{other}"]["ns/op"] for event in ("flat", "nested", "map", "clean", "large50")]
        return f"{min(ratios):.2f} to {max(ratios):.2f}"
    shape_ratio = rows["BenchmarkStructuredPath/json_shape"]["ns/op"] / rows["BenchmarkStructuredPath/old_string"]["ns/op"]
    text += ("\nEach library is timed against an embargo configuration of similar detection breadth. masq and go-masker are given email and card rules and ferret-scan is narrowed to its EMAIL and CREDIT_CARD checks, so `embargo` selects KindEmail and KindPAN. pii-shield cannot turn its built-in detectors off, so `embargo-default` runs the default scanner against it. The scenario and leak tables use ferret-scan with every check. "
             f"For these five configured events the median time ratio embargo/go-masker ranges from {ratio_range('go-masker')}, embargo/masq from {ratio_range('masq')} and embargo/ferret-scan from {ratio_range('ferret-scan')}; embargo-default/pii-shield ranges from {ratio_range('pii-shield', 'embargo-default')}. Below 1 means less time for embargo. "
             f"The default scanner takes {ratio_range('embargo', 'embargo-default')} times the email-and-card configuration. The structured JSON path uses {shape_ratio:.2f} times the old string-only time. These ratios are regenerated from the same samples as the table.\n")
    modes = ('plain', 'embargo', 'embargo-default', 'pii-shield', 'masq', 'go-masker')
    events = ('flat', 'nested', 'map', 'clean', 'large50')
    maximum = max(rows[f"BenchmarkComparison/{event}/{mode}"]["ns/op"]/1000 for event in events for mode in modes)
    chart = SVG(1100, 1065, 'JSON slog time by event', 'Identical events through plain slog, embargo with email and card, embargo with its default scanner, pii-shield, masq and go-masker; median microseconds per event on one linear axis. Lower is faster.')
    chart.text(24, 34, 'JSON slog time by event', 25)
    chart.text(24, 61, 'Median microseconds per event; same linear axis. Lower is faster.', 16)
    chart.text(24, 84, 'pii-shield v3.0.0, masq v0.2.3 and go-masker v0.6.1; identical events, sink and ten-sample method. ferret-scan is in the table.', 14)
    labels = ('slog alone', 'embargo email, card', 'embargo default', 'slog + pii-shield', 'slog + masq', 'slog + go-masker')
    for index, event in enumerate(events):
        y = 112 + index * 175
        chart.text(24, y+17, {'flat':'Email + card', 'nested':'Nested struct', 'map':'Map', 'clean':'Clean event', 'large50':'50 attributes'}[event], 16)
        for offset, (mode, label, color) in enumerate(zip(modes, labels, ('#617281', '#087f75', '#0b5f58', '#8a6d00', '#4169b1', '#9a4814'))):
            value = rows[f"BenchmarkComparison/{event}/{mode}"]["ns/op"]/1000
            width = value/maximum*590
            row = y+offset*28
            chart.text(190, row+17, label, 14)
            chart.bar(350, row, width, 22, color)
            chart.text(round(360+width, 2), row+17, f'{value:.2f} µs', 14)
    chart.line(350, 978, 940, 978)
    for step in range(5):
        chart.text(350+590*step/4, 1002, f'{maximum*step/4:.1f}', 12, anchor='middle')
    chart.text(645, 1026, 'Time per event (microseconds; linear scale)', 15, anchor='middle')
    chart.text(24, 1052, 'Encoding and masking included; construction excluded. The scenario matrix shows differing protection and partial masking.', 13)
    return text, chart.render()



def speed_summary(rows):
    """One README sentence with the measured time ratios, so it cannot go stale."""
    events = ("flat", "nested", "map", "clean", "large50")
    def ratios(other):
        values = [rows[f"BenchmarkComparison/{event}/{other}"]["ns/op"] / rows[f"BenchmarkComparison/{event}/embargo"]["ns/op"] for event in events]
        return min(values), max(values)
    def default_ratios(other):
        values = [rows[f"BenchmarkComparison/{event}/embargo-default"]["ns/op"] / rows[f"BenchmarkComparison/{event}/{other}"]["ns/op"] for event in events]
        return min(values), max(values)
    masker, shield = ratios("go-masker"), default_ratios("pii-shield")
    return (f"On the same five JSON slog events, go-masker takes {masker[0]:.2f} to {masker[1]:.2f} times the time of embargo given the same email and card rules. "
            f"With its default scanner, embargo takes {shield[0]:.2f} to {shield[1]:.2f} times the time of pii-shield's default policy. [Time per event](doc/comparison.md#time-and-allocations)\n")


def replace_block(text, name, content):
    start, end = f"<!-- {name}:start -->", f"<!-- {name}:end -->"
    if text.count(start) != 1 or text.count(end) != 1 or text.index(start) >= text.index(end):
        raise ValueError(f"{name}: require exactly one ordered start/end marker")
    updated, count = re.subn(r"(?s)(" + re.escape(start) + r"\n).*?(" + re.escape(end) + r")", lambda m: m[1] + content + m[2], text)
    if count != 1:
        raise ValueError(f"{name}: expected one replacement, got {count}")
    return updated


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
    if meta["benchmarks"] != parse(raw) or meta["scenarios_sha256"] != hashlib.sha256((DOC/"comparison-scenarios.json").read_bytes()).hexdigest():
        raise ValueError("comparison JSON does not match measured evidence")
    table, svg = rendered(raw, meta)
    page = DOC / "comparison.md"
    original = page.read_text(encoding="utf-8")
    updated = replace_block(original, "comparison", table)
    correctness = (DOC / "comparison-correctness.md").read_text(encoding="utf-8")
    updated = replace_block(updated, "correctness", correctness)
    readme_path = ROOT / "README.md"
    readme = replace_block(readme_path.read_text(encoding="utf-8"), "speed-summary", speed_summary(parse(raw)))
    for path, content in ((page, updated), (DOC / "images/comparison.svg", svg), (readme_path, readme)):
        if args.check:
            if path.read_text(encoding="utf-8") != content:
                raise SystemExit("stale generated comparison: " + str(path))
        else:
            path.write_text(content, encoding="utf-8")

    import readme_charts
    readme_charts.generate(check=args.check)


if __name__ == "__main__":
    main()
