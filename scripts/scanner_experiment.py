#!/usr/bin/env python3
"""Measure explicit kind selections and regenerate narrowing evidence."""
import argparse
import os
import pathlib
import re
import statistics
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
OUT = ROOT / 'doc/performance'


def measure(cpu):
    env = dict(os.environ, GOMAXPROCS='1', GOTOOLCHAIN='go1.26.11')
    with tempfile.TemporaryDirectory(prefix='embargo-narrowing-') as tmp:
        binary = pathlib.Path(tmp)/'scanner.test'
        subprocess.run(['go', 'test', '-c', '-o', str(binary), '.'], cwd=ROOT, env=env, check=True)
        chunks = []
        for sample in range(10):
            kinds = ['all', 'kinds1', 'kinds3', 'kinds8']
            for kind in kinds if sample % 2 == 0 else reversed(kinds):
                command = ['taskset', '-c', str(cpu), str(binary), '-test.run=^$',
                           '-test.bench=^BenchmarkNarrowing/'+kind+'/(clean|dirty)$',
                           '-test.benchtime=200ms', '-test.count=1', '-test.benchmem']
                chunks.append(subprocess.check_output(command, cwd=ROOT, env=env, text=True))
        raw = ''.join(chunks)
        medians(raw)
        (OUT/'scanner-narrowing.raw.txt').write_text(raw, encoding='utf-8')


def medians(raw):
    rows = {}
    for kind,state,value in re.findall(r'BenchmarkNarrowing/(\w+)/(\w+)\s+\d+\s+([\d.]+) ns/op', raw):
        rows.setdefault((kind,state),[]).append(float(value))
    expected = {(kind,state) for kind in ('all','kinds1','kinds3','kinds8') for state in ('clean','dirty')}
    if set(rows) != expected or any(len(values)!=10 for values in rows.values()):
        raise ValueError('narrowing requires ten samples for every kind set and input')
    return {key:statistics.median(values) for key,values in rows.items()}


def render(check):
    raw = (OUT/'scanner-narrowing.raw.txt').read_text(encoding="utf-8")
    values = medians(raw)
    table = '| Selection | Clean ns/op | Dirty ns/op | Clean / dirty speedup over WithAll |\n|---|---:|---:|---|\n'
    for kind in ('all','kinds1','kinds3','kinds8'):
        clean,dirty = values[kind,'clean'],values[kind,'dirty']
        table += f"| {kind} | {clean:,.3f} | {dirty:,.1f} | {values['all','clean']/clean:.2f}× / {values['all','dirty']/dirty:.2f}× |\n"
    page = ROOT/'doc/benchmarks.md'
    original = page.read_text(encoding="utf-8")
    pattern = r'(?s)(<!-- narrowing:start -->\n).*?(<!-- narrowing:end -->)'
    if len(re.findall(pattern,original)) != 1:
        raise ValueError('expected one narrowing block')
    updated = re.sub(pattern,lambda m:m[1]+table+m[2],original)
    readme = ROOT/'README.md'
    existing = readme.read_text(encoding="utf-8")
    synopsis = 'Recorded scanner medians (ten interleaved samples):\n\n'+table+'\n[kinds1/3/8 definitions, input sizes and uncertainty](doc/benchmarks.md#choose-the-kinds-the-application-needs). Narrower selection avoids irrelevant detections and gives up their recall.\n'
    readme_pattern = r'(?s)(<!-- narrowing-summary:start -->\n).*?(<!-- narrowing-summary:end -->)'
    if len(re.findall(readme_pattern,existing)) != 1:
        raise ValueError('expected one README narrowing block')
    changed = re.sub(readme_pattern,lambda m:m[1]+synopsis+m[2],existing)
    # The README prose quotes the same medians, so it is generated with the table.
    line = f"Pick the kinds you need: on 2.7 KB of log lines with no secret, `WithKinds(KindEmail)` returns in {values['kinds1','clean']/1000:.2f} µs because there is no `@` to inspect, while `WithAll()` takes {values['all','clean']/1000:.0f} µs. [Per-detector benchmarks](doc/benchmarks.md)\n"
    line_pattern = r'(?s)(<!-- narrowing-line:start -->\n).*?(<!-- narrowing-line:end -->)'
    if len(re.findall(line_pattern,changed)) != 1:
        raise ValueError('expected one README narrowing sentence')
    changed = re.sub(line_pattern,lambda m:m[1]+line+m[2],changed)
    if check:
        if existing != changed:
            raise SystemExit('stale README narrowing table')
        if original != updated:
            raise SystemExit('stale narrowing table: run python3 scripts/scanner_experiment.py')
    else:
        page.write_text(updated,encoding="utf-8")
        readme.write_text(changed,encoding="utf-8")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--measure',action='store_true')
    parser.add_argument('--cpu',type=int,default=0)
    parser.add_argument('--check',action='store_true')
    args = parser.parse_args()
    if args.measure:
        if args.cpu < 0:
            parser.error('--cpu must be nonnegative')
        measure(args.cpu)
    render(args.check)


if __name__ == '__main__':
    main()
