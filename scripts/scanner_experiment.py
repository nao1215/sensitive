#!/usr/bin/env python3
"""Retain the rejected lexer experiment and regenerate narrowing evidence."""
import argparse
import datetime
import hashlib
import json
import os
import pathlib
import re
import shutil
import statistics
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
OUT = ROOT / 'doc/performance'
NAMES = ('base', 'head', 'candidate', 'narrowing')


def measure(base, cpu):
    env = dict(os.environ, GOMAXPROCS='1', GOTOOLCHAIN='go1.26.11')
    commands = []
    def run(argv, cwd=ROOT):
        commands.append({'cwd':str(cwd), 'argv':argv})
        return subprocess.check_output(argv, cwd=cwd, env=env, text=True)
    with tempfile.TemporaryDirectory(prefix='embargo-experiment-') as tmp:
        tmp = pathlib.Path(tmp)
        baseline = tmp/'base'
        run(['git', 'clone', '--quiet', '--shared', str(base.resolve()), str(baseline)])
        for name in ('scanner_candidate_experiment_test.go', 'narrowing_benchmark_test.go'):
            shutil.copy2(ROOT/name, baseline/name)
        for name, where in (('base',baseline), ('head',ROOT)):
            run(['go', 'test', '-c', '-o', str(tmp/(name+'.test')), '.'], where)
        outputs = {name:[] for name in NAMES}
        for pair in range(10):
            order = ['base','head','candidate'] if pair%2 == 0 else ['candidate','head','base']
            for mode in order:
                binary = 'base' if mode == 'base' else 'head'
                variant = 'candidate' if mode == 'candidate' else 'production'
                raw = run(['taskset','-c',str(cpu),str(tmp/(binary+'.test')), '-test.run=^$', '-test.bench=^BenchmarkCandidateExperiment/(clean|dirty)/'+variant+'$', '-test.benchtime=200ms','-test.count=1','-test.benchmem'], baseline if mode == 'base' else ROOT)
                outputs[mode].append(re.sub(r'(BenchmarkCandidateExperiment/(?:clean|dirty))/(?:production|candidate)', r'\1', raw))
            order = ['all','kinds1','kinds3','kinds8']
            for kind in order if pair%2 == 0 else reversed(order):
                outputs['narrowing'].append(run(['taskset','-c',str(cpu),str(tmp/'head.test'),'-test.run=^$', '-test.bench=^BenchmarkNarrowing/'+kind+'/(clean|dirty)$', '-test.benchtime=200ms','-test.count=1','-test.benchmem']))
        for name,chunks in outputs.items():
            (OUT/('round13-'+name+'-bench.txt')).write_text(''.join(chunks),encoding='utf-8')
        metadata = {'date':datetime.datetime.now(datetime.timezone.utc).isoformat(), 'go':run(['go','version']).strip(), 'baseline':run(['git','rev-parse','HEAD'],baseline).strip(), 'head_base':run(['git','rev-parse','HEAD']).strip(), 'affinity':[cpu], 'samples':10, 'pair_order':'base/head/candidate then candidate/head/base; narrowing kind order reversed each pair', 'background_load':'operator must record concurrent workload', 'commands':commands, 'binary_sha256':{name:hashlib.sha256((tmp/(name+'.test')).read_bytes()).hexdigest() for name in ('base','head')}}
    (OUT/'round13-bench-metadata.json').write_text(json.dumps(metadata,indent=2)+'\n',encoding='utf-8')
    benchstats()


def benchstats():
    with tempfile.TemporaryDirectory(prefix='embargo-stats-') as tmp:
        tmp = pathlib.Path(tmp)
        for name in ('base','head','candidate'):
            shutil.copy2(OUT/('round13-'+name+'-bench.txt'),tmp/(name+'.txt'))
        raw = (OUT/'round13-narrowing-bench.txt').read_text(encoding="utf-8")
        for kind in ('all','kinds1','kinds3','kinds8'):
            lines = [line.replace('BenchmarkNarrowing/'+kind,'BenchmarkNarrowing') for line in raw.splitlines() if not line.startswith('Benchmark') or line.startswith('BenchmarkNarrowing/'+kind+'/')]
            (tmp/(kind+'.txt')).write_text('\n'.join(lines)+'\n',encoding='utf-8')
        pairs = [('before-after','base','head'),('candidate','head','candidate')]+[('narrow-'+kind,'all',kind) for kind in ('kinds1','kinds3','kinds8')]
        for name,left,right in pairs:
            stats = subprocess.check_output(['benchstat',left+'.txt',right+'.txt'],cwd=tmp,text=True)
            (OUT/('round13-'+name+'-benchstat.txt')).write_text(stats,encoding="utf-8")


def medians(raw):
    rows = {}
    for kind,state,value in re.findall(r'BenchmarkNarrowing/(\w+)/(\w+)\s+\d+\s+([\d.]+) ns/op', raw):
        rows.setdefault((kind,state),[]).append(float(value))
    expected = {(kind,state) for kind in ('all','kinds1','kinds3','kinds8') for state in ('clean','dirty')}
    if set(rows) != expected or any(len(values)!=10 for values in rows.values()):
        raise ValueError('narrowing requires ten samples for every kind set and input')
    return {key:statistics.median(values) for key,values in rows.items()}


def render(check):
    raw = (OUT/'round13-narrowing-bench.txt').read_text(encoding="utf-8")
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
    synopsis = 'Round 13 scanner medians (ten interleaved samples):\n\n'+table+'\n[kinds1/3/8 definitions, input sizes and uncertainty](doc/benchmarks.md#choose-the-kinds-the-application-needs). Narrower selection avoids irrelevant detections and gives up their recall.\n'
    readme_pattern = r'(?s)(<!-- narrowing-summary:start -->\n).*?(<!-- narrowing-summary:end -->)'
    if len(re.findall(readme_pattern,existing)) != 1:
        raise ValueError('expected one README narrowing block')
    changed = re.sub(readme_pattern,lambda m:m[1]+synopsis+m[2],existing)
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
    parser.add_argument('--base')
    parser.add_argument('--cpu',type=int,default=0)
    parser.add_argument('--check',action='store_true')
    args = parser.parse_args()
    if args.measure:
        if not args.base or not args.base.strip():
            parser.error('--measure needs --base pointing at a baseline clone')
        measure(pathlib.Path(args.base),args.cpu)
    render(args.check)


if __name__ == '__main__':
    main()
