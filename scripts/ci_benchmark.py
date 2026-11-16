"""Build base and head once, alternate their samples, and publish benchstat."""
import argparse
import json
import os
import math
import re
import statistics
from pathlib import Path
import subprocess
import tempfile

ROOT=Path(__file__).resolve().parents[1]


def run(command, **kwargs):
    return subprocess.check_output(command,text=True,**kwargs)


def default_gate(base, head):
    """Require ten paired samples for both default workloads; compare medians."""
    measured = {}
    for label, text in [('base', base), ('head', head)]:
        workloads = {'clean': [], 'dirty': []}
        for line in text.splitlines():
            match = re.match(r'^BenchmarkCIDefault/(clean|dirty)(?:-\d+)?\s+\d+\s+(\S+)\s+ns/op\b', line)
            if match:
                value = float(match[2])
                if not math.isfinite(value) or value <= 0:
                    raise ValueError('nonpositive or nonfinite default-scanner measurement')
                workloads[match[1]].append(value)
        if any(len(values) != 10 for values in workloads.values()):
            raise ValueError('each default workload requires exactly ten samples per revision')
        measured[label] = {name: statistics.median(values) for name, values in workloads.items()}
    rows = [{'workload': name, 'base_ns': measured['base'][name], 'head_ns': measured['head'][name],
             'ratio': measured['head'][name]/measured['base'][name]} for name in ('clean', 'dirty')]
    return {'maximum_ratio': 1.2, 'samples': 10, 'passed': all(row['ratio'] <= 1.2 for row in rows), 'workloads': rows}


def root_harness(source):
    """Keep the fixture unchanged while adapting its package to the root archive."""
    converted, count = re.subn(rb"^package benchmarks\n", b"package embargo_test\n", source, count=1)
    if count != 1:
        raise ValueError("unexpected benchmark harness package")
    return converted


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--base',required=True);parser.add_argument('--head',required=True);args=parser.parse_args()
    results=ROOT/'benchmark-results';results.mkdir(exist_ok=True)
    env=dict(os.environ,GOMAXPROCS='1')
    revisions={label:run(['git','rev-parse','--verify',revision+'^{commit}'],cwd=ROOT).strip() for label,revision in [('base',args.base),('head',args.head)]}
    harness=root_harness(subprocess.check_output(['git','show',revisions['head']+':tests/benchmarks/benchmark_test.go'],cwd=ROOT))
    with tempfile.TemporaryDirectory(prefix='embargo-benchmark-') as tmp:
        binaries={}
        for label,sha in revisions.items():
            checkout=Path(tmp)/label;checkout.mkdir()
            # An archive avoids changing the active checkout or Git worktree state.
            archive=subprocess.check_output(['git','archive',sha],cwd=ROOT)
            subprocess.run(['tar','-x','-C',str(checkout)],input=archive,check=True)
            # Copy the head-owned harness to both revisions, including older bases.
            (checkout/'ci_default_benchmark_test.go').write_bytes(harness)
            binary=Path(tmp)/(label+'.test');binaries[label]=binary
            subprocess.run(['go','test','-c','-o',str(binary),'.'],cwd=checkout,env=env,check=True)
        samples={'base':[],'head':[]}
        orders=[]
        for i in range(10):
            order=['base','head'] if i%2==0 else ['head','base'];orders.append(order)
            for label in order:
                samples[label].append(run([str(binaries[label]),'-test.run=^$','-test.bench=^(BenchmarkNarrowing|BenchmarkCIDefault)$','-test.benchtime=100ms','-test.benchmem','-test.count=1'],env=env))
        for label,text in samples.items():(results/(label+'.txt')).write_text(''.join(text))
    summary=run(['go','-C','tests/tools','run','golang.org/x/perf/cmd/benchstat',str(results/'base.txt'),str(results/'head.txt')],cwd=ROOT)
    (results/'benchstat.txt').write_text(summary)
    (results/'conditions.json').write_text(json.dumps({'base':revisions['base'],'head':revisions['head'],'order':orders,'go':run(['go','version']).strip(),'gomaxprocs':1,'benchtime':'100ms'},indent=2)+'\n')
    gate=default_gate((results/'base.txt').read_text(),(results/'head.txt').read_text())
    (results/'gate.json').write_text(json.dumps(gate,indent=2)+'\n')
    print(summary)
    print(json.dumps(gate,indent=2))
    if os.environ.get('GITHUB_STEP_SUMMARY'):
        with open(os.environ['GITHUB_STEP_SUMMARY'],'a') as output:output.write('Base and head ran on this runner in alternating order. Each default-scanner median must stay within +20%; allocation contracts remain hard test gates.\n\n```text\n'+summary+'\n```\n\n```json\n'+json.dumps(gate,indent=2)+'\n```\n')

    if not gate['passed']:
        raise SystemExit('default scanner median exceeded the 20% regression budget')


if __name__=='__main__':main()
