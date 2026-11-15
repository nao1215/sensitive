"""Build base and head once, alternate their samples, and publish benchstat."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile

ROOT=Path(__file__).resolve().parents[1]


def run(command, **kwargs):
    return subprocess.check_output(command,text=True,**kwargs)


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--base',required=True);parser.add_argument('--head',required=True);args=parser.parse_args()
    results=ROOT/'benchmark-results';results.mkdir(exist_ok=True)
    env=dict(os.environ,GOMAXPROCS='1')
    with tempfile.TemporaryDirectory(prefix='embargo-benchmark-') as tmp:
        binaries={}
        for label,revision in [('base',args.base),('head',args.head)]:
            sha=run(['git','rev-parse','--verify',revision+'^{commit}'],cwd=ROOT).strip()
            checkout=Path(tmp)/label;checkout.mkdir()
            # An archive avoids changing the active checkout or Git worktree state.
            archive=subprocess.check_output(['git','archive',sha],cwd=ROOT)
            subprocess.run(['tar','-x','-C',str(checkout)],input=archive,check=True)
            binary=Path(tmp)/(label+'.test');binaries[label]=binary
            subprocess.run(['go','test','-c','-o',str(binary),'.'],cwd=checkout,env=env,check=True)
        samples={'base':[],'head':[]}
        orders=[]
        for i in range(10):
            order=['base','head'] if i%2==0 else ['head','base'];orders.append(order)
            for label in order:
                samples[label].append(run([str(binaries[label]),'-test.run=^$','-test.bench=^BenchmarkNarrowing$','-test.benchtime=100ms','-test.benchmem','-test.count=1'],env=env))
        for label,text in samples.items():(results/(label+'.txt')).write_text(''.join(text))
    summary=run(['go','-C','tests/tools','run','golang.org/x/perf/cmd/benchstat',str(results/'base.txt'),str(results/'head.txt')],cwd=ROOT)
    (results/'benchstat.txt').write_text(summary)
    (results/'conditions.json').write_text(json.dumps({'base':args.base,'head':args.head,'order':orders,'go':run(['go','version']).strip(),'gomaxprocs':1,'benchtime':'100ms'},indent=2)+'\n')
    print(summary)
    if os.environ.get('GITHUB_STEP_SUMMARY'):
        with open(os.environ['GITHUB_STEP_SUMMARY'],'a') as output:output.write('Base and head ran on this runner in alternating order. Time deltas are observations; allocation contracts remain hard test gates.\n\n```text\n'+summary+'\n```\n')


if __name__=='__main__':main()
