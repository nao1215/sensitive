"""Discover every root-module fuzz target for Make and scheduled CI."""
import argparse
import json
import os
from pathlib import Path
import re
import shlex
import subprocess

ROOT=Path(__file__).resolve().parents[1]


def targets(root=ROOT):
    found=[]
    for path in sorted(root.rglob('*_test.go')):
        relative=path.relative_to(root)
        if any(p in relative.parts for p in ['.git','testdata','node_modules','.lake']):continue
        if any((parent/'go.mod').exists() for parent in path.parents if parent!=root and root in parent.parents):continue
        for name in re.findall(r'^func (Fuzz\w+)\(',path.read_text(),re.M):
            found.append({'pkg':'./'+str(relative.parent) if relative.parent!=Path('.') else '.', 'name':name})
    if not found:raise ValueError('no fuzz targets discovered')
    return found


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--run');args=parser.parse_args()
    found=targets()
    if args.run:
        for target in found:
            command = ['go','test','-run','^$','-fuzz','^'+target['name']+'$','-fuzztime='+args.run,target['pkg']]
            print(shlex.join(command), flush=True)
            subprocess.run(command,cwd=ROOT,env=dict(os.environ,GOMAXPROCS='4'),check=True)
    else:print(json.dumps({'target':found},separators=(',',':')))


if __name__=='__main__':main()
