"""Compile checked reference models and reject stale differential vectors."""
import argparse
import os
from pathlib import Path
import subprocess

ROOT=Path(__file__).resolve().parents[1]


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--write',action='store_true');args=parser.parse_args()
    project=ROOT/'tests/lean'
    for path in project.glob('*.lean'):
        import re
        if re.search(r'\b(sorry|axiom|unsafe|native_decide)\b',path.read_text()):raise ValueError('unchecked proof escape: '+str(path))
    subprocess.run(['lake','build'],cwd=project,env=dict(os.environ, LEAN_NUM_THREADS='4'),check=True)
    output=subprocess.check_output([str(project/'.lake/build/bin/vectors')])
    path=project/'vectors.tsv'
    if args.write:path.write_bytes(output)
    elif path.read_bytes()!=output:raise ValueError('Lean vectors are stale')
    subprocess.run(['go','-C',str(ROOT/'tests'),'test','.', '-run','^TestLeanReferenceVectors$','-count=1'],check=True)


if __name__=='__main__':main()
