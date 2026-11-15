"""Verify bounded lifecycle models and replay reproducible simulator traces."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
MODELS = ROOT / 'tests/models'


def plain(value):
    if isinstance(value, dict):
        if '#bigint' in value:
            return int(value['#bigint'])
        if '#set' in value:
            return sorted(plain(x) for x in value['#set'])
        return {k: plain(v) for k, v in value.items() if k != '#meta'}
    if isinstance(value, list):
        return [plain(x) for x in value]
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--skip-verify', action='store_true')
    args = parser.parse_args()
    quint = os.environ.get('QUINT', str(MODELS / 'node_modules/.bin/quint'))
    for name in ('input', 'recorder', 'guard'):
        source = MODELS / (name + '.qnt')
        started = time.monotonic()
        if not args.skip_verify:
            subprocess.run([quint, 'verify', str(source), '--invariant=invariant', '--max-steps=8'], check=True)
        with tempfile.TemporaryDirectory() as directory:
            subprocess.run([quint, 'run', str(source), '--n-threads=1', '--invariant=invariant', '--max-steps=12', '--max-samples=64', '--n-traces=64', '--seed=14', '--out-itf=' + directory + '/trace{seq}.itf.json'], check=True)
            traces = []
            for path in sorted(Path(directory).glob('*.itf.json')):
                states = json.loads(path.read_text())['states']
                traces.append([plain(next(v for k, v in state.items() if k == 's' or k.endswith('::s'))) for state in states])
            if len(traces) != 64:
                raise RuntimeError('expected 64 traces, got ' + str(len(traces)))
            if name == 'guard':
                for failure in ['overflow', 'timeout', 'scannerFailed', 'exitFailed']:
                    if not any(state[failure] for trace in traces for state in trace):
                        raise RuntimeError('Guard replay misses '+failure)
                if not any(state['replay'] for trace in traces for state in trace):
                    raise RuntimeError('Guard replay misses safe output')
        result = {'toolchain': 'quint 0.33.1 / Apalache 0.62.4', 'source_sha256': hashlib.sha256(source.read_bytes()).hexdigest(), 'traces': traces}
        rendered = json.dumps(result, sort_keys=True, separators=(',', ':')) + '\n'
        target = MODELS / (name + '.json')
        if args.check:
            if target.read_text() != rendered:
                raise RuntimeError(str(target) + ' is stale')
        else:
            target.write_text(rendered)
        print(name, '64 traces, depth 12;', 'model checker skipped;' if args.skip_verify else 'model checker depth 8;', round(time.monotonic()-started, 2), 'seconds', flush=True)


if __name__ == '__main__':
    main()
