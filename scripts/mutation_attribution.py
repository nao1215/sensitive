"""Replay selected round-13 survivors against each newly added technique."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]

# IDs refer to the retained round-13 log, before comment-only line shifts.
CASES = [
    ('mask-range', 'CONDITIONALS_BOUNDARY at mask.go:28:27', 'mask.go', 'f.End <= f.Start', 'f.End < f.Start'),
    ('json-depth', 'CONDITIONALS_BOUNDARY at json.go:79:11', 'json.go', 'depth > maxDepth', 'depth >= maxDepth'),
    ('json-space', 'CONDITIONALS_NEGATION at json.go:68:12', 'json.go', 'for w.pos < len(w.data) {', 'for w.pos >= len(w.data) {'),
    ('json-scalar', 'CONDITIONALS_NEGATION at json.go:121:12', 'json.go', "raw[0] == 't'", "raw[0] != 't'"),
    ('json-escaped', 'CONDITIONALS_NEGATION at json.go:198:32', 'json.go', "bytes.IndexByte(raw, '\\\\') >= 0", "bytes.IndexByte(raw, '\\\\') < 0"),
    ('json-unmarshal', 'CONDITIONALS_NEGATION at json.go:199:45', 'json.go', 'if err := json.Unmarshal(raw, &text); err != nil {', 'if err := json.Unmarshal(raw, &text); err == nil {'),
    ('recorder-empty', 'CONDITIONALS_BOUNDARY at embargotest/recorder.go:233:31', 'embargotest/recorder.go', 'len(r.sinks) > 0 && len(r.expectations) > 0', 'len(r.sinks) >= 0 && len(r.expectations) > 0'),
]
GROUPS = {
    'bitmap oracle': ['go', 'test', '.', '-run', '^TestMaskByteCoverageOracle$', '-count=1'],
    'adversarial': ['go', 'test', './...', '-run', '^TestAdversarial', '-count=1'],
    'logger snapshot': ['go', '-C', 'adapters/zap', 'test', '.', '-run', '^TestLoggerSnapshot$', '-count=1'],
    'snapshot': ['go', 'test', './...', '-run', 'Snapshot', '-count=1'],
    'structure fuzz seeds': ['go', 'test', './...', '-run', '^Fuzz(JSONPaths|CredentialGrammar|AdversarialBudgets|Guard)', '-count=1'],
    'Quint replay': ['go', 'test', './embargotest', '-run', '^TestQuint', '-count=1'],
    'metamorphic': ['go', '-C', 'tests', 'test', '.', '-run', '^TestMetamorphic(Independent|Kinds|JSON)', '-count=1'],
    'Lean vectors': ['go', '-C', 'tests', 'test', '.', '-run', '^TestLeanReferenceVectors$', '-count=1'],
    'external oracles': ['go', '-C', 'tests', 'test', '.', '-run', '^(TestExternal|TestStandardLibrary)', '-count=1'],
}


def execute(command, root):
    try:
        result = subprocess.run(command, cwd=root, env=dict(os.environ, GOMAXPROCS='4'), capture_output=True, text=True, timeout=90)
    except subprocess.TimeoutExpired:
        return 'timeout', ''
    if result.returncode == 0:
        return 'survived', result.stdout
    if '--- FAIL:' not in result.stdout or '[build failed]' in result.stdout:
        raise RuntimeError('test infrastructure failure: '+result.stdout+result.stderr)
    return 'killed', result.stdout


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--case', action='append', choices=[row[0] for row in CASES])
    args = parser.parse_args()
    baseline = (ROOT/'doc/performance/round13-mutation.txt').read_text()
    results = []
    with tempfile.TemporaryDirectory(prefix='embargo-attribution-') as temporary:
        copy = Path(temporary)/'repo'
        shutil.copytree(ROOT, copy, ignore=shutil.ignore_patterns('.git', 'node_modules', '.lake', '__pycache__', 'benchmark-results', '_apalache-out'))
        for name, command in GROUPS.items():
            status, _ = execute(command, copy)
            if status != 'survived':
                raise RuntimeError('unmutated technique failed: '+name)
        for name, identity, filename, original, changed in CASES:
            if args.case and name not in args.case:
                continue
            if 'LIVED '+identity not in baseline:
                raise ValueError('not a baseline survivor: '+identity)
            path = copy/filename
            source = path.read_text()
            if original not in source:
                raise ValueError('mutation site changed: '+name)
            path.write_text(source.replace(original, changed, 1))
            try:
                row = {'mutant': identity, 'results': {}}
                for technique, command in GROUPS.items():
                    status, output = execute(command, copy)
                    row['results'][technique] = status
                    print(name, technique, status, flush=True)
                results.append(row)
            finally:
                path.write_text(source)
    args.output.write_text(json.dumps(results, indent=2)+'\n')


if __name__ == '__main__':
    main()
