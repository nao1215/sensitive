"""Require covered Go blocks on changed root-module statements, plus explicit exceptions."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def changed_lines(diff):
    result = {}
    current = None
    line = 0
    for text in diff.splitlines():
        if text.startswith('+++ b/'):
            current = text[6:]
            result.setdefault(current, set())
        elif text.startswith('@@ '):
            match = re.match(r'@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@', text)
            if not match:
                raise ValueError('malformed diff hunk')
            line = int(match[1])
        elif current is not None and text.startswith('+') and not text.startswith('+++'):
            result[current].add(line)
            line += 1
        elif current is not None and text.startswith(' '):
            line += 1
    return result


def read_blocks(profile, module='github.com/nao1215/embargo/'):
    lines = profile.splitlines()
    if not lines or lines[0] not in ('mode: set', 'mode: count', 'mode: atomic'):
        raise ValueError('invalid coverage header')
    result = {}
    for line in lines[1:]:
        match = re.fullmatch(r'(.+):(\d+)\.(\d+),(\d+)\.(\d+) (\d+) (\d+)', line)
        if not match:
            raise ValueError('invalid coverage block')
        name, start, _, end, _, statements, count = match.groups()
        if name.startswith(module):
            result.setdefault(name[len(module):], []).append((int(start), int(end), int(statements), int(count)))
    return result


def exceptions(root, entries):
    result = {}
    for entry in entries:
        name, start, end = entry['file'], entry['start'], entry['end']
        if Path(name).is_absolute() or '..' in Path(name).parts or start < 1 or end < start or not entry['reason'].strip():
            raise ValueError('invalid coverage exception')
        source = (root/name).read_text(encoding="utf-8").splitlines(keepends=True)
        text = ''.join(source[start-1:end])
        if end > len(source) or hashlib.sha256(text.encode()).hexdigest() != entry['sha256']:
            raise ValueError('stale coverage exception: '+name)
        result.setdefault(name, set()).update(range(start, end+1))
    return result


def check(changes, blocks, sources, excluded):
    failures = []
    checked = 0
    for name, lines in changes.items():
        if name not in sources or not lines:
            continue
        # An added source must be instrumented even if it was never imported.
        if name not in blocks and any(re.search(r'\bfunc\b', line) for line in sources[name].splitlines()):
            failures.append(name+': no instrumented coverage')
            continue
        for start, end, statements, count in blocks.get(name, []):
            touched = lines.intersection(range(start, end+1))
            if statements and touched:
                checked += statements
                if not count and not touched <= excluded.get(name, set()):
                    failures.append(f'{name}:{start}-{end}: {statements} changed statements uncovered')
    if failures:
        raise ValueError('\n'.join(failures))
    return checked


def root_sources():
    output = subprocess.check_output(['go', 'list', '-json', './...'], cwd=ROOT, text=True)
    decoder = json.JSONDecoder()
    sources = {}
    while output.strip():
        package, end = decoder.raw_decode(output.lstrip())
        output = output.lstrip()[end:]
        for name in package.get('GoFiles', []) + package.get('CgoFiles', []):
            path = Path(package['Dir'])/name
            sources[path.relative_to(ROOT).as_posix()] = path.read_text(encoding="utf-8")
    return sources


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base')
    parser.add_argument('--profile', type=Path, default=ROOT/'coverage.out')
    args = parser.parse_args()
    base = args.base
    if not base and os.environ.get('GITHUB_EVENT_NAME') == 'pull_request':
        base = json.loads(Path(os.environ['GITHUB_EVENT_PATH']).read_text(encoding="utf-8"))['pull_request']['base']['sha']
    if not base:
        parser.error('--base or a pull_request event is required')
    diff = subprocess.check_output(['git', 'diff', '--no-ext-diff', '--no-renames', '--unified=0', base, '--', '*.go'], cwd=ROOT, text=True)
    excluded = exceptions(ROOT, json.loads((ROOT/'doc/coverage-exceptions.json').read_text(encoding="utf-8")))
    total = check(changed_lines(diff), read_blocks(args.profile.read_text(encoding="utf-8")), root_sources(), excluded)
    print(f'Changed statement coverage: 100% ({total} statements); total gate remains 97%.')


if __name__ == '__main__':
    main()
