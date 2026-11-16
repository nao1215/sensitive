"""Check a measured detection snapshot and require release notes for drift from the PR base."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess

import real_logs

ROOT = Path(__file__).resolve().parents[1]
SNAPSHOT = 'doc/detection-findings.json'


def has_detection_entry(changelog):
    section = re.search(r'^## \[Unreleased\]\s*\n(.*?)(?=^## |\Z)', changelog, re.M | re.S)
    if not section:
        return False
    heading = re.search(r'^### Detection changes\s*\n(.*?)(?=^### |\Z)', section[1], re.M | re.S)
    return bool(heading and re.search(r'^- \S.+', heading[1], re.M))


def check_change(before, after, changelog):
    if before != after and not has_detection_entry(changelog):
        raise ValueError('detection findings changed: add an Unreleased Detection changes entry')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cache', type=Path, required=True)
    parser.add_argument('--update', action='store_true')
    parser.add_argument('--base')
    args = parser.parse_args()
    manifest = real_logs.load('real-logs-manifest.json')
    real_logs.cache_datasets(args.cache, manifest)
    raw = subprocess.check_output(['go', '-C', 'tests', 'run', './cmd/detectionbaseline', '--cache', str(args.cache.resolve())], cwd=ROOT, text=True)
    measured = json.loads(raw)
    path = ROOT/SNAPSHOT
    if args.update:
        path.write_text(raw)
    elif not path.exists() or json.loads(path.read_text()) != measured:
        raise ValueError('stale detection findings: run scripts/detection_changes.py --update --cache CACHE')
    base = args.base
    if not base and os.environ.get('GITHUB_EVENT_NAME') == 'pull_request':
        base = json.loads(Path(os.environ['GITHUB_EVENT_PATH']).read_text())['pull_request']['base']['sha']
    if base:
        exists = subprocess.run(['git', 'cat-file', '-e', base+':'+SNAPSHOT], cwd=ROOT, capture_output=True)
        before = json.loads(subprocess.check_output(['git', 'show', base+':'+SNAPSHOT], cwd=ROOT, text=True)) if exists.returncode == 0 else None
        check_change(before, measured, (ROOT/'CHANGELOG.md').read_text())
    print('Detection compatibility snapshot and release note gate passed.')


if __name__ == '__main__':
    main()
