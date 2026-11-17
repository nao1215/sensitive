"""Measure default-scanner coverage against generated gitleaks rule examples.

The gitleaks rule generator validates every rule against true-positive lines
before writing its configuration. This script downloads a pinned gitleaks
module, records those lines and the secret each rule extracts in a cache
outside the repository, and prints the coverage that tests/cmd/gitleaksoracle
measures. Generated examples look like real credentials, so they are never
committed.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]
MODULE = 'github.com/zricethezav/gitleaks/v8'
VERSION = 'v8.30.0'
VALIDATE = 'cmd/generate/config/utils/validate.go'
HOOK_CALL = '\tr := &rule\n\td := createSingleRuleDetector(r)\n\tfor _, tp := range truePositives {'
HOOK = '''
func recordTruePositives(r *config.Rule, tps []string, d *detect.Detector) {
\tf, err := os.OpenFile(os.Getenv("EMBARGO_ORACLE_SAMPLES"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
\tif err != nil {
\t\treturn
\t}
\tdefer f.Close()
\tfor _, tp := range tps {
\t\tfor _, finding := range d.DetectString(tp) {
\t\t\tline, _ := json.Marshal(map[string]string{"rule": r.RuleID, "line": tp, "secret": finding.Secret})
\t\t\t_, _ = f.Write(append(line, '\\n'))
\t\t}
\t}
}
'''


def patch_validate(source):
    """Insert the recording hook into Validate; fail when upstream moved it."""
    if HOOK_CALL not in source or 'import (' not in source:
        raise ValueError('unexpected gitleaks validate.go layout')
    source = source.replace(HOOK_CALL, HOOK_CALL.replace('\tfor _, tp', '\trecordTruePositives(r, truePositives, d)\n\tfor _, tp'), 1)
    source = source.replace('import (', 'import (\n\t"encoding/json"\n\t"os"', 1)
    return source + HOOK


def module_dir():
    raw = subprocess.check_output(['go', 'mod', 'download', '-json', MODULE+'@'+VERSION], cwd=ROOT, text=True)
    return Path(json.loads(raw)['Dir'])


def generate(cache):
    """Write generated true positives to cache/samples.jsonl and return its path."""
    source = cache/'gitleaks'
    if source.exists():
        shutil.rmtree(source)
    shutil.copytree(module_dir(), source)
    # Module cache files are read-only; the copy must be writable and removable.
    for path in [source, *source.rglob('*')]:
        path.chmod(0o700 if path.is_dir() else 0o600)
    validate = source/VALIDATE
    validate.write_text(patch_validate(validate.read_text()))
    samples = cache/'samples.jsonl'
    samples.unlink(missing_ok=True)
    env = dict(os.environ, EMBARGO_ORACLE_SAMPLES=str(samples.resolve()))
    subprocess.run(['go', 'run', '.', str((cache/'gitleaks.toml').resolve())], cwd=source/'cmd/generate/config', env=env, check=True, stdout=subprocess.DEVNULL)
    return samples


def table(summary):
    """Render the coverage summary as the Markdown table used in doc/credentials.md."""
    def percent(part, whole):
        return f'{100*part/whole:.1f}%'
    return '\n'.join([
        '| Input | Examples masked | Rules fully masked |',
        '|---|---|---|',
        f"| Generated lines with keys and syntax | {summary['masked_lines']}/{summary['lines']} ({percent(summary['masked_lines'], summary['lines'])}) | {summary['rules_all_lines']}/{summary['rules']} |",
        f"| Bare secrets without a key | {summary['masked_bare']}/{summary['secrets']} ({percent(summary['masked_bare'], summary['secrets'])}) | {summary['rules_all_bare']}/{summary['rules']} |",
    ])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cache', type=Path, required=True, help='directory outside the repository for generated examples')
    parser.add_argument('--json', action='store_true', help='print per-rule results instead of the summary table')
    args = parser.parse_args()
    cache = args.cache.resolve()
    if cache.is_relative_to(ROOT):
        raise ValueError('the cache must be outside the repository')
    cache.mkdir(parents=True, exist_ok=True)
    samples = generate(cache)
    raw = subprocess.check_output(['go', '-C', 'tests', 'run', './cmd/gitleaksoracle', '--samples', str(samples)], cwd=ROOT, text=True)
    summary = json.loads(raw)
    print(raw if args.json else table(summary))


if __name__ == '__main__':
    main()
