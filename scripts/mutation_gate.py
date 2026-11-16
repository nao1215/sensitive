"""Measure released gremlins in the tools module and enforce per-package score floors."""
import argparse
from collections import Counter
import hashlib
import json
import os
import re
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
TOOL = 'github.com/go-gremlins/gremlins/cmd/gremlins@v0.6.0'
BASELINE = ROOT/'doc/mutation-baseline.json'
EVIDENCE = ROOT/'doc/performance/mutation-baseline.json'
DOCUMENT = ROOT/'doc/testing.md'
STATUSES = {'KILLED', 'LIVED', 'NOT COVERED', 'NOT VIABLE', 'TIMED OUT'}


def project_measurement(packages):
    counts = Counter()
    for package in packages.values():
        counts.update(package['counts'])
    killed, lived, timed_out = (counts[name] for name in ('KILLED', 'LIVED', 'TIMED OUT'))
    executed = killed+lived+timed_out
    return {'mutation': {'killed': killed, 'lived': lived, 'uncovered': counts['NOT COVERED'], 'timed_out': timed_out, 'not_viable': counts['NOT VIABLE'], 'skipped': 0}, 'efficacy': round(100*killed/(killed+lived), 2), 'mutator_coverage': round(100*executed/(executed+counts['NOT COVERED']), 2)}


def measurement_from_log(log):
    if 'EMBARGO_MUTATION_START' in log:
        summaries = re.findall(r'^EMBARGO_MUTATION_SUMMARY (.+)$', log, re.M)
        if len(summaries) != 1:
            raise ValueError('project mutation run must be complete; calibration is not a baseline')
        return project_measurement(json.loads(summaries[0])['packages'])
    summary = re.search(r'Killed: (\d+), Lived: (\d+), Not covered: (\d+)\s+Timed out: (\d+), Not viable: (\d+), Skipped: (\d+)\s+Test efficacy: ([\d.]+)%\s+Mutator coverage: ([\d.]+)%', log)
    if not summary or 'Mutation testing completed' not in log:
        raise ValueError('mutation run must be complete')
    return {'mutation': dict(zip(['killed', 'lived', 'uncovered', 'timed_out', 'not_viable', 'skipped'], map(int, summary.groups()[:6]))), 'efficacy': float(summary[7]), 'mutator_coverage': float(summary[8])}


def package_scores(report, prefix=''):
    packages = {}
    for file in report['files']:
        path = Path(file['file_name'])
        if path.is_absolute() or '..' in path.parts:
            raise ValueError('invalid mutation source path')
        package = prefix or path.parent.as_posix()
        counts = packages.setdefault(package, Counter())
        for mutant in file['mutations']:
            status = mutant['status'].replace('_', ' ').upper()
            if status not in STATUSES:
                raise ValueError('unknown or incomplete mutation result: '+status)
            counts[status] += 1
    result = {}
    for name, counts in sorted(packages.items()):
        denominator = counts['KILLED']+counts['LIVED']+counts['TIMED OUT']
        total = denominator+counts['NOT COVERED']
        if not denominator or not total:
            raise ValueError('no executed mutants for package '+name)
        result[name] = {'score': round(100*counts['KILLED']/denominator, 2), 'coverage': round(100*denominator/total, 2), 'counts': dict(sorted(counts.items()))}
    if not result:
        raise ValueError('empty mutation report')
    return result


def mutation_inventory(report):
    result = {}
    for file in report['files']:
        name = file['file_name']
        if name in result:
            raise ValueError('duplicate mutation file: '+name)
        result[name] = Counter((m['type'], m['line'], m['column']) for m in file['mutations'])
    if not result:
        raise ValueError('empty mutation inventory')
    return result


def validate_inventory(report, inventory):
    if mutation_inventory(report) != mutation_inventory(inventory):
        raise ValueError('mutation results do not contain every generated expression')


def check(actual, baseline):
    if set(actual) != set(baseline):
        raise ValueError('mutation package scope changed; review and measure every package')
    for name, values in baseline.items():
        for metric in ('score', 'coverage'):
            if actual[name][metric] < values[metric]:
                raise ValueError(f'{name} mutation {metric} fell: {actual[name][metric]} < {values[metric]}')


def mutation_table(packages):
    rows = ['| Package | Score floor | Mutation coverage floor | Killed | Lived | Timed out | Uncovered |', '|---|---:|---:|---:|---:|---:|---:|']
    for name, result in sorted(packages.items()):
        counts = result['counts']
        rows.append(f"| {name} | {result['score']:.2f}% | {result['coverage']:.2f}% | {counts.get('KILLED', 0)} | {counts.get('LIVED', 0)} | {counts.get('TIMED OUT', 0)} | {counts.get('NOT COVERED', 0)} |")
    return '\n'.join(rows)+'\n'


def document_baseline(packages, write=False):
    text = DOCUMENT.read_text(encoding='utf-8')
    pattern = r'(?s)(<!-- mutation-baseline:start -->\n).*?(<!-- mutation-baseline:end -->)'
    if text.count('<!-- mutation-baseline:start -->') != 1 or text.count('<!-- mutation-baseline:end -->') != 1 or len(re.findall(pattern, text)) != 1:
        raise ValueError('missing or duplicate mutation baseline markers')
    rendered = re.sub(pattern, lambda match: match[1]+mutation_table(packages)+match[2], text)
    if write:
        DOCUMENT.write_text(rendered, encoding='utf-8')
    elif text != rendered:
        raise ValueError('documented mutation baseline differs from recorded package floors')


def check_recorded_evidence():
    baseline = json.loads(BASELINE.read_text(encoding='utf-8'))
    evidence = json.loads(EVIDENCE.read_text(encoding='utf-8'))
    if package_scores(evidence) != baseline['packages'] or evidence['tool'] != TOOL:
        raise ValueError('recorded mutation baseline differs from its expression results')
    files = {file['file_name'] for file in evidence['files']}
    if set(evidence['source_sha256']) != files:
        raise ValueError('recorded mutation evidence lacks source fingerprints')
    document_baseline(baseline['packages'])
    print('Recorded per-package mutation baseline agrees with all expression results.')


def run_tool(target, destination, workers, env, exclude=None):
    command = ['go', '-C', str(ROOT/'tests/tools'), 'run', TOOL, 'unleash', '--workers', str(workers), '--timeout-coefficient', '10', '--output', str(destination)]
    if exclude:
        command += ['--exclude-files', exclude]
    command += [str(target)]
    # v0.6.0 passes --test-cpu as a malformed single Go flag. The wrapper's
    # --test-cpu instead sets GOMAXPROCS for every test process, never that flag.
    inventory_path = destination.with_suffix('.inventory.json')
    inventory_command = command[:-1]+['--dry-run', command[-1]]
    inventory_command[inventory_command.index('--output')+1] = str(inventory_path)
    subprocess.run(inventory_command, env=env, check=True)
    inventory = json.loads(inventory_path.read_text(encoding='utf-8'))
    # The inventory run populates Go's test cache. A cached timing would give
    # the real campaign a timeout shorter than an ordinary uncached test run.
    subprocess.run(['go', 'clean', '-testcache'], cwd=target, env=env, check=True)
    subprocess.run(command, env=env, check=True)
    report = json.loads(destination.read_text(encoding='utf-8'))
    validate_inventory(report, inventory)
    return report


def control(directory, workers, env):
    target = directory/'control'
    target.mkdir()
    (target/'go.mod').write_text('module mutationcontrol\n\ngo 1.26.11\n')
    (target/'control.go').write_text('package mutationcontrol\nfunc Boundary(n int) bool { return n == 0 }\nfunc Partial(n int) bool { return n >= 0 }\n')
    (target/'control_test.go').write_text('package mutationcontrol\nimport "testing"\nfunc TestBoundary(t *testing.T) { if !Boundary(0) || Boundary(1) { t.Fatal("boundary") } }\nfunc TestPartial(t *testing.T) { if !Partial(1) { t.Fatal("partial") } }\n')
    report = run_tool(target, directory/'control.json', workers, env)
    counts = package_scores(report)['.']['counts']
    if not counts.get('KILLED') or not counts.get('LIVED') or counts.get('NOT VIABLE') or counts.get('TIMED OUT'):
        raise ValueError('mutation controls failed: kills and a known survivor must both be observed')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workers', type=int, default=2)
    parser.add_argument('--test-cpu', type=int, default=2)
    parser.add_argument('--output', type=Path, default=ROOT/'mutation-results')
    parser.add_argument('--record', action='store_true')
    parser.add_argument('--control-only', action='store_true')
    parser.add_argument('--check-evidence', action='store_true')
    args = parser.parse_args()
    if args.check_evidence:
        check_recorded_evidence()
        return
    if not 1 <= args.workers <= 2 or not 1 <= args.test_cpu <= 4:
        parser.error('use at most two mutation workers and four CPUs per test')
    env = dict(os.environ, GOMAXPROCS=str(args.test_cpu), GOWORK='off')
    args.output.mkdir(parents=True, exist_ok=True)
    output = args.output.resolve()
    print('EMBARGO_MUTATION_START', flush=True)
    with tempfile.TemporaryDirectory(prefix='embargo-mutation-') as temporary:
        temporary = Path(temporary)
        control(temporary, args.workers, env)
        shutil.copyfile(temporary/'control.json', output/'control.json')
        shutil.copyfile(temporary/'control.inventory.json', output/'control.inventory.json')
        if args.control_only:
            return
        snapshot = temporary/'source'
        shutil.copytree(ROOT, snapshot, ignore=shutil.ignore_patterns('.git', 'node_modules', '.lake', '__pycache__', 'mutation-results', 'benchmark-results', 'quality-results', '_apalache-out'))
        subprocess.run(['go', 'test', './...'], cwd=snapshot, env=env, check=True)
        root_report = run_tool(snapshot, output/'root.json', args.workers, env, r'(^|/)(adapters|tests|cmd)/')
        scores = package_scores(root_report)
        # gremlins infers package paths from package names; nested package main
        # is mapped incorrectly. A temporary module makes the command its root.
        command = temporary/'command'
        shutil.copytree(snapshot/'cmd/embargo-audit', command)
        version = subprocess.check_output(['go', '-C', str(ROOT/'tests'), 'list', '-m', '-f', '{{.Version}}', 'github.com/nao1215/embargo'], env=env, text=True).strip()
        (command/'go.mod').write_text(f'module mutationcommand\n\ngo 1.26.11\n\nrequire github.com/nao1215/embargo {version}\nreplace github.com/nao1215/embargo => {snapshot}\n')
        report = run_tool(command, output/'command.json', args.workers, env)
        scores.update(package_scores(report, 'cmd/embargo-audit'))
        files = root_report['files'] + [dict(file, file_name='cmd/embargo-audit/'+file['file_name']) for file in report['files']]
        evidence = {'tool': TOOL, 'files': files, 'source_sha256': {file['file_name']: hashlib.sha256((snapshot/file['file_name']).read_bytes()).hexdigest() for file in files}}
        if package_scores(evidence) != scores:
            raise ValueError('combined command and root mutation scopes disagree')
    result = {'tool': TOOL, 'workers': args.workers, 'gomaxprocs': args.test_cpu, 'timeout_coefficient': 10, 'packages': scores}
    (output/'summary.json').write_text(json.dumps(result, indent=2)+'\n')
    if args.record:
        if BASELINE.exists():
            check(scores, json.loads(BASELINE.read_text())['packages'])
        BASELINE.write_text(json.dumps(result, indent=2)+'\n')
        EVIDENCE.write_text(json.dumps(evidence, indent=2)+'\n')
        document_baseline(scores, write=True)
    else:
        check(scores, json.loads(BASELINE.read_text())['packages'])
    print('EMBARGO_MUTATION_SUMMARY '+json.dumps(result))
    print('Per-package mutation score and coverage floors passed; timeouts are not kills.')


if __name__ == '__main__':
    main()
