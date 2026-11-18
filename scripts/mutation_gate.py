"""Measure released gremlins in the tools module and enforce per-package score floors."""
import argparse
from collections import Counter
import hashlib
import json
import os
import re
import resource
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor

ROOT = Path(__file__).resolve().parents[1]
TOOL = 'github.com/go-gremlins/gremlins/cmd/gremlins@v0.6.0'
BASELINE = ROOT/'doc/mutation-baseline.json'
EVIDENCE = ROOT/'doc/performance/mutation-baseline.json'
DOCUMENT = ROOT/'doc/testing.md'
# A mutant that turns a loop into unbounded growth used to be killed only after
# it exhausted tens of gigabytes. Capping the address space of the tool, the go
# command and every test binary makes it fail fast as out of memory instead.
ADDRESS_SPACE = 4 << 30
COMMAND = 'cmd/embargo'
PACKAGES = ('embargotest', 'internal/ascii', 'internal/detect', 'internal/output', 'internal/saferecord')
STATUSES = {'KILLED', 'LIVED', 'NOT COVERED', 'NOT VIABLE', 'TIMED OUT'}
# gremlins times `go test` including the build of the mutated package, so a
# mutant compiled while other workers compete for the CPU can exceed ten times
# the coverage run without being slower. Timed-out mutants are rebuilt alone
# and only their test binary is timed, with the same coefficient.
TIMEOUT_COEFFICIENT = 10
MINIMUM_RERUN_TIMEOUT = 10.0
# The operators gremlins v0.6.0 replaces for each default mutator type.
REPLACEMENTS = {
    'ARITHMETIC_BASE': {'+': '-', '-': '+', '*': '/', '/': '*', '%': '*'},
    'CONDITIONALS_BOUNDARY': {'>=': '>', '>': '>=', '<=': '<', '<': '<='},
    'CONDITIONALS_NEGATION': {'==': '!=', '!=': '==', '>=': '<', '>': '<=', '<=': '>', '<': '>='},
    'INCREMENT_DECREMENT': {'++': '--', '--': '++'},
    'INVERT_NEGATIVES': {'-': '+'},
}
# Go operators longest first, so the token at a column is never read as its prefix.
GO_OPERATORS = sorted(('<<=', '>>=', '&^=', '&&', '||', '<-', '++', '--', '==', '!=', '<=', '>=', '+=', '-=', '*=', '/=', '%=', '&=', '|=', '^=', '<<', '>>', '&^', ':=', '+', '-', '*', '/', '%', '<', '>', '=', '!', '&', '|', '^'), key=len, reverse=True)


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


def check(actual, baseline, selected=None):
    """Compare every measured package with its floors and report all of them
    before failing; selected limits the comparison to a partial run."""
    expected = set(baseline) if selected is None else set(selected)
    if set(actual) != expected or not expected <= set(baseline):
        raise ValueError('mutation package scope changed; review and measure every package')
    failures = []
    for name in sorted(expected):
        row = [name]
        for metric in ('score', 'coverage'):
            got, floor = actual[name][metric], baseline[name][metric]
            row.append(f'{metric} {got} (floor {floor})')
            if got < floor:
                failures.append(f'{name} mutation {metric} fell: {got} < {floor}')
        print('  '.join(row), flush=True)
    if failures:
        raise ValueError('; '.join(failures))


def selected_packages(value):
    """Parse --packages: a comma-separated subset of the measured packages."""
    if value is None:
        return None
    names = [name.strip() for name in value.split(',') if name.strip()]
    known = ('.', *PACKAGES, COMMAND)
    unknown = sorted(set(names) - set(known))
    if not names or unknown:
        raise ValueError('--packages takes a comma-separated subset of: '+', '.join(known))
    return sorted(set(names))


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


def mutate_source(source, mutant):
    """Apply one gremlins mutation at its 1-based line and byte column."""
    lines = source.split(b'\n')
    line, column = mutant['line']-1, mutant['column']-1
    if not 0 <= line < len(lines) or not 0 <= column < len(lines[line]):
        raise ValueError(f"mutant position outside source: {mutant['line']}:{mutant['column']}")
    text = lines[line]
    replacements = REPLACEMENTS.get(mutant['type'])
    if replacements is None:
        raise ValueError('unsupported mutant type for rerun: '+mutant['type'])
    token = next((operator for operator in GO_OPERATORS if text.startswith(operator.encode(), column)), None)
    if token not in replacements:
        raise ValueError(f"no {mutant['type']} operator at {mutant['line']}:{mutant['column']}")
    lines[line] = text[:column]+replacements[token].encode()+text[column+len(token):]
    return b'\n'.join(lines)


def test_binary(module, package, overlay, binary, env):
    command = ['go', 'test', '-c', '-o', str(binary)]
    if overlay:
        command += ['-overlay', str(overlay)]
    subprocess.run(command+['./'+package if package != '.' else '.'], cwd=module, env=env, check=True, stdout=subprocess.DEVNULL, preexec_fn=limit_memory)


def run_binary(binary, directory, env, timeout):
    """Return KILLED, LIVED or TIMED OUT for one test binary run."""
    try:
        result = subprocess.run([str(binary), '-test.failfast', '-test.timeout', f'{int(timeout)+2}s'], cwd=directory, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=timeout, preexec_fn=limit_memory)
    except subprocess.TimeoutExpired:
        return 'TIMED OUT'
    return 'LIVED' if result.returncode == 0 else 'KILLED'


def rerun_timed_out(report, module, package, workers, env, scratch):
    """Rebuild each timed-out mutant alone and time only its test binary."""
    directory = module/package
    pending = [(file, mutant) for file in report['files'] for mutant in file['mutations'] if mutant['status'].replace('_', ' ').upper() == 'TIMED OUT']
    if not pending:
        return report
    scratch.mkdir(parents=True, exist_ok=True)
    original = scratch/'original.test'
    test_binary(module, package, None, original, env)
    started = time.monotonic()
    if run_binary(original, directory, env, 600) != 'LIVED':
        raise ValueError('unmutated tests fail or hang for '+package)
    timeout = max(MINIMUM_RERUN_TIMEOUT, TIMEOUT_COEFFICIENT*(time.monotonic()-started))

    def rerun(index, file, mutant):
        path = directory/file['file_name']
        mutated = scratch/f'{index}.go'
        mutated.write_bytes(mutate_source(path.read_bytes(), mutant))
        overlay = scratch/f'{index}.json'
        overlay.write_text(json.dumps({'Replace': {str(path): str(mutated)}}))
        binary = scratch/f'{index}.test'
        test_binary(module, package, overlay, binary, env)
        status = run_binary(binary, directory, env, timeout)
        binary.unlink()
        return status

    with ThreadPoolExecutor(max_workers=workers) as pool:
        statuses = list(pool.map(lambda item: rerun(item[0], *item[1]), enumerate(pending)))
    for (_, mutant), status in zip(pending, statuses):
        mutant['status'] = status
        mutant['rerun_timeout_seconds'] = round(timeout, 1)
    return report


def limit_memory():
    resource.setrlimit(resource.RLIMIT_AS, (ADDRESS_SPACE, ADDRESS_SPACE))


def run_tool(target, destination, workers, env, exclude=None, diff=None):
    command = ['go', '-C', str(ROOT/'tests/tools'), 'run', TOOL, 'unleash', '--workers', str(workers), '--timeout-coefficient', str(TIMEOUT_COEFFICIENT), '--output', str(destination)]
    if exclude:
        command += ['--exclude-files', exclude]
    if diff:
        command += ['--diff', diff]
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
    subprocess.run(command, env=env, check=True, preexec_fn=limit_memory)
    report = json.loads(destination.read_text(encoding='utf-8'))
    validate_inventory(report, inventory)
    return report


def measure(module, package, destination, workers, env, scratch, exclude=None, diff=None):
    """Run gremlins on one package, then settle its timed-out mutants alone."""
    report = run_tool(module/package, destination, workers, env, exclude, diff)
    report = rerun_timed_out(report, module, package, workers, env, scratch)
    destination.write_text(json.dumps(report, indent=2)+'\n')
    return report


def changed_survivors(files):
    return [f"{file['file_name']}:{mutant['line']}:{mutant['column']} {mutant['type']} {mutant['status']}" for file in files for mutant in file['mutations'] if mutant['status'].replace('_', ' ').upper() in ('LIVED', 'TIMED OUT', 'NOT COVERED')]


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
    parser.add_argument('--diff', metavar='REF', help='mutate only lines changed since REF and list survivors; floors are not checked')
    parser.add_argument('--packages', metavar='LIST', help='measure only these packages, such as internal/detect,., and check their floors; cannot record')
    args = parser.parse_args()
    try:
        selected = selected_packages(args.packages)
    except ValueError as error:
        parser.error(str(error))
    if selected is not None and args.record:
        parser.error('--record needs every package; omit --packages')
    wanted = set(selected or ('.', *PACKAGES, COMMAND))
    if args.check_evidence:
        check_recorded_evidence()
        return
    if not 1 <= args.workers <= 8 or not 1 <= args.test_cpu <= 2:
        parser.error('use at most eight mutation workers and two CPUs per test')
    env = dict(os.environ, GOMAXPROCS=str(args.test_cpu), GOWORK='off', EMBARGO_MUTATION='1')
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
        # gremlins reads the diff with git, so a diff run keeps the history.
        ignored = () if args.diff else ('.git',)
        shutil.copytree(ROOT, snapshot, symlinks=True, ignore=shutil.ignore_patterns(*ignored, 'node_modules', '.lake', '__pycache__', 'mutation-results', 'benchmark-results', 'quality-results', '_apalache-out'))
        subprocess.run(['go', 'test', './...'], cwd=snapshot, env=env, check=True, preexec_fn=limit_memory)
        listed = subprocess.check_output(['go', 'list', '-f', '{{.Dir}}', './...'], cwd=snapshot, env=env, text=True).split()
        listed = {Path(path).relative_to(snapshot).as_posix() for path in listed} - {'.', 'cmd/embargo'}
        if listed != set(PACKAGES):
            raise ValueError('root packages changed; list every package in PACKAGES')
        # One run per package: gremlins derives every mutant's timeout from the
        # coverage run of its target, so a whole-module target made a 0.2 s
        # package wait for ten times the module's test time.
        scratch = temporary/'rerun'
        files = []
        if '.' in wanted:
            files += measure(snapshot, '.', output/'root.json', args.workers, env, scratch/'root', '/', args.diff)['files']
        for package in sorted(wanted & set(PACKAGES)):
            report = measure(snapshot, package, output/(package.replace('/', '-')+'.json'), args.workers, env, scratch/package, '/', args.diff)
            files += [dict(file, file_name=package+'/'+file['file_name']) for file in report['files']]
        root_report = {'files': files}
        if args.diff:
            survivors = changed_survivors(files)
            print('\n'.join(['Surviving mutants on changed lines:']+survivors) if survivors else 'Every mutant on changed lines was killed.')
            return
        scores = package_scores(root_report) if files else {}
        if COMMAND not in wanted:
            result = {'tool': TOOL, 'workers': args.workers, 'gomaxprocs': args.test_cpu, 'timeout_coefficient': TIMEOUT_COEFFICIENT, 'packages': scores}
            (output/'summary.json').write_text(json.dumps(result, indent=2)+'\n')
            check(scores, json.loads(BASELINE.read_text())['packages'], selected)
            print('Mutation floors passed for '+', '.join(sorted(scores))+'.')
            return
        # gremlins infers package paths from package names; nested package main
        # is mapped incorrectly. A temporary module makes the command its root.
        command = temporary/'command'
        shutil.copytree(snapshot/'cmd/embargo', command)
        version = subprocess.check_output(['go', '-C', str(ROOT/'tests'), 'list', '-m', '-f', '{{.Version}}', 'github.com/nao1215/embargo'], env=env, text=True).strip()
        (command/'go.mod').write_text(f'module mutationcommand\n\ngo 1.26.11\n\nrequire github.com/nao1215/embargo {version}\nreplace github.com/nao1215/embargo => {snapshot}\n')
        report = measure(command, '.', output/'command.json', args.workers, env, scratch/'command')
        scores.update(package_scores(report, COMMAND))
        files = root_report['files'] + [dict(file, file_name=COMMAND+'/'+file['file_name']) for file in report['files']]
        evidence = {'tool': TOOL, 'files': files, 'source_sha256': {file['file_name']: hashlib.sha256((snapshot/file['file_name']).read_bytes()).hexdigest() for file in files}}
        if package_scores(evidence) != scores:
            raise ValueError('combined command and root mutation scopes disagree')
    result = {'tool': TOOL, 'workers': args.workers, 'gomaxprocs': args.test_cpu, 'timeout_coefficient': TIMEOUT_COEFFICIENT, 'packages': scores}
    (output/'summary.json').write_text(json.dumps(result, indent=2)+'\n')
    if args.record:
        if BASELINE.exists():
            check(scores, json.loads(BASELINE.read_text())['packages'])
        BASELINE.write_text(json.dumps(result, indent=2)+'\n')
        EVIDENCE.write_text(json.dumps(evidence, indent=2)+'\n')
        document_baseline(scores, write=True)
    else:
        check(scores, json.loads(BASELINE.read_text())['packages'], selected)
    print('EMBARGO_MUTATION_SUMMARY '+json.dumps(result))
    print('Per-package mutation score and coverage floors passed; timeouts that persist when rerun alone are not kills.')


if __name__ == '__main__':
    main()
