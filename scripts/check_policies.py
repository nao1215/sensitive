"""Enforce repository policies and verify that their CI mapping is executable."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def read(path):
    return (ROOT / path).read_text()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def test_file_budget(files=None):
    """Use source counterparts, or one canonical subject in the tests module."""
    if files is None:
        files = subprocess.check_output(['git', 'ls-files'], cwd=ROOT, text=True).splitlines()
    paths = set(files)
    subjects = {'accuracy', 'real_logs', 'comparison', 'cases', 'docs', 'severity',
                'integrations', 'quality_gates', 'properties', 'lifecycle', 'oracles',
                'api', 'policy'}
    extras = {'example_test.go', 'fuzz_test.go', 'benchmark_test.go'}
    violations = []
    for name in sorted(paths):
        path = Path(name)
        if not name.endswith('_test.go') or path.name in extras:
            continue
        source = path.with_name(path.name.removesuffix('_test.go') + '.go').as_posix()
        subject = (path.parts[0] == 'tests' and 'cmd' not in path.parts and
                   path.name.removesuffix('_test.go') in subjects)
        if source not in paths and not subject:
            violations.append(name)
    require(not violations, 'test file budget: ' + ', '.join(violations))


def repository_traces(files=None):
    """Keep development labels out of filenames, prose and generated text."""
    if files is None:
        names = subprocess.check_output(['git', 'ls-files'], cwd=ROOT, text=True).splitlines()
        files = {name: (ROOT/name).read_bytes().decode('utf-8', errors='replace') for name in names}
    pattern = re.compile(r'(?i)(?<![a-z])rounds?[ _-]*[0-9]+|\bR[0-9]+-[0-9]+\b|\bADR[ _-]*[0-9]+\b|\bPR [A-Z]\b|github\.com/nao1215/embargo/(?:pull/[0-9]+|commit/[0-9a-f]+)')
    violations = []
    for name, text in sorted(files.items()):
        if name == 'CHANGELOG.md':
            continue
        if pattern.search(name) or pattern.search(text):
            violations.append(name)
    require(not violations, 'development trace labels: ' + ', '.join(violations))


def root_module():
    module = json.loads(subprocess.check_output(['go', 'mod', 'edit', '-json'], cwd=ROOT))
    require(not module.get('Require'), 'root go.mod must have no require directives')
    require(not module.get('Tool'), 'tools belong in a separate module')


def documentation_contract():
    """Compare repeated architecture facts with Go and the executable gate."""
    expected = []
    for directory in ['.'] + ['adapters/'+name for name in ('grpc', 'logrus', 'otel', 'sentry', 'zap', 'zerolog')]:
        expected.extend(subprocess.check_output(['go', 'list', './...'], cwd=ROOT/directory, text=True).splitlines())
    require(read('CLAUDE.md') == '@AGENTS.md\n', 'CLAUDE.md must load the shared agent guide')
    text = read('AGENTS.md')
    block = re.search(r'<!-- packages:start -->\n(.*?)<!-- packages:end -->', text, re.S)
    require(block is not None, 'documented package inventory missing')
    actual = re.findall(r'^- `([^`]+)`$', block[1], re.M)
    require(sorted(actual) == sorted(expected), 'documented package inventory differs from go list')
    gate = re.search(r'acceptable:\s*(\d+)%', read('.octocov.yml'))[1]
    figures = re.findall(r'coverage[^\n]*?(\d+)%', text, re.I)
    require(figures and all(value == gate for value in figures), 'documented coverage differs from the gate')


def function_growth():
    """Require a reviewed baseline for growth in large production functions."""
    subprocess.run(['go', '-C', 'tests', 'run', './cmd/functionmetrics'], cwd=ROOT, check=True, stdout=subprocess.DEVNULL)


# slsa-verifier checks the generator's ref, so it must be referenced by its tag.
TAG_PINNED_WORKFLOWS = {'slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@v2.1.0'}


def workflows():
    # release.yml signs keylessly (id-token), attests archives (attestations) and
    # uploads them with the SLSA provenance (contents).
    writes = {'release.yml': {'contents', 'id-token', 'attestations'}, 'coverage.yml': {'actions', 'pull-requests'},
              'reviewdog.yml': {'pull-requests'}, 'codeql.yml': {'security-events'},
              'trivy.yml': {'security-events'}, 'scorecard.yml': {'security-events', 'id-token'},
              'fuzz.yml': {'issues'}}
    for path in sorted((ROOT / '.github/workflows').glob('*.yml')):
        text = path.read_text()
        require('permissions:' in text, f'{path.name}: explicit permissions required')
        require('write-all' not in text, f'{path.name}: write-all forbidden')
        actual = set(re.findall(r'^\s+([\w-]+):\s*write\s*$', text, re.M))
        require(actual <= writes.get(path.name, set()), f'{path.name}: unexpected write permissions: {actual}')
        if path.name == 'fuzz.yml':
            fuzz_issue_permissions(text)
        if path.name == 'scorecard.yml':
            require(not re.search(r'^(?:env|defaults):', text, re.M), 'Scorecard publication forbids workflow env/defaults')
        for reference in re.findall(r'uses:\s*([^\s#]+)', text):
            if reference.startswith('./'):
                require((ROOT/reference).is_file(), f'missing local workflow: {reference}')
            else:
                require(re.search(r'@[0-9a-f]{40}$', reference) or reference in TAG_PINNED_WORKFLOWS, f'unpinned action: {reference}')
        require('pull_request_target:' not in text, f'{path.name}: privileged PR execution forbidden')
    require('github-actions' in read('.github/dependabot.yml'), 'Dependabot must watch actions')


def fuzz_issue_permissions(text):
    """Limit issue writes to the scheduled main-branch reporting job."""
    prefix, jobs = text.split('\njobs:\n', 1)
    parts = re.split(r'^  ([\w-]+):\n', jobs, flags=re.M)
    blocks = dict(zip(parts[1::2], parts[2::2]))
    report = blocks.get('report', '')
    permission = r'^\s+issues:\s*write\s*$'
    require(not re.search(permission, prefix, re.M), 'fuzz issue permission must be job-scoped')
    require(sum(len(re.findall(permission, block, re.M)) for block in blocks.values()) == 1
            and re.search(r'^      issues: write$', report, re.M),
            'fuzz issue permission belongs only to the report job')
    condition = re.search(r'^    if: (.+)$', report, re.M)
    required = ['always()', "(github.event_name == 'schedule' || github.event_name == 'workflow_dispatch')", "github.ref == 'refs/heads/main'",
                "github.repository == 'nao1215/embargo'"]
    require(condition and condition[1].split(' && ') == required,
            'fuzz issue report must be restricted to scheduled main runs')
    require('    needs: [targets, fuzz]\n' in report, 'fuzz issue report must await all fuzz jobs')


def branding():
    text = read('README.md')
    badges = re.findall(r'^\[?!\[([^\]]+)\]', text.split('<p align=')[0], re.M)
    expected = ['All Contributors', 'Go Reference', 'MultiPlatformUnitTest', 'reviewdog', 'Gosec', 'Trivy', 'Coverage', 'OpenSSF Scorecard']
    require(badges == expected, f'badge set/order changed: {badges}')
    require(re.search(r'<p align="center">\s*<img[^>]+logo', text), 'README logo must be centered')
    require('https://github.com/sponsors/nao1215' in text, 'README sponsor link missing')


def lint_rules():
    config = read('.golangci.yml')
    for name in ['depguard', 'gochecknoglobals', 'errcheck', 'errorlint', 'revive', 'paralleltest', 'forbidigo', 'exhaustruct_v5']:
        require(re.search(r'\b'+name+r'\b', config), 'required linter removed: '+name)
    require('deepScan: true' in read('.go-arch-lint.yml'), 'architecture deep scan disabled')
    require('misspell' in read('.github/workflows/reviewdog.yml'), 'spelling review disabled')
    require('actionlint' in read('.github/workflows/reviewdog.yml'), 'workflow syntax check disabled')


def api_boundaries():
    for path in list(ROOT.glob('*.go')) + list((ROOT/'internal').rglob('*.go')):
        if path.name.endswith('_test.go'):
            continue
        text = path.read_text()
        require(not re.search(r'\.Tag\.(?:Get|Lookup)\("(?:mask|embargo|sensitive)"', text), 'struct-tag masking API is excluded')
    for path in ['secret.go', 'input.go']:
        require(not re.search(r'func\s+\([^)]*\b(?:Secret|Input)\[.*?\]\)\s+Value\(', read(path)), 'implicit SQL output is forbidden')
    require('func (s Secret[T]) Reveal() T' in read('secret.go'), 'Reveal must remain explicit')


def api_symbols(text):
    return {symbol for entry in json.loads(text) for symbol in entry['symbols']}


def unreleased(changelog):
    return changelog.split('## [Unreleased]', 1)[1].split('\n## [', 1)[0]


def untagged_release(changelog, tag):
    """Return the first version section after [Unreleased] when it is not the
    latest tag, as in a release PR that has cut the section but not tagged it."""
    after = changelog.split('## [Unreleased]', 1)[1].split('\n## [', 1)
    if tag is None or len(after) < 2:
        return ''
    version, _, body = after[1].partition(']')
    if 'v' + version == tag:
        return ''
    return body.split('\n## [', 1)[0]


def api_additions(previous=None, current=None, changelog=None, tag=None):
    """A public symbol added since the last release tag must be named in CHANGELOG
    [Unreleased], or in the version section a release PR cut from it."""
    if previous is None:
        tag = subprocess.run(['git', 'describe', '--tags', '--abbrev=0', '--match', 'v[0-9]*'], cwd=ROOT, capture_output=True, text=True, check=False).stdout.strip()
        shown = subprocess.run(['git', 'show', f'{tag}:doc/api-reasons.json'], cwd=ROOT, capture_output=True, text=True, check=False) if tag else None
        if not shown or shown.returncode != 0:
            return
        previous = shown.stdout
    current = read('doc/api-reasons.json') if current is None else current
    changelog = read('CHANGELOG.md') if changelog is None else changelog
    # A release PR moves the notes from [Unreleased] into the new version's
    # section, which no tag names yet; the symbols must be named in either.
    notes = unreleased(changelog) + untagged_release(changelog, tag)
    for symbol in sorted(api_symbols(current) - api_symbols(previous)):
        name = symbol.split(' ', 1)[1] if symbol.startswith('embargo --') else symbol.rsplit('.', 1)[-1]
        require(re.search(r'`[^`\n]*(?<![\w-])' + re.escape(name) + r'(?:\(\))?`', notes), f'api-additions: {symbol} is new public API; name it in CHANGELOG [Unreleased] with the reason from doc/api-reasons.json')


def schedules():
    text=read('.github/workflows/fuzz.yml')
    require('schedule:' in text and '-fuzz ' in text, 'continuous fuzz search missing')
    require('scripts/fuzz_targets.py' in text, 'fuzz inventory must be discovered')
    for path in ['.github/workflows/verification.yml','.github/workflows/heavy.yml']:
        require((ROOT/path).is_file(), 'missing technique workflow '+path)
    for name in ['quint_models.py','check_lean.py','check_prose.py','check_policies.py','lock_actions.py --check']:
        require(name in read('.github/workflows/verification.yml'), 'verification is not wired: '+name)


def detector_docs():
    workflow = read('.github/workflows/verification.yml')
    for command in ['go -C tests run ./cmd/detectordocs --check', 'go -C tests test ./cmd/detectordocs -count=1']:
        require(command in workflow, 'detector documentation check missing: '+command)


def pr_metadata():
    if os.environ.get('GITHUB_EVENT_NAME') != 'pull_request':
        return
    event=json.loads(Path(os.environ['GITHUB_EVENT_PATH']).read_text())
    title=event['pull_request']['title']
    require(re.fullmatch(r'(?:feat|fix|docs|test|perf|refactor|build|ci|chore|revert)(?:\([a-z0-9_-]+\))?!?: [^\n]+', title), 'PR title must be an English Conventional Commit')
    require(not re.search('[\u3040-\u30ff\u4e00-\u9fff]',title), 'PR title must be English')
    base=event['pull_request']['base']['sha'];head=event['pull_request']['head']['sha']
    messages=subprocess.check_output(['git','log','--format=%B',base+'..'+head],cwd=ROOT,text=True)
    require(not re.search(r'(?im)^.*(?:co-authored-by|signed-off-by).*\b(?:claude|codex|copilot|openai|anthropic)\b',messages), 'agent trailers are forbidden')
    # Publishing stays a separate, explicitly requested workflow; PR jobs cannot release.
    require('gh release create' not in '\n'.join(p.read_text() for p in (ROOT/'.github/workflows').glob('*.yml') if p.name!='release.yml'), 'PR verification must not publish releases')


def linked_tests():
    techniques=json.loads(read('scripts/testing_techniques.json'))
    for row in techniques:
        require(row['bug'] and row['ci'], 'technique needs a concrete bug class and CI job')
        for path in row['paths']:
            require((ROOT/path).is_file(), 'technique test path missing: '+path)
        workflow,job=row['ci'].split(':')
        text = read('.github/workflows/'+workflow+'.yml')
        match = re.search(r'^  '+re.escape(job)+r':\n(.*?)(?=^  [\w-]+:|\Z)', text, re.M | re.S)
        require(match, 'technique job missing: '+row['ci'])
        require(row.get('commands'), 'technique must name its executed commands: '+row['name'])
        for command in row['commands']:
            require(command in match[1], 'technique command missing: '+command)


def evidence():
    # held-split: the owner has inspected the previous held partition.
    require('held split has been seen' in read('doc/testing.md'), 'disclose held data reuse')
    # ci-timing: measurements stay in review metadata.
    require('timing tables in PR bodies only' in read('doc/ci.md'), 'CI timing placement policy missing')
    # regression-evidence: CI checks retention; the report records red-before-green order.
    for path in ['internal/detect/ipaddr_test.go','embargotest/guard_test.go']:
        require((ROOT/path).is_file(), 'regression removed: '+path)
    # security-scans: do not optimize away security visibility.
    for path in ['codeql.yml','gosec.yml','trivy.yml','govulncheck.yml']:
        require('pull_request:' in read('.github/workflows/'+path), 'PR security scan removed')


def cohesion(files=None):
    """Keep byte classes, the scanned view and each detector in one owner."""
    if files is None:
        names = subprocess.check_output(['git', 'ls-files', '*.go'], cwd=ROOT, text=True).splitlines()
        files = {name: read(name) for name in names}
    production = {name: text for name, text in files.items()
                  if not name.endswith('_test.go') and not name.startswith(('tests/', 'adapters/'))}
    ascii_range = re.compile(r"""(?:>=\s*'0'\s*&&\s*[\w.\[\]+-]+\s*<=\s*'9'|>=\s*'a'\s*&&\s*[\w.\[\]+-]+\s*<=\s*'z'|>=\s*'A'\s*&&\s*[\w.\[\]+-]+\s*<=\s*'Z')""")
    violations = []
    for name, text in sorted(production.items()):
        if not name.startswith('internal/ascii/') and ascii_range.search(text):
            violations.append(name + ': ASCII class outside internal/ascii')
        if not name.startswith('internal/detect/') and re.search(r'\.\(\*?detect\.', text):
            violations.append(name + ': detector-specific type assertion')
        if name == 'scanner_dispatch.go' and re.search(r'\bKind[A-Z]\w*', text):
            violations.append(name + ': dispatch names a detector kind')
        if name.startswith('internal/detect/'):
            receivers = set(re.findall(r'^func \(\w+ \*?(\w+)\) Scan\(data \[\]byte\) \[\]Finding', text, re.M))
            if len(receivers) > 1:
                violations.append(name + ': more than one detector: ' + ', '.join(sorted(receivers)))
            if name != 'internal/detect/view.go' and re.search(r'^func (?:composePositions|originalPosition|mapOriginalRange|decodePercent|removeTokenSeparators)\(', text, re.M):
                violations.append(name + ': offset map outside view.go')
    require(not violations, 'cohesion: ' + '; '.join(violations))


def mapping():
    rows=json.loads(read('scripts/policies.json'))
    checks={'function-growth':function_growth,'documentation-contract':documentation_contract,'repository-traces':repository_traces,'test-file-budget':test_file_budget,'root-module':root_module,'workflow-security':workflows,'branding':branding,'lint-config':lint_rules,'api-boundary':api_boundaries,'schedules':schedules,'pr-metadata':pr_metadata,'technique-links':linked_tests, 'evidence':evidence, 'detector-docs':detector_docs, 'cohesion':cohesion, 'api-additions':api_additions}
    for row in rows:
        require(row['source'] and row['rule'] and row['where'], 'policy mapping is incomplete')
        if row['check'] in checks:
            continue
        path,marker=row['check'].split('#',1)
        require(marker in read(path), 'policy check missing: '+row['check'])
        require(row['where'] in {'MultiPlatformUnitTest','golangci-lint','Verification','Heavy verification','Coverage','reviewdog','Pre-merge audit'}, 'unknown policy workflow')
    for check in checks.values():check()
    table='| Rule | Source | Check | Where it runs |\n|---|---|---|---|\n'
    for row in rows:
        check=row['check']
        label=check if '#' not in check else check.split('#')[1]
        target='../scripts/check_policies.py' if '#' not in check else '../'+check.split('#')[0]
        table+=f"| {row['rule']} | {row['source']} | [{label}]({target}) | {row['where']} |\n"
    return table


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--write',action='store_true');args=parser.parse_args()
    table=mapping()
    path=ROOT/'doc/policies.md';text=path.read_text()
    start='<!-- policy-map:start -->';end='<!-- policy-map:end -->'
    expected=text.split(start)[0]+start+'\n'+table+end+text.split(end)[1]
    if args.write:path.write_text(expected)
    else:require(text==expected,'policy mapping is stale; run python3 scripts/check_policies.py --write')
    print('repository policies and mapped checks passed')


if __name__=='__main__':main()
