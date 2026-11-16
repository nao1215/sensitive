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


def root_module():
    module = json.loads(subprocess.check_output(['go', 'mod', 'edit', '-json'], cwd=ROOT))
    require(not module.get('Require'), 'root go.mod must have no require directives')
    require(not module.get('Tool'), 'tools belong in a separate module')


def workflows():
    writes = {'release.yml': {'contents'}, 'coverage.yml': {'actions', 'pull-requests'},
              'reviewdog.yml': {'pull-requests'}, 'codeql.yml': {'security-events'},
              'trivy.yml': {'security-events'}, 'scorecard.yml': {'security-events', 'id-token'}}
    for path in sorted((ROOT / '.github/workflows').glob('*.yml')):
        text = path.read_text()
        require('permissions:' in text, f'{path.name}: explicit permissions required')
        require('write-all' not in text, f'{path.name}: write-all forbidden')
        actual = set(re.findall(r'^\s+([\w-]+):\s*write\s*$', text, re.M))
        require(actual <= writes.get(path.name, set()), f'{path.name}: unexpected write permissions: {actual}')
        if path.name == 'scorecard.yml':
            require(not re.search(r'^(?:env|defaults):', text, re.M), 'Scorecard publication forbids workflow env/defaults')
        for reference in re.findall(r'uses:\s*([^\s#]+)', text):
            if reference.startswith('./'):
                require((ROOT/reference).is_file(), f'missing local workflow: {reference}')
            else:
                require(re.search(r'@[0-9a-f]{40}$', reference), f'unpinned action: {reference}')
        require('pull_request_target:' not in text, f'{path.name}: privileged PR execution forbidden')
    require('github-actions' in read('.github/dependabot.yml'), 'Dependabot must watch actions')


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
    # ci-timing: values are observations tied to commits, never guessed durations.
    require('Workflow | Base' in read('doc/ci.md') and 'Job | Base' in read('doc/ci.md'), 'missing round CI timing tables')
    # regression-evidence: CI checks retention; the report records red-before-green order.
    for path in ['internal/detect/ipaddr_test.go','embargotest/guard_adversarial_test.go']:
        require((ROOT/path).is_file(), 'regression removed: '+path)
    # security-scans: do not optimize away security visibility.
    for path in ['codeql.yml','gosec.yml','trivy.yml','govulncheck.yml']:
        require('pull_request:' in read('.github/workflows/'+path), 'PR security scan removed')


def mapping():
    rows=json.loads(read('scripts/policies.json'))
    checks={'root-module':root_module,'workflow-security':workflows,'branding':branding,'lint-config':lint_rules,'api-boundary':api_boundaries,'schedules':schedules,'pr-metadata':pr_metadata,'technique-links':linked_tests, 'evidence':evidence, 'detector-docs':detector_docs}
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
