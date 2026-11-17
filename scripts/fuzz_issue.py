"""Keep one bot-owned issue for scheduled main-branch fuzz failures."""
import json
import os
import re
import subprocess

REPOSITORY = 'nao1215/embargo'
MARKER = '<!-- embargo-nightly-fuzz -->'
TITLE = 'Scheduled fuzzing failed on main'


def api(path, method='GET', body=None):
    command = ['gh', 'api', '--method', method, 'repos/' + REPOSITORY + '/' + path]
    if body is not None:
        command += ['--input', '-']
    result = subprocess.run(command, input=json.dumps(body) if body is not None else None,
                            text=True, capture_output=True, check=True)
    return json.loads(result.stdout)


def pages(path, key=None):
    result = []
    for page in range(1, 1001):
        separator = '&' if '?' in path else '?'
        data = api(f'{path}{separator}per_page=100&page={page}')
        batch = data[key] if key else data
        result.extend(batch)
        if len(batch) < 100:
            return result
    raise RuntimeError('GitHub pagination limit reached')


def issue_update(env, jobs, artifacts, issues):
    """Build a mutation only for this workflow's own issue and a newer result."""
    if (env['GITHUB_REPOSITORY'] != REPOSITORY or env['GITHUB_EVENT_NAME'] not in ('schedule', 'workflow_dispatch')
            or env['GITHUB_REF'] != 'refs/heads/main'):
        return None
    failures = [job for job in jobs if job['conclusion'] == 'failure']
    results = (env['TARGET_RESULT'], env['FUZZ_RESULT'])
    green = results == ('success', 'success')
    if not green and (env['GITHUB_EVENT_NAME'] != 'schedule' or 'failure' not in results):
        return None  # Cancellation or skipped work does not establish recovery.
    owned = [issue for issue in issues if 'pull_request' not in issue
             and issue['user']['login'] == 'github-actions[bot]'
             and MARKER in (issue.get('body') or '')]
    if len(owned) > 1:
        raise RuntimeError('multiple bot-owned fuzz issues require reconciliation')
    issue = owned[0] if owned else None
    number = int(env['GITHUB_RUN_NUMBER'])
    attempt = int(env['GITHUB_RUN_ATTEMPT'])
    if issue:
        prior = re.search(r'<!-- fuzz-run: (\d+)/(\d+) -->', issue['body'])
        if prior and (number, attempt) < tuple(map(int, prior.groups())):
            return None
    if green and issue is None:
        return None
    run = f"https://github.com/{REPOSITORY}/actions/runs/{env['GITHUB_RUN_ID']}"
    lines = [MARKER, f'<!-- fuzz-run: {number}/{attempt} -->', '',
             f"Fuzzing on main {'passed' if green else 'failed'}: [workflow run]({run})."]
    if not green:
        if not failures:
            raise RuntimeError('failed workflow result has no failed job evidence')
        for job in failures:
            target = re.search(r'\bFuzz\w+\b', job['name'])
            name = target[0] if target else 'Target discovery'
            matching = [a for a in artifacts if target and
                        a['name'].startswith('fuzz-crashers-' + name + '-')]
            lines += ['', f'Target: `{name}`; [failed job]({job["html_url"]}).']
            if matching:
                lines += ['', 'Crasher artifacts: ' + ', '.join(
                    f'[{a["name"]}]({run}/artifacts/{a["id"]})' for a in matching) + '.']
            else:
                lines += ['', 'No crasher artifact was uploaded; inspect the failed job and the run artifacts.']
    body = {'title': TITLE, 'body': '\n'.join(lines) + '\n', 'state': 'closed' if green else 'open'}
    if issue:
        if green:
            body['state_reason'] = 'completed'
        return f'issues/{issue["number"]}', 'PATCH', body
    body.pop('state')
    return 'issues', 'POST', body


def main():
    env = os.environ
    if (env['GITHUB_REPOSITORY'] != REPOSITORY or env['GITHUB_EVENT_NAME'] not in ('schedule', 'workflow_dispatch')
            or env['GITHUB_REF'] != 'refs/heads/main'):
        return
    run = env['GITHUB_RUN_ID']
    jobs = pages(f'actions/runs/{run}/attempts/{env["GITHUB_RUN_ATTEMPT"]}/jobs', 'jobs')
    artifacts = pages(f'actions/runs/{run}/artifacts', 'artifacts')
    issues = pages('issues?state=all&creator=github-actions%5Bbot%5D')
    update = issue_update(env, jobs, artifacts, issues)
    if update:
        result = api(*update)
        print(result['html_url'])


if __name__ == '__main__':
    main()
