"""Wait until every other check on the tagged commit has passed, or fail.

The release job publishes archives, signatures and provenance for a tag. A tag
on a commit whose unit, coverage or verification jobs failed, or are still
running, must not publish; this step makes that a precondition instead of a
convention.
"""
import argparse
import json
import subprocess
import time

PASSING = {'success', 'skipped', 'neutral'}


def verdict(runs, own_suite):
    """Return 'pass', 'wait' or a failure reason for the check runs outside
    this workflow run's own check suite, whose later jobs wait for this one."""
    others = [run for run in runs if run['suite'] != own_suite]
    if not others:
        return 'wait'
    failed = sorted(run['name'] for run in others if run['status'] == 'completed' and run['conclusion'] not in PASSING)
    if failed:
        return 'failed: '+', '.join(failed)
    if any(run['status'] != 'completed' for run in others):
        return 'wait'
    return 'pass'


def check_runs(repository, sha):
    output = subprocess.check_output(['gh', 'api', '--paginate', f'repos/{repository}/commits/{sha}/check-runs?per_page=100', '--jq', '.check_runs[] | {name, status, conclusion, suite: .check_suite.id}'], text=True)
    return [json.loads(line) for line in output.splitlines() if line.strip()]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repository', required=True)
    parser.add_argument('--sha', required=True)
    parser.add_argument('--run-id', required=True, help='this workflow run, whose own jobs are excluded')
    parser.add_argument('--timeout', type=int, default=1500)
    args = parser.parse_args()
    own_suite = int(subprocess.check_output(['gh', 'api', f'repos/{args.repository}/actions/runs/{args.run_id}', '--jq', '.check_suite_id'], text=True))
    deadline = time.monotonic()+args.timeout
    while True:
        result = verdict(check_runs(args.repository, args.sha), own_suite)
        if result == 'pass':
            print('every other check on the tagged commit passed')
            return
        if result != 'wait':
            raise SystemExit('tagged commit has failing checks; '+result)
        if time.monotonic() > deadline:
            raise SystemExit('checks on the tagged commit did not finish in time')
        time.sleep(30)


if __name__ == '__main__':
    main()
