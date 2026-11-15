"""Collect GitHub workflow, job and step times for a specific reviewed commit."""
import argparse
import datetime
import json
from pathlib import Path
import subprocess


def gh(*args):
    return json.loads(subprocess.check_output(['gh', *args], text=True))


def seconds(start, end):
    return (datetime.datetime.fromisoformat(end.replace('Z', '+00:00')) - datetime.datetime.fromisoformat(start.replace('Z', '+00:00'))).total_seconds()


def collect(commit):
    repo = 'nao1215/embargo'
    runs = gh('run', 'list', '--repo', repo, '--commit', commit, '--limit', '100', '--json', 'databaseId,name,headSha,createdAt,updatedAt,status,conclusion,event')
    if not runs or any(run['status'] != 'completed' for run in runs):
        raise ValueError('wait for completed workflows before recording timings')
    for run in runs:
        pages = gh('api', '--paginate', '--slurp', f'repos/{repo}/actions/runs/{run["databaseId"]}/jobs?per_page=100')
        jobs = [job for page in pages for job in page['jobs']]
        run['jobs'] = []
        for job in jobs:
            run['jobs'].append({'name': job['name'], 'seconds': seconds(job['started_at'], job['completed_at']),
                                'conclusion': job['conclusion'], 'started_at': job['started_at'], 'completed_at': job['completed_at'],
                                'steps': [{'name': step['name'], 'seconds': seconds(step['started_at'], step['completed_at']) if step.get('started_at') and step.get('completed_at') else None} for step in job['steps']]})
        run['wall_seconds'] = seconds(run['createdAt'], max((job['completed_at'] for job in jobs), default=run['updatedAt']))
    return runs


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--commit', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    runs = collect(args.commit)
    args.output.write_text(json.dumps(runs, indent=2)+'\n', encoding='utf-8')
    for run in runs:
        print(f'{run["name"]}: {run["wall_seconds"]}s')


if __name__ == '__main__':
    main()
