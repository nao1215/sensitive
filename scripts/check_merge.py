"""Read live state before an owner-authorized squash merge of this repository."""
import argparse
import json
import re
import subprocess


def gh(*args):
    return json.loads(subprocess.check_output(['gh', *args], text=True))


def owned_repository(repo):
    if repo != 'nao1215/embargo':
        raise ValueError('this workflow only operates on nao1215/embargo')


def explicit_review_limit(entry):
    """Accept the service's explicit limit response, never an ordinary skip."""
    if entry['author']['login'] not in {'coderabbitai', 'coderabbitai[bot]'}:
        return False
    return bool(re.search(r'review rate limit|rate limit exceeded|<!-- This is an auto-generated comment: rate limited by coderabbit.ai -->', entry['body'], re.I))


def check_merge(number):
    repo = 'nao1215/embargo'
    owned_repository(repo)
    pr = gh('pr', 'view', str(number), '--repo', repo, '--json', 'number,author,headRefOid,headRepositoryOwner,state,title,statusCheckRollup,comments,reviews')
    if pr['author']['login'] != 'nao1215' or pr['headRepositoryOwner']['login'] != 'nao1215' or pr['state'] != 'OPEN':
        raise ValueError('only the owner-authored open PR may be merged')
    checks = pr['statusCheckRollup']
    if not checks or any(c.get('conclusion',c.get('state')) not in {'SUCCESS','NEUTRAL','SKIPPED'} for c in checks):
        raise ValueError('every current-head check must have completed successfully')
    query = '''query($n:Int!,$cursor:String){repository(owner:"nao1215",name:"embargo"){pullRequest(number:$n){reviewThreads(first:100,after:$cursor){nodes{isResolved}pageInfo{hasNextPage endCursor}}}}}'''
    cursor = None
    while True:
        args = ['api','graphql','-f','query='+query,'-F','n='+str(number)]
        if cursor: args += ['-f','cursor='+cursor]
        threads = gh(*args)['data']['repository']['pullRequest']['reviewThreads']
        if any(not t['isResolved'] for t in threads['nodes']): raise ValueError('unresolved review threads')
        if not threads['pageInfo']['hasNextPage']: break
        cursor = threads['pageInfo']['endCursor']
    rabbit = [x for x in pr['reviews']+pr['comments'] if 'coderabbit' in x['author']['login'].lower()]
    reviewed = any(x.get('commit',{}).get('oid') == pr['headRefOid'] for x in rabbit)
    rate_limited = any(explicit_review_limit(x) for x in rabbit)
    if not reviewed and not rate_limited: raise ValueError('current-head CodeRabbit review or explicit rate limit required')
    print(json.dumps({'repository':repo,'pr':number,'head':pr['headRefOid'],'checks':len(checks),'unresolved_threads':0,'explicit_review_rate_limit':rate_limited},indent=2))
    # No release, push, issue edits, or external repository writes occur here.
    print(f'gh pr merge {number} --repo {repo} --squash --match-head-commit {pr["headRefOid"]}')


if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('pr',type=int)
    check_merge(parser.parse_args().pr)
