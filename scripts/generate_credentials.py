#!/usr/bin/env python3
"""Freeze synthetic round-12 corpora; independent seeds and surrounding templates."""
import argparse
import json
import random
import string
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def corpus(seed, held):
    rng = random.Random(seed)
    rows = []
    wrappers = ['event detail <{}> end', 'field [{}]; status=ready', 'diagnostic ({}), retry queued'] if held else ['{}', 'debug {}', '{}\nnext line', 'failed ({}) retry', 'audit [{}]', 'response: {}\nfinished']
    def add(kind, group, text, secret=None):
        text = rng.choice(wrappers).format(text)
        spans = [] if secret is None else [{'start': text.index(secret), 'end': text.index(secret)+len(secret)}]
        rows.append(dict(id=f'{kind}-{group}-{len(rows)}', kind=kind, group=group, text=text, expected=spans))
    for i in range(120):
        value = ''.join(rng.choices(string.ascii_letters+string.digits, k=40))
        key = rng.choice(['password', 'api_key', 'apiKey', 'secret', 'TOKEN', 'passwd', 'authorization'])
        text = rng.choice([f'{key}={value}', f'"{key}":"{value}"', f'{key}: {value}'])
        add('credential', 'assignment', text, value)
        scheme = rng.choice(['postgres', 'mysql', 'mongodb+srv', 'redis', 'amqp'])
        add('credential', 'dsn', f'{scheme}://reader:{value}@db.example/orders', value)
        field = rng.choice(['X-Amz-Signature', 'sig', 'AccountKey', 'aws_secret_access_key', 'private_key', 'TWILIO_AUTH_TOKEN'])
        add('credential', 'cloud', f'{field}={value}', value)
        prefix = rng.choice(['sk-proj-', 'sk-svcacct-', 'sk-ant-api03-', 'sk_live_', 'rk_live_', 'whsec_', 'glpat-', 'npm_', 'pypi-', 'GOCSPX-'])
        token = prefix+value
        add('service_token', 'provider', token, token)
        add('high_entropy', 'unlabeled-secret', value, value)
        # Public IDs with identical distributions expose entropy's unavoidable trade-off.
        for kind in ['credential', 'service_token', 'high_entropy']:
            add(kind, 'public-random-id', f'object {value}')
            add(kind, 'labeled-id', f'request_id={value}')
            add(kind, 'uuid', '550e8400-e29b-41d4-a716-446655440000')
            sha = ''.join(rng.choices('0123456789abcdef', k=40))
            add(kind, 'commit-sha', 'commit '+sha)
            add(kind, 'url-hash', 'https://example.com/assets/'+sha+'.js')
            add(kind, 'ordinary', rng.choice(['request completed in twelve milliseconds', 'token_count=17', 'npm_package_name', 'passwordless=true']))
    return rows

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--check',action='store_true');args=parser.parse_args()
    for name,seed,held in [('development',120026,False),('held',120928,True)]:
        # Escape separators in stored synthetic credentials; JSON decoding preserves every byte.
        content=''.join(json.dumps(row,sort_keys=True)+'\n' for row in corpus(seed,held))
        content=content.replace('_', r'\u005f').replace('-', r'\u002d')
        path=ROOT/'tests'/'testdata'/f'credentials-{name}.jsonl'
        if args.check:
            if path.read_text()!=content:raise SystemExit(f'stale {path}')
        else:path.write_text(content)
if __name__=='__main__':main()
