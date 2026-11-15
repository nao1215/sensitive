"""Compare complete logs only where git source lines and mutation sites match."""
import argparse
import collections
import difflib
import json
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
PATTERN = re.compile(r'^\s*(KILLED|LIVED|NOT COVERED|TIMED OUT) (\w+) at (.+):(\d+):(\d+)$', re.M)


def parse(path):
    text = path.read_text()
    if 'Mutation testing completed' not in text:
        raise ValueError('incomplete mutation log: '+str(path))
    rows = {}
    for status, kind, source, line, column in PATTERN.findall(text):
        key = (source, int(line), int(column), kind)
        if key in rows:
            raise ValueError('ambiguous duplicate mutation identity: '+str(key))
        rows[key] = status
    return rows


def source(commit, path):
    result = subprocess.run(['git', 'show', commit+':'+path], cwd=ROOT, capture_output=True, text=True)
    return result.stdout.splitlines() if result.returncode == 0 else []


def compare(before, after, base, head):
    mappings = {}
    for path in {row[0] for row in before}:
        old, new = source(base, path), source(head, path)
        mapping = {}
        for block in difflib.SequenceMatcher(a=old, b=new, autojunk=False).get_matching_blocks():
            for offset in range(block.size):
                mapping[block.a+offset+1] = block.b+offset+1
        mappings[path] = mapping
    matched, removed, seen = [], [], set()
    for (path, line, column, kind), status in before.items():
        mapped = mappings[path].get(line)
        key = (path, mapped, column, kind)
        if mapped is None or key not in after:
            removed.append({'path':path, 'line':line, 'column':column, 'kind':kind, 'status':status})
            continue
        seen.add(key)
        matched.append({'path':path, 'base_line':line, 'head_line':mapped, 'column':column, 'kind':kind, 'before':status, 'after':after[key]})
    added = [{'path':p, 'line':line, 'column':c, 'kind':k, 'status':v} for (p,line,c,k),v in after.items() if (p,line,c,k) not in seen]
    return {'base':base, 'head':head, 'matching_rule':'unchanged git source line, same column and mutator; no semantic-equivalence claim',
            'transitions':dict(collections.Counter(row['before']+' -> '+row['after'] for row in matched)),
            'changed_outcomes':[row for row in matched if row['before'] != row['after']], 'unmatched_before':removed, 'unmatched_after':added}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ['before','after','output']:
        parser.add_argument('--'+name, type=Path, required=True)
    for name in ['base','head']:
        parser.add_argument('--'+name, required=True)
    args = parser.parse_args()
    result = compare(parse(args.before), parse(args.after), args.base, args.head)
    args.output.write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps(result['transitions'], indent=2))


if __name__ == '__main__':
    main()
