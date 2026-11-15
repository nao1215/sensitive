"""Generate the technique inventory without changing surrounding README prose."""
import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def generate(check=False):
    rows = json.loads((ROOT/'scripts/testing_techniques.json').read_text())
    for filename in ['doc/testing.md', 'README.md']:
        path = ROOT/filename
        detailed = filename.startswith('doc/')
        prefix = '../' if detailed else ''
        table = '| Technique | Bug class caught here | Tests | CI |\n|---|---|---|---|\n' if detailed else '| Technique | Tests |\n|---|---|\n'
        for row in rows:
            links = ', '.join(f'[{Path(p).stem}]({prefix}{p})' for p in row['paths'])
            table += f"| {row['name']} | {row['bug']} | {links} | {row['ci']} |\n" if detailed else f"| {row['name']} | [{row['name']}](doc/testing.md) |\n"
        text = path.read_text()
        start, end = '<!-- techniques:start -->', '<!-- techniques:end -->'
        expected = text.split(start)[0]+start+'\n'+table+end+text.split(end)[1]
        if check:
            if text != expected: raise ValueError(filename+' technique inventory is stale')
        else: path.write_text(expected)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    generate(parser.parse_args().check)
