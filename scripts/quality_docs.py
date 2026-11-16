"""Render the frozen quality thresholds without refreshing them from new results."""
import argparse
from fractions import Fraction
from pathlib import Path

from quality_gate import definitions

ROOT = Path(__file__).resolve().parents[1]
START = '<!-- quality-gates:start -->'
END = '<!-- quality-gates:end -->'


def render():
    gates = definitions()
    accuracy = {(r['set'], r['kind']): r for r in gates['accuracy']}
    fp = {(r['set'], r['kind']): Fraction(r['numerator'], r['denominator']) for r in gates['false_positives']}
    lines = ['| Kind | Development P / R floor (%) | Held P / R floor (%) | Development FP/GB ceiling | Held FP/GB ceiling |', '|---|---:|---:|---:|---:|']
    for kind in sorted({k for _, k in accuracy}):
        cells = [kind]
        for split in ('development', 'held'):
            r = accuracy[(split, kind)]
            cells.append(f"{100*r['tp']/(r['tp']+r['fp']):.2f} / {100*r['tp']/(r['tp']+r['fn']):.2f}")
        cells.extend(f'{float(fp[(split, kind)]):.6f}' for split in ('development', 'held'))
        lines.append('| '+' | '.join(cells)+' |')
    return '\n'.join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    path = ROOT/'doc/ci.md'
    text = path.read_text(encoding='utf-8')
    before, rest = text.split(START, 1)
    _, after = rest.split(END, 1)
    expected = before+START+'\n'+render()+'\n'+END+after
    if args.check:
        if expected != text:
            raise SystemExit('stale quality table: run python3 scripts/quality_docs.py')
    else:
        path.write_text(expected, encoding='utf-8')


if __name__ == '__main__':
    main()
