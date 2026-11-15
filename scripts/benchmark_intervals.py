#!/usr/bin/env python3
"""Report paired bootstrap intervals from alternating base/head benchmark runs."""
import argparse
import random
import re
import statistics
from pathlib import Path


def samples(path):
    rows = {}
    for line in path.read_text().splitlines():
        match = re.match(r'(Benchmark\S+?)(?:-\d+)?\s+\d+\s+([\d.]+)\s+ns/op', line)
        if match:
            rows.setdefault(match[1], []).append(float(match[2]))
    return rows


def intervals(before, after):
    if before.keys() != after.keys() or not before:
        raise ValueError('base and head must contain the same benchmark names')
    rng = random.Random(20261115)
    out = ['| Benchmark | Time delta | Paired bootstrap 95% interval |', '|---|---:|---:|']
    for name in sorted(before):
        base, head = before[name], after[name]
        if len(base) != len(head) or len(base) < 10 or min(base + head) <= 0:
            raise ValueError('at least ten positive paired samples are required')
        changes = []
        for _ in range(20000):
            indices = [rng.randrange(len(base)) for _ in base]
            changes.append(100 * (statistics.median(head[i] for i in indices) / statistics.median(base[i] for i in indices) - 1))
        changes.sort()
        delta = 100 * (statistics.median(head) / statistics.median(base) - 1)
        lo, hi = changes[499], changes[19499]
        out.append(f'| {name.removeprefix("BenchmarkPublished")} | {delta:+.2f}% | [{lo:+.2f}%, {hi:+.2f}%] |')
    return '\n'.join(out)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('before', type=Path)
    parser.add_argument('after', type=Path)
    args = parser.parse_args()
    print(intervals(samples(args.before), samples(args.after)))
