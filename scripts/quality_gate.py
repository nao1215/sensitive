"""Enforce frozen accuracy and sampled real-log false-positive budgets."""
import argparse
from fractions import Fraction
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

import real_logs

ROOT = Path(__file__).resolve().parents[1]


def definitions():
    gates = json.loads((ROOT/'doc/quality-gates.json').read_text(encoding='utf-8'))
    kinds = set(re.findall(r'Kind\w+\s+Kind\s*=\s*"([^"]+)"', (ROOT/'finding.go').read_text()))
    expected = {(split, kind) for split in ('development', 'held') for kind in kinds}
    for metric in ('accuracy', 'false_positives'):
        rows = gates[metric]
        keys = [(row['set'], row['kind']) for row in rows]
        if len(set(keys)) != len(keys) or set(keys) != expected:
            raise ValueError(metric+': every built-in Kind needs one threshold per split')
        for row in rows:
            if metric == 'accuracy':
                if any(type(row[k]) is not int or row[k] < 0 for k in ('tp', 'fp', 'fn')) or row['tp'] == 0:
                    raise ValueError('invalid accuracy floor')
            elif type(row['numerator']) is not int or type(row['denominator']) is not int or row['numerator'] < 0 or row['denominator'] <= 0:
                raise ValueError('invalid false-positive ceiling')
    if gates['critical_residual_bytes'] != 0:
        raise ValueError('critical residual exposure must remain zero')
    if gates['speed'] != {'maximum_ratio': 1.2, 'samples': 10}:
        raise ValueError('speed policy requires ten samples and a 20% median budget')
    return gates


def false_positive_rates(rows, manifest):
    """Weight each labeled stratum before summing; retain exact rational rates."""
    if {r['dataset'] for r in rows} != {d['name'] for d in manifest['datasets']} or len(rows) != len(manifest['datasets']):
        raise ValueError('missing or duplicate measured dataset')
    rates = {}
    for split in ('development', 'held'):
        datasets = [d for d in manifest['datasets'] if d['split'] == split]
        names = {d['name'] for d in datasets}
        size = sum(d['bytes'] for d in datasets)
        if size <= 0:
            raise ValueError('empty split')
        for kind in manifest['kinds']:
            fp = Fraction(0)
            for row in rows:
                if row['dataset'] not in names:
                    continue
                count = row['counts']['all'].get(kind, 0)
                if count:
                    stratum = row['strata'][kind]
                    if not 0 <= stratum['sample_fp'] <= stratum['sample_count'] or stratum['sample_count'] <= 0:
                        raise ValueError('invalid sample counts')
                    fp += Fraction(count*stratum['sample_fp'], stratum['sample_count'])
            rates[(split, kind)] = fp*10**9/size
    return rates


def compare_rates(rates, ceilings):
    expected = {(row['set'], row['kind']): Fraction(row['numerator'], row['denominator']) for row in ceilings}
    if rates.keys() != expected.keys():
        raise ValueError('measured kinds and ceilings differ')
    return [f'{split}/{kind}: {float(rate):.6f} FP/GB exceeds {float(expected[(split,kind)]):.6f}'
            for (split, kind), rate in sorted(rates.items()) if rate > expected[(split, kind)]]


def measure_false_positives(cache, gates):
    manifest = real_logs.load('real-logs-manifest.json')
    labels = real_logs.load('real-logs-labels.json')['labels']
    cache = cache.resolve()
    real_logs.cache_datasets(cache, manifest)
    source = real_logs.source_hash()
    raw = []
    with tempfile.TemporaryDirectory(prefix='quality-', dir=cache) as directory:
        for split in ('development', 'held'):
            output = Path(directory)/(split+'.json')
            subprocess.run(['go', '-C', 'tests', 'run', './cmd/logscan', '--cache', str(cache), '--split', split, '--output', str(output)],
                           cwd=ROOT, env=dict(os.environ, GOMAXPROCS='4'), check=True)
            raw.extend(json.loads(output.read_text(encoding='utf-8')))
    if source != real_logs.source_hash():
        raise ValueError('source changed while measuring')
    rows = real_logs.summarize(raw, labels)
    rates = false_positive_rates(rows, manifest)
    failures = compare_rates(rates, gates['false_positives'])
    results = ROOT/'quality-results'
    results.mkdir(exist_ok=True)
    # Only aggregates leave the external cache; raw logs and sampled values do not.
    summary = {'source_sha256': source, 'failures': failures, 'rates': [dict(set=s, kind=k, numerator=v.numerator, denominator=v.denominator) for (s,k),v in sorted(rates.items())]}
    (results/'false-positives.json').write_text(json.dumps(summary, indent=2)+'\n')
    if failures:
        raise ValueError('\n'.join(failures))
    print('All per-Kind FP/GB ceilings passed on the pinned cached logs.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('metric', choices=['accuracy', 'false-positives'])
    parser.add_argument('--cache', type=Path, default=Path.home()/'.cache/embargo-real-logs')
    args = parser.parse_args()
    gates = definitions()
    if args.metric == 'accuracy':
        subprocess.run(['go', '-C', 'tests', 'test', '.', '-run', '^Test(QualityAccuracy|QualityFloorRejectsPrecisionAndRecallLoss|SeverityAccuracy)$', '-count=1', '-v'], cwd=ROOT, check=True)
    else:
        measure_false_positives(args.cache, gates)


if __name__ == '__main__':
    main()
