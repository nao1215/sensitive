"""Render two README charts from measured JSON; --check rejects missing or stale images."""
import argparse
import json
import math
from pathlib import Path

from doc_figures import SVG

ROOT = Path(__file__).resolve().parents[1]
LIBRARIES = ('embargo', 'masq', 'go-masker', 'slog-formatter', 'go-mask', 'godlp')
COLORS = ('#087f75', '#4169b1', '#9a4814', '#75539f', '#506878', '#a43658')


def event_chart(measurement):
    rows = measurement['benchmarks']
    modes = ('plain', 'embargo', 'masq', 'go-masker')
    values = [rows['BenchmarkComparison/flat/'+mode]['ns/op']/1000 for mode in modes]
    if any(not math.isfinite(v) or v <= 0 for v in values):
        raise ValueError('event timings must be finite positive measurements')
    maximum = math.ceil(max(values)/2)*2
    chart = SVG(1000, 365, 'Time per JSON slog event', 'Four labeled bars on the same linear microsecond axis. Lower is faster. Identical request message, email and card attributes; encoding and masking included.')
    chart.text(24, 34, 'Time per log event', 25)
    chart.text(24, 60, 'Same JSON slog event: request + email + card. Lower is faster.', 16)
    chart.text(24, 84, measurement['date']+' · '+measurement['cpu']+' · one CPU thread', 12)
    left, width = 240, 650
    for step in range(5):
        value = maximum*step/4
        x = left+width*step/4
        chart.line(x, 105, x, 279)
        chart.text(round(x, 2), 302, f'{value:g}', 13, anchor='middle')
    labels = ('slog alone', 'slog + embargo', 'slog + masq '+measurement['versions']['masq'], 'slog + go-masker '+measurement['versions']['go-masker'])
    for i, (label, value) in enumerate(zip(labels, values)):
        y = 113+i*42
        chart.text(24, y+21, label, 15)
        chart.bar(left, y, width*value/maximum, 28, ('#617281', *COLORS[:3])[i])
        chart.text(round(left+width*value/maximum+10, 2), y+21, f'{value:.2f} µs', 14)
    chart.text(left+width/2, 328, 'Time per event (microseconds; linear scale)', 15, anchor='middle')
    chart.text(24, 352, 'Median of ten 200 ms samples; JSON to io.Discard; setup excluded. Policies and raw samples: doc/comparison.md.', 12)
    return chart.render()


def scenario_chart(measurement):
    rows = measurement['rows']
    positives = [row for row in rows if row['positive']]
    if not positives or len({row['name'] for row in rows}) != len(rows):
        raise ValueError('scenarios must be nonempty and uniquely named')
    for row in rows:
        if set(row['results']) != set(LIBRARIES):
            raise ValueError('every library must run every scenario')
    total = len(positives)
    chart = SVG(1120, 880, 'Scenario catch rate and every observed result', 'Bars count the original planted values removed from identical positive scenarios. The matrix also shows two clean controls, ties, tag-only wins and the US phone case.')
    chart.text(24, 34, 'Scenario catch rate', 25)
    chart.text(24, 60, f'Same {total} positive scenarios for every library; matrix shows all results and clean controls.', 16)
    for i, library in enumerate(LIBRARIES):
        count = sum(row['results'][library]['removed'] for row in positives)
        label = library if library == 'embargo' else library+' '+measurement['versions'][library]
        y = 84+i*32
        chart.text(24, y+17, label, 14)
        chart.bar(245, y, 600*count/total, 23, COLORS[i])
        chart.text(round(257+600*count/total, 2), y+17, f'{count} / {total}', 14)
    chart.line(245, 278, 845, 278)
    for count in range(0, total+1, 2):
        x = 245+600*count/total
        chart.text(round(x, 2), 299, count, 12, anchor='middle')
    chart.text(545, 323, 'Scenarios with the planted value removed (count; higher is better)', 14, anchor='middle')
    left, cell = 300, 130
    chart.text(24, 356, 'Positive scenario', 14)
    for i, library in enumerate(LIBRARIES):
        chart.text(left+i*cell+cell/2, 356, library, 13, anchor='middle')
    for index, row in enumerate(rows):
        y = 371+index*27
        if not row['positive'] and (index == 0 or rows[index-1]['positive']):
            chart.line(24, y-5, 1090, y-5, '#526472')
        chart.text(24, y+17, row['label'], 14)
        for i, library in enumerate(LIBRARIES):
            removed = row['results'][library]['removed']
            good = removed if row['positive'] else not removed
            label = ('masked' if removed else 'visible') if row['positive'] else ('changed' if removed else 'kept')
            chart.bar(left+i*cell+2, y, cell-5, 23, '#d7eee8' if good else '#f0e5de')
            chart.text(left+i*cell+cell/2, y+16, label, 12, '#173d35' if good else '#62351c', 'middle')
    chart.text(24, 788, 'Masked means the original planted value disappeared; partial masks count. Kept is correct for the two controls.', 14)
    chart.text(24, 813, 'embargo: default kinds, confidence 0.7. go-masker: default policy, Luhn cards enabled, fixed tag rule.', 13)
    chart.text(24, 837, 'masq: regex, name and tag rules. go-mask: field/tag rules. slog-formatter: PII fields. godlp: six built-in rules.', 13)
    chart.text(24, 861, 'This measures these configurations, not production accuracy. Full synthetic outputs: doc/comparison-scenarios.json.', 13)
    return chart.render()


def generate(check=False):
    for name, render, source in [('log-event-time', event_chart, 'comparison.json'), ('scenario-catch', scenario_chart, 'comparison-scenarios.json')]:
        expected = render(json.loads((ROOT/'doc'/source).read_text(encoding="utf-8")))
        path = ROOT/'doc/images'/f'{name}.svg'
        if check:
            if not path.exists() or path.read_text(encoding="utf-8") != expected:
                raise ValueError('missing or stale README chart: '+name)
        else:
            path.write_text(expected, encoding="utf-8")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    generate(parser.parse_args().check)
