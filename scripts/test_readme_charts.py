"""Charts require measured values, equal scenario scope and deterministic output."""
import copy
import os
import subprocess
import sys
import unittest
import xml.etree.ElementTree as ET

import readme_charts as charts


class ChartTests(unittest.TestCase):
    def test_chart_io_is_independent_of_locale(self):
        result = subprocess.run([sys.executable, str(charts.ROOT/'scripts/readme_charts.py'), '--check'], env=dict(os.environ, PYTHONUTF8='0', PYTHONCOERCECLOCALE='0', LC_ALL='C'), capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_time_uses_same_event_and_microseconds(self):
        source = {'benchmarks': {'BenchmarkComparison/flat/'+mode: {'ns/op': value} for mode, value in zip(('plain', 'embargo', 'masq', 'go-masker'), (1000, 2000, 3000, 4000))}, 'date': '2026-01-01', 'cpu': 'fixture', 'versions': {'masq': 'v1', 'go-masker': 'v2'}}
        svg = charts.event_chart(source)
        for label in ('1.00 µs', '2.00 µs', '3.00 µs', '4.00 µs', 'linear scale'):
            self.assertIn(label, svg)
        grids = [r for r in ET.fromstring(svg).findall('.//{http://www.w3.org/2000/svg}rect') if r.attrib.get('width') == '1.00']
        self.assertEqual(len(grids), 5)
        self.assertEqual({g.attrib['fill'] for g in grids}, {'#ccd2da'})
        self.assertTrue(all(float(g.attrib['x']).is_integer() for g in grids))
        source['benchmarks']['BenchmarkComparison/flat/plain']['ns/op'] = 0
        with self.assertRaises(ValueError):
            charts.event_chart(source)

    def test_all_libraries_run_the_same_cases(self):
        source = {'versions': {name: 'v1' for name in charts.LIBRARIES}, 'rows': [{'name': 'one', 'label': 'One case', 'positive': True, 'results': {name: {'removed': name == 'masq'} for name in charts.LIBRARIES}}]}
        svg = charts.scenario_chart(source)
        self.assertIn('1 / 1', svg)
        self.assertIn('0 / 1', svg)
        self.assertEqual(svg, charts.scenario_chart(copy.deepcopy(source)))
        del source['rows'][0]['results']['masq']
        with self.assertRaises(ValueError):
            charts.scenario_chart(source)
