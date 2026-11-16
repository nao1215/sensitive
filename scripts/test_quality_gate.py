from fractions import Fraction
import copy
import unittest
from pathlib import Path
import re
from unittest.mock import patch

from quality_gate import compare_rates, definitions, false_positive_rates


class QualityGateTest(unittest.TestCase):
    def test_three_jobs_share_detector_filter(self):
        root = Path(__file__).resolve().parents[1]
        workflow = (root/'.github/workflows/verification.yml').read_text()
        jobs = dict(re.findall(r'^  (\w+):\n((?:    .*\n|\n)*)', workflow, re.M))
        for name, command in [('accuracy', 'scripts/quality_gate.py accuracy'), ('false_positives', 'scripts/quality_gate.py false-positives'), ('benchmark', 'scripts/ci_benchmark.py')]:
            self.assertIn("if: needs.changes.outputs.detectors == 'true'", jobs[name])
            self.assertIn(command, jobs[name])
        changes = (root/'.github/workflows/changes.yml').read_text()
        self.assertIn('value: ${{ jobs.changes.outputs.detectors }}', changes)
        self.assertIn('detectors: ${{ steps.filter.outputs.detectors }}', changes)
        self.assertIn('scripts/quality_docs.py --check', jobs['policies'])

    def test_exact_ceiling_not_rounded_display(self):
        ceiling = [{'set': 'held', 'kind': 'pan', 'numerator': 1, 'denominator': 3}]
        self.assertEqual(compare_rates({('held', 'pan'): Fraction(1, 3)}, ceiling), [])
        self.assertTrue(compare_rates({('held', 'pan'): Fraction(333334, 1000000)}, ceiling))
        with self.assertRaises(ValueError):
            compare_rates({}, ceiling)

    def test_stratum_weighting_and_split_bytes(self):
        manifest = {'kinds': ['pan'], 'datasets': [{'name': 'one', 'split': 'development', 'bytes': 1000000000}, {'name': 'two', 'split': 'development', 'bytes': 1000000000}, {'name': 'three', 'split': 'held', 'bytes': 1000000000}]}
        rows = [{'dataset': name, 'counts': {'all': {'pan': count}}, 'strata': {'pan': {'sample_fp': fp, 'sample_count': total}}} for name, count, fp, total in [('one', 100, 1, 2), ('two', 10, 0, 2), ('three', 10, 1, 5)]]
        self.assertEqual(false_positive_rates(rows, manifest), {('development', 'pan'): Fraction(25), ('held', 'pan'): Fraction(2)})
        with self.assertRaises(ValueError):
            false_positive_rates(rows[:-1], manifest)
        rows[0]['strata']['pan']['sample_count'] = 0
        with self.assertRaises(ValueError):
            false_positive_rates(rows, manifest)

    def test_new_kind_needs_explicit_thresholds(self):
        gates = definitions()
        with patch('quality_gate.json.loads', return_value={**gates, 'accuracy': gates['accuracy'][:-1]}):
            with self.assertRaisesRegex(ValueError, 'every built-in Kind'):
                definitions()
        duplicate = copy.deepcopy(gates)
        duplicate['false_positives'].append(duplicate['false_positives'][0])
        with patch('quality_gate.json.loads', return_value=duplicate):
            with self.assertRaises(ValueError):
                definitions()


if __name__ == '__main__':
    unittest.main()
