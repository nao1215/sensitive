import tempfile
import unittest
from pathlib import Path

import benchmark_intervals


class BenchmarkIntervalsTest(unittest.TestCase):
    def test_constant_ratio_has_exact_interval(self):
        actual = benchmark_intervals.intervals({'x': [10] * 10}, {'x': [20] * 10})
        self.assertIn('| x | +100.00% | [+100.00%, +100.00%] |', actual)

    def test_missing_or_short_pairs_are_rejected(self):
        for before, after in [({}, {}), ({'x': [1] * 10}, {'y': [1] * 10}),
                              ({'x': [1] * 9}, {'x': [1] * 9}),
                              ({'x': [1] * 10}, {'x': [1] * 11})]:
            with self.assertRaises(ValueError):
                benchmark_intervals.intervals(before, after)

    def test_parser_handles_processor_suffix_and_ignores_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'bench.txt'
            path.write_text('goos: linux\nBenchmarkPublishedScanner/all/clean-4 100 12.5 ns/op 0 B/op\n')
            self.assertEqual(benchmark_intervals.samples(path), {'BenchmarkPublishedScanner/all/clean': [12.5]})
