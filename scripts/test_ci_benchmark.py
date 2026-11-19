import unittest
from pathlib import Path
import ci_benchmark
from ci_benchmark import default_gate


def samples(clean=100, dirty=200, count=10, json=300, slog=400):
    return ''.join(f'BenchmarkCIDefault/clean 100 {clean} ns/op 0 B/op 0 allocs/op\nBenchmarkCIDefault/dirty 100 {dirty} ns/op 128 B/op 1 allocs/op\n'
                   f'BenchmarkCIDefault/json-8 100 {json} ns/op 64 B/op 2 allocs/op\nBenchmarkCIDefault/slog 100 {slog} ns/op 0 B/op 0 allocs/op\n' for _ in range(count))


class DefaultGateTest(unittest.TestCase):
    def test_shared_fixture_can_compile_as_a_root_external_test(self):
        source = (Path(__file__).resolve().parents[1]/"tests/benchmarks/benchmark_test.go").read_bytes()
        converted = ci_benchmark.root_harness(source)
        self.assertTrue(converted.startswith(b"package embargo_test\n"))
        self.assertEqual(converted.split(b"\n", 1)[1], source.split(b"\n", 1)[1])
        with self.assertRaises(ValueError):
            ci_benchmark.root_harness(b"package unexpected\n")

    def test_twenty_percent_boundary_and_loss(self):
        self.assertTrue(default_gate(samples(), samples(120, 240))['passed'])
        self.assertFalse(default_gate(samples(), samples(121, 200))['passed'])
        self.assertFalse(default_gate(samples(), samples(100, 241))['passed'])

    def test_every_workload_is_gated(self):
        self.assertFalse(default_gate(samples(), samples(json=361))['passed'])
        self.assertFalse(default_gate(samples(), samples(slog=481))['passed'])
        with self.assertRaises(ValueError):
            default_gate(samples(), samples()+'BenchmarkCIDefault/unknown 100 1 ns/op\n')

    def test_median_not_single_outlier(self):
        noisy = samples(count=9)+samples(100000, 200000, count=1, json=900000, slog=900000)
        self.assertTrue(default_gate(samples(), noisy)['passed'])

    def test_missing_extra_and_invalid_samples_fail_closed(self):
        for text in [samples(count=9), samples(count=11), samples(0), samples(-1), samples('NaN'), samples('inf'), '']:
            with self.subTest(text=text[:80]):
                with self.assertRaises(ValueError):
                    default_gate(samples(), text)


if __name__ == '__main__':
    unittest.main()
