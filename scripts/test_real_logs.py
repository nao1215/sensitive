"""Evidence checks must work without network access or the raw datasets."""
import hashlib
import pathlib
import tempfile
import unittest
from unittest.mock import patch
import real_logs
import scanner_experiment


class RealLogEvidenceTests(unittest.TestCase):
    def test_changed_cached_bytes_fail_without_download(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp)/'log'
            path.write_bytes(b'changed')
            with patch('urllib.request.urlopen', side_effect=AssertionError('network used')):
                with self.assertRaisesRegex(ValueError, 'cached checksum mismatch'):
                    real_logs.download('https://example.invalid/log', path, hashlib.sha256(b'original').hexdigest())

    def test_unknown_sample_is_not_assumed_safe(self):
        raw = [{'dataset':'test','samples':{'pan':[{'id':'missing'}]}}]
        with self.assertRaisesRegex(ValueError,'unreviewed samples'):
            real_logs.summarize(raw,{})

    def test_unclassified_sample_is_not_assumed_safe(self):
        raw = [{'dataset':'test','samples':{'pan':[{'id':'pending'}]}}]
        with self.assertRaisesRegex(ValueError,'invalid classification'):
            real_logs.summarize(raw,{'pending':{'classification':'pending'}})

    def test_estimate_weights_each_stratum_before_summing(self):
        rows = [{'dataset':'a','counts':{'all':{'pan':100}},'strata':{'pan':{'sample_fp':1,'sample_count':4}}},
                {'dataset':'b','counts':{'all':{'pan':20}},'strata':{'pan':{'sample_fp':3,'sample_count':4}}}]
        self.assertEqual(real_logs.estimate(rows, ['a','b'], 'all'), (120,40.0,8,4))
        self.assertEqual(real_logs.estimate(rows, ['a'], 'all'), (100,25.0,4,1))

    def test_benchmark_parser_rejects_missing_configuration(self):
        with self.assertRaisesRegex(ValueError,'ten samples'):
            scanner_experiment.medians('BenchmarkNarrowing/all/clean 100 40 ns/op\n'*10)


if __name__ == '__main__':
    unittest.main()
