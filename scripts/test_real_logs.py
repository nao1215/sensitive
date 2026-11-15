"""Evidence checks must work without network access or the raw datasets."""
import hashlib
import pathlib
import tempfile
import unittest
from unittest.mock import patch
import real_logs
import scanner_experiment


class RealLogEvidenceTests(unittest.TestCase):
    def test_measure_passes_absolute_cache_to_go(self):
        with patch.object(real_logs, 'cache_datasets'), patch.object(real_logs.subprocess, 'run', side_effect=RuntimeError('stop')) as run:
            with self.assertRaisesRegex(RuntimeError, 'stop'):
                real_logs.measure(pathlib.Path('../log-cache'), {}, {})
            argv = run.call_args.args[0]
            self.assertTrue(pathlib.Path(argv[argv.index('--cache')+1]).is_absolute())
            self.assertTrue(pathlib.Path(argv[argv.index('--output')+1]).is_absolute())

    def test_measure_rejects_source_changes_without_publishing(self):
        with tempfile.TemporaryDirectory() as tmp:
            cache = pathlib.Path(tmp)
            for split in ('development', 'held'):
                (cache/('measured-'+split+'.json')).write_text('[]', encoding='utf-8')
            with patch.object(real_logs, 'cache_datasets'), patch.object(real_logs.subprocess, 'run'), patch.object(real_logs, 'source_hash', side_effect=['before', 'after']), patch.object(pathlib.Path, 'write_text') as write:
                with self.assertRaisesRegex(ValueError, 'source changed during measurement'):
                    real_logs.measure(cache, {}, {})
                write.assert_not_called()

    def test_offline_check_rejects_unclassified_sample(self):
        row = {'strata': {'email': {'sample_ids': ['pending'], 'sample_count': 1, 'sample_fp': 0}}}
        with self.assertRaisesRegex(ValueError, 'invalid classification'):
            real_logs.validate_strata([row], {'pending': {'classification': 'unclassified'}})

    def test_unset_benchmark_baseline_does_not_measure(self):
        with patch('sys.argv', ['scanner_experiment.py', '--measure', '--base', '']), patch.object(scanner_experiment, 'measure') as measure:
            with self.assertRaises(SystemExit):
                scanner_experiment.main()
            measure.assert_not_called()

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

    def test_narrowing_check_uses_utf8_on_windows(self):
        original = pathlib.Path.read_text
        def legacy_read(path, encoding=None, **kwargs):
            return original(path, encoding=encoding or 'cp1252', **kwargs)
        with patch.object(pathlib.Path, 'read_text', legacy_read):
            scanner_experiment.render(check=True)

    def test_benchmark_parser_rejects_missing_configuration(self):
        with self.assertRaisesRegex(ValueError,'ten samples'):
            scanner_experiment.medians('BenchmarkNarrowing/all/clean 100 40 ns/op\n'*10)


if __name__ == '__main__':
    unittest.main()
