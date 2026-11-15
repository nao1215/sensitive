"""Retry module transport failures, while leaving test failures visible."""
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch
import download_modules


class ModuleDownloadTests(unittest.TestCase):
    def test_transient_download_retries_then_succeeds(self):
        failure = subprocess.CalledProcessError(1,['go','mod','download'])
        with patch.object(download_modules.subprocess,'run',side_effect=[failure,None]) as run, patch.object(download_modules.time,'sleep'):
            download_modules.download(Path('.'))
        self.assertEqual(run.call_count,2)
        self.assertEqual(run.call_args.args[0],['go','mod','download'])

    def test_persistent_failure_is_not_swallowed(self):
        failure = subprocess.CalledProcessError(1,['go','mod','download'])
        with patch.object(download_modules.subprocess,'run',side_effect=failure) as run, patch.object(download_modules.time,'sleep'):
            with self.assertRaises(subprocess.CalledProcessError):
                download_modules.download(Path('.'))
        self.assertEqual(run.call_count,3)
