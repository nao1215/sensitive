"""An upstream generator must not silently relax the workflow SHA policy."""
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import lock_actions


class LockActionsTests(unittest.TestCase):
    def test_restore_sha_even_when_generator_fails(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workflows = root/'.github/workflows'; workflows.mkdir(parents=True)
            path = workflows/'test.yml'
            original = b'uses: actions/checkout@' + b'a'*40 + b'\n'
            path.write_bytes(original)
            def generate(*args, **kwargs):
                path.write_text('uses: actions/checkout@v7\n')
                raise subprocess.CalledProcessError(1, args[0])
            with patch.object(lock_actions, 'ROOT', root), patch.object(lock_actions.subprocess, 'run', side_effect=generate):
                with self.assertRaises(subprocess.CalledProcessError):
                    lock_actions.main()
            self.assertEqual(path.read_bytes(), original)


if __name__ == '__main__':
    unittest.main()
