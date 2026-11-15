"""A cached evaluator must not hide an incompatible npm update."""
from pathlib import Path
from unittest.mock import patch
import sys
import tempfile
import unittest
import install_quint_evaluator as evaluator


class EvaluatorTests(unittest.TestCase):
    def test_changed_expected_version_fails_before_cached_install(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            manager = home/'binaryManager.js'
            manager.write_text("const QUINT_EVALUATOR_VERSION = 'v999.0.0';")
            target = home/('rust-evaluator-'+evaluator.VERSION)
            target.mkdir()
            (target/'quint_evaluator').write_text('stale binary')
            with self.assertRaisesRegex(ValueError, 'update VERSION and DIGEST'):
                evaluator.check_version(manager)
            with patch.object(evaluator.check_version, "__defaults__", (manager,)), \
                    patch.object(sys, "argv", ["install_quint_evaluator.py", directory]), \
                    patch.object(evaluator, "install") as install, \
                    self.assertRaisesRegex(ValueError, "update VERSION and DIGEST"):
                evaluator.main()
            install.assert_not_called()

    def test_pinned_version_is_accepted(self):
        with tempfile.TemporaryDirectory() as directory:
            manager = Path(directory)/'binaryManager.js'
            manager.write_text("const QUINT_EVALUATOR_VERSION = '"+evaluator.VERSION+"';")
            evaluator.check_version(manager)

    def test_installer_check_is_required_after_npm_ci(self):
        # Resolve from the installed script, not from node_modules being present.
        workflow = Path(evaluator.__file__).resolve().parents[1]/'.github/workflows/verification.yml'
        text = workflow.read_text()
        self.assertLess(text.index('npm ci --prefix tests/models'),text.index('python3 scripts/install_quint_evaluator.py'))
        self.assertLess(text.index('python3 scripts/install_quint_evaluator.py'),text.index('python3 scripts/quint_models.py'))
