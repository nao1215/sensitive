"""Policy failures are exercised without editing the active checkout."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import check_policies as policies
import fuzz_targets


class PolicyTests(unittest.TestCase):
    def test_test_file_budget_rejects_extra_files(self):
        for extra in ('scan_contract_test.go', 'scan_linux_test.go',
                      'adapters/logger/snapshot_test.go', 'tests/accuracy_extra_test.go',
                      'tests/cmd/tool/scores_test.go'):
            with self.subTest(extra=extra):
                files = ['scan.go', 'scan_test.go', 'adapters/logger/adapter.go',
                         'tests/doc.go', 'tests/cmd/tool/main.go', extra]
                with self.assertRaisesRegex(ValueError, 'test file budget'):
                    policies.test_file_budget(files)

    def test_test_file_budget_accepts_source_files_and_subjects(self):
        policies.test_file_budget(['scan.go', 'scan_test.go', 'doc.go', 'doc_test.go',
                                  'example_test.go', 'fuzz_test.go', 'benchmark_test.go',
                                  'adapters/logger/adapter.go', 'adapters/logger/adapter_test.go',
                                  'tests/doc.go', 'tests/accuracy_test.go', 'tests/quality_gates_test.go',
                                  'tests/contracts/policy_test.go', 'tests/cmd/tool/main.go',
                                  'tests/cmd/tool/main_test.go'])

    def test_root_dependencies(self):
        for manifest in ({'Require':[{'Path':'example.com/runtime'}]}, {'Tool':['example.com/tool']}):
            with patch.object(policies.subprocess, 'check_output', return_value=json.dumps(manifest)):
                with self.assertRaises(ValueError):
                    policies.root_module()

    def test_missing_technique(self):
        row = dict(name='fake', bug='real bug', ci='verification:policies', paths=['does-not-exist.go'])
        with patch.object(policies, 'read', return_value=json.dumps([row])):
            with self.assertRaisesRegex(ValueError, 'path missing'):
                policies.linked_tests()

    def test_rule_without_check(self):
        row = dict(rule='Owner rule', source='CLAUDE', check='missing.py#test', where='Verification')
        real_read = policies.read
        def read(path):
            return json.dumps([row]) if path == 'scripts/policies.json' else real_read(path)
        with patch.object(policies, 'read', side_effect=read):
            with self.assertRaises((ValueError, FileNotFoundError)):
                policies.mapping()

    def test_fuzz_discovery_excludes_nested_modules(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/'x_test.go').write_text('func FuzzRoot(f *testing.F) {}\n')
            nested = root/'nested'; nested.mkdir()
            (nested/'go.mod').write_text('module example.com/nested\n')
            (nested/'x_test.go').write_text('func FuzzNested(f *testing.F) {}\n')
            self.assertEqual(fuzz_targets.targets(root), [{'pkg':'.', 'name':'FuzzRoot'}])

    def test_detector_documentation_commands_cannot_disappear(self):
        commands = ['go -C tests run ./cmd/detectordocs --check',
                    'go -C tests test ./cmd/detectordocs -count=1']
        for retained in commands:
            with self.subTest(retained=retained):
                with patch.object(policies, 'read', return_value=retained):
                    with self.assertRaisesRegex(ValueError, 'detector documentation check missing'):
                        policies.detector_docs()
        policies.detector_docs()

    def test_widened_permissions_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            workflows = root/'.github/workflows'; workflows.mkdir(parents=True)
            (workflows/'verification.yml').write_text('permissions:\n  contents: write\n')
            with patch.object(policies, 'ROOT', root):
                with self.assertRaisesRegex(ValueError, 'unexpected write permissions'):
                    policies.workflows()


if __name__ == '__main__':
    unittest.main()
