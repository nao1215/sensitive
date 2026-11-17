"""Mutation infrastructure and package floors must fail closed."""
import subprocess
import sys
import unittest
import json
from pathlib import Path
import tempfile
from unittest.mock import patch
import mutation_gate as gate


class MutationGateTests(unittest.TestCase):
    def test_project_publication_excludes_calibration_and_requires_completion(self):
        control = 'Mutation testing completed\nKilled: 2, Lived: 1, Not covered: 0\nTimed out: 0, Not viable: 0, Skipped: 0\nTest efficacy: 66.67%\nMutator coverage: 100.00%\n'
        self.assertEqual(gate.measurement_from_log(control)['mutation']['killed'], 2)
        log = 'EMBARGO_MUTATION_START\n'+control
        with self.assertRaises(ValueError):
            gate.measurement_from_log(log)
        summary = 'EMBARGO_MUTATION_SUMMARY '+json.dumps({'packages': {'a': {'counts': {'KILLED': 9, 'LIVED': 1, 'TIMED OUT': 1, 'NOT COVERED': 1}}, 'b': {'counts': {'KILLED': 10}}}})+'\n'
        measured = gate.measurement_from_log(log+summary)
        self.assertEqual(measured['mutation']['killed'], 19)
        self.assertEqual(measured['mutation']['timed_out'], 1)
        self.assertEqual(measured['efficacy'], 95)
        with self.assertRaises(ValueError):
            gate.measurement_from_log(log+summary+summary)

    def test_every_root_package_is_mutated_in_its_own_run(self):
        listed = subprocess.check_output(['go', 'list', '-f', '{{.Dir}}', './...'], cwd=gate.ROOT, text=True).split()
        listed = {Path(path).relative_to(gate.ROOT).as_posix() for path in listed} - {'.', 'cmd/embargo'}
        self.assertEqual(set(gate.PACKAGES), listed)

    def test_memory_cap_applies_to_child_processes(self):
        script = 'import resource; print(resource.getrlimit(resource.RLIMIT_AS)[0])'
        out = subprocess.check_output([sys.executable, '-c', script], preexec_fn=gate.limit_memory, text=True)
        self.assertEqual(int(out), gate.ADDRESS_SPACE)

    def test_timeout_is_not_a_kill(self):
        report = {'files': [{'file_name': 'embargotest/run.go', 'mutations': [{'status': value} for value in ['KILLED', 'LIVED', 'TIMED OUT', 'NOT COVERED', 'NOT VIABLE']]}]}
        got = gate.package_scores(report)['embargotest']
        self.assertEqual(got['score'], 33.33)
        self.assertEqual(got['coverage'], 75)
        self.assertEqual(gate.package_scores(report, 'command')['command'], got)

    def test_each_package_and_metric_must_remain_above_baseline(self):
        baseline = {'a': {'score': 90, 'coverage': 95}, 'b': {'score': 60, 'coverage': 80}}
        gate.check(baseline, baseline)
        for actual in ({'a': baseline['a']}, dict(baseline, a={'score': 89, 'coverage': 100}), dict(baseline, b={'score': 100, 'coverage': 79})):
            with self.assertRaises(ValueError):
                gate.check(actual, baseline)

    def test_missing_or_unexecuted_results_cannot_pass(self):
        for report in ({'files': []}, {'files': [{'file_name': 'a.go', 'mutations': [{'status': 'NOT COVERED'}]}]}, {'files': [{'file_name': 'a.go', 'mutations': [{'status': 'RUNNING'}]}]}, {'files': [{'file_name': '../a.go', 'mutations': []}]}):
            with self.assertRaises(ValueError):
                gate.package_scores(report)

    def test_truncated_and_duplicate_mutation_inventories_are_rejected(self):
        mutant = {'type': 'CONDITIONALS_BOUNDARY', 'line': 2, 'column': 10, 'status': 'KILLED'}
        report = {'files': [{'file_name': 'a.go', 'mutations': [mutant]}]}
        gate.validate_inventory(report, report)
        for changed in ({'files': []}, {'files': [{'file_name': 'a.go', 'mutations': []}]}, {'files': report['files']*2}, {'files': [{'file_name': 'a.go', 'mutations': [dict(mutant, line=3)]}]}):
            with self.assertRaises(ValueError):
                gate.validate_inventory(changed, report)

    def test_recorded_scores_cannot_diverge_from_expression_results(self):
        evidence = {'tool': gate.TOOL, 'files': [{'file_name': 'a.go', 'mutations': [{'type': 'CONDITIONALS_BOUNDARY', 'line': 2, 'column': 10, 'status': 'KILLED'}]}], 'source_sha256': {'a.go': 'a'*64}}
        baseline = {'packages': gate.package_scores(evidence)}
        with tempfile.TemporaryDirectory() as directory:
            baseline_path, evidence_path = Path(directory)/'baseline.json', Path(directory)/'evidence.json'
            baseline_path.write_text(json.dumps(baseline), encoding='utf-8')
            evidence_path.write_text(json.dumps(evidence), encoding='utf-8')
            document_path = Path(directory)/'testing.md'
            document_path.write_text('<!-- mutation-baseline:start -->\n'+gate.mutation_table(baseline['packages'])+'<!-- mutation-baseline:end -->\n', encoding='utf-8')
            with patch.object(gate, 'BASELINE', baseline_path), patch.object(gate, 'EVIDENCE', evidence_path), patch.object(gate, 'DOCUMENT', document_path):
                gate.check_recorded_evidence()
                evidence['files'][0]['mutations'][0]['status'] = 'LIVED'
                evidence_path.write_text(json.dumps(evidence), encoding='utf-8')
                with self.assertRaises(ValueError):
                    gate.check_recorded_evidence()

    def test_document_baseline_rejects_missing_and_stale_rows(self):
        packages = {'a': {'score': 80, 'coverage': 90, 'counts': {'KILLED': 4, 'LIVED': 1}}}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'testing.md'
            with patch.object(gate, 'DOCUMENT', path):
                for text in ('', '<!-- mutation-baseline:start -->\n<!-- mutation-baseline:end -->\n'):
                    path.write_text(text, encoding='utf-8')
                    with self.assertRaises(ValueError):
                        gate.document_baseline(packages)
                gate.document_baseline(packages, write=True)
                gate.document_baseline(packages)

    def test_mutate_source_replaces_the_operator_gremlins_named(self):
        source = b'package p\nfunc f(a, b int) bool {\n\tfor i := 0; i < a; i++ {\n\t}\n\treturn a <= b && a-b != 0\n}\n'
        cases = [
            ({'type': 'CONDITIONALS_BOUNDARY', 'line': 3, 'column': 16}, b'i <= a'),
            ({'type': 'CONDITIONALS_NEGATION', 'line': 3, 'column': 16}, b'i >= a'),
            ({'type': 'INCREMENT_DECREMENT', 'line': 3, 'column': 22}, b'i--'),
            ({'type': 'CONDITIONALS_BOUNDARY', 'line': 5, 'column': 11}, b'a < b'),
            ({'type': 'ARITHMETIC_BASE', 'line': 5, 'column': 20}, b'a+b'),
            ({'type': 'INVERT_NEGATIVES', 'line': 5, 'column': 20}, b'a+b'),
            ({'type': 'CONDITIONALS_NEGATION', 'line': 5, 'column': 23}, b'== 0'),
        ]
        for mutant, fragment in cases:
            mutated = gate.mutate_source(source, mutant)
            self.assertIn(fragment, mutated, mutant)
            self.assertEqual(len(mutated.split(b'\n')), len(source.split(b'\n')))
        for mutant in ({'type': 'CONDITIONALS_BOUNDARY', 'line': 5, 'column': 20}, {'type': 'ARITHMETIC_BASE', 'line': 5, 'column': 11}, {'type': 'INVERT_LOGICAL', 'line': 5, 'column': 16}, {'type': 'ARITHMETIC_BASE', 'line': 9, 'column': 1}, {'type': 'ARITHMETIC_BASE', 'line': 1, 'column': 40}):
            with self.assertRaises(ValueError):
                gate.mutate_source(source, mutant)

    def test_timed_out_mutants_are_rerun_alone_and_keep_persistent_timeouts(self):
        with tempfile.TemporaryDirectory() as directory:
            module = Path(directory)
            (module/'go.mod').write_text('module rerun\n\ngo 1.26.11\n')
            (module/'loop.go').write_text('package rerun\n\nfunc Count(n int) int {\n\ttotal := 0\n\tfor i := 0; i < n; i++ {\n\t\ttotal += i\n\t}\n\treturn total\n}\n')
            (module/'loop_test.go').write_text('package rerun\n\nimport "testing"\n\nfunc TestCount(t *testing.T) {\n\tif Count(4) != 6 {\n\t\tt.Fatal("count")\n\t}\n}\n')
            mutants = [{'type': 'INCREMENT_DECREMENT', 'line': 5, 'column': 22, 'status': 'TIMED OUT'}, {'type': 'CONDITIONALS_BOUNDARY', 'line': 5, 'column': 16, 'status': 'TIMED_OUT'}, {'type': 'ARITHMETIC_BASE', 'line': 5, 'column': 16, 'status': 'KILLED'}]
            report = {'files': [{'file_name': 'loop.go', 'mutations': mutants}]}
            env = dict(gate.os.environ, GOWORK='off', GOFLAGS='-mod=mod')
            with patch.object(gate, 'MINIMUM_RERUN_TIMEOUT', 2.0):
                gate.rerun_timed_out(report, module, '.', 2, env, module/'scratch')
            self.assertEqual([m['status'] for m in mutants], ['TIMED OUT', 'KILLED', 'KILLED'])
            self.assertIn('rerun_timeout_seconds', mutants[0])
            self.assertNotIn('rerun_timeout_seconds', mutants[2])
            self.assertEqual((module/'loop.go').read_text().count('i++'), 1)
