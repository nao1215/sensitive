"""Every SDK module must reach the repository's existing CI gates."""
from pathlib import Path
import re
import unittest

ROOT=Path(__file__).resolve().parents[1]


class HookPolicyTests(unittest.TestCase):
    def test_sdk_modules_keep_unit_lint_security_and_dependency_checks(self):
        modules={p.parent.name for p in (ROOT/'adapters').glob('*/go.mod')}
        for workflow in ('unit_test.yml','golangci-lint.yml'):
            text=(ROOT/'.github/workflows'/workflow).read_text()
            loops=re.findall(r'for module in ([^;]+); do',text)
            self.assertTrue(loops,workflow)
            for loop in loops:self.assertLessEqual(modules,set(loop.split()),workflow)
        for workflow in ('gosec.yml','govulncheck.yml'):
            text=(ROOT/'.github/workflows'/workflow).read_text()
            for module in modules:self.assertIn('adapters/'+module,text,workflow)
        dependency=(ROOT/'scripts/check_adapter_dependencies.py').read_text()
        for module in modules:self.assertIn('"'+module+'"',dependency)

    def test_hook_scaling_is_scheduled_for_each_new_module(self):
        text=(ROOT/'.github/workflows/heavy.yml').read_text()
        self.assertIn('BenchmarkHookScaling',text)
        self.assertIn('grpc otel sentry',text)
        for module in ('grpc','otel','sentry'):
            source='\n'.join(path.read_text() for path in (ROOT/'adapters'/module).glob('*_test.go'))
            self.assertIn('TestHookAllocationBudget',source)
            self.assertIn('BenchmarkHookScaling',source)

    def test_mutation_target_limits_workers_and_test_cpus(self):
        makefile=(ROOT/'Makefile').read_text(encoding='utf-8')
        command=re.search(r'^mutation:.*?\n\t([^\n]+)',makefile,re.M).group(1)
        self.assertIn('--workers $(MUTATION_WORKERS)',command)
        self.assertIn('--test-cpu 2',command)
        workers=re.search(r'^MUTATION_WORKERS \?= (.+)$',makefile,re.M).group(1)
        self.assertIn('min(8, max(1, os.cpu_count()//2))',workers)
