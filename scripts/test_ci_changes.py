import unittest
from unittest.mock import patch
from ci_changes import classify, changes


class ChangesTest(unittest.TestCase):
    def test_docs_only(self):
        self.assertEqual(classify(["README.md", "doc/benchmarks.json", "doc/images/ogp.png", "LICENSE", ".all-contributorsrc", "nested/guide.md"]), {"code": False, "workflows": False})

    def test_code_mixed_unknown_and_renamed(self):
        for path in ["scanner.go", "tests/go.mod", "Makefile", ".golangci.yml", "scripts/tool.py", "testdata/accuracy.json", "unknown"]:
            with self.subTest(path=path):
                self.assertTrue(classify(["README.md", path])["code"])
        self.assertTrue(classify(["scanner.go", "doc/scanner.go"])["code"])

    def test_workflows(self):
        self.assertEqual(classify([".github/workflows/unit_test.yml"]), {"code": True, "workflows": True})

    def test_schedules_and_manual_runs_always_run(self):
        for name in ["schedule", "workflow_dispatch"]:
            self.assertEqual(changes(name, {}), {"code": True, "workflows": True})

    @patch("ci_changes.subprocess.check_output", return_value=b"README.md\0")
    def test_pull_request_uses_merge_base_and_push_uses_before(self, command):
        self.assertFalse(changes("pull_request", {"pull_request": {"base": {"sha": "base"}, "head": {"sha": "head"}}})["code"])
        self.assertIn("base...head", command.call_args.args[0])
        self.assertIn("--no-renames", command.call_args.args[0])
        self.assertFalse(changes("push", {"before": "before", "after": "after"})["code"])
        self.assertEqual(command.call_args.args[0][-3:], ["before", "after", "--"])

    def test_new_branch_runs_all(self):
        self.assertTrue(changes("push", {"before": "0" * 40, "after": "head"})["code"])


if __name__ == "__main__":
    unittest.main()
