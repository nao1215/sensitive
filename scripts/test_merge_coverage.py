import tempfile
import unittest
from pathlib import Path
from merge_coverage import merge


class MergeCoverageTest(unittest.TestCase):
    def test_union_counts_each_source_block_once(self):
        with tempfile.TemporaryDirectory() as directory:
            a, b = Path(directory) / "a", Path(directory) / "b"
            a.write_text("mode: set\nx.go:1.1,2.1 3 0\nx.go:3.1,4.1 2 1\n")
            b.write_text("mode: set\nx.go:1.1,2.1 3 1\nx.go:3.1,4.1 2 1\n")
            self.assertEqual(merge([a, b]), "mode: set\nx.go:1.1,2.1 3 1\nx.go:3.1,4.1 2 1\n")
            b.write_text("mode: count\nx.go:1.1,2.1 3 1\n")
            with self.assertRaises(ValueError):
                merge([a, b])

    def test_package_scope_excludes_nested_modules_not_internal_code(self):
        with tempfile.TemporaryDirectory() as directory:
            profile = Path(directory)/'coverage.out'
            profile.write_text('mode: set\nexample/lib/scanner.go:1.1,2.1 2 1\nexample/lib/internal/parser.go:1.1,2.1 2 0\nexample/lib/tests/cmd/tool.go:1.1,2.1 100 0\n')
            self.assertEqual(merge([profile], packages={'example/lib','example/lib/internal'}), 'mode: set\nexample/lib/internal/parser.go:1.1,2.1 2 0\nexample/lib/scanner.go:1.1,2.1 2 1\n')


if __name__ == "__main__":
    unittest.main()
