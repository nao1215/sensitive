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


if __name__ == "__main__":
    unittest.main()
