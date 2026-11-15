"""README rows should explain distinct failures and navigate to their evidence."""
import json
from pathlib import Path
import re
import tempfile
import unittest
from unittest.mock import patch
import testing_techniques


class TechniqueTests(unittest.TestCase):
    def test_readme_links_each_bug_to_its_section(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/'scripts').mkdir()
            (root/'doc').mkdir()
            rows = json.loads((testing_techniques.ROOT/'scripts/testing_techniques.json').read_text())
            (root/'scripts/testing_techniques.json').write_text(json.dumps(rows))
            for name in ['README.md', 'doc/testing.md']:
                (root/name).write_text('<!-- techniques:start -->\n<!-- techniques:end -->\n')
            with patch.object(testing_techniques, 'ROOT', root):
                testing_techniques.generate()
            readme = (root/'README.md').read_text()
            detail = (root/'doc/testing.md').read_text()
            links = re.findall(r'\[([^]]+)\]\(doc/testing.md#([^)]+)\)', readme)
            self.assertEqual(len(links), len(rows))
            self.assertEqual(len({anchor for _, anchor in links}), len(rows))
            for (label, anchor), row in zip(links, rows):
                self.assertNotEqual(label, row['name'])
                self.assertIn(f'<a id="{anchor}"></a>', detail)
                self.assertIn(row['bug'], detail)
