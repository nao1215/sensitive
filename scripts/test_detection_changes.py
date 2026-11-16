"""Changed findings cannot be blessed by an empty heading or an older release note."""
import unittest

from detection_changes import check_change, has_detection_entry


class DetectionChangesTests(unittest.TestCase):
    def test_change_requires_unreleased_entry(self):
        for text in ('', '## [Unreleased]\n### Detection changes\n', '## [Unreleased]\n## [0.1.0]\n### Detection changes\n- Old change.\n', '## [Unreleased]\n### Detection changes\n### Fixed\n- Unrelated change.\n'):
            with self.assertRaises(ValueError):
                check_change({'old': 1}, {'new': 2}, text)
        text = '## [Unreleased]\n### Detection changes\n- Normalize Unicode separators.\n'
        self.assertTrue(has_detection_entry(text))
        check_change({}, {'new': 1}, text)
        check_change({}, {}, '')
