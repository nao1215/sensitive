"""Ordinary skipped reviews do not satisfy the owner's merge exception."""
import unittest

import check_merge


class MergeTests(unittest.TestCase):
    def test_explicit_service_limit(self):
        for body in ["Review rate limit exceeded", "<!-- This is an auto-generated comment: rate limited by coderabbit.ai -->\nThis review could not start because sufficient usage credits or metered capacity are not available."]:
            self.assertTrue(check_merge.explicit_review_limit({'author': {'login': 'coderabbitai'}, 'body': body}))

    def test_skips_and_untrusted_authors_do_not_grant_exception(self):
        for body in ["Review skipped: fewer than 10 stars", "Review skipped: 137 files exceed the limit of 100.", "Review complete"]:
            self.assertFalse(check_merge.explicit_review_limit({'author': {'login': 'coderabbitai'}, 'body': body}))
        self.assertFalse(check_merge.explicit_review_limit({'author': {'login': 'another-coderabbit'}, 'body': 'Review rate limit exceeded'}))


if __name__ == '__main__':
    unittest.main()
