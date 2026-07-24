from __future__ import annotations

import unittest

from httpdiff.analyzers.json_body import diff_json
from httpdiff.models import ChangeType


class TestJsonDiff(unittest.TestCase):
    def test_key_added(self):
        diffs = diff_json({"a": 1}, {"a": 1, "b": 2})
        self.assertEqual(len(diffs), 1)
        self.assertEqual(diffs[0].change_type, ChangeType.ADDED)
        self.assertEqual(diffs[0].path, "$.b")

    def test_key_removed(self):
        diffs = diff_json({"a": 1, "b": 2}, {"a": 1})
        self.assertEqual(diffs[0].change_type, ChangeType.REMOVED)

    def test_value_changed(self):
        diffs = diff_json({"role": "user"}, {"role": "admin"})
        self.assertEqual(diffs[0].path, "$.role")
        self.assertTrue(diffs[0].security_relevant)

    def test_type_changed(self):
        diffs = diff_json({"count": 1}, {"count": "1"})
        self.assertIn("type changed", diffs[0].description)

    def test_array_changed(self):
        diffs = diff_json({"items": [1, 2]}, {"items": [1, 2, 3]})
        self.assertTrue(any(d.path == "$.items[2]" for d in diffs))

    def test_role_change_flagged_security_relevant(self):
        diffs = diff_json({"user": {"role": "user"}}, {"user": {"role": "admin"}})
        self.assertTrue(diffs[0].security_relevant)

    def test_sensitive_value_redacted(self):
        diffs = diff_json({"password": "old-pass"}, {"password": "new-pass"})
        self.assertTrue(str(diffs[0].baseline_value).startswith("sha256:"))

    def test_ignored_json_path(self):
        diffs = diff_json(
            {"metadata": {"timestamp": 1}, "value": 1},
            {"metadata": {"timestamp": 2}, "value": 1},
            ignore_paths=["$.metadata.timestamp"],
        )
        self.assertEqual(diffs, [])

    def test_null_vs_missing(self):
        diffs = diff_json({}, {"email": None})
        self.assertEqual(diffs[0].change_type, ChangeType.ADDED)


if __name__ == "__main__":
    unittest.main()
