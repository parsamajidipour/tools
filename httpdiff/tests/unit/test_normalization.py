from __future__ import annotations

import unittest

from httpdiff.normalization import is_dynamic_header, normalize_value


class TestNormalization(unittest.TestCase):
    def test_date_is_ignored_by_default(self):
        self.assertTrue(is_dynamic_header("Date"))
        self.assertTrue(is_dynamic_header("date"))

    def test_uuid_normalized(self):
        result = normalize_value("id=11111111-1111-1111-1111-111111111111")
        self.assertIn("<uuid>", result.normalized)
        self.assertTrue(result.changed)

    def test_dynamic_request_id_suppressed_via_uuid_pattern(self):
        a = normalize_value("req-11111111-1111-1111-1111-111111111111")
        b = normalize_value("req-22222222-2222-2222-2222-222222222222")
        self.assertEqual(a.normalized, b.normalized)

    def test_original_value_preserved(self):
        original = "id=11111111-1111-1111-1111-111111111111"
        result = normalize_value(original)
        self.assertEqual(result.original, original)

    def test_non_dynamic_value_unchanged(self):
        result = normalize_value("application/json")
        self.assertFalse(result.changed)


if __name__ == "__main__":
    unittest.main()
