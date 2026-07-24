from __future__ import annotations

import unittest

from httpdiff.analyzers.headers import analyze_headers
from httpdiff.models import ChangeType, HeaderCollection


def _headers(pairs):
    h = HeaderCollection()
    for name, value in pairs:
        h.add(name, value)
    return h


class TestHeaderAnalyzer(unittest.TestCase):
    def test_added_header(self):
        b = _headers([("Content-Type", "text/html")])
        c = _headers([("Content-Type", "text/html"), ("X-New", "1")])
        diffs = analyze_headers(b, c)
        added = [d for d in diffs if d.path == "X-New"]
        self.assertEqual(len(added), 1)
        self.assertEqual(added[0].change_type, ChangeType.ADDED)

    def test_removed_header(self):
        b = _headers([("X-Old", "1")])
        c = _headers([])
        diffs = analyze_headers(b, c)
        self.assertEqual(diffs[0].change_type, ChangeType.REMOVED)

    def test_modified_header(self):
        b = _headers([("Content-Type", "application/json")])
        c = _headers([("Content-Type", "text/html")])
        diffs = analyze_headers(b, c)
        self.assertEqual(diffs[0].change_type, ChangeType.MODIFIED)

    def test_security_header_removed_is_flagged(self):
        b = _headers([("Strict-Transport-Security", "max-age=1000")])
        c = _headers([])
        diffs = analyze_headers(b, c)
        self.assertTrue(diffs[0].security_relevant)

    def test_dynamic_header_suppressed(self):
        b = _headers([("X-Request-ID", "11111111-1111-1111-1111-111111111111")])
        c = _headers([("X-Request-ID", "22222222-2222-2222-2222-222222222222")])
        diffs = analyze_headers(b, c)
        self.assertTrue(diffs[0].suppressed)

    def test_cache_control_changed_not_dynamic(self):
        b = _headers([("Cache-Control", "private")])
        c = _headers([("Cache-Control", "public")])
        diffs = analyze_headers(b, c)
        self.assertFalse(diffs[0].suppressed)

    def test_duplicate_header_comparison(self):
        b = _headers([("X-Foo", "1"), ("X-Foo", "2")])
        c = _headers([("X-Foo", "2"), ("X-Foo", "1")])
        diffs = analyze_headers(b, c)
        # Order-insensitive comparison: no diff should be reported.
        self.assertEqual(diffs, [])

    def test_ignore_header_option(self):
        b = _headers([("Date", "Mon, 01 Jan 2024 00:00:00 GMT")])
        c = _headers([("Date", "Tue, 02 Jan 2024 00:00:00 GMT")])
        diffs = analyze_headers(b, c, ignore_headers=frozenset({"date"}))
        self.assertEqual(diffs, [])


if __name__ == "__main__":
    unittest.main()
