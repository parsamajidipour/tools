from __future__ import annotations

import unittest

from httpdiff.analyzers.redirect import analyze_redirect
from httpdiff.parser import parse_response


def _redirect(status, location):
    raw = f"HTTP/1.1 {status} Found\r\nLocation: {location}\r\n\r\n".encode()
    return parse_response(raw, source="test")


class TestRedirectAnalyzer(unittest.TestCase):
    def test_relative_to_external(self):
        b = _redirect(302, "/dashboard")
        c = _redirect(302, "https://evil.example/dashboard")
        diffs = analyze_redirect(b, c)
        self.assertTrue(any(d.path == "redirect.host" for d in diffs))

    def test_https_to_http_downgrade(self):
        b = _redirect(302, "https://example.com/x")
        c = _redirect(302, "http://example.com/x")
        diffs = analyze_redirect(b, c)
        self.assertTrue(any(d.path == "redirect.scheme" for d in diffs))

    def test_host_changed(self):
        b = _redirect(302, "https://a.example.com/x")
        c = _redirect(302, "https://b.example.com/x")
        diffs = analyze_redirect(b, c)
        self.assertTrue(any(d.path == "redirect.host" for d in diffs))

    def test_same_location_no_diff(self):
        b = _redirect(302, "/same")
        c = _redirect(302, "/same")
        diffs = analyze_redirect(b, c)
        self.assertEqual(diffs, [])

    def test_non_redirect_status_skips(self):
        b = parse_response(b"HTTP/1.1 200 OK\r\n\r\n", source="test")
        c = parse_response(b"HTTP/1.1 200 OK\r\n\r\n", source="test")
        diffs = analyze_redirect(b, c)
        self.assertEqual(diffs, [])


if __name__ == "__main__":
    unittest.main()
