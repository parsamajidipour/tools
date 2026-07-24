from __future__ import annotations

import unittest

from httpdiff.analyzers.cookies import analyze_cookies
from httpdiff.parser import parse_cookie_header


class TestCookieAnalyzer(unittest.TestCase):
    def test_secure_removed(self):
        b = [parse_cookie_header("session=abc; Secure; HttpOnly")]
        c = [parse_cookie_header("session=abc; HttpOnly")]
        diffs = analyze_cookies(b, c)
        secure_diffs = [d for d in diffs if d.path.endswith(".secure")]
        self.assertEqual(len(secure_diffs), 1)
        self.assertTrue(secure_diffs[0].security_relevant)

    def test_httponly_removed(self):
        b = [parse_cookie_header("session=abc; HttpOnly")]
        c = [parse_cookie_header("session=abc")]
        diffs = analyze_cookies(b, c)
        self.assertTrue(any(d.path.endswith(".httponly") for d in diffs))

    def test_samesite_weakened(self):
        b = [parse_cookie_header("session=abc; SameSite=Strict")]
        c = [parse_cookie_header("session=abc; SameSite=None")]
        diffs = analyze_cookies(b, c)
        self.assertTrue(any(d.path.endswith(".samesite") for d in diffs))

    def test_domain_widened(self):
        b = [parse_cookie_header("session=abc; Domain=sub.example.com")]
        c = [parse_cookie_header("session=abc; Domain=example.com")]
        diffs = analyze_cookies(b, c)
        self.assertTrue(any(d.path.endswith(".domain") for d in diffs))

    def test_value_redacted_by_default(self):
        b = [parse_cookie_header("session=super-secret-value")]
        c = [parse_cookie_header("session=another-secret-value")]
        diffs = analyze_cookies(b, c)
        value_diff = next(d for d in diffs if d.path.endswith(".value"))
        self.assertNotIn("super-secret-value", str(value_diff.baseline_value))
        self.assertTrue(str(value_diff.baseline_value).startswith("sha256:"))

    def test_path_broadened(self):
        b = [parse_cookie_header("track=1; Path=/account")]
        c = [parse_cookie_header("track=1; Path=/")]
        diffs = analyze_cookies(b, c)
        self.assertTrue(any(d.path.endswith(".path") for d in diffs))

    def test_cookie_added_and_removed(self):
        b = [parse_cookie_header("old=1")]
        c = [parse_cookie_header("new=1")]
        diffs = analyze_cookies(b, c)
        paths = {d.path for d in diffs}
        self.assertIn("cookie:old", paths)
        self.assertIn("cookie:new", paths)

    def test_ignore_cookies_option(self):
        b = [parse_cookie_header("analytics=1")]
        c = [parse_cookie_header("analytics=2")]
        diffs = analyze_cookies(b, c, ignore_cookies=frozenset({"analytics"}))
        self.assertEqual(diffs, [])


if __name__ == "__main__":
    unittest.main()
