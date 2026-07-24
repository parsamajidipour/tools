from __future__ import annotations

import unittest

from httpdiff.analyzers.html_body import analyze_html


class TestHtmlAnalyzer(unittest.TestCase):
    def test_title_changed(self):
        b = "<html><head><title>Login</title></head><body></body></html>"
        c = "<html><head><title>Administration</title></head><body></body></html>"
        diffs = analyze_html(b, c)
        self.assertTrue(any(d.path == "html.title" for d in diffs))

    def test_form_action_changed(self):
        b = '<html><body><form action="/login" method="post"></form></body></html>'
        c = '<html><body><form action="/admin/login" method="post"></form></body></html>'
        diffs = analyze_html(b, c)
        self.assertTrue(any("html.form" in d.path for d in diffs))

    def test_new_script_source(self):
        b = "<html><body></body></html>"
        c = '<html><body><script src="https://evil.example/x.js"></script></body></html>'
        diffs = analyze_html(b, c)
        script_diffs = [d for d in diffs if "html.script" in d.path]
        self.assertEqual(len(script_diffs), 1)
        self.assertTrue(script_diffs[0].security_relevant)

    def test_new_password_input(self):
        b = '<html><body><form action="/x"><input type="text" name="q"></form></body></html>'
        c = '<html><body><form action="/y"><input type="password" name="p"></form></body></html>'
        diffs = analyze_html(b, c)
        self.assertTrue(any("password input" in d.description for d in diffs))

    def test_malformed_html_does_not_crash(self):
        b = "<html><body><div>unclosed"
        c = "<html><body><div>also unclosed but different</div>"
        diffs = analyze_html(b, c)
        self.assertIsInstance(diffs, list)


if __name__ == "__main__":
    unittest.main()
