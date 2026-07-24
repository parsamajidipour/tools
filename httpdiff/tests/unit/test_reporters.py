from __future__ import annotations

import json
import unittest

from httpdiff.comparison import CompareOptions, compare_responses
from httpdiff.parser import parse_response
from httpdiff.reporters import render_json, render_markdown, render_terminal


def _resp(raw: bytes):
    return parse_response(raw, source="test")


class TestReporters(unittest.TestCase):
    def setUp(self):
        self.baseline = _resp(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
            b"Set-Cookie: session=abc; Secure; HttpOnly\r\n\r\n"
            b'{"role": "user"}'
        )
        self.candidate = _resp(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
            b"Set-Cookie: session=xyz; HttpOnly\r\n\r\n"
            b'{"role": "admin"}'
        )
        self.report = compare_responses(self.baseline, self.candidate, CompareOptions())

    def test_terminal_report_renders(self):
        text = render_terminal(self.report, use_color=False)
        self.assertIn("Comparison Summary", text)
        self.assertIn("Security Findings", text)

    def test_json_report_is_valid_json(self):
        text = render_json(self.report)
        payload = json.loads(text)
        self.assertEqual(payload["schema_version"], "1.0")
        self.assertIn("findings", payload)

    def test_json_no_secrets_by_default(self):
        text = render_json(self.report)
        self.assertNotIn("session=abc", text)
        self.assertNotIn("session=xyz", text)

    def test_markdown_report_renders(self):
        text = render_markdown(self.report)
        self.assertIn("# HTTPDiff Comparison Report", text)
        self.assertIn("Security Findings", text)


if __name__ == "__main__":
    unittest.main()
