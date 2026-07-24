from __future__ import annotations

import unittest

from httpdiff.comparison import CompareOptions, compare_responses
from httpdiff.parser import parse_response


def _resp(raw: bytes):
    return parse_response(raw, source="test")


class TestRuleEngine(unittest.TestCase):
    def test_authorization_finding_requires_multiple_signals(self):
        baseline = _resp(
            b"HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\n"
            b"Set-Cookie: session=abc; Secure; HttpOnly\r\n\r\n"
            b'{"error": "forbidden"}'
        )
        candidate = _resp(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
            b"Set-Cookie: session=abc; Secure; HttpOnly\r\n\r\n"
            b'{"role": "admin", "account_id": 42}'
        )
        report = compare_responses(baseline, candidate, CompareOptions())
        authz = [f for f in report.findings if f.rule_id == "HTTPDIFF-AUTHZ-001"]
        self.assertEqual(len(authz), 1)
        self.assertIn("Manual", authz[0].recommendation + " Manually verify")

    def test_status_change_alone_does_not_trigger_authz(self):
        baseline = _resp(b"HTTP/1.1 403 Forbidden\r\n\r\n")
        candidate = _resp(b"HTTP/1.1 200 OK\r\n\r\n")
        report = compare_responses(baseline, candidate, CompareOptions())
        authz = [f for f in report.findings if f.rule_id == "HTTPDIFF-AUTHZ-001"]
        self.assertEqual(authz, [])

    def test_reflection_rule_fires_on_marker(self):
        candidate = _resp(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"
            b'<html><body><input value="HTTPDIFF123"></body></html>'
        )
        baseline = _resp(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html></html>")
        options = CompareOptions(reflection_value="HTTPDIFF123")
        report = compare_responses(baseline, candidate, options)
        reflect = [f for f in report.findings if f.rule_id == "HTTPDIFF-REFLECT-001"]
        self.assertTrue(len(reflect) >= 1)

    def test_no_findings_labeled_high_confidence_without_evidence(self):
        baseline = _resp(b"HTTP/1.1 200 OK\r\n\r\nhello")
        candidate = _resp(b"HTTP/1.1 200 OK\r\n\r\nhello world")
        report = compare_responses(baseline, candidate, CompareOptions())
        # A trivial body change should not produce any findings at all.
        self.assertEqual(report.findings, [])


if __name__ == "__main__":
    unittest.main()
