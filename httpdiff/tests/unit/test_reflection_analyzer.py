from __future__ import annotations

import unittest

from httpdiff.analyzers.reflection import detect_reflection
from httpdiff.parser import parse_response


class TestReflectionAnalyzer(unittest.TestCase):
    def test_reflection_in_html_attribute(self):
        raw = (
            b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"
            b'<input value="HTTPDIFF123">'
        )
        resp = parse_response(raw, source="test")
        matches = detect_reflection(resp, "HTTPDIFF123")
        self.assertTrue(any(m.location == "HTML attribute" for m in matches))

    def test_reflection_url_encoded(self):
        raw = (
            b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"
            b"<p>value=HTTPDIFF%20123</p>"
        )
        resp = parse_response(raw, source="test")
        matches = detect_reflection(resp, "HTTPDIFF 123")
        self.assertTrue(any(m.encoding == "url-encoded" for m in matches))

    def test_no_reflection_returns_empty(self):
        raw = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<p>nothing here</p>"
        resp = parse_response(raw, source="test")
        matches = detect_reflection(resp, "NOT_PRESENT_MARKER")
        self.assertEqual(matches, [])

    def test_reflection_in_header(self):
        raw = b"HTTP/1.1 200 OK\r\nX-Echo: HTTPDIFF123\r\n\r\n"
        resp = parse_response(raw, source="test")
        matches = detect_reflection(resp, "HTTPDIFF123")
        self.assertTrue(any(m.location == "response header" for m in matches))


if __name__ == "__main__":
    unittest.main()
