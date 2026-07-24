from __future__ import annotations

import gzip
import unittest

from httpdiff.exceptions import ParseError
from httpdiff.parser import parse_cookie_header, parse_response


class TestBasicParsing(unittest.TestCase):
    def test_basic_response(self):
        raw = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nhello"
        resp = parse_response(raw, source="test")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.reason_phrase, "OK")
        self.assertEqual(resp.headers.get_first("Content-Type"), "text/plain")
        self.assertEqual(resp.body.text, "hello")

    def test_lf_only_line_endings(self):
        raw = b"HTTP/1.1 200 OK\nContent-Type: text/plain\n\nhello"
        resp = parse_response(raw, source="test")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.body.text, "hello")

    def test_duplicate_headers_preserved(self):
        raw = b"HTTP/1.1 200 OK\r\nX-Foo: 1\r\nX-Foo: 2\r\n\r\n"
        resp = parse_response(raw, source="test")
        self.assertEqual(resp.headers.get_all("X-Foo"), ["1", "2"])

    def test_multiple_set_cookie_headers(self):
        raw = (
            b"HTTP/1.1 200 OK\r\n"
            b"Set-Cookie: a=1; Path=/\r\n"
            b"Set-Cookie: b=2; Path=/admin\r\n\r\n"
        )
        resp = parse_response(raw, source="test")
        self.assertEqual(len(resp.cookies), 2)
        self.assertEqual({c.name for c in resp.cookies}, {"a", "b"})

    def test_empty_body(self):
        raw = b"HTTP/1.1 204 No Content\r\nX-Foo: bar\r\n\r\n"
        resp = parse_response(raw, source="test")
        self.assertEqual(resp.body.byte_length, 0)

    def test_body_only_input(self):
        raw = b'{"hello": "world"}'
        resp = parse_response(raw, source="test", force_body_only=True)
        self.assertFalse(resp.had_status_line)
        self.assertEqual(resp.body.detected_type, "json")

    def test_header_only_input_falls_back(self):
        raw = b"X-Foo: bar\r\nX-Baz: qux"
        resp = parse_response(raw, source="test")
        self.assertFalse(resp.had_status_line)
        self.assertEqual(resp.headers.get_first("X-Foo"), "bar")

    def test_malformed_recoverable_response(self):
        raw = b"HTTP/1.1 200 OK\r\nThis is not a valid header line\r\nX-Foo: bar\r\n\r\nbody"
        resp = parse_response(raw, source="test")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.headers.get_first("X-Foo"), "bar")
        self.assertTrue(any("skipped" in w for w in resp.parse_warnings))

    def test_empty_input_raises(self):
        with self.assertRaises(ParseError):
            parse_response(b"", source="test")

    def test_compressed_gzip_response(self):
        body = gzip.compress(b"hello world")
        raw = b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n\r\n" + body
        resp = parse_response(raw, source="test")
        self.assertEqual(resp.body.text, "hello world")

    def test_chunked_response(self):
        chunked_body = b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"
        raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" + chunked_body
        resp = parse_response(raw, source="test")
        self.assertEqual(resp.body.text, "hello world")

    def test_crlf_status_no_headers(self):
        raw = b"HTTP/1.1 500 Internal Server Error\r\n\r\n"
        resp = parse_response(raw, source="test")
        self.assertEqual(resp.status_code, 500)
        self.assertEqual(resp.body.byte_length, 0)


class TestCookieParsing(unittest.TestCase):
    def test_full_attributes(self):
        cookie = parse_cookie_header(
            "session=abc; Domain=example.com; Path=/; Secure; HttpOnly; SameSite=Strict"
        )
        self.assertEqual(cookie.name, "session")
        self.assertEqual(cookie.value, "abc")
        self.assertEqual(cookie.domain, "example.com")
        self.assertTrue(cookie.secure)
        self.assertTrue(cookie.http_only)
        self.assertEqual(cookie.same_site, "Strict")

    def test_host_prefix_violation_without_secure(self):
        cookie = parse_cookie_header("__Host-session=abc; Path=/")
        violations = cookie.prefix_violations()
        self.assertTrue(any("Secure" in v for v in violations))

    def test_host_prefix_ok(self):
        cookie = parse_cookie_header("__Host-session=abc; Path=/; Secure")
        self.assertEqual(cookie.prefix_violations(), [])


if __name__ == "__main__":
    unittest.main()
