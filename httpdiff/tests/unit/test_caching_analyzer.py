from __future__ import annotations

import unittest

from httpdiff.analyzers.caching import analyze_caching
from httpdiff.parser import parse_response


def _resp(status=200, headers="", body=b""):
    raw = f"HTTP/1.1 {status} OK\r\n{headers}\r\n".encode() + body
    return parse_response(raw, source="test")


class TestCachingAnalyzer(unittest.TestCase):
    def test_private_to_public(self):
        b = _resp(headers="Cache-Control: private\r\n")
        c = _resp(headers="Cache-Control: public\r\n")
        diffs = analyze_caching(b, c)
        self.assertTrue(any(d.path == "cache-control.visibility" for d in diffs))

    def test_no_store_removed(self):
        b = _resp(headers="Cache-Control: no-store\r\n")
        c = _resp(headers="Cache-Control: max-age=100\r\n")
        diffs = analyze_caching(b, c)
        self.assertTrue(any(d.path == "cache-control.no-store" for d in diffs))

    def test_vary_removed_cookie(self):
        b = _resp(headers="Vary: Cookie\r\n")
        c = _resp(headers="Vary: Accept-Encoding\r\n")
        diffs = analyze_caching(b, c)
        vary_diff = next(d for d in diffs if d.path == "vary")
        self.assertTrue(vary_diff.security_relevant)

    def test_cdn_miss_to_hit(self):
        b = _resp(headers="X-Cache: MISS\r\n")
        c = _resp(headers="X-Cache: HIT\r\n")
        diffs = analyze_caching(b, c)
        self.assertTrue(any(d.path == "cdn.status" for d in diffs))

    def test_personalized_json_with_public_cache(self):
        body = b'{"email": "user@example.com"}'
        b = _resp(headers="Content-Type: application/json\r\nCache-Control: private\r\n", body=body)
        c = _resp(headers="Content-Type: application/json\r\nCache-Control: public\r\n", body=body)
        diffs = analyze_caching(b, c)
        self.assertTrue(any(d.path == "cache.personalization_risk" for d in diffs))


if __name__ == "__main__":
    unittest.main()
