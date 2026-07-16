import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

from header_analyzer import (
    check_csp,
    check_hsts,
    check_x_content_type_options,
    grade,
    normalize_url,
    scan,
)


class UnitTests(unittest.TestCase):
    def test_normalize_url(self):
        self.assertEqual(normalize_url("example.com"), "https://example.com")
        self.assertEqual(normalize_url("http://example.com"), "http://example.com")

    def test_invalid_url(self):
        with self.assertRaises(ValueError):
            normalize_url("ftp://example.com")

    def test_grade_boundaries(self):
        self.assertEqual(grade(90), "A")
        self.assertEqual(grade(80), "B")
        self.assertEqual(grade(70), "C")
        self.assertEqual(grade(60), "D")
        self.assertEqual(grade(59), "F")

    def test_strong_csp(self):
        finding = check_csp({
            "content-security-policy": "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'"
        }, "https://example.com")
        self.assertEqual(finding.status, "PASS")

    def test_weak_csp(self):
        finding = check_csp({
            "content-security-policy": "default-src *; script-src * 'unsafe-inline' 'unsafe-eval'"
        }, "https://example.com")
        self.assertEqual(finding.status, "WARN")

    def test_hsts_http_context(self):
        finding = check_hsts({}, "http://example.com")
        self.assertEqual(finding.status, "WARN")

    def test_nosniff_validation(self):
        self.assertEqual(check_x_content_type_options({"x-content-type-options": "nosniff"}, "").status, "PASS")
        self.assertEqual(check_x_content_type_options({"x-content-type-options": "invalid"}, "").status, "WARN")


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/secure")
            self.end_headers()
            return

        self.send_response(200)
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "strict-origin-when-cross-origin")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, format, *args):
        pass


class IntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = HTTPServer(("127.0.0.1", 0), Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def test_local_scan_and_redirect_chain(self):
        result = scan(self.base + "/redirect", timeout=2)
        self.assertEqual(result.status_code, 200)
        self.assertEqual(len(result.redirect_chain), 2)
        self.assertTrue(any(item.header == "Content-Security-Policy" and item.status == "PASS" for item in result.findings))
        self.assertEqual(result.final_url, self.base + "/secure")


if __name__ == "__main__":
    unittest.main()
