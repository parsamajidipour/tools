from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

BASELINE = (
    b"HTTP/1.1 200 OK\r\n"
    b"Content-Type: application/json\r\n"
    b"Set-Cookie: session=abc123; Secure; HttpOnly; SameSite=Lax\r\n"
    b"Cache-Control: private\r\n\r\n"
    b'{"user":{"id":10,"role":"user"}}'
)
CANDIDATE = (
    b"HTTP/1.1 200 OK\r\n"
    b"Content-Type: application/json\r\n"
    b"Set-Cookie: session=xyz789; HttpOnly; SameSite=Lax\r\n"
    b"Cache-Control: public\r\n\r\n"
    b'{"user":{"id":10,"role":"admin"}}'
)


def run_cli(args: list[str], stdin: bytes | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "httpdiff", *args],
        input=stdin,
        capture_output=True,
    )


class TestCLI(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.base_path = Path(self.tmpdir.name) / "baseline.txt"
        self.cand_path = Path(self.tmpdir.name) / "candidate.txt"
        self.base_path.write_bytes(BASELINE)
        self.cand_path.write_bytes(CANDIDATE)

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_help(self):
        result = run_cli(["--help"])
        self.assertEqual(result.returncode, 0)
        self.assertIn(b"httpdiff", result.stdout)

    def test_version(self):
        result = run_cli(["--version"])
        self.assertEqual(result.returncode, 0)
        self.assertIn(b"httpdiff", result.stdout)

    def test_invalid_input_exit_code(self):
        result = run_cli(["compare", "/no/such/file.txt", str(self.cand_path)])
        self.assertEqual(result.returncode, 2)

    def test_exit_threshold_triggers_failure(self):
        result = run_cli(
            ["compare", str(self.base_path), str(self.cand_path), "--fail-on", "medium"]
        )
        self.assertEqual(result.returncode, 1)

    def test_exit_threshold_none_by_default(self):
        result = run_cli(["compare", str(self.base_path), str(self.cand_path)])
        self.assertEqual(result.returncode, 0)

    def test_output_file(self):
        out_path = Path(self.tmpdir.name) / "report.json"
        result = run_cli(
            [
                "compare",
                str(self.base_path),
                str(self.cand_path),
                "--format",
                "json",
                "--output",
                str(out_path),
                "--quiet",
            ]
        )
        self.assertEqual(result.returncode, 0)
        self.assertTrue(out_path.is_file())
        payload = json.loads(out_path.read_text())
        self.assertEqual(payload["schema_version"], "1.0")

    def test_no_color_mode(self):
        result = run_cli(["compare", str(self.base_path), str(self.cand_path), "--no-color"])
        self.assertNotIn(b"\x1b[", result.stdout)

    def test_color_mode_default(self):
        result = run_cli(["compare", str(self.base_path), str(self.cand_path)])
        self.assertIn(b"\x1b[", result.stdout)

    def test_json_output_is_parseable(self):
        result = run_cli(
            ["compare", str(self.base_path), str(self.cand_path), "--format", "json"]
        )
        payload = json.loads(result.stdout)
        self.assertIn("findings", payload)
        self.assertGreater(len(payload["findings"]), 0)

    def test_stdin_baseline_default_exit(self):
        result = run_cli(
            ["compare", "--stdin-baseline", str(self.cand_path), "--format", "json"],
            stdin=BASELINE,
        )
        payload = json.loads(result.stdout)
        self.assertIn("summary", payload)


if __name__ == "__main__":
    unittest.main()
