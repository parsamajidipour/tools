#!/usr/bin/env python3
"""Header Analyzer: practical HTTP response security-header auditing."""

from __future__ import annotations

import argparse
import json
import re
import ssl
import sys
from dataclasses import asdict, dataclass
from typing import Any, Callable
from urllib.parse import urlparse

import requests
from requests import Response, Session
from requests.exceptions import RequestException


VERSION = "1.0.0"
DEFAULT_UA = f"header-analyzer/{VERSION} (+https://github.com/parsamajidipour/tools)"


@dataclass(frozen=True)
class Finding:
    header: str
    status: str
    severity: str
    message: str
    value: str | None
    recommendation: str
    points_awarded: int
    points_possible: int


@dataclass
class ScanResult:
    target: str
    final_url: str
    status_code: int
    elapsed_ms: int
    redirect_chain: list[dict[str, Any]]
    findings: list[Finding]
    observations: list[str]
    score: int
    grade: str
    response_headers: dict[str, str]


def _split_directives(value: str) -> dict[str, list[str]]:
    directives: dict[str, list[str]] = {}
    for part in value.split(";"):
        tokens = part.strip().split()
        if tokens:
            directives[tokens[0].lower()] = tokens[1:]
    return directives


def _pass(header: str, value: str, message: str, recommendation: str, points: int) -> Finding:
    return Finding(header, "PASS", "info", message, value, recommendation, points, points)


def _warn(header: str, value: str | None, message: str, recommendation: str, awarded: int, possible: int) -> Finding:
    return Finding(header, "WARN", "medium", message, value, recommendation, awarded, possible)


def _fail(header: str, message: str, recommendation: str, points: int) -> Finding:
    return Finding(header, "FAIL", "high", message, None, recommendation, 0, points)


def check_csp(headers: dict[str, str], _: str) -> Finding:
    name, points = "Content-Security-Policy", 25
    value = headers.get(name.lower())
    rec = "Deploy a restrictive CSP; prefer nonces or hashes and avoid broad sources."
    if not value:
        report_only = headers.get("content-security-policy-report-only")
        if report_only:
            return _warn(name, report_only, "Only a report-only policy is present.", rec, 8, points)
        return _fail(name, "CSP is missing.", rec, points)

    directives = _split_directives(value)
    risky: list[str] = []
    script_sources = directives.get("script-src", directives.get("default-src", []))
    if "*" in script_sources:
        risky.append("wildcard script source")
    if "'unsafe-inline'" in script_sources:
        risky.append("'unsafe-inline'")
    if "'unsafe-eval'" in script_sources:
        risky.append("'unsafe-eval'")
    if not script_sources:
        risky.append("no script-src/default-src restriction")
    if "object-src" not in directives:
        risky.append("object-src not defined")
    if "base-uri" not in directives:
        risky.append("base-uri not defined")

    if risky:
        return _warn(name, value, "Policy is present but potentially weak: " + ", ".join(risky) + ".", rec, 12, points)
    return _pass(name, value, "A CSP is present without the basic risky patterns checked by this tool.", rec, points)


def check_hsts(headers: dict[str, str], final_url: str) -> Finding:
    name, points = "Strict-Transport-Security", 20
    value = headers.get(name.lower())
    rec = "On HTTPS, use HSTS with max-age of at least 31536000; consider includeSubDomains."
    if urlparse(final_url).scheme != "https":
        return _warn(name, value, "Final response is not HTTPS, so HSTS cannot protect this connection.", rec, 0, points)
    if not value:
        return _fail(name, "HSTS is missing on an HTTPS response.", rec, points)

    match = re.search(r"max-age\s*=\s*(\d+)", value, re.I)
    if not match:
        return _warn(name, value, "HSTS does not contain a valid max-age directive.", rec, 5, points)

    max_age = int(match.group(1))
    issues = []
    if max_age < 31_536_000:
        issues.append(f"max-age is only {max_age}")
    if "includesubdomains" not in value.lower():
        issues.append("includeSubDomains is absent")
    if issues:
        return _warn(name, value, "HSTS is present but could be strengthened: " + ", ".join(issues) + ".", rec, 12, points)
    return _pass(name, value, "HSTS is enabled with a long max-age and includeSubDomains.", rec, points)


def check_x_content_type_options(headers: dict[str, str], _: str) -> Finding:
    name, points = "X-Content-Type-Options", 10
    value = headers.get(name.lower())
    rec = "Set X-Content-Type-Options: nosniff."
    if not value:
        return _fail(name, "Header is missing.", rec, points)
    if value.strip().lower() != "nosniff":
        return _warn(name, value, "Header is present but is not set to nosniff.", rec, 2, points)
    return _pass(name, value, "MIME sniffing protection is enabled.", rec, points)


def check_referrer_policy(headers: dict[str, str], _: str) -> Finding:
    name, points = "Referrer-Policy", 10
    value = headers.get(name.lower())
    rec = "Use a privacy-preserving policy such as strict-origin-when-cross-origin or no-referrer."
    if not value:
        return _fail(name, "Referrer-Policy is missing.", rec, points)
    effective = value.split(",")[-1].strip().lower()
    weak = {"unsafe-url", "no-referrer-when-downgrade"}
    if effective in weak:
        return _warn(name, value, f"The effective policy '{effective}' may disclose more referrer data than necessary.", rec, 4, points)
    return _pass(name, value, f"Referrer policy is set to '{effective}'.", rec, points)


def check_frame_protection(headers: dict[str, str], _: str) -> Finding:
    name, points = "Frame Protection", 10
    xfo = headers.get("x-frame-options")
    csp = headers.get("content-security-policy", "")
    rec = "Set CSP frame-ancestors; X-Frame-Options can be retained for legacy compatibility."
    directives = _split_directives(csp) if csp else {}
    if "frame-ancestors" in directives:
        return _pass(name, f"CSP frame-ancestors {' '.join(directives['frame-ancestors'])}", "Framing is controlled by CSP.", rec, points)
    if not xfo:
        return _fail(name, "Neither CSP frame-ancestors nor X-Frame-Options is present.", rec, points)
    if xfo.strip().upper() not in {"DENY", "SAMEORIGIN"}:
        return _warn(name, xfo, "X-Frame-Options has a non-standard or weak value.", rec, 3, points)
    return _pass(name, xfo, "Framing is restricted with X-Frame-Options.", rec, points)


def check_permissions_policy(headers: dict[str, str], _: str) -> Finding:
    name, points = "Permissions-Policy", 8
    value = headers.get(name.lower())
    rec = "Define a Permissions-Policy that disables browser features the application does not need."
    if not value:
        return _fail(name, "Permissions-Policy is missing.", rec, points)
    if not re.search(r"[a-zA-Z-]+\s*=", value):
        return _warn(name, value, "Permissions-Policy appears malformed or empty.", rec, 2, points)
    return _pass(name, value, "A Permissions-Policy is present.", rec, points)


def check_cross_origin(headers: dict[str, str], _: str) -> Finding:
    name, points = "Cross-Origin-Opener-Policy", 7
    value = headers.get(name.lower())
    rec = "For compatible document applications, consider Cross-Origin-Opener-Policy: same-origin."
    if not value:
        return _warn(name, None, "COOP is not present. This may be acceptable depending on application requirements.", rec, 2, points)
    if value.strip().lower() not in {"same-origin", "same-origin-allow-popups", "unsafe-none"}:
        return _warn(name, value, "COOP contains an unrecognized value.", rec, 2, points)
    if value.strip().lower() == "unsafe-none":
        return _warn(name, value, "COOP explicitly uses unsafe-none.", rec, 2, points)
    return _pass(name, value, "Cross-origin opener isolation is configured.", rec, points)


CHECKS: tuple[Callable[[dict[str, str], str], Finding], ...] = (
    check_csp,
    check_hsts,
    check_x_content_type_options,
    check_referrer_policy,
    check_frame_protection,
    check_permissions_policy,
    check_cross_origin,
)


def normalize_url(value: str) -> str:
    value = value.strip()
    if not value:
        raise ValueError("target cannot be empty")
    if "://" not in value:
        value = "https://" + value
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("target must be a valid HTTP or HTTPS URL")
    return value


def grade(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"


def observations(headers: dict[str, str], response: Response) -> list[str]:
    notes: list[str] = []
    for disclosure in ("server", "x-powered-by", "x-aspnet-version"):
        if disclosure in headers:
            notes.append(f"Information disclosure: {disclosure}: {headers[disclosure]}")

    for cookie in response.raw.headers.getlist("Set-Cookie") if hasattr(response.raw.headers, "getlist") else []:
        lower = cookie.lower()
        cookie_name = cookie.split("=", 1)[0].strip() or "(unnamed)"
        missing = [flag for flag in ("secure", "httponly", "samesite") if flag not in lower]
        if missing:
            notes.append(f"Cookie '{cookie_name}' is missing: {', '.join(missing)}")

    acao = headers.get("access-control-allow-origin")
    acac = headers.get("access-control-allow-credentials", "").lower()
    if acao == "*" and acac == "true":
        notes.append("Potentially invalid CORS combination: wildcard origin with credentials enabled.")
    elif acao == "*":
        notes.append("CORS allows any origin. Confirm that the resource is intentionally public.")

    if "x-xss-protection" in headers and headers["x-xss-protection"].strip() not in {"0", "0;"}:
        notes.append("Legacy X-XSS-Protection is enabled; modern guidance generally favors CSP and disabling this header.")

    return notes


def scan(
    target: str,
    *,
    timeout: float = 10.0,
    verify_tls: bool = True,
    user_agent: str = DEFAULT_UA,
    session: Session | None = None,
) -> ScanResult:
    normalized = normalize_url(target)
    client = session or requests.Session()
    try:
        response = client.get(
            normalized,
            timeout=timeout,
            verify=verify_tls,
            allow_redirects=True,
            headers={"User-Agent": user_agent, "Accept": "*/*"},
            stream=True,
        )
    except RequestException as exc:
        raise RuntimeError(f"request failed: {exc}") from exc

    lower_headers = {k.lower(): v for k, v in response.headers.items()}
    findings = [check(lower_headers, response.url) for check in CHECKS]
    possible = sum(item.points_possible for item in findings)
    awarded = sum(item.points_awarded for item in findings)
    score = round((awarded / possible) * 100) if possible else 0

    chain = [
        {
            "url": item.url,
            "status_code": item.status_code,
            "location": item.headers.get("Location"),
        }
        for item in [*response.history, response]
    ]

    result = ScanResult(
        target=normalized,
        final_url=response.url,
        status_code=response.status_code,
        elapsed_ms=round(response.elapsed.total_seconds() * 1000),
        redirect_chain=chain,
        findings=findings,
        observations=observations(lower_headers, response),
        score=score,
        grade=grade(score),
        response_headers=dict(response.headers),
    )
    response.close()
    return result


class Colors:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    RED = "\033[31m"
    CYAN = "\033[36m"


def render_text(result: ScanResult, use_color: bool = True, show_headers: bool = False) -> str:
    def c(text: str, color: str) -> str:
        return f"{color}{text}{Colors.RESET}" if use_color else text

    lines = [
        c("Header Analyzer", Colors.BOLD + Colors.CYAN),
        f"Target:    {result.target}",
        f"Final URL: {result.final_url}",
        f"Status:    {result.status_code}",
        f"Time:      {result.elapsed_ms} ms",
        "",
        c("Redirect chain", Colors.BOLD),
    ]
    for hop in result.redirect_chain:
        suffix = f" -> {hop['location']}" if hop.get("location") else ""
        lines.append(f"  {hop['status_code']} {hop['url']}{suffix}")

    lines.extend(["", c("Security header findings", Colors.BOLD)])
    for item in result.findings:
        color = Colors.GREEN if item.status == "PASS" else Colors.YELLOW if item.status == "WARN" else Colors.RED
        lines.append(f"  {c(f'[{item.status}]', color)} {item.header} ({item.points_awarded}/{item.points_possible})")
        lines.append(f"         {item.message}")
        if item.value:
            lines.append(f"         Value: {item.value}")
        if item.status != "PASS":
            lines.append(f"         Fix: {item.recommendation}")

    if result.observations:
        lines.extend(["", c("Additional observations", Colors.BOLD)])
        lines.extend(f"  - {note}" for note in result.observations)

    lines.extend([
        "",
        c("Summary", Colors.BOLD),
        f"  Score: {result.score}/100",
        f"  Grade: {result.grade}",
        "",
        "Note: Results are heuristic and must be interpreted in application context.",
    ])

    if show_headers:
        lines.extend(["", c("Response headers", Colors.BOLD)])
        lines.extend(f"  {name}: {value}" for name, value in sorted(result.response_headers.items(), key=lambda x: x[0].lower()))

    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="header-analyzer",
        description="Audit HTTP response security headers and highlight weak configurations.",
    )
    parser.add_argument("target", nargs="?", help="HTTP or HTTPS target URL")
    parser.add_argument("-i", "--input", help="File containing one target per line")
    parser.add_argument("-o", "--output", help="Write output to a file")
    parser.add_argument("--format", choices=("text", "json"), default="text", help="Output format")
    parser.add_argument("--timeout", type=float, default=10.0, help="Request timeout in seconds")
    parser.add_argument("--insecure", action="store_true", help="Disable TLS certificate verification")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI colors")
    parser.add_argument("--show-headers", action="store_true", help="Include all response headers in text output")
    parser.add_argument("--user-agent", default=DEFAULT_UA, help="Custom User-Agent")
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    return parser


def load_targets(target: str | None, input_file: str | None) -> list[str]:
    targets: list[str] = []
    if target:
        targets.append(target)
    if input_file:
        try:
            with open(input_file, encoding="utf-8") as handle:
                targets.extend(line.strip() for line in handle if line.strip() and not line.lstrip().startswith("#"))
        except OSError as exc:
            raise ValueError(f"cannot read input file: {exc}") from exc
    if not targets:
        raise ValueError("provide a target or --input file")
    return targets


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        targets = load_targets(args.target, args.input)
    except ValueError as exc:
        parser.error(str(exc))

    results: list[ScanResult] = []
    errors: list[dict[str, str]] = []

    for target in targets:
        try:
            results.append(
                scan(
                    target,
                    timeout=args.timeout,
                    verify_tls=not args.insecure,
                    user_agent=args.user_agent,
                )
            )
        except (ValueError, RuntimeError) as exc:
            errors.append({"target": target, "error": str(exc)})

    if args.format == "json":
        payload = {
            "tool": "header-analyzer",
            "version": VERSION,
            "results": [asdict(result) for result in results],
            "errors": errors,
        }
        output = json.dumps(payload, indent=2, ensure_ascii=False)
    else:
        blocks = [render_text(result, use_color=not args.no_color and sys.stdout.isatty(), show_headers=args.show_headers) for result in results]
        blocks.extend(f"[ERROR] {item['target']}: {item['error']}" for item in errors)
        output = "\n\n" + ("\n\n" + "=" * 72 + "\n\n").join(blocks) if blocks else ""

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as handle:
                handle.write(output + "\n")
        except OSError as exc:
            print(f"error: cannot write output file: {exc}", file=sys.stderr)
            return 2
    else:
        print(output)

    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
