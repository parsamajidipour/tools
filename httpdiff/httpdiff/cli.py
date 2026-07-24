"""HTTPDiff command-line interface."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from . import __version__
from .client import RequestSpec, fetch, parse_raw_request
from .comparison import CompareOptions, compare_responses
from .config import HTTPDiffConfig, load_config
from .exceptions import ConfigError, HTTPDiffError, NetworkError, ParseError, RequestFileError
from .models import ComparisonReport, Severity
from .parser import parse_response
from .reporters import render_json, render_markdown, render_terminal

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_BAD_ARGS = 2
EXIT_NETWORK = 3
EXIT_INTERNAL = 4

_SEVERITY_ORDER = ["none", "info", "low", "medium", "high"]


def _read_file_or_stdin(path: str | None, stdin_data: bytes | None = None) -> bytes:
    if path == "-":
        return sys.stdin.buffer.read()
    if path is None:
        if stdin_data is not None:
            return stdin_data
        raise ConfigError("no input provided")
    p = Path(path)
    if not p.is_file():
        raise ConfigError(f"file not found: {path}")
    return p.read_bytes()


def _add_global_options(parser: argparse.ArgumentParser) -> None:
    """Register options shared by the top-level parser and every subcommand,
    so they can be given either before or after the subcommand name."""
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("--quiet", action="store_true", help="Suppress non-essential output")
    parser.add_argument("--no-color", action="store_true", help="Disable colored terminal output")
    parser.add_argument("--config", metavar="PATH", help="Path to a TOML configuration file")
    parser.add_argument("--output", metavar="PATH", help="Write report to a file instead of stdout")
    parser.add_argument(
        "--format", choices=["terminal", "json", "markdown"], default=None, help="Output format"
    )
    parser.add_argument(
        "--fail-on",
        choices=["none", "info", "low", "medium", "high"],
        default="none",
        help="Exit with status 1 if a finding reaches this severity",
    )
    parser.add_argument("--timeout", type=float, default=15.0, help="Request timeout in seconds")
    parser.add_argument("--insecure", action="store_true", help="Disable TLS certificate verification")
    parser.add_argument("--proxy", metavar="URL", help="HTTP proxy URL")
    parser.add_argument("--user-agent", metavar="VALUE", help="Custom User-Agent header")

    parser.add_argument("--ignore-header", action="append", default=[], metavar="NAME")
    parser.add_argument("--include-header", action="append", default=[], metavar="NAME")
    parser.add_argument("--ignore-cookie", action="append", default=[], metavar="NAME")
    parser.add_argument("--ignore-json-path", action="append", default=[], metavar="PATH")
    parser.add_argument("--ignore-regex", action="append", default=[], metavar="REGEX")
    parser.add_argument("--normalize", action="store_true", default=None)
    parser.add_argument("--no-normalize", dest="normalize", action="store_false")
    parser.add_argument("--show-raw-diff", action="store_true")
    parser.add_argument("--show-unchanged", action="store_true")
    parser.add_argument("--show-secrets", action="store_true")
    parser.add_argument("--reflection-value", metavar="VALUE")
    parser.add_argument("--similarity-threshold", type=float, default=None)
    parser.add_argument("--max-body-size", type=int, default=None)
    parser.add_argument("--max-diff-lines", type=int, default=None)
    parser.add_argument("--max-json-depth", type=int, default=None)
    parser.add_argument("--scheme", default="https", choices=["http", "https"])
    parser.add_argument("--follow-redirects", action="store_true")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="httpdiff", description="Semantic HTTP response comparison tool.")
    parser.add_argument("--version", action="version", version=f"httpdiff {__version__}")
    _add_global_options(parser)

    subparsers = parser.add_subparsers(dest="command", required=True)

    compare_p = subparsers.add_parser("compare", help="Compare two raw HTTP response files")
    _add_global_options(compare_p)
    compare_p.add_argument("baseline", nargs="?", help="Baseline response file")
    compare_p.add_argument("candidate", nargs="?", help="Candidate response file")
    compare_p.add_argument("--baseline", dest="baseline_opt", metavar="PATH")
    compare_p.add_argument("--candidate", dest="candidate_opt", metavar="PATH")
    compare_p.add_argument("--stdin-baseline", metavar="CANDIDATE_PATH", help="Read baseline from stdin")
    compare_p.add_argument("--stdin-candidate", metavar="BASELINE_PATH", help="Read candidate from stdin")

    url_p = subparsers.add_parser("url", help="Compare two live URLs")
    _add_global_options(url_p)
    url_p.add_argument("--baseline", required=True, metavar="URL")
    url_p.add_argument("--candidate", required=True, metavar="URL")
    url_p.add_argument("--method", default="GET")

    request_p = subparsers.add_parser("request", help="Send two raw request files to their targets")
    _add_global_options(request_p)
    request_p.add_argument("--baseline-request", required=True, metavar="PATH")
    request_p.add_argument("--candidate-request", required=True, metavar="PATH")

    return parser


def _resolve_ignore_set(cli_values: list[str], config_values: list[str]) -> frozenset[str]:
    return frozenset(v.lower() for v in ([*config_values, *cli_values]))


def _build_options(args: argparse.Namespace, config: HTTPDiffConfig) -> CompareOptions:
    similarity = args.similarity_threshold if args.similarity_threshold is not None else config.similarity_threshold
    normalize = config.normalize if args.normalize is None else args.normalize
    min_severity = Severity(config.minimum_severity) if config.minimum_severity != "info" else Severity.INFO

    return CompareOptions(
        ignore_headers=_resolve_ignore_set(args.ignore_header, config.ignore_headers),
        include_headers=frozenset(h.lower() for h in args.include_header) or None,
        ignore_cookies=_resolve_ignore_set(args.ignore_cookie, config.ignore_cookies),
        ignore_json_paths=[*config.ignore_json_paths, *args.ignore_json_path],
        ignore_regexes=[*config.ignore_regexes, *args.ignore_regex],
        normalize=normalize,
        show_secrets=args.show_secrets or config.show_secrets,
        reflection_value=args.reflection_value,
        similarity_threshold=similarity,
        minimum_severity=min_severity,
    )


def _max_body_size(args: argparse.Namespace, config: HTTPDiffConfig) -> int:
    return args.max_body_size if args.max_body_size is not None else config.max_body_size


def _render(report: ComparisonReport, args: argparse.Namespace, config: HTTPDiffConfig) -> str:
    fmt = args.format or config.output_format
    if fmt == "json":
        return render_json(report)
    if fmt == "markdown":
        return render_markdown(report)
    return render_terminal(report, use_color=not args.no_color, show_unchanged=args.show_unchanged)


def _write_output(text: str, args: argparse.Namespace) -> None:
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
        if not args.quiet:
            print(f"Report written to {args.output}", file=sys.stderr)
    else:
        print(text)


def _exit_code_for_findings(report: ComparisonReport, fail_on: str) -> int:
    if fail_on == "none":
        return EXIT_OK
    threshold_rank = _SEVERITY_ORDER.index(fail_on)
    for finding in report.findings:
        if _SEVERITY_ORDER.index(finding.severity.value) >= threshold_rank:
            return EXIT_FINDINGS
    return EXIT_OK


def _cmd_compare(args: argparse.Namespace, config: HTTPDiffConfig) -> int:
    baseline_path = args.baseline_opt or args.baseline
    candidate_path = args.candidate_opt or args.candidate

    stdin_data = None
    if args.stdin_baseline:
        stdin_data = sys.stdin.buffer.read()
        baseline_raw = stdin_data
        candidate_raw = _read_file_or_stdin(args.stdin_baseline)
    elif args.stdin_candidate:
        stdin_data = sys.stdin.buffer.read()
        baseline_raw = _read_file_or_stdin(args.stdin_candidate)
        candidate_raw = stdin_data
    else:
        if not baseline_path or not candidate_path:
            raise ConfigError("both baseline and candidate files are required")
        baseline_raw = _read_file_or_stdin(baseline_path)
        candidate_raw = _read_file_or_stdin(candidate_path)

    max_body = _max_body_size(args, config)
    baseline = parse_response(baseline_raw, source=baseline_path or "<stdin>", max_body_size=max_body)
    candidate = parse_response(candidate_raw, source=candidate_path or "<stdin>", max_body_size=max_body)

    options = _build_options(args, config)
    report = compare_responses(baseline, candidate, options)
    _write_output(_render(report, args, config), args)
    return _exit_code_for_findings(report, args.fail_on)


def _cmd_url(args: argparse.Namespace, config: HTTPDiffConfig) -> int:
    max_body = _max_body_size(args, config)
    baseline_spec = RequestSpec(method=args.method, url=args.baseline)
    candidate_spec = RequestSpec(method=args.method, url=args.candidate)

    baseline = fetch(
        baseline_spec,
        timeout=args.timeout,
        verify_tls=not args.insecure,
        proxy=args.proxy,
        user_agent=args.user_agent,
        follow_redirects=args.follow_redirects,
        max_body_size=max_body,
    )
    candidate = fetch(
        candidate_spec,
        timeout=args.timeout,
        verify_tls=not args.insecure,
        proxy=args.proxy,
        user_agent=args.user_agent,
        follow_redirects=args.follow_redirects,
        max_body_size=max_body,
    )

    options = _build_options(args, config)
    report = compare_responses(baseline, candidate, options)
    _write_output(_render(report, args, config), args)
    return _exit_code_for_findings(report, args.fail_on)


def _cmd_request(args: argparse.Namespace, config: HTTPDiffConfig) -> int:
    max_body = _max_body_size(args, config)
    baseline_raw = _read_file_or_stdin(args.baseline_request)
    candidate_raw = _read_file_or_stdin(args.candidate_request)

    baseline_spec = parse_raw_request(baseline_raw, scheme=args.scheme)
    candidate_spec = parse_raw_request(candidate_raw, scheme=args.scheme)

    baseline = fetch(
        baseline_spec,
        timeout=args.timeout,
        verify_tls=not args.insecure,
        proxy=args.proxy,
        user_agent=args.user_agent,
        follow_redirects=args.follow_redirects,
        max_body_size=max_body,
    )
    candidate = fetch(
        candidate_spec,
        timeout=args.timeout,
        verify_tls=not args.insecure,
        proxy=args.proxy,
        user_agent=args.user_agent,
        follow_redirects=args.follow_redirects,
        max_body_size=max_body,
    )

    options = _build_options(args, config)
    report = compare_responses(baseline, candidate, options)
    _write_output(_render(report, args, config), args)
    return _exit_code_for_findings(report, args.fail_on)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.verbose:
        os.environ["HTTPDIFF_DEBUG"] = "1"

    try:
        config = load_config(args.config)
    except ConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_BAD_ARGS

    try:
        if args.command == "compare":
            return _cmd_compare(args, config)
        if args.command == "url":
            return _cmd_url(args, config)
        if args.command == "request":
            return _cmd_request(args, config)
        parser.print_help()
        return EXIT_BAD_ARGS
    except (ConfigError, ParseError, RequestFileError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_BAD_ARGS
    except NetworkError as exc:
        print(f"network error: {exc}", file=sys.stderr)
        return EXIT_NETWORK
    except HTTPDiffError as exc:  # pragma: no cover - defensive catch-all
        print(f"internal error: {exc}", file=sys.stderr)
        return EXIT_INTERNAL
    except Exception as exc:  # pragma: no cover - last-resort safety net
        if args.verbose:
            raise
        print(f"internal error: {exc}", file=sys.stderr)
        return EXIT_INTERNAL


if __name__ == "__main__":
    sys.exit(main())
