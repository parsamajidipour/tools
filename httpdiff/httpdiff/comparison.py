"""Glues the analyzers + rule engine together into one ComparisonReport."""

from __future__ import annotations

from dataclasses import dataclass, field

from .analyzers.body import analyze_body_metadata, compute_similarity
from .analyzers.caching import analyze_caching
from .analyzers.cookies import analyze_cookies
from .analyzers.headers import analyze_headers
from .analyzers.html_body import analyze_html
from .analyzers.json_body import diff_json
from .analyzers.redirect import analyze_redirect
from .analyzers.reflection import ReflectionMatch, detect_reflection
from .analyzers.status import analyze_status
from .analyzers.xml_body import analyze_xml
from .models import ComparisonReport, ComparisonSummary, HTTPResponse, Severity
from .rules import build_default_engine
from .rules.reflection import build_reflection_findings

TOOL_VERSION = "1.0.0"


@dataclass
class CompareOptions:
    ignore_headers: frozenset[str] = field(default_factory=frozenset)
    include_headers: frozenset[str] | None = None
    ignore_cookies: frozenset[str] = field(default_factory=frozenset)
    ignore_json_paths: list[str] = field(default_factory=list)
    ignore_regexes: list[str] = field(default_factory=list)
    normalize: bool = True
    show_secrets: bool = False
    reflection_value: str | None = None
    similarity_threshold: float = 0.92
    minimum_severity: Severity = Severity.INFO


def compare_responses(
    baseline: HTTPResponse,
    candidate: HTTPResponse,
    options: CompareOptions | None = None,
) -> ComparisonReport:
    options = options or CompareOptions()
    report = ComparisonReport(
        tool_version=TOOL_VERSION,
        baseline_source=baseline.source,
        candidate_source=candidate.source,
    )

    differences = []
    differences += analyze_status(baseline, candidate)
    differences += analyze_headers(
        baseline.headers,
        candidate.headers,
        ignore_headers=options.ignore_headers,
        include_headers=options.include_headers,
        extra_ignore_regexes=options.ignore_regexes,
        show_secrets=options.show_secrets,
    )
    differences += analyze_cookies(
        baseline.cookies,
        candidate.cookies,
        ignore_cookies=options.ignore_cookies,
        show_secrets=options.show_secrets,
    )
    differences += analyze_body_metadata(baseline.body, candidate.body)
    differences += analyze_redirect(baseline, candidate)
    differences += analyze_caching(baseline, candidate)

    body_similarity: float | None = None
    if baseline.body.text is not None and candidate.body.text is not None:
        body_similarity = compute_similarity(baseline.body.text, candidate.body.text)

    detected_type = candidate.body.detected_type or baseline.body.detected_type
    if detected_type == "json" and baseline.body.parsed_json is not None and candidate.body.parsed_json is not None:
        differences += diff_json(
            baseline.body.parsed_json,
            candidate.body.parsed_json,
            ignore_paths=options.ignore_json_paths,
            show_secrets=options.show_secrets,
        )
    elif detected_type == "html" and baseline.body.text and candidate.body.text:
        differences += analyze_html(baseline.body.text, candidate.body.text)
    elif detected_type == "xml" and baseline.body.text and candidate.body.text:
        differences += analyze_xml(baseline.body.text, candidate.body.text)

    reflection_matches: list[ReflectionMatch] = []
    if options.reflection_value:
        reflection_matches = detect_reflection(candidate, options.reflection_value)

    report.differences = differences
    report.suppressed = [d for d in differences if d.suppressed]

    engine = build_default_engine()
    findings = engine.run(baseline=baseline, candidate=candidate, differences=differences)
    findings += build_reflection_findings(reflection_matches)

    # Filter by minimum severity for reporting purposes; the full list is
    # always computed so JSON consumers relying on --format json --fail-on
    # can still access everything if minimum_severity is info (default).
    findings = [f for f in findings if f.severity.rank >= options.minimum_severity.rank]
    report.findings = findings

    highest = Severity.INFO
    for finding in findings:
        if finding.severity.rank > highest.rank:
            highest = finding.severity

    report.summary = ComparisonSummary(
        status_unchanged=baseline.status_code == candidate.status_code,
        baseline_status=baseline.status_code,
        candidate_status=candidate.status_code,
        body_similarity=body_similarity,
        total_differences=len(report.active_differences()),
        suppressed_differences=len(report.suppressed),
        total_findings=len(findings),
        highest_severity=highest,
    )

    return report
