"""Rules for header-related security findings."""

from __future__ import annotations

from ..analyzers.headers import SECURITY_HEADERS
from ..models import ChangeType, Confidence, Difference, DifferenceCategory, Finding, HTTPResponse, Severity
from .base import Rule


class SecurityHeaderRemovedRule(Rule):
    rule_id = "HTTPDIFF-HEADER-001"
    title = "Security header removed"

    def evaluate(
        self, *, baseline: HTTPResponse, candidate: HTTPResponse, differences: list[Difference]
    ) -> list[Finding]:
        findings: list[Finding] = []
        for diff in differences:
            if diff.category != DifferenceCategory.HEADERS or diff.change_type != ChangeType.REMOVED:
                continue
            if diff.path.lower() not in SECURITY_HEADERS:
                continue
            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    title=self.title,
                    category=DifferenceCategory.HEADERS,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    summary=f"The {diff.path} security header disappeared in the candidate response.",
                    evidence=[f"Baseline: {diff.path}: {diff.baseline_value}", f"Candidate: header absent"],
                    recommendation=(
                        f"Confirm whether {diff.path} was intentionally removed. If not, "
                        "restore it to maintain the same security posture."
                    ),
                    false_positive_notes=(
                        "Some headers are only set conditionally (e.g. per-route CSP); "
                        "verify this is not expected routing behavior."
                    ),
                )
            )
        return findings


class CORSWildcardWithCredentialsRule(Rule):
    rule_id = "HTTPDIFF-HEADER-002"
    title = "CORS became more permissive"

    def evaluate(
        self, *, baseline: HTTPResponse, candidate: HTTPResponse, differences: list[Difference]
    ) -> list[Finding]:
        findings: list[Finding] = []
        b_origin = baseline.headers.get_first("Access-Control-Allow-Origin")
        c_origin = candidate.headers.get_first("Access-Control-Allow-Origin")
        c_creds = (candidate.headers.get_first("Access-Control-Allow-Credentials") or "").lower()

        if b_origin and b_origin != "*" and c_origin == "*":
            severity = Severity.HIGH if c_creds == "true" else Severity.MEDIUM
            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    title=self.title,
                    category=DifferenceCategory.CORS,
                    severity=severity,
                    confidence=Confidence.HIGH,
                    summary=(
                        "Access-Control-Allow-Origin changed from a fixed origin to a wildcard."
                    ),
                    evidence=[
                        f"Baseline Access-Control-Allow-Origin: {b_origin}",
                        f"Candidate Access-Control-Allow-Origin: {c_origin}",
                        f"Candidate Access-Control-Allow-Credentials: {c_creds or 'unset'}",
                    ],
                    recommendation=(
                        "Restrict Access-Control-Allow-Origin to an explicit allow-list, "
                        "especially if credentials are allowed."
                    ),
                    false_positive_notes="Wildcard CORS may be intentional for public, unauthenticated APIs.",
                )
            )
        return findings
