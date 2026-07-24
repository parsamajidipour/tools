"""Rules for cookie-related security findings."""

from __future__ import annotations

from ..models import ChangeType, Confidence, Difference, DifferenceCategory, Finding, HTTPResponse, Severity
from .base import Rule

_ATTR_TO_SEVERITY = {
    ".secure": Severity.MEDIUM,
    ".httponly": Severity.MEDIUM,
    ".samesite": Severity.LOW,
    ".domain": Severity.MEDIUM,
    ".path": Severity.LOW,
    ".prefix": Severity.MEDIUM,
}


class CookieHardeningWeakenedRule(Rule):
    rule_id = "HTTPDIFF-COOKIE-001"
    title = "Cookie security attribute weakened"

    def evaluate(
        self, *, baseline: HTTPResponse, candidate: HTTPResponse, differences: list[Difference]
    ) -> list[Finding]:
        findings: list[Finding] = []
        for diff in differences:
            if diff.category != DifferenceCategory.COOKIES or not diff.security_relevant:
                continue
            severity = Severity.LOW
            for suffix, sev in _ATTR_TO_SEVERITY.items():
                if diff.path.endswith(suffix):
                    severity = sev
                    break
            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    title=self.title,
                    category=DifferenceCategory.COOKIES,
                    severity=severity,
                    confidence=Confidence.HIGH,
                    summary=diff.description,
                    evidence=[
                        f"Path: {diff.path}",
                        f"Baseline: {diff.baseline_value}",
                        f"Candidate: {diff.candidate_value}",
                    ],
                    recommendation=(
                        "Restore the stronger cookie attribute unless this change was "
                        "intentional and reviewed for session-hijacking / CSRF impact."
                    ),
                    false_positive_notes=(
                        "Non-session cookies (e.g. analytics/preference cookies) may not "
                        "require the same hardening."
                    ),
                )
            )
        return findings


class CookieRemovedRule(Rule):
    rule_id = "HTTPDIFF-COOKIE-002"
    title = "Session-like cookie disappeared"

    def evaluate(
        self, *, baseline: HTTPResponse, candidate: HTTPResponse, differences: list[Difference]
    ) -> list[Finding]:
        findings: list[Finding] = []
        for diff in differences:
            if (
                diff.category == DifferenceCategory.COOKIES
                and diff.path.startswith("cookie:")
                and "." not in diff.path
                and diff.change_type == ChangeType.REMOVED
            ):
                name = diff.path.split(":", 1)[1]
                if "session" in name.lower() or "sess" in name.lower() or "auth" in name.lower():
                    findings.append(
                        Finding(
                            rule_id=self.rule_id,
                            title=self.title,
                            category=DifferenceCategory.COOKIES,
                            severity=Severity.INFO,
                            confidence=Confidence.MEDIUM,
                            summary=f"Cookie '{name}' (session-like name) disappeared in the candidate response.",
                            evidence=[diff.description],
                            recommendation="Confirm this reflects an intended logout/session-end flow.",
                            false_positive_notes="Cookie name matching is heuristic, not authoritative.",
                        )
                    )
        return findings
