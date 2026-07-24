"""Rules for redirect-related security findings."""

from __future__ import annotations

from ..models import Confidence, Difference, DifferenceCategory, Finding, HTTPResponse, Severity
from .base import Rule


class RedirectRiskRule(Rule):
    rule_id = "HTTPDIFF-REDIRECT-001"
    title = "Redirect behavior change"

    def evaluate(
        self, *, baseline: HTTPResponse, candidate: HTTPResponse, differences: list[Difference]
    ) -> list[Finding]:
        findings: list[Finding] = []
        for diff in differences:
            if diff.category != DifferenceCategory.REDIRECT:
                continue
            if diff.path == "redirect.host":
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        title="Redirect target host changed",
                        category=DifferenceCategory.REDIRECT,
                        severity=Severity.MEDIUM,
                        confidence=Confidence.MEDIUM,
                        summary=diff.description,
                        evidence=[f"Baseline: {diff.baseline_value}", f"Candidate: {diff.candidate_value}"],
                        recommendation=(
                            "If the redirect target is influenced by user input, verify it "
                            "cannot be pointed at an attacker-controlled host (open redirect)."
                        ),
                        false_positive_notes=(
                            "A changed redirect host is not itself proof of an open redirect "
                            "without confirming attacker control over the destination."
                        ),
                    )
                )
            elif diff.path == "redirect.scheme":
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        title="Redirect downgraded to HTTP",
                        category=DifferenceCategory.REDIRECT,
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        summary=diff.description,
                        evidence=[diff.description],
                        recommendation="Ensure redirects preserve HTTPS to avoid man-in-the-middle exposure.",
                    )
                )
            elif diff.path == "redirect.cross_origin":
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        title="Redirect became cross-origin",
                        category=DifferenceCategory.REDIRECT,
                        severity=Severity.LOW,
                        confidence=Confidence.MEDIUM,
                        summary="The redirect now points to a different origin than before.",
                        evidence=[diff.description],
                        recommendation="Manual verification recommended; confirm this is expected.",
                    )
                )
        return findings
