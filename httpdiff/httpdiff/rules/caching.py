"""Rules for cache-behavior security findings."""

from __future__ import annotations

from ..models import Confidence, Difference, DifferenceCategory, Finding, HTTPResponse, Severity
from .base import Rule


class PublicCacheRiskRule(Rule):
    rule_id = "HTTPDIFF-CACHE-001"
    title = "Potential cache-risk combination"

    def evaluate(
        self, *, baseline: HTTPResponse, candidate: HTTPResponse, differences: list[Difference]
    ) -> list[Finding]:
        findings: list[Finding] = []
        for diff in differences:
            if diff.category != DifferenceCategory.CACHING:
                continue
            if diff.path == "cache.personalization_risk":
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        title=self.title,
                        category=DifferenceCategory.CACHING,
                        severity=Severity.MEDIUM,
                        confidence=Confidence.MEDIUM,
                        summary="Cache-Control: public combined with personalized response fields.",
                        evidence=[
                            "Cache-Control: public",
                            "Response appears to contain user-specific fields",
                            "Vary does not include Cookie or Authorization",
                        ],
                        recommendation=(
                            "Verify the cache key includes the session/authorization context, "
                            "or mark this response private/no-store. Manual cache-isolation "
                            "testing is recommended."
                        ),
                        false_positive_notes=(
                            "HTTPDiff cannot see the actual CDN/cache-key configuration; this "
                            "is a heuristic based on response headers and body content alone."
                        ),
                    )
                )
            elif diff.path == "cache-control.visibility":
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        title="Cache visibility changed",
                        category=DifferenceCategory.CACHING,
                        severity=Severity.LOW,
                        confidence=Confidence.HIGH,
                        summary="Response became publicly cacheable (private -> public).",
                        evidence=[diff.description],
                        recommendation="Confirm the response does not contain per-user data before allowing public caching.",
                    )
                )
            elif diff.path == "cache-control.no-store":
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        title="no-store removed",
                        category=DifferenceCategory.CACHING,
                        severity=Severity.LOW,
                        confidence=Confidence.HIGH,
                        summary="no-store was removed from Cache-Control.",
                        evidence=[diff.description],
                        recommendation="Confirm this response is safe to cache/store, especially on shared caches.",
                    )
                )
            elif diff.path == "etag.stability" and "ETag remained stable" in diff.description:
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        title="ETag did not reflect body change",
                        category=DifferenceCategory.CACHING,
                        severity=Severity.LOW,
                        confidence=Confidence.MEDIUM,
                        summary="ETag remained stable while body content changed.",
                        evidence=[diff.description],
                        recommendation="Verify ETag generation reflects actual content/state to avoid stale-cache serving.",
                    )
                )
        return findings
