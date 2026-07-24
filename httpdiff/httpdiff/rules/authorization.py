"""Authorization heuristics - status code getting "better" plus newly
visible privileged fields, while auth signals stayed the same."""

from __future__ import annotations

from ..models import Confidence, Difference, DifferenceCategory, Finding, HTTPResponse, Severity
from .base import Rule

_IDENTITY_PATH_HINTS = ("role", "permission", "privilege", "admin", "scope")


class PossibleAccessControlDifferenceRule(Rule):
    rule_id = "HTTPDIFF-AUTHZ-001"
    title = "Possible access-control difference"

    def evaluate(
        self, *, baseline: HTTPResponse, candidate: HTTPResponse, differences: list[Difference]
    ) -> list[Finding]:
        findings: list[Finding] = []

        b_status, c_status = baseline.status_code, candidate.status_code
        became_successful = (
            b_status is not None
            and c_status is not None
            and b_status in (401, 403)
            and 200 <= c_status < 300
        )

        privilege_field_changes = [
            d
            for d in differences
            if d.category == DifferenceCategory.JSON
            and d.security_relevant
            and any(hint in d.path.lower() for hint in _IDENTITY_PATH_HINTS)
        ]

        newly_visible_fields = [
            d
            for d in differences
            if d.category == DifferenceCategory.JSON and d.change_type.value == "added"
        ]

        session_cookie_stable = not any(
            d.category == DifferenceCategory.COOKIES and "session" in d.path.lower() for d in differences
        )

        evidence_count = sum(
            [
                became_successful,
                bool(privilege_field_changes),
                bool(newly_visible_fields),
                session_cookie_stable and became_successful,
            ]
        )

        if became_successful and (privilege_field_changes or newly_visible_fields):
            confidence = Confidence.HIGH if evidence_count >= 3 else Confidence.MEDIUM
            evidence = [f"Baseline status: {b_status}", f"Candidate status: {c_status}"]
            if privilege_field_changes:
                evidence.append(
                    f"Candidate contains changed privilege/role fields: "
                    f"{', '.join(d.path for d in privilege_field_changes[:5])}"
                )
            if newly_visible_fields:
                evidence.append(
                    f"Candidate exposes additional fields: "
                    f"{', '.join(d.path for d in newly_visible_fields[:5])}"
                )
            if session_cookie_stable:
                evidence.append("Session cookie fingerprint appears unchanged")

            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    title=self.title,
                    category=DifferenceCategory.AUTHORIZATION,
                    severity=Severity.MEDIUM,
                    confidence=confidence,
                    summary=(
                        "Access that was previously denied now succeeds and returns "
                        "additional or privileged data."
                    ),
                    evidence=evidence,
                    recommendation=(
                        "Manually verify whether the candidate request should be authorized "
                        "for the acting principal. Check object-level and function-level "
                        "access control independently."
                    ),
                    false_positive_notes=(
                        "This finding does not confirm an authorization bypass. It may "
                        "reflect an intended state change (e.g. the user logged in between "
                        "requests, or was legitimately granted new permissions)."
                    ),
                )
            )
        return findings
