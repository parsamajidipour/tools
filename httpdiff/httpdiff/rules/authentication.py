"""Authentication heuristics. Combines a few weak signals (status change,
WWW-Authenticate, cookie changes) into one finding - never claims auth was
actually bypassed, just that the behavior changed."""

from __future__ import annotations

from ..models import Confidence, Difference, DifferenceCategory, Finding, HTTPResponse, Severity
from .base import Rule

_AUTH_STATUS_CODES = {401, 403}


class AuthenticationBehaviorChangedRule(Rule):
    rule_id = "HTTPDIFF-AUTHN-001"
    title = "Authentication-related behavior changed"

    def evaluate(
        self, *, baseline: HTTPResponse, candidate: HTTPResponse, differences: list[Difference]
    ) -> list[Finding]:
        findings: list[Finding] = []

        b_status, c_status = baseline.status_code, candidate.status_code
        status_signal = (
            b_status in _AUTH_STATUS_CODES or c_status in _AUTH_STATUS_CODES
        ) and b_status != c_status

        www_auth_changed = baseline.headers.get_first("WWW-Authenticate") != candidate.headers.get_first(
            "WWW-Authenticate"
        )

        session_cookie_changed = any(
            d.category == DifferenceCategory.COOKIES
            and "session" in d.path.lower()
            and d.change_type.value in ("added", "removed", "modified")
            for d in differences
        )

        signals = [status_signal, www_auth_changed, session_cookie_changed]
        active_signals = sum(1 for s in signals if s)

        if active_signals >= 2:
            confidence = Confidence.MEDIUM if active_signals == 2 else Confidence.HIGH
            evidence = []
            if status_signal:
                evidence.append(f"Status changed: {b_status} -> {c_status}")
            if www_auth_changed:
                evidence.append("WWW-Authenticate header changed")
            if session_cookie_changed:
                evidence.append("Session cookie changed")

            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    title=self.title,
                    category=DifferenceCategory.AUTHENTICATION,
                    severity=Severity.LOW,
                    confidence=confidence,
                    summary=(
                        "Multiple authentication-related signals changed between baseline "
                        "and candidate responses."
                    ),
                    evidence=evidence,
                    recommendation=(
                        "Manually verify whether this reflects an intended login/logout "
                        "transition or an unexpected authentication state change."
                    ),
                    false_positive_notes=(
                        "These signals commonly change during normal login/logout flows; "
                        "this finding does not by itself indicate a vulnerability."
                    ),
                )
            )
        return findings
