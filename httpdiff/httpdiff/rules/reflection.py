"""Turns reflection matches (from analyzers/reflection.py) into Findings."""

from __future__ import annotations

from ..analyzers.reflection import ReflectionMatch
from ..models import Confidence, DifferenceCategory, Finding, Severity


def build_reflection_findings(matches: list[ReflectionMatch]) -> list[Finding]:
    findings: list[Finding] = []
    for match in matches:
        risky_context = match.location in ("HTML attribute", "HTML text", "script block")
        severity = Severity.LOW if risky_context else Severity.INFO
        confidence = Confidence.MEDIUM if (risky_context and match.encoding == "none") else Confidence.LOW
        findings.append(
            Finding(
                rule_id="HTTPDIFF-REFLECT-001",
                title="Potential reflection detected",
                category=DifferenceCategory.REFLECTION,
                severity=severity,
                confidence=confidence,
                summary=f"Reflection of the supplied marker was found in {match.location} ({match.encoding}).",
                evidence=[
                    f"Location: {match.location}",
                    f"Encoding: {match.encoding}",
                    f"Context: {match.context}",
                ],
                recommendation=match.note,
                false_positive_notes=(
                    "Reflection alone does not confirm an injection vulnerability; "
                    "output-context encoding and sanitization must be verified manually."
                ),
            )
        )
    return findings
