"""Generic body metadata comparison (applies regardless of content type)."""

from __future__ import annotations

import difflib

from ..models import BodyAnalysis, ChangeType, Difference, DifferenceCategory


def compute_similarity(a: str, b: str) -> float:
    if not a and not b:
        return 1.0
    return difflib.SequenceMatcher(None, a, b, autojunk=False).ratio()


def analyze_body_metadata(baseline: BodyAnalysis, candidate: BodyAnalysis) -> list[Difference]:
    diffs: list[Difference] = []

    if baseline.sha256 != candidate.sha256:
        diffs.append(
            Difference(
                category=DifferenceCategory.BODY,
                path="body.hash",
                change_type=ChangeType.MODIFIED,
                baseline_value=baseline.sha256,
                candidate_value=candidate.sha256,
                description="Body content hash changed",
            )
        )

    if baseline.detected_type != candidate.detected_type:
        diffs.append(
            Difference(
                category=DifferenceCategory.BODY,
                path="body.content_type",
                change_type=ChangeType.MODIFIED,
                baseline_value=baseline.detected_type,
                candidate_value=candidate.detected_type,
                description=(
                    f"Detected body type changed: {baseline.detected_type} -> "
                    f"{candidate.detected_type}"
                ),
                security_relevant=True,
            )
        )

    if baseline.truncated or candidate.truncated:
        diffs.append(
            Difference(
                category=DifferenceCategory.BODY,
                path="body.truncated",
                change_type=ChangeType.MODIFIED,
                baseline_value=baseline.truncated,
                candidate_value=candidate.truncated,
                description="One or both bodies were truncated due to --max-body-size",
                suppressed=False,
            )
        )

    return diffs


def unified_text_diff(
    baseline_text: str, candidate_text: str, *, max_lines: int = 200
) -> list[str]:
    lines = list(
        difflib.unified_diff(
            baseline_text.splitlines(),
            candidate_text.splitlines(),
            fromfile="baseline",
            tofile="candidate",
            lineterm="",
        )
    )
    if len(lines) > max_lines:
        lines = lines[:max_lines] + [f"... diff truncated at {max_lines} lines ..."]
    return lines
