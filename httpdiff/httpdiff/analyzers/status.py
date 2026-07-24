"""Status line and protocol comparison."""

from __future__ import annotations

from ..models import ChangeType, Difference, DifferenceCategory, HTTPResponse


def analyze_status(baseline: HTTPResponse, candidate: HTTPResponse) -> list[Difference]:
    diffs: list[Difference] = []

    if baseline.http_version != candidate.http_version:
        diffs.append(
            Difference(
                category=DifferenceCategory.PROTOCOL,
                path="http_version",
                change_type=ChangeType.MODIFIED,
                baseline_value=baseline.http_version,
                candidate_value=candidate.http_version,
                description=(
                    f"HTTP protocol version changed: {baseline.http_version} -> "
                    f"{candidate.http_version}"
                ),
            )
        )

    if baseline.status_code != candidate.status_code:
        b_class = baseline.status_class or "none"
        c_class = candidate.status_class or "none"
        class_note = " (status class changed)" if b_class != c_class else ""
        diffs.append(
            Difference(
                category=DifferenceCategory.STATUS,
                path="status_code",
                change_type=ChangeType.MODIFIED,
                baseline_value=baseline.status_code,
                candidate_value=candidate.status_code,
                description=(
                    f"Status changed: {baseline.status_code} -> {candidate.status_code}"
                    f"{class_note}"
                ),
                security_relevant=b_class != c_class,
            )
        )

    baseline_empty = baseline.body.byte_length == 0
    candidate_empty = candidate.body.byte_length == 0
    if baseline_empty != candidate_empty:
        diffs.append(
            Difference(
                category=DifferenceCategory.BODY,
                path="body.presence",
                change_type=ChangeType.MODIFIED,
                baseline_value="empty" if baseline_empty else "non-empty",
                candidate_value="empty" if candidate_empty else "non-empty",
                description=(
                    "Response became empty"
                    if candidate_empty
                    else "Response gained a body where it previously had none"
                ),
            )
        )

    return diffs
