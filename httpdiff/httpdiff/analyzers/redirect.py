"""Redirect target and behavior comparison."""

from __future__ import annotations

from urllib.parse import urlsplit

from ..models import ChangeType, Difference, DifferenceCategory, HTTPResponse


def _is_redirect(response: HTTPResponse) -> bool:
    return response.status_code is not None and 300 <= response.status_code < 400


def analyze_redirect(baseline: HTTPResponse, candidate: HTTPResponse) -> list[Difference]:
    diffs: list[Difference] = []
    b_loc = baseline.headers.get_first("Location")
    c_loc = candidate.headers.get_first("Location")

    if not _is_redirect(baseline) and not _is_redirect(candidate):
        return diffs

    if b_loc == c_loc:
        return diffs

    if b_loc is None or c_loc is None:
        diffs.append(
            Difference(
                category=DifferenceCategory.REDIRECT,
                path="redirect.location",
                change_type=ChangeType.MODIFIED,
                baseline_value=b_loc,
                candidate_value=c_loc,
                description=f"Redirect Location header changed: {b_loc!r} -> {c_loc!r}",
                security_relevant=True,
            )
        )
        return diffs

    b_parts = urlsplit(b_loc)
    c_parts = urlsplit(c_loc)

    if c_parts.netloc and b_parts.netloc != c_parts.netloc:
        diffs.append(
            Difference(
                category=DifferenceCategory.REDIRECT,
                path="redirect.host",
                change_type=ChangeType.MODIFIED,
                baseline_value=b_parts.netloc,
                candidate_value=c_parts.netloc,
                description=(
                    f"Redirect target host changed: {b_parts.netloc or '(relative, no host)'} -> "
                    f"{c_parts.netloc}"
                ),
                security_relevant=True,
            )
        )
        diffs.append(
            Difference(
                category=DifferenceCategory.REDIRECT,
                path="redirect.cross_origin",
                change_type=ChangeType.MODIFIED,
                baseline_value=False,
                candidate_value=True,
                description="Redirect became cross-origin",
                security_relevant=True,
            )
        )

    if b_parts.scheme == "https" and c_parts.scheme == "http":
        diffs.append(
            Difference(
                category=DifferenceCategory.REDIRECT,
                path="redirect.scheme",
                change_type=ChangeType.MODIFIED,
                baseline_value=b_parts.scheme,
                candidate_value=c_parts.scheme,
                description="Redirect downgraded from HTTPS to HTTP",
                security_relevant=True,
            )
        )

    if b_parts.path != c_parts.path or b_parts.query != c_parts.query:
        diffs.append(
            Difference(
                category=DifferenceCategory.REDIRECT,
                path="redirect.path",
                change_type=ChangeType.MODIFIED,
                baseline_value=b_loc,
                candidate_value=c_loc,
                description=f"Redirect target changed: {b_loc} -> {c_loc}",
            )
        )

    if len(candidate.redirect_chain) != len(baseline.redirect_chain):
        diffs.append(
            Difference(
                category=DifferenceCategory.REDIRECT,
                path="redirect.chain_length",
                change_type=ChangeType.MODIFIED,
                baseline_value=len(baseline.redirect_chain),
                candidate_value=len(candidate.redirect_chain),
                description=(
                    f"Redirect chain length changed: {len(baseline.redirect_chain)} -> "
                    f"{len(candidate.redirect_chain)}"
                ),
            )
        )

    return diffs
