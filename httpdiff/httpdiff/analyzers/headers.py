"""Semantic header comparison."""

from __future__ import annotations

from ..models import ChangeType, Difference, DifferenceCategory, HeaderCollection
from ..normalization import is_dynamic_header, normalize_value
from ..redaction import SENSITIVE_HEADER_NAMES, fingerprint

SECURITY_HEADERS = frozenset(
    h.lower()
    for h in [
        "Content-Security-Policy",
        "Content-Security-Policy-Report-Only",
        "Strict-Transport-Security",
        "X-Content-Type-Options",
        "X-Frame-Options",
        "Referrer-Policy",
        "Permissions-Policy",
        "Cross-Origin-Opener-Policy",
        "Cross-Origin-Embedder-Policy",
        "Cross-Origin-Resource-Policy",
    ]
)

CACHING_HEADERS = frozenset(
    h.lower()
    for h in [
        "Cache-Control",
        "Pragma",
        "Expires",
        "Age",
        "ETag",
        "Last-Modified",
        "Vary",
        "Surrogate-Control",
        "CDN-Cache-Control",
        "Cloudflare-CDN-Cache-Control",
        "X-Cache",
        "X-Cache-Hits",
        "CF-Cache-Status",
        "X-Served-By",
        "Via",
    ]
)

CORS_HEADERS = frozenset(
    h.lower()
    for h in [
        "Access-Control-Allow-Origin",
        "Access-Control-Allow-Credentials",
        "Access-Control-Allow-Headers",
        "Access-Control-Allow-Methods",
        "Access-Control-Expose-Headers",
        "Access-Control-Max-Age",
    ]
)

AUTH_HEADERS = frozenset(
    h.lower()
    for h in ["WWW-Authenticate", "Authorization", "Proxy-Authenticate", "Authentication-Info"]
)


def _categorize(name: str) -> str:
    lname = name.lower()
    if lname in SECURITY_HEADERS:
        return "security"
    if lname in CACHING_HEADERS:
        return "caching"
    if lname in CORS_HEADERS:
        return "cors"
    if lname in AUTH_HEADERS:
        return "authentication"
    return "general"


def analyze_headers(
    baseline: HeaderCollection,
    candidate: HeaderCollection,
    *,
    ignore_headers: frozenset[str] = frozenset(),
    include_headers: frozenset[str] | None = None,
    extra_ignore_regexes: list[str] | None = None,
    show_secrets: bool = False,
) -> list[Difference]:
    diffs: list[Difference] = []
    all_names = {n.lower(): n for n in baseline.names()}
    all_names.update({n.lower(): n for n in candidate.names()})

    for lname, display_name in sorted(all_names.items()):
        if include_headers is not None and lname not in include_headers:
            continue
        if lname in ignore_headers:
            continue

        b_values = sorted(baseline.get_all(display_name))
        c_values = sorted(candidate.get_all(display_name))
        category = _categorize(display_name)

        if b_values == c_values:
            continue

        dynamic = is_dynamic_header(display_name)
        b_norm = [normalize_value(v, extra_regexes=extra_ignore_regexes) for v in b_values]
        c_norm = [normalize_value(v, extra_regexes=extra_ignore_regexes) for v in c_values]
        b_norm_values = sorted(r.normalized for r in b_norm)
        c_norm_values = sorted(r.normalized for r in c_norm)

        is_sensitive = lname in SENSITIVE_HEADER_NAMES
        display_b_values = b_values if show_secrets or not is_sensitive else [fingerprint(v) for v in b_values]
        display_c_values = c_values if show_secrets or not is_sensitive else [fingerprint(v) for v in c_values]

        if not b_values:
            change_type = ChangeType.ADDED
            description = f"Header added: {display_name}: {', '.join(display_c_values)}"
        elif not c_values:
            change_type = ChangeType.REMOVED
            description = f"Header removed: {display_name}"
        else:
            change_type = ChangeType.MODIFIED
            description = (
                f"{display_name} changed from {', '.join(display_b_values)} to "
                f"{', '.join(display_c_values)}"
            )

        suppressed = dynamic and b_norm_values == c_norm_values
        security_relevant = category == "security" and change_type == ChangeType.REMOVED

        diff = Difference(
            category=DifferenceCategory.HEADERS,
            path=display_name,
            change_type=change_type,
            baseline_value=display_b_values,
            candidate_value=display_c_values,
            description=description,
            suppressed=suppressed,
            suppression_reason=(
                "dynamic header normalized to an equal value" if suppressed else None
            ),
            normalized=bool(b_norm_values != b_values or c_norm_values != c_values),
            original_baseline_value=b_values if show_secrets or not is_sensitive else None,
            original_candidate_value=c_values if show_secrets or not is_sensitive else None,
            security_relevant=security_relevant,
            redacted=is_sensitive and not show_secrets,
        )
        diffs.append(diff)

    return diffs
