"""Suppresses the diffs that are just dynamic noise (timestamps, request
IDs, etc). Original values are always kept around - we mark things as
suppressed, we don't delete them."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

# Headers that are dynamic by nature and safe to normalize/ignore by default.
DEFAULT_DYNAMIC_HEADERS: frozenset[str] = frozenset(
    h.lower()
    for h in [
        "Date",
        "Server-Timing",
        "X-Request-ID",
        "X-Correlation-ID",
        "X-Trace-ID",
        "Traceparent",
        "Tracestate",
        "CF-Ray",
        "X-Amzn-Trace-Id",
        "X-Served-By",
        "X-Cache-Hits",
        "X-Timer",
    ]
)

# Age is intentionally excluded from DEFAULT_DYNAMIC_HEADERS: it is dynamic
# but meaningful cache-behavior changes must remain visible (see caching
# analyzer), so it is only normalized for *numeric noise*, never suppressed
# outright.

_UUID_RE = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
)
_TIMESTAMP_RE = re.compile(
    r"\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b"
)
_RFC1123_DATE_RE = re.compile(
    r"\b(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun), \d{2} "
    r"(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{4} "
    r"\d{2}:\d{2}:\d{2} GMT\b"
)
_UNIX_TS_RE = re.compile(r"\b1\d{9}\b")
_NONCE_LIKE_RE = re.compile(r"\b[A-Za-z0-9+/]{20,}={0,2}\b")


@dataclass
class NormalizationResult:
    original: str
    normalized: str
    reasons: list[str] = field(default_factory=list)

    @property
    def changed(self) -> bool:
        return self.original != self.normalized


def normalize_whitespace(value: str) -> str:
    return re.sub(r"[ \t]+", " ", value.strip())


def normalize_line_endings(text: str) -> str:
    return text.replace("\r\n", "\n").replace("\r", "\n")


def normalize_value(value: str, *, extra_regexes: list[str] | None = None) -> NormalizationResult:
    """Apply generic dynamic-value normalization to a single header/text value."""
    reasons: list[str] = []
    result = value

    if _UUID_RE.search(result):
        result = _UUID_RE.sub("<uuid>", result)
        reasons.append("UUID-like value normalized")
    if _TIMESTAMP_RE.search(result):
        result = _TIMESTAMP_RE.sub("<timestamp>", result)
        reasons.append("ISO timestamp normalized")
    if _RFC1123_DATE_RE.search(result):
        result = _RFC1123_DATE_RE.sub("<http-date>", result)
        reasons.append("HTTP date normalized")
    if _UNIX_TS_RE.search(result):
        result = _UNIX_TS_RE.sub("<unix-timestamp>", result)
        reasons.append("Unix timestamp normalized")

    for pattern in extra_regexes or []:
        try:
            if re.search(pattern, result):
                result = re.sub(pattern, "<ignored>", result)
                reasons.append(f"matched custom ignore-regex: {pattern}")
        except re.error:
            continue

    normalized_ws = normalize_whitespace(result)
    if normalized_ws != result:
        reasons.append("whitespace normalized")
        result = normalized_ws

    return NormalizationResult(original=value, normalized=result, reasons=reasons)


def normalize_json_text(text: str) -> str:
    """Re-serialize JSON with sorted keys and stable separators so that pure
    formatting differences do not appear as changes."""
    try:
        parsed = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return text
    return json.dumps(parsed, sort_keys=True, separators=(",", ":"))


def is_dynamic_header(name: str, *, extra_ignored: frozenset[str] = frozenset()) -> bool:
    lname = name.lower()
    return lname in DEFAULT_DYNAMIC_HEADERS or lname in extra_ignored


def normalize_cookie_attribute_order(raw_cookie: str) -> str:
    """Sort cookie attributes (excluding the leading name=value pair) so
    attribute ordering does not create false diffs."""
    parts = [p.strip() for p in raw_cookie.split(";")]
    if not parts:
        return raw_cookie
    head, *attrs = parts
    attrs_sorted = sorted(a.lower() for a in attrs if a)
    return "; ".join([head] + attrs_sorted)
