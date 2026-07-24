"""Redaction helpers. Nothing here writes a real secret out unless the
caller passed --show-secrets."""

from __future__ import annotations

import hashlib
import re

SENSITIVE_JSON_KEY_PATTERNS: tuple[str, ...] = (
    "password",
    "passwd",
    "secret",
    "token",
    "access_token",
    "refresh_token",
    "api_key",
    "apikey",
    "authorization",
    "session",
    "private_key",
)

SENSITIVE_HEADER_NAMES: frozenset[str] = frozenset(
    h.lower() for h in ["Authorization", "Proxy-Authorization", "Cookie", "Set-Cookie"]
)

_SENSITIVE_KEY_RE = re.compile(
    "|".join(re.escape(p) for p in SENSITIVE_JSON_KEY_PATTERNS), re.IGNORECASE
)


def is_sensitive_json_key(key: str) -> bool:
    return bool(_SENSITIVE_KEY_RE.search(key))


def fingerprint(value: str, *, length: int = 8) -> str:
    """Return a short, non-reversible fingerprint suitable for display."""
    digest = hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()
    return f"sha256:{digest[:length]}..."


def redact_cookie_value(name: str, value: str, *, show_secrets: bool) -> str:
    if show_secrets:
        return value
    return fingerprint(value)


def redact_header_value(name: str, value: str, *, show_secrets: bool) -> str:
    if show_secrets:
        return value
    if name.lower() in SENSITIVE_HEADER_NAMES:
        return fingerprint(value)
    return value


def redact_json_value(key: str, value: object, *, show_secrets: bool) -> object:
    if show_secrets:
        return value
    if is_sensitive_json_key(key):
        return fingerprint(str(value))
    return value
