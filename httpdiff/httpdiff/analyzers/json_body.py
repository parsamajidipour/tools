"""JSON diff, JSONPath-style. Flags role/permission/identity-looking
fields as security-relevant."""

from __future__ import annotations

import fnmatch
from typing import Any

from ..models import ChangeType, Difference, DifferenceCategory
from ..redaction import is_sensitive_json_key, redact_json_value

_IDENTITY_KEY_HINTS = frozenset(
    [
        "role",
        "roles",
        "permission",
        "permissions",
        "privilege",
        "privileges",
        "is_admin",
        "isadmin",
        "admin",
        "authenticated",
        "user_id",
        "userid",
        "account_id",
        "accountid",
        "scope",
        "scopes",
        "email",
        "username",
    ]
)


def _is_identity_key(key: str) -> bool:
    return key.lower() in _IDENTITY_KEY_HINTS


def _matches_ignored(path: str, ignore_paths: list[str]) -> bool:
    return any(fnmatch.fnmatch(path, pattern) for pattern in ignore_paths)


def _json_path(parent: str, key: Any) -> str:
    if isinstance(key, int):
        return f"{parent}[{key}]"
    return f"{parent}.{key}" if parent else f"$.{key}"


def diff_json(
    baseline: Any,
    candidate: Any,
    *,
    path: str = "$",
    ignore_paths: list[str] | None = None,
    show_secrets: bool = False,
) -> list[Difference]:
    ignore_paths = ignore_paths or []
    diffs: list[Difference] = []
    _diff_json_value(baseline, candidate, path, diffs, ignore_paths, show_secrets)
    return diffs


def _diff_json_value(
    b: Any,
    c: Any,
    path: str,
    diffs: list[Difference],
    ignore_paths: list[str],
    show_secrets: bool,
) -> None:
    if _matches_ignored(path, ignore_paths):
        return

    if type(b) is not type(c) and not (_is_number(b) and _is_number(c)):
        key = path.rsplit(".", 1)[-1].rsplit("[", 1)[0]
        diffs.append(
            Difference(
                category=DifferenceCategory.JSON,
                path=path,
                change_type=ChangeType.MODIFIED,
                baseline_value=_safe(key, b, show_secrets),
                candidate_value=_safe(key, c, show_secrets),
                description=f"{path}: type changed from {type(b).__name__} to {type(c).__name__}",
                security_relevant=_is_identity_key(key),
                redacted=is_sensitive_json_key(key) and not show_secrets,
            )
        )
        return

    if isinstance(b, dict) and isinstance(c, dict):
        all_keys = sorted(set(b) | set(c))
        for key in all_keys:
            child_path = _json_path(path, key)
            if _matches_ignored(child_path, ignore_paths):
                continue
            if key not in b:
                diffs.append(
                    Difference(
                        category=DifferenceCategory.JSON,
                        path=child_path,
                        change_type=ChangeType.ADDED,
                        baseline_value=None,
                        candidate_value=_safe(key, c[key], show_secrets),
                        description=f'{child_path}: field added ("{key}")',
                        security_relevant=_is_identity_key(key),
                        redacted=is_sensitive_json_key(key) and not show_secrets,
                    )
                )
            elif key not in c:
                diffs.append(
                    Difference(
                        category=DifferenceCategory.JSON,
                        path=child_path,
                        change_type=ChangeType.REMOVED,
                        baseline_value=_safe(key, b[key], show_secrets),
                        candidate_value=None,
                        description=f"{child_path}: field became missing",
                        security_relevant=_is_identity_key(key),
                        redacted=is_sensitive_json_key(key) and not show_secrets,
                    )
                )
            else:
                _diff_json_value(b[key], c[key], child_path, diffs, ignore_paths, show_secrets)
        return

    if isinstance(b, list) and isinstance(c, list):
        max_len = max(len(b), len(c))
        for i in range(max_len):
            child_path = _json_path(path, i)
            if _matches_ignored(child_path, ignore_paths):
                continue
            if i >= len(b):
                diffs.append(
                    Difference(
                        category=DifferenceCategory.JSON,
                        path=child_path,
                        change_type=ChangeType.ADDED,
                        baseline_value=None,
                        candidate_value=c[i],
                        description=f"{child_path}: added {c[i]!r}",
                    )
                )
            elif i >= len(c):
                diffs.append(
                    Difference(
                        category=DifferenceCategory.JSON,
                        path=child_path,
                        change_type=ChangeType.REMOVED,
                        baseline_value=b[i],
                        candidate_value=None,
                        description=f"{child_path}: removed {b[i]!r}",
                    )
                )
            else:
                _diff_json_value(b[i], c[i], child_path, diffs, ignore_paths, show_secrets)
        return

    if b != c:
        key = path.rsplit(".", 1)[-1].rsplit("[", 1)[0]
        null_transition = (b is None) != (c is None)
        diffs.append(
            Difference(
                category=DifferenceCategory.JSON,
                path=path,
                change_type=ChangeType.MODIFIED,
                baseline_value=_safe(key, b, show_secrets),
                candidate_value=_safe(key, c, show_secrets),
                description=(
                    f"{path}: became {'visible' if b is None else 'null'}"
                    if null_transition
                    else f"{path}: {b!r} -> {c!r}"
                ),
                security_relevant=_is_identity_key(key),
                redacted=is_sensitive_json_key(key) and not show_secrets,
            )
        )


def _is_number(v: Any) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def _safe(key: str, value: Any, show_secrets: bool) -> Any:
    return redact_json_value(key, value, show_secrets=show_secrets)
