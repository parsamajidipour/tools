"""Cookie security-attribute comparison."""

from __future__ import annotations

from ..models import ChangeType, Cookie, Difference, DifferenceCategory
from ..redaction import fingerprint

_SAME_SITE_STRENGTH = {"strict": 2, "lax": 1, "none": 0}


def _same_site_rank(value: str | None) -> int:
    if value is None:
        return 1  # browsers default missing SameSite to Lax-like behavior
    return _SAME_SITE_STRENGTH.get(value.lower(), 1)


def _domain_is_broader(old: str | None, new: str | None) -> bool:
    if old == new:
        return False
    if old is None and new is not None:
        return True  # host-only cookie became domain cookie
    if old is not None and new is not None:
        return new.lstrip(".").count(".") < old.lstrip(".").count(".") and new in old
    return False


def _path_is_broader(old: str | None, new: str | None) -> bool:
    old = old or "/"
    new = new or "/"
    return new == "/" and old != "/"


def analyze_cookies(
    baseline: list[Cookie],
    candidate: list[Cookie],
    *,
    ignore_cookies: frozenset[str] = frozenset(),
    show_secrets: bool = False,
) -> list[Difference]:
    diffs: list[Difference] = []
    b_by_name = {c.name: c for c in baseline}
    c_by_name = {c.name: c for c in candidate}
    all_names = sorted(set(b_by_name) | set(c_by_name))

    for name in all_names:
        if name in ignore_cookies:
            continue
        b_cookie = b_by_name.get(name)
        c_cookie = c_by_name.get(name)

        if b_cookie is None:
            diffs.append(
                Difference(
                    category=DifferenceCategory.COOKIES,
                    path=f"cookie:{name}",
                    change_type=ChangeType.ADDED,
                    baseline_value=None,
                    candidate_value=fingerprint(c_cookie.value) if not show_secrets else c_cookie.value,
                    description=f"Cookie added: {name}",
                    redacted=not show_secrets,
                )
            )
            continue
        if c_cookie is None:
            diffs.append(
                Difference(
                    category=DifferenceCategory.COOKIES,
                    path=f"cookie:{name}",
                    change_type=ChangeType.REMOVED,
                    baseline_value=fingerprint(b_cookie.value) if not show_secrets else b_cookie.value,
                    candidate_value=None,
                    description=f"Cookie removed: {name}",
                    redacted=not show_secrets,
                    security_relevant=True,
                )
            )
            continue

        if b_cookie.value != c_cookie.value:
            diffs.append(
                Difference(
                    category=DifferenceCategory.COOKIES,
                    path=f"cookie:{name}.value",
                    change_type=ChangeType.MODIFIED,
                    baseline_value=fingerprint(b_cookie.value),
                    candidate_value=fingerprint(c_cookie.value),
                    description=f"Session cookie value changed and was redacted: {name}",
                    redacted=True,
                )
            )

        if b_cookie.secure and not c_cookie.secure:
            diffs.append(
                Difference(
                    category=DifferenceCategory.COOKIES,
                    path=f"cookie:{name}.secure",
                    change_type=ChangeType.MODIFIED,
                    baseline_value=True,
                    candidate_value=False,
                    description=f"Secure attribute was removed from cookie {name}",
                    security_relevant=True,
                )
            )

        if b_cookie.http_only and not c_cookie.http_only:
            diffs.append(
                Difference(
                    category=DifferenceCategory.COOKIES,
                    path=f"cookie:{name}.httponly",
                    change_type=ChangeType.MODIFIED,
                    baseline_value=True,
                    candidate_value=False,
                    description=f"HttpOnly attribute was removed from cookie {name}",
                    security_relevant=True,
                )
            )

        if _same_site_rank(c_cookie.same_site) < _same_site_rank(b_cookie.same_site):
            diffs.append(
                Difference(
                    category=DifferenceCategory.COOKIES,
                    path=f"cookie:{name}.samesite",
                    change_type=ChangeType.MODIFIED,
                    baseline_value=b_cookie.same_site,
                    candidate_value=c_cookie.same_site,
                    description=(
                        f"SameSite became weaker for cookie {name}: "
                        f"{b_cookie.same_site} -> {c_cookie.same_site}"
                    ),
                    security_relevant=True,
                )
            )

        if _domain_is_broader(b_cookie.domain, c_cookie.domain):
            diffs.append(
                Difference(
                    category=DifferenceCategory.COOKIES,
                    path=f"cookie:{name}.domain",
                    change_type=ChangeType.MODIFIED,
                    baseline_value=b_cookie.domain,
                    candidate_value=c_cookie.domain,
                    description=f"Cookie domain became broader for {name}",
                    security_relevant=True,
                )
            )

        if _path_is_broader(b_cookie.path, c_cookie.path):
            diffs.append(
                Difference(
                    category=DifferenceCategory.COOKIES,
                    path=f"cookie:{name}.path",
                    change_type=ChangeType.MODIFIED,
                    baseline_value=b_cookie.path,
                    candidate_value=c_cookie.path,
                    description=f"Cookie path became broader for {name}",
                    security_relevant=True,
                )
            )

        for violation in c_cookie.prefix_violations():
            diffs.append(
                Difference(
                    category=DifferenceCategory.COOKIES,
                    path=f"cookie:{name}.prefix",
                    change_type=ChangeType.MODIFIED,
                    baseline_value=None,
                    candidate_value=violation,
                    description=violation,
                    security_relevant=True,
                )
            )

    return diffs
