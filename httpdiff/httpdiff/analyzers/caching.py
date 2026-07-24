"""Cache-behavior semantic comparison."""

from __future__ import annotations

from ..models import ChangeType, Difference, DifferenceCategory, HTTPResponse


def _parse_cache_control(value: str | None) -> dict[str, str | bool]:
    directives: dict[str, str | bool] = {}
    if not value:
        return directives
    for part in value.split(","):
        part = part.strip()
        if not part:
            continue
        if "=" in part:
            k, v = part.split("=", 1)
            directives[k.strip().lower()] = v.strip()
        else:
            directives[part.lower()] = True
    return directives


def analyze_caching(baseline: HTTPResponse, candidate: HTTPResponse) -> list[Difference]:
    diffs: list[Difference] = []
    b_cc = _parse_cache_control(baseline.headers.get_first("Cache-Control"))
    c_cc = _parse_cache_control(candidate.headers.get_first("Cache-Control"))

    if b_cc.get("private") and c_cc.get("public"):
        diffs.append(
            Difference(
                category=DifferenceCategory.CACHING,
                path="cache-control.visibility",
                change_type=ChangeType.MODIFIED,
                baseline_value="private",
                candidate_value="public",
                description="Response became publicly cacheable (private -> public)",
                security_relevant=True,
            )
        )

    if b_cc.get("no-store") and not c_cc.get("no-store"):
        diffs.append(
            Difference(
                category=DifferenceCategory.CACHING,
                path="cache-control.no-store",
                change_type=ChangeType.REMOVED,
                baseline_value=True,
                candidate_value=False,
                description="no-store was removed from Cache-Control",
                security_relevant=True,
            )
        )

    b_vary = {v.strip().lower() for v in (baseline.headers.get_first("Vary") or "").split(",") if v.strip()}
    c_vary = {v.strip().lower() for v in (candidate.headers.get_first("Vary") or "").split(",") if v.strip()}
    if b_vary != c_vary:
        removed_sensitive = {"cookie", "authorization"} & (b_vary - c_vary)
        diffs.append(
            Difference(
                category=DifferenceCategory.CACHING,
                path="vary",
                change_type=ChangeType.MODIFIED,
                baseline_value=sorted(b_vary),
                candidate_value=sorted(c_vary),
                description=(
                    f"Vary changed and no longer includes {', '.join(sorted(removed_sensitive))}"
                    if removed_sensitive
                    else "Vary header changed"
                ),
                security_relevant=bool(removed_sensitive),
            )
        )

    b_cdn = baseline.headers.get_first("X-Cache") or baseline.headers.get_first("CF-Cache-Status")
    c_cdn = candidate.headers.get_first("X-Cache") or candidate.headers.get_first("CF-Cache-Status")
    if b_cdn and c_cdn and b_cdn.upper() != c_cdn.upper():
        if "MISS" in b_cdn.upper() and "HIT" in c_cdn.upper():
            diffs.append(
                Difference(
                    category=DifferenceCategory.CACHING,
                    path="cdn.status",
                    change_type=ChangeType.MODIFIED,
                    baseline_value=b_cdn,
                    candidate_value=c_cdn,
                    description="CDN status changed from MISS to HIT",
                )
            )

    b_etag = baseline.headers.get_first("ETag")
    c_etag = candidate.headers.get_first("ETag")
    body_changed = baseline.body.sha256 != candidate.body.sha256
    if b_etag and c_etag:
        if b_etag == c_etag and body_changed:
            diffs.append(
                Difference(
                    category=DifferenceCategory.CACHING,
                    path="etag.stability",
                    change_type=ChangeType.MODIFIED,
                    baseline_value=b_etag,
                    candidate_value=c_etag,
                    description="ETag remained stable while body changed",
                    security_relevant=True,
                )
            )
        elif b_etag != c_etag and not body_changed:
            diffs.append(
                Difference(
                    category=DifferenceCategory.CACHING,
                    path="etag.stability",
                    change_type=ChangeType.MODIFIED,
                    baseline_value=b_etag,
                    candidate_value=c_etag,
                    description="Body remained stable while ETag changed",
                )
            )

    # Personalized-data-in-public-cache heuristic (evidence only; the rule
    # engine turns this into a formal Finding).
    has_personal_field = False
    if candidate.body.parsed_json is not None:
        has_personal_field = _contains_identity_field(candidate.body.parsed_json)
    if c_cc.get("public") and has_personal_field and "cookie" not in c_vary and "authorization" not in c_vary:
        diffs.append(
            Difference(
                category=DifferenceCategory.CACHING,
                path="cache.personalization_risk",
                change_type=ChangeType.MODIFIED,
                baseline_value=None,
                candidate_value="public + personalized + Vary missing Cookie/Authorization",
                description="Personalized data appears in a public-cacheable response",
                security_relevant=True,
            )
        )

    return diffs


def _contains_identity_field(obj: object, depth: int = 0) -> bool:
    if depth > 6:
        return False
    hints = {"role", "email", "username", "user_id", "account_id", "token", "session"}
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k.lower() in hints:
                return True
            if _contains_identity_field(v, depth + 1):
                return True
    elif isinstance(obj, list):
        return any(_contains_identity_field(i, depth + 1) for i in obj)
    return False
