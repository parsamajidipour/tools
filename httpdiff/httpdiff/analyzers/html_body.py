"""HTML semantic diff analyzer. No JavaScript execution, no browser."""

from __future__ import annotations

from bs4 import BeautifulSoup

from ..models import ChangeType, Difference, DifferenceCategory

_INDICATOR_WORDS = ("login", "logout", "admin", "administration", "error", "debug", "traceback")


def _parse(html: str) -> BeautifulSoup:
    return BeautifulSoup(html, "lxml")


def _form_signature(form) -> tuple[str, str, tuple[str, ...]]:
    action = form.get("action", "") or ""
    method = (form.get("method", "get") or "get").lower()
    inputs = tuple(
        sorted(
            f"{i.get('type', 'text')}:{i.get('name', '')}"
            for i in form.find_all(["input", "select", "textarea"])
        )
    )
    return action, method, inputs


def analyze_html(baseline_text: str, candidate_text: str) -> list[Difference]:
    diffs: list[Difference] = []
    try:
        b_soup = _parse(baseline_text)
        c_soup = _parse(candidate_text)
    except Exception:
        return diffs

    b_title = b_soup.title.get_text(strip=True) if b_soup.title else None
    c_title = c_soup.title.get_text(strip=True) if c_soup.title else None
    if b_title != c_title:
        diffs.append(
            Difference(
                category=DifferenceCategory.HTML,
                path="html.title",
                change_type=ChangeType.MODIFIED,
                baseline_value=b_title,
                candidate_value=c_title,
                description=f"Page title changed from {b_title!r} to {c_title!r}",
            )
        )

    b_forms = {_form_signature(f) for f in b_soup.find_all("form")}
    c_forms = {_form_signature(f) for f in c_soup.find_all("form")}
    for action, method, inputs in c_forms - b_forms:
        has_password = any(i.startswith("password:") for i in inputs)
        diffs.append(
            Difference(
                category=DifferenceCategory.HTML,
                path=f"html.form[{action}]",
                change_type=ChangeType.ADDED,
                baseline_value=None,
                candidate_value=f"{method.upper()} {action}",
                description=(
                    f"New password input appeared in a form (action={action!r})"
                    if has_password
                    else f"Form action added or changed: {method.upper()} {action}"
                ),
                security_relevant=has_password,
            )
        )
    for action, method, inputs in b_forms - c_forms:
        diffs.append(
            Difference(
                category=DifferenceCategory.HTML,
                path=f"html.form[{action}]",
                change_type=ChangeType.REMOVED,
                baseline_value=f"{method.upper()} {action}",
                candidate_value=None,
                description=f"Form removed: {method.upper()} {action}",
            )
        )

    b_scripts = {s.get("src") for s in b_soup.find_all("script") if s.get("src")}
    c_scripts = {s.get("src") for s in c_soup.find_all("script") if s.get("src")}
    for src in c_scripts - b_scripts:
        external = src.startswith("http://") or src.startswith("https://") or src.startswith("//")
        diffs.append(
            Difference(
                category=DifferenceCategory.HTML,
                path=f"html.script[{src}]",
                change_type=ChangeType.ADDED,
                baseline_value=None,
                candidate_value=src,
                description=(
                    f"External script source was added: {src}"
                    if external
                    else f"Script source added: {src}"
                ),
                security_relevant=external,
            )
        )

    b_iframes = {i.get("src") for i in b_soup.find_all("iframe") if i.get("src")}
    c_iframes = {i.get("src") for i in c_soup.find_all("iframe") if i.get("src")}
    for src in c_iframes - b_iframes:
        diffs.append(
            Difference(
                category=DifferenceCategory.HTML,
                path=f"html.iframe[{src}]",
                change_type=ChangeType.ADDED,
                baseline_value=None,
                candidate_value=src,
                description=f"Iframe source added: {src}",
                security_relevant=True,
            )
        )

    b_meta_csp = b_soup.find("meta", attrs={"http-equiv": lambda v: v and v.lower() == "content-security-policy"})
    c_meta_csp = c_soup.find("meta", attrs={"http-equiv": lambda v: v and v.lower() == "content-security-policy"})
    if b_meta_csp and not c_meta_csp:
        diffs.append(
            Difference(
                category=DifferenceCategory.HTML,
                path="html.meta.csp",
                change_type=ChangeType.REMOVED,
                baseline_value=str(b_meta_csp),
                candidate_value=None,
                description="CSP meta element disappeared",
                security_relevant=True,
            )
        )

    b_text = b_soup.get_text(" ", strip=True).lower()
    c_text = c_soup.get_text(" ", strip=True).lower()
    for word in _INDICATOR_WORDS:
        b_has, c_has = word in b_text, word in c_text
        if not b_has and c_has:
            diffs.append(
                Difference(
                    category=DifferenceCategory.HTML,
                    path=f"html.indicator[{word}]",
                    change_type=ChangeType.ADDED,
                    baseline_value=None,
                    candidate_value=word,
                    description=(
                        f"Candidate contains additional {word!r} indicator text; "
                        "possible debug/administration content"
                        if word in ("debug", "traceback", "admin", "administration")
                        else f"Candidate contains additional {word!r} indicator text"
                    ),
                    security_relevant=word in ("debug", "traceback", "admin", "administration"),
                )
            )

    return diffs
