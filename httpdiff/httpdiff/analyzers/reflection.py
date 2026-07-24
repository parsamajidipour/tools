"""Looks for an attacker-supplied marker in the response, in a bunch of
common encodings, and reports where it turned up."""

from __future__ import annotations

import base64
import html
import json
import re
import urllib.parse
from dataclasses import dataclass

from ..models import HTTPResponse


@dataclass
class ReflectionMatch:
    value: str
    location: str
    encoding: str
    context: str
    note: str


def _encodings_for(value: str) -> list[tuple[str, str]]:
    variants: list[tuple[str, str]] = [("none", value)]
    variants.append(("url-encoded", urllib.parse.quote(value)))
    variants.append(("html-encoded", html.escape(value)))
    variants.append(("json-escaped", json.dumps(value)[1:-1]))
    variants.append(("unicode-escaped", value.encode("unicode_escape").decode("ascii")))
    try:
        variants.append(("base64", base64.b64encode(value.encode()).decode()))
    except Exception:  # pragma: no cover - defensive
        pass
    variants.append(("uppercase", value.upper()))
    variants.append(("lowercase", value.lower()))
    return variants


def _guess_context(text: str, index: int, length: int) -> str:
    window_start = max(0, index - 40)
    window_end = min(len(text), index + length + 40)
    snippet = text[window_start:window_end]
    before = text[max(0, index - 15):index]
    if re.search(r'=["\']$', before):
        return "HTML attribute"
    if "<script" in text[max(0, index - 300):index].lower():
        return "script block"
    if before.rstrip().endswith(("{", ",", ":")):
        return "JSON string"
    if "<" in snippet and ">" in snippet:
        return "HTML text"
    return "plain text"


def _security_note(location: str, encoding: str) -> str:
    if location == "HTML attribute" and encoding == "none":
        return "unencoded reflection in an HTML attribute requires manual XSS verification"
    if location == "HTML text" and encoding == "none":
        return "unencoded reflection in HTML body text requires manual XSS verification"
    if location == "script block":
        return "reflection inside a script block requires manual XSS verification"
    if location == "JSON string":
        return "reflection in a JSON string is unlikely to be directly exploitable but may affect downstream consumers"
    return "reflection detected; manual verification recommended"


def detect_reflection(response: HTTPResponse, marker: str) -> list[ReflectionMatch]:
    if not marker:
        return []
    matches: list[ReflectionMatch] = []
    variants = _encodings_for(marker)

    for name in response.headers.names():
        for value in response.headers.get_all(name):
            for encoding, needle in variants:
                if needle and needle in value:
                    matches.append(
                        ReflectionMatch(
                            value=marker,
                            location="response header",
                            encoding=encoding,
                            context=f"{name}: {value}",
                            note="reflection in a response header requires manual verification",
                        )
                    )

    for cookie in response.cookies:
        for encoding, needle in variants:
            if needle and needle in cookie.value:
                matches.append(
                    ReflectionMatch(
                        value=marker,
                        location="cookie",
                        encoding=encoding,
                        context=f"{cookie.name}=<redacted>",
                        note="reflection in a cookie value requires manual verification",
                    )
                )

    text = response.body.text or ""
    if text:
        seen_spans: set[tuple[int, str]] = set()
        for encoding, needle in variants:
            if not needle:
                continue
            for m in re.finditer(re.escape(needle), text):
                key = (m.start(), encoding)
                if key in seen_spans:
                    continue
                seen_spans.add(key)
                location = _guess_context(text, m.start(), len(needle))
                matches.append(
                    ReflectionMatch(
                        value=marker,
                        location=location,
                        encoding=encoding,
                        context=text[max(0, m.start() - 20):m.end() + 20],
                        note=_security_note(location, encoding),
                    )
                )

    return matches
