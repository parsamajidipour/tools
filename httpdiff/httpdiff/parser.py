"""Turns raw HTTP/1.x response bytes into an HTTPResponse.

Captured responses are often a little broken - missing status line, weird
line endings, whatever. We try to recover and note a warning rather than
blow up. Only truly empty/unusable input raises.
"""

from __future__ import annotations

import hashlib
import math
import re
import zlib
from collections import Counter
from http.cookies import SimpleCookie

from .exceptions import ParseError
from .models import BodyAnalysis, Cookie, HeaderCollection, HTTPResponse

_STATUS_LINE_RE = re.compile(
    r"^HTTP/(?P<version>\d(?:\.\d)?)\s+(?P<code>\d{3})(?:\s+(?P<reason>.*))?$"
)
_HEADER_LINE_RE = re.compile(r"^(?P<name>[!#$%&'*+\-.^_`|~0-9A-Za-z]+):[ \t]?(?P<value>.*)$")


def _split_headers_body(raw: bytes) -> tuple[bytes, bytes]:
    """Split raw response bytes into header block and body, tolerating
    both CRLFCRLF and LFLF separators."""
    for sep in (b"\r\n\r\n", b"\n\n"):
        idx = raw.find(sep)
        if idx != -1:
            return raw[:idx], raw[idx + len(sep):]
    # No blank-line separator found: treat entire input as headers-only
    # if it looks header-like, otherwise treat entire input as body.
    return raw, b""


def _looks_like_headers(block: str) -> bool:
    lines = [l for l in block.splitlines() if l.strip()]
    if not lines:
        return False
    header_like = sum(1 for l in lines[1:] if _HEADER_LINE_RE.match(l))
    return bool(_STATUS_LINE_RE.match(lines[0].strip())) or header_like >= max(1, len(lines) - 1)


def _decompress(body: bytes, content_encoding: str | None) -> tuple[bytes, str | None]:
    if not content_encoding:
        return body, None
    enc = content_encoding.lower().strip()
    try:
        if enc == "gzip":
            return zlib.decompress(body, zlib.MAX_WBITS | 16), None
        if enc == "deflate":
            try:
                return zlib.decompress(body), None
            except zlib.error:
                return zlib.decompress(body, -zlib.MAX_WBITS), None
        if enc == "br":
            try:
                import brotli  # type: ignore

                return brotli.decompress(body), None
            except Exception as exc:  # pragma: no cover - optional dependency
                return body, f"brotli decompression failed: {exc}"
    except Exception as exc:  # pragma: no cover - defensive
        return body, f"{enc} decompression failed: {exc}"
    return body, None


def _dechunk(body: bytes) -> tuple[bytes, str | None]:
    """Decode chunked transfer encoding if the body looks chunked."""
    out = bytearray()
    pos = 0
    try:
        while True:
            nl = body.find(b"\r\n", pos)
            if nl == -1:
                nl = body.find(b"\n", pos)
                if nl == -1:
                    return bytes(body), "chunked body ended unexpectedly"
                size_line = body[pos:nl]
                nl_len = 1
            else:
                size_line = body[pos:nl]
                nl_len = 2
            size_str = size_line.split(b";", 1)[0].strip()
            if not size_str:
                return bytes(body), "empty chunk size line"
            size = int(size_str, 16)
            pos = nl + nl_len
            if size == 0:
                return bytes(out), None
            chunk = body[pos:pos + size]
            out.extend(chunk)
            pos += size + nl_len  # skip trailing CRLF after chunk data
    except (ValueError, IndexError) as exc:
        return bytes(body), f"failed to dechunk body: {exc}"


def _detect_charset(headers: HeaderCollection, body: bytes) -> str:
    content_type = headers.get_first("Content-Type") or ""
    match = re.search(r"charset=([\w-]+)", content_type, re.IGNORECASE)
    if match:
        return match.group(1)
    try:
        import chardet  # type: ignore

        guess = chardet.detect(body[:4096])
        if guess and guess.get("encoding") and guess.get("confidence", 0) > 0.5:
            return str(guess["encoding"])
    except Exception:  # pragma: no cover - optional dependency
        pass
    return "utf-8"


def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def _detect_body_type(headers: HeaderCollection, text: str | None, raw: bytes) -> str:
    content_type = (headers.get_first("Content-Type") or "").lower()
    if "json" in content_type:
        return "json"
    if "html" in content_type:
        return "html"
    if "xml" in content_type:
        return "xml"
    if "javascript" in content_type or "ecmascript" in content_type:
        return "javascript"
    if "form-urlencoded" in content_type:
        return "form"
    if content_type.startswith("text/"):
        return "text"
    if text is not None:
        stripped = text.strip()
        if stripped.startswith("{") or stripped.startswith("["):
            return "json"
        if stripped.startswith("<") and ("<html" in stripped.lower() or "<!doctype" in stripped.lower()):
            return "html"
        if stripped.startswith("<?xml") or (stripped.startswith("<") and stripped.endswith(">")):
            return "xml"
        return "text"
    return "binary"


def parse_cookie_header(raw_value: str) -> Cookie:
    """Parse a single Set-Cookie header value into a Cookie model."""
    parts = [p.strip() for p in raw_value.split(";")]
    if not parts or "=" not in parts[0]:
        name, value = parts[0], ""
    else:
        name, value = parts[0].split("=", 1)
        name = name.strip()
        value = value.strip()

    cookie = Cookie(name=name, value=value, raw=raw_value)
    for attr in parts[1:]:
        attr = attr.strip()
        if not attr:
            continue
        if "=" in attr:
            key, val = attr.split("=", 1)
            key_lower = key.strip().lower()
            val = val.strip()
        else:
            key_lower = attr.lower()
            val = ""
        if key_lower == "domain":
            cookie.domain = val
        elif key_lower == "path":
            cookie.path = val
        elif key_lower == "expires":
            cookie.expires = val
        elif key_lower == "max-age":
            cookie.max_age = val
        elif key_lower == "secure":
            cookie.secure = True
        elif key_lower == "httponly":
            cookie.http_only = True
        elif key_lower == "samesite":
            cookie.same_site = val
        elif key_lower == "partitioned":
            cookie.partitioned = True
        elif key_lower == "priority":
            cookie.priority = val
    return cookie


def parse_response(
    raw: bytes,
    *,
    source: str = "",
    max_body_size: int | None = None,
    force_body_only: bool = False,
) -> HTTPResponse:
    """Parse raw HTTP response bytes into an HTTPResponse.

    Raises ParseError only when the input is empty or entirely unusable.
    """
    if raw is None or len(raw) == 0:
        raise ParseError("empty input, nothing to parse", source=source)

    warnings: list[str] = []
    response = HTTPResponse(source=source)

    if force_body_only:
        header_block, body = b"", raw
        response.had_status_line = False
    else:
        header_block, body = _split_headers_body(raw)
        # Decode header block permissively for line-based parsing.
        header_text = header_block.decode("latin-1", errors="replace")
        if not _looks_like_headers(header_text):
            # Whole input is likely just a body.
            header_block, body = b"", raw
            response.had_status_line = False

    header_text = header_block.decode("latin-1", errors="replace")
    lines = header_text.splitlines()

    if lines:
        status_match = _STATUS_LINE_RE.match(lines[0].strip())
        if status_match:
            response.http_version = f"HTTP/{status_match.group('version')}"
            response.status_code = int(status_match.group("code"))
            response.reason_phrase = status_match.group("reason") or ""
            header_lines = lines[1:]
        else:
            response.had_status_line = False
            header_lines = lines
            warnings.append("no valid HTTP status line found; treating first block as headers only")
    else:
        header_lines = []
        response.had_status_line = False

    headers = HeaderCollection()
    for line in header_lines:
        if not line.strip():
            continue
        match = _HEADER_LINE_RE.match(line)
        if match:
            headers.add(match.group("name"), match.group("value").strip())
        else:
            warnings.append(f"skipped unparsable header line: {line[:80]!r}")
    response.headers = headers

    # Cookies
    for value in headers.get_all("Set-Cookie"):
        try:
            response.cookies.append(parse_cookie_header(value))
        except Exception as exc:  # pragma: no cover - defensive
            warnings.append(f"failed to parse Set-Cookie header: {exc}")

    # Body handling: dechunk, decompress, detect type/charset.
    transfer_encoding = (headers.get_first("Transfer-Encoding") or "").lower()
    if "chunked" in transfer_encoding:
        body, dechunk_warning = _dechunk(body)
        if dechunk_warning:
            warnings.append(dechunk_warning)

    content_encoding = headers.get_first("Content-Encoding")
    body, decompress_warning = _decompress(body, content_encoding)
    if decompress_warning:
        warnings.append(decompress_warning)

    truncated = False
    full_length = len(body)
    if max_body_size is not None and len(body) > max_body_size:
        body = body[:max_body_size]
        truncated = True
        warnings.append(f"body truncated to {max_body_size} bytes (original {full_length} bytes)")

    charset = _detect_charset(headers, body)
    text: str | None
    decode_error: str | None = None
    try:
        text = body.decode(charset, errors="strict")
    except (LookupError, UnicodeDecodeError):
        try:
            text = body.decode(charset, errors="replace")
            decode_error = f"body could not be fully decoded as {charset}; used replacement characters"
        except LookupError:
            text = body.decode("utf-8", errors="replace")
            decode_error = f"unknown charset {charset!r}; fell back to utf-8 with replacement"

    is_binary = b"\x00" in body[:1024] if body else False
    detected_type = "binary" if is_binary else _detect_body_type(headers, text, body)

    response.body = BodyAnalysis(
        raw_bytes=body,
        text=None if is_binary else text,
        detected_type=detected_type,
        charset=charset,
        byte_length=full_length,
        char_length=len(text) if text and not is_binary else 0,
        sha256=hashlib.sha256(body).hexdigest(),
        truncated=truncated,
        entropy=_shannon_entropy(body) if body else 0.0,
        decode_error=decode_error,
    )

    if detected_type == "json" and text is not None and not truncated:
        import json

        try:
            response.body.parsed_json = json.loads(text)
        except (json.JSONDecodeError, ValueError) as exc:
            warnings.append(f"body looked like JSON but failed to parse: {exc}")
            response.body.detected_type = "text"

    response.parse_warnings = warnings
    return response
