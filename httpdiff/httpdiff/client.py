"""HTTP client for the `url` and `request` subcommands.

Built on urllib instead of a third-party client so this module has no
mandatory external dependency. Redirects aren't followed unless asked for,
and credentials get stripped when a redirect crosses origins.
"""

from __future__ import annotations

import re
import socket
import ssl
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from .exceptions import NetworkError, RequestFileError
from .models import HTTPResponse, RedirectHop
from .parser import parse_response

_IDEMPOTENT_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
_REQUEST_LINE_RE = re.compile(r"^(?P<method>[A-Z]+)\s+(?P<target>\S+)\s+HTTP/(?P<version>\d\.\d)$")
_MAX_REDIRECTS = 10


@dataclass
class RequestSpec:
    method: str = "GET"
    url: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""


def parse_raw_request(raw: bytes, *, scheme: str = "https") -> RequestSpec:
    """Parse a Burp-style raw HTTP request file into a RequestSpec."""
    text = raw.decode("latin-1", errors="replace")
    if "\r\n\r\n" in text:
        header_block, _, body_text = text.partition("\r\n\r\n")
    else:
        header_block, _, body_text = text.partition("\n\n")

    lines = header_block.splitlines()
    if not lines:
        raise RequestFileError("raw request file is empty")

    match = _REQUEST_LINE_RE.match(lines[0].strip())
    if not match:
        raise RequestFileError(f"could not parse request line: {lines[0]!r}")

    method = match.group("method")
    target = match.group("target")

    headers: dict[str, str] = {}
    for line in lines[1:]:
        if not line.strip() or ":" not in line:
            continue
        name, _, value = line.partition(":")
        headers[name.strip()] = value.strip()

    host = headers.get("Host") or headers.get("host")
    if target.startswith("http://") or target.startswith("https://"):
        url = target
    elif host:
        url = f"{scheme}://{host}{target}"
    else:
        raise RequestFileError("request file has no Host header and target is not an absolute URL")

    return RequestSpec(method=method, url=url, headers=headers, body=body_text.encode("latin-1", errors="replace"))


def _redact_error(message: str) -> str:
    message = re.sub(r"(?i)(authorization:\s*)\S+", r"\1<redacted>", message)
    message = re.sub(r"(?i)(cookie:\s*)\S+", r"\1<redacted>", message)
    return message


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Disables urllib's built-in redirect following so HTTPDiff can
    implement redirects itself with full control over the chain."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: N802,ANN001
        return None


def _single_request(
    spec: RequestSpec,
    *,
    timeout: float,
    verify_tls: bool,
    proxy: str | None,
    user_agent: str | None,
) -> tuple[bytes, str]:
    """Perform exactly one HTTP request (no redirect following) and return
    the raw response bytes (status line + headers + body) plus final URL."""
    headers = dict(spec.headers)
    if user_agent:
        headers["User-Agent"] = user_agent

    ctx = ssl.create_default_context()
    if not verify_tls:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    handlers: list[urllib.request.BaseHandler] = [_NoRedirect(), urllib.request.HTTPSHandler(context=ctx)]
    if proxy:
        handlers.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
    opener = urllib.request.build_opener(*handlers)

    req = urllib.request.Request(
        spec.url, data=spec.body or None, headers=headers, method=spec.method.upper()
    )

    try:
        response = opener.open(req, timeout=timeout)
    except urllib.error.HTTPError as exc:
        # HTTPError doubles as a valid response object for status >= 400.
        response = exc
    except (urllib.error.URLError, socket.timeout, ssl.SSLError, ConnectionError, OSError) as exc:
        raise NetworkError(_redact_error(str(exc)), url=spec.url) from exc

    status_code = response.getcode() or 0
    reason = getattr(response, "reason", "") or ""
    raw_headers = response.headers if hasattr(response, "headers") else response.info()
    body = response.read()
    final_url = response.geturl() if hasattr(response, "geturl") else spec.url

    head = f"HTTP/1.1 {status_code} {reason}\r\n"
    for name, value in raw_headers.items():
        head += f"{name}: {value}\r\n"
    raw = head.encode("latin-1", errors="replace") + b"\r\n" + body
    return raw, final_url


def fetch(
    spec: RequestSpec,
    *,
    timeout: float = 15.0,
    verify_tls: bool = True,
    proxy: str | None = None,
    user_agent: str | None = None,
    follow_redirects: bool = False,
    max_body_size: int | None = None,
) -> HTTPResponse:
    """Perform an HTTP request (optionally following redirects manually)
    and parse the final result into an HTTPResponse."""
    start = time.monotonic()
    redirect_chain: list[RedirectHop] = []
    current = spec
    original_origin = urlsplit(spec.url)

    for _ in range(_MAX_REDIRECTS + 1):
        raw, final_url = _single_request(
            current, timeout=timeout, verify_tls=verify_tls, proxy=proxy, user_agent=user_agent
        )
        parsed = parse_response(raw, source=current.url, max_body_size=max_body_size)

        is_redirect = parsed.status_code is not None and 300 <= parsed.status_code < 400
        location = parsed.headers.get_first("Location")

        if not follow_redirects or not is_redirect or not location:
            parsed.final_url = final_url
            parsed.redirect_chain = redirect_chain
            parsed.elapsed_ms = (time.monotonic() - start) * 1000
            if redirect_chain:
                last_scheme = urlsplit(final_url).scheme
                if original_origin.scheme == "https" and last_scheme == "http":
                    parsed.parse_warnings.append("redirect chain downgraded from HTTPS to HTTP")
            return parsed

        redirect_chain.append(
            RedirectHop(status_code=parsed.status_code, location=location, url=current.url)
        )

        next_url = location
        if not (next_url.startswith("http://") or next_url.startswith("https://")):
            base = urlsplit(current.url)
            if next_url.startswith("/"):
                next_url = f"{base.scheme}://{base.netloc}{next_url}"
            else:
                next_url = f"{base.scheme}://{base.netloc}/{next_url.lstrip('/')}"

        next_origin = urlsplit(next_url)
        next_headers = dict(current.headers)
        if next_origin.netloc != original_origin.netloc:
            # Never forward credentials to a different origin on redirect.
            next_headers.pop("Authorization", None)
            next_headers.pop("Cookie", None)

        next_method = current.method
        next_body = current.body
        if parsed.status_code in (301, 302, 303) and current.method.upper() not in _IDEMPOTENT_METHODS:
            next_method = "GET"
            next_body = b""

        current = RequestSpec(method=next_method, url=next_url, headers=next_headers, body=next_body)

    raise NetworkError("too many redirects", url=spec.url)
