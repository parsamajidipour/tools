"""Data models shared across the codebase. Kept independent of the parsing/
comparison logic on purpose, to avoid circular imports."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


# --------------------------------------------------------------------------- #
# Enums
# --------------------------------------------------------------------------- #


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

    @property
    def rank(self) -> int:
        return {"info": 0, "low": 1, "medium": 2, "high": 3}[self.value]


class Confidence(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class ChangeType(str, Enum):
    ADDED = "added"
    REMOVED = "removed"
    MODIFIED = "modified"
    UNCHANGED = "unchanged"


class DifferenceCategory(str, Enum):
    PROTOCOL = "protocol"
    STATUS = "status"
    HEADERS = "headers"
    COOKIES = "cookies"
    BODY = "body"
    JSON = "json"
    HTML = "html"
    XML = "xml"
    TEXT = "text"
    REFLECTION = "reflection"
    REDIRECT = "redirect"
    CACHING = "caching"
    CORS = "cors"
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"


# --------------------------------------------------------------------------- #
# HTTP response models
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class HeaderEntry:
    """A single header occurrence, preserving original casing/order."""

    name: str
    value: str

    @property
    def lower_name(self) -> str:
        return self.name.lower()


@dataclass
class HeaderCollection:
    """An ordered, duplicate-preserving collection of HTTP headers.

    Headers are looked up case-insensitively, but original name casing and
    the order/multiplicity of duplicate headers is preserved for accurate
    display and re-comparison.
    """

    entries: list[HeaderEntry] = field(default_factory=list)

    def add(self, name: str, value: str) -> None:
        self.entries.append(HeaderEntry(name=name, value=value))

    def get_all(self, name: str) -> list[str]:
        lname = name.lower()
        return [e.value for e in self.entries if e.lower_name == lname]

    def get_first(self, name: str) -> str | None:
        values = self.get_all(name)
        return values[0] if values else None

    def names(self) -> list[str]:
        """Unique header names, in first-seen order."""
        seen: list[str] = []
        seen_lower: set[str] = set()
        for e in self.entries:
            if e.lower_name not in seen_lower:
                seen_lower.add(e.lower_name)
                seen.append(e.name)
        return seen

    def __len__(self) -> int:
        return len(self.entries)

    def __iter__(self):
        return iter(self.entries)


@dataclass
class Cookie:
    """A single Set-Cookie header, fully parsed."""

    name: str
    value: str
    domain: str | None = None
    path: str | None = None
    expires: str | None = None
    max_age: str | None = None
    secure: bool = False
    http_only: bool = False
    same_site: str | None = None
    partitioned: bool = False
    priority: str | None = None
    raw: str = ""

    @property
    def has_host_prefix(self) -> bool:
        return self.name.startswith("__Host-")

    @property
    def has_secure_prefix(self) -> bool:
        return self.name.startswith("__Secure-")

    def prefix_violations(self) -> list[str]:
        """Return a list of __Host-/__Secure- requirement violations."""
        violations: list[str] = []
        if self.has_host_prefix:
            if not self.secure:
                violations.append("__Host- cookie is missing the Secure attribute")
            if self.path != "/":
                violations.append("__Host- cookie must have Path=/")
            if self.domain:
                violations.append("__Host- cookie must not set a Domain attribute")
        elif self.has_secure_prefix:
            if not self.secure:
                violations.append("__Secure- cookie is missing the Secure attribute")
        return violations


@dataclass
class BodyAnalysis:
    """Metadata and derived analysis about a response body."""

    raw_bytes: bytes = b""
    text: str | None = None
    detected_type: str = "unknown"  # json, html, xml, text, form, javascript, binary
    charset: str | None = None
    byte_length: int = 0
    char_length: int = 0
    sha256: str = ""
    truncated: bool = False
    entropy: float | None = None
    parsed_json: Any = None
    decode_error: str | None = None


@dataclass
class HTTPResponse:
    """A fully parsed HTTP response, independent of how it was obtained."""

    http_version: str = "HTTP/1.1"
    status_code: int | None = None
    reason_phrase: str = ""
    headers: HeaderCollection = field(default_factory=HeaderCollection)
    cookies: list[Cookie] = field(default_factory=list)
    body: BodyAnalysis = field(default_factory=BodyAnalysis)
    source: str = ""  # file path, URL, or "<stdin>"
    final_url: str | None = None
    redirect_chain: list["RedirectHop"] = field(default_factory=list)
    elapsed_ms: float | None = None
    had_status_line: bool = True
    parse_warnings: list[str] = field(default_factory=list)

    @property
    def status_class(self) -> str | None:
        if self.status_code is None:
            return None
        return f"{self.status_code // 100}xx"


@dataclass
class RedirectHop:
    status_code: int
    location: str | None
    url: str


# --------------------------------------------------------------------------- #
# Comparison / reporting models
# --------------------------------------------------------------------------- #


@dataclass
class Difference:
    """A single detected difference between baseline and candidate."""

    category: DifferenceCategory
    path: str  # e.g. header name, "$.user.role", "status_code"
    change_type: ChangeType
    baseline_value: Any = None
    candidate_value: Any = None
    description: str = ""
    suppressed: bool = False
    suppression_reason: str | None = None
    normalized: bool = False
    original_baseline_value: Any = None
    original_candidate_value: Any = None
    security_relevant: bool = False
    redacted: bool = False


@dataclass
class Finding:
    """A security-relevant observation produced by the rule engine."""

    rule_id: str
    title: str
    category: DifferenceCategory
    severity: Severity
    confidence: Confidence
    summary: str
    evidence: list[str] = field(default_factory=list)
    recommendation: str = ""
    false_positive_notes: str = ""
    references: list[str] = field(default_factory=list)


@dataclass
class ComparisonSummary:
    status_unchanged: bool = True
    baseline_status: int | None = None
    candidate_status: int | None = None
    body_similarity: float | None = None
    total_differences: int = 0
    suppressed_differences: int = 0
    total_findings: int = 0
    highest_severity: Severity = Severity.INFO


@dataclass
class ComparisonReport:
    """The full result of comparing two HTTP responses."""

    schema_version: str = "1.0"
    tool_version: str = "1.0.0"
    baseline_source: str = ""
    candidate_source: str = ""
    summary: ComparisonSummary = field(default_factory=ComparisonSummary)
    differences: list[Difference] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    suppressed: list[Difference] = field(default_factory=list)

    def active_differences(self) -> list[Difference]:
        return [d for d in self.differences if not d.suppressed]
