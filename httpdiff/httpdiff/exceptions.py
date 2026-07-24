"""Custom exceptions. Mostly here so the CLI can print something useful
instead of a raw traceback."""

from __future__ import annotations


class HTTPDiffError(Exception):
    """Base class for all HTTPDiff errors."""


class ParseError(HTTPDiffError):
    """Raised when an HTTP response cannot be parsed, even leniently."""

    def __init__(self, message: str, *, source: str | None = None) -> None:
        self.source = source
        full = f"{message} (source: {source})" if source else message
        super().__init__(full)


class ConfigError(HTTPDiffError):
    """Raised when the configuration file or CLI arguments are invalid."""


class NetworkError(HTTPDiffError):
    """Raised when a request to a target fails."""

    def __init__(self, message: str, *, url: str | None = None) -> None:
        self.url = url
        full = f"{message} (url: {url})" if url else message
        super().__init__(full)


class RequestFileError(HTTPDiffError):
    """Raised when a raw request file cannot be parsed."""


class BodyTooLargeError(HTTPDiffError):
    """Raised internally when a body exceeds configured limits.

    This is caught and converted into a truncation notice; it should not
    normally escape to the user as a crash.
    """


class InternalError(HTTPDiffError):
    """Raised for unexpected internal failures (maps to exit code 4)."""
