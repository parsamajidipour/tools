"""Configuration file loading and merging with CLI arguments.

CLI arguments always take precedence over file-based configuration.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .exceptions import ConfigError

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover
    import tomli as tomllib  # type: ignore

DEFAULT_CONFIG_LOCATIONS = (
    Path("httpdiff.toml"),
    Path.home() / ".config" / "httpdiff" / "config.toml",
)


@dataclass
class HTTPDiffConfig:
    similarity_threshold: float = 0.92
    max_body_size: int = 5 * 1024 * 1024
    max_diff_lines: int = 200
    max_json_depth: int = 50
    normalize: bool = True
    ignore_headers: list[str] = field(default_factory=list)
    ignore_cookies: list[str] = field(default_factory=list)
    ignore_json_paths: list[str] = field(default_factory=list)
    ignore_regexes: list[str] = field(default_factory=list)
    output_format: str = "terminal"
    show_secrets: bool = False
    minimum_severity: str = "info"

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "HTTPDiffConfig":
        comparison = data.get("comparison", {})
        ignore = data.get("ignore", {})
        report = data.get("report", {})
        rules = data.get("rules", {})
        try:
            return cls(
                similarity_threshold=float(comparison.get("similarity_threshold", 0.92)),
                max_body_size=int(comparison.get("max_body_size", 5 * 1024 * 1024)),
                max_diff_lines=int(comparison.get("max_diff_lines", 200)),
                max_json_depth=int(comparison.get("max_json_depth", 50)),
                normalize=bool(comparison.get("normalize", True)),
                ignore_headers=list(ignore.get("headers", [])),
                ignore_cookies=list(ignore.get("cookies", [])),
                ignore_json_paths=list(ignore.get("json_paths", [])),
                ignore_regexes=list(ignore.get("regexes", [])),
                output_format=str(report.get("format", "terminal")),
                show_secrets=bool(report.get("show_secrets", False)),
                minimum_severity=str(rules.get("minimum_severity", "info")),
            )
        except (TypeError, ValueError) as exc:
            raise ConfigError(f"invalid configuration value: {exc}") from exc


def load_config(explicit_path: str | None) -> HTTPDiffConfig:
    """Load configuration from an explicit path, or the default search
    locations. Returns defaults if nothing is found."""
    if explicit_path:
        path = Path(explicit_path)
        if not path.is_file():
            raise ConfigError(f"config file not found: {explicit_path}")
        return _load_path(path)

    for candidate in DEFAULT_CONFIG_LOCATIONS:
        if candidate.is_file():
            return _load_path(candidate)

    return HTTPDiffConfig()


def _load_path(path: Path) -> HTTPDiffConfig:
    try:
        with path.open("rb") as f:
            data = tomllib.load(f)
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"failed to parse config file {path}: {exc}") from exc
    return HTTPDiffConfig.from_dict(data)
