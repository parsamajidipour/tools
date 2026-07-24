"""Base classes for the rule engine.

A Rule takes the diffs (plus the original responses) and returns zero or
more Findings. Rules should fire on combinations of evidence, not single
keywords - and be honest about confidence.
"""

from __future__ import annotations

import os
import sys
from abc import ABC, abstractmethod

from ..models import ComparisonReport, Difference, Finding, HTTPResponse


class Rule(ABC):
    """Base class for all security rules."""

    rule_id: str
    title: str

    @abstractmethod
    def evaluate(
        self,
        *,
        baseline: HTTPResponse,
        candidate: HTTPResponse,
        differences: list[Difference],
    ) -> list[Finding]:
        """Return any findings this rule detects. Must not raise for normal
        (even malformed) input; catch and skip internally instead."""
        raise NotImplementedError


class RuleEngine:
    """Runs all registered rules against a set of differences."""

    def __init__(self, rules: list[Rule] | None = None) -> None:
        self._rules: list[Rule] = rules if rules is not None else []

    def register(self, rule: Rule) -> None:
        self._rules.append(rule)

    def run(
        self,
        *,
        baseline: HTTPResponse,
        candidate: HTTPResponse,
        differences: list[Difference],
    ) -> list[Finding]:
        findings: list[Finding] = []
        for rule in self._rules:
            try:
                findings.extend(
                    rule.evaluate(baseline=baseline, candidate=candidate, differences=differences)
                )
            except Exception as exc:
                # A single misbehaving rule must never crash the whole run,
                # but the failure should not be silent: surface it when
                # HTTPDIFF_DEBUG is set (used by --verbose in the CLI) so
                # rule bugs are discoverable during development/testing.
                if os.environ.get("HTTPDIFF_DEBUG"):
                    print(f"[httpdiff] rule {rule.rule_id} raised {exc!r}", file=sys.stderr)
                continue
        return findings


def find_by_path_prefix(differences: list[Difference], prefix: str) -> list[Difference]:
    return [d for d in differences if d.path.startswith(prefix)]


def find_by_category(differences: list[Difference], category: str) -> list[Difference]:
    return [d for d in differences if d.category.value == category]
