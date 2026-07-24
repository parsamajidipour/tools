"""Human-readable terminal report renderer.

Never relies on color alone: every line carries a bracketed text label.
"""

from __future__ import annotations

from ..models import ChangeType, ComparisonReport, Severity

_SEVERITY_LABELS = {
    Severity.INFO: "INFO",
    Severity.LOW: "LOW",
    Severity.MEDIUM: "MEDIUM",
    Severity.HIGH: "HIGH",
}

_SEVERITY_COLORS = {
    Severity.INFO: "\033[36m",
    Severity.LOW: "\033[33m",
    Severity.MEDIUM: "\033[35m",
    Severity.HIGH: "\033[31m",
}
_RESET = "\033[0m"
_BOLD = "\033[1m"


def _colorize(text: str, code: str, use_color: bool) -> str:
    if not use_color:
        return text
    return f"{code}{text}{_RESET}"


def _section(title: str, use_color: bool) -> str:
    line = f"\n{title}\n{'-' * len(title)}"
    return _colorize(line, _BOLD, use_color)


def render_terminal(report: ComparisonReport, *, use_color: bool = True, show_unchanged: bool = False) -> str:
    lines: list[str] = []

    lines.append(_colorize("Comparison Summary", _BOLD, use_color))
    s = report.summary
    status_note = "unchanged" if s.status_unchanged else "changed"
    lines.append(f"  Baseline:  {report.baseline_source}")
    lines.append(f"  Candidate: {report.candidate_source}")
    lines.append(f"  Status: {status_note}, {s.baseline_status} -> {s.candidate_status}")
    if s.body_similarity is not None:
        lines.append(f"  Body similarity: {s.body_similarity * 100:.1f}%")
    lines.append(f"  Differences: {s.total_differences} (suppressed: {s.suppressed_differences})")
    lines.append(f"  Findings: {s.total_findings} (highest severity: {s.highest_severity.value})")

    active = report.active_differences()
    if active:
        lines.append(_section("Differences", use_color))
        for d in active:
            tag = "CHANGE" if d.change_type != ChangeType.UNCHANGED else "INFO"
            lines.append(f"  [{tag}] {d.description}")

    findings = report.findings
    if findings:
        lines.append(_section("Security Findings", use_color))
        for f in sorted(findings, key=lambda x: -x.severity.rank):
            label = _SEVERITY_LABELS[f.severity]
            colored_label = _colorize(f"[{label}]", _SEVERITY_COLORS[f.severity], use_color)
            lines.append(f"  {colored_label} ({f.rule_id}, confidence: {f.confidence.value}) {f.summary}")
            for ev in f.evidence:
                lines.append(f"      - {ev}")
            if f.recommendation:
                lines.append(f"      Recommendation: {f.recommendation}")

    if report.suppressed:
        lines.append(_section("Suppressed Dynamic Differences", use_color))
        for d in report.suppressed:
            lines.append(f"  [NOISE] {d.description} ({d.suppression_reason})")

    if not active and not findings:
        lines.append("\nNo meaningful differences detected.")

    return "\n".join(lines) + "\n"
