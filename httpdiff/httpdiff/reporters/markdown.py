"""Markdown report renderer, suitable for GitHub issues and pentest notes."""

from __future__ import annotations

from ..models import ComparisonReport

_SEVERITY_EMOJI = {"info": "ℹ️", "low": "🟡", "medium": "🟠", "high": "🔴"}


def render_markdown(report: ComparisonReport) -> str:
    s = report.summary
    lines: list[str] = []
    lines.append("# HTTPDiff Comparison Report")
    lines.append("")
    lines.append(f"- **Baseline:** `{report.baseline_source}`")
    lines.append(f"- **Candidate:** `{report.candidate_source}`")
    lines.append(f"- **Status:** {s.baseline_status} -> {s.candidate_status}")
    if s.body_similarity is not None:
        lines.append(f"- **Body similarity:** {s.body_similarity * 100:.1f}%")
    lines.append(f"- **Differences:** {s.total_differences} (suppressed: {s.suppressed_differences})")
    lines.append(f"- **Findings:** {s.total_findings} (highest severity: {s.highest_severity.value})")
    lines.append("")

    active = report.active_differences()
    if active:
        lines.append("## Differences")
        lines.append("")
        lines.append("| Category | Path | Change | Description |")
        lines.append("|---|---|---|---|")
        for d in active:
            desc = d.description.replace("|", "\\|")
            lines.append(f"| {d.category.value} | `{d.path}` | {d.change_type.value} | {desc} |")
        lines.append("")

    if report.findings:
        lines.append("## Security Findings")
        lines.append("")
        for f in sorted(report.findings, key=lambda x: -x.severity.rank):
            emoji = _SEVERITY_EMOJI.get(f.severity.value, "")
            lines.append(f"### {emoji} [{f.severity.value.upper()}] {f.title} (`{f.rule_id}`)")
            lines.append("")
            lines.append(f"**Confidence:** {f.confidence.value}")
            lines.append("")
            lines.append(f.summary)
            lines.append("")
            if f.evidence:
                lines.append("**Evidence:**")
                for ev in f.evidence:
                    lines.append(f"- {ev}")
                lines.append("")
            if f.recommendation:
                lines.append(f"**Recommendation:** {f.recommendation}")
                lines.append("")
            if f.false_positive_notes:
                lines.append(f"**False-positive considerations:** {f.false_positive_notes}")
                lines.append("")

    if report.suppressed:
        lines.append("## Suppressed Dynamic Differences")
        lines.append("")
        for d in report.suppressed:
            lines.append(f"- `{d.path}`: {d.description} _( {d.suppression_reason} )_")
        lines.append("")

    lines.append(
        "> HTTPDiff findings are evidence-based heuristics intended to guide manual "
        "security testing. Manual verification is recommended for all findings above."
    )

    return "\n".join(lines) + "\n"
