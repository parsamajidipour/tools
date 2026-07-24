"""Stable, versioned JSON report renderer suitable for automation/CI."""

from __future__ import annotations

import json
from dataclasses import asdict
from typing import Any

from ..models import ComparisonReport


def _serialize_value(value: Any) -> Any:
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, (list, tuple)):
        return [_serialize_value(v) for v in value]
    if isinstance(value, dict):
        return {k: _serialize_value(v) for k, v in value.items()}
    return str(value)


def build_json_payload(report: ComparisonReport) -> dict[str, Any]:
    return {
        "schema_version": report.schema_version,
        "tool_version": report.tool_version,
        "baseline": {"source": report.baseline_source},
        "candidate": {"source": report.candidate_source},
        "summary": {
            "status_unchanged": report.summary.status_unchanged,
            "baseline_status": report.summary.baseline_status,
            "candidate_status": report.summary.candidate_status,
            "body_similarity": report.summary.body_similarity,
            "total_differences": report.summary.total_differences,
            "suppressed_differences": report.summary.suppressed_differences,
            "total_findings": report.summary.total_findings,
            "highest_severity": report.summary.highest_severity.value,
        },
        "differences": [
            {
                "category": d.category.value,
                "path": d.path,
                "change_type": d.change_type.value,
                "baseline_value": _serialize_value(d.baseline_value),
                "candidate_value": _serialize_value(d.candidate_value),
                "description": d.description,
                "suppressed": d.suppressed,
                "suppression_reason": d.suppression_reason,
                "normalized": d.normalized,
                "security_relevant": d.security_relevant,
                "redacted": d.redacted,
            }
            for d in report.differences
            if not d.suppressed
        ],
        "findings": [
            {
                "rule_id": f.rule_id,
                "title": f.title,
                "category": f.category.value,
                "severity": f.severity.value,
                "confidence": f.confidence.value,
                "summary": f.summary,
                "evidence": f.evidence,
                "recommendation": f.recommendation,
                "false_positive_notes": f.false_positive_notes,
                "references": f.references,
            }
            for f in report.findings
        ],
        "suppressed": [
            {
                "category": d.category.value,
                "path": d.path,
                "description": d.description,
                "suppression_reason": d.suppression_reason,
            }
            for d in report.suppressed
        ],
    }


def render_json(report: ComparisonReport, *, indent: int = 2) -> str:
    return json.dumps(build_json_payload(report), indent=indent, sort_keys=False)
