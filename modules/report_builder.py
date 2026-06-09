"""
modules/report_builder.py

Extended report formatting helpers for Shieldr.

The core formatter lives in guard.py (format_report). This module provides
additional output helpers for integrations that need JSON, Markdown, or
structured data (e.g. webhook payloads, dashboards, audit logs).
"""

from __future__ import annotations

import json
from dataclasses import asdict
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from guard import ScanResult


def to_json(result: "ScanResult", indent: int = 2) -> str:
    """
    Serialise a ScanResult to a JSON string.

    Args:
        result: The ScanResult from guard.scan().
        indent: JSON indentation level.

    Returns:
        JSON string.
    """
    payload = {
        "input_preview": result.input_text[:200],
        "risk_score": result.risk_score,
        "verdict": result.verdict,
        "decoded_payload": result.decoded_payload,
        "findings": [
            {
                "severity": f.severity,
                "code": f.code,
                "detail": f.detail,
                "decoded": f.decoded,
            }
            for f in result.findings
        ],
    }
    return json.dumps(payload, indent=indent, ensure_ascii=False)


def to_markdown(result: "ScanResult") -> str:
    """
    Render a ScanResult as a Markdown document suitable for
    embedding in reports, issue trackers, or audit logs.
    """
    lines: list[str] = []
    lines.append("## 🛡️ Shieldr Security Scan Report")
    lines.append("")
    lines.append(f"**Risk Score:** {result.risk_score}/100  ")
    lines.append(f"**Verdict:** {result.verdict}  ")
    lines.append(f"**Input preview:** `{result.input_text[:100]}`")
    lines.append("")

    if result.findings:
        lines.append("### Findings")
        lines.append("")
        lines.append("| Severity | Code | Detail |")
        lines.append("|---|---|---|")
        for f in result.findings:
            detail = f.detail.replace("|", "\\|")[:120]
            lines.append(f"| {f.severity} | `{f.code}` | {detail} |")
    else:
        lines.append("_No threats detected._")

    if result.decoded_payload:
        lines.append("")
        lines.append("### Decoded Payload")
        lines.append(f"```\n{result.decoded_payload[:500]}\n```")

    return "\n".join(lines)
