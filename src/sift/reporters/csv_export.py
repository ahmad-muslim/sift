"""CSV exporter for prioritized vulnerability findings with formula-injection protection."""

from __future__ import annotations

import csv
import io
from collections.abc import Sequence
from pathlib import Path

from sift.models import NormalizedFinding

CSV_COLUMNS: tuple[str, ...] = (
    "priority",
    "priority_label",
    "target",
    "port",
    "service",
    "cve_id",
    "rule_id",
    "cvss_score",
    "epss_score",
    "epss_percentile",
    "in_kev",
    "kev_ransomware_use",
    "scanner_sources",
    "priority_reason",
    "description",
    "references",
)

FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def sanitize_csv_cell(value: str) -> str:
    """Neutralize spreadsheet formula injection in untrusted scan text fields."""
    if not value:
        return value
    if value.startswith(FORMULA_PREFIXES):
        return f"'{value}"
    return value


def format_csv(findings: Sequence[NormalizedFinding]) -> str:
    """Render prioritized findings to an RFC 4180 CSV string."""
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(CSV_COLUMNS)

    for finding in findings:
        intel = finding.threat_intel
        writer.writerow(
            [
                finding.priority.value,
                finding.priority.label,
                sanitize_csv_cell(finding.target),
                "" if finding.port is None else str(finding.port),
                sanitize_csv_cell(finding.service or ""),
                finding.cve_id or "",
                sanitize_csv_cell(finding.rule_id or ""),
                "" if finding.cvss_score is None else f"{finding.cvss_score:.1f}",
                "" if intel.epss_score is None else f"{intel.epss_score:.5f}",
                "" if intel.epss_percentile is None else f"{intel.epss_percentile:.5f}",
                "true" if intel.in_kev else "false",
                (
                    ""
                    if intel.kev_ransomware_use is None
                    else ("true" if intel.kev_ransomware_use else "false")
                ),
                ", ".join(finding.scanner_sources),
                sanitize_csv_cell(finding.priority_reason),
                sanitize_csv_cell(finding.description),
                sanitize_csv_cell("; ".join(finding.references)),
            ]
        )

    return buffer.getvalue()


def export_csv(findings: Sequence[NormalizedFinding], output_path: Path) -> Path:
    """Write prioritized findings to a CSV file on disk."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(format_csv(findings), encoding="utf-8")
    return output_path
