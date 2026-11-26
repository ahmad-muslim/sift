"""GitHub- and client-ready Markdown report generator."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

from sift.models import NormalizedFinding, PriorityTier

PRIORITY_BADGES: dict[PriorityTier, str] = {
    PriorityTier.P1: "**P1 (Urgent)**",
    PriorityTier.P2: "**P2 (High)**",
    PriorityTier.P3: "P3 (Medium)",
    PriorityTier.P4: "P4 (Low/Info)",
}


def _escape_md_cell(value: str, *, max_len: int | None = None) -> str:
    """Escape pipe characters and collapse whitespace for safe Markdown table cells."""
    cleaned = " ".join(value.replace("\r", " ").replace("\n", " ").split())
    if max_len is not None and len(cleaned) > max_len:
        cleaned = f"{cleaned[: max_len - 3].rstrip()}..."
    return cleaned.replace("|", "\\|")


def format_markdown(
    findings: Sequence[NormalizedFinding],
    *,
    raw_count: int | None = None,
    duplicates_merged: int = 0,
    warnings: Sequence[str] = (),
    generated_at: datetime | None = None,
) -> str:
    """Render prioritized findings as a clean Markdown report."""
    timestamp = (generated_at or datetime.now(UTC)).strftime("%Y-%m-%d %H:%M:%S UTC")

    tier_counts: dict[PriorityTier, int] = {tier: 0 for tier in PriorityTier}
    for finding in findings:
        tier_counts[finding.priority] += 1
    kev_count = sum(1 for finding in findings if finding.in_kev)

    lines: list[str] = [
        "# Vulnerability Prioritization Report (`sift`)",
        "",
        f"_Generated: {timestamp}_",
        "",
        "## Executive Summary",
        "",
        "| Metric | Count |",
        "| --- | ---: |",
        f"| Total Prioritized Findings | {len(findings)} |",
    ]
    if raw_count is not None:
        lines.append(f"| Raw Scanner Findings Ingested | {raw_count} |")
        lines.append(f"| Duplicate Findings Merged | {duplicates_merged} |")

    lines.extend(
        [
            f"| **P1 (Urgent)** | **{tier_counts[PriorityTier.P1]}** |",
            f"| **P2 (High)** | **{tier_counts[PriorityTier.P2]}** |",
            f"| P3 (Medium) | {tier_counts[PriorityTier.P3]} |",
            f"| P4 (Low/Info) | {tier_counts[PriorityTier.P4]} |",
            f"| Listed in CISA KEV | {kev_count} |",
            "",
        ]
    )

    if warnings:
        lines.append("> [!WARNING]")
        for warning in warnings:
            lines.append(f"> - {_escape_md_cell(warning)}")
        lines.append("")

    lines.append("## Prioritized Findings")
    lines.append("")

    if not findings:
        lines.append("_No findings matched the specified criteria._")
        lines.append("")
        return "\n".join(lines)

    lines.extend(
        [
            (
                "| Priority | Target | Port | Service | ID | CVSS | EPSS | KEV | "
                "Scanners | Rationale |"
            ),
            "| --- | --- | ---: | --- | --- | ---: | ---: | :---: | --- | --- |",
        ]
    )

    for finding in findings:
        identifier = finding.cve_id or finding.rule_id or "N/A"
        port_str = str(finding.port) if finding.port is not None else "-"
        service_str = _escape_md_cell(finding.service or "-")
        cvss_str = f"{finding.cvss_score:.1f}" if finding.cvss_score is not None else "-"
        epss_str = (
            f"{finding.threat_intel.epss_score:.1%}"
            if finding.threat_intel.epss_score is not None
            else "-"
        )
        kev_str = "**YES**" if finding.in_kev else "No"
        scanners_str = ", ".join(finding.scanner_sources)
        reason_str = _escape_md_cell(finding.priority_reason or "-")

        lines.append(
            f"| {PRIORITY_BADGES[finding.priority]} "
            f"| `{_escape_md_cell(finding.target)}` "
            f"| {port_str} "
            f"| {service_str} "
            f"| `{_escape_md_cell(identifier)}` "
            f"| {cvss_str} "
            f"| {epss_str} "
            f"| {kev_str} "
            f"| {scanners_str} "
            f"| {reason_str} |"
        )

    high_priority = [
        finding for finding in findings if finding.priority in {PriorityTier.P1, PriorityTier.P2}
    ]
    if high_priority:
        lines.extend(["", "## High-Priority Remediation Details (P1 & P2)", ""])
        for finding in high_priority:
            identifier = finding.cve_id or finding.rule_id or "Unnamed Finding"
            endpoint = f"{finding.target}:{finding.port}" if finding.port else finding.target
            lines.append(f"### [{finding.priority.value}] `{identifier}` on `{endpoint}`")
            lines.append("")
            lines.append(f"- **Priority Rationale:** {finding.priority_reason}")
            lines.append(f"- **Scanners:** {', '.join(finding.scanner_sources)}")
            if finding.service:
                lines.append(f"- **Service / Package:** `{finding.service}`")
            if finding.threat_intel.in_kev and finding.threat_intel.kev_due_date:
                lines.append(
                    f"- **CISA KEV Due Date:** {finding.threat_intel.kev_due_date.isoformat()}"
                )
            if finding.metadata.get("fixed_version"):
                lines.append(f"- **Fixed Version:** `{finding.metadata['fixed_version']}`")
            if finding.description:
                lines.append(f"- **Description:** {' '.join(finding.description.split())}")
            if finding.references:
                refs_md = ", ".join(f"<{ref}>" for ref in finding.references[:5])
                lines.append(f"- **References:** {refs_md}")
            lines.append("")

    return "\n".join(lines)


def export_markdown(
    findings: Sequence[NormalizedFinding],
    output_path: Path,
    *,
    raw_count: int | None = None,
    duplicates_merged: int = 0,
    warnings: Sequence[str] = (),
    generated_at: datetime | None = None,
) -> Path:
    """Write prioritized findings to a Markdown report file on disk."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        format_markdown(
            findings,
            raw_count=raw_count,
            duplicates_merged=duplicates_merged,
            warnings=warnings,
            generated_at=generated_at,
        ),
        encoding="utf-8",
    )
    return output_path
