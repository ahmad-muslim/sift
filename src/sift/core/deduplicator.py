"""Cross-scanner finding deduplication and merge engine."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from sift.models import NormalizedFinding, RawFinding


def _merge_metadata(existing: dict[str, Any], incoming: dict[str, Any]) -> dict[str, Any]:
    """Merge scanner metadata dictionaries without losing existing context."""
    merged = dict(existing)
    for key, value in incoming.items():
        if key not in merged or merged[key] in (None, ""):
            merged[key] = value
    return merged


def deduplicate_findings(raw_findings: Iterable[RawFinding]) -> list[NormalizedFinding]:
    """Deduplicate identical findings across scanners while preserving all scanner sources.

    Findings are grouped by `RawFinding.dedup_key`:
    - `(target, port, cve_id)` when a CVE is present
    - `(target, port, "rule:<rule_id>")` for non-CVE findings with a rule/template/advisory ID
    - `(target, port, "desc:<sha256[:16]>")` otherwise

    Merge rules when duplicates collapse into a single `NormalizedFinding`:
    - `scanner_sources`: sorted union of all originating scanner names
    - `cvss_score`: highest non-null CVSS score (conservative risk posture)
    - `service`: first non-empty service/package identifier
    - `description`: longest non-empty description
    - `references`: order-preserving union of unique URLs
    """
    grouped: dict[tuple[str, int | None, str], list[RawFinding]] = {}
    for finding in raw_findings:
        grouped.setdefault(finding.dedup_key, []).append(finding)

    normalized: list[NormalizedFinding] = []
    for bucket in grouped.values():
        first = bucket[0]
        sources = sorted({item.scanner_source for item in bucket})

        cvss_scores = [item.cvss_score for item in bucket if item.cvss_score is not None]
        best_cvss = max(cvss_scores) if cvss_scores else None

        service = next((item.service for item in bucket if item.service), None)
        rule_id = next((item.rule_id for item in bucket if item.rule_id), None)

        descriptions = [item.description for item in bucket if item.description]
        best_description = max(descriptions, key=len) if descriptions else ""

        references: list[str] = []
        for item in bucket:
            for ref in item.references:
                if ref not in references:
                    references.append(ref)

        metadata: dict[str, Any] = {}
        for item in bucket:
            metadata = _merge_metadata(metadata, item.metadata)

        normalized.append(
            NormalizedFinding(
                target=first.target,
                port=first.port,
                service=service,
                cve_id=first.cve_id,
                cvss_score=best_cvss,
                scanner_sources=sources,
                description=best_description,
                rule_id=rule_id,
                references=references,
                metadata=metadata,
            )
        )

    return normalized
