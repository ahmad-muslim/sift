"""End-to-end scan ingestion, deduplication, enrichment, and prioritization pipeline."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

from sift.core.deduplicator import deduplicate_findings
from sift.core.prioritizer import prioritize_findings
from sift.enrichment import (
    DEFAULT_TIMEOUT_SECONDS,
    DEFAULT_TTL_SECONDS,
    EnrichmentResult,
    ThreatEnricher,
)
from sift.models import NormalizedFinding, PriorityTier, RawFinding
from sift.parsers import ParserRegistry, create_default_registry


@dataclass
class ParsedFileSummary:
    """Summary of a single ingested scan file."""

    path: Path
    parser_name: str
    raw_finding_count: int


@dataclass
class PipelineResult:
    """Complete result of running the sift analysis pipeline."""

    findings: list[NormalizedFinding]
    files_parsed: list[ParsedFileSummary] = field(default_factory=list)
    raw_count: int = 0
    unique_count: int = 0
    duplicates_merged: int = 0
    enrichment: EnrichmentResult = field(default_factory=EnrichmentResult)

    @property
    def tier_counts(self) -> dict[PriorityTier, int]:
        counts: dict[PriorityTier, int] = {tier: 0 for tier in PriorityTier}
        for finding in self.findings:
            counts[finding.priority] += 1
        return counts

    @property
    def kev_count(self) -> int:
        return sum(1 for finding in self.findings if finding.in_kev)


def run_pipeline(
    scan_files: Sequence[Path],
    *,
    registry: ParserRegistry | None = None,
    parser_name: str | None = None,
    enricher: ThreatEnricher | None = None,
    cache_dir: Path | str | None = None,
    ttl_seconds: int = DEFAULT_TTL_SECONDS,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    offline: bool = False,
    refresh_cache: bool = False,
    cve_only: bool = False,
    min_priority: PriorityTier | None = None,
) -> PipelineResult:
    """Ingest scan files, deduplicate, enrich with KEV/EPSS, prioritize, and filter."""
    active_registry = registry or create_default_registry()

    raw_findings: list[RawFinding] = []
    files_parsed: list[ParsedFileSummary] = []
    for path in scan_files:
        detected_name, parsed = active_registry.parse_file(path, parser_name=parser_name)
        files_parsed.append(
            ParsedFileSummary(
                path=path,
                parser_name=detected_name,
                raw_finding_count=len(parsed),
            )
        )
        raw_findings.extend(parsed)

    deduped = deduplicate_findings(raw_findings)
    raw_count = len(raw_findings)
    unique_count = len(deduped)
    duplicates_merged = raw_count - unique_count

    if cve_only:
        deduped = [finding for finding in deduped if finding.cve_id is not None]

    if enricher is not None:
        enriched, enrichment_result = enricher.enrich_findings(deduped)
    else:
        with ThreatEnricher(
            cache_dir=cache_dir,
            ttl_seconds=ttl_seconds,
            timeout=timeout,
            offline=offline,
            refresh_cache=refresh_cache,
        ) as owned_enricher:
            enriched, enrichment_result = owned_enricher.enrich_findings(deduped)

    prioritized = prioritize_findings(enriched)

    if min_priority is not None:
        prioritized = [
            finding for finding in prioritized if finding.priority.rank <= min_priority.rank
        ]

    return PipelineResult(
        findings=prioritized,
        files_parsed=files_parsed,
        raw_count=raw_count,
        unique_count=unique_count,
        duplicates_merged=duplicates_merged,
        enrichment=enrichment_result,
    )
