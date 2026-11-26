"""Threat intelligence orchestrator combining CISA KEV, FIRST EPSS, and SQLite caching."""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from sift.enrichment.cache import DEFAULT_TTL_SECONDS, ThreatIntelCache
from sift.enrichment.epss import DEFAULT_BATCH_SIZE, EpssClient
from sift.enrichment.http import (
    DEFAULT_TIMEOUT_SECONDS,
    HttpClient,
    HttpRequestError,
    create_default_http_client,
)
from sift.enrichment.kev import KevClient
from sift.models import (
    EpssRecord,
    KevRecord,
    NormalizedFinding,
    ThreatIntel,
    normalize_required_cve_id,
)


@dataclass
class EnrichmentResult:
    """Aggregated threat intelligence lookup outcome and telemetry."""

    intel_by_cve: dict[str, ThreatIntel] = field(default_factory=dict)
    kev_from_cache: bool = False
    kev_stale: bool = False
    epss_cache_hits: int = 0
    epss_api_fetched: int = 0
    epss_stale_hits: int = 0
    warnings: list[str] = field(default_factory=list)


class ThreatEnricher:
    """Coordinates CISA KEV and FIRST EPSS enrichment with local caching and offline fallback."""

    def __init__(
        self,
        *,
        cache: ThreatIntelCache | None = None,
        cache_dir: Path | str | None = None,
        kev_client: KevClient | None = None,
        epss_client: EpssClient | None = None,
        http_client: HttpClient | None = None,
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
        batch_size: int = DEFAULT_BATCH_SIZE,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        offline: bool = False,
        refresh_cache: bool = False,
    ) -> None:
        self.ttl_seconds = ttl_seconds
        self.offline = offline
        self.refresh_cache = refresh_cache
        self._batch_size = batch_size
        self._timeout = timeout

        self._owns_cache = cache is None
        self.cache = cache or ThreatIntelCache(cache_dir=cache_dir)

        self._shared_http_client = http_client
        self._owns_shared_http = False
        self._kev_client = kev_client
        self._epss_client = epss_client

    def _ensure_http_client(self) -> HttpClient:
        if self._shared_http_client is None:
            self._shared_http_client = create_default_http_client(timeout=self._timeout)
            self._owns_shared_http = True
        return self._shared_http_client

    def _get_kev_client(self) -> KevClient:
        if self._kev_client is None:
            self._kev_client = KevClient(http_client=self._ensure_http_client())
        return self._kev_client

    def _get_epss_client(self) -> EpssClient:
        if self._epss_client is None:
            self._epss_client = EpssClient(
                batch_size=self._batch_size,
                http_client=self._ensure_http_client(),
            )
        return self._epss_client

    def close(self) -> None:
        """Close owned SQLite cache and HTTP client resources."""
        if self._owns_shared_http and self._shared_http_client is not None:
            self._shared_http_client.close()
            self._shared_http_client = None
        if self._owns_cache:
            self.cache.close()

    def __enter__(self) -> ThreatEnricher:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def enrich_cves(
        self,
        cve_ids: Iterable[str],
        *,
        now: float | None = None,
    ) -> EnrichmentResult:
        """Enrich unique CVE identifiers with CISA KEV and FIRST EPSS data."""
        normalized = sorted({normalize_required_cve_id(cve) for cve in cve_ids})
        result = EnrichmentResult()
        if not normalized:
            return result

        kev_map = self._resolve_kev(normalized, result, now=now)
        epss_map = self._resolve_epss(normalized, result, now=now)

        enriched_at = datetime.now(UTC)
        for cve_id in normalized:
            kev = kev_map.get(cve_id)
            epss = epss_map.get(cve_id)
            result.intel_by_cve[cve_id] = ThreatIntel(
                in_kev=kev is not None,
                kev_date_added=kev.date_added if kev is not None else None,
                kev_due_date=kev.due_date if kev is not None else None,
                kev_ransomware_use=kev.known_ransomware_campaign_use if kev is not None else None,
                epss_score=epss.epss if epss is not None else None,
                epss_percentile=epss.percentile if epss is not None else None,
                enriched_at=enriched_at,
            )

        return result

    def enrich_findings(
        self,
        findings: Sequence[NormalizedFinding],
        *,
        now: float | None = None,
    ) -> tuple[list[NormalizedFinding], EnrichmentResult]:
        """Attach threat intelligence to a sequence of NormalizedFinding objects."""
        cves = [f.cve_id for f in findings if f.cve_id is not None]
        enrichment = self.enrich_cves(cves, now=now)

        enriched_findings = [
            (
                finding.model_copy(
                    update={"threat_intel": enrichment.intel_by_cve[finding.cve_id]}
                )
                if finding.cve_id and finding.cve_id in enrichment.intel_by_cve
                else finding
            )
            for finding in findings
        ]
        return enriched_findings, enrichment

    def _resolve_kev(
        self,
        cve_ids: list[str],
        result: EnrichmentResult,
        *,
        now: float | None,
    ) -> dict[str, KevRecord]:
        if not self.refresh_cache and self.cache.is_kev_fresh(self.ttl_seconds, now=now):
            result.kev_from_cache = True
            return self.cache.get_kev_records(cve_ids)

        if self.offline:
            if self.cache.has_kev_data():
                result.kev_from_cache = True
                result.kev_stale = True
                result.warnings.append("Offline mode: using stale cached CISA KEV catalog.")
                return self.cache.get_kev_records(cve_ids)
            result.warnings.append(
                "Offline mode: no cached CISA KEV catalog available; "
                "KEV flags will default to False."
            )
            return {}

        try:
            catalog = self._get_kev_client().fetch_catalog()
            self.cache.replace_kev_catalog(
                catalog.records,
                catalog_version=catalog.catalog_version,
                fetched_at=now,
            )
            return self.cache.get_kev_records(cve_ids)
        except HttpRequestError as exc:
            if self.cache.has_kev_data():
                result.kev_from_cache = True
                result.kev_stale = True
                result.warnings.append(
                    f"CISA KEV fetch failed ({exc}); falling back to stale cached catalog."
                )
                return self.cache.get_kev_records(cve_ids)
            result.warnings.append(
                f"CISA KEV fetch failed ({exc}) and no cached catalog exists; "
                "proceeding without KEV data."
            )
            return {}

    def _resolve_epss(
        self,
        cve_ids: list[str],
        result: EnrichmentResult,
        *,
        now: float | None,
    ) -> dict[str, EpssRecord | None]:
        resolved: dict[str, EpssRecord | None] = {}

        if self.refresh_cache and not self.offline:
            missing = set(cve_ids)
        else:
            cached, missing = self.cache.get_epss_records(
                cve_ids,
                ttl_seconds=self.ttl_seconds,
                include_stale=False,
                now=now,
            )
            resolved.update(cached)
            result.epss_cache_hits = len(cached)

        if not missing:
            return resolved

        if self.offline:
            stale_map, still_missing = self.cache.get_epss_records(
                missing,
                ttl_seconds=self.ttl_seconds,
                include_stale=True,
                now=now,
            )
            resolved.update(stale_map)
            result.epss_stale_hits = len(stale_map)
            if stale_map:
                result.warnings.append(
                    f"Offline mode: using stale cached EPSS data for {len(stale_map)} CVE(s)."
                )
            if still_missing:
                result.warnings.append(
                    f"Offline mode: no cached EPSS data available for {len(still_missing)} CVE(s)."
                )
            return resolved

        batch_result = self._get_epss_client().fetch_scores(missing)
        result.warnings.extend(batch_result.warnings)

        if batch_result.records:
            self.cache.upsert_epss_records(batch_result.records, fetched_at=now)
            resolved.update(batch_result.records)
            result.epss_api_fetched = len(batch_result.records)

        if batch_result.failed_cves:
            stale_map, _ = self.cache.get_epss_records(
                batch_result.failed_cves,
                ttl_seconds=self.ttl_seconds,
                include_stale=True,
                now=now,
            )
            resolved.update(stale_map)
            result.epss_stale_hits += len(stale_map)

        return resolved
