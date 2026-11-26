"""FIRST.org EPSS public API client with CVE batching."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import date
from typing import Any

from pydantic import ValidationError

from sift.enrichment.http import (
    DEFAULT_TIMEOUT_SECONDS,
    HttpClient,
    HttpRequestError,
    create_default_http_client,
)
from sift.models import EpssRecord, normalize_required_cve_id

DEFAULT_EPSS_URL = "https://api.first.org/data/v1/epss"
DEFAULT_BATCH_SIZE = 50


@dataclass
class EpssBatchResult:
    """Outcome of a batched EPSS lookup across one or more HTTP requests."""

    records: dict[str, EpssRecord | None] = field(default_factory=dict)
    failed_cves: set[str] = field(default_factory=set)
    warnings: list[str] = field(default_factory=list)


def _parse_score_date(raw: Any) -> date | None:
    if not isinstance(raw, str) or not raw.strip():
        return None
    try:
        return date.fromisoformat(raw.strip()[:10])
    except ValueError:
        return None


class EpssClient:
    """Batched client for the free, unauthenticated FIRST EPSS REST API."""

    def __init__(
        self,
        *,
        url: str = DEFAULT_EPSS_URL,
        batch_size: int = DEFAULT_BATCH_SIZE,
        http_client: HttpClient | None = None,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        if batch_size < 1 or batch_size > 100:
            raise ValueError("batch_size must be between 1 and 100")
        self.url = url
        self.batch_size = batch_size
        self._owns_client = http_client is None
        self._client = http_client or create_default_http_client(timeout=timeout)

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def __enter__(self) -> EpssClient:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def fetch_scores(self, cve_ids: Iterable[str]) -> EpssBatchResult:
        """Fetch EPSS scores for CVEs in rate-limit-friendly batches.

        CVEs present in a successful batch response map to an `EpssRecord`; CVEs
        absent from a successful batch response map to `None` (enabling negative
        caching). If an individual batch fails, its CVEs are recorded in
        `failed_cves` and remaining batches still proceed.
        """
        normalized = sorted({normalize_required_cve_id(cve) for cve in cve_ids})
        result = EpssBatchResult()
        if not normalized:
            return result

        for idx in range(0, len(normalized), self.batch_size):
            batch = normalized[idx : idx + self.batch_size]
            try:
                batch_records = self._fetch_single_batch(batch)
            except HttpRequestError as exc:
                result.failed_cves.update(batch)
                result.warnings.append(
                    f"FIRST EPSS batch failed ({len(batch)} CVEs): {exc}"
                )
                continue

            for cve_id in batch:
                result.records[cve_id] = batch_records.get(cve_id)

        return result

    def _fetch_single_batch(self, batch: list[str]) -> dict[str, EpssRecord]:
        response = self._client.get(self.url, params={"cve": ",".join(batch)})
        try:
            payload = response.json()
        except Exception as exc:
            raise HttpRequestError(f"Invalid JSON in FIRST EPSS response: {exc}") from exc

        if not isinstance(payload, dict) or not isinstance(payload.get("data"), list):
            raise HttpRequestError("Unexpected FIRST EPSS response structure: missing 'data'")

        parsed: dict[str, EpssRecord] = {}
        for item in payload["data"]:
            if not isinstance(item, dict):
                continue
            raw_cve = item.get("cve")
            raw_epss = item.get("epss")
            raw_percentile = item.get("percentile")
            if not isinstance(raw_cve, str) or raw_epss is None or raw_percentile is None:
                continue
            try:
                record = EpssRecord(
                    cve_id=raw_cve,
                    epss=float(raw_epss),
                    percentile=float(raw_percentile),
                    score_date=_parse_score_date(item.get("date")),
                )
                parsed[record.cve_id] = record
            except (ValidationError, ValueError, TypeError):
                continue

        return parsed
