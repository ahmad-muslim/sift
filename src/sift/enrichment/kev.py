"""CISA Known Exploited Vulnerabilities (KEV) public JSON feed client."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from typing import Any

from pydantic import ValidationError

from sift.enrichment.http import (
    DEFAULT_TIMEOUT_SECONDS,
    HttpClient,
    HttpRequestError,
    create_default_http_client,
)
from sift.models import KevRecord

DEFAULT_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)


@dataclass(frozen=True)
class KevCatalog:
    """Parsed CISA KEV catalog snapshot."""

    records: list[KevRecord]
    catalog_version: str = ""
    skipped_entries: int = 0


def _parse_date(raw: Any) -> date | None:
    if not isinstance(raw, str) or not raw.strip():
        return None
    try:
        return date.fromisoformat(raw.strip()[:10])
    except ValueError:
        return None


def _parse_ransomware_flag(raw: Any) -> bool:
    if isinstance(raw, bool):
        return raw
    if isinstance(raw, str):
        return raw.strip().lower() == "known"
    return False


class KevClient:
    """Client for fetching and parsing the unauthenticated CISA KEV JSON feed."""

    def __init__(
        self,
        *,
        url: str = DEFAULT_KEV_URL,
        http_client: HttpClient | None = None,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        self.url = url
        self._owns_client = http_client is None
        self._client = http_client or create_default_http_client(timeout=timeout)

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def __enter__(self) -> KevClient:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def fetch_catalog(self) -> KevCatalog:
        """Download and parse the CISA KEV JSON catalog."""
        response = self._client.get(self.url)
        try:
            payload = response.json()
        except Exception as exc:
            raise HttpRequestError(f"Invalid JSON in CISA KEV feed: {exc}") from exc

        if not isinstance(payload, dict) or not isinstance(payload.get("vulnerabilities"), list):
            raise HttpRequestError("Unexpected CISA KEV feed structure: missing 'vulnerabilities'")

        catalog_version = str(payload.get("catalogVersion") or "")
        records: list[KevRecord] = []
        skipped = 0

        for entry in payload["vulnerabilities"]:
            if not isinstance(entry, dict):
                skipped += 1
                continue
            raw_cve = entry.get("cveID")
            if not isinstance(raw_cve, str):
                skipped += 1
                continue
            try:
                record = KevRecord(
                    cve_id=raw_cve,
                    vendor_project=str(entry.get("vendorProject") or ""),
                    product=str(entry.get("product") or ""),
                    vulnerability_name=str(entry.get("vulnerabilityName") or ""),
                    date_added=_parse_date(entry.get("dateAdded")),
                    due_date=_parse_date(entry.get("dueDate")),
                    known_ransomware_campaign_use=_parse_ransomware_flag(
                        entry.get("knownRansomwareCampaignUse")
                    ),
                )
                records.append(record)
            except (ValidationError, ValueError, TypeError):
                skipped += 1

        return KevCatalog(
            records=records,
            catalog_version=catalog_version,
            skipped_entries=skipped,
        )
