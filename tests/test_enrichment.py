"""Unit tests for CISA KEV, FIRST EPSS, SQLite TTL cache, and ThreatEnricher."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Any

import pytest

from sift.enrichment import (
    DEFAULT_EPSS_URL,
    DEFAULT_KEV_URL,
    DEFAULT_TTL_SECONDS,
    EpssClient,
    HttpRequestError,
    KevClient,
    ThreatEnricher,
    ThreatIntelCache,
    resolve_cache_dir,
)
from sift.models import EpssRecord, KevRecord, NormalizedFinding


@dataclass
class FakeResponse:
    """Minimal HttpResponse test double."""

    payload: Any
    status_code: int = 200
    json_error: Exception | None = None

    def json(self) -> Any:
        if self.json_error is not None:
            raise self.json_error
        return self.payload

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise HttpRequestError(f"HTTP {self.status_code}")


@dataclass
class FakeHttpClient:
    """Controllable HttpClient test double recording every outbound call."""

    handler: Callable[[str, Mapping[str, str] | None], FakeResponse]
    calls: list[tuple[str, dict[str, str] | None]] = field(default_factory=list)
    closed: bool = False

    def get(
        self,
        url: str,
        *,
        params: Mapping[str, str] | None = None,
    ) -> FakeResponse:
        recorded_params = dict(params) if params is not None else None
        self.calls.append((url, recorded_params))
        return self.handler(url, params)

    def close(self) -> None:
        self.closed = True


SAMPLE_KEV_PAYLOAD: dict[str, Any] = {
    "title": "CISA Catalog of Known Exploited Vulnerabilities",
    "catalogVersion": "2026.11.20",
    "count": 2,
    "vulnerabilities": [
        {
            "cveID": "CVE-2021-44228",
            "vendorProject": "Apache",
            "product": "Log4j2",
            "vulnerabilityName": "Apache Log4j2 Remote Code Execution Vulnerability",
            "dateAdded": "2021-12-10",
            "dueDate": "2021-12-24",
            "knownRansomwareCampaignUse": "Known",
        },
        {
            "cveID": "CVE-2024-3094",
            "vendorProject": "Tukaani",
            "product": "XZ Utils",
            "vulnerabilityName": "XZ Utils Embedded Malicious Code",
            "dateAdded": "2024-04-01",
            "dueDate": "2024-04-22",
            "knownRansomwareCampaignUse": "Unknown",
        },
    ],
}


class TestThreatIntelCache:
    def test_resolve_cache_dir_precedence(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        explicit = tmp_path / "explicit"
        env_dir = tmp_path / "from_env"
        monkeypatch.setenv("SIFT_CACHE_DIR", str(env_dir))

        assert resolve_cache_dir(explicit) == explicit
        assert resolve_cache_dir() == env_dir

        monkeypatch.delenv("SIFT_CACHE_DIR", raising=False)
        default_dir = resolve_cache_dir()
        # Linux/macOS end with ".../sift"; Windows ends with "...\\sift\\Cache"
        assert "sift" in {part.lower() for part in default_dir.parts}

    def test_kev_replace_lookup_and_ttl(self, tmp_path: Path) -> None:
        t0 = 1_700_000_000.0
        with ThreatIntelCache(cache_dir=tmp_path) as cache:
            assert cache.has_kev_data() is False
            assert cache.is_kev_fresh(now=t0) is False

            inserted = cache.replace_kev_catalog(
                [
                    KevRecord(
                        cve_id="CVE-2021-44228",
                        vendor_project="Apache",
                        product="Log4j2",
                        date_added=date(2021, 12, 10),
                        known_ransomware_campaign_use=True,
                    )
                ],
                catalog_version="2026.11.20",
                fetched_at=t0,
            )
            assert inserted == 1
            assert cache.has_kev_data() is True
            assert cache.is_kev_fresh(ttl_seconds=DEFAULT_TTL_SECONDS, now=t0 + 100) is True
            assert (
                cache.is_kev_fresh(ttl_seconds=DEFAULT_TTL_SECONDS, now=t0 + DEFAULT_TTL_SECONDS)
                is False
            )

            found = cache.get_kev_records(["cve-2021-44228", "CVE-2099-0001"])
            assert list(found.keys()) == ["CVE-2021-44228"]
            assert found["CVE-2021-44228"].known_ransomware_campaign_use is True

            # Atomic replacement clears old entries
            cache.replace_kev_catalog([], catalog_version="empty", fetched_at=t0 + 10)
            assert cache.get_kev_records(["CVE-2021-44228"]) == {}

    def test_epss_upsert_negative_caching_ttl_and_stale(self, tmp_path: Path) -> None:
        t0 = 1_700_000_000.0
        with ThreatIntelCache(cache_dir=tmp_path) as cache:
            cache.upsert_epss_records(
                {
                    "CVE-2021-44228": EpssRecord(
                        cve_id="CVE-2021-44228",
                        epss=0.975,
                        percentile=0.999,
                        score_date=date(2026, 11, 20),
                    ),
                    "CVE-2026-9999": None,  # Negative cache entry
                },
                fetched_at=t0,
            )

            cached, missing = cache.get_epss_records(
                ["CVE-2021-44228", "CVE-2026-9999", "CVE-2025-1111"],
                ttl_seconds=DEFAULT_TTL_SECONDS,
                now=t0 + 60,
            )
            assert set(cached.keys()) == {"CVE-2021-44228", "CVE-2026-9999"}
            assert cached["CVE-2021-44228"] is not None
            assert cached["CVE-2021-44228"].epss == pytest.approx(0.975)
            assert cached["CVE-2026-9999"] is None
            assert missing == {"CVE-2025-1111"}

            # After TTL expires, entries are treated as missing unless include_stale=True
            expired_cached, expired_missing = cache.get_epss_records(
                ["CVE-2021-44228", "CVE-2026-9999"],
                ttl_seconds=DEFAULT_TTL_SECONDS,
                now=t0 + DEFAULT_TTL_SECONDS + 1,
            )
            assert expired_cached == {}
            assert expired_missing == {"CVE-2021-44228", "CVE-2026-9999"}

            stale_cached, stale_missing = cache.get_epss_records(
                ["CVE-2021-44228", "CVE-2026-9999"],
                ttl_seconds=DEFAULT_TTL_SECONDS,
                include_stale=True,
                now=t0 + DEFAULT_TTL_SECONDS + 1,
            )
            assert set(stale_cached.keys()) == {"CVE-2021-44228", "CVE-2026-9999"}
            assert stale_missing == set()

            stats = cache.stats()
            assert stats.epss_count == 1
            assert stats.epss_negative_count == 1

            cache.clear()
            cleared = cache.stats()
            assert cleared.epss_count == 0
            assert cleared.epss_negative_count == 0
            assert cleared.kev_fetched_at is None


class TestKevClient:
    def test_fetch_catalog_parses_records_and_skips_malformed(self) -> None:
        payload = {
            **SAMPLE_KEV_PAYLOAD,
            "vulnerabilities": [
                *SAMPLE_KEV_PAYLOAD["vulnerabilities"],
                {"cveID": "NOT-A-CVE", "vendorProject": "Bad"},
                "unexpected-string-row",
            ],
        }
        http = FakeHttpClient(lambda _url, _params: FakeResponse(payload))
        client = KevClient(http_client=http)

        catalog = client.fetch_catalog()
        assert catalog.catalog_version == "2026.11.20"
        assert len(catalog.records) == 2
        assert catalog.skipped_entries == 2
        assert catalog.records[0].cve_id == "CVE-2021-44228"
        assert catalog.records[0].known_ransomware_campaign_use is True
        assert catalog.records[1].known_ransomware_campaign_use is False

    def test_fetch_catalog_raises_on_bad_schema(self) -> None:
        http = FakeHttpClient(lambda _url, _params: FakeResponse({"unexpected": True}))
        with pytest.raises(HttpRequestError):
            KevClient(http_client=http).fetch_catalog()


class TestEpssClient:
    def test_fetch_scores_batches_and_handles_missing_cves(self) -> None:
        def handler(_url: str, params: Mapping[str, str] | None) -> FakeResponse:
            assert params is not None
            batch = params["cve"].split(",")
            # Return EPSS scores only for even-numbered CVEs to verify negative mapping
            data = [
                {
                    "cve": cve,
                    "epss": "0.42000",
                    "percentile": "0.88000",
                    "date": "2026-11-20",
                }
                for cve in batch
                if int(cve.split("-")[-1]) % 2 == 0
            ]
            return FakeResponse({"status": "OK", "data": data})

        http = FakeHttpClient(handler)
        client = EpssClient(batch_size=50, http_client=http)

        cves = [f"CVE-2024-{i:04d}" for i in range(1, 121)]
        result = client.fetch_scores(cves)

        assert len(http.calls) == 3
        assert len(http.calls[0][1]["cve"].split(",")) == 50  # type: ignore[index]
        assert len(http.calls[1][1]["cve"].split(",")) == 50  # type: ignore[index]
        assert len(http.calls[2][1]["cve"].split(",")) == 20  # type: ignore[index]
        assert result.failed_cves == set()
        assert len(result.records) == 120
        assert result.records["CVE-2024-0002"] is not None
        assert result.records["CVE-2024-0002"].epss == pytest.approx(0.42)
        assert result.records["CVE-2024-0001"] is None

    def test_fetch_scores_isolates_failed_batch(self) -> None:
        call_num = 0

        def handler(_url: str, params: Mapping[str, str] | None) -> FakeResponse:
            nonlocal call_num
            call_num += 1
            if call_num == 1:
                raise HttpRequestError("simulated timeout")
            assert params is not None
            return FakeResponse(
                {
                    "status": "OK",
                    "data": [
                        {
                            "cve": cve,
                            "epss": "0.75",
                            "percentile": "0.95",
                            "date": "2026-11-20",
                        }
                        for cve in params["cve"].split(",")
                    ],
                }
            )

        http = FakeHttpClient(handler)
        client = EpssClient(batch_size=2, http_client=http)
        result = client.fetch_scores(
            ["CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003", "CVE-2024-0004"]
        )

        assert result.failed_cves == {"CVE-2024-0001", "CVE-2024-0002"}
        assert set(result.records.keys()) == {"CVE-2024-0003", "CVE-2024-0004"}
        assert len(result.warnings) == 1


class TestThreatEnricher:
    def _make_online_http(self) -> FakeHttpClient:
        def handler(url: str, params: Mapping[str, str] | None) -> FakeResponse:
            if url == DEFAULT_KEV_URL:
                return FakeResponse(SAMPLE_KEV_PAYLOAD)
            if url == DEFAULT_EPSS_URL:
                assert params is not None
                requested = set(params["cve"].split(","))
                scores = {
                    "CVE-2021-44228": ("0.97565", "0.99998"),
                    "CVE-2024-3094": ("0.12000", "0.74000"),
                }
                data = [
                    {
                        "cve": cve,
                        "epss": scores[cve][0],
                        "percentile": scores[cve][1],
                        "date": "2026-11-20",
                    }
                    for cve in sorted(requested)
                    if cve in scores
                ]
                return FakeResponse({"status": "OK", "data": data})
            raise AssertionError(f"Unexpected URL: {url}")

        return FakeHttpClient(handler)

    def test_cold_then_warm_cache_makes_zero_http_calls_on_second_run(
        self,
        tmp_path: Path,
    ) -> None:
        t0 = 1_700_000_000.0
        http = self._make_online_http()
        cves = ["CVE-2021-44228", "CVE-2024-3094", "CVE-2026-8888"]

        with ThreatEnricher(cache_dir=tmp_path, http_client=http) as enricher:
            first = enricher.enrich_cves(cves, now=t0)
            assert len(http.calls) == 2  # 1 KEV + 1 EPSS batch
            assert first.kev_from_cache is False
            assert first.epss_api_fetched == 3
            assert first.intel_by_cve["CVE-2021-44228"].in_kev is True
            assert first.intel_by_cve["CVE-2021-44228"].epss_score == pytest.approx(0.97565)
            assert first.intel_by_cve["CVE-2026-8888"].in_kev is False
            assert first.intel_by_cve["CVE-2026-8888"].epss_score is None

            # Second run within 24h TTL hits cache exclusively (including negative EPSS cache)
            second = enricher.enrich_cves(cves, now=t0 + 3_600)
            assert len(http.calls) == 2
            assert second.kev_from_cache is True
            assert second.epss_cache_hits == 3
            assert second.epss_api_fetched == 0
            assert second.intel_by_cve["CVE-2021-44228"].in_kev is True

            # After 24h TTL expires, both KEV and EPSS refresh
            third = enricher.enrich_cves(cves, now=t0 + DEFAULT_TTL_SECONDS + 10)
            assert len(http.calls) == 4
            assert third.kev_from_cache is False
            assert third.epss_api_fetched == 3

    def test_network_failure_falls_back_to_stale_cache(self, tmp_path: Path) -> None:
        t0 = 1_700_000_000.0
        online_http = self._make_online_http()

        # Prime cache
        with ThreatEnricher(cache_dir=tmp_path, http_client=online_http) as enricher:
            enricher.enrich_cves(["CVE-2021-44228"], now=t0)

        # Simulate complete network outage after TTL expires
        def failing_handler(url: str, _params: Mapping[str, str] | None) -> FakeResponse:
            raise HttpRequestError(f"DNS lookup failed for {url}")

        failing_http = FakeHttpClient(failing_handler)
        with ThreatEnricher(cache_dir=tmp_path, http_client=failing_http) as enricher:
            res = enricher.enrich_cves(
                ["CVE-2021-44228"],
                now=t0 + DEFAULT_TTL_SECONDS + 100,
            )
            assert res.kev_stale is True
            assert res.epss_stale_hits == 1
            assert res.intel_by_cve["CVE-2021-44228"].in_kev is True
            assert res.intel_by_cve["CVE-2021-44228"].epss_score == pytest.approx(0.97565)
            assert len(res.warnings) == 2

    def test_offline_mode_never_calls_network(self, tmp_path: Path) -> None:
        def should_not_be_called(url: str, _params: Mapping[str, str] | None) -> FakeResponse:
            raise AssertionError(f"Offline mode attempted HTTP call to {url}")

        http = FakeHttpClient(should_not_be_called)
        with ThreatEnricher(cache_dir=tmp_path, http_client=http, offline=True) as enricher:
            res = enricher.enrich_cves(["CVE-2021-44228"])
            assert http.calls == []
            assert res.intel_by_cve["CVE-2021-44228"].in_kev is False
            assert res.intel_by_cve["CVE-2021-44228"].epss_score is None
            assert len(res.warnings) == 2

    def test_enrich_findings_leaves_non_cve_findings_untouched(self, tmp_path: Path) -> None:
        http = self._make_online_http()
        findings = [
            NormalizedFinding(
                target="192.0.2.10",
                port=443,
                cve_id="CVE-2021-44228",
                cvss_score=10.0,
                scanner_sources=["nmap", "nuclei"],
            ),
            NormalizedFinding(
                target="192.0.2.10",
                port=80,
                cve_id=None,
                rule_id="exposed-git",
                scanner_sources=["nuclei"],
            ),
        ]

        with ThreatEnricher(cache_dir=tmp_path, http_client=http) as enricher:
            enriched, meta = enricher.enrich_findings(findings)
            assert enriched[0].in_kev is True
            assert enriched[0].epss_score == pytest.approx(0.97565)
            assert enriched[1].in_kev is False
            assert enriched[1].epss_score is None
            assert meta.warnings == []

    def test_empty_cve_list_short_circuits_without_http(self, tmp_path: Path) -> None:
        def should_not_be_called(url: str, _params: Mapping[str, str] | None) -> FakeResponse:
            raise AssertionError(f"Unexpected HTTP call to {url}")

        http = FakeHttpClient(should_not_be_called)
        with ThreatEnricher(cache_dir=tmp_path, http_client=http) as enricher:
            res = enricher.enrich_cves([])
            assert res.intel_by_cve == {}
            assert http.calls == []
