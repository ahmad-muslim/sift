"""Unit and end-to-end tests for deduplication, prioritization, pipeline, and exporters."""

from __future__ import annotations

import csv
import io
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

import pytest

from sift.core import (
    deduplicate_findings,
    evaluate_priority,
    prioritize_findings,
    run_pipeline,
)
from sift.enrichment import DEFAULT_EPSS_URL, DEFAULT_KEV_URL, ThreatEnricher
from sift.models import NormalizedFinding, PriorityTier, RawFinding, ThreatIntel
from sift.reporters import (
    CSV_COLUMNS,
    export_csv,
    export_markdown,
    format_csv,
    format_markdown,
    sanitize_csv_cell,
)

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@dataclass
class _StubResponse:
    payload: Any
    status_code: int = 200

    def json(self) -> Any:
        return self.payload

    def raise_for_status(self) -> None:
        return None


class _StubHttpClient:
    def get(
        self,
        url: str,
        *,
        params: Mapping[str, str] | None = None,
    ) -> _StubResponse:
        if url == DEFAULT_KEV_URL:
            return _StubResponse(
                {
                    "catalogVersion": "2026.11.20",
                    "vulnerabilities": [
                        {
                            "cveID": "CVE-2021-44228",
                            "vendorProject": "Apache",
                            "product": "Log4j2",
                            "vulnerabilityName": "Apache Log4j2 RCE",
                            "dateAdded": "2021-12-10",
                            "dueDate": "2021-12-24",
                            "knownRansomwareCampaignUse": "Known",
                        },
                        {
                            "cveID": "CVE-2021-41773",
                            "vendorProject": "Apache",
                            "product": "HTTP Server",
                            "vulnerabilityName": "Apache Path Traversal",
                            "dateAdded": "2021-11-03",
                            "dueDate": "2021-11-17",
                            "knownRansomwareCampaignUse": "Unknown",
                        },
                    ],
                }
            )
        if url == DEFAULT_EPSS_URL:
            assert params is not None
            requested = set(params["cve"].split(","))
            epss_scores = {
                "CVE-2021-44228": ("0.97565", "0.99998"),
                "CVE-2021-41773": ("0.94100", "0.99900"),
                "CVE-2014-0160": ("0.88000", "0.99500"),
                "CVE-2023-38545": ("0.45000", "0.92000"),
                "CVE-2024-6387": ("0.15000", "0.75000"),
                "CVE-2024-3094": ("0.08000", "0.60000"),
                "CVE-2023-38546": ("0.02000", "0.30000"),
            }
            return _StubResponse(
                {
                    "status": "OK",
                    "data": [
                        {
                            "cve": cve,
                            "epss": epss_scores[cve][0],
                            "percentile": epss_scores[cve][1],
                            "date": "2026-11-20",
                        }
                        for cve in sorted(requested)
                        if cve in epss_scores
                    ],
                }
            )
        raise AssertionError(f"Unexpected URL: {url}")

    def close(self) -> None:
        return None


class TestDeduplicator:
    def test_merges_cross_scanner_duplicates_preserving_sources_and_max_cvss(self) -> None:
        raw = [
            RawFinding(
                target="192.0.2.10",
                port=443,
                service=None,
                cve_id="CVE-2021-44228",
                cvss_score=9.3,
                scanner_source="nmap",
                description="Short Nmap description.",
                references=["https://a.example"],
            ),
            RawFinding(
                target="192.0.2.10",
                port=443,
                service="https",
                cve_id="cve-2021-44228",
                cvss_score=10.0,
                scanner_source="nuclei",
                description="Much more detailed Nuclei description for Apache Log4j2 RCE.",
                references=["https://a.example", "https://b.example"],
            ),
            RawFinding(
                target="192.0.2.10",
                port=8443,
                service="https",
                cve_id="CVE-2021-44228",
                cvss_score=10.0,
                scanner_source="nuclei",
                description="Different port stays distinct.",
            ),
        ]

        deduped = deduplicate_findings(raw)
        assert len(deduped) == 2

        merged = deduped[0]
        assert merged.scanner_sources == ["nmap", "nuclei"]
        assert merged.cvss_score == pytest.approx(10.0)
        assert merged.service == "https"
        assert "Much more detailed" in merged.description
        assert merged.references == ["https://a.example", "https://b.example"]


class TestPrioritizer:
    @pytest.mark.parametrize(
        ("in_kev", "epss", "cvss", "expected_tier"),
        [
            (True, 0.01, 2.0, PriorityTier.P1),   # KEV overrides low EPSS/CVSS
            (False, 0.70, 5.0, PriorityTier.P1),  # EPSS >= 0.70 boundary
            (False, 0.95, None, PriorityTier.P1), # High EPSS without CVSS
            (False, 0.69, 5.0, PriorityTier.P2),  # EPSS in [0.30, 0.70)
            (False, 0.30, None, PriorityTier.P2), # EPSS >= 0.30 boundary
            (False, 0.05, 8.0, PriorityTier.P2),  # CVSS >= 8.0 boundary
            (False, None, 9.8, PriorityTier.P2),  # High CVSS without EPSS
            (False, 0.29, 7.9, PriorityTier.P3),  # CVSS upper P3 boundary
            (False, None, 4.0, PriorityTier.P3),  # CVSS lower P3 boundary
            (False, 0.10, 3.9, PriorityTier.P4),  # CVSS < 4.0
            (False, None, None, PriorityTier.P4), # Informational / non-CVE
        ],
    )
    def test_priority_tier_boundaries(
        self,
        in_kev: bool,
        epss: float | None,
        cvss: float | None,
        expected_tier: PriorityTier,
    ) -> None:
        finding = NormalizedFinding(
            target="192.0.2.1",
            cve_id="CVE-2024-0001",
            cvss_score=cvss,
            scanner_sources=["nmap"],
            threat_intel=ThreatIntel(in_kev=in_kev, epss_score=epss),
        )
        tier, reason = evaluate_priority(finding)
        assert tier == expected_tier
        assert reason != ""


class TestEndToEndPipeline:
    def test_ingests_deduplicates_enriches_and_prioritizes_all_three_scanners(
        self,
        tmp_path: Path,
    ) -> None:
        scan_files = [
            FIXTURES_DIR / "nmap_vuln.xml",
            FIXTURES_DIR / "nuclei_results.jsonl",
            FIXTURES_DIR / "trivy_scan.json",
        ]

        with ThreatEnricher(cache_dir=tmp_path, http_client=_StubHttpClient()) as enricher:
            result = run_pipeline(scan_files, enricher=enricher)

        # 5 Nmap + 4 Nuclei + 4 Trivy = 13 raw; CVE-2021-44228 on 192.0.2.10:443 merged -> 12 unique
        assert result.raw_count == 13
        assert result.unique_count == 12
        assert result.duplicates_merged == 1
        assert len(result.findings) == 12
        assert result.kev_count == 2

        # Top finding must be the deduplicated Nmap+Nuclei Log4j2 P1 KEV finding
        top = result.findings[0]
        assert top.cve_id == "CVE-2021-44228"
        assert top.scanner_sources == ["nmap", "nuclei"]
        assert top.priority == PriorityTier.P1
        assert top.in_kev is True

        # Verify P1 findings include KEV entries and Heartbleed (EPSS 0.88 >= 0.70)
        p1_cves = {f.cve_id for f in result.findings if f.priority == PriorityTier.P1}
        assert p1_cves == {"CVE-2021-44228", "CVE-2021-41773", "CVE-2014-0160"}

        # Verify filtering (--cve-only and --min-priority P2)
        with ThreatEnricher(cache_dir=tmp_path, http_client=_StubHttpClient()) as enricher:
            filtered = run_pipeline(
                scan_files,
                enricher=enricher,
                cve_only=True,
                min_priority=PriorityTier.P2,
            )
        assert all(f.cve_id is not None for f in filtered.findings)
        assert all(f.priority in {PriorityTier.P1, PriorityTier.P2} for f in filtered.findings)


class TestReporters:
    def _sample_findings(self) -> list[NormalizedFinding]:
        return prioritize_findings(
            [
                NormalizedFinding(
                    target="192.0.2.10",
                    port=443,
                    service="https",
                    cve_id="CVE-2021-44228",
                    cvss_score=10.0,
                    scanner_sources=["nmap", "nuclei"],
                    description="=cmd|' /C calc'!A0 | Log4j2 RCE\nmultiline",
                    references=["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
                    threat_intel=ThreatIntel(
                        in_kev=True,
                        kev_date_added=date(2021, 12, 10),
                        kev_due_date=date(2021, 12, 24),
                        kev_ransomware_use=True,
                        epss_score=0.97565,
                        epss_percentile=0.99998,
                    ),
                ),
                NormalizedFinding(
                    target="dockerfile",
                    port=None,
                    service="dockerfile",
                    cve_id=None,
                    rule_id="DS002",
                    cvss_score=None,
                    scanner_sources=["trivy"],
                    description="Container runs as root.",
                ),
            ]
        )

    def test_csv_export_and_formula_injection_sanitization(self, tmp_path: Path) -> None:
        assert sanitize_csv_cell("=SUM(A1)") == "'=SUM(A1)"
        assert sanitize_csv_cell("+1+1") == "'+1+1"
        assert sanitize_csv_cell("@cmd") == "'@cmd"
        assert sanitize_csv_cell("normal text") == "normal text"

        findings = self._sample_findings()
        csv_text = format_csv(findings)
        rows = list(csv.DictReader(io.StringIO(csv_text)))

        assert tuple(rows[0].keys()) == CSV_COLUMNS
        assert len(rows) == 2
        assert rows[0]["priority"] == "P1"
        assert rows[0]["in_kev"] == "true"
        assert rows[0]["scanner_sources"] == "nmap, nuclei"
        # Dangerous leading '=' neutralized with single quote
        assert rows[0]["description"].startswith("'=cmd")

        out_path = export_csv(findings, tmp_path / "reports" / "out.csv")
        assert out_path.exists()
        assert out_path.read_text(encoding="utf-8") == csv_text

    def test_markdown_export_escapes_pipes_and_renders_summary(self, tmp_path: Path) -> None:
        findings = self._sample_findings()
        md = format_markdown(
            findings,
            raw_count=3,
            duplicates_merged=1,
            warnings=["Offline mode: using cached KEV catalog."],
            generated_at=datetime(2026, 11, 25, 12, 0, 0, tzinfo=UTC),
        )

        assert "# Vulnerability Prioritization Report (`sift`)" in md
        assert "| Duplicate Findings Merged | 1 |" in md
        assert "> [!WARNING]" in md
        assert "**P1 (Urgent)**" in md
        assert "nmap, nuclei" in md
        assert "## High-Priority Remediation Details (P1 & P2)" in md
        assert "2021-12-24" in md  # KEV due date included in details

        out_path = export_markdown(findings, tmp_path / "reports" / "out.md")
        assert out_path.exists()
        assert "## Prioritized Findings" in out_path.read_text(encoding="utf-8")
