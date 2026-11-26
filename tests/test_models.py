"""Unit tests for sift unified Pydantic v2 data models."""

from __future__ import annotations

from datetime import date

import pytest
from pydantic import ValidationError

from sift.models import (
    EpssRecord,
    KevRecord,
    NormalizedFinding,
    PriorityTier,
    RawFinding,
    ThreatIntel,
)


class TestThreatIntelModels:
    def test_kev_record_normalizes_cve(self) -> None:
        record = KevRecord(
            cve_id=" cve-2021-44228 ",
            vendor_project="Apache",
            product="Log4j2",
            vulnerability_name="Apache Log4j2 Remote Code Execution",
            date_added=date(2021, 12, 10),
            known_ransomware_campaign_use=True,
        )
        assert record.cve_id == "CVE-2021-44228"
        assert record.known_ransomware_campaign_use is True

    @pytest.mark.parametrize("bad_cve", ["", "   ", "CVE-21-1234", "GHSA-1234-5678", "not-a-cve"])
    def test_kev_record_rejects_invalid_cve(self, bad_cve: str) -> None:
        with pytest.raises(ValidationError):
            KevRecord(cve_id=bad_cve)

    def test_epss_record_bounds(self) -> None:
        record = EpssRecord(cve_id="cve-2023-23397", epss=0.9712, percentile=0.999)
        assert record.cve_id == "CVE-2023-23397"
        assert record.epss == pytest.approx(0.9712)

        with pytest.raises(ValidationError):
            EpssRecord(cve_id="CVE-2023-23397", epss=1.01, percentile=0.5)

        with pytest.raises(ValidationError):
            EpssRecord(cve_id="CVE-2023-23397", epss=-0.01, percentile=0.5)

    def test_threat_intel_defaults(self) -> None:
        intel = ThreatIntel()
        assert intel.in_kev is False
        assert intel.epss_score is None
        assert intel.epss_percentile is None


class TestRawFinding:
    def test_normalization_of_fields(self) -> None:
        finding = RawFinding(
            target="  Web01.Example.COM/  ",
            port=8443,
            service="  nginx  ",
            cve_id=" cve-2024-6387 ",
            cvss_score=8.1,
            scanner_source="  Nuclei ",
            description="  OpenSSH regreSSHion  ",
            rule_id="  openssh-regresshion  ",
            references=[" https://a.example ", "https://a.example", "  ", "https://b.example"],
        )

        assert finding.target == "web01.example.com"
        assert finding.port == 8443
        assert finding.service == "nginx"
        assert finding.cve_id == "CVE-2024-6387"
        assert finding.scanner_source == "nuclei"
        assert finding.description == "OpenSSH regreSSHion"
        assert finding.rule_id == "openssh-regresshion"
        assert finding.references == ["https://a.example", "https://b.example"]

    def test_portless_and_non_cve_finding_retained_with_rule_id(self) -> None:
        finding = RawFinding(
            target="alpine:3.18",
            port=None,
            service="openssl@3.0.2",
            cve_id="   ",
            cvss_score=None,
            scanner_source="trivy",
            rule_id="GHSA-xxxx-yyyy-zzzz",
            description="Advisory without assigned CVE.",
        )
        assert finding.port is None
        assert finding.cve_id is None
        assert finding.dedup_key == ("alpine:3.18", None, "rule:ghsa-xxxx-yyyy-zzzz")

    def test_dedup_key_precedence_cve_over_rule_over_description(self) -> None:
        with_cve = RawFinding(
            target="192.0.2.5",
            port=22,
            cve_id="CVE-2024-6387",
            rule_id="nmap-ssh-vuln",
            scanner_source="nmap",
            description="SSH issue",
        )
        with_rule = RawFinding(
            target="192.0.2.5",
            port=22,
            cve_id=None,
            rule_id="exposed-git",
            scanner_source="nuclei",
            description="Exposed .git directory",
        )
        desc_only_a = RawFinding(
            target="192.0.2.5",
            port=80,
            scanner_source="nmap",
            description="Weak TLS cipher enabled",
        )
        desc_only_b = RawFinding(
            target="192.0.2.5",
            port=80,
            scanner_source="nuclei",
            description="  weak tls cipher enabled ",
        )

        assert with_cve.dedup_key == ("192.0.2.5", 22, "CVE-2024-6387")
        assert with_rule.dedup_key == ("192.0.2.5", 22, "rule:exposed-git")
        assert desc_only_a.dedup_key == desc_only_b.dedup_key
        assert desc_only_a.dedup_key[2].startswith("desc:")

    @pytest.mark.parametrize("bad_port", [0, -1, 65536])
    def test_invalid_port_rejected(self, bad_port: int) -> None:
        with pytest.raises(ValidationError):
            RawFinding(target="192.0.2.1", port=bad_port, scanner_source="nmap")

    @pytest.mark.parametrize("bad_cvss", [-0.1, 10.1])
    def test_invalid_cvss_rejected(self, bad_cvss: float) -> None:
        with pytest.raises(ValidationError):
            RawFinding(target="192.0.2.1", cvss_score=bad_cvss, scanner_source="nmap")

    def test_invalid_cve_rejected(self) -> None:
        with pytest.raises(ValidationError):
            RawFinding(target="192.0.2.1", cve_id="CVE-2024-12", scanner_source="nmap")


class TestNormalizedFindingAndPriority:
    def test_scanner_sources_deduped_and_sorted(self) -> None:
        finding = NormalizedFinding(
            target="app.example",
            port=443,
            cve_id="CVE-2021-44228",
            cvss_score=10.0,
            scanner_sources=["Trivy", "nmap", "NMAP", "nuclei"],
        )
        assert finding.scanner_sources == ["nmap", "nuclei", "trivy"]

    def test_computed_fields_and_serialization(self, sample_threat_intel: ThreatIntel) -> None:
        finding = NormalizedFinding(
            target="192.0.2.10",
            port=443,
            cve_id="CVE-2024-3094",
            cvss_score=10.0,
            scanner_sources=["nmap", "nuclei"],
            threat_intel=sample_threat_intel,
            priority=PriorityTier.P1,
            priority_reason="Listed in CISA KEV",
        )
        assert finding.in_kev is True
        assert finding.epss_score == pytest.approx(0.87)

        dumped = finding.model_dump()
        assert dumped["in_kev"] is True
        assert dumped["epss_score"] == pytest.approx(0.87)
        assert dumped["priority"] == PriorityTier.P1

    def test_priority_tier_labels_and_ranks(self) -> None:
        assert [t.rank for t in PriorityTier] == [1, 2, 3, 4]
        assert PriorityTier.P1.label == "Urgent"
        assert PriorityTier.P2.label == "High"
        assert PriorityTier.P3.label == "Medium"
        assert PriorityTier.P4.label == "Low/Info"

    def test_sort_key_orders_highest_risk_first(self) -> None:
        p4_info = NormalizedFinding(
            target="192.0.2.1",
            scanner_sources=["nuclei"],
            rule_id="tech-detect",
            priority=PriorityTier.P4,
        )
        p3_med = NormalizedFinding(
            target="192.0.2.1",
            cve_id="CVE-2023-0001",
            cvss_score=5.3,
            scanner_sources=["trivy"],
            priority=PriorityTier.P3,
        )
        p2_high = NormalizedFinding(
            target="192.0.2.1",
            cve_id="CVE-2023-0002",
            cvss_score=8.8,
            scanner_sources=["nmap"],
            priority=PriorityTier.P2,
        )
        p1_epss = NormalizedFinding(
            target="192.0.2.1",
            cve_id="CVE-2023-0003",
            cvss_score=7.5,
            scanner_sources=["nuclei"],
            threat_intel=ThreatIntel(in_kev=False, epss_score=0.85),
            priority=PriorityTier.P1,
        )
        p1_kev = NormalizedFinding(
            target="192.0.2.1",
            cve_id="CVE-2023-0004",
            cvss_score=6.5,
            scanner_sources=["nmap", "nuclei"],
            threat_intel=ThreatIntel(in_kev=True, epss_score=0.40),
            priority=PriorityTier.P1,
        )

        ordered = sorted(
            [p4_info, p2_high, p1_epss, p3_med, p1_kev],
            key=lambda item: item.sort_key,
        )
        assert [item.cve_id or item.rule_id for item in ordered] == [
            "CVE-2023-0004",  # P1 + KEV
            "CVE-2023-0003",  # P1 + high EPSS
            "CVE-2023-0002",  # P2
            "CVE-2023-0001",  # P3
            "tech-detect",    # P4
        ]
