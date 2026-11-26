"""Unit tests for the modular parser registry and Nmap, Nuclei, and Trivy adapters."""

from __future__ import annotations

from pathlib import Path
from typing import ClassVar

import pytest

from sift.models import RawFinding
from sift.parsers import (
    BaseParser,
    NmapXmlParser,
    NucleiJsonlParser,
    ParseError,
    TrivyJsonParser,
    create_default_registry,
)

FIXTURES_DIR = Path(__file__).parent / "fixtures"


class DummyCustomParser(BaseParser):
    """Minimal third-party parser verifying contributor extensibility."""

    name: ClassVar[str] = "custom-scanner"
    description: ClassVar[str] = "Example custom scanner adapter"

    def can_parse(self, path: Path, preview: str) -> bool:
        return preview.startswith("CUSTOM_SCAN:")

    def parse_text(self, content: str, *, source_name: str = "<memory>") -> list[RawFinding]:
        return [
            RawFinding(
                target="198.51.100.5",
                port=8080,
                cve_id="CVE-2025-0001",
                scanner_source=self.name,
                description=f"Parsed from {source_name}",
            )
        ]


class TestParserRegistry:
    def test_auto_detects_all_builtin_fixtures(self) -> None:
        registry = create_default_registry()
        assert [p.name for p in registry.list_parsers()] == ["nmap", "nuclei", "trivy"]

        nmap_name, nmap_findings = registry.parse_file(FIXTURES_DIR / "nmap_vuln.xml")
        nuclei_name, nuclei_findings = registry.parse_file(FIXTURES_DIR / "nuclei_results.jsonl")
        trivy_name, trivy_findings = registry.parse_file(FIXTURES_DIR / "trivy_scan.json")

        assert nmap_name == "nmap"
        assert nuclei_name == "nuclei"
        assert trivy_name == "trivy"
        assert len(nmap_findings) == 5
        assert len(nuclei_findings) == 4
        assert len(trivy_findings) == 4

    def test_custom_adapter_registration_and_unknown_format(self, tmp_path: Path) -> None:
        registry = create_default_registry()
        registry.register(DummyCustomParser())

        custom_file = tmp_path / "scan.txt"
        custom_file.write_text("CUSTOM_SCAN:ok", encoding="utf-8")
        name, findings = registry.parse_file(custom_file)
        assert name == "custom-scanner"
        assert len(findings) == 1
        assert findings[0].cve_id == "CVE-2025-0001"

        unknown_file = tmp_path / "unknown.txt"
        unknown_file.write_text("unrecognized format payload", encoding="utf-8")
        with pytest.raises(ParseError, match="Could not auto-detect"):
            registry.parse_file(unknown_file)

        with pytest.raises(ParseError, match="Unknown parser"):
            registry.get("nonexistent")

        with pytest.raises(ValueError, match="already registered"):
            registry.register(DummyCustomParser())


class TestNmapXmlParser:
    def test_parses_vulners_nse_tables_and_filters_not_vulnerable(self) -> None:
        parser = NmapXmlParser()
        findings = parser.parse(FIXTURES_DIR / "nmap_vuln.xml")

        # 2 vulners CVEs + 1 heartbleed CVE + 1 non-CVE weak cipher + 1 SSH CVE
        # (http-shellshock NOT VULNERABLE and http-title info script must be excluded)
        assert len(findings) == 5

        by_key = {(f.target, f.port, f.cve_id or f.rule_id): f for f in findings}

        log4j = by_key[("192.0.2.10", 443, "CVE-2021-44228")]
        assert log4j.service == "https"
        assert log4j.cvss_score == pytest.approx(10.0)
        assert log4j.scanner_source == "nmap"
        assert log4j.metadata["is_exploit"] is True

        heartbleed = by_key[("192.0.2.10", 443, "CVE-2014-0160")]
        assert heartbleed.cvss_score == pytest.approx(7.5)
        assert "https://heartbleed.com/" in heartbleed.references

        weak_cipher = by_key[("192.0.2.10", 443, "ssl-weak-cipher")]
        assert weak_cipher.cve_id is None
        assert weak_cipher.rule_id == "ssl-weak-cipher"

        ssh_finding = by_key[("app.example", 22, "CVE-2024-6387")]
        assert ssh_finding.service == "ssh"
        assert ssh_finding.cvss_score == pytest.approx(8.1)
        assert ssh_finding.metadata["ip"] == "192.0.2.20"

        # Ensure NOT VULNERABLE CVE-2014-6271 was filtered out
        assert all(f.cve_id != "CVE-2014-6271" for f in findings)

    def test_rejects_xxe_and_dtd_payloads(self) -> None:
        xxe_xml = """<?xml version="1.0"?>
        <!DOCTYPE nmaprun [
          <!ENTITY xxe SYSTEM "file:///etc/passwd">
        ]>
        <nmaprun><host><address addr="&xxe;" addrtype="ipv4"/></host></nmaprun>
        """
        with pytest.raises(ParseError):
            NmapXmlParser().parse_text(xxe_xml, source_name="xxe.xml")


class TestNucleiJsonlParser:
    def test_parses_single_multi_cve_and_non_cve_records(self) -> None:
        parser = NucleiJsonlParser()
        findings = parser.parse(FIXTURES_DIR / "nuclei_results.jsonl")

        assert len(findings) == 4
        assert all(f.scanner_source == "nuclei" for f in findings)

        log4j = findings[0]
        assert log4j.target == "192.0.2.10"
        assert log4j.port == 443
        assert log4j.service == "https"
        assert log4j.cve_id == "CVE-2021-44228"
        assert log4j.cvss_score == pytest.approx(10.0)

        git_config = findings[1]
        assert git_config.cve_id is None
        assert git_config.rule_id == "git-config"
        assert git_config.port == 443

        # Multi-CVE fan-out with inferred HTTP port 80
        multi = findings[2:]
        assert [(f.target, f.port, f.cve_id) for f in multi] == [
            ("app.example", 80, "CVE-2023-38545"),
            ("app.example", 80, "CVE-2023-38546"),
        ]

    def test_raises_parse_error_on_malformed_jsonl_line(self) -> None:
        with pytest.raises(ParseError, match="line 2"):
            NucleiJsonlParser().parse_text('{"template-id": "a", "info": {}}\n{bad json\n')


class TestTrivyJsonParser:
    def test_parses_vulnerabilities_cvss_precedence_ghsa_and_misconfigs(self) -> None:
        parser = TrivyJsonParser()
        findings = parser.parse(FIXTURES_DIR / "trivy_scan.json")

        # 3 vulnerabilities + 1 failed misconfiguration (PASS misconfig excluded)
        assert len(findings) == 4
        assert all(f.scanner_source == "trivy" and f.port is None for f in findings)

        curl = findings[0]
        assert curl.cve_id == "CVE-2023-38545"
        assert curl.service == "curl@8.2.1-r0"
        # NVD V3Score (9.8) preferred over RedHat V3Score (9.1)
        assert curl.cvss_score == pytest.approx(9.8)
        assert curl.metadata["fixed_version"] == "8.4.0-r0"
        assert curl.references[0] == "https://avd.aquasec.com/nvd/cve-2023-38545"

        xz = findings[1]
        assert xz.cve_id == "CVE-2024-3094"
        assert xz.cvss_score == pytest.approx(10.0)

        ghsa = findings[2]
        assert ghsa.cve_id is None
        assert ghsa.rule_id == "GHSA-jfh8-c2jp-5v3q"
        # Falls back to V2Score when no V3Score exists
        assert ghsa.cvss_score == pytest.approx(7.8)

        misconfig = findings[3]
        assert misconfig.cve_id is None
        assert misconfig.rule_id == "DS002"
        assert misconfig.target == "dockerfile"
        assert misconfig.metadata["kind"] == "misconfiguration"

    def test_empty_results_returns_empty_list(self) -> None:
        assert TrivyJsonParser().parse_text('{"SchemaVersion": 2, "Results": null}') == []
