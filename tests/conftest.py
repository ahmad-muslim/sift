"""Shared pytest fixtures for sift test suite."""

from __future__ import annotations

import pytest

from sift.models import RawFinding, ThreatIntel


@pytest.fixture
def sample_raw_finding() -> RawFinding:
    """Return a realistic CVE-backed RawFinding."""
    return RawFinding(
        target="192.0.2.10",
        port=443,
        service="https",
        cve_id="CVE-2024-3094",
        cvss_score=10.0,
        scanner_source="nmap",
        description="XZ Utils backdoor in liblzma.",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2024-3094"],
    )


@pytest.fixture
def sample_threat_intel() -> ThreatIntel:
    """Return a populated ThreatIntel payload for testing."""
    return ThreatIntel(
        in_kev=True,
        epss_score=0.87,
        epss_percentile=0.99,
    )
