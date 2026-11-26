"""Threat intelligence models for CISA KEV and FIRST EPSS enrichment."""

from __future__ import annotations

import re
from datetime import date, datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator

CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$")


def normalize_required_cve_id(value: object) -> str:
    """Normalize and validate a required CVE identifier."""
    if not isinstance(value, str):
        raise ValueError("cve_id must be a string")
    cleaned = value.strip().upper()
    if not CVE_PATTERN.match(cleaned):
        raise ValueError(f"Invalid CVE identifier format: {value!r}")
    return cleaned


def normalize_optional_cve_id(value: object) -> str | None:
    """Normalize and validate an optional CVE identifier (blank strings become None)."""
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError("cve_id must be a string or None")
    cleaned = value.strip().upper()
    if not cleaned:
        return None
    if not CVE_PATTERN.match(cleaned):
        raise ValueError(f"Invalid CVE identifier format: {value!r}")
    return cleaned


class KevRecord(BaseModel):
    """Single entry from the CISA Known Exploited Vulnerabilities (KEV) catalog."""

    model_config = ConfigDict(frozen=True, str_strip_whitespace=True)

    cve_id: str = Field(..., description="Normalized CVE ID (CVE-YYYY-NNNN+)")
    vendor_project: str = ""
    product: str = ""
    vulnerability_name: str = ""
    date_added: date | None = None
    due_date: date | None = None
    known_ransomware_campaign_use: bool = False

    @field_validator("cve_id", mode="before")
    @classmethod
    def validate_cve_id(cls, value: object) -> str:
        return normalize_required_cve_id(value)


class EpssRecord(BaseModel):
    """Exploit Prediction Scoring System (EPSS) record from FIRST.org."""

    model_config = ConfigDict(frozen=True, str_strip_whitespace=True)

    cve_id: str = Field(..., description="Normalized CVE ID (CVE-YYYY-NNNN+)")
    epss: float = Field(ge=0.0, le=1.0, description="Probability of exploitation in next 30 days")
    percentile: float = Field(ge=0.0, le=1.0, description="Relative percentile across all CVEs")
    score_date: date | None = None

    @field_validator("cve_id", mode="before")
    @classmethod
    def validate_cve_id(cls, value: object) -> str:
        return normalize_required_cve_id(value)


class ThreatIntel(BaseModel):
    """Combined CISA KEV and FIRST EPSS threat intelligence for a finding."""

    model_config = ConfigDict(frozen=True)

    in_kev: bool = False
    kev_date_added: date | None = None
    kev_due_date: date | None = None
    kev_ransomware_use: bool | None = None
    epss_score: float | None = Field(default=None, ge=0.0, le=1.0)
    epss_percentile: float | None = Field(default=None, ge=0.0, le=1.0)
    enriched_at: datetime | None = None
