"""Unified Pydantic v2 models for scanner findings and risk prioritization."""

from __future__ import annotations

import hashlib
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, computed_field, field_validator

from sift.models.enrichment import ThreatIntel, normalize_optional_cve_id


class PriorityTier(StrEnum):
    """Risk-based remediation priority tiers."""

    P1 = "P1"
    P2 = "P2"
    P3 = "P3"
    P4 = "P4"

    @property
    def label(self) -> str:
        """Human-readable label for terminal tables and reports."""
        return {
            PriorityTier.P1: "Urgent",
            PriorityTier.P2: "High",
            PriorityTier.P3: "Medium",
            PriorityTier.P4: "Low/Info",
        }[self]

    @property
    def rank(self) -> int:
        """Numeric sort rank (1 = highest urgency, 4 = lowest)."""
        return {
            PriorityTier.P1: 1,
            PriorityTier.P2: 2,
            PriorityTier.P3: 3,
            PriorityTier.P4: 4,
        }[self]


def _normalize_target(value: str) -> str:
    cleaned = value.strip().lower().rstrip("/")
    if not cleaned:
        raise ValueError("target must be a non-empty string")
    return cleaned


def _normalize_optional_str(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError("value must be a string or None")
    cleaned = value.strip()
    return cleaned or None


def _normalize_references(values: list[str]) -> list[str]:
    return list(dict.fromkeys(v.strip() for v in values if v and v.strip()))


def _build_dedup_key(
    target: str,
    port: int | None,
    cve_id: str | None,
    rule_id: str | None,
    description: str,
) -> tuple[str, int | None, str]:
    """Build deterministic deduplication key across scanners.

    CVE findings deduplicate on `(target, port, cve_id)`. Non-CVE findings fall
    back to `rule_id` (e.g., Nuclei template ID, Nmap script ID, or GHSA ID), or
    finally a short hash of the normalized description.
    """
    if cve_id:
        identifier = cve_id
    elif rule_id:
        identifier = f"rule:{rule_id.lower()}"
    else:
        digest = hashlib.sha256(description.strip().lower().encode("utf-8")).hexdigest()[:16]
        identifier = f"desc:{digest}"
    return (target, port, identifier)


class RawFinding(BaseModel):
    """Unmerged finding emitted by an individual scanner parser adapter."""

    model_config = ConfigDict(str_strip_whitespace=True)

    target: str = Field(..., min_length=1, description="Host, IP, image, or artifact scanned")
    port: int | None = Field(default=None, ge=1, le=65535, description="Network port if applicable")
    service: str | None = Field(default=None, description="Network service or package identifier")
    cve_id: str | None = Field(default=None, description="Normalized CVE ID (CVE-YYYY-NNNN+)")
    cvss_score: float | None = Field(
        default=None,
        ge=0.0,
        le=10.0,
        description="CVSS base score (0.0-10.0)",
    )
    scanner_source: str = Field(..., min_length=1, description="Originating scanner adapter name")
    description: str = Field(default="", description="Human-readable vulnerability summary")

    rule_id: str | None = Field(
        default=None,
        description="Fallback identifier (e.g., Nuclei template ID, Nmap script ID, GHSA ID)",
    )
    references: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("target")
    @classmethod
    def validate_target(cls, value: str) -> str:
        return _normalize_target(value)

    @field_validator("cve_id", mode="before")
    @classmethod
    def validate_cve_id(cls, value: object) -> str | None:
        return normalize_optional_cve_id(value)

    @field_validator("service", "rule_id", mode="before")
    @classmethod
    def validate_optional_strings(cls, value: object) -> str | None:
        return _normalize_optional_str(value)

    @field_validator("scanner_source")
    @classmethod
    def validate_scanner_source(cls, value: str) -> str:
        cleaned = value.strip().lower()
        if not cleaned:
            raise ValueError("scanner_source must be non-empty")
        return cleaned

    @field_validator("references")
    @classmethod
    def validate_references(cls, values: list[str]) -> list[str]:
        return _normalize_references(values)

    @property
    def dedup_key(self) -> tuple[str, int | None, str]:
        """Deterministic key used to deduplicate findings across scanners."""
        return _build_dedup_key(
            self.target,
            self.port,
            self.cve_id,
            self.rule_id,
            self.description,
        )


class NormalizedFinding(BaseModel):
    """Deduplicated, threat-intel-enriched, and risk-prioritized finding."""

    model_config = ConfigDict(str_strip_whitespace=True)

    target: str = Field(..., min_length=1)
    port: int | None = Field(default=None, ge=1, le=65535)
    service: str | None = None
    cve_id: str | None = None
    cvss_score: float | None = Field(default=None, ge=0.0, le=10.0)
    scanner_sources: list[str] = Field(..., min_length=1)
    description: str = ""
    rule_id: str | None = None
    references: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

    threat_intel: ThreatIntel = Field(default_factory=ThreatIntel)
    priority: PriorityTier = PriorityTier.P4
    priority_reason: str = ""

    @field_validator("target")
    @classmethod
    def validate_target(cls, value: str) -> str:
        return _normalize_target(value)

    @field_validator("cve_id", mode="before")
    @classmethod
    def validate_cve_id(cls, value: object) -> str | None:
        return normalize_optional_cve_id(value)

    @field_validator("service", "rule_id", mode="before")
    @classmethod
    def validate_optional_strings(cls, value: object) -> str | None:
        return _normalize_optional_str(value)

    @field_validator("scanner_sources")
    @classmethod
    def validate_scanner_sources(cls, values: list[str]) -> list[str]:
        normalized = sorted({v.strip().lower() for v in values if v and v.strip()})
        if not normalized:
            raise ValueError("scanner_sources must contain at least one scanner name")
        return normalized

    @field_validator("references")
    @classmethod
    def validate_references(cls, values: list[str]) -> list[str]:
        return _normalize_references(values)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def in_kev(self) -> bool:
        """Whether this finding's CVE is listed in the CISA KEV catalog."""
        return self.threat_intel.in_kev

    @computed_field  # type: ignore[prop-decorator]
    @property
    def epss_score(self) -> float | None:
        """FIRST EPSS exploitation probability score (0.0-1.0), if available."""
        return self.threat_intel.epss_score

    @property
    def dedup_key(self) -> tuple[str, int | None, str]:
        """Deterministic key identifying this deduplicated finding."""
        return _build_dedup_key(
            self.target,
            self.port,
            self.cve_id,
            self.rule_id,
            self.description,
        )

    @property
    def sort_key(self) -> tuple[int, bool, float, float, str, int, str]:
        """Deterministic risk-descending sort key for CLI tables and reports."""
        return (
            self.priority.rank,
            not self.threat_intel.in_kev,
            -(self.threat_intel.epss_score if self.threat_intel.epss_score is not None else -1.0),
            -(self.cvss_score if self.cvss_score is not None else -1.0),
            self.target,
            self.port or 0,
            self.cve_id or self.rule_id or "",
        )
