"""Nuclei JSONL scan output parser."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, ClassVar
from urllib.parse import urlparse

from sift.models import CVE_PATTERN, RawFinding
from sift.parsers.base import BaseParser, ParseError

SCHEME_DEFAULT_PORTS: dict[str, int] = {
    "http": 80,
    "https": 443,
    "ssh": 22,
    "ftp": 21,
    "smtp": 25,
    "dns": 53,
    "rdp": 3389,
}


def _extract_host_port_service(
    record: dict[str, Any],
) -> tuple[str | None, int | None, str | None]:
    """Extract normalized target host, port, and service from a Nuclei JSONL record."""
    raw_host = str(record.get("host") or record.get("matched-at") or "").strip()
    raw_ip = str(record.get("ip") or "").strip() or None
    raw_scheme = str(record.get("scheme") or "").strip().lower() or None
    raw_type = str(record.get("type") or "").strip().lower() or None

    parsed_host: str | None = None
    parsed_port: int | None = None
    parsed_scheme: str | None = None

    if raw_host:
        url_candidate = raw_host if "://" in raw_host else f"//{raw_host}"
        parsed = urlparse(url_candidate)
        parsed_host = parsed.hostname
        parsed_scheme = parsed.scheme.lower() or None
        try:
            parsed_port = parsed.port
        except ValueError:
            parsed_port = None

    explicit_port: int | None = None
    raw_port = record.get("port")
    if isinstance(raw_port, int) and 1 <= raw_port <= 65535:
        explicit_port = raw_port
    elif isinstance(raw_port, str) and raw_port.strip().isdigit():
        candidate = int(raw_port.strip())
        if 1 <= candidate <= 65535:
            explicit_port = candidate

    scheme = raw_scheme or parsed_scheme
    port = explicit_port or parsed_port or (SCHEME_DEFAULT_PORTS.get(scheme) if scheme else None)
    service = scheme or raw_type
    target = parsed_host or raw_ip or raw_host or None
    return target, port, service


def _extract_cves(template_id: str, classification: dict[str, Any]) -> list[str]:
    """Extract normalized CVE IDs from classification.cve-id or template-id."""
    raw_cves = classification.get("cve-id")
    candidates: list[str] = []
    if isinstance(raw_cves, str):
        candidates.append(raw_cves)
    elif isinstance(raw_cves, list):
        candidates.extend(str(item) for item in raw_cves if item is not None)

    normalized: list[str] = []
    for item in candidates:
        cleaned = item.strip().upper()
        if CVE_PATTERN.match(cleaned) and cleaned not in normalized:
            normalized.append(cleaned)

    if not normalized:
        tpl_upper = template_id.strip().upper()
        if CVE_PATTERN.match(tpl_upper):
            normalized.append(tpl_upper)

    return normalized


def _extract_cvss(classification: dict[str, Any]) -> float | None:
    raw = classification.get("cvss-score")
    if raw is None or raw == "":
        return None
    try:
        score = float(raw)
    except (TypeError, ValueError):
        return None
    return score if 0.0 <= score <= 10.0 else None


def _extract_references(info: dict[str, Any]) -> list[str]:
    raw_refs = info.get("reference")
    if isinstance(raw_refs, str):
        return [raw_refs]
    if isinstance(raw_refs, list):
        return [str(ref) for ref in raw_refs if isinstance(ref, str) and ref.strip()]
    return []


class NucleiJsonlParser(BaseParser):
    """Adapter for Nuclei JSONL outputs (`nuclei -jsonl`)."""

    name: ClassVar[str] = "nuclei"
    description: ClassVar[str] = "Nuclei JSON Lines (JSONL) vulnerability scan output"
    supported_extensions: ClassVar[tuple[str, ...]] = (".jsonl", ".ndjson", ".json")

    def can_parse(self, path: Path, preview: str) -> bool:
        for line in preview.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            try:
                obj = json.loads(stripped)
            except json.JSONDecodeError:
                return False
            return isinstance(obj, dict) and "template-id" in obj and isinstance(
                obj.get("info"), dict
            )
        return False

    def parse_text(self, content: str, *, source_name: str = "<memory>") -> list[RawFinding]:
        findings: list[RawFinding] = []
        non_empty_lines = 0

        for line_no, raw_line in enumerate(content.splitlines(), start=1):
            stripped = raw_line.strip()
            if not stripped:
                continue
            non_empty_lines += 1

            try:
                record = json.loads(stripped)
            except json.JSONDecodeError as exc:
                raise ParseError(
                    f"Invalid JSON on line {line_no} of '{source_name}': {exc}"
                ) from exc

            if not isinstance(record, dict):
                raise ParseError(
                    f"Expected JSON object on line {line_no} of '{source_name}'"
                )

            # Skip explicit non-matches when Nuclei includes matcher-status=false
            if record.get("matcher-status") is False:
                continue

            info = record.get("info")
            if not isinstance(info, dict):
                continue

            target, port, service = _extract_host_port_service(record)
            if not target:
                continue

            template_id = str(record.get("template-id") or "").strip()
            classification = info.get("classification")
            classification_dict = classification if isinstance(classification, dict) else {}

            cves = _extract_cves(template_id, classification_dict)
            cvss = _extract_cvss(classification_dict)
            references = _extract_references(info)

            name = str(info.get("name") or "").strip()
            desc = str(info.get("description") or "").strip()
            description = desc or name

            metadata: dict[str, Any] = {}
            if template_id:
                metadata["template_id"] = template_id
            if info.get("severity"):
                metadata["severity"] = str(info["severity"]).lower()
            if record.get("matched-at"):
                metadata["matched_at"] = str(record["matched-at"])
            if record.get("matcher-name"):
                metadata["matcher_name"] = str(record["matcher-name"])
            if record.get("ip"):
                metadata["ip"] = str(record["ip"])

            if cves:
                for cve in cves:
                    findings.append(
                        RawFinding(
                            target=target,
                            port=port,
                            service=service,
                            cve_id=cve,
                            cvss_score=cvss,
                            scanner_source=self.name,
                            description=description,
                            rule_id=template_id or cve,
                            references=references,
                            metadata=metadata,
                        )
                    )
            else:
                findings.append(
                    RawFinding(
                        target=target,
                        port=port,
                        service=service,
                        cve_id=None,
                        cvss_score=cvss,
                        scanner_source=self.name,
                        description=description,
                        rule_id=template_id or None,
                        references=references,
                        metadata=metadata,
                    )
                )

        return findings
