"""Trivy JSON vulnerability and misconfiguration scan parser."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, ClassVar

from sift.models import CVE_PATTERN, RawFinding
from sift.parsers.base import BaseParser, ParseError


def _extract_trivy_cvss(cvss_obj: Any) -> float | None:
    """Select the most authoritative CVSS score from Trivy's vendor CVSS map.

    Preference order:
    1. `nvd.V3Score`
    2. Highest `V3Score` across any vendor source
    3. `nvd.V2Score`
    4. Highest `V2Score` across any vendor source
    """
    if not isinstance(cvss_obj, dict):
        return None

    def _valid_score(raw: Any) -> float | None:
        if raw is None:
            return None
        try:
            val = float(raw)
        except (TypeError, ValueError):
            return None
        return val if 0.0 <= val <= 10.0 else None

    nvd = cvss_obj.get("nvd")
    if isinstance(nvd, dict):
        nvd_v3 = _valid_score(nvd.get("V3Score"))
        if nvd_v3 is not None:
            return nvd_v3

    v3_scores = [
        score
        for vendor_data in cvss_obj.values()
        if isinstance(vendor_data, dict)
        if (score := _valid_score(vendor_data.get("V3Score"))) is not None
    ]
    if v3_scores:
        return max(v3_scores)

    if isinstance(nvd, dict):
        nvd_v2 = _valid_score(nvd.get("V2Score"))
        if nvd_v2 is not None:
            return nvd_v2

    v2_scores = [
        score
        for vendor_data in cvss_obj.values()
        if isinstance(vendor_data, dict)
        if (score := _valid_score(vendor_data.get("V2Score"))) is not None
    ]
    return max(v2_scores) if v2_scores else None


class TrivyJsonParser(BaseParser):
    """Adapter for Trivy JSON outputs (`trivy image/fs/repo -f json`)."""

    name: ClassVar[str] = "trivy"
    description: ClassVar[str] = "Trivy JSON vulnerability and misconfiguration scan output"
    supported_extensions: ClassVar[tuple[str, ...]] = (".json",)

    def can_parse(self, path: Path, preview: str) -> bool:
        stripped = preview.lstrip()
        if not stripped.startswith("{"):
            return False
        return '"SchemaVersion"' in preview or (
            '"ArtifactName"' in preview and '"Results"' in preview
        )

    def parse_text(self, content: str, *, source_name: str = "<memory>") -> list[RawFinding]:
        try:
            payload = json.loads(content)
        except json.JSONDecodeError as exc:
            raise ParseError(f"Invalid Trivy JSON in '{source_name}': {exc}") from exc

        if not isinstance(payload, dict) or (
            "Results" not in payload and "SchemaVersion" not in payload
        ):
            raise ParseError(f"Unexpected Trivy JSON structure in '{source_name}'")

        artifact_name = str(payload.get("ArtifactName") or "").strip()
        artifact_type = str(payload.get("ArtifactType") or "").strip()
        results = payload.get("Results")
        if not isinstance(results, list):
            return []

        findings: list[RawFinding] = []
        for result in results:
            if not isinstance(result, dict):
                continue

            target = str(result.get("Target") or artifact_name or "").strip()
            if not target:
                continue

            result_type = str(result.get("Type") or "").strip()
            result_class = str(result.get("Class") or "").strip()

            vulns = result.get("Vulnerabilities")
            if isinstance(vulns, list):
                for vuln in vulns:
                    if not isinstance(vuln, dict):
                        continue
                    findings.append(
                        self._parse_vulnerability(
                            vuln=vuln,
                            target=target,
                            artifact_name=artifact_name,
                            artifact_type=artifact_type,
                            result_type=result_type,
                            result_class=result_class,
                        )
                    )

            misconfigs = result.get("Misconfigurations")
            if isinstance(misconfigs, list):
                for misconfig in misconfigs:
                    if not isinstance(misconfig, dict):
                        continue
                    status = str(misconfig.get("Status") or "FAIL").upper()
                    if status != "FAIL":
                        continue
                    findings.append(
                        self._parse_misconfiguration(
                            misconfig=misconfig,
                            target=target,
                            artifact_name=artifact_name,
                            artifact_type=artifact_type,
                            result_type=result_type,
                        )
                    )

        return findings

    def _parse_vulnerability(
        self,
        *,
        vuln: dict[str, Any],
        target: str,
        artifact_name: str,
        artifact_type: str,
        result_type: str,
        result_class: str,
    ) -> RawFinding:
        vuln_id = str(vuln.get("VulnerabilityID") or "").strip()
        cve_id = vuln_id.upper() if CVE_PATTERN.match(vuln_id.upper()) else None

        pkg_name = str(vuln.get("PkgName") or "").strip()
        installed_version = str(vuln.get("InstalledVersion") or "").strip()
        fixed_version = str(vuln.get("FixedVersion") or "").strip()

        service: str | None = None
        if pkg_name and installed_version:
            service = f"{pkg_name}@{installed_version}"
        elif pkg_name:
            service = pkg_name

        title = str(vuln.get("Title") or "").strip()
        desc = str(vuln.get("Description") or "").strip()
        description = desc or title

        raw_refs = vuln.get("References")
        references = (
            [str(ref) for ref in raw_refs if isinstance(ref, str) and ref.strip()]
            if isinstance(raw_refs, list)
            else []
        )
        primary_url = str(vuln.get("PrimaryURL") or "").strip()
        if primary_url and primary_url not in references:
            references.insert(0, primary_url)

        metadata: dict[str, Any] = {}
        if pkg_name:
            metadata["pkg_name"] = pkg_name
        if installed_version:
            metadata["installed_version"] = installed_version
        if fixed_version:
            metadata["fixed_version"] = fixed_version
        if vuln.get("Severity"):
            metadata["severity"] = str(vuln["Severity"]).lower()
        if artifact_name:
            metadata["artifact_name"] = artifact_name
        if artifact_type:
            metadata["artifact_type"] = artifact_type
        if result_type:
            metadata["result_type"] = result_type
        if result_class:
            metadata["result_class"] = result_class

        return RawFinding(
            target=target,
            port=None,
            service=service,
            cve_id=cve_id,
            cvss_score=_extract_trivy_cvss(vuln.get("CVSS")),
            scanner_source=self.name,
            description=description,
            rule_id=vuln_id or None,
            references=references,
            metadata=metadata,
        )

    def _parse_misconfiguration(
        self,
        *,
        misconfig: dict[str, Any],
        target: str,
        artifact_name: str,
        artifact_type: str,
        result_type: str,
    ) -> RawFinding:
        rule_id = str(misconfig.get("ID") or misconfig.get("AVDID") or "").strip() or None
        title = str(misconfig.get("Title") or "").strip()
        message = str(misconfig.get("Message") or "").strip()
        desc = str(misconfig.get("Description") or "").strip()
        description = message or desc or title

        raw_refs = misconfig.get("References")
        references = (
            [str(ref) for ref in raw_refs if isinstance(ref, str) and ref.strip()]
            if isinstance(raw_refs, list)
            else []
        )
        primary_url = str(misconfig.get("PrimaryURL") or "").strip()
        if primary_url and primary_url not in references:
            references.insert(0, primary_url)

        metadata: dict[str, Any] = {"kind": "misconfiguration"}
        if misconfig.get("Severity"):
            metadata["severity"] = str(misconfig["Severity"]).lower()
        if misconfig.get("Resolution"):
            metadata["resolution"] = str(misconfig["Resolution"])
        if artifact_name:
            metadata["artifact_name"] = artifact_name
        if artifact_type:
            metadata["artifact_type"] = artifact_type

        return RawFinding(
            target=target,
            port=None,
            service=result_type or None,
            cve_id=None,
            cvss_score=None,
            scanner_source=self.name,
            description=description,
            rule_id=rule_id,
            references=references,
            metadata=metadata,
        )
