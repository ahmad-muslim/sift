"""Nmap XML vulnerability scan parser using defusedxml."""

from __future__ import annotations

import re
import xml.etree.ElementTree as StdlibET
from pathlib import Path
from typing import Any, ClassVar

from sift.models import RawFinding
from sift.parsers.base import BaseParser, ParseError

CVE_FINDALL_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
CVSS_OUTPUT_RE = re.compile(
    r"(?:CVSS(?:v[23](?:\.\d)?)?|Risk\s+score)\s*[:=]\s*(\d{1,2}(?:\.\d+)?)",
    re.IGNORECASE,
)
UNSAFE_XML_DECL_RE = re.compile(r"<!\s*(?:DOCTYPE|ENTITY)\b", re.IGNORECASE)
NOT_VULNERABLE_RE = re.compile(r"\bNOT\s+VULNERABLE\b", re.IGNORECASE)
VULNERABLE_RE = re.compile(r"\b(?:LIKELY\s+)?VULNERABLE\b", re.IGNORECASE)


def _safe_parse_xml(content: str, *, source_name: str) -> StdlibET.Element:
    """Parse XML safely using defusedxml (blocking XXE and DTD entity expansion)."""
    try:
        from defusedxml import ElementTree as DefusedET
        from defusedxml.common import DefusedXmlException
    except ImportError:
        # Guarded fallback for minimal environments without defusedxml installed:
        # explicitly forbid DTD/ENTITY declarations before calling ElementTree.
        if UNSAFE_XML_DECL_RE.search(content):
            raise ParseError(
                f"Rejected unsafe XML DTD/ENTITY declaration in '{source_name}'."
            ) from None
        try:
            return StdlibET.fromstring(content)  # noqa: S314
        except StdlibET.ParseError as exc:
            raise ParseError(f"Invalid Nmap XML in '{source_name}': {exc}") from exc

    try:
        element: StdlibET.Element = DefusedET.fromstring(content)
        return element
    except (DefusedXmlException, StdlibET.ParseError) as exc:
        raise ParseError(f"Invalid or unsafe Nmap XML in '{source_name}': {exc}") from exc


def _extract_host_target(host_el: StdlibET.Element) -> tuple[str | None, dict[str, Any]]:
    """Select canonical host target (preferring user-supplied hostname, else IP)."""
    user_hostname: str | None = None
    fallback_hostname: str | None = None
    ip_addr: str | None = None

    for hn in host_el.findall("./hostnames/hostname"):
        name = (hn.get("name") or "").strip()
        if not name:
            continue
        if hn.get("type") == "user" and user_hostname is None:
            user_hostname = name
        elif fallback_hostname is None:
            fallback_hostname = name

    for addr in host_el.findall("./address"):
        addr_type = (addr.get("addrtype") or "").lower()
        value = (addr.get("addr") or "").strip()
        if value and addr_type in {"ipv4", "ipv6"}:
            ip_addr = value
            break

    target = user_hostname or ip_addr or fallback_hostname
    meta: dict[str, Any] = {}
    if ip_addr:
        meta["ip"] = ip_addr
    if user_hostname or fallback_hostname:
        meta["hostname"] = user_hostname or fallback_hostname
    return target, meta


def _parse_cvss(raw: str | None) -> float | None:
    if not raw:
        return None
    try:
        score = float(raw.strip())
    except ValueError:
        return None
    if 0.0 <= score <= 10.0:
        return score
    return None


def _extract_cvss_from_text(text: str) -> float | None:
    match = CVSS_OUTPUT_RE.search(text)
    if not match:
        return None
    return _parse_cvss(match.group(1))


class NmapXmlParser(BaseParser):
    """Adapter for Nmap XML outputs (`nmap -oX`) containing NSE vulnerability scripts."""

    name: ClassVar[str] = "nmap"
    description: ClassVar[str] = "Nmap XML scan output with NSE vulnerability scripts"
    supported_extensions: ClassVar[tuple[str, ...]] = (".xml",)

    def can_parse(self, path: Path, preview: str) -> bool:
        lower = preview.lstrip().lower()
        return "<nmaprun" in lower

    def parse_text(self, content: str, *, source_name: str = "<memory>") -> list[RawFinding]:
        root = _safe_parse_xml(content, source_name=source_name)
        if root.tag != "nmaprun":
            raise ParseError(
                f"Expected <nmaprun> root element in '{source_name}', got <{root.tag}>"
            )

        findings: list[RawFinding] = []
        for host_el in root.findall("./host"):
            status_el = host_el.find("./status")
            if status_el is not None and status_el.get("state") == "down":
                continue

            target, host_meta = _extract_host_target(host_el)
            if not target:
                continue

            # Port-level NSE scripts
            for port_el in host_el.findall("./ports/port"):
                state_el = port_el.find("./state")
                if state_el is not None and state_el.get("state") not in {"open", "open|filtered"}:
                    continue

                raw_port = port_el.get("portid")
                port = int(raw_port) if raw_port and raw_port.isdigit() else None
                protocol = port_el.get("protocol") or "tcp"

                service_el = port_el.find("./service")
                service_name = service_el.get("name") if service_el is not None else None
                port_meta = dict(host_meta)
                port_meta["protocol"] = protocol
                if service_el is not None:
                    for attr in ("product", "version", "extrainfo"):
                        val = service_el.get(attr)
                        if val:
                            port_meta[attr] = val

                for script_el in port_el.findall("./script"):
                    findings.extend(
                        self._parse_script(
                            script_el=script_el,
                            target=target,
                            port=port,
                            service=service_name,
                            base_meta=port_meta,
                        )
                    )

            # Host-level NSE scripts (<hostscript>)
            for script_el in host_el.findall("./hostscript/script"):
                findings.extend(
                    self._parse_script(
                        script_el=script_el,
                        target=target,
                        port=None,
                        service=None,
                        base_meta=dict(host_meta),
                    )
                )

        return findings

    def _parse_script(
        self,
        *,
        script_el: StdlibET.Element,
        target: str,
        port: int | None,
        service: str | None,
        base_meta: dict[str, Any],
    ) -> list[RawFinding]:
        script_id = (script_el.get("id") or "").strip()
        output = (script_el.get("output") or "").strip()

        if script_id.lower() == "vulners":
            return self._parse_vulners_script(
                script_el=script_el,
                target=target,
                port=port,
                service=service,
                base_meta=base_meta,
            )

        # Structured NSE `vulns` library tables (e.g., ssl-heartbleed, http-vuln-*, smb-vuln-*)
        vuln_tables = self._parse_nse_vuln_tables(
            script_el=script_el,
            script_id=script_id,
            output=output,
            target=target,
            port=port,
            service=service,
            base_meta=base_meta,
        )
        if vuln_tables is not None:
            return vuln_tables

        # Fallback: generic script text output mentioning CVEs or VULNERABLE state
        if NOT_VULNERABLE_RE.search(output):
            return []

        cves = sorted({m.upper() for m in CVE_FINDALL_RE.findall(output)})
        cvss = _extract_cvss_from_text(output)
        meta = {**base_meta, "script_id": script_id}

        if cves:
            return [
                RawFinding(
                    target=target,
                    port=port,
                    service=service,
                    cve_id=cve,
                    cvss_score=cvss,
                    scanner_source=self.name,
                    description=output,
                    rule_id=script_id or None,
                    metadata=meta,
                )
                for cve in cves
            ]

        if VULNERABLE_RE.search(output):
            return [
                RawFinding(
                    target=target,
                    port=port,
                    service=service,
                    cve_id=None,
                    cvss_score=cvss,
                    scanner_source=self.name,
                    description=output,
                    rule_id=script_id or None,
                    metadata=meta,
                )
            ]

        return []

    def _parse_vulners_script(
        self,
        *,
        script_el: StdlibET.Element,
        target: str,
        port: int | None,
        service: str | None,
        base_meta: dict[str, Any],
    ) -> list[RawFinding]:
        results: list[RawFinding] = []
        for cpe_table in script_el.findall("./table"):
            cpe = cpe_table.get("key") or ""
            for entry_table in cpe_table.findall("./table"):
                elems = {
                    (el.get("key") or "").lower(): (el.text or "").strip()
                    for el in entry_table.findall("./elem")
                    if el.get("key")
                }
                entry_id = elems.get("id", "").upper()
                if not entry_id:
                    continue

                is_cve = bool(CVE_FINDALL_RE.fullmatch(entry_id))
                cve_id = entry_id if is_cve else None
                cvss = _parse_cvss(elems.get("cvss"))
                is_exploit = elems.get("is_exploit", "").lower() == "true"

                meta = {
                    **base_meta,
                    "script_id": "vulners",
                    "is_exploit": is_exploit,
                }
                if cpe:
                    meta["cpe"] = cpe
                if elems.get("type"):
                    meta["vulners_type"] = elems["type"]

                desc_parts = [f"Detected {entry_id} via Nmap vulners script"]
                if cpe:
                    desc_parts.append(f"({cpe})")
                if is_exploit:
                    desc_parts.append("[exploit available]")

                results.append(
                    RawFinding(
                        target=target,
                        port=port,
                        service=service,
                        cve_id=cve_id,
                        cvss_score=cvss,
                        scanner_source=self.name,
                        description=" ".join(desc_parts),
                        rule_id=entry_id,
                        references=(
                            [f"https://vulners.com/cve/{cve_id}"] if cve_id else []
                        ),
                        metadata=meta,
                    )
                )
        return results

    def _parse_nse_vuln_tables(
        self,
        *,
        script_el: StdlibET.Element,
        script_id: str,
        output: str,
        target: str,
        port: int | None,
        service: str | None,
        base_meta: dict[str, Any],
    ) -> list[RawFinding] | None:
        """Parse standard NSE `vulns` library tables. Returns None if not a vulns table."""
        tables = script_el.findall("./table")
        if not tables:
            return None

        has_state_table = any(t.find("./elem[@key='state']") is not None for t in tables)
        if not has_state_table:
            return None

        findings: list[RawFinding] = []
        for table in tables:
            state_el = table.find("./elem[@key='state']")
            state_text = (state_el.text or "").strip() if state_el is not None else ""
            if not state_text or NOT_VULNERABLE_RE.search(state_text):
                continue
            if not VULNERABLE_RE.search(state_text):
                continue

            title_el = table.find("./elem[@key='title']")
            title = (title_el.text or "").strip() if title_el is not None else ""

            desc_elems = [
                (el.text or "").strip()
                for el in table.findall("./table[@key='description']/elem")
                if el.text and el.text.strip()
            ]
            description = " ".join(desc_elems) or title or output

            refs = [
                (el.text or "").strip()
                for el in table.findall("./table[@key='refs']/elem")
                if el.text and el.text.strip()
            ]

            raw_id_sources = [table.get("key") or ""]
            raw_id_sources.extend(
                (el.text or "").strip() for el in table.findall("./table[@key='ids']/elem")
            )
            cves = sorted(
                {m.upper() for src in raw_id_sources for m in CVE_FINDALL_RE.findall(src)}
            )

            cvss_el = table.find("./elem[@key='cvss']")
            cvss = _parse_cvss(cvss_el.text if cvss_el is not None else None)
            if cvss is None:
                cvss = _extract_cvss_from_text(output)

            meta = {
                **base_meta,
                "script_id": script_id,
                "state": state_text,
            }
            if title:
                meta["title"] = title

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
                            rule_id=script_id or cve,
                            references=refs,
                            metadata=meta,
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
                        rule_id=script_id or table.get("key"),
                        references=refs,
                        metadata=meta,
                    )
                )

        return findings
