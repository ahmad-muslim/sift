"""Risk-based vulnerability prioritization engine (P1-P4)."""

from __future__ import annotations

from collections.abc import Iterable

from sift.models import NormalizedFinding, PriorityTier

P1_EPSS_THRESHOLD = 0.70
P2_EPSS_THRESHOLD = 0.30
P2_CVSS_THRESHOLD = 8.0
P3_CVSS_THRESHOLD = 4.0


def evaluate_priority(finding: NormalizedFinding) -> tuple[PriorityTier, str]:
    """Evaluate a finding's risk tier and return `(PriorityTier, reason)`.

    Tier criteria:
    - P1 (Urgent): Listed in CISA KEV OR EPSS >= 0.70
    - P2 (High): EPSS >= 0.30 OR CVSS >= 8.0
    - P3 (Medium): CVSS 4.0-7.9
    - P4 (Low/Info): Everything else
    """
    in_kev = finding.threat_intel.in_kev
    epss = finding.threat_intel.epss_score
    cvss = finding.cvss_score

    # P1 (Urgent)
    p1_reasons: list[str] = []
    if in_kev:
        p1_reasons.append("CISA KEV")
    if epss is not None and epss >= P1_EPSS_THRESHOLD:
        p1_reasons.append(f"EPSS {epss:.1%} (>= 70%)")
    if p1_reasons:
        return PriorityTier.P1, " + ".join(p1_reasons)

    # P2 (High)
    p2_reasons: list[str] = []
    if epss is not None and epss >= P2_EPSS_THRESHOLD:
        p2_reasons.append(f"EPSS {epss:.1%} (>= 30%)")
    if cvss is not None and cvss >= P2_CVSS_THRESHOLD:
        p2_reasons.append(f"CVSS {cvss:.1f} (>= 8.0)")
    if p2_reasons:
        return PriorityTier.P2, " + ".join(p2_reasons)

    # P3 (Medium)
    if cvss is not None and cvss >= P3_CVSS_THRESHOLD:
        return PriorityTier.P3, f"CVSS {cvss:.1f} (4.0-7.9)"

    # P4 (Low/Info)
    if cvss is not None:
        return PriorityTier.P4, f"CVSS {cvss:.1f} (< 4.0)"
    return PriorityTier.P4, "No KEV/EPSS/CVSS high-risk signals"


def assign_priority(finding: NormalizedFinding) -> NormalizedFinding:
    """Return a copy of `finding` with `priority` and `priority_reason` populated."""
    tier, reason = evaluate_priority(finding)
    return finding.model_copy(update={"priority": tier, "priority_reason": reason})


def prioritize_findings(findings: Iterable[NormalizedFinding]) -> list[NormalizedFinding]:
    """Assign risk priority tiers and sort findings in descending risk order."""
    scored = [assign_priority(finding) for finding in findings]
    scored.sort(key=lambda item: item.sort_key)
    return scored
