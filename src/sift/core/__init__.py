"""Core deduplication, prioritization, and pipeline orchestration."""

from sift.core.deduplicator import deduplicate_findings
from sift.core.pipeline import ParsedFileSummary, PipelineResult, run_pipeline
from sift.core.prioritizer import (
    P1_EPSS_THRESHOLD,
    P2_CVSS_THRESHOLD,
    P2_EPSS_THRESHOLD,
    P3_CVSS_THRESHOLD,
    assign_priority,
    evaluate_priority,
    prioritize_findings,
)

__all__ = [
    "P1_EPSS_THRESHOLD",
    "P2_CVSS_THRESHOLD",
    "P2_EPSS_THRESHOLD",
    "P3_CVSS_THRESHOLD",
    "ParsedFileSummary",
    "PipelineResult",
    "assign_priority",
    "deduplicate_findings",
    "evaluate_priority",
    "prioritize_findings",
    "run_pipeline",
]
