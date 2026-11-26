"""Rich terminal UI renderer for prioritized vulnerability tables and summaries."""

from __future__ import annotations

from typing import Any

from sift.core.pipeline import PipelineResult
from sift.models import PriorityTier

PRIORITY_STYLES: dict[PriorityTier, str] = {
    PriorityTier.P1: "bold white on red",
    PriorityTier.P2: "bold black on yellow",
    PriorityTier.P3: "bold cyan",
    PriorityTier.P4: "dim",
}


def render_terminal_report(
    result: PipelineResult,
    *,
    console: Any | None = None,
    err_console: Any | None = None,
) -> None:
    """Render an executive summary banner and color-coded Rich table to the terminal."""
    from rich import box
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text

    out = console or Console()
    err = err_console or Console(stderr=True)

    for warning in result.enrichment.warnings:
        err.print(f"[yellow]Warning:[/yellow] {warning}")

    counts = result.tier_counts
    summary = Text()
    summary.append("Files: ", style="bold")
    summary.append(f"{len(result.files_parsed)}  |  ")
    summary.append("Raw: ", style="bold")
    summary.append(f"{result.raw_count}  |  ")
    summary.append("Unique: ", style="bold")
    summary.append(f"{len(result.findings)} ")
    if result.duplicates_merged > 0:
        summary.append(f"({result.duplicates_merged} merged)  |  ", style="dim")
    else:
        summary.append(" |  ")

    summary.append(f"P1: {counts[PriorityTier.P1]}", style="bold red")
    summary.append("  ")
    summary.append(f"P2: {counts[PriorityTier.P2]}", style="bold yellow")
    summary.append("  ")
    summary.append(f"P3: {counts[PriorityTier.P3]}", style="bold cyan")
    summary.append("  ")
    summary.append(f"P4: {counts[PriorityTier.P4]}", style="dim")
    summary.append("  |  ")
    summary.append(
        f"KEV: {result.kev_count}",
        style="bold red" if result.kev_count else "green",
    )

    out.print(Panel(summary, title="[bold]sift — Risk Prioritization Summary[/bold]", expand=False))

    if not result.findings:
        out.print("[green]No vulnerabilities matched the selected filters.[/green]")
        return

    table = Table(
        box=box.ROUNDED,
        show_lines=False,
        header_style="bold magenta",
        expand=True,
    )
    table.add_column("Priority", justify="center", no_wrap=True)
    table.add_column("Target", overflow="fold")
    table.add_column("Port", justify="right", no_wrap=True)
    table.add_column("Service", overflow="fold")
    table.add_column("CVE / Rule", no_wrap=True)
    table.add_column("CVSS", justify="right", no_wrap=True)
    table.add_column("EPSS", justify="right", no_wrap=True)
    table.add_column("KEV", justify="center", no_wrap=True)
    table.add_column("Scanners", no_wrap=True)
    table.add_column("Rationale", overflow="fold")

    for finding in result.findings:
        priority_badge = Text(
            f" {finding.priority.value} ({finding.priority.label}) ",
            style=PRIORITY_STYLES[finding.priority],
        )
        identifier = finding.cve_id or finding.rule_id or "-"
        cvss_str = f"{finding.cvss_score:.1f}" if finding.cvss_score is not None else "-"
        epss_str = (
            f"{finding.threat_intel.epss_score:.1%}"
            if finding.threat_intel.epss_score is not None
            else "-"
        )
        kev_cell = Text("YES", style="bold red") if finding.in_kev else Text("-", style="dim")

        table.add_row(
            priority_badge,
            finding.target,
            str(finding.port) if finding.port is not None else "-",
            finding.service or "-",
            identifier,
            cvss_str,
            epss_str,
            kev_cell,
            ", ".join(finding.scanner_sources),
            finding.priority_reason,
        )

    out.print(table)
