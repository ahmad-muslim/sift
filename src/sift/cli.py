"""Typer CLI entrypoint for sift (Universal Scan Normalizer & Risk Prioritizer)."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from sift import __version__
from sift.core import PipelineResult, run_pipeline
from sift.enrichment import DEFAULT_TIMEOUT_SECONDS, ThreatIntelCache
from sift.models import PriorityTier
from sift.parsers import ParseError, create_default_registry
from sift.reporters import export_csv, export_html, export_markdown, render_terminal_report

app = typer.Typer(
    name="sift",
    help="Universal vulnerability scan normalizer & risk prioritizer (CISA KEV + FIRST EPSS).",
    no_args_is_help=True,
    rich_markup_mode="rich",
)

cache_app = typer.Typer(
    help="Inspect or clear the local SQLite threat-intelligence cache.",
    no_args_is_help=True,
)
app.add_typer(cache_app, name="cache")


def _version_callback(show_version: bool) -> None:
    if show_version:
        typer.echo(f"sift {__version__}")
        raise typer.Exit(code=0)


@app.callback()
def main(
    version: Annotated[
        bool,
        typer.Option(
            "--version",
            "-V",
            callback=_version_callback,
            is_eager=True,
            help="Show the sift version and exit.",
        ),
    ] = False,
) -> None:
    """Universal vulnerability scan normalizer and risk prioritizer."""


@app.command()
def scan(
    scan_files: Annotated[
        list[Path],
        typer.Argument(
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
            help="One or more scan files to ingest (Nmap XML, Nuclei JSONL, Trivy JSON).",
        ),
    ],
    parser: Annotated[
        str | None,
        typer.Option(
            "--parser",
            "-p",
            help="Force a specific parser adapter (nmap, nuclei, trivy) instead of auto-detecting.",
        ),
    ] = None,
    output_csv: Annotated[
        Path | None,
        typer.Option(
            "--output-csv",
            help="Export prioritized findings to an RFC 4180 CSV file.",
        ),
    ] = None,
    output_md: Annotated[
        Path | None,
        typer.Option(
            "--output-md",
            help="Export a GitHub/client-ready Markdown report.",
        ),
    ] = None,
    output_html: Annotated[
        Path | None,
        typer.Option(
            "--output-html",
            dir_okay=False,
            help="Export a self-contained interactive HTML dashboard report.",
        ),
    ] = None,
    offline: Annotated[
        bool,
        typer.Option(
            "--offline",
            help="Disable outbound KEV/EPSS API requests and use local SQLite cache only.",
        ),
    ] = False,
    refresh_cache: Annotated[
        bool,
        typer.Option(
            "--refresh-cache",
            help="Bypass the 24-hour TTL and refresh CISA KEV / FIRST EPSS data.",
        ),
    ] = False,
    cache_dir: Annotated[
        Path | None,
        typer.Option(
            "--cache-dir",
            help="Override the local SQLite cache directory (or set SIFT_CACHE_DIR).",
        ),
    ] = None,
    timeout: Annotated[
        float,
        typer.Option(
            "--timeout",
            min=1.0,
            max=120.0,
            help="HTTP timeout in seconds for public threat-intelligence APIs.",
        ),
    ] = DEFAULT_TIMEOUT_SECONDS,
    cve_only: Annotated[
        bool,
        typer.Option(
            "--cve-only",
            help="Exclude non-CVE findings (e.g., misconfigurations or template-only alerts).",
        ),
    ] = False,
    min_priority: Annotated[
        PriorityTier | None,
        typer.Option(
            "--min-priority",
            case_sensitive=False,
            help="Only include findings at or above this priority tier (P1, P2, P3, P4).",
        ),
    ] = None,
    fail_on: Annotated[
        PriorityTier | None,
        typer.Option(
            "--fail-on",
            case_sensitive=False,
            help="Exit with code 2 if any finding meets or exceeds this priority tier (CI gate).",
        ),
    ] = None,
    no_table: Annotated[
        bool,
        typer.Option(
            "--no-table",
            help=(
                "Suppress terminal table rendering "
                "(useful when exporting only to CSV/Markdown/HTML)."
            ),
        ),
    ] = False,
) -> None:
    """Ingest scan files, deduplicate, enrich with CISA KEV & FIRST EPSS, and prioritize."""
    console = Console()
    err_console = Console(stderr=True)

    result: PipelineResult
    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=err_console,
            transient=True,
        ) as progress:
            progress.add_task(
                description=(
                    f"Parsing {len(scan_files)} scan file(s) and enriching threat intelligence..."
                ),
                total=None,
            )
            result = run_pipeline(
                scan_files,
                parser_name=parser,
                cache_dir=cache_dir,
                timeout=timeout,
                offline=offline,
                refresh_cache=refresh_cache,
                cve_only=cve_only,
                min_priority=min_priority,
            )
    except ParseError as exc:
        err_console.print(f"[bold red]Parse Error:[/bold red] {exc}")
        raise typer.Exit(code=1) from exc

    if not no_table:
        render_terminal_report(result, console=console, err_console=err_console)
    else:
        for warning in result.enrichment.warnings:
            err_console.print(f"[yellow]Warning:[/yellow] {warning}")

    if output_csv is not None:
        written_csv = export_csv(result.findings, output_csv)
        err_console.print(f"[green]CSV report written:[/green] {written_csv}")

    if output_md is not None:
        written_md = export_markdown(
            result.findings,
            output_md,
            raw_count=result.raw_count,
            duplicates_merged=result.duplicates_merged,
            warnings=result.enrichment.warnings,
        )
        err_console.print(f"[green]Markdown report written:[/green] {written_md}")

    if output_html is not None:
        try:
            written_html = export_html(
                result.findings,
                output_html,
                raw_count=result.raw_count,
                duplicates_merged=result.duplicates_merged,
                warnings=result.enrichment.warnings,
            )
        except (ValueError, OSError) as exc:
            err_console.print(f"[bold red]HTML Export Error:[/bold red] {exc}")
            raise typer.Exit(code=1) from exc
        err_console.print(f"[green]HTML report written:[/green] {written_html}")

    if fail_on is not None and any(
        finding.priority.rank <= fail_on.rank for finding in result.findings
    ):
        err_console.print(
            f"[bold red]Threshold triggered:[/bold red] findings exist at or above {fail_on.value}."
        )
        raise typer.Exit(code=2)


@app.command()
def parsers() -> None:
    """List all registered scanner parser adapters."""
    console = Console()
    registry = create_default_registry()

    table = Table(title="Registered Scanner Parsers", header_style="bold magenta")
    table.add_column("Name", style="bold cyan", no_wrap=True)
    table.add_column("Extensions", no_wrap=True)
    table.add_column("Description")

    for adapter in registry.list_parsers():
        exts = ", ".join(adapter.supported_extensions) or "auto"
        table.add_row(adapter.name, exts, adapter.description)

    console.print(table)


@cache_app.command("stats")
def cache_stats(
    cache_dir: Annotated[
        Path | None,
        typer.Option("--cache-dir", help="Override the local SQLite cache directory."),
    ] = None,
) -> None:
    """Display local SQLite threat-intelligence cache statistics."""
    console = Console()
    with ThreatIntelCache(cache_dir=cache_dir) as cache:
        info = cache.stats()

    table = Table(title="sift Local Cache Stats", header_style="bold magenta")
    table.add_column("Metric", style="bold")
    table.add_column("Value")
    table.add_row("Database Path", str(info.db_path))
    table.add_row("CISA KEV Entries", str(info.kev_count))
    table.add_row("KEV Catalog Version", info.kev_catalog_version or "-")
    table.add_row(
        "KEV Last Refreshed",
        info.kev_fetched_at.strftime("%Y-%m-%d %H:%M:%S UTC") if info.kev_fetched_at else "Never",
    )
    table.add_row("Cached EPSS Scores", str(info.epss_count))
    table.add_row("Negative-Cached EPSS CVEs", str(info.epss_negative_count))
    console.print(table)


@cache_app.command("clear")
def cache_clear(
    cache_dir: Annotated[
        Path | None,
        typer.Option("--cache-dir", help="Override the local SQLite cache directory."),
    ] = None,
) -> None:
    """Clear all cached CISA KEV and FIRST EPSS records."""
    console = Console()
    with ThreatIntelCache(cache_dir=cache_dir) as cache:
        cache.clear()
        db_path = cache.db_path
    console.print(f"[green]Cleared local threat-intelligence cache:[/green] {db_path}")
