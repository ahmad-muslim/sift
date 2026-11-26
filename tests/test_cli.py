"""CLI integration tests using Typer CliRunner (requires typer & rich installed)."""

from __future__ import annotations

from pathlib import Path

import pytest

typer = pytest.importorskip("typer")
pytest.importorskip("rich")

from typer.testing import CliRunner  # noqa: E402

from sift import __version__  # noqa: E402
from sift.cli import app  # noqa: E402

FIXTURES_DIR = Path(__file__).parent / "fixtures"
runner = CliRunner()


def test_cli_version() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.stdout


def test_cli_parsers_command() -> None:
    result = runner.invoke(app, ["parsers"])
    assert result.exit_code == 0
    for name in ("nmap", "nuclei", "trivy"):
        assert name in result.stdout


def test_cli_scan_offline_exports_and_fail_on(tmp_path: Path) -> None:
    csv_out = tmp_path / "out.csv"
    md_out = tmp_path / "out.md"
    html_out = tmp_path / "out.html"

    result = runner.invoke(
        app,
        [
            "scan",
            str(FIXTURES_DIR / "nmap_vuln.xml"),
            str(FIXTURES_DIR / "nuclei_results.jsonl"),
            str(FIXTURES_DIR / "trivy_scan.json"),
            "--offline",
            "--cache-dir",
            str(tmp_path / "cache"),
            "--output-csv",
            str(csv_out),
            "--output-md",
            str(md_out),
            "--output-html",
            str(html_out),
            "--fail-on",
            "P2",
        ],
    )
    # High-CVSS findings trigger P2 threshold -> exit code 2
    assert result.exit_code == 2
    assert csv_out.exists()
    assert md_out.exists()
    assert html_out.exists()
    assert "CVE-2021-44228" in md_out.read_text(encoding="utf-8")
    html_content = html_out.read_text(encoding="utf-8")
    assert "<!DOCTYPE html>" in html_content
    assert "CVE-2021-44228" in html_content
    assert 'id="sift-findings-data"' in html_content


def test_cli_scan_rejects_directory_as_output_html(tmp_path: Path) -> None:
    out_dir = tmp_path / "dir_target"
    out_dir.mkdir()
    result = runner.invoke(
        app,
        [
            "scan",
            str(FIXTURES_DIR / "trivy_scan.json"),
            "--offline",
            "--no-table",
            "--cache-dir",
            str(tmp_path / "cache"),
            "--output-html",
            str(out_dir),
        ],
    )
    assert result.exit_code != 0


def test_cli_cache_stats_and_clear(tmp_path: Path) -> None:
    cache_dir = str(tmp_path / "cache")
    stats_res = runner.invoke(app, ["cache", "stats", "--cache-dir", cache_dir])
    assert stats_res.exit_code == 0
    assert "CISA KEV Entries" in stats_res.stdout

    clear_res = runner.invoke(app, ["cache", "clear", "--cache-dir", cache_dir])
    assert clear_res.exit_code == 0
    assert "Cleared" in clear_res.stdout
