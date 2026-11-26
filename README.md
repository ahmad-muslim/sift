# sift — Universal Scan Normalizer & Risk Prioritizer

`sift` is a fast, lightweight, open-source Python CLI that ingests vulnerability scan outputs from multiple open-source scanners, normalizes and deduplicates findings into a unified Pydantic v2 schema, enriches CVEs with real-world exploitation intelligence (**CISA KEV** and **FIRST EPSS** — 100% free, zero API keys required), and outputs prioritized remediation reports.

## Key Features

- **Modular Scanner Adapters (Adapter Pattern):** Built-in auto-detecting parsers for **Nmap XML** (`defusedxml`), **Nuclei JSONL**, and **Trivy JSON**, with a clean `BaseParser` interface for community contributions.
- **Cross-Scanner Deduplication:** Merges identical `(target, port, cve_id)` findings across multiple scan files while preserving all `scanner_sources` and keeping the highest CVSS score. Non-CVE findings are retained via `rule_id`.
- **Zero-Key Threat Intelligence & 24h Local SQLite Cache:** Fetches the public CISA KEV feed and FIRST EPSS API (batched 50 CVEs/request) into a local SQLite WAL cache with negative caching and graceful offline / stale-cache fallback.
- **Actionable Risk Prioritization:**

| Tier | Label | Criteria |
| --- | --- | --- |
| **P1** | Urgent | Listed in **CISA KEV** OR **EPSS ≥ 0.70** |
| **P2** | High | **EPSS ≥ 0.30** OR **CVSS ≥ 8.0** |
| **P3** | Medium | **CVSS 4.0–7.9** |
| **P4** | Low/Info | Everything else |

- **Flexible Outputs & CI Gate:** Color-coded `Rich` terminal table by default, RFC 4180 `--output-csv` (with spreadsheet formula-injection sanitization), GitHub/client-ready `--output-md`, self-contained offline interactive `--output-html` dashboard, and `--fail-on` exit code gating for CI/CD pipelines.

## Installation

Requires **Python 3.11+**.

```bash
pip install sift-sec
```

Or install from source for development:

```bash
git clone https://github.com/ahmad-muslim/sift.git
cd sift
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Quick Start

Ingest multiple scan outputs (formats are auto-detected):

```bash
sift scan nmap_vuln.xml nuclei_results.jsonl trivy_scan.json
```

Export prioritized reports to Markdown, CSV, and interactive HTML:

```bash
sift scan nmap_vuln.xml nuclei_results.jsonl trivy_scan.json \
  --output-md report.md \
  --output-csv findings.csv \
  --output-html dashboard.html
```

Run fully offline using cached threat intelligence, or fail a CI build on P1 findings:

```bash
sift scan trivy_scan.json --offline --min-priority P2 --fail-on P1
```

Inspect supported scanner adapters or manage the local SQLite cache:

```bash
sift parsers
sift cache stats
sift cache clear
```

## Development & Testing

```bash
ruff check src tests
mypy src
pytest -v
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for instructions on adding a new scanner parser adapter.

## License

Released under the [MIT License](LICENSE).
