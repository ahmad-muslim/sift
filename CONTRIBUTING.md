# Contributing to `sift`

Thank you for considering contributing to `sift`! We welcome bug reports, documentation improvements, and especially new scanner parser adapters.

## Development Environment

1. Fork and clone the repository.
2. Create a Python 3.11+ virtual environment and install development dependencies:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

3. Run the quality suite before opening a pull request:

```bash
ruff check src tests
mypy src
pytest -v
```

## Adding a New Scanner Parser

`sift` uses an Adapter Pattern so each scanner lives in its own isolated module under `src/sift/parsers/`:

1. Subclass `BaseParser` and define its unique `name` and format detection logic (`can_parse`).
2. Emit validated `sift.models.RawFinding` instances (one `scanner_source` string; enrichment and deduplication are handled automatically downstream).
3. Register the parser in `ParserRegistry`.
4. Add sanitized mock scan fixtures in `tests/fixtures/` and thorough unit tests covering edge cases (missing CVSS, non-CVE findings, malformed lines).

## Security Guidelines

- Never use unsafe XML parsers (`xml.etree.ElementTree`, `minidom`, etc.); always use `defusedxml`.
- Never hardcode secrets or require paid/authenticated API keys for core functionality.
- Keep scan fixtures sanitized (use RFC 5737 documentation IPs like `192.0.2.x` / `198.51.100.x` and `.example` domains).
