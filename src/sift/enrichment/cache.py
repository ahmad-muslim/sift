"""Local SQLite cache with 24-hour TTL for CISA KEV and FIRST EPSS threat intelligence."""

from __future__ import annotations

import os
import sqlite3
import time
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, date, datetime
from pathlib import Path

from sift.models import EpssRecord, KevRecord, normalize_required_cve_id

DEFAULT_TTL_SECONDS = 86_400  # 24 hours
CACHE_DB_FILENAME = "threat_intel.sqlite3"
SCHEMA_VERSION = "1"
ENV_CACHE_DIR = "SIFT_CACHE_DIR"


@dataclass(frozen=True)
class CacheStats:
    """Summary statistics for the local threat intelligence SQLite cache."""

    db_path: Path
    kev_count: int
    kev_fetched_at: datetime | None
    kev_catalog_version: str | None
    epss_count: int
    epss_negative_count: int


def resolve_cache_dir(cache_dir: Path | str | None = None) -> Path:
    """Resolve the local cache directory using CLI arg, SIFT_CACHE_DIR, or platformdirs."""
    if cache_dir is not None:
        return Path(cache_dir).expanduser()

    env_override = os.environ.get(ENV_CACHE_DIR)
    if env_override:
        return Path(env_override).expanduser()

    try:
        from platformdirs import user_cache_dir

        return Path(user_cache_dir(appname="sift"))
    except ImportError:
        return Path.home() / ".cache" / "sift"


def _parse_optional_date(raw: str | None) -> date | None:
    if not raw:
        return None
    try:
        return date.fromisoformat(raw)
    except ValueError:
        return None


class ThreatIntelCache:
    """SQLite-backed local cache for CISA KEV catalog and FIRST EPSS scores.

    Features:
    - WAL journal mode and busy timeout for safe concurrent CLI runs.
    - 24-hour configurable TTL per data source.
    - Negative caching for CVEs absent from FIRST EPSS to avoid repeated API calls.
    - Stale-read support for graceful offline fallback when public APIs are unreachable.
    """

    def __init__(self, cache_dir: Path | str | None = None) -> None:
        resolved_dir = resolve_cache_dir(cache_dir)
        resolved_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = resolved_dir / CACHE_DB_FILENAME
        self._conn = sqlite3.connect(self.db_path)
        self._conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self) -> None:
        with self._conn:
            self._conn.execute("PRAGMA journal_mode=WAL;")
            self._conn.execute("PRAGMA busy_timeout=5000;")
            self._conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS cache_meta (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS kev_entries (
                    cve_id TEXT PRIMARY KEY,
                    vendor_project TEXT NOT NULL DEFAULT '',
                    product TEXT NOT NULL DEFAULT '',
                    vulnerability_name TEXT NOT NULL DEFAULT '',
                    date_added TEXT,
                    due_date TEXT,
                    known_ransomware INTEGER NOT NULL DEFAULT 0
                );

                CREATE TABLE IF NOT EXISTS epss_entries (
                    cve_id TEXT PRIMARY KEY,
                    epss REAL,
                    percentile REAL,
                    score_date TEXT,
                    fetched_at REAL NOT NULL
                );
                """
            )
            self._conn.execute(
                "INSERT OR REPLACE INTO cache_meta (key, value) VALUES (?, ?)",
                ("schema_version", SCHEMA_VERSION),
            )

    def close(self) -> None:
        """Close the underlying SQLite connection."""
        self._conn.close()

    def __enter__(self) -> ThreatIntelCache:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def _get_meta(self, key: str) -> str | None:
        row = self._conn.execute(
            "SELECT value FROM cache_meta WHERE key = ?",
            (key,),
        ).fetchone()
        return str(row["value"]) if row is not None else None

    def _set_meta(self, key: str, value: str) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO cache_meta (key, value) VALUES (?, ?)",
            (key, value),
        )

    def get_kev_fetched_at(self) -> float | None:
        """Return Unix timestamp of last KEV catalog refresh, or None if never cached."""
        raw = self._get_meta("kev_fetched_at")
        if raw is None:
            return None
        try:
            return float(raw)
        except ValueError:
            return None

    def has_kev_data(self) -> bool:
        """Return True if a KEV catalog snapshot has been cached (even if stale)."""
        return self.get_kev_fetched_at() is not None

    def is_kev_fresh(
        self,
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
        *,
        now: float | None = None,
    ) -> bool:
        """Return True if cached KEV catalog is within the TTL window."""
        fetched_at = self.get_kev_fetched_at()
        if fetched_at is None:
            return False
        current = time.time() if now is None else now
        return (current - fetched_at) < ttl_seconds

    def replace_kev_catalog(
        self,
        records: Iterable[KevRecord],
        *,
        catalog_version: str = "",
        fetched_at: float | None = None,
    ) -> int:
        """Atomically replace the cached CISA KEV catalog."""
        timestamp = time.time() if fetched_at is None else fetched_at
        rows = [
            (
                record.cve_id,
                record.vendor_project,
                record.product,
                record.vulnerability_name,
                record.date_added.isoformat() if record.date_added else None,
                record.due_date.isoformat() if record.due_date else None,
                1 if record.known_ransomware_campaign_use else 0,
            )
            for record in records
        ]

        with self._conn:
            self._conn.execute("DELETE FROM kev_entries")
            self._conn.executemany(
                """
                INSERT OR REPLACE INTO kev_entries (
                    cve_id,
                    vendor_project,
                    product,
                    vulnerability_name,
                    date_added,
                    due_date,
                    known_ransomware
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                rows,
            )
            self._set_meta("kev_fetched_at", f"{timestamp:.6f}")
            self._set_meta("kev_catalog_version", catalog_version)

        return len(rows)

    def get_kev_records(self, cve_ids: Iterable[str]) -> dict[str, KevRecord]:
        """Look up cached KEV records for a collection of CVE IDs."""
        normalized = sorted({normalize_required_cve_id(cve) for cve in cve_ids})
        if not normalized:
            return {}

        results: dict[str, KevRecord] = {}
        # Chunk queries to stay comfortably below SQLite's variable limit (999)
        chunk_size = 500
        for idx in range(0, len(normalized), chunk_size):
            chunk = normalized[idx : idx + chunk_size]
            placeholders = ",".join("?" for _ in chunk)
            rows = self._conn.execute(
                f"""
                SELECT
                    cve_id,
                    vendor_project,
                    product,
                    vulnerability_name,
                    date_added,
                    due_date,
                    known_ransomware
                FROM kev_entries
                WHERE cve_id IN ({placeholders})
                """,  # noqa: S608
                chunk,
            ).fetchall()
            for row in rows:
                results[row["cve_id"]] = KevRecord(
                    cve_id=row["cve_id"],
                    vendor_project=row["vendor_project"],
                    product=row["product"],
                    vulnerability_name=row["vulnerability_name"],
                    date_added=_parse_optional_date(row["date_added"]),
                    due_date=_parse_optional_date(row["due_date"]),
                    known_ransomware_campaign_use=bool(row["known_ransomware"]),
                )

        return results

    def upsert_epss_records(
        self,
        records: Mapping[str, EpssRecord | None],
        *,
        fetched_at: float | None = None,
    ) -> int:
        """Insert or update EPSS records (including None entries for negative caching)."""
        if not records:
            return 0

        timestamp = time.time() if fetched_at is None else fetched_at
        rows: list[tuple[str, float | None, float | None, str | None, float]] = []
        for raw_cve, record in records.items():
            cve_id = normalize_required_cve_id(raw_cve)
            if record is None:
                rows.append((cve_id, None, None, None, timestamp))
            else:
                rows.append(
                    (
                        record.cve_id,
                        record.epss,
                        record.percentile,
                        record.score_date.isoformat() if record.score_date else None,
                        timestamp,
                    )
                )

        with self._conn:
            self._conn.executemany(
                """
                INSERT OR REPLACE INTO epss_entries (
                    cve_id,
                    epss,
                    percentile,
                    score_date,
                    fetched_at
                ) VALUES (?, ?, ?, ?, ?)
                """,
                rows,
            )

        return len(rows)

    def get_epss_records(
        self,
        cve_ids: Iterable[str],
        *,
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
        include_stale: bool = False,
        now: float | None = None,
    ) -> tuple[dict[str, EpssRecord | None], set[str]]:
        """Retrieve cached EPSS entries and return `(cached_map, missing_or_expired_cves)`.

        `cached_map[cve]` is an `EpssRecord` when present or `None` when negatively cached
        (the CVE was queried recently and had no EPSS score on FIRST.org).
        """
        normalized = sorted({normalize_required_cve_id(cve) for cve in cve_ids})
        if not normalized:
            return {}, set()

        current = time.time() if now is None else now
        cached: dict[str, EpssRecord | None] = {}
        missing: set[str] = set(normalized)

        chunk_size = 500
        for idx in range(0, len(normalized), chunk_size):
            chunk = normalized[idx : idx + chunk_size]
            placeholders = ",".join("?" for _ in chunk)
            rows = self._conn.execute(
                f"""
                SELECT cve_id, epss, percentile, score_date, fetched_at
                FROM epss_entries
                WHERE cve_id IN ({placeholders})
                """,  # noqa: S608
                chunk,
            ).fetchall()

            for row in rows:
                age = current - float(row["fetched_at"])
                if not include_stale and age >= ttl_seconds:
                    continue

                cve_id = str(row["cve_id"])
                missing.discard(cve_id)
                if row["epss"] is None or row["percentile"] is None:
                    cached[cve_id] = None
                else:
                    cached[cve_id] = EpssRecord(
                        cve_id=cve_id,
                        epss=float(row["epss"]),
                        percentile=float(row["percentile"]),
                        score_date=_parse_optional_date(row["score_date"]),
                    )

        return cached, missing

    def clear(self) -> None:
        """Delete all cached KEV and EPSS entries."""
        with self._conn:
            self._conn.execute("DELETE FROM kev_entries")
            self._conn.execute("DELETE FROM epss_entries")
            self._conn.execute(
                "DELETE FROM cache_meta WHERE key IN ('kev_fetched_at', 'kev_catalog_version')"
            )

    def stats(self) -> CacheStats:
        """Return cache population and freshness statistics."""
        kev_count = int(self._conn.execute("SELECT COUNT(*) FROM kev_entries").fetchone()[0])
        epss_total = int(self._conn.execute("SELECT COUNT(*) FROM epss_entries").fetchone()[0])
        epss_neg = int(
            self._conn.execute("SELECT COUNT(*) FROM epss_entries WHERE epss IS NULL").fetchone()[0]
        )
        fetched_ts = self.get_kev_fetched_at()
        fetched_dt = datetime.fromtimestamp(fetched_ts, tz=UTC) if fetched_ts is not None else None
        return CacheStats(
            db_path=self.db_path,
            kev_count=kev_count,
            kev_fetched_at=fetched_dt,
            kev_catalog_version=self._get_meta("kev_catalog_version"),
            epss_count=epss_total - epss_neg,
            epss_negative_count=epss_neg,
        )
