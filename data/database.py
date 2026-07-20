"""SQLite cache for IP enrichment results.

The cache is keyed on ``(ip, enricher)`` and stores the raw JSON
response returned by the upstream API.  A configurable TTL
(``[cache]/ttl_hours`` in ``config.ini``) controls how long entries
remain valid; setting the TTL to ``0`` disables expiry.

This cache dramatically reduces the number of API calls when the same
IPs recur across alerts (very common in SOC work) and helps stay within
the free-tier rate limits of VirusTotal and AbuseIPDB.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Dict, Optional

from utils.config import ConfigManager
from utils.logger import get_logger

logger = get_logger(__name__)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DB_PATH = PROJECT_ROOT / "data" / "enrichment_cache.db"


class EnrichmentCache:
    """Thread-safe SQLite cache for enrichment results.

    A single :class:`sqlite3.Connection` is shared across threads; every
    call acquires a :class:`threading.Lock` to serialize writes (SQLite
    is not happy with concurrent writers).  Reads use ``check_same_thread=False``
    so worker threads can call :meth:`get`.
    """

    def __init__(self,
                 config: ConfigManager,
                 db_path: Optional[Path] = None) -> None:
        self.config = config
        self.db_path = Path(db_path) if db_path else DEFAULT_DB_PATH
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(
            str(self.db_path),
            check_same_thread=False,
            isolation_level=None,  # autocommit
        )
        self._conn.row_factory = sqlite3.Row
        self._init_schema()
        logger.debug("Enrichment cache ready at %s", self.db_path)

    def _init_schema(self) -> None:
        with self._lock:
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS enrichment (
                    ip        TEXT NOT NULL,
                    enricher  TEXT NOT NULL,
                    payload   TEXT NOT NULL,
                    cached_at REAL NOT NULL,
                    PRIMARY KEY (ip, enricher)
                )
                """
            )
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_enrichment_ip ON enrichment(ip)"
            )

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #
    def get(self, ip: str, enricher: str) -> Optional[Dict[str, Any]]:
        """Return cached payload for ``(ip, enricher)`` or ``None``.

        Returns ``None`` if no entry exists, or if the entry is older
        than the configured TTL (unless TTL is ``0``).
        """
        ttl_hours = self.config.get_int("cache", "ttl_hours", fallback=24)
        with self._lock:
            row = self._conn.execute(
                "SELECT payload, cached_at FROM enrichment WHERE ip = ? AND enricher = ?",
                (ip, enricher),
            ).fetchone()

        if row is None:
            return None

        if ttl_hours > 0:
            age_seconds = time.time() - row["cached_at"]
            if age_seconds > ttl_hours * 3600:
                logger.debug("Cache miss (expired) for %s/%s", ip, enricher)
                return None

        try:
            return json.loads(row["payload"])
        except json.JSONDecodeError:
            logger.warning("Corrupt cache entry for %s/%s; ignoring.", ip, enricher)
            return None

    def put(self, ip: str, enricher: str, payload: Dict[str, Any]) -> None:
        """Insert (or replace) the cached payload for ``(ip, enricher)``."""
        serialized = json.dumps(payload, ensure_ascii=False)
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO enrichment (ip, enricher, payload, cached_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(ip, enricher) DO UPDATE SET
                    payload = excluded.payload,
                    cached_at = excluded.cached_at
                """,
                (ip, enricher, serialized, time.time()),
            )

    def clear(self) -> int:
        """Delete all cached entries.  Returns the number of rows deleted."""
        with self._lock:
            cur = self._conn.execute("DELETE FROM enrichment")
            deleted = cur.rowcount or 0
        logger.info("Cleared %d cache entries.", deleted)
        return deleted

    def stats(self) -> Dict[str, int]:
        """Return basic cache statistics."""
        with self._lock:
            total = self._conn.execute(
                "SELECT COUNT(*) AS c FROM enrichment"
            ).fetchone()["c"]
            distinct_ips = self._conn.execute(
                "SELECT COUNT(DISTINCT ip) AS c FROM enrichment"
            ).fetchone()["c"]
        return {"entries": total, "distinct_ips": distinct_ips}

    def close(self) -> None:
        with self._lock:
            self._conn.close()


__all__ = ["EnrichmentCache", "DEFAULT_DB_PATH"]
