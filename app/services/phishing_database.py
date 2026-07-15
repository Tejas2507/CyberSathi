"""
ConfirmedPhishingDatabase
=========================
SQLite-backed cache for high-confidence phishing verdicts.

Insertion policy:
  - verdict == "phishing"   AND
  - confidence >= PHISHING_CONFIDENCE_THRESHOLD (default 0.95)

Legitimate and uncertain verdicts are NEVER stored.
"""

from __future__ import annotations

import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Dict, Any

from app.logging import logger
from app.settings import settings


class ConfirmedPhishingDatabase:
    """
    Thread-safe SQLite store for confirmed phishing URLs.
    A single shared connection is maintained with check_same_thread=False.
    """

    _instance: Optional["ConfirmedPhishingDatabase"] = None
    _class_lock = threading.Lock()

    def __new__(cls) -> "ConfirmedPhishingDatabase":
        with cls._class_lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._initialized = False
            return cls._instance

    def __init__(self) -> None:
        if self._initialized:
            return

        self._db_path = Path(settings.PHISHING_DB_PATH)
        self._threshold = settings.PHISHING_CONFIDENCE_THRESHOLD
        self._lock = threading.Lock()
        self._conn: sqlite3.Connection = sqlite3.connect(
            str(self._db_path),
            check_same_thread=False,
        )
        self._conn.row_factory = sqlite3.Row
        self._create_schema()
        self._initialized = True
        logger.info(
            f"[PhishingDB] Initialized at '{self._db_path}' "
            f"(threshold={self._threshold})"
        )

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    def _create_schema(self) -> None:
        with self._conn:
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS confirmed_phishing (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    url             TEXT    NOT NULL UNIQUE,
                    domain          TEXT    NOT NULL,
                    confidence      REAL    NOT NULL,
                    severity        TEXT,
                    impersonated    TEXT,
                    scam_category   TEXT,
                    summary         TEXT,
                    first_seen      TEXT    NOT NULL,
                    last_seen       TEXT    NOT NULL,
                    hit_count       INTEGER NOT NULL DEFAULT 1
                )
                """
            )
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_url ON confirmed_phishing (url)"
            )
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_domain ON confirmed_phishing (domain)"
            )
        logger.debug("[PhishingDB] Schema ready.")

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_domain(url: str) -> str:
        from urllib.parse import urlparse

        try:
            return urlparse(url).netloc.lower() or url
        except Exception:
            return url

    @staticmethod
    def _now_iso() -> str:
        return datetime.now(timezone.utc).isoformat()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def lookup(self, url: str) -> Optional[Dict[str, Any]]:
        """
        Returns the cached record for *url* if it exists, else None.
        Also increments hit_count and updates last_seen on cache hit.
        """
        now = self._now_iso()
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM confirmed_phishing WHERE url = ?", (url,)
            ).fetchone()

            if row is None:
                return None

            # Update hit stats
            self._conn.execute(
                "UPDATE confirmed_phishing SET hit_count = hit_count + 1, last_seen = ? WHERE url = ?",
                (now, url),
            )
            self._conn.commit()

        record = dict(row)
        logger.info(
            f"[PhishingDB] Cache HIT for '{url}' "
            f"(hits={record['hit_count'] + 1}, confidence={record['confidence']})"
        )
        return record

    def insert(
        self,
        url: str,
        verdict_json: Dict[str, Any],
    ) -> bool:
        """
        Persists a confirmed phishing result.
        Returns True if inserted/updated, False if policy rejected it.

        Policy:
          - verdict must be "phishing"
          - confidence must be >= threshold
        """
        verdict = verdict_json.get("verdict", "")
        confidence = float(verdict_json.get("confidence", 0.0))

        if verdict != "phishing":
            logger.debug(f"[PhishingDB] Skipped insert for '{url}': verdict={verdict}")
            return False

        if confidence < self._threshold:
            logger.debug(
                f"[PhishingDB] Skipped insert for '{url}': "
                f"confidence={confidence} < threshold={self._threshold}"
            )
            return False

        domain = self._extract_domain(url)
        now = self._now_iso()

        with self._lock:
            existing = self._conn.execute(
                "SELECT id, hit_count FROM confirmed_phishing WHERE url = ?", (url,)
            ).fetchone()

            if existing:
                self._conn.execute(
                    """
                    UPDATE confirmed_phishing
                    SET confidence   = ?,
                        severity     = ?,
                        impersonated = ?,
                        scam_category = ?,
                        summary      = ?,
                        last_seen    = ?,
                        hit_count    = hit_count + 1
                    WHERE url = ?
                    """,
                    (
                        confidence,
                        verdict_json.get("severity"),
                        verdict_json.get("impersonated_entity"),
                        verdict_json.get("scam_category"),
                        verdict_json.get("summary"),
                        now,
                        url,
                    ),
                )
            else:
                self._conn.execute(
                    """
                    INSERT INTO confirmed_phishing
                        (url, domain, confidence, severity, impersonated, scam_category, summary, first_seen, last_seen, hit_count)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
                    """,
                    (
                        url,
                        domain,
                        confidence,
                        verdict_json.get("severity"),
                        verdict_json.get("impersonated_entity"),
                        verdict_json.get("scam_category"),
                        verdict_json.get("summary"),
                        now,
                        now,
                    ),
                )
            self._conn.commit()

        logger.info(
            f"[PhishingDB] {'Updated' if existing else 'Inserted'} "
            f"confirmed phishing record for '{url}' (confidence={confidence})"
        )
        return True

    def count(self) -> int:
        """Returns total number of confirmed phishing records in the DB."""
        with self._lock:
            row = self._conn.execute(
                "SELECT COUNT(*) as cnt FROM confirmed_phishing"
            ).fetchone()
            return row["cnt"] if row else 0

    def close(self) -> None:
        """Closes the database connection."""
        with self._lock:
            self._conn.close()
        logger.info("[PhishingDB] Connection closed.")


# Singleton export
phishing_db = ConfirmedPhishingDatabase()
