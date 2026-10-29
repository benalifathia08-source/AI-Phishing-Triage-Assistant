"""SQLite cache for lookup results, plus daily usage counters for the free API quotas.

Lookup results name the links, domains and senders of the emails analyzed, so they are purged after
CACHE_RETENTION_DAYS (`phishtriage cache purge`, and at every start of the web interface). Deleted rows
are overwritten and the file compacted, so purged results cannot be read back from the file.
This is the working cache only: a frozen snapshot for the M7 evaluation must live in its own file."""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from datetime import date
from pathlib import Path


class Cache:
    def __init__(self, path: Path | str = ":memory:") -> None:
        if str(path) != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._db = sqlite3.connect(str(path), check_same_thread=False)
        self._db.execute("PRAGMA secure_delete = ON")  # deleted rows are overwritten, not left in free pages
        self._db.executescript("""
            CREATE TABLE IF NOT EXISTS results (service TEXT, key TEXT, fetched REAL, value TEXT, PRIMARY KEY (service, key));
            CREATE TABLE IF NOT EXISTS usage (service TEXT, day TEXT, count INTEGER, PRIMARY KEY (service, day));
        """)

    def get(self, service: str, key: str, max_age_seconds: float) -> dict | None:
        with self._lock:
            row = self._db.execute("SELECT fetched, value FROM results WHERE service = ? AND key = ?", (service, key)).fetchone()
        if row and time.time() - row[0] <= max_age_seconds:
            return json.loads(row[1])
        return None

    def put(self, service: str, key: str, value: dict) -> None:
        with self._lock, self._db:
            self._db.execute("INSERT OR REPLACE INTO results VALUES (?, ?, ?, ?)", (service, key, time.time(), json.dumps(value)))

    def purge(self, older_than_seconds: float) -> int:
        """Delete results fetched longer ago than this, and usage counters older than a week. Returns rows deleted."""
        cutoff = time.time() - older_than_seconds
        with self._lock:
            with self._db:
                deleted = self._db.execute("DELETE FROM results WHERE fetched < ?", (cutoff,)).rowcount
                week_ago = date.fromtimestamp(time.time() - 7 * 86400).isoformat()
                self._db.execute("DELETE FROM usage WHERE day < ?", (week_ago,))
            if deleted:
                self._db.execute("VACUUM")  # give the freed pages back: the file no longer holds them
        return deleted

    def stats(self) -> dict[str, tuple[int, float, float]]:
        """{service: (results, oldest fetch time, newest fetch time)}."""
        with self._lock:
            rows = self._db.execute("SELECT service, COUNT(*), MIN(fetched), MAX(fetched) FROM results GROUP BY service")
            return {service: (count, oldest, newest) for service, count, oldest, newest in rows}

    def close(self) -> None:
        with self._lock:
            self._db.close()

    def used_today(self, service: str) -> int:
        with self._lock:
            row = self._db.execute("SELECT count FROM usage WHERE service = ? AND day = ?", (service, date.today().isoformat())).fetchone()
        return row[0] if row else 0

    def count_use(self, service: str) -> None:
        with self._lock, self._db:
            self._db.execute(
                "INSERT INTO usage VALUES (?, ?, 1) ON CONFLICT (service, day) DO UPDATE SET count = count + 1",
                (service, date.today().isoformat()),
            )


def purge_expired(settings) -> int:
    """Apply the retention to the working cache, without creating it when it does not exist yet."""
    if not Path(settings.cache_path).exists():
        return 0
    cache = Cache(settings.cache_path)
    try:
        return cache.purge(settings.cache_retention_days * 86400)
    finally:
        cache.close()


class SnapshotCache(Cache):
    """The frozen, dated lookup snapshot for the M7 evaluation (EVALUATION.md section 3), in its own file.

    While recording, the first answer for each lookup is kept whatever its age, so a recording spread over
    several days (the free quotas) stays one snapshot. Read-only replay opens the file read-only at the SQLite
    level: answers are served whatever their age, nothing is written, and no quota is counted. The working
    cache's purge never touches this file, because it lives elsewhere."""

    def __init__(self, path: Path | str, read_only: bool = False) -> None:
        self.read_only = read_only
        if not read_only:
            super().__init__(path)
            self._db.execute("CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT)")
            return
        if not Path(path).exists():
            raise FileNotFoundError(f"no lookup snapshot at {path}")
        self._lock = threading.Lock()
        self._db = sqlite3.connect(f"{Path(path).resolve().as_uri()}?mode=ro", uri=True, check_same_thread=False)

    def get(self, service: str, key: str, max_age_seconds: float) -> dict | None:
        return super().get(service, key, float("inf"))  # frozen: the age of an answer does not matter

    def put(self, service: str, key: str, value: dict) -> None:
        if self.read_only:
            return
        if self.get(service, key, 0) is None:  # keep the first answer: the snapshot is frozen at first fetch
            super().put(service, key, value)

    def used_today(self, service: str) -> int:
        return 0 if self.read_only else super().used_today(service)

    def count_use(self, service: str) -> None:
        if not self.read_only:
            super().count_use(service)

    def set_meta(self, key: str, value: str) -> None:
        with self._lock, self._db:
            self._db.execute("INSERT OR REPLACE INTO meta VALUES (?, ?)", (key, value))

    def get_meta(self, key: str) -> str | None:
        with self._lock:
            try:
                row = self._db.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
            except sqlite3.OperationalError:
                return None
        return row[0] if row else None
