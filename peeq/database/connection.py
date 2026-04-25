"""Database connection lifecycle, PRAGMA configuration, and platform workarounds.

Every database interaction in peeq flows through `open_cache_db`.
No other module should import `sqlite3` directly.
"""

from __future__ import annotations

import logging
import platform
import sqlite3
import sys
import time
from contextlib import contextmanager
from typing import TYPE_CHECKING, Any

from peeq.database.schema import ensure_schema

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

logger = logging.getLogger(__name__)

SQLITE_VERSION = sqlite3.sqlite_version_info
"""Parsed version tuple of the linked SQLite C library."""


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


@contextmanager
def open_cache_db(cache_dir: Path) -> Iterator[sqlite3.Connection]:
    """Open a connection to the cache database with optimal settings.

    This is the single entry point for all database access in peeq.
    Handles PRAGMA configuration, schema initialisation, and cleanup.

    The connection uses autocommit mode so that all writes require explicit
    transaction boundaries (`BEGIN` / `COMMIT` or `with conn:`).
    This prevents Python's implicit `BEGIN` from holding read locks
    open across `await` points, which would block WAL checkpointing.
    """
    db_path = cache_dir / "cache.db"
    db_path.parent.mkdir(parents=True, exist_ok=True)

    # Python 3.12+ has PEP 249 compliant `autocommit` parameter.
    # For 3.10/3.11, `isolation_level=None` achieves the same effect
    # by disabling Python's implicit BEGIN emission.
    connect_kwargs: dict[str, Any] = {"timeout": 5.0}
    if sys.version_info >= (3, 12):
        connect_kwargs["autocommit"] = True
    else:
        connect_kwargs["isolation_level"] = None

    conn = _connect_with_retry(db_path, connect_kwargs)
    conn.row_factory = sqlite3.Row

    try:
        _apply_persistent_pragmas(conn)
        _apply_per_connection_pragmas(conn)
        ensure_schema(conn)
        yield conn
    finally:
        _optimize_on_close(conn)
        conn.close()


# ---------------------------------------------------------------------------
# PRAGMA helpers
# ---------------------------------------------------------------------------


def _apply_persistent_pragmas(conn: sqlite3.Connection) -> None:
    """PRAGMAs that modify the database file structure.  Applied once.

    Setting WAL on an already-WAL database is a no-op.
    """
    result = conn.execute("PRAGMA journal_mode = WAL;").fetchone()
    if result is None or result[0] != "wal":
        # WAL may fail on certain filesystems (e.g. network mounts).
        logger.warning(
            "Failed to enable WAL journal mode — falling back to DELETE mode"
        )

    # Cap WAL file growth at 4 MB to prevent unbounded disk usage
    # during bursty batch inserts (dependency tree resolution).
    conn.execute("PRAGMA journal_size_limit = 4194304;")


def _apply_per_connection_pragmas(conn: sqlite3.Connection) -> None:
    """PRAGMAs that configure runtime behaviour.  Applied every connection."""
    # NORMAL sync: skip fsync on commits, sync only on checkpoint.
    # Safe for a cache — worst case, lose the last transaction on OS crash.
    conn.execute("PRAGMA synchronous = NORMAL;")

    # Enable ON DELETE CASCADE for clean LRU eviction.
    conn.execute("PRAGMA foreign_keys = ON;")

    # Keep temp tables/indices in RAM.
    conn.execute("PRAGMA temp_store = MEMORY;")

    # 4 MB page cache (negative value = kilobytes, not pages).
    conn.execute("PRAGMA cache_size = -4000;")

    # Retry on lock contention for up to 5 seconds.
    conn.execute("PRAGMA busy_timeout = 5000;")


def _optimize_on_close(conn: sqlite3.Connection) -> None:
    """Update query planner statistics before process exit."""
    try:
        # SQLite < 3.46.0 requires an explicit analysis_limit to prevent
        # ANALYZE from scanning entire tables.
        if SQLITE_VERSION < (3, 46, 0):
            conn.execute("PRAGMA analysis_limit = 400;")
        conn.execute("PRAGMA optimize;")
    except sqlite3.Error:
        # Best-effort — skip if the database is locked by another process.
        pass


# ---------------------------------------------------------------------------
# Windows antivirus resilience
# ---------------------------------------------------------------------------


def _connect_with_retry(
    db_path: Path,
    connect_kwargs: dict[str, Any],
    max_retries: int = 3,
) -> sqlite3.Connection:
    """Connect to the database, retrying on Windows antivirus locks.

    On Windows, antivirus software (Windows Defender, etc.) may hold
    transient kernel-level file locks that bypass SQLite's busy_timeout.
    We retry a few times with backoff before giving up.
    """
    if platform.system() != "Windows":
        return sqlite3.connect(str(db_path), **connect_kwargs)

    backoff_ms = [50, 100, 200]
    last_error: sqlite3.OperationalError | None = None
    for attempt in range(max_retries):
        try:
            return sqlite3.connect(str(db_path), **connect_kwargs)
        except sqlite3.OperationalError as exc:  # noqa: PERF203
            last_error = exc
            if attempt < max_retries - 1:
                time.sleep(backoff_ms[attempt] / 1000)

    # last_error is guaranteed to be set if we reach here because
    # max_retries >= 1 and the loop only exits after catching an error.
    raise last_error  # ty: ignore[invalid-raise]
