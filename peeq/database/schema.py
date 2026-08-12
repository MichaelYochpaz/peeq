"""Database schema definitions and versioning.

Owns the DDL statements, schema version constants, and the
"check version -> recreate if mismatched" logic.  This is a cache,
so schema mismatches discard and recreate the database (no migrations).
"""

from __future__ import annotations

import logging
import sqlite3

logger = logging.getLogger(__name__)

# Bump when table structure changes (columns, indices, constraints).
# Mismatch = drop and recreate the entire database file.
CURRENT_SCHEMA_VERSION = 2

# Bump when metadata extraction/parsing logic changes in peeq.
# Mismatch on a specific distribution = re-resolve its metadata,
# reusing the cached artifact if available.
CURRENT_METADATA_SCHEMA_VERSION = 1

_CREATE_TABLES = """\
CREATE TABLE IF NOT EXISTS packages (
    id INTEGER PRIMARY KEY,
    registry TEXT NOT NULL,
    name TEXT NOT NULL,
    latest_version TEXT,
    summary TEXT,
    available_versions TEXT,
    version_count INTEGER,
    legacy_metadata TEXT,
    fetched_at INTEGER NOT NULL,
    ttl_seconds INTEGER NOT NULL DEFAULT 3600,
    UNIQUE(registry, name)
);

CREATE TABLE IF NOT EXISTS distributions (
    id INTEGER PRIMARY KEY,
    package_id INTEGER NOT NULL,
    version TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    sha256_source TEXT NOT NULL DEFAULT 'registry',
    filename TEXT,
    download_url TEXT,
    archive_path TEXT,
    size_bytes INTEGER,
    created_at INTEGER NOT NULL,
    last_accessed_at INTEGER NOT NULL,
    metadata TEXT,
    metadata_source TEXT,
    metadata_schema_version INTEGER DEFAULT 1,
    metadata_cached_at INTEGER,
    deps_known BOOLEAN NOT NULL DEFAULT TRUE,
    dynamic_fields TEXT,
    UNIQUE(package_id, sha256),
    FOREIGN KEY (package_id) REFERENCES packages(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS dependencies (
    id INTEGER PRIMARY KEY,
    distribution_id INTEGER NOT NULL
        REFERENCES distributions(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    specifier TEXT NOT NULL DEFAULT '',
    extras TEXT,
    markers TEXT,
    raw TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_distributions_sha256
    ON distributions(sha256);
CREATE INDEX IF NOT EXISTS idx_distributions_last_accessed
    ON distributions(last_accessed_at);
CREATE INDEX IF NOT EXISTS idx_dep_name
    ON dependencies(name);
CREATE INDEX IF NOT EXISTS idx_dep_distribution
    ON dependencies(distribution_id);
CREATE INDEX IF NOT EXISTS idx_distributions_priority
    ON distributions(package_id, version, deps_known DESC, metadata_source);
"""


def ensure_schema(conn: sqlite3.Connection) -> None:
    """Create tables if missing, or recreate if the schema version changed.

    Uses `PRAGMA user_version` to track the schema version.  On mismatch
    the database is wiped and recreated — this is acceptable because all
    data is a cache that can be rebuilt from upstream sources.
    """
    row = conn.execute("PRAGMA user_version;").fetchone()
    current = row[0] if row else 0

    if current == CURRENT_SCHEMA_VERSION:
        return

    if current != 0:
        logger.info(
            "Schema version mismatch (have %d, want %d) — recreating cache",
            current,
            CURRENT_SCHEMA_VERSION,
        )
        # Drop everything and start fresh.
        conn.executescript(
            "DROP TABLE IF EXISTS dependencies;DROP TABLE IF EXISTS distributions;DROP TABLE IF EXISTS packages;"
        )

    conn.executescript(_CREATE_TABLES)
    conn.execute(f"PRAGMA user_version = {CURRENT_SCHEMA_VERSION};")
