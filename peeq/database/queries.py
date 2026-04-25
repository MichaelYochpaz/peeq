"""Typed query functions for the cache database.

All SQL lives here.  Functions accept a `sqlite3.Connection` and return
Pydantic models or primitives.  No other module should contain raw SQL.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, NamedTuple

from peeq.database.schema import CURRENT_METADATA_SCHEMA_VERSION
from peeq.models import CacheStats, Dependency, PackageMetadata

# ---------------------------------------------------------------------------
# packages table
# ---------------------------------------------------------------------------


def get_package(
    conn: sqlite3.Connection,
    registry: str,
    name: str,
) -> dict[str, Any] | None:
    """Look up a cached package row.

    Returns the raw row as a `dict` (callers interpret TTL, versions,
    etc.) or `None` if not found.
    """
    row = conn.execute(
        "SELECT * FROM packages WHERE registry = ? AND name = ?",
        (registry, name),
    ).fetchone()
    return dict(row) if row else None


def upsert_package(  # noqa: PLR0913
    conn: sqlite3.Connection,
    *,
    registry: str,
    name: str,
    latest_version: str | None = None,
    summary: str | None = None,
    available_versions: list[str] | None = None,
    version_count: int | None = None,
    legacy_metadata: str | None = None,
    fetched_at: int,
    ttl_seconds: int = 3600,
) -> int:
    """Insert or update a package row.  Returns the `id`."""
    versions_json = json.dumps(available_versions) if available_versions else None
    with conn:
        cursor = conn.execute(
            """\
            INSERT INTO packages
                (registry, name, latest_version, summary,
                 available_versions, version_count, legacy_metadata,
                 fetched_at, ttl_seconds)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(registry, name) DO UPDATE SET
                latest_version = excluded.latest_version,
                summary = excluded.summary,
                available_versions = excluded.available_versions,
                version_count = excluded.version_count,
                legacy_metadata = excluded.legacy_metadata,
                fetched_at = excluded.fetched_at,
                ttl_seconds = excluded.ttl_seconds
            """,
            (
                registry,
                name,
                latest_version,
                summary,
                versions_json,
                version_count,
                legacy_metadata,
                fetched_at,
                ttl_seconds,
            ),
        )
        # On INSERT lastrowid is the new id; on UPDATE we need to query.
        if cursor.lastrowid:
            return cursor.lastrowid
    row = conn.execute(
        "SELECT id FROM packages WHERE registry = ? AND name = ?",
        (registry, name),
    ).fetchone()
    return row[0]


def ensure_package(
    conn: sqlite3.Connection,
    *,
    registry: str,
    name: str,
) -> int:
    """Ensure a package row exists (FK stub).

    Uses `INSERT ... ON CONFLICT DO NOTHING` so that existing cached
    API data (latest_version, summary, available_versions, etc.) is
    never clobbered.  If the row already exists its `id` is returned
    without modification.

    A stub row uses `fetched_at=0` which causes immediate TTL expiry,
    ensuring the next `check()` call will refresh from the API.
    """
    with conn:
        conn.execute(
            """\
            INSERT INTO packages (registry, name, fetched_at)
            VALUES (?, ?, 0)
            ON CONFLICT(registry, name) DO NOTHING
            """,
            (registry, name),
        )
    row = conn.execute(
        "SELECT id FROM packages WHERE registry = ? AND name = ?",
        (registry, name),
    ).fetchone()
    return row[0]


# ---------------------------------------------------------------------------
# distributions table + metadata assembly
# ---------------------------------------------------------------------------


class DistributionMetadataResult(NamedTuple):
    """Cached distribution metadata plus the backing row id."""

    metadata: PackageMetadata
    distribution_id: int


def get_distribution_metadata(
    conn: sqlite3.Connection,
    registry: str,
    name: str,
    version: str,
) -> DistributionMetadataResult | None:
    """Assemble a complete `PackageMetadata` from the cache.

    Assembly stages:
    1. JSON blob  ->  scalar fields
    2. `metadata_source` column  ->  `source`
    3. `filename` column  ->  `source_filename`
    4. `dynamic_fields` column  ->  `dynamic_fields`
    5. `dependencies` table  ->  `dependencies`
    6. `deps_known` column  ->  `None` vs `[]` disambiguation

    When multiple rows exist for the same version (sdist, wheel variants,
    PEP 658 (https://peps.python.org/pep-0658/) metadata), the row with
    the best metadata source is selected: `deps_known DESC`, then
    `pep658 > wheel > sdist`.

    Returns `None` if the distribution is not cached or has no metadata.
    Otherwise returns the assembled metadata plus the selected
    distribution row id.
    """
    row = conn.execute(
        """\
        SELECT d.id, d.metadata, d.metadata_source,
               d.metadata_schema_version, d.deps_known,
               d.filename, d.dynamic_fields
        FROM distributions d
        JOIN packages p ON d.package_id = p.id
        WHERE p.registry = ? AND p.name = ? AND d.version = ?
        ORDER BY d.deps_known DESC,
            CASE d.metadata_source
                WHEN 'pep658' THEN 1
                WHEN 'wheel' THEN 2
                WHEN 'sdist' THEN 3
                ELSE 4
            END
        LIMIT 1
        """,
        (registry, name, version),
    ).fetchone()

    if row is None or row["metadata"] is None:
        return None

    # Check schema freshness
    if (row["metadata_schema_version"] or 0) < CURRENT_METADATA_SCHEMA_VERSION:
        return None  # Caller should re-resolve

    # Stage 1: scalar fields from JSON blob
    metadata = PackageMetadata.model_validate_json(row["metadata"])

    # Stage 2: source from column
    metadata.source = row["metadata_source"]

    # Stage 3: filename from column
    metadata.source_filename = row["filename"]

    # Stage 4: dynamic_fields from column
    metadata.dynamic_fields = (
        json.loads(row["dynamic_fields"]) if row["dynamic_fields"] else None
    )

    # Stage 5 & 6: dependencies from table
    dist_id: int = row["id"]
    if row["deps_known"]:
        dep_rows = conn.execute(
            """\
            SELECT name, specifier, extras, markers, raw
            FROM dependencies
            WHERE distribution_id = ?
            """,
            (dist_id,),
        ).fetchall()
        metadata.dependencies = [_row_to_dependency(r) for r in dep_rows]
    else:
        metadata.dependencies = None

    return DistributionMetadataResult(
        metadata=metadata,
        distribution_id=dist_id,
    )


def upsert_distribution(  # noqa: PLR0913
    conn: sqlite3.Connection,
    *,
    package_id: int,
    version: str,
    sha256: str,
    sha256_source: str = "registry",
    filename: str | None = None,
    download_url: str | None = None,
    archive_path: str | None = None,
    size_bytes: int | None = None,
    created_at: int,
    last_accessed_at: int,
    metadata: PackageMetadata | None = None,
    deps_known: bool = True,
    dynamic_fields: str | None = None,
) -> int:
    """Insert or update a distribution, including metadata and dependencies.

    Metadata is split across storage locations in a single transaction:
    - JSON blob (excluding deps, source, filename, dynamic)  ->  `metadata` column
    - `source`  ->  `metadata_source` column
    - `source_filename`  ->  `filename` column
    - `dynamic_fields`  ->  `dynamic_fields` column
    - `dependencies`  ->  `dependencies` table rows

    Uses `COALESCE` for `archive_path`, `download_url`,
    `size_bytes`, `filename`, `metadata`, `metadata_source`,
    `metadata_cached_at`, `dynamic_fields`, and a guarded
    `CASE` for `deps_known` so that metadata-only and
    archive-only upserts do not clobber each other's fields.
    Dependency rows are only replaced when *metadata* is provided.

    Returns the distribution `id`.
    """
    metadata_json: str | None = None
    metadata_source: str | None = None
    metadata_cached_at: int | None = None

    if metadata is not None:
        metadata_json = metadata.model_dump_json(
            exclude={"dependencies", "source", "source_filename", "dynamic_fields"},
        )
        metadata_source = metadata.source
        metadata_cached_at = last_accessed_at

    with conn:
        cursor = conn.execute(
            """\
            INSERT INTO distributions
                (package_id, version, sha256, sha256_source, filename,
                 download_url, archive_path, size_bytes,
                 created_at, last_accessed_at,
                 metadata, metadata_source, metadata_schema_version,
                 metadata_cached_at, deps_known, dynamic_fields)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(package_id, sha256) DO UPDATE SET
                sha256_source = excluded.sha256_source,
                download_url = COALESCE(excluded.download_url, distributions.download_url),
                archive_path = COALESCE(excluded.archive_path, distributions.archive_path),
                size_bytes = COALESCE(excluded.size_bytes, distributions.size_bytes),
                filename = COALESCE(excluded.filename, distributions.filename),
                last_accessed_at = excluded.last_accessed_at,
                metadata = COALESCE(excluded.metadata, distributions.metadata),
                metadata_source = COALESCE(excluded.metadata_source, distributions.metadata_source),
                metadata_schema_version = excluded.metadata_schema_version,
                metadata_cached_at = COALESCE(excluded.metadata_cached_at, distributions.metadata_cached_at),
                deps_known = CASE
                    WHEN excluded.metadata IS NOT NULL THEN excluded.deps_known
                    ELSE distributions.deps_known
                END,
                dynamic_fields = COALESCE(excluded.dynamic_fields, distributions.dynamic_fields)
            """,
            (
                package_id,
                version,
                sha256,
                sha256_source,
                filename,
                download_url,
                archive_path,
                size_bytes,
                created_at,
                last_accessed_at,
                metadata_json,
                metadata_source,
                CURRENT_METADATA_SCHEMA_VERSION,
                metadata_cached_at,
                deps_known,
                dynamic_fields,
            ),
        )

        dist_id = cursor.lastrowid
        if not dist_id:
            row = conn.execute(
                "SELECT id FROM distributions WHERE package_id = ? AND sha256 = ?",
                (package_id, sha256),
            ).fetchone()
            dist_id = row[0]

        # Replace dependency rows only when new metadata is provided.
        if metadata is not None:
            conn.execute(
                "DELETE FROM dependencies WHERE distribution_id = ?",
                (dist_id,),
            )
            if metadata.dependencies is not None:
                _insert_dependencies(conn, dist_id, metadata.dependencies)

    return dist_id


# ---------------------------------------------------------------------------
# dependencies table
# ---------------------------------------------------------------------------


def get_dependencies(
    conn: sqlite3.Connection,
    distribution_id: int,
) -> list[Dependency]:
    """Fetch all dependencies for a distribution."""
    rows = conn.execute(
        """\
        SELECT name, specifier, extras, markers, raw
        FROM dependencies
        WHERE distribution_id = ?
        """,
        (distribution_id,),
    ).fetchall()
    return [_row_to_dependency(r) for r in rows]


def upsert_dependencies(
    conn: sqlite3.Connection,
    distribution_id: int,
    dependencies: list[Dependency],
) -> None:
    """Replace all dependency rows for a distribution."""
    with conn:
        conn.execute(
            "DELETE FROM dependencies WHERE distribution_id = ?",
            (distribution_id,),
        )
        _insert_dependencies(conn, distribution_id, dependencies)


def find_dependents(
    conn: sqlite3.Connection,
    dependency_name: str,
) -> list[dict[str, Any]]:
    """Find cached packages that depend on *dependency_name*.

    Returns a list of dicts with keys `name`, `version`, `specifier`.
    Uses the `idx_dep_name` index for O(log N) lookups.
    """
    rows = conn.execute(
        """\
        SELECT DISTINCT p.name, d.version, dep.specifier
        FROM dependencies dep
        JOIN distributions d ON dep.distribution_id = d.id
        JOIN packages p ON d.package_id = p.id
        WHERE dep.name = ?
        """,
        (dependency_name,),
    ).fetchall()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Hash-based lookups
# ---------------------------------------------------------------------------


def find_by_hash(
    conn: sqlite3.Connection,
    sha256: str,
) -> dict[str, Any] | None:
    """Find a cached distribution by its SHA-256 hash.

    Uses the `idx_distributions_sha256` index.
    Returns a dict with `archive_path`, `registry`, `name`,
    `version`, or `None` if not found.

    Rows with a live `archive_path` are preferred over
    soft-evicted rows (`archive_path IS NULL`) so that
    hash-based deduplication works correctly after eviction.
    """
    row = conn.execute(
        """\
        SELECT d.archive_path, p.registry, p.name, d.version
        FROM distributions d
        JOIN packages p ON d.package_id = p.id
        WHERE d.sha256 = ?
        ORDER BY (d.archive_path IS NOT NULL) DESC,
                 d.last_accessed_at DESC
        LIMIT 1
        """,
        (sha256,),
    ).fetchone()
    return dict(row) if row else None


# ---------------------------------------------------------------------------
# LRU / maintenance
# ---------------------------------------------------------------------------


def touch_distribution(
    conn: sqlite3.Connection,
    distribution_id: int,
    accessed_at: int,
) -> None:
    """Update `last_accessed_at` for LRU tracking."""
    with conn:
        conn.execute(
            "UPDATE distributions SET last_accessed_at = ? WHERE id = ?",
            (accessed_at, distribution_id),
        )


def evict_older_than(
    conn: sqlite3.Connection,
    cutoff_timestamp: int,
) -> tuple[int, list[str]]:
    """Delete distributions not accessed since *cutoff_timestamp*.

    `ON DELETE CASCADE` on the foreign keys automatically removes
    associated `dependencies` rows.

    Packages whose *all* distributions have been evicted are also removed.

    Returns a tuple of `(evicted_count, archive_paths)` where
    *archive_paths* is the list of `archive_path` values from the
    deleted rows.  The caller must perform dedup-safe file deletion
    (only unlink paths with no remaining DB references).
    """
    # Collect archive paths before deletion for dedup-safe cleanup
    rows = conn.execute(
        """\
        SELECT archive_path FROM distributions
        WHERE last_accessed_at < ? AND archive_path IS NOT NULL
        """,
        (cutoff_timestamp,),
    ).fetchall()
    stale_paths = [r["archive_path"] for r in rows]

    with conn:
        cursor = conn.execute(
            "DELETE FROM distributions WHERE last_accessed_at < ?",
            (cutoff_timestamp,),
        )
        evicted = cursor.rowcount

        # Clean up orphaned packages (no distributions left).
        conn.execute(
            """\
            DELETE FROM packages
            WHERE id NOT IN (SELECT DISTINCT package_id FROM distributions)
            """
        )

    return evicted, stale_paths


# ---------------------------------------------------------------------------
# Stats / diagnostics
# ---------------------------------------------------------------------------


def get_cache_stats(
    conn: sqlite3.Connection,
    cache_dir_path: str,
    *,
    limit_bytes: int | None = None,
) -> CacheStats:
    """Gather aggregate cache statistics for `cache info`.

    Parameters
    ----------
    limit_bytes:
        Configured cache size limit.  `None` means unlimited.
        Used to compute `usage_percent`.
    """
    pkg_count = conn.execute("SELECT COUNT(*) FROM packages").fetchone()[0]
    dist_count = conn.execute("SELECT COUNT(*) FROM distributions").fetchone()[0]

    # Count distinct physical files to avoid double-counting
    # deduplicated archives and metadata-only rows.
    size_row = conn.execute(
        """\
        SELECT COALESCE(SUM(size_bytes), 0) FROM (
            SELECT DISTINCT archive_path, size_bytes
            FROM distributions
            WHERE archive_path IS NOT NULL
        )
        """
    ).fetchone()
    total_size: int = size_row[0]

    # Archived vs metadata-only distribution counts
    archived_count: int = conn.execute(
        "SELECT COUNT(*) FROM distributions WHERE archive_path IS NOT NULL"
    ).fetchone()[0]
    metadata_only_count = dist_count - archived_count

    age_row = conn.execute(
        """\
        SELECT MIN(created_at) AS oldest, MAX(created_at) AS newest
        FROM distributions
        """
    ).fetchone()

    oldest = (
        datetime.fromtimestamp(age_row["oldest"], tz=timezone.utc)
        if age_row["oldest"]
        else None
    )
    newest = (
        datetime.fromtimestamp(age_row["newest"], tz=timezone.utc)
        if age_row["newest"]
        else None
    )

    usage_percent: float | None = None
    if limit_bytes is not None and limit_bytes > 0:
        usage_percent = (total_size / limit_bytes) * 100.0

    return CacheStats(
        location=Path(cache_dir_path),
        package_count=pkg_count,
        distribution_count=dist_count,
        total_size_bytes=total_size,
        archived_count=archived_count,
        metadata_only_count=metadata_only_count,
        limit_bytes=limit_bytes,
        usage_percent=usage_percent,
        oldest_entry=oldest,
        newest_entry=newest,
    )


def dump_all(conn: sqlite3.Connection) -> dict[str, Any]:
    """Export the full cache contents as a JSON-serialisable dict.

    Used by `peeq cache dump` for inspectability.
    """
    packages = [dict(r) for r in conn.execute("SELECT * FROM packages")]
    distributions = [dict(r) for r in conn.execute("SELECT * FROM distributions")]
    dependencies = [dict(r) for r in conn.execute("SELECT * FROM dependencies")]
    return {
        "packages": packages,
        "distributions": distributions,
        "dependencies": dependencies,
    }


def run_diagnostics(conn: sqlite3.Connection) -> dict[str, Any]:
    """Run PRAGMA verification and structural integrity checks.

    Used by `peeq cache check`.
    """
    journal_mode = conn.execute("PRAGMA journal_mode;").fetchone()[0]
    synchronous = conn.execute("PRAGMA synchronous;").fetchone()[0]
    foreign_keys = conn.execute("PRAGMA foreign_keys;").fetchone()[0]
    temp_store = conn.execute("PRAGMA temp_store;").fetchone()[0]

    size_row = conn.execute(
        """\
        SELECT page_count * page_size AS total_bytes, freelist_count
        FROM pragma_page_count(), pragma_page_size(), pragma_freelist_count()
        """
    ).fetchone()

    quick_check = conn.execute("PRAGMA quick_check;").fetchone()[0]

    return {
        "journal_mode": journal_mode,
        "synchronous": synchronous,
        "foreign_keys": foreign_keys,
        "temp_store": temp_store,
        "total_bytes": size_row["total_bytes"] if size_row else 0,
        "freelist_count": size_row["freelist_count"] if size_row else 0,
        "quick_check": quick_check,
    }


# ---------------------------------------------------------------------------
# Size-based LRU eviction
# ---------------------------------------------------------------------------


def get_archive_size(conn: sqlite3.Connection) -> int:
    """Return the total size of cached archive files in bytes.

    Counts each distinct `archive_path` only once (dedup-safe).
    Metadata-only rows (`archive_path IS NULL`) are excluded.
    """
    row = conn.execute(
        """\
        SELECT COALESCE(SUM(size_bytes), 0) FROM (
            SELECT DISTINCT archive_path, size_bytes
            FROM distributions
            WHERE archive_path IS NOT NULL
        )
        """
    ).fetchone()
    return row[0]


def select_lru_eviction_candidates(
    conn: sqlite3.Connection,
) -> list[dict[str, Any]]:
    """Return all distributions with archives, ordered LRU-first.

    Each row contains `id`, `archive_path`, and `size_bytes`.
    The caller iterates to determine how many to evict.
    """
    rows = conn.execute(
        """\
        SELECT id, archive_path, size_bytes
        FROM distributions
        WHERE archive_path IS NOT NULL
        ORDER BY last_accessed_at ASC
        """
    ).fetchall()
    return [dict(r) for r in rows]


def soft_evict_distributions(
    conn: sqlite3.Connection,
    distribution_ids: list[int],
) -> None:
    """Soft-evict distributions by nulling their archive references.

    The distribution row, metadata, and dependencies are preserved.
    Only `archive_path` and `size_bytes` are cleared.
    """
    if not distribution_ids:
        return
    placeholders = ",".join("?" * len(distribution_ids))
    with conn:
        conn.execute(
            f"""\
            UPDATE distributions
            SET archive_path = NULL, size_bytes = NULL
            WHERE id IN ({placeholders})
            """,  # noqa: S608 — parameterized via ? placeholders
            distribution_ids,
        )


def find_orphaned_archive_paths(
    conn: sqlite3.Connection,
    candidate_paths: list[str],
) -> list[str]:
    """Return paths from *candidate_paths* with no remaining DB references.

    Used after soft-eviction to determine which physical files can
    safely be deleted (dedup-safe: shared files are kept if any
    distribution still references them).
    """
    if not candidate_paths:
        return []

    referenced: set[str] = set()
    # Query in batches to avoid SQLite variable limit
    batch_size = 500
    for i in range(0, len(candidate_paths), batch_size):
        batch = candidate_paths[i : i + batch_size]
        placeholders = ",".join("?" * len(batch))
        rows = conn.execute(
            f"""\
            SELECT DISTINCT archive_path FROM distributions
            WHERE archive_path IN ({placeholders})
              AND archive_path IS NOT NULL
            """,  # noqa: S608 — parameterized via ? placeholders
            batch,
        ).fetchall()
        referenced.update(r["archive_path"] for r in rows)

    return [p for p in candidate_paths if p not in referenced]


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _row_to_dependency(row: sqlite3.Row) -> Dependency:
    """Convert a database row to a `Dependency` model."""
    extras_raw = row["extras"]
    extras: list[str] = json.loads(extras_raw) if extras_raw else []
    return Dependency(
        name=row["name"],
        specifier=row["specifier"],
        extras=extras,
        markers=row["markers"],
        raw=row["raw"],
    )


def _insert_dependencies(
    conn: sqlite3.Connection,
    distribution_id: int,
    dependencies: list[Dependency],
) -> None:
    """Batch-insert dependency rows."""
    conn.executemany(
        """\
        INSERT INTO dependencies
            (distribution_id, name, specifier, extras, markers, raw)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        [
            (
                distribution_id,
                dep.name,
                dep.specifier,
                json.dumps(dep.extras) if dep.extras else None,
                dep.markers,
                dep.raw,
            )
            for dep in dependencies
        ],
    )
