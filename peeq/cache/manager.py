"""Cache orchestration: database index + archive file storage.

The `CacheManager` coordinates the SQLite cache index (via the
`database` module) with tar.gz / .whl archive files stored on disk.  It is
the single entry point for all cache operations in peeq.

Directory layout::

    <cache_dir>/                         # Via platformdirs
    +-- cache.db                         # SQLite database
    +-- cache.db-wal                     # WAL file (transient, managed by SQLite)
    +-- cache.db-shm                     # Shared memory (transient)
    +-- archives/
        +-- pypi.org/
            +-- requests/
                +-- 2.31.0.tar.gz

Key design decisions:

- Archives are kept as compressed tar.gz/whl on disk, not unpacked.
- Files are extracted **in memory** on demand (see `extraction` module).
- SHA-256 is verified on every download entering the cache.
- Hash-based deduplication: same artifact from different sources shares one file.
- TTL-based invalidation for API data; schema-version-based for metadata.
"""

from __future__ import annotations

import hashlib
import logging
import os
import shutil
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any

from peeq.config import get_settings
from peeq.database import open_cache_db
from peeq.database import queries as db
from peeq.extraction import (
    ExtractionLimits,
    extract_all,
    extract_archive_to_disk,
    extract_file,
    list_archive,
)
from peeq.sanitize import sanitize_diagnostic, sanitize_filename

if TYPE_CHECKING:
    from peeq.extraction import ArchiveMember
    from peeq.models import (
        CacheStats,
        PackageMetadata,
    )

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_SHA256_BUF_SIZE: int = 256 * 1024  # 256 KB read chunks


# ---------------------------------------------------------------------------
# CacheManager
# ---------------------------------------------------------------------------


_EVICTION_WATERMARK: float = 0.80
"""Evict down to this fraction of the limit to avoid thrashing."""


class CacheManager:
    """Coordinates the SQLite cache index with on-disk archive storage.

    Constructed with a cache directory path.      Use `default` to get
    the platform-standard location via `platformdirs`.

    .. important::

        `CacheManager` does NOT hold a long-lived database connection.
        Each public method opens a connection via `open_cache_db` for
        the duration of the operation, then closes it.  This is intentional:
        peeq is a CLI tool where each invocation is short-lived, and
        holding connections across `await` points would block WAL
        checkpointing.
    """

    def __init__(self, cache_dir: Path) -> None:
        self._cache_dir = cache_dir
        self._archives_dir = cache_dir / "archives"
        self._dirty = False
        """Set when `store_archive` writes a new (non-deduplicated) file."""

    @classmethod
    def default(cls) -> CacheManager:
        """Create a `CacheManager` using the configured cache directory.

        Reads from `get_settings`.  Defaults to the
        platform-standard cache directory via `platformdirs`
        (Linux: `~/.cache/peeq`, macOS: `~/Library/Caches/peeq`,
        Windows: `%LOCALAPPDATA%\\peeq`).
        """
        return cls(get_settings().cache.dir)

    @property
    def cache_dir(self) -> Path:
        """Root directory for all cache data."""
        return self._cache_dir

    @property
    def archives_dir(self) -> Path:
        """Directory where archive files are stored."""
        return self._archives_dir

    # ------------------------------------------------------------------
    # Package-level operations (API data)
    # ------------------------------------------------------------------

    def get_package(
        self,
        registry: str,
        name: str,
    ) -> dict[str, Any] | None:
        """Look up cached API data for a package.

        Returns the raw row dict if the entry exists **and** its TTL has
        not expired, otherwise `None`.
        """
        with open_cache_db(self._cache_dir) as conn:
            row = db.get_package(conn, registry, name)

        if row is None:
            return None

        # Check TTL
        now = int(time.time())
        if row["fetched_at"] + row["ttl_seconds"] < now:
            return None  # Stale

        return row

    def upsert_package(  # noqa: PLR0913
        self,
        *,
        registry: str,
        name: str,
        latest_version: str | None = None,
        summary: str | None = None,
        available_versions: list[str] | None = None,
        version_count: int | None = None,
        legacy_metadata: str | None = None,
        ttl_seconds: int | None = None,
    ) -> int:
        """Insert or update API data for a package.  Returns the package ID.

        If *ttl_seconds* is `None`, the value from
        `get_settings` is used.
        """
        if ttl_seconds is None:
            ttl_seconds = get_settings().cache.api_ttl_seconds
        now = int(time.time())
        with open_cache_db(self._cache_dir) as conn:
            return db.upsert_package(
                conn,
                registry=registry,
                name=name,
                latest_version=latest_version,
                summary=summary,
                available_versions=available_versions,
                version_count=version_count,
                legacy_metadata=legacy_metadata,
                fetched_at=now,
                ttl_seconds=ttl_seconds,
            )

    # ------------------------------------------------------------------
    # Distribution-level operations (metadata + archives)
    # ------------------------------------------------------------------

    def get_metadata(
        self,
        registry: str,
        name: str,
        version: str,
    ) -> PackageMetadata | None:
        """Retrieve cached metadata for a specific distribution.

        Assembles the full `PackageMetadata` from the database (JSON blob
        + source column + dependencies table).  Returns `None` if not
        cached, or if the metadata schema version is outdated.
        """
        with open_cache_db(self._cache_dir) as conn:
            result = db.get_distribution_metadata(conn, registry, name, version)
            if result is not None:
                # Touch LRU timestamp
                db.touch_distribution(
                    conn,
                    result.distribution_id,
                    int(time.time()),
                )

        return result.metadata if result is not None else None

    def save_metadata(  # noqa: PLR0913
        self,
        *,
        registry: str,
        name: str,
        version: str,
        sha256: str,
        sha256_source: str = "registry",
        download_url: str | None = None,
        archive_path: str | None = None,
        size_bytes: int | None = None,
        metadata: PackageMetadata,
        deps_known: bool = True,
        filename: str | None = None,
        dynamic_fields: str | None = None,
    ) -> int:
        """Save metadata for a distribution.

        Creates the package row if needed, then upserts the distribution
        with split storage (JSON blob + source column + deps table).

        Returns the distribution ID.
        """
        now = int(time.time())
        with open_cache_db(self._cache_dir) as conn:
            pkg_id = db.ensure_package(
                conn,
                registry=registry,
                name=name,
            )
            return db.upsert_distribution(
                conn,
                package_id=pkg_id,
                version=version,
                sha256=sha256,
                sha256_source=sha256_source,
                filename=filename,
                download_url=sanitize_diagnostic(download_url, fallback="") if download_url else None,
                archive_path=archive_path,
                size_bytes=size_bytes,
                created_at=now,
                last_accessed_at=now,
                metadata=metadata,
                deps_known=deps_known,
                dynamic_fields=dynamic_fields,
            )

    def store_archive(  # noqa: PLR0913
        self,
        *,
        registry: str,
        name: str,
        version: str,
        archive_data: bytes,
        filename: str,
        expected_sha256: str | None = None,
        sha256_source: str = "registry",
        download_url: str | None = None,
        metadata: PackageMetadata | None = None,
        deps_known: bool = True,
    ) -> StoreResult:
        """Store a downloaded archive in the cache.

        Computes SHA-256, checks for hash-based deduplication, verifies
        against the expected hash (if provided), writes the file to disk,
        and updates the database.

        Parameters
        ----------
        archive_data:
            Raw bytes of the archive (tar.gz or .whl).
        filename:
            Filename to store as (e.g., `"requests-2.31.0.tar.gz"`).
        expected_sha256:
            SHA-256 hash from the registry.  If provided and the computed
            hash does not match, raises `HashMismatchError`.
        sha256_source:
            `"registry"` or `"computed"`.
        download_url:
            URL the archive was downloaded from.
        metadata:
            Optional metadata to store alongside the archive.
        deps_known:
            Whether the dependency list is known (see
            `peeq.database.queries`).

        Returns
        -------
        StoreResult
            Contains the SHA-256 hash, archive path, size, distribution ID,
            and whether deduplication was used.
        """
        # Compute SHA-256
        computed_hash = hashlib.sha256(archive_data).hexdigest()

        # Verify against expected hash
        if expected_sha256 is not None and computed_hash != expected_sha256:
            msg = f"SHA-256 mismatch for {filename}: expected {expected_sha256}, got {computed_hash}"
            raise HashMismatchError(msg)

        sha256 = expected_sha256 or computed_hash
        if expected_sha256 is None:
            sha256_source = "computed"

        # Check for deduplication
        with open_cache_db(self._cache_dir) as conn:
            existing = db.find_by_hash(conn, sha256)

        deduplicated = False
        rel_path = f"archives/{registry}/{name}/{sanitize_filename(filename)}"

        if existing and existing["archive_path"]:
            existing_abs = self._cache_dir / existing["archive_path"]
            if existing_abs.exists():
                # Reuse existing archive file path
                rel_path = existing["archive_path"]
                deduplicated = True
                logger.debug(
                    "Deduplicating %s — same hash as %s/%s",
                    filename,
                    existing["name"],
                    existing["version"],
                )

        if not deduplicated:
            # Write archive to disk using atomic write pattern:
            # write to a temp file in the same directory, then replace
            # to the final path.  This prevents two concurrent peeq
            # processes from interleaving writes to the same file.
            # Uses Path.replace() per CONTRIBUTING.md (cross-platform
            # atomic move, unlike Path.rename() which raises
            # FileExistsError on Windows).
            abs_path = self._cache_dir / rel_path
            abs_path.parent.mkdir(parents=True, exist_ok=True)
            tmp_path = abs_path.with_suffix(f"{abs_path.suffix}.{os.getpid()}.tmp")
            try:
                tmp_path.write_bytes(archive_data)
                tmp_path.replace(abs_path)
            except BaseException:
                tmp_path.unlink(missing_ok=True)
                raise
            self._dirty = True

        # Update database
        now = int(time.time())
        with open_cache_db(self._cache_dir) as conn:
            pkg_id = db.ensure_package(
                conn,
                registry=registry,
                name=name,
            )
            dist_id = db.upsert_distribution(
                conn,
                package_id=pkg_id,
                version=version,
                sha256=sha256,
                sha256_source=sha256_source,
                filename=filename,
                download_url=sanitize_diagnostic(download_url, fallback="") if download_url else None,
                archive_path=rel_path,
                size_bytes=len(archive_data),
                created_at=now,
                last_accessed_at=now,
                metadata=metadata,
                deps_known=deps_known,
            )

        return StoreResult(
            sha256=sha256,
            archive_path=rel_path,
            size_bytes=len(archive_data),
            distribution_id=dist_id,
            deduplicated=deduplicated,
        )

    def get_archive_path(
        self,
        registry: str,
        name: str,
        version: str,
    ) -> Path | None:
        """Get the absolute path to a cached archive file.

        Returns `None` if not cached or if the file is missing from disk.
        Updates the LRU timestamp on access.
        """
        with open_cache_db(self._cache_dir) as conn:
            row = conn.execute(
                """\
                SELECT d.id, d.archive_path
                FROM distributions d
                JOIN packages p ON d.package_id = p.id
                WHERE p.registry = ? AND p.name = ? AND d.version = ?
                  AND d.archive_path IS NOT NULL
                LIMIT 1
                """,
                (registry, name, version),
            ).fetchone()

            if row is None:
                return None

            abs_path = self._cache_dir / row["archive_path"]
            if not abs_path.exists():
                return None

            # Touch LRU
            db.touch_distribution(conn, row["id"], int(time.time()))

        return Path(abs_path)

    # ------------------------------------------------------------------
    # File extraction from cached archives
    # ------------------------------------------------------------------

    def extract_file(
        self,
        registry: str,
        name: str,
        version: str,
        member_path: str,
        *,
        limits: ExtractionLimits | None = None,
    ) -> bytes:
        """Extract a single file from a cached archive.

        Raises `ArchiveNotCachedError` if the archive is not in the
        cache.  Delegates to `extraction.extract_file` for the
        actual extraction.
        """
        archive = self.get_archive_path(registry, name, version)
        if archive is None:
            msg = f"No cached archive for {name}=={version} on {registry}"
            raise ArchiveNotCachedError(msg)

        return extract_file(archive, member_path, limits=limits)

    def list_archive(
        self,
        registry: str,
        name: str,
        version: str,
        *,
        limits: ExtractionLimits | None = None,
    ) -> list[ArchiveMember]:
        """List files in a cached archive.

        Returns a list of `ArchiveMember`
        objects.  Raises `ArchiveNotCachedError` if the archive is
        not in the cache.
        """
        archive = self.get_archive_path(registry, name, version)
        if archive is None:
            msg = f"No cached archive for {name}=={version} on {registry}"
            raise ArchiveNotCachedError(msg)

        return list_archive(archive, limits=limits)

    def extract_all(
        self,
        registry: str,
        name: str,
        version: str,
        *,
        limits: ExtractionLimits | None = None,
    ) -> dict[str, bytes]:
        """Extract all files from a cached archive into memory.

        Returns a dict mapping member paths to their uncompressed content.
        Raises `ArchiveNotCachedError` if the archive is not cached.
        """
        archive = self.get_archive_path(registry, name, version)
        if archive is None:
            msg = f"No cached archive for {name}=={version} on {registry}"
            raise ArchiveNotCachedError(msg)

        return extract_all(archive, limits=limits)

    def extract_to_disk(
        self,
        registry: str,
        name: str,
        version: str,
        dest: Path,
        *,
        limits: ExtractionLimits | None = None,
    ) -> list[Path]:
        """Extract a cached archive to disk (for `download --extract`).

        Uses PEP 706 safety on Python 3.12+, manual shim on 3.10/3.11.
        Raises `ArchiveNotCachedError` if the archive is not cached.
        """
        archive = self.get_archive_path(registry, name, version)
        if archive is None:
            msg = f"No cached archive for {name}=={version} on {registry}"
            raise ArchiveNotCachedError(msg)

        return extract_archive_to_disk(archive, dest, limits=limits)

    # ------------------------------------------------------------------
    # Dependency lookups
    # ------------------------------------------------------------------

    def find_dependents(self, dependency_name: str) -> list[dict[str, Any]]:
        """Find cached packages that depend on *dependency_name*."""
        with open_cache_db(self._cache_dir) as conn:
            return db.find_dependents(conn, dependency_name)

    def find_by_hash(self, sha256: str) -> dict[str, Any] | None:
        """Find a cached distribution by SHA-256 hash."""
        with open_cache_db(self._cache_dir) as conn:
            return db.find_by_hash(conn, sha256)

    # ------------------------------------------------------------------
    # Cache management commands
    # ------------------------------------------------------------------

    def get_stats(self) -> CacheStats:
        """Gather cache statistics for `cache info`."""
        max_size_mb = get_settings().cache.max_size_mb
        limit_bytes: int | None = max_size_mb * 1024 * 1024 if max_size_mb > 0 else None
        with open_cache_db(self._cache_dir) as conn:
            return db.get_cache_stats(conn, str(self._cache_dir), limit_bytes=limit_bytes)

    def clear(self, *, older_than_seconds: int | None = None) -> int:
        """Clear cached data.

        Parameters
        ----------
        older_than_seconds:
            If provided, evict only entries whose `last_accessed_at` is
            older than `now - older_than_seconds`.  Also deletes orphaned
            archive files.  If `None`, delete **everything** (DB + all
            archive files).

        Returns
        -------
        int
            Number of distributions evicted.
        """
        if older_than_seconds is None:
            return self._clear_all()
        return self._evict_older_than(older_than_seconds)

    def dump(self) -> dict[str, Any]:
        """Export the full cache index as a JSON-serialisable dict.

        Used by `peeq cache dump` for inspectability.
        """
        with open_cache_db(self._cache_dir) as conn:
            return db.dump_all(conn)

    def check(self) -> dict[str, Any]:
        """Run diagnostic checks on the cache database.

        Returns a dict of PRAGMA values and integrity check results.
        Used by `peeq cache check`.
        """
        with open_cache_db(self._cache_dir) as conn:
            return db.run_diagnostics(conn)

    # ------------------------------------------------------------------
    # SHA-256 verification
    # ------------------------------------------------------------------

    @staticmethod
    def compute_sha256(data: bytes) -> str:
        """Compute the SHA-256 hex digest of *data*."""
        return hashlib.sha256(data).hexdigest()

    @staticmethod
    def compute_sha256_file(path: Path) -> str:
        """Compute the SHA-256 hex digest of a file on disk."""
        h = hashlib.sha256()
        with path.open("rb") as f:
            while True:
                chunk = f.read(_SHA256_BUF_SIZE)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()

    def verify_archive(
        self,
        registry: str,
        name: str,
        version: str,
    ) -> bool:
        """Verify a cached archive's SHA-256 against the stored hash.

        Returns `True` if the hash matches, `False` if it does not
        or the archive is not cached.
        """
        with open_cache_db(self._cache_dir) as conn:
            row = conn.execute(
                """\
                SELECT d.sha256, d.archive_path
                FROM distributions d
                JOIN packages p ON d.package_id = p.id
                WHERE p.registry = ? AND p.name = ? AND d.version = ?
                  AND d.archive_path IS NOT NULL
                LIMIT 1
                """,
                (registry, name, version),
            ).fetchone()

        if row is None:
            return False

        abs_path = self._cache_dir / row["archive_path"]
        if not abs_path.exists():
            return False

        return self.compute_sha256_file(abs_path) == row["sha256"]

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _clear_all(self) -> int:
        """Delete the entire cache (database + archive files)."""
        evicted = 0

        # Count distributions before deleting
        with open_cache_db(self._cache_dir) as conn:
            row = conn.execute("SELECT COUNT(*) FROM distributions").fetchone()
            evicted = row[0] if row else 0

            # Drop all rows (CASCADE handles dependencies)
            with conn:
                conn.execute("DELETE FROM distributions")
                conn.execute("DELETE FROM packages")

        # Remove archive files
        if self._archives_dir.exists():
            shutil.rmtree(self._archives_dir, ignore_errors=True)

        return evicted

    def maybe_evict(self) -> None:
        """Evict least-recently-used archives if the cache exceeds its size limit.

        Called once per CLI invocation (from `_open_service`'s `finally`
        block) after all downloads are complete.  Skipped when no new
        archives were written (`_dirty` is `False`) or when the
        configured limit is `0` (unlimited).

        Archives are *soft-evicted*: the physical file is deleted but the
        distribution row, metadata, and dependencies are preserved.
        Commands that only need metadata (`deps`, `info`) continue to
        get instant cache hits.  Commands that need the archive trigger a
        transparent re-download.
        """
        if not self._dirty:
            return

        max_size_mb = get_settings().cache.max_size_mb
        if max_size_mb <= 0:
            return

        max_bytes = max_size_mb * 1024 * 1024

        with open_cache_db(self._cache_dir) as conn:
            current_size = db.get_archive_size(conn)
            if current_size <= max_bytes:
                return

            target_bytes = int(max_bytes * _EVICTION_WATERMARK)

            # Select LRU candidates
            candidates = db.select_lru_eviction_candidates(conn)

            to_evict_ids: list[int] = []
            evicted_paths: list[str] = []
            freed = 0

            for row in candidates:
                if current_size - freed <= target_bytes:
                    break
                to_evict_ids.append(row["id"])
                if row["archive_path"]:
                    evicted_paths.append(row["archive_path"])
                freed += row["size_bytes"] or 0

            if not to_evict_ids:
                if current_size > max_bytes:
                    logger.warning(
                        "Cache (%d MB) exceeds limit (%d MB) but no archives available for eviction.",
                        current_size // (1024 * 1024),
                        max_size_mb,
                    )
                return

            # Soft-evict: NULL out archive references, keep metadata
            db.soft_evict_distributions(conn, to_evict_ids)

            # Dedup-safe: only delete files with no remaining references
            orphaned = db.find_orphaned_archive_paths(conn, evicted_paths)

        # Delete files outside the connection context
        self._delete_archive_files(orphaned)

        freed_mb = freed / (1024 * 1024)
        current_mb = current_size / (1024 * 1024)
        logger.info(
            "Cache limit exceeded (%.1f MB / %d MB). Evicted %d archives, freed %.1f MB.",
            current_mb,
            max_size_mb,
            len(to_evict_ids),
            freed_mb,
        )

    def _evict_older_than(self, older_than_seconds: int) -> int:
        """Evict entries older than *older_than_seconds* (hard delete)."""
        cutoff = int(time.time()) - older_than_seconds

        with open_cache_db(self._cache_dir) as conn:
            evicted, stale_paths = db.evict_older_than(conn, cutoff)
            # Dedup-safe: only unlink files with no remaining references
            orphaned = db.find_orphaned_archive_paths(conn, stale_paths)

        self._delete_archive_files(orphaned)
        return evicted

    def _delete_archive_files(self, rel_paths: list[str]) -> None:
        """Delete archive files from disk and prune empty directories.

        Shared by both size-based soft eviction and age-based hard eviction.
        """
        for rel_path in rel_paths:
            abs_path = self._cache_dir / rel_path
            abs_path.unlink(missing_ok=True)
            self._cleanup_empty_dirs(abs_path.parent)

    def _cleanup_empty_dirs(self, directory: Path) -> None:
        """Remove empty directories up to (but not including) archives_dir."""
        current = directory
        archives_resolved = self._archives_dir.resolve()
        while current.resolve() != archives_resolved and current != current.parent:
            try:
                current.rmdir()  # Only succeeds if empty
            except OSError:
                break
            current = current.parent


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------


class StoreResult:
    """Result of storing an archive in the cache."""

    __slots__ = (
        "archive_path",
        "deduplicated",
        "distribution_id",
        "sha256",
        "size_bytes",
    )

    def __init__(
        self,
        *,
        sha256: str,
        archive_path: str,
        size_bytes: int,
        distribution_id: int,
        deduplicated: bool,
    ) -> None:
        self.sha256 = sha256
        self.archive_path = archive_path
        self.size_bytes = size_bytes
        self.distribution_id = distribution_id
        self.deduplicated = deduplicated


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class HashMismatchError(Exception):
    """SHA-256 verification failed for a downloaded archive."""


class ArchiveNotCachedError(Exception):
    """The requested archive is not in the cache."""
