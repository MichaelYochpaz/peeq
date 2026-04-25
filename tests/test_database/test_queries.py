"""Tests for database query functions."""

from __future__ import annotations

import pytest

from peeq.database.connection import open_cache_db
from peeq.database.queries import (
    dump_all,
    evict_older_than,
    find_by_hash,
    find_dependents,
    find_orphaned_archive_paths,
    get_archive_size,
    get_cache_stats,
    get_dependencies,
    get_distribution_metadata,
    get_package,
    run_diagnostics,
    select_lru_eviction_candidates,
    soft_evict_distributions,
    touch_distribution,
    upsert_dependencies,
    upsert_distribution,
    upsert_package,
)
from peeq.database.schema import CURRENT_METADATA_SCHEMA_VERSION
from peeq.models import Dependency, PackageMetadata


@pytest.fixture
def db(tmp_path):
    """Yield an open database connection for each test."""
    with open_cache_db(tmp_path) as conn:
        yield conn


@pytest.fixture
def sample_package_id(db):
    """Insert a sample package and return its id."""
    return upsert_package(
        db,
        registry="pypi.org",
        name="requests",
        latest_version="2.31.0",
        summary="HTTP for Humans",
        available_versions=["2.31.0", "2.30.0", "2.29.0"],
        fetched_at=1000,
    )


# ---------------------------------------------------------------------------
# packages table
# ---------------------------------------------------------------------------


class TestPackageQueries:
    def test_upsert_and_get(self, db):
        pkg_id = upsert_package(
            db,
            registry="pypi.org",
            name="requests",
            latest_version="2.31.0",
            fetched_at=1000,
        )
        assert pkg_id > 0

        row = get_package(db, "pypi.org", "requests")
        assert row is not None
        assert row["name"] == "requests"
        assert row["latest_version"] == "2.31.0"

    def test_get_missing_returns_none(self, db):
        assert get_package(db, "pypi.org", "nonexistent") is None

    def test_upsert_updates_existing(self, db):
        upsert_package(
            db,
            registry="pypi.org",
            name="requests",
            latest_version="2.30.0",
            fetched_at=1000,
        )
        upsert_package(
            db,
            registry="pypi.org",
            name="requests",
            latest_version="2.31.0",
            fetched_at=2000,
        )
        row = get_package(db, "pypi.org", "requests")
        assert row is not None
        assert row["latest_version"] == "2.31.0"
        assert row["fetched_at"] == 2000

    def test_different_registries(self, db):
        upsert_package(db, registry="pypi.org", name="pkg", fetched_at=1000)
        upsert_package(db, registry="internal.corp", name="pkg", fetched_at=1000)
        assert get_package(db, "pypi.org", "pkg") is not None
        assert get_package(db, "internal.corp", "pkg") is not None


# ---------------------------------------------------------------------------
# distributions + metadata assembly
# ---------------------------------------------------------------------------


class TestDistributionQueries:
    def test_upsert_and_get_metadata(self, db, sample_package_id):
        metadata = PackageMetadata(
            dependencies=[
                Dependency.from_requirement_string("urllib3>=1.21.1,<3"),
                Dependency.from_requirement_string("certifi>=2017.4.17"),
            ],
            python_requires=">=3.8",
            license="Apache-2.0",
            summary="HTTP for Humans",
            source="pep658",
        )
        upsert_distribution(
            db,
            package_id=sample_package_id,
            version="2.31.0",
            sha256="abc123",
            created_at=1000,
            last_accessed_at=1000,
            metadata=metadata,
        )

        result = get_distribution_metadata(db, "pypi.org", "requests", "2.31.0")
        assert result is not None
        assert result.distribution_id > 0
        assert result.metadata.python_requires == ">=3.8"
        assert result.metadata.license == "Apache-2.0"
        assert result.metadata.source == "pep658"
        assert result.metadata.dependencies is not None
        assert len(result.metadata.dependencies) == 2
        assert result.metadata.dependencies[0].name == "urllib3"

    def test_missing_returns_none(self, db):
        result = get_distribution_metadata(db, "pypi.org", "nonexistent", "1.0.0")
        assert result is None

    def test_deps_known_false(self, db, sample_package_id):
        """When deps_known=FALSE, dependencies should be None."""
        metadata = PackageMetadata(
            python_requires=">=3.7",
            source="sdist",
        )
        upsert_distribution(
            db,
            package_id=sample_package_id,
            version="2.31.0",
            sha256="abc123",
            created_at=1000,
            last_accessed_at=1000,
            metadata=metadata,
            deps_known=False,
        )

        result = get_distribution_metadata(db, "pypi.org", "requests", "2.31.0")
        assert result is not None
        assert result.metadata.dependencies is None

    def test_deps_known_true_empty(self, db, sample_package_id):
        """When deps_known=TRUE and no dep rows, dependencies should be []."""
        metadata = PackageMetadata(
            dependencies=[],
            python_requires=">=3.7",
            source="wheel",
        )
        upsert_distribution(
            db,
            package_id=sample_package_id,
            version="2.31.0",
            sha256="abc123",
            created_at=1000,
            last_accessed_at=1000,
            metadata=metadata,
            deps_known=True,
        )

        result = get_distribution_metadata(db, "pypi.org", "requests", "2.31.0")
        assert result is not None
        assert result.metadata.dependencies == []

    def test_upsert_replaces_dependencies(self, db, sample_package_id):
        """Upserting a distribution replaces all dependency rows."""
        meta1 = PackageMetadata(
            dependencies=[
                Dependency.from_requirement_string("numpy>=1.0"),
            ],
            source="wheel",
        )
        upsert_distribution(
            db,
            package_id=sample_package_id,
            version="1.0.0",
            sha256="hash1",
            created_at=1000,
            last_accessed_at=1000,
            metadata=meta1,
        )

        # Upsert with different deps
        meta2 = PackageMetadata(
            dependencies=[
                Dependency.from_requirement_string("pandas>=2.0"),
                Dependency.from_requirement_string("scipy"),
            ],
            source="pep658",
        )
        upsert_distribution(
            db,
            package_id=sample_package_id,
            version="1.0.0",
            sha256="hash1",
            created_at=1000,
            last_accessed_at=2000,
            metadata=meta2,
        )

        result = get_distribution_metadata(db, "pypi.org", "requests", "1.0.0")
        assert result is not None
        assert result.metadata.dependencies is not None
        assert len(result.metadata.dependencies) == 2
        dep_names = {d.name for d in result.metadata.dependencies}
        assert dep_names == {"pandas", "scipy"}

    def test_archive_only_upsert_preserves_existing_metadata(
        self, db, sample_package_id
    ):
        metadata = PackageMetadata(
            dependencies=[
                Dependency.from_requirement_string("urllib3>=1.21.1,<3"),
            ],
            summary="HTTP for Humans",
            source="pep658",
        )
        upsert_distribution(
            db,
            package_id=sample_package_id,
            version="2.31.0",
            sha256="abc123",
            created_at=1000,
            last_accessed_at=1000,
            metadata=metadata,
            dynamic_fields='["requires_dist"]',
        )

        upsert_distribution(
            db,
            package_id=sample_package_id,
            version="2.31.0",
            sha256="abc123",
            archive_path="archives/pypi.org/requests/requests-2.31.0.whl",
            filename="requests-2.31.0-py3-none-any.whl",
            created_at=1000,
            last_accessed_at=2000,
        )

        result = get_distribution_metadata(db, "pypi.org", "requests", "2.31.0")
        assert result is not None
        assert result.metadata.summary == "HTTP for Humans"
        assert result.metadata.source == "pep658"
        assert result.metadata.dynamic_fields == ["requires_dist"]
        assert result.metadata.dependencies is not None
        assert [dep.name for dep in result.metadata.dependencies] == ["urllib3"]


# ---------------------------------------------------------------------------
# dependency extras / markers round-trip
# ---------------------------------------------------------------------------


class TestDependencyRoundTrip:
    def test_extras_preserved(self, db, sample_package_id):
        metadata = PackageMetadata(
            dependencies=[
                Dependency.from_requirement_string("httpx[http2]>=0.28"),
            ],
            source="wheel",
        )
        upsert_distribution(
            db,
            package_id=sample_package_id,
            version="1.0.0",
            sha256="hash",
            created_at=1000,
            last_accessed_at=1000,
            metadata=metadata,
        )

        result = get_distribution_metadata(db, "pypi.org", "requests", "1.0.0")
        assert result is not None
        assert result.metadata.dependencies is not None
        assert result.metadata.dependencies[0].extras == ["http2"]

    def test_markers_preserved(self, db, sample_package_id):
        metadata = PackageMetadata(
            dependencies=[
                Dependency.from_requirement_string('PySocks>=1.5.6; extra == "socks"'),
            ],
            source="wheel",
        )
        upsert_distribution(
            db,
            package_id=sample_package_id,
            version="1.0.0",
            sha256="hash",
            created_at=1000,
            last_accessed_at=1000,
            metadata=metadata,
        )

        result = get_distribution_metadata(db, "pypi.org", "requests", "1.0.0")
        assert result is not None
        assert result.metadata.dependencies is not None
        assert result.metadata.dependencies[0].markers == 'extra == "socks"'
        assert result.metadata.dependencies[0].name == "pysocks"


# ---------------------------------------------------------------------------
# dependencies table CRUD
# ---------------------------------------------------------------------------


class TestDependencyCrud:
    def test_get_and_upsert(self, db, sample_package_id):
        dist_id = upsert_distribution(
            db,
            package_id=sample_package_id,
            version="1.0.0",
            sha256="hash",
            created_at=1000,
            last_accessed_at=1000,
        )

        deps = [
            Dependency.from_requirement_string("numpy>=1.21"),
            Dependency.from_requirement_string("pandas"),
        ]
        upsert_dependencies(db, dist_id, deps)

        result = get_dependencies(db, dist_id)
        assert len(result) == 2

    def test_upsert_replaces(self, db, sample_package_id):
        dist_id = upsert_distribution(
            db,
            package_id=sample_package_id,
            version="1.0.0",
            sha256="hash",
            created_at=1000,
            last_accessed_at=1000,
        )

        upsert_dependencies(db, dist_id, [Dependency.from_requirement_string("numpy")])
        upsert_dependencies(db, dist_id, [Dependency.from_requirement_string("pandas")])

        result = get_dependencies(db, dist_id)
        assert len(result) == 1
        assert result[0].name == "pandas"


# ---------------------------------------------------------------------------
# find_dependents (reverse lookup)
# ---------------------------------------------------------------------------


class TestFindDependents:
    def test_find_dependents(self, db):
        pkg1 = upsert_package(db, registry="pypi.org", name="flask", fetched_at=1000)
        pkg2 = upsert_package(db, registry="pypi.org", name="django", fetched_at=1000)

        upsert_distribution(
            db,
            package_id=pkg1,
            version="3.0.0",
            sha256="h1",
            created_at=1000,
            last_accessed_at=1000,
            metadata=PackageMetadata(
                dependencies=[
                    Dependency.from_requirement_string("jinja2>=3.0"),
                ],
                source="wheel",
            ),
        )
        upsert_distribution(
            db,
            package_id=pkg2,
            version="5.0.0",
            sha256="h2",
            created_at=1000,
            last_accessed_at=1000,
            metadata=PackageMetadata(
                dependencies=[
                    Dependency.from_requirement_string("jinja2>=2.0"),
                ],
                source="wheel",
            ),
        )

        dependents = find_dependents(db, "jinja2")
        assert len(dependents) == 2
        names = {d["name"] for d in dependents}
        assert names == {"flask", "django"}

    def test_no_dependents(self, db):
        assert find_dependents(db, "nonexistent") == []

    def test_find_dependents_deduplicates_versions(self, db):
        pkg = upsert_package(db, registry="pypi.org", name="flask", fetched_at=1000)

        for sha256, source in (("h1", "pep658"), ("h2", "wheel")):
            upsert_distribution(
                db,
                package_id=pkg,
                version="3.0.0",
                sha256=sha256,
                created_at=1000,
                last_accessed_at=1000,
                metadata=PackageMetadata(
                    dependencies=[
                        Dependency.from_requirement_string("jinja2>=3.0"),
                    ],
                    source=source,
                ),
            )

        dependents = find_dependents(db, "jinja2")
        assert dependents == [
            {"name": "flask", "version": "3.0.0", "specifier": ">=3.0"}
        ]


# ---------------------------------------------------------------------------
# find_by_hash
# ---------------------------------------------------------------------------


class TestFindByHash:
    def test_find_existing(self, db, sample_package_id):
        upsert_distribution(
            db,
            package_id=sample_package_id,
            version="2.31.0",
            sha256="deadbeef",
            archive_path="pypi.org/requests/2.31.0.tar.gz",
            created_at=1000,
            last_accessed_at=1000,
        )

        result = find_by_hash(db, "deadbeef")
        assert result is not None
        assert result["archive_path"] == "pypi.org/requests/2.31.0.tar.gz"
        assert result["name"] == "requests"

    def test_not_found(self, db):
        assert find_by_hash(db, "nonexistent") is None


# ---------------------------------------------------------------------------
# LRU / maintenance
# ---------------------------------------------------------------------------


class TestLruMaintenance:
    def test_touch_distribution(self, db, sample_package_id):
        dist_id = upsert_distribution(
            db,
            package_id=sample_package_id,
            version="1.0.0",
            sha256="hash",
            created_at=1000,
            last_accessed_at=1000,
        )
        touch_distribution(db, dist_id, 9999)

        row = db.execute(
            "SELECT last_accessed_at FROM distributions WHERE id = ?",
            (dist_id,),
        ).fetchone()
        assert row["last_accessed_at"] == 9999

    def test_evict_older_than(self, db, sample_package_id):
        upsert_distribution(
            db,
            package_id=sample_package_id,
            version="1.0.0",
            sha256="h1",
            created_at=1000,
            last_accessed_at=500,  # old
        )
        upsert_distribution(
            db,
            package_id=sample_package_id,
            version="2.0.0",
            sha256="h2",
            created_at=1000,
            last_accessed_at=2000,  # recent
        )

        evicted, stale_paths = evict_older_than(db, 1000)
        assert evicted == 1
        assert stale_paths == []  # no archive_path set on these rows

        # Only the recent one should remain
        count = db.execute("SELECT COUNT(*) FROM distributions").fetchone()[0]
        assert count == 1

    def test_evict_cascades_dependencies(self, db, sample_package_id):
        """Dependencies are cleaned up via ON DELETE CASCADE."""
        metadata = PackageMetadata(
            dependencies=[
                Dependency.from_requirement_string("numpy"),
            ],
            source="wheel",
        )
        upsert_distribution(
            db,
            package_id=sample_package_id,
            version="1.0.0",
            sha256="hash",
            created_at=1000,
            last_accessed_at=500,
            metadata=metadata,
        )

        dep_count_before = db.execute("SELECT COUNT(*) FROM dependencies").fetchone()[0]
        assert dep_count_before == 1

        evict_older_than(db, 1000)

        dep_count_after = db.execute("SELECT COUNT(*) FROM dependencies").fetchone()[0]
        assert dep_count_after == 0

    def test_evict_removes_orphaned_packages(self, db):
        """Packages with no distributions left are cleaned up."""
        pkg_id = upsert_package(
            db, registry="pypi.org", name="orphan-pkg", fetched_at=1000
        )
        upsert_distribution(
            db,
            package_id=pkg_id,
            version="1.0.0",
            sha256="hash",
            created_at=1000,
            last_accessed_at=500,
        )

        evict_older_than(db, 1000)

        pkg = get_package(db, "pypi.org", "orphan-pkg")
        assert pkg is None


# ---------------------------------------------------------------------------
# Stats / diagnostics
# ---------------------------------------------------------------------------


class TestStatsAndDiagnostics:
    def test_cache_stats_empty(self, db, tmp_path):
        stats = get_cache_stats(db, str(tmp_path))
        assert stats.package_count == 0
        assert stats.distribution_count == 0
        assert stats.total_size_bytes == 0
        assert stats.oldest_entry is None
        assert stats.newest_entry is None

    def test_cache_stats_with_data(self, db, tmp_path, sample_package_id):
        upsert_distribution(
            db,
            package_id=sample_package_id,
            version="1.0.0",
            sha256="h1",
            archive_path="archives/pypi.org/pkg/pkg-1.0.0.tar.gz",
            size_bytes=5000,
            created_at=1000,
            last_accessed_at=1000,
        )
        upsert_distribution(
            db,
            package_id=sample_package_id,
            version="2.0.0",
            sha256="h2",
            archive_path="archives/pypi.org/pkg/pkg-2.0.0.tar.gz",
            size_bytes=8000,
            created_at=2000,
            last_accessed_at=2000,
        )

        stats = get_cache_stats(db, str(tmp_path))
        assert stats.package_count == 1
        assert stats.distribution_count == 2
        assert stats.total_size_bytes == 13000
        assert stats.archived_count == 2
        assert stats.metadata_only_count == 0
        assert stats.oldest_entry is not None
        assert stats.newest_entry is not None

    def test_dump_all(self, db, sample_package_id):
        upsert_distribution(
            db,
            package_id=sample_package_id,
            version="1.0.0",
            sha256="hash",
            created_at=1000,
            last_accessed_at=1000,
            metadata=PackageMetadata(
                dependencies=[
                    Dependency.from_requirement_string("numpy"),
                ],
                source="wheel",
            ),
        )

        data = dump_all(db)
        assert len(data["packages"]) == 1
        assert len(data["distributions"]) == 1
        assert len(data["dependencies"]) == 1

    def test_run_diagnostics(self, db):
        diag = run_diagnostics(db)
        assert diag["journal_mode"] == "wal"
        assert diag["synchronous"] == 1
        assert diag["foreign_keys"] == 1
        assert diag["temp_store"] == 2
        assert diag["quick_check"] == "ok"
        assert diag["total_bytes"] >= 0


# ---------------------------------------------------------------------------
# Metadata schema version staleness
# ---------------------------------------------------------------------------


class TestMetadataSchemaVersion:
    def test_stale_schema_version_returns_none(self, db, sample_package_id):
        """Return None when metadata_schema_version is outdated."""
        metadata = PackageMetadata(
            summary="HTTP for Humans",
            source="wheel",
        )
        dist_id = upsert_distribution(
            db,
            package_id=sample_package_id,
            version="2.31.0",
            sha256="abc123",
            created_at=1000,
            last_accessed_at=1000,
            metadata=metadata,
        )

        # Manually set an outdated schema version
        with db:
            db.execute(
                "UPDATE distributions SET metadata_schema_version = ? WHERE id = ?",
                (CURRENT_METADATA_SCHEMA_VERSION - 1, dist_id),
            )

        result = get_distribution_metadata(db, "pypi.org", "requests", "2.31.0")
        assert result is None


# ---------------------------------------------------------------------------
# Size-based LRU eviction queries
# ---------------------------------------------------------------------------


class TestEvictionQueries:
    def test_soft_evict_nulls_archive_path(self, db, sample_package_id):
        """Null archive_path and size_bytes while preserving metadata."""
        dist_id = upsert_distribution(
            db,
            package_id=sample_package_id,
            version="1.0.0",
            sha256="h1",
            archive_path="archives/pypi.org/requests/r-1.0.0.tar.gz",
            size_bytes=5000,
            created_at=1000,
            last_accessed_at=1000,
            metadata=PackageMetadata(summary="test", source="wheel"),
        )

        soft_evict_distributions(db, [dist_id])

        row = db.execute(
            "SELECT archive_path, size_bytes, metadata FROM distributions WHERE id = ?",
            (dist_id,),
        ).fetchone()
        assert row["archive_path"] is None
        assert row["size_bytes"] is None
        assert row["metadata"] is not None

    def test_soft_evict_preserves_unaffected(self, db, sample_package_id):
        """Leave non-targeted distributions unchanged."""
        dist1 = upsert_distribution(
            db,
            package_id=sample_package_id,
            version="1.0.0",
            sha256="h1",
            archive_path="archives/r-1.0.0.tar.gz",
            size_bytes=5000,
            created_at=1000,
            last_accessed_at=1000,
        )
        dist2 = upsert_distribution(
            db,
            package_id=sample_package_id,
            version="2.0.0",
            sha256="h2",
            archive_path="archives/r-2.0.0.tar.gz",
            size_bytes=8000,
            created_at=1000,
            last_accessed_at=2000,
        )

        soft_evict_distributions(db, [dist1])

        row = db.execute(
            "SELECT archive_path, size_bytes FROM distributions WHERE id = ?",
            (dist2,),
        ).fetchone()
        assert row["archive_path"] == "archives/r-2.0.0.tar.gz"
        assert row["size_bytes"] == 8000

    def test_soft_evict_empty_list_is_noop(self, db):
        """Accept an empty list without error."""
        soft_evict_distributions(db, [])

    def test_find_orphaned_no_references(self, db, sample_package_id):
        """Return paths that have no remaining DB references."""
        dist_id = upsert_distribution(
            db,
            package_id=sample_package_id,
            version="1.0.0",
            sha256="h1",
            archive_path="archives/r-1.0.0.tar.gz",
            size_bytes=5000,
            created_at=1000,
            last_accessed_at=1000,
        )

        soft_evict_distributions(db, [dist_id])

        orphaned = find_orphaned_archive_paths(db, ["archives/r-1.0.0.tar.gz"])
        assert orphaned == ["archives/r-1.0.0.tar.gz"]

    def test_find_orphaned_excludes_still_referenced(self, db):
        """Keep paths that are still referenced by another distribution."""
        pkg1 = upsert_package(db, registry="pypi.org", name="pkg-a", fetched_at=1000)
        pkg2 = upsert_package(db, registry="pypi.org", name="pkg-b", fetched_at=1000)

        dist1 = upsert_distribution(
            db,
            package_id=pkg1,
            version="1.0.0",
            sha256="same-hash",
            archive_path="archives/shared.tar.gz",
            size_bytes=5000,
            created_at=1000,
            last_accessed_at=1000,
        )
        upsert_distribution(
            db,
            package_id=pkg2,
            version="1.0.0",
            sha256="same-hash",
            archive_path="archives/shared.tar.gz",
            size_bytes=5000,
            created_at=1000,
            last_accessed_at=2000,
        )

        soft_evict_distributions(db, [dist1])

        orphaned = find_orphaned_archive_paths(db, ["archives/shared.tar.gz"])
        assert orphaned == []

    def test_find_orphaned_empty_list(self, db):
        """Return empty list for empty candidate list."""
        assert find_orphaned_archive_paths(db, []) == []

    def test_select_lru_candidates_ordered(self, db, sample_package_id):
        """Return candidates ordered by last_accessed_at ascending."""
        upsert_distribution(
            db,
            package_id=sample_package_id,
            version="3.0.0",
            sha256="h3",
            archive_path="archives/r-3.0.0.tar.gz",
            size_bytes=3000,
            created_at=1000,
            last_accessed_at=3000,
        )
        upsert_distribution(
            db,
            package_id=sample_package_id,
            version="1.0.0",
            sha256="h1",
            archive_path="archives/r-1.0.0.tar.gz",
            size_bytes=1000,
            created_at=1000,
            last_accessed_at=1000,
        )
        upsert_distribution(
            db,
            package_id=sample_package_id,
            version="2.0.0",
            sha256="h2",
            archive_path="archives/r-2.0.0.tar.gz",
            size_bytes=2000,
            created_at=1000,
            last_accessed_at=2000,
        )

        candidates = select_lru_eviction_candidates(db)
        assert len(candidates) == 3
        assert candidates[0]["archive_path"] == "archives/r-1.0.0.tar.gz"
        assert candidates[1]["archive_path"] == "archives/r-2.0.0.tar.gz"
        assert candidates[2]["archive_path"] == "archives/r-3.0.0.tar.gz"

    def test_select_lru_candidates_excludes_metadata_only(self, db, sample_package_id):
        """Exclude metadata-only distributions (no archive_path)."""
        upsert_distribution(
            db,
            package_id=sample_package_id,
            version="1.0.0",
            sha256="h1",
            archive_path="archives/r-1.0.0.tar.gz",
            size_bytes=1000,
            created_at=1000,
            last_accessed_at=1000,
        )
        upsert_distribution(
            db,
            package_id=sample_package_id,
            version="2.0.0",
            sha256="h2",
            created_at=1000,
            last_accessed_at=500,
            metadata=PackageMetadata(summary="cached", source="pep658"),
        )

        candidates = select_lru_eviction_candidates(db)
        assert len(candidates) == 1
        assert candidates[0]["archive_path"] == "archives/r-1.0.0.tar.gz"

    def test_get_archive_size_dedup(self, db, sample_package_id):
        """Count each distinct archive_path only once."""
        upsert_distribution(
            db,
            package_id=sample_package_id,
            version="1.0.0",
            sha256="h1",
            archive_path="archives/shared.tar.gz",
            size_bytes=5000,
            created_at=1000,
            last_accessed_at=1000,
        )
        upsert_distribution(
            db,
            package_id=sample_package_id,
            version="2.0.0",
            sha256="h2",
            archive_path="archives/shared.tar.gz",
            size_bytes=5000,
            created_at=1000,
            last_accessed_at=2000,
        )
        upsert_distribution(
            db,
            package_id=sample_package_id,
            version="3.0.0",
            sha256="h3",
            archive_path="archives/other.tar.gz",
            size_bytes=8000,
            created_at=1000,
            last_accessed_at=3000,
        )

        total = get_archive_size(db)
        assert total == 13000

    def test_get_archive_size_empty(self, db):
        """Return 0 when no archives exist."""
        assert get_archive_size(db) == 0

    def test_get_archive_size_excludes_metadata_only(self, db, sample_package_id):
        """Exclude metadata-only distributions (no archive_path)."""
        upsert_distribution(
            db,
            package_id=sample_package_id,
            version="1.0.0",
            sha256="h1",
            created_at=1000,
            last_accessed_at=1000,
            metadata=PackageMetadata(summary="cached", source="pep658"),
        )

        assert get_archive_size(db) == 0
