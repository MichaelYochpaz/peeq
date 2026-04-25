"""Tests for peeq.cache.manager — CacheManager."""

from __future__ import annotations

import hashlib
import io
import tarfile
import zipfile
from pathlib import Path
from unittest.mock import patch

import pytest

from peeq.cache.manager import (
    ArchiveNotCachedError,
    CacheManager,
    HashMismatchError,
    StoreResult,
)
from peeq.models import Dependency, PackageMetadata
from peeq.sanitize import UnsafeFilenameError

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_tar_gz_bytes(files: dict[str, bytes]) -> bytes:
    """Create a tar.gz archive in memory and return raw bytes."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, data in files.items():
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def _make_zip_bytes(files: dict[str, bytes]) -> bytes:
    """Create a .whl (zip) archive in memory and return raw bytes."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in files.items():
            zf.writestr(name, data)
    return buf.getvalue()


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def cache_dir(tmp_path: Path) -> Path:
    """Isolated cache directory for each test."""
    return tmp_path / "cache"


@pytest.fixture
def manager(cache_dir: Path) -> CacheManager:
    """CacheManager using an isolated temp directory."""
    return CacheManager(cache_dir)


@pytest.fixture
def sample_archive() -> bytes:
    """A minimal tar.gz archive with two files."""
    return _make_tar_gz_bytes(
        {
            "pkg-1.0.0/README.md": b"# Test Package",
            "pkg-1.0.0/setup.py": b"from setuptools import setup; setup()",
        }
    )


@pytest.fixture
def sample_whl() -> bytes:
    """A minimal .whl (zip) archive."""
    return _make_zip_bytes(
        {
            "pkg/__init__.py": b"",
            "pkg-1.0.0.dist-info/METADATA": b"Name: pkg\nVersion: 1.0.0",
        }
    )


# ---------------------------------------------------------------------------
# Construction
# ---------------------------------------------------------------------------


class TestConstruction:
    def test_cache_dir(self, manager: CacheManager, cache_dir: Path) -> None:
        assert manager.cache_dir == cache_dir

    def test_archives_dir(self, manager: CacheManager, cache_dir: Path) -> None:
        assert manager.archives_dir == cache_dir / "archives"

    def test_default_uses_platformdirs(self) -> None:
        """CacheManager.default() returns a manager with a real path."""
        cm = CacheManager.default()
        # platformdirs may add platform-specific suffixes (e.g., "Cache"
        # on Windows), but "peeq" must appear in the path.
        assert "peeq" in str(cm.cache_dir)


# ---------------------------------------------------------------------------
# Package-level operations (API data)
# ---------------------------------------------------------------------------


class TestPackageOps:
    def test_upsert_and_get(self, manager: CacheManager) -> None:
        pkg_id = manager.upsert_package(
            registry="pypi.org",
            name="requests",
            latest_version="2.31.0",
            summary="HTTP library",
            available_versions=["2.31.0", "2.30.0"],
        )
        assert pkg_id > 0

        row = manager.get_package("pypi.org", "requests")
        assert row is not None
        assert row["name"] == "requests"
        assert row["latest_version"] == "2.31.0"
        assert row["summary"] == "HTTP library"

    def test_get_nonexistent(self, manager: CacheManager) -> None:
        assert manager.get_package("pypi.org", "nonexistent") is None

    def test_ttl_expiry(self, manager: CacheManager) -> None:
        """Expired entries return None."""
        base_time = 1_700_000_000
        with patch("peeq.cache.manager.time") as mock_time:
            mock_time.time.return_value = base_time
            manager.upsert_package(
                registry="pypi.org",
                name="old-pkg",
                ttl_seconds=0,  # Immediately expired
            )
            # Advance clock so fetched_at + 0 < now
            mock_time.time.return_value = base_time + 2
            assert manager.get_package("pypi.org", "old-pkg") is None

    def test_upsert_updates_existing(self, manager: CacheManager) -> None:
        manager.upsert_package(
            registry="pypi.org",
            name="pkg",
            latest_version="1.0.0",
        )
        manager.upsert_package(
            registry="pypi.org",
            name="pkg",
            latest_version="2.0.0",
        )
        row = manager.get_package("pypi.org", "pkg")
        assert row is not None
        assert row["latest_version"] == "2.0.0"


# ---------------------------------------------------------------------------
# store_archive + SHA-256
# ---------------------------------------------------------------------------


class TestStoreArchive:
    def test_store_and_retrieve(
        self, manager: CacheManager, sample_archive: bytes
    ) -> None:
        expected_hash = _sha256(sample_archive)
        result = manager.store_archive(
            registry="pypi.org",
            name="pkg",
            version="1.0.0",
            archive_data=sample_archive,
            filename="pkg-1.0.0.tar.gz",
            expected_sha256=expected_hash,
        )
        assert isinstance(result, StoreResult)
        assert result.sha256 == expected_hash
        assert result.size_bytes == len(sample_archive)
        assert result.deduplicated is False
        assert result.distribution_id > 0

        # Verify archive is on disk
        abs_path = manager.cache_dir / result.archive_path
        assert abs_path.exists()
        assert abs_path.read_bytes() == sample_archive

    def test_hash_mismatch(self, manager: CacheManager, sample_archive: bytes) -> None:
        with pytest.raises(HashMismatchError, match="SHA-256 mismatch"):
            manager.store_archive(
                registry="pypi.org",
                name="pkg",
                version="1.0.0",
                archive_data=sample_archive,
                filename="pkg-1.0.0.tar.gz",
                expected_sha256="0" * 64,  # Wrong hash
            )

    def test_computed_hash_when_no_expected(
        self, manager: CacheManager, sample_archive: bytes
    ) -> None:
        result = manager.store_archive(
            registry="pypi.org",
            name="pkg",
            version="1.0.0",
            archive_data=sample_archive,
            filename="pkg-1.0.0.tar.gz",
            # No expected_sha256 — computed from data
        )
        assert result.sha256 == _sha256(sample_archive)

    def test_deduplication(self, manager: CacheManager, sample_archive: bytes) -> None:
        """Same archive stored twice uses dedup (same file on disk)."""
        expected_hash = _sha256(sample_archive)

        r1 = manager.store_archive(
            registry="pypi.org",
            name="pkg",
            version="1.0.0",
            archive_data=sample_archive,
            filename="pkg-1.0.0.tar.gz",
            expected_sha256=expected_hash,
        )
        assert r1.deduplicated is False

        # Store same bytes under a different name/version
        r2 = manager.store_archive(
            registry="pypi.org",
            name="pkg",
            version="1.0.1",
            archive_data=sample_archive,
            filename="pkg-1.0.1.tar.gz",
            expected_sha256=expected_hash,
        )
        assert r2.deduplicated is True
        # Both should reference the same archive path
        assert r2.archive_path == r1.archive_path

    def test_store_with_metadata(
        self, manager: CacheManager, sample_archive: bytes
    ) -> None:
        metadata = PackageMetadata(
            dependencies=[
                Dependency.from_requirement_string("urllib3>=1.21.1,<3"),
            ],
            python_requires=">=3.8",
            summary="Test package",
            source="pep658",
        )

        manager.store_archive(
            registry="pypi.org",
            name="pkg",
            version="1.0.0",
            archive_data=sample_archive,
            filename="pkg-1.0.0.tar.gz",
            metadata=metadata,
        )

        # Retrieve the metadata back
        cached = manager.get_metadata("pypi.org", "pkg", "1.0.0")
        assert cached is not None
        assert cached.summary == "Test package"
        assert cached.python_requires == ">=3.8"
        assert cached.source == "pep658"
        assert cached.dependencies is not None
        assert len(cached.dependencies) == 1
        assert cached.dependencies[0].name == "urllib3"

    def test_store_archive_preserves_existing_metadata_on_same_hash(
        self, manager: CacheManager, sample_archive: bytes
    ) -> None:
        sha256 = _sha256(sample_archive)
        manager.save_metadata(
            registry="pypi.org",
            name="pkg",
            version="1.0.0",
            sha256=sha256,
            metadata=PackageMetadata(
                dependencies=[
                    Dependency.from_requirement_string("urllib3>=1.21.1,<3"),
                ],
                summary="Test package",
                source="pep658",
            ),
            dynamic_fields='["requires_dist"]',
        )

        manager.store_archive(
            registry="pypi.org",
            name="pkg",
            version="1.0.0",
            archive_data=sample_archive,
            filename="pkg-1.0.0.tar.gz",
            expected_sha256=sha256,
        )

        cached = manager.get_metadata("pypi.org", "pkg", "1.0.0")
        assert cached is not None
        assert cached.summary == "Test package"
        assert cached.source == "pep658"
        assert cached.dynamic_fields == ["requires_dist"]
        assert cached.dependencies is not None
        assert [dep.name for dep in cached.dependencies] == ["urllib3"]


# ---------------------------------------------------------------------------
# get_metadata / save_metadata
# ---------------------------------------------------------------------------


class TestMetadata:
    def test_save_and_get(self, manager: CacheManager) -> None:
        metadata = PackageMetadata(
            dependencies=[
                Dependency.from_requirement_string("certifi>=2017.4.17"),
                Dependency.from_requirement_string("idna>=2.5,<4"),
            ],
            python_requires=">=3.7",
            license="Apache-2.0",
            summary="A test package",
            author="Test Author",
            homepage="https://example.com",
            source="wheel",
        )

        dist_id = manager.save_metadata(
            registry="pypi.org",
            name="test-pkg",
            version="1.0.0",
            sha256="a" * 64,
            metadata=metadata,
        )
        assert dist_id > 0

        cached = manager.get_metadata("pypi.org", "test-pkg", "1.0.0")
        assert cached is not None
        assert cached.python_requires == ">=3.7"
        assert cached.license == "Apache-2.0"
        assert cached.summary == "A test package"
        assert cached.author == "Test Author"
        assert cached.homepage == "https://example.com"
        assert cached.source == "wheel"
        assert cached.dependencies is not None
        assert len(cached.dependencies) == 2
        dep_names = {d.name for d in cached.dependencies}
        assert dep_names == {"certifi", "idna"}

    def test_get_nonexistent(self, manager: CacheManager) -> None:
        assert manager.get_metadata("pypi.org", "nope", "1.0.0") is None

    def test_deps_known_false(self, manager: CacheManager) -> None:
        """When deps_known=False, dependencies should be None."""
        metadata = PackageMetadata(
            python_requires=">=3.8",
            source="sdist",
        )
        manager.save_metadata(
            registry="pypi.org",
            name="dynamic-pkg",
            version="1.0.0",
            sha256="b" * 64,
            metadata=metadata,
            deps_known=False,
        )

        cached = manager.get_metadata("pypi.org", "dynamic-pkg", "1.0.0")
        assert cached is not None
        assert cached.dependencies is None

    def test_no_dependencies(self, manager: CacheManager) -> None:
        """When deps_known=True and no deps, dependencies should be []."""
        metadata = PackageMetadata(
            dependencies=[],
            source="pep658",
        )
        manager.save_metadata(
            registry="pypi.org",
            name="no-deps-pkg",
            version="1.0.0",
            sha256="c" * 64,
            metadata=metadata,
            deps_known=True,
        )

        cached = manager.get_metadata("pypi.org", "no-deps-pkg", "1.0.0")
        assert cached is not None
        assert cached.dependencies == []


# ---------------------------------------------------------------------------
# get_archive_path
# ---------------------------------------------------------------------------


class TestGetArchivePath:
    def test_returns_path(self, manager: CacheManager, sample_archive: bytes) -> None:
        manager.store_archive(
            registry="pypi.org",
            name="pkg",
            version="1.0.0",
            archive_data=sample_archive,
            filename="pkg-1.0.0.tar.gz",
        )
        path = manager.get_archive_path("pypi.org", "pkg", "1.0.0")
        assert path is not None
        assert path.exists()

    def test_returns_none_when_not_cached(self, manager: CacheManager) -> None:
        assert manager.get_archive_path("pypi.org", "nope", "1.0.0") is None

    def test_returns_none_when_file_deleted(
        self, manager: CacheManager, sample_archive: bytes
    ) -> None:
        result = manager.store_archive(
            registry="pypi.org",
            name="pkg",
            version="1.0.0",
            archive_data=sample_archive,
            filename="pkg-1.0.0.tar.gz",
        )
        # Delete the actual file
        (manager.cache_dir / result.archive_path).unlink()
        assert manager.get_archive_path("pypi.org", "pkg", "1.0.0") is None

    def test_ignores_metadata_only_rows(
        self, manager: CacheManager, sample_archive: bytes
    ) -> None:
        manager.save_metadata(
            registry="pypi.org",
            name="pkg",
            version="1.0.0",
            sha256="a" * 64,
            metadata=PackageMetadata(
                summary="cached metadata",
                source="pep658",
            ),
        )
        manager.store_archive(
            registry="pypi.org",
            name="pkg",
            version="1.0.0",
            archive_data=sample_archive,
            filename="pkg-1.0.0.tar.gz",
        )

        path = manager.get_archive_path("pypi.org", "pkg", "1.0.0")
        assert path is not None
        assert path.exists()


# ---------------------------------------------------------------------------
# File extraction from cached archives
# ---------------------------------------------------------------------------


class TestCacheExtraction:
    def test_extract_file(self, manager: CacheManager, sample_archive: bytes) -> None:
        manager.store_archive(
            registry="pypi.org",
            name="pkg",
            version="1.0.0",
            archive_data=sample_archive,
            filename="pkg-1.0.0.tar.gz",
        )
        # Root prefix is stripped — pass path relative to package root
        content = manager.extract_file("pypi.org", "pkg", "1.0.0", "README.md")
        assert content == b"# Test Package"

    def test_extract_file_not_cached(self, manager: CacheManager) -> None:
        with pytest.raises(ArchiveNotCachedError):
            manager.extract_file("pypi.org", "nope", "1.0.0", "README.md")

    def test_list_archive(self, manager: CacheManager, sample_archive: bytes) -> None:
        manager.store_archive(
            registry="pypi.org",
            name="pkg",
            version="1.0.0",
            archive_data=sample_archive,
            filename="pkg-1.0.0.tar.gz",
        )
        members = manager.list_archive("pypi.org", "pkg", "1.0.0")
        assert len(members) == 2
        names = {m.path for m in members}
        # Root prefix is stripped — paths are relative to package root
        assert "README.md" in names
        assert "setup.py" in names

    def test_list_archive_not_cached(self, manager: CacheManager) -> None:
        with pytest.raises(ArchiveNotCachedError):
            manager.list_archive("pypi.org", "nope", "1.0.0")

    def test_extract_all(self, manager: CacheManager, sample_archive: bytes) -> None:
        manager.store_archive(
            registry="pypi.org",
            name="pkg",
            version="1.0.0",
            archive_data=sample_archive,
            filename="pkg-1.0.0.tar.gz",
        )
        result = manager.extract_all("pypi.org", "pkg", "1.0.0")
        # Root prefix is stripped — keys are relative to package root
        assert "README.md" in result
        assert result["README.md"] == b"# Test Package"

    def test_extract_to_disk(
        self,
        manager: CacheManager,
        sample_archive: bytes,
        tmp_path: Path,
    ) -> None:
        manager.store_archive(
            registry="pypi.org",
            name="pkg",
            version="1.0.0",
            archive_data=sample_archive,
            filename="pkg-1.0.0.tar.gz",
        )
        dest = tmp_path / "extracted"
        paths = manager.extract_to_disk("pypi.org", "pkg", "1.0.0", dest)
        assert len(paths) == 2
        assert (dest / "pkg-1.0.0" / "README.md").exists()

    def test_extract_zip(self, manager: CacheManager, sample_whl: bytes) -> None:
        """Test extraction from .whl (zip) archives."""
        manager.store_archive(
            registry="pypi.org",
            name="pkg",
            version="1.0.0",
            archive_data=sample_whl,
            filename="pkg-1.0.0-py3-none-any.whl",
        )
        content = manager.extract_file(
            "pypi.org",
            "pkg",
            "1.0.0",
            "pkg-1.0.0.dist-info/METADATA",
        )
        assert b"Name: pkg" in content


# ---------------------------------------------------------------------------
# Dependency lookups
# ---------------------------------------------------------------------------


class TestDependencyLookups:
    def test_find_dependents(self, manager: CacheManager) -> None:
        metadata = PackageMetadata(
            dependencies=[
                Dependency.from_requirement_string("numpy>=1.21"),
                Dependency.from_requirement_string("pandas>=1.0"),
            ],
            source="wheel",
        )
        manager.save_metadata(
            registry="pypi.org",
            name="my-pkg",
            version="1.0.0",
            sha256="d" * 64,
            metadata=metadata,
        )

        dependents = manager.find_dependents("numpy")
        assert len(dependents) == 1
        assert dependents[0]["name"] == "my-pkg"
        assert dependents[0]["version"] == "1.0.0"

    def test_find_dependents_none(self, manager: CacheManager) -> None:
        assert manager.find_dependents("nonexistent") == []

    def test_find_by_hash(self, manager: CacheManager, sample_archive: bytes) -> None:
        h = _sha256(sample_archive)
        manager.store_archive(
            registry="pypi.org",
            name="pkg",
            version="1.0.0",
            archive_data=sample_archive,
            filename="pkg-1.0.0.tar.gz",
            expected_sha256=h,
        )
        found = manager.find_by_hash(h)
        assert found is not None
        assert found["name"] == "pkg"

    def test_find_by_hash_not_found(self, manager: CacheManager) -> None:
        assert manager.find_by_hash("f" * 64) is None

    def test_find_dependents_deduplicates_versions(self, manager: CacheManager) -> None:
        metadata = PackageMetadata(
            dependencies=[
                Dependency.from_requirement_string("numpy>=1.21"),
            ],
            source="pep658",
        )
        manager.save_metadata(
            registry="pypi.org",
            name="my-pkg",
            version="1.0.0",
            sha256="d" * 64,
            metadata=metadata,
        )
        manager.save_metadata(
            registry="pypi.org",
            name="my-pkg",
            version="1.0.0",
            sha256="e" * 64,
            metadata=PackageMetadata(
                dependencies=[
                    Dependency.from_requirement_string("numpy>=1.21"),
                ],
                source="wheel",
            ),
        )

        dependents = manager.find_dependents("numpy")
        assert dependents == [
            {"name": "my-pkg", "version": "1.0.0", "specifier": ">=1.21"}
        ]


# ---------------------------------------------------------------------------
# SHA-256 verification
# ---------------------------------------------------------------------------


class TestSHA256:
    def test_compute_sha256_file(self, tmp_path: Path) -> None:
        f = tmp_path / "test.bin"
        data = b"test file content"
        f.write_bytes(data)
        assert CacheManager.compute_sha256_file(f) == _sha256(data)

    def test_verify_archive_valid(
        self, manager: CacheManager, sample_archive: bytes
    ) -> None:
        manager.store_archive(
            registry="pypi.org",
            name="pkg",
            version="1.0.0",
            archive_data=sample_archive,
            filename="pkg-1.0.0.tar.gz",
        )
        assert manager.verify_archive("pypi.org", "pkg", "1.0.0") is True

    def test_verify_archive_corrupted(
        self, manager: CacheManager, sample_archive: bytes
    ) -> None:
        result = manager.store_archive(
            registry="pypi.org",
            name="pkg",
            version="1.0.0",
            archive_data=sample_archive,
            filename="pkg-1.0.0.tar.gz",
        )
        # Corrupt the file
        abs_path = manager.cache_dir / result.archive_path
        abs_path.write_bytes(b"corrupted data")

        assert manager.verify_archive("pypi.org", "pkg", "1.0.0") is False

    def test_verify_archive_not_cached(self, manager: CacheManager) -> None:
        assert manager.verify_archive("pypi.org", "nope", "1.0.0") is False

    def test_verify_archive_ignores_metadata_only_rows(
        self, manager: CacheManager, sample_archive: bytes
    ) -> None:
        manager.save_metadata(
            registry="pypi.org",
            name="pkg",
            version="1.0.0",
            sha256="a" * 64,
            metadata=PackageMetadata(
                summary="cached metadata",
                source="pep658",
            ),
        )
        manager.store_archive(
            registry="pypi.org",
            name="pkg",
            version="1.0.0",
            archive_data=sample_archive,
            filename="pkg-1.0.0.tar.gz",
        )

        assert manager.verify_archive("pypi.org", "pkg", "1.0.0") is True


# ---------------------------------------------------------------------------
# Cache management commands
# ---------------------------------------------------------------------------


class TestCacheManagement:
    def test_get_stats_empty(self, manager: CacheManager) -> None:
        stats = manager.get_stats()
        assert stats.package_count == 0
        assert stats.distribution_count == 0
        assert stats.total_size_bytes == 0

    def test_get_stats_with_data(
        self, manager: CacheManager, sample_archive: bytes
    ) -> None:
        manager.store_archive(
            registry="pypi.org",
            name="pkg",
            version="1.0.0",
            archive_data=sample_archive,
            filename="pkg-1.0.0.tar.gz",
        )
        stats = manager.get_stats()
        assert stats.package_count == 1
        assert stats.distribution_count == 1
        assert stats.total_size_bytes == len(sample_archive)
        assert str(manager.cache_dir) in str(stats.location)

    def test_clear_all(self, manager: CacheManager, sample_archive: bytes) -> None:
        manager.store_archive(
            registry="pypi.org",
            name="pkg",
            version="1.0.0",
            archive_data=sample_archive,
            filename="pkg-1.0.0.tar.gz",
        )
        evicted = manager.clear()
        assert evicted == 1

        stats = manager.get_stats()
        assert stats.package_count == 0
        assert stats.distribution_count == 0
        # Archives dir should be gone
        assert not manager.archives_dir.exists()

    def test_clear_older_than(
        self, manager: CacheManager, sample_archive: bytes
    ) -> None:
        base_time = 1_700_000_000
        with patch("peeq.cache.manager.time") as mock_time:
            mock_time.time.return_value = base_time
            manager.store_archive(
                registry="pypi.org",
                name="pkg",
                version="1.0.0",
                archive_data=sample_archive,
                filename="pkg-1.0.0.tar.gz",
            )
            # Advance clock so the entry's last_accessed_at is in the past
            mock_time.time.return_value = base_time + 2
            # Evict with a 0-second window (everything is "old")
            evicted = manager.clear(older_than_seconds=0)
            assert evicted == 1

    def test_clear_older_than_keeps_recent(
        self, manager: CacheManager, sample_archive: bytes
    ) -> None:
        manager.store_archive(
            registry="pypi.org",
            name="pkg",
            version="1.0.0",
            archive_data=sample_archive,
            filename="pkg-1.0.0.tar.gz",
        )
        # Evict with a very large window (nothing is old enough)
        evicted = manager.clear(older_than_seconds=86400)
        assert evicted == 0

        stats = manager.get_stats()
        assert stats.distribution_count == 1

    def test_dump(self, manager: CacheManager, sample_archive: bytes) -> None:
        manager.store_archive(
            registry="pypi.org",
            name="pkg",
            version="1.0.0",
            archive_data=sample_archive,
            filename="pkg-1.0.0.tar.gz",
        )
        dump = manager.dump()
        assert "packages" in dump
        assert "distributions" in dump
        assert "dependencies" in dump
        assert len(dump["packages"]) == 1
        assert len(dump["distributions"]) == 1

    def test_check(self, manager: CacheManager) -> None:
        # Just opening the manager initializes the DB
        manager.upsert_package(registry="pypi.org", name="test", latest_version="1.0.0")
        diagnostics = manager.check()
        assert diagnostics["journal_mode"] == "wal"
        assert diagnostics["quick_check"] == "ok"
        assert diagnostics["foreign_keys"] == 1


# ---------------------------------------------------------------------------
# StoreResult
# ---------------------------------------------------------------------------


class TestStoreResult:
    def test_attributes(self) -> None:
        r = StoreResult(
            sha256="abc123",
            archive_path="archives/pypi.org/pkg/pkg-1.0.0.tar.gz",
            size_bytes=1024,
            distribution_id=42,
            deduplicated=False,
        )
        assert r.sha256 == "abc123"
        assert r.archive_path == "archives/pypi.org/pkg/pkg-1.0.0.tar.gz"
        assert r.size_bytes == 1024
        assert r.distribution_id == 42
        assert r.deduplicated is False


# ---------------------------------------------------------------------------
# maybe_evict — LRU size-based eviction
# ---------------------------------------------------------------------------


class TestMaybeEvict:
    def test_exceeds_limit_triggers_eviction(
        self, manager: CacheManager, cache_dir: Path
    ) -> None:
        """Evict least-recently-used archives when cache exceeds size limit."""
        archive_size = 400_000  # 400 KB each
        base_time = 1_700_000_000

        with (
            patch("peeq.cache.manager.time") as mock_time,
            patch("peeq.cache.manager.get_settings") as mock_settings,
        ):
            mock_settings.return_value.cache.max_size_mb = 1
            mock_settings.return_value.cache.api_ttl_seconds = 3600

            # Store 3 archives (3 x 400 KB = 1.2 MB > 1 MB limit)
            for i in range(3):
                mock_time.time.return_value = base_time + i * 100
                data = bytes([i]) * archive_size
                manager.store_archive(
                    registry="pypi.org",
                    name=f"pkg{i}",
                    version="1.0.0",
                    archive_data=data,
                    filename=f"pkg{i}-1.0.0.tar.gz",
                )

            manager.maybe_evict()

        # Oldest entry (pkg0) should be soft-evicted
        assert manager.get_archive_path("pypi.org", "pkg0", "1.0.0") is None

        # More recent entries should still be available
        assert manager.get_archive_path("pypi.org", "pkg1", "1.0.0") is not None
        assert manager.get_archive_path("pypi.org", "pkg2", "1.0.0") is not None

    def test_under_limit_no_eviction(
        self, manager: CacheManager, sample_archive: bytes
    ) -> None:
        """Skip eviction when cache is under the size limit."""
        with patch("peeq.cache.manager.get_settings") as mock_settings:
            mock_settings.return_value.cache.max_size_mb = 100
            mock_settings.return_value.cache.api_ttl_seconds = 3600

            manager.store_archive(
                registry="pypi.org",
                name="pkg",
                version="1.0.0",
                archive_data=sample_archive,
                filename="pkg-1.0.0.tar.gz",
            )

            manager.maybe_evict()

        assert manager.get_archive_path("pypi.org", "pkg", "1.0.0") is not None

    def test_not_dirty_skips_eviction(self, manager: CacheManager) -> None:
        """Skip eviction when no new archives were written."""
        with patch("peeq.cache.manager.get_settings") as mock_settings:
            manager.maybe_evict()
            mock_settings.assert_not_called()

    def test_unlimited_cache_skips_eviction(
        self, manager: CacheManager, sample_archive: bytes
    ) -> None:
        """Skip eviction when max_size_mb is 0 (unlimited)."""
        with patch("peeq.cache.manager.get_settings") as mock_settings:
            mock_settings.return_value.cache.max_size_mb = 0
            mock_settings.return_value.cache.api_ttl_seconds = 3600

            manager.store_archive(
                registry="pypi.org",
                name="pkg",
                version="1.0.0",
                archive_data=sample_archive,
                filename="pkg-1.0.0.tar.gz",
            )

            manager.maybe_evict()

        assert manager.get_archive_path("pypi.org", "pkg", "1.0.0") is not None

    def test_dedup_safety_shared_file_preserved(self, manager: CacheManager) -> None:
        """Preserve shared archive file when only one referrer is evicted."""
        archive_size = 600_000  # 600 KB
        shared_data = bytes([0xAA]) * archive_size
        unique_data = bytes([0xBB]) * archive_size
        base_time = 1_700_000_000

        with (
            patch("peeq.cache.manager.time") as mock_time,
            patch("peeq.cache.manager.get_settings") as mock_settings,
        ):
            mock_settings.return_value.cache.max_size_mb = 1
            mock_settings.return_value.cache.api_ttl_seconds = 3600

            # Store first copy of shared data (earliest access — LRU first)
            mock_time.time.return_value = base_time
            r1 = manager.store_archive(
                registry="pypi.org",
                name="pkg-a",
                version="1.0.0",
                archive_data=shared_data,
                filename="pkg-a-1.0.0.tar.gz",
            )

            # Store dedup'd copy (same bytes → same hash → same file)
            mock_time.time.return_value = base_time + 100
            r2 = manager.store_archive(
                registry="pypi.org",
                name="pkg-b",
                version="1.0.0",
                archive_data=shared_data,
                filename="pkg-b-1.0.0.tar.gz",
            )
            assert r2.deduplicated is True
            assert r2.archive_path == r1.archive_path

            # Store a different archive
            mock_time.time.return_value = base_time + 200
            manager.store_archive(
                registry="pypi.org",
                name="pkg-c",
                version="1.0.0",
                archive_data=unique_data,
                filename="pkg-c-1.0.0.tar.gz",
            )

            # Total: 600 KB (shared) + 600 KB (unique) = 1.2 MB > 1 MB
            manager.maybe_evict()

        # pkg-a (oldest) should be soft-evicted
        assert manager.get_archive_path("pypi.org", "pkg-a", "1.0.0") is None

        # Shared file must still exist — pkg-b still references it
        shared_file = manager.cache_dir / r1.archive_path
        assert shared_file.exists()
        assert manager.get_archive_path("pypi.org", "pkg-b", "1.0.0") is not None


# ---------------------------------------------------------------------------
# Integration: atomic write — no temp files remain
# ---------------------------------------------------------------------------


class TestAtomicWrite:
    """Verify that the atomic write pattern leaves no .tmp files."""

    def test_no_tmp_files_after_successful_store(
        self, manager: CacheManager, sample_archive: bytes
    ) -> None:
        """After a successful store, no .tmp files should remain."""
        manager.store_archive(
            registry="pypi.org",
            name="clean-pkg",
            version="1.0.0",
            archive_data=sample_archive,
            filename="clean-pkg-1.0.0.tar.gz",
        )
        # Walk the entire cache directory and assert no .tmp files exist.
        tmp_files = list(manager.cache_dir.rglob("*.tmp"))
        assert tmp_files == [], f"Leftover temp files: {tmp_files}"

    def test_no_tmp_files_after_failed_store(self, manager: CacheManager) -> None:
        """After a failed store (write error), no .tmp files should remain."""
        # Patch write_bytes to simulate a disk-full error after the
        # temp file is created.
        original_write_bytes = Path.write_bytes

        def _failing_write_bytes(self_path: Path, data: bytes) -> int:
            # Create the file (so it exists on disk), then raise.
            original_write_bytes(self_path, data)
            msg = "Simulated disk full"
            raise OSError(msg)

        with (
            patch.object(Path, "write_bytes", _failing_write_bytes),
            pytest.raises(OSError, match="Simulated disk full"),
        ):
            manager.store_archive(
                registry="pypi.org",
                name="fail-pkg",
                version="1.0.0",
                archive_data=b"fake archive data",
                filename="fail-pkg-1.0.0.tar.gz",
            )

        # The cleanup handler should have removed the temp file.
        tmp_files = list(manager.cache_dir.rglob("*.tmp"))
        assert tmp_files == [], f"Leftover temp files: {tmp_files}"


# ---------------------------------------------------------------------------
# Integration: filename sanitization at the store_archive call site
# ---------------------------------------------------------------------------


class TestFilenameSanitization:
    """Verify that store_archive rejects malicious registry-supplied filenames."""

    def test_rejects_path_traversal_filename(self, manager: CacheManager) -> None:
        """Filename with traversal pattern is rejected before any I/O."""
        with pytest.raises(UnsafeFilenameError):
            manager.store_archive(
                registry="pypi.org",
                name="evil-pkg",
                version="1.0.0",
                archive_data=b"fake data",
                filename="../../../evil.tar.gz",
            )
