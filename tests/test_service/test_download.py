"""Tests for artifact download, file extraction, and caching helpers.

Covers `PackageService.download_package`,
`PackageService.get_file_content`, `PackageService.list_artifact_files`,
`PackageService._ensure_artifact_cached`, and
`PackageService.resolve_dependencies`.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from packaging.version import Version

from peeq.extraction import ExtractionError
from peeq.resolver.base import DependencyResolver
from peeq.resolver.models import (
    ResolvedDependency,
    SolverResult,
    TargetEnvironment,
)
from peeq.service import ArtifactNotAvailableError, FileNotInArchiveError
from tests.test_service.conftest import (
    _download_side_effect,
    _make_backend,
    _make_cache,
    _make_sdist_bytes,
    _make_service,
    _make_wheel_bytes,
    _sdist_fi,
    _wheel_fi,
)

# ===================================================================
# Tests: PackageService.get_file_content()
# ===================================================================


class TestGetFileContent:
    """Test file extraction from cached archives."""

    async def test_file_extraction(self) -> None:
        cache = _make_cache()
        cache.get_archive_path.return_value = Path("/cache/archives/pkg.tar.gz")
        cache.extract_file.return_value = b"file content"

        service = _make_service(cache=cache)
        result = await service.get_file_content("pkg", "1.0.0", "setup.py")

        assert result == b"file content"
        cache.extract_file.assert_called_once_with(
            "pypi.org",
            "pkg",
            "1.0.0",
            "setup.py",
        )

    async def test_artifact_not_available(self) -> None:
        backend = _make_backend()
        backend.files.return_value = []  # No files
        cache = _make_cache()
        cache.get_archive_path.return_value = None
        service = _make_service(cache=cache, backend=backend)

        with pytest.raises(ArtifactNotAvailableError):
            await service.get_file_content("pkg", "1.0.0", "setup.py")

    async def test_file_not_in_archive(self) -> None:
        cache = _make_cache()
        cache.get_archive_path.return_value = Path("/cache/pkg.tar.gz")
        cache.extract_file.side_effect = ExtractionError("not found")

        service = _make_service(cache=cache)

        with pytest.raises(FileNotInArchiveError):
            await service.get_file_content("pkg", "1.0.0", "missing.txt")


# ===================================================================
# Tests: PackageService.list_artifact_files()
# ===================================================================


class TestListArtifactFiles:
    """Test listing files inside cached archives."""

    async def test_list_files(self) -> None:
        cache = _make_cache()
        cache.get_archive_path.return_value = Path("/cache/pkg.tar.gz")
        members = [MagicMock(path="setup.py"), MagicMock(path="README.md")]
        cache.list_archive.return_value = members

        service = _make_service(cache=cache)
        result = await service.list_artifact_files("pkg", "1.0.0")

        assert result == members

    async def test_downloads_if_not_cached(self) -> None:
        sdist_bytes = _make_sdist_bytes()
        backend = _make_backend()
        backend.files.return_value = [_sdist_fi()]
        backend.download.side_effect = _download_side_effect(sdist_bytes)

        cache = _make_cache()
        # Not cached initially — triggers download
        cache.get_archive_path.return_value = None
        cache.store_archive.return_value = MagicMock(
            archive_path="archives/pypi.org/pkg/pkg.tar.gz",
        )
        cache.cache_dir = Path("/cache")
        cache.list_archive.return_value = []

        service = _make_service(cache=cache, backend=backend)
        await service.list_artifact_files("pkg", "1.0.0")

        cache.store_archive.assert_called_once()


# ===================================================================
# Tests: PackageService.download_package()
# ===================================================================


class TestDownloadPackage:
    """Test package download to a destination directory."""

    async def test_copy_from_cache(self, tmp_path: Path) -> None:
        # Create a fake cached archive
        cached = tmp_path / "cached" / "pkg.tar.gz"
        cached.parent.mkdir(parents=True)
        cached.write_bytes(b"archive data")

        cache = _make_cache()
        cache.get_archive_path.return_value = cached

        service = _make_service(cache=cache)
        dest = tmp_path / "output"
        dest.mkdir()
        result = await service.download_package("pkg", "1.0.0", dest)

        assert result == dest / "pkg.tar.gz"
        assert result.read_bytes() == b"archive data"

    async def test_extract_from_cache(self, tmp_path: Path) -> None:
        cache = _make_cache()
        cache.get_archive_path.return_value = Path("/cache/pkg.tar.gz")
        cache.extract_to_disk.return_value = [Path("setup.py")]

        service = _make_service(cache=cache)
        dest = tmp_path / "extracted"
        result = await service.download_package(
            "pkg",
            "1.0.0",
            dest,
            extract=True,
        )

        assert result == dest
        cache.extract_to_disk.assert_called_once_with(
            "pypi.org",
            "pkg",
            "1.0.0",
            dest,
        )

    async def test_downloads_if_not_cached(self, tmp_path: Path) -> None:
        sdist_bytes = _make_sdist_bytes()
        backend = _make_backend()
        backend.files.return_value = [_sdist_fi()]
        backend.download.side_effect = _download_side_effect(sdist_bytes)

        # _ensure_artifact_cached returns cache_dir / store_result.archive_path
        archive_rel = "archives/pypi.org/pkg/pkg.tar.gz"
        cached_path = tmp_path / archive_rel
        cached_path.parent.mkdir(parents=True)
        cached_path.write_bytes(sdist_bytes)

        cache = _make_cache()
        cache.get_archive_path.return_value = None  # not cached yet
        cache.store_archive.return_value = MagicMock(
            archive_path=archive_rel,
        )
        cache.cache_dir = tmp_path

        service = _make_service(cache=cache, backend=backend)
        dest = tmp_path / "output"
        dest.mkdir()
        result = await service.download_package("pkg", "1.0.0", dest)

        assert result.exists()

    async def test_no_artifact_raises(self) -> None:
        backend = _make_backend()
        backend.files.return_value = []
        cache = _make_cache()
        cache.get_archive_path.return_value = None

        service = _make_service(cache=cache, backend=backend)

        with pytest.raises(ArtifactNotAvailableError):
            await service.download_package("pkg", "1.0.0", Path("/out"))


# ===================================================================
# Tests: PackageService.resolve_dependencies()
# ===================================================================


class TestResolveDependencies:
    """Test dependency resolution delegation."""

    async def test_delegates_to_solver(self) -> None:
        expected = SolverResult(
            resolved=[
                ResolvedDependency(
                    name="requests",
                    version=Version("2.31.0"),
                ),
            ],
            solver_id="uv",
        )

        cache = _make_cache()
        backend = _make_backend()
        service = _make_service(cache=cache, backend=backend)
        target = TargetEnvironment(python_version="3.12")

        with patch.object(
            DependencyResolver,
            "get_solver",
        ) as mock_get_solver:
            mock_solver = AsyncMock()
            mock_solver.resolve.return_value = expected
            mock_get_solver.return_value = mock_solver

            result = await service.resolve_dependencies(
                ["requests>=2.0"],
                target,
            )

        assert result is expected
        mock_get_solver.assert_called_once()
        assert mock_get_solver.call_args[0][0] == "uv"
        assert "provider" in mock_get_solver.call_args.kwargs


# ===================================================================
# Tests: _ensure_artifact_cached
# ===================================================================


class TestEnsureArtifactCached:
    """Test the internal `_ensure_artifact_cached` helper."""

    async def test_already_cached(self) -> None:
        cache = _make_cache()
        cache.get_archive_path.return_value = Path("/cache/pkg.tar.gz")

        service = _make_service(cache=cache)
        result = await service._ensure_artifact_cached("pkg", "1.0.0")

        assert result == Path("/cache/pkg.tar.gz")
        service._backend.files.assert_not_awaited()  # type: ignore[union-attr]

    async def test_sdist_preferred(self) -> None:
        sdist_bytes = _make_sdist_bytes()
        backend = _make_backend()
        backend.files.return_value = [_sdist_fi(), _wheel_fi()]
        backend.download.side_effect = _download_side_effect(sdist_bytes)

        cache = _make_cache()
        cache.get_archive_path.return_value = None
        cache.store_archive.return_value = MagicMock(
            archive_path="archives/pypi.org/pkg/pkg.tar.gz",
        )
        cache.cache_dir = Path("/cache")

        service = _make_service(cache=cache, backend=backend)
        result = await service._ensure_artifact_cached("pkg", "1.0.0")

        assert result == Path("/cache/archives/pypi.org/pkg/pkg.tar.gz")
        # Only sdist downloaded, not wheel
        assert backend.download.await_count == 1

    async def test_falls_back_to_wheel(self) -> None:
        wheel_bytes = _make_wheel_bytes()
        backend = _make_backend()
        backend.files.return_value = [_wheel_fi()]  # No sdist
        backend.download.side_effect = _download_side_effect(wheel_bytes)

        cache = _make_cache()
        cache.get_archive_path.return_value = None
        cache.store_archive.return_value = MagicMock(
            archive_path="archives/pypi.org/pkg/pkg.whl",
        )
        cache.cache_dir = Path("/cache")

        service = _make_service(cache=cache, backend=backend)
        result = await service._ensure_artifact_cached("pkg", "1.0.0")

        assert result is not None

    async def test_no_files_raises(self) -> None:
        backend = _make_backend()
        backend.files.return_value = []
        cache = _make_cache()
        cache.get_archive_path.return_value = None

        service = _make_service(cache=cache, backend=backend)

        with pytest.raises(ArtifactNotAvailableError):
            await service._ensure_artifact_cached("pkg", "1.0.0")
