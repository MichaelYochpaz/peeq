"""Tests for PackageProvider (data bridge between data layer and solvers)."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest
from packaging.specifiers import SpecifierSet
from packaging.version import Version

from peeq.models import Dependency, DistType, FileInfo, PackageMetadata, VersionInfo
from peeq.resolver.models import TargetEnvironment
from peeq.resolver.provider import PackageProvider

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def mock_cache() -> MagicMock:
    """Create a mock CacheManager."""
    return MagicMock()


@pytest.fixture
def mock_metadata_fetcher() -> AsyncMock:
    """Create a mock MetadataFetcher."""
    fetcher = AsyncMock()
    fetcher.get_metadata = AsyncMock(return_value=None)
    return fetcher


@pytest.fixture
def mock_backend() -> AsyncMock:
    """Create a mock PackageRepository backend."""
    backend = AsyncMock()
    backend.versions = AsyncMock(return_value=[])
    backend.files = AsyncMock(return_value=[])
    backend.base_url = "https://pypi.org"
    return backend


@pytest.fixture
def target_env() -> TargetEnvironment:
    """Default target environment for tests."""
    return TargetEnvironment(
        python_version="3.12",
        os_name="posix",
        sys_platform="linux",
    )


@pytest.fixture
def provider(
    mock_cache: MagicMock,
    mock_metadata_fetcher: AsyncMock,
    mock_backend: AsyncMock,
    target_env: TargetEnvironment,
) -> PackageProvider:
    """Create a PackageProvider with mocked dependencies."""
    return PackageProvider(
        cache=mock_cache,
        metadata_fetcher=mock_metadata_fetcher,
        backend=mock_backend,
        target_env=target_env,
    )


def _dep(raw: str) -> Dependency:
    """Create a Dependency from a requirement string."""
    return Dependency.from_requirement_string(raw)


# ---------------------------------------------------------------------------
# Version listing
# ---------------------------------------------------------------------------


class TestGetVersions:
    """Tests for PackageProvider.get_versions()."""

    async def test_returns_versions_sorted_descending(self, provider: PackageProvider, mock_backend: AsyncMock) -> None:
        mock_backend.versions.return_value = [
            VersionInfo(version=Version("1.0.0")),
            VersionInfo(version=Version("2.0.0")),
            VersionInfo(version=Version("1.5.0")),
        ]
        versions = await provider.get_versions("requests")
        assert versions == [Version("2.0.0"), Version("1.5.0"), Version("1.0.0")]

    async def test_filters_prereleases_by_default(self, provider: PackageProvider, mock_backend: AsyncMock) -> None:
        mock_backend.versions.return_value = [
            VersionInfo(version=Version("1.0.0")),
            VersionInfo(version=Version("2.0.0rc1")),
            VersionInfo(version=Version("2.0.0")),
        ]
        versions = await provider.get_versions("requests")
        assert Version("2.0.0rc1") not in versions
        assert versions == [Version("2.0.0"), Version("1.0.0")]

    async def test_includes_prereleases_when_enabled(
        self,
        mock_cache: MagicMock,
        mock_metadata_fetcher: AsyncMock,
        mock_backend: AsyncMock,
        target_env: TargetEnvironment,
    ) -> None:
        mock_backend.versions.return_value = [
            VersionInfo(version=Version("1.0.0")),
            VersionInfo(version=Version("2.0.0rc1")),
        ]
        provider = PackageProvider(
            cache=mock_cache,
            metadata_fetcher=mock_metadata_fetcher,
            backend=mock_backend,
            target_env=target_env,
            include_prereleases=True,
        )
        versions = await provider.get_versions("requests")
        assert Version("2.0.0rc1") in versions

    async def test_filters_dev_releases(self, provider: PackageProvider, mock_backend: AsyncMock) -> None:
        mock_backend.versions.return_value = [
            VersionInfo(version=Version("1.0.0")),
            VersionInfo(version=Version("1.1.0.dev1")),
        ]
        versions = await provider.get_versions("requests")
        assert Version("1.1.0.dev1") not in versions

    async def test_caches_results(self, provider: PackageProvider, mock_backend: AsyncMock) -> None:
        mock_backend.versions.return_value = [VersionInfo(version=Version("1.0.0"))]
        await provider.get_versions("requests")
        await provider.get_versions("requests")
        # Backend should only be called once.
        mock_backend.versions.assert_called_once_with("requests")

    async def test_yanked_cache_prepopulated(self, provider: PackageProvider, mock_backend: AsyncMock) -> None:
        """get_versions() pre-populates _yanked_cache from VersionInfo data."""
        mock_backend.versions.return_value = [
            VersionInfo(version=Version("2.0.0"), yanked=False),
            VersionInfo(version=Version("1.5.0"), yanked=True),
            VersionInfo(version=Version("1.0.0"), yanked=False),
        ]
        await provider.get_versions("pkg")

        assert provider._yanked_cache[("pkg", "2.0.0")] is False
        assert provider._yanked_cache[("pkg", "1.5.0")] is True
        assert provider._yanked_cache[("pkg", "1.0.0")] is False

    async def test_empty_versions(self, provider: PackageProvider, mock_backend: AsyncMock) -> None:
        mock_backend.versions.return_value = []
        versions = await provider.get_versions("nonexistent")
        assert versions == []

    async def test_filters_yanked_by_default(self, provider: PackageProvider, mock_backend: AsyncMock) -> None:
        """Yanked versions are excluded by default."""
        mock_backend.versions.return_value = [
            VersionInfo(version=Version("2.0.0"), yanked=False),
            VersionInfo(version=Version("1.5.0"), yanked=True),
            VersionInfo(version=Version("1.0.0"), yanked=False),
        ]
        versions = await provider.get_versions("pkg")
        assert Version("1.5.0") not in versions
        assert versions == [Version("2.0.0"), Version("1.0.0")]

    async def test_includes_yanked_when_requested(self, provider: PackageProvider, mock_backend: AsyncMock) -> None:
        """Yanked versions are included when include_yanked=True."""
        mock_backend.versions.return_value = [
            VersionInfo(version=Version("2.0.0"), yanked=False),
            VersionInfo(version=Version("1.5.0"), yanked=True),
            VersionInfo(version=Version("1.0.0"), yanked=False),
        ]
        versions = await provider.get_versions("pkg", include_yanked=True)
        assert Version("1.5.0") in versions
        assert len(versions) == 3

    async def test_filters_incompatible_python_requires(
        self, provider: PackageProvider, mock_backend: AsyncMock
    ) -> None:
        """Versions with incompatible requires_python are excluded."""
        mock_backend.versions.return_value = [
            VersionInfo(version=Version("3.0.0"), requires_python=">=3.13"),
            VersionInfo(version=Version("2.0.0"), requires_python=">=3.10"),
            VersionInfo(version=Version("1.0.0"), requires_python=">=3.8"),
        ]
        # Provider target is python_version="3.12"
        versions = await provider.get_versions("pkg")
        assert Version("3.0.0") not in versions
        assert versions == [Version("2.0.0"), Version("1.0.0")]

    async def test_keeps_versions_without_requires_python(
        self, provider: PackageProvider, mock_backend: AsyncMock
    ) -> None:
        """Versions without requires_python are kept (permissive)."""
        mock_backend.versions.return_value = [
            VersionInfo(version=Version("2.0.0"), requires_python=">=3.10"),
            VersionInfo(version=Version("1.0.0")),  # No requires_python
        ]
        versions = await provider.get_versions("pkg")
        assert Version("1.0.0") in versions

    async def test_keeps_versions_with_invalid_requires_python(
        self, provider: PackageProvider, mock_backend: AsyncMock
    ) -> None:
        """Versions with invalid requires_python are kept (permissive)."""
        mock_backend.versions.return_value = [
            VersionInfo(version=Version("1.0.0"), requires_python="not-valid!!!"),
        ]
        versions = await provider.get_versions("pkg")
        assert Version("1.0.0") in versions

    async def test_no_python_filtering_without_target(
        self,
        mock_cache: MagicMock,
        mock_metadata_fetcher: AsyncMock,
        mock_backend: AsyncMock,
    ) -> None:
        """Without a target Python version, all versions pass."""
        mock_backend.versions.return_value = [
            VersionInfo(version=Version("1.0.0"), requires_python=">=3.13"),
        ]
        provider = PackageProvider(
            cache=mock_cache,
            metadata_fetcher=mock_metadata_fetcher,
            backend=mock_backend,
            target_env=TargetEnvironment(),  # No python_version
        )
        versions = await provider.get_versions("pkg")
        assert Version("1.0.0") in versions

    async def test_cache_distinguishes_include_yanked(self, provider: PackageProvider, mock_backend: AsyncMock) -> None:
        """Cache keys differ for include_yanked=True vs False."""
        mock_backend.versions.return_value = [
            VersionInfo(version=Version("2.0.0"), yanked=False),
            VersionInfo(version=Version("1.0.0"), yanked=True),
        ]
        without_yanked = await provider.get_versions("pkg")
        with_yanked = await provider.get_versions("pkg", include_yanked=True)
        assert len(without_yanked) == 1
        assert len(with_yanked) == 2

    async def test_admits_pinned_prerelease_via_equality(
        self, provider: PackageProvider, mock_backend: AsyncMock
    ) -> None:
        """Pre-release is admitted when a requirement pins it via `==`."""
        mock_backend.versions.return_value = [
            VersionInfo(version=Version("1.0.0")),
            VersionInfo(version=Version("2.0.0a1")),
        ]
        versions = await provider.get_versions(
            "pkg",
            requirements=[SpecifierSet("==2.0.0a1")],
        )
        assert Version("2.0.0a1") in versions
        assert versions == [Version("2.0.0a1"), Version("1.0.0")]

    async def test_filters_prereleases_without_explicit_pin(
        self, provider: PackageProvider, mock_backend: AsyncMock
    ) -> None:
        """Pre-releases are still filtered when no requirement pins one."""
        mock_backend.versions.return_value = [
            VersionInfo(version=Version("1.0.0")),
            VersionInfo(version=Version("2.0.0a1")),
        ]
        versions = await provider.get_versions(
            "pkg",
            requirements=[SpecifierSet(">=1.0")],
        )
        assert Version("2.0.0a1") not in versions
        assert versions == [Version("1.0.0")]

    async def test_admits_dev_release_pinned_via_equality(
        self, provider: PackageProvider, mock_backend: AsyncMock
    ) -> None:
        """Dev release is admitted when a requirement pins it via `==`."""
        mock_backend.versions.return_value = [
            VersionInfo(version=Version("1.0.0")),
            VersionInfo(version=Version("1.1.0.dev1")),
        ]
        versions = await provider.get_versions(
            "pkg",
            requirements=[SpecifierSet("==1.1.0.dev1")],
        )
        assert Version("1.1.0.dev1") in versions

    async def test_no_requirements_filters_prereleases(
        self, provider: PackageProvider, mock_backend: AsyncMock
    ) -> None:
        """Without requirements parameter, pre-releases are filtered as before."""
        mock_backend.versions.return_value = [
            VersionInfo(version=Version("1.0.0")),
            VersionInfo(version=Version("2.0.0rc1")),
        ]
        versions = await provider.get_versions("pkg")
        assert Version("2.0.0rc1") not in versions


# ---------------------------------------------------------------------------
# Dependency fetching
# ---------------------------------------------------------------------------


class TestGetDependencies:
    """Tests for PackageProvider.get_dependencies()."""

    async def test_returns_dependencies(
        self,
        provider: PackageProvider,
        mock_metadata_fetcher: AsyncMock,
    ) -> None:
        mock_metadata_fetcher.get_metadata.return_value = PackageMetadata(
            dependencies=[
                _dep("urllib3>=1.21.1,<3"),
                _dep("certifi>=2017.4.17"),
            ],
        )
        deps = await provider.get_dependencies("requests", "2.31.0")
        assert len(deps) == 2
        assert deps[0].name == "urllib3"

    async def test_returns_empty_when_no_metadata(
        self,
        provider: PackageProvider,
        mock_metadata_fetcher: AsyncMock,
    ) -> None:
        mock_metadata_fetcher.get_metadata.return_value = None
        deps = await provider.get_dependencies("missing", "1.0.0")
        assert deps == []

    async def test_returns_empty_when_deps_none(
        self,
        provider: PackageProvider,
        mock_metadata_fetcher: AsyncMock,
    ) -> None:
        mock_metadata_fetcher.get_metadata.return_value = PackageMetadata(
            dependencies=None,
        )
        deps = await provider.get_dependencies("dynamic-pkg", "1.0.0")
        assert deps == []

    async def test_filters_platform_markers(
        self,
        provider: PackageProvider,
        mock_metadata_fetcher: AsyncMock,
    ) -> None:
        """Deps with non-matching platform markers are excluded."""
        mock_metadata_fetcher.get_metadata.return_value = PackageMetadata(
            dependencies=[
                _dep("urllib3>=1.0"),
                _dep('pywin32; sys_platform == "win32"'),
            ],
        )
        # Provider's target_env has sys_platform="linux", so pywin32
        # should be filtered out.
        deps = await provider.get_dependencies("requests", "2.31.0")
        names = [d.name for d in deps]
        assert "urllib3" in names
        assert "pywin32" not in names

    async def test_keeps_matching_platform_markers(
        self,
        mock_cache: MagicMock,
        mock_metadata_fetcher: AsyncMock,
        mock_backend: AsyncMock,
    ) -> None:
        """Deps matching the target platform are kept."""
        mock_metadata_fetcher.get_metadata.return_value = PackageMetadata(
            dependencies=[
                _dep('pywin32; sys_platform == "win32"'),
            ],
        )
        provider = PackageProvider(
            cache=mock_cache,
            metadata_fetcher=mock_metadata_fetcher,
            backend=mock_backend,
            target_env=TargetEnvironment(sys_platform="win32"),
        )
        deps = await provider.get_dependencies("pkg", "1.0.0")
        assert len(deps) == 1
        assert deps[0].name == "pywin32"

    async def test_keeps_extra_markers(
        self,
        provider: PackageProvider,
        mock_metadata_fetcher: AsyncMock,
    ) -> None:
        """Deps gated on extras are kept (solver handles extras)."""
        mock_metadata_fetcher.get_metadata.return_value = PackageMetadata(
            dependencies=[
                _dep("urllib3>=1.0"),
                _dep('PySocks>=1.5.6; extra == "socks"'),
            ],
        )
        deps = await provider.get_dependencies("requests", "2.31.0")
        names = [d.name for d in deps]
        assert "urllib3" in names
        assert "pysocks" in names

    async def test_caches_results(
        self,
        provider: PackageProvider,
        mock_metadata_fetcher: AsyncMock,
    ) -> None:
        mock_metadata_fetcher.get_metadata.return_value = PackageMetadata(
            dependencies=[_dep("click>=7.0")],
        )
        await provider.get_dependencies("flask", "2.0.0")
        await provider.get_dependencies("flask", "2.0.0")
        mock_metadata_fetcher.get_metadata.assert_called_once()

    async def test_includes_deps_with_invalid_markers(
        self,
        provider: PackageProvider,
        mock_metadata_fetcher: AsyncMock,
    ) -> None:
        """Deps with unparseable markers are included (permissive)."""
        dep = Dependency(
            name="weird-dep",
            specifier=">=1.0",
            markers="invalid marker!!!",
            raw="weird-dep>=1.0; invalid marker!!!",
        )
        mock_metadata_fetcher.get_metadata.return_value = PackageMetadata(
            dependencies=[dep],
        )
        deps = await provider.get_dependencies("pkg", "1.0.0")
        assert len(deps) == 1


# ---------------------------------------------------------------------------
# Yanked status
# ---------------------------------------------------------------------------


class TestIsYanked:
    """Tests for PackageProvider.is_yanked()."""

    async def test_not_yanked(self, provider: PackageProvider, mock_backend: AsyncMock) -> None:
        mock_backend.files.return_value = [
            FileInfo(
                filename="pkg-1.0.0.tar.gz",
                url="https://example.com/pkg-1.0.0.tar.gz",
                dist_type=DistType.SDIST,
                yanked=False,
            ),
        ]
        assert await provider.is_yanked("pkg", "1.0.0") is False

    async def test_all_files_yanked(self, provider: PackageProvider, mock_backend: AsyncMock) -> None:
        mock_backend.files.return_value = [
            FileInfo(
                filename="pkg-1.0.0.tar.gz",
                url="https://example.com/pkg-1.0.0.tar.gz",
                dist_type=DistType.SDIST,
                yanked=True,
            ),
            FileInfo(
                filename="pkg-1.0.0-py3-none-any.whl",
                url="https://example.com/pkg-1.0.0-py3-none-any.whl",
                dist_type=DistType.WHEEL,
                yanked=True,
            ),
        ]
        assert await provider.is_yanked("pkg", "1.0.0") is True

    async def test_partial_yank_not_yanked(self, provider: PackageProvider, mock_backend: AsyncMock) -> None:
        """If some files are yanked but not all, version is not yanked."""
        mock_backend.files.return_value = [
            FileInfo(
                filename="pkg-1.0.0.tar.gz",
                url="https://example.com/pkg-1.0.0.tar.gz",
                dist_type=DistType.SDIST,
                yanked=True,
            ),
            FileInfo(
                filename="pkg-1.0.0-py3-none-any.whl",
                url="https://example.com/pkg-1.0.0-py3-none-any.whl",
                dist_type=DistType.WHEEL,
                yanked=False,
            ),
        ]
        assert await provider.is_yanked("pkg", "1.0.0") is False

    async def test_no_files_not_yanked(self, provider: PackageProvider, mock_backend: AsyncMock) -> None:
        """Empty file list means not yanked."""
        mock_backend.files.return_value = []
        assert await provider.is_yanked("pkg", "1.0.0") is False

    async def test_caches_results(self, provider: PackageProvider, mock_backend: AsyncMock) -> None:
        mock_backend.files.return_value = [
            FileInfo(
                filename="pkg-1.0.0.tar.gz",
                url="https://example.com/pkg-1.0.0.tar.gz",
                dist_type=DistType.SDIST,
                yanked=False,
            ),
        ]
        await provider.is_yanked("pkg", "1.0.0")
        await provider.is_yanked("pkg", "1.0.0")
        mock_backend.files.assert_called_once()

    async def test_backend_error_returns_false(self, provider: PackageProvider, mock_backend: AsyncMock) -> None:
        """Backend errors default to not-yanked (permissive)."""
        mock_backend.files.side_effect = Exception("network error")
        assert await provider.is_yanked("pkg", "1.0.0") is False


# ---------------------------------------------------------------------------
# Python requires
# ---------------------------------------------------------------------------


class TestCheckPythonRequires:
    """Tests for PackageProvider.check_python_requires()."""

    async def test_compatible(
        self,
        provider: PackageProvider,
        mock_metadata_fetcher: AsyncMock,
    ) -> None:
        mock_metadata_fetcher.get_metadata.return_value = PackageMetadata(
            python_requires=">=3.8",
        )
        assert await provider.check_python_requires("pkg", "1.0.0") is True

    async def test_incompatible(
        self,
        provider: PackageProvider,
        mock_metadata_fetcher: AsyncMock,
    ) -> None:
        mock_metadata_fetcher.get_metadata.return_value = PackageMetadata(
            python_requires=">=3.13",
        )
        # Provider has target python_version="3.12"
        assert await provider.check_python_requires("pkg", "1.0.0") is False

    async def test_no_python_requires(
        self,
        provider: PackageProvider,
        mock_metadata_fetcher: AsyncMock,
    ) -> None:
        mock_metadata_fetcher.get_metadata.return_value = PackageMetadata()
        assert await provider.check_python_requires("pkg", "1.0.0") is True

    async def test_no_metadata(
        self,
        provider: PackageProvider,
        mock_metadata_fetcher: AsyncMock,
    ) -> None:
        mock_metadata_fetcher.get_metadata.return_value = None
        assert await provider.check_python_requires("pkg", "1.0.0") is True

    async def test_no_target_python_version(
        self,
        mock_cache: MagicMock,
        mock_metadata_fetcher: AsyncMock,
        mock_backend: AsyncMock,
    ) -> None:
        """Without a target Python version, always returns True."""
        provider = PackageProvider(
            cache=mock_cache,
            metadata_fetcher=mock_metadata_fetcher,
            backend=mock_backend,
            target_env=TargetEnvironment(),
        )
        assert await provider.check_python_requires("pkg", "1.0.0") is True

    async def test_invalid_python_requires(
        self,
        provider: PackageProvider,
        mock_metadata_fetcher: AsyncMock,
    ) -> None:
        """Invalid python_requires is treated as compatible (permissive)."""
        mock_metadata_fetcher.get_metadata.return_value = PackageMetadata(
            python_requires="not-a-valid-spec!!!",
        )
        assert await provider.check_python_requires("pkg", "1.0.0") is True
