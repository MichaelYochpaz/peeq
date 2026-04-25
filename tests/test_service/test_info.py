"""Tests for `PackageService.info` and orchestration paths."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

from packaging.version import Version

from peeq.models import (
    DistType,
    FileInfo,
    PackageInfo,
    PackageMetadata,
    VersionInfo,
    VulnerabilityReport,
)
from tests.test_service.conftest import _dep, _make_backend, _make_service

# ===================================================================
# Tests: PackageService.info()
# ===================================================================


class TestInfo:
    """Test `PackageService.info` with target version."""

    async def test_requires_python_updated_for_target_version(self) -> None:
        """requires_python reflects the targeted version, not latest."""
        backend = _make_backend()
        latest_info = PackageInfo(
            name="mylib",
            latest_version=Version("3.0.0"),
            version_count=3,
            requires_python=">=3.10",
            registry="pypi.org",
        )
        backend.check.return_value = latest_info
        backend.versions.return_value = [
            VersionInfo(version=Version("3.0.0")),
            VersionInfo(version=Version("2.0.0")),
            VersionInfo(version=Version("1.0.0")),
        ]
        backend.files.return_value = [
            FileInfo(
                filename="mylib-2.0.0-py3-none-any.whl",
                url="https://example.com/mylib-2.0.0-py3-none-any.whl",
                dist_type=DistType.WHEEL,
                requires_python=">=3.7",
            ),
        ]

        service = _make_service(backend=backend)
        report = await service.info(
            "mylib",
            target_version="2.0.0",
            include_deps=True,
        )

        assert report is not None
        assert report.info.requires_python == ">=3.7"

    async def test_requires_python_unchanged_for_latest(self) -> None:
        """requires_python stays as-is when targeting the latest version."""
        backend = _make_backend()
        latest_info = PackageInfo(
            name="mylib",
            latest_version=Version("3.0.0"),
            version_count=1,
            requires_python=">=3.10",
            registry="pypi.org",
        )
        backend.check.return_value = latest_info

        service = _make_service(backend=backend)
        report = await service.info("mylib")

        assert report is not None
        assert report.info.requires_python == ">=3.10"

    async def test_requires_python_none_for_older_version(self) -> None:
        """requires_python becomes None when the old version has no constraint."""
        backend = _make_backend()
        latest_info = PackageInfo(
            name="mylib",
            latest_version=Version("3.0.0"),
            version_count=2,
            requires_python=">=3.10",
            registry="pypi.org",
        )
        backend.check.return_value = latest_info
        backend.versions.return_value = [
            VersionInfo(version=Version("3.0.0")),
            VersionInfo(version=Version("1.0.0")),
        ]
        # Old version files have no requires_python
        backend.files.return_value = [
            FileInfo(
                filename="mylib-1.0.0.tar.gz",
                url="https://example.com/mylib-1.0.0.tar.gz",
                dist_type=DistType.SDIST,
            ),
        ]

        service = _make_service(backend=backend)
        report = await service.info(
            "mylib",
            target_version="1.0.0",
            include_vulns=True,
        )

        assert report is not None
        assert report.info.requires_python is None


# ===================================================================
# Tests: PackageService.info() — orchestration
# ===================================================================


class TestInfoOrchestration:
    """Test `PackageService.info` orchestration paths."""

    async def test_include_versions(self) -> None:
        """Version list is included when include_versions=True."""
        backend = _make_backend()
        latest_info = PackageInfo(
            name="mylib",
            latest_version=Version("3.0.0"),
            version_count=3,
            registry="pypi.org",
        )
        backend.check.return_value = latest_info
        versions_list = [
            VersionInfo(version=Version("3.0.0")),
            VersionInfo(version=Version("2.0.0")),
            VersionInfo(version=Version("1.0.0")),
        ]
        backend.versions.return_value = versions_list

        service = _make_service(backend=backend)
        report = await service.info("mylib", include_versions=True)

        assert report is not None
        assert report.versions is not None
        assert len(report.versions) == 3
        assert report.versions_total == 3

    async def test_include_vulns(self) -> None:
        """Vulnerability report is included when include_vulns=True."""
        backend = _make_backend()
        latest_info = PackageInfo(
            name="mylib",
            latest_version=Version("2.0.0"),
            version_count=1,
            registry="pypi.org",
        )
        backend.check.return_value = latest_info

        mock_report = VulnerabilityReport(
            package="mylib", version="2.0.0", vulnerabilities=[]
        )

        service = _make_service(backend=backend)
        with patch.object(
            service,
            "check_vulnerabilities",
            new=AsyncMock(return_value=mock_report),
        ):
            report = await service.info("mylib", include_vulns=True)

        assert report is not None
        assert report.vulnerabilities is not None
        assert report.vulnerabilities.package == "mylib"

    async def test_include_deps(self) -> None:
        """Metadata is included when include_deps=True."""
        backend = _make_backend()
        latest_info = PackageInfo(
            name="mylib",
            latest_version=Version("2.0.0"),
            version_count=1,
            registry="pypi.org",
        )
        backend.check.return_value = latest_info

        meta = PackageMetadata(
            dependencies=[_dep("requests>=2.0")],
            source="pep658",
        )

        service = _make_service(backend=backend)
        with patch.object(
            service,
            "get_metadata",
            new=AsyncMock(return_value=meta),
        ):
            report = await service.info("mylib", include_deps=True)

        assert report is not None
        assert report.metadata is not None
        assert report.metadata.source == "pep658"
        assert report.target_version == "2.0.0"

    async def test_invalid_target_version(self) -> None:
        """Invalid target_version populates errors for vulns and deps."""
        backend = _make_backend()
        latest_info = PackageInfo(
            name="mylib",
            latest_version=Version("2.0.0"),
            version_count=2,
            registry="pypi.org",
        )
        backend.check.return_value = latest_info
        backend.versions.return_value = [
            VersionInfo(version=Version("2.0.0")),
            VersionInfo(version=Version("1.0.0")),
        ]

        service = _make_service(backend=backend)
        report = await service.info(
            "mylib",
            target_version="99.0.0",
            include_vulns=True,
            include_deps=True,
        )

        assert report is not None
        assert report.errors is not None
        assert "vulns" in report.errors
        assert "deps" in report.errors
        assert "99.0.0" in report.errors["vulns"]
        # Metadata and vulns should NOT be populated
        assert report.metadata is None
        assert report.vulnerabilities is None

    async def test_partial_failure_vulns(self) -> None:
        """Vulns task failure populates errors, deps still succeeds."""
        backend = _make_backend()
        latest_info = PackageInfo(
            name="mylib",
            latest_version=Version("2.0.0"),
            version_count=1,
            registry="pypi.org",
        )
        backend.check.return_value = latest_info

        meta = PackageMetadata(
            dependencies=[_dep("click>=7.0")],
            source="wheel",
        )

        service = _make_service(backend=backend)
        with (
            patch.object(
                service,
                "check_vulnerabilities",
                new=AsyncMock(side_effect=Exception("OSV timeout")),
            ),
            patch.object(
                service,
                "get_metadata",
                new=AsyncMock(return_value=meta),
            ),
        ):
            report = await service.info("mylib", include_vulns=True, include_deps=True)

        assert report is not None
        assert report.errors is not None
        assert "vulns" in report.errors
        assert "OSV timeout" in report.errors["vulns"]
        # Deps should still succeed
        assert report.metadata is not None
        assert report.metadata.source == "wheel"

    async def test_partial_failure_deps(self) -> None:
        """Deps task failure populates errors, vulns still succeeds."""
        backend = _make_backend()
        latest_info = PackageInfo(
            name="mylib",
            latest_version=Version("2.0.0"),
            version_count=1,
            registry="pypi.org",
        )
        backend.check.return_value = latest_info

        mock_vuln_report = VulnerabilityReport(
            package="mylib", version="2.0.0", vulnerabilities=[]
        )

        service = _make_service(backend=backend)
        with (
            patch.object(
                service,
                "check_vulnerabilities",
                new=AsyncMock(return_value=mock_vuln_report),
            ),
            patch.object(
                service,
                "get_metadata",
                new=AsyncMock(side_effect=Exception("Download failed")),
            ),
        ):
            report = await service.info("mylib", include_vulns=True, include_deps=True)

        assert report is not None
        assert report.errors is not None
        assert "deps" in report.errors
        assert "Download failed" in report.errors["deps"]
        # Vulns should still succeed
        assert report.vulnerabilities is not None

    async def test_package_not_found_returns_none(self) -> None:
        """Return None when package does not exist."""
        backend = _make_backend()
        backend.check.return_value = None
        service = _make_service(backend=backend)

        report = await service.info("nonexistent")

        assert report is None
