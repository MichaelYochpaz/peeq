"""Tests for `PackageService.versions` and `PackageService.files`."""

from __future__ import annotations

from packaging.version import Version

from peeq.models import VersionInfo
from tests.test_service.conftest import _make_backend, _make_service, _wheel_fi


class TestVersionsAndFiles:
    """Test delegation to backend for `versions` and `files`."""

    async def test_versions_delegates(self) -> None:
        backend = _make_backend()
        backend.versions.return_value = [
            VersionInfo(version=Version("2.0.0")),
            VersionInfo(version=Version("1.0.0")),
        ]
        service = _make_service(backend=backend)

        result = await service.versions("pkg")

        assert result == [
            VersionInfo(version=Version("2.0.0")),
            VersionInfo(version=Version("1.0.0")),
        ]
        backend.versions.assert_awaited_once_with("pkg")

    async def test_files_delegates(self) -> None:
        backend = _make_backend()
        fi = _wheel_fi()
        backend.files.return_value = [fi]
        service = _make_service(backend=backend)

        result = await service.files("pkg", "1.0.0")

        assert result == [fi]
        backend.files.assert_awaited_once_with("pkg", "1.0.0")
