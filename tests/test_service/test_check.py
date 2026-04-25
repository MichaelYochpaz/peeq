"""Tests for `PackageService.check`."""

from __future__ import annotations

from packaging.version import Version

from peeq.models import PackageInfo, VersionInfo
from tests.test_service.conftest import _make_backend, _make_cache, _make_service


class TestCheck:
    """Test `PackageService.check`."""

    async def test_cache_hit(self) -> None:
        cache = _make_cache()
        cache.get_package.return_value = {
            "name": "requests",
            "latest_version": "2.31.0",
            "summary": "HTTP for Humans",
            "available_versions": '["2.31.0", "2.30.0", "2.29.0"]',
        }
        service = _make_service(cache=cache)

        result = await service.check("requests")

        assert result is not None
        assert result.name == "requests"
        assert result.latest_version == Version("2.31.0")
        assert result.version_count == 3
        assert result.summary == "HTTP for Humans"

    async def test_cache_hit_no_latest_version(self) -> None:
        cache = _make_cache()
        cache.get_package.return_value = {
            "name": "empty",
            "latest_version": None,
            "available_versions": None,
        }
        service = _make_service(cache=cache)

        assert await service.check("empty") is None

    async def test_cache_miss_fetches_backend(self) -> None:
        backend = _make_backend()
        info = PackageInfo(
            name="requests",
            latest_version=Version("2.31.0"),
            version_count=142,
            summary="HTTP for Humans",
            registry="pypi.org",
        )
        backend.check.return_value = info
        backend.versions.return_value = [
            VersionInfo(version=Version("2.31.0")),
            VersionInfo(version=Version("2.30.0")),
        ]

        cache = _make_cache()
        service = _make_service(cache=cache, backend=backend)

        result = await service.check("requests")

        assert result is info
        cache.upsert_package.assert_called_once()
        call_kwargs = cache.upsert_package.call_args.kwargs
        assert call_kwargs["name"] == "requests"
        assert call_kwargs["latest_version"] == "2.31.0"
        assert call_kwargs["available_versions"] == ["2.31.0", "2.30.0"]

    async def test_package_not_found(self) -> None:
        backend = _make_backend()
        backend.check.return_value = None
        service = _make_service(backend=backend)

        assert await service.check("nonexistent") is None
