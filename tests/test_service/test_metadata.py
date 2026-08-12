"""Tests for `PackageService.get_metadata` and related helpers.

Covers the full metadata resolution fallback chain: cache hit,
PEP 658 (https://peps.python.org/pep-0658/), sdist extraction,
wheel extraction, and tag-based variant selection.
"""

from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING

import pytest

from peeq.cache import HashMismatchError
from peeq.models import (
    DistType,
    DownloadResult,
    FileInfo,
    HashDigest,
    PackageMetadata,
)
from peeq.resolver.provider import MetadataFetcher
from peeq.service import (
    TagNotFoundError,
    _extract_wheel_tag,
    _select_best_wheel,
)
from tests.test_service.conftest import (
    _SAMPLE_METADATA_DYNAMIC_TEXT,
    _dep,
    _download_side_effect,
    _make_backend,
    _make_cache,
    _make_sdist_bytes,
    _make_service,
    _make_wheel_bytes,
    _mock_response,
    _sdist_fi,
    _wheel_fi,
)

if TYPE_CHECKING:
    from pathlib import Path

# ===================================================================
# Tests: module-level helpers
# ===================================================================


class TestSelectBestWheel:
    """Test `_select_best_wheel`."""

    def test_prefers_pure_python(self) -> None:
        pure = _wheel_fi(filename="pkg-1.0.0-py3-none-any.whl", size=1000)
        platform = _wheel_fi(
            filename="pkg-1.0.0-cp312-cp312-manylinux.whl",
            size=500,
        )
        assert _select_best_wheel([platform, pure]) is pure

    def test_falls_back_to_smallest(self) -> None:
        big = _wheel_fi(
            filename="pkg-1.0.0-cp312-cp312-linux.whl",
            size=5000,
        )
        small = _wheel_fi(
            filename="pkg-1.0.0-cp312-cp312-win.whl",
            size=1000,
        )
        assert _select_best_wheel([big, small]) is small

    def test_size_none_deprioritized(self) -> None:
        """Unknown-size wheels sort after known-size wheels."""
        no_size = _wheel_fi(
            filename="pkg-1.0.0-cp312-cp312-linux.whl",
            size=None,
        )
        with_size = _wheel_fi(
            filename="pkg-1.0.0-cp312-cp312-win.whl",
            size=100,
        )
        assert _select_best_wheel([with_size, no_size]) is with_size


class TestExtractWheelTag:
    """Test `_extract_wheel_tag`."""

    @pytest.mark.parametrize(
        ("filename", "expected"),
        [
            ("numpy-1.26.0-cp312-cp312-win_amd64.whl", "cp312-cp312-win_amd64"),
            ("requests-2.31.0-py3-none-any.whl", "py3-none-any"),
            ("pkg-1.0.0-1-py3-none-any.whl", "py3-none-any"),
            ("pkg-1.0.0.tar.gz", None),
            ("pkg.whl", None),
        ],
    )
    def test_extract_wheel_tag(self, filename: str, expected: str | None) -> None:
        assert _extract_wheel_tag(filename) == expected


# ===================================================================
# Tests: PackageService.get_metadata() — cache hit
# ===================================================================


class TestGetMetadataCacheHit:
    """Cache hit returns immediately without backend calls."""

    async def test_cache_hit_returns_metadata(self) -> None:
        cache = _make_cache()
        meta = PackageMetadata(
            dependencies=[_dep("requests>=2.0")],
            source="pep658",
        )
        cache.get_metadata.return_value = meta

        service = _make_service(cache=cache)
        result = await service.get_metadata("pkg", "1.0.0")

        assert result is meta
        # Backend should not be called
        service._backend.files.assert_not_awaited()  # ty: ignore[unresolved-attribute]


# ===================================================================
# Tests: PackageService.get_metadata() — PEP 658
# ===================================================================


class TestGetMetadataPep658:
    """PEP 658 (https://peps.python.org/pep-0658/) metadata path (no artifact download)."""

    async def test_pep658_success(self) -> None:
        backend = _make_backend()
        wheel = _wheel_fi(
            metadata_available=True,
            sha256="wheel_sha256",
        )
        backend.files.return_value = [wheel]
        backend.get_with_retry.return_value = _mock_response()

        cache = _make_cache()
        service = _make_service(cache=cache, backend=backend)
        result = await service.get_metadata("pkg", "1.0.0")

        assert result is not None
        assert result.source == "pep658"
        assert result.source_filename == wheel.filename
        assert result.dependencies is not None
        assert len(result.dependencies) == 2
        cache.save_metadata.assert_called_once()
        assert cache.save_metadata.call_args.kwargs["filename"] == wheel.filename

    async def test_pep658_no_metadata_available(self) -> None:
        """No wheels have `metadata_available` — full fallback returns None."""
        backend = _make_backend()
        backend.files.return_value = [
            _wheel_fi(metadata_available=False),
        ]
        cache = _make_cache()
        service = _make_service(cache=cache, backend=backend)

        result = await service.get_metadata("pkg", "1.0.0")

        assert result is None
        # PEP 658 path was correctly skipped (no HTTP fetch attempted)
        backend.get_with_retry.assert_not_awaited()

    async def test_pep658_http_failure(self) -> None:
        backend = _make_backend()
        backend.files.return_value = [
            _wheel_fi(metadata_available=True),
        ]
        backend.get_with_retry.return_value = _mock_response(
            is_success=False,
            status_code=404,
        )
        service = _make_service(backend=backend)

        result = await service.get_metadata("pkg", "1.0.0")

        assert result is None

    async def test_pep658_hash_mismatch(self) -> None:
        backend = _make_backend()
        backend.files.return_value = [
            _wheel_fi(
                metadata_available=True,
                metadata_hash=HashDigest(sha256="wrong", source="registry"),
            ),
        ]
        backend.get_with_retry.return_value = _mock_response()
        service = _make_service(backend=backend)

        result = await service.get_metadata("pkg", "1.0.0")

        assert result is None

    async def test_pep658_no_wheel_hash_skips_cache(self) -> None:
        """Wheel without hash: metadata returned but not cached."""
        backend = _make_backend()
        wheel = FileInfo(
            filename="pkg-1.0.0-py3-none-any.whl",
            url="https://example.com/pkg-1.0.0-py3-none-any.whl",
            hash=None,
            dist_type=DistType.WHEEL,
            metadata_available=True,
        )
        backend.files.return_value = [wheel]
        backend.get_with_retry.return_value = _mock_response()

        cache = _make_cache()
        service = _make_service(cache=cache, backend=backend)
        result = await service.get_metadata("pkg", "1.0.0")

        assert result is not None
        assert result.source == "pep658"
        cache.save_metadata.assert_not_called()


# ===================================================================
# Tests: PackageService.get_metadata() — sdist extraction
# ===================================================================


class TestGetMetadataSdist:
    """Sdist extraction path (PEP 658 (https://peps.python.org/pep-0658/) unavailable)."""

    async def test_sdist_success(self) -> None:
        sdist_bytes = _make_sdist_bytes()
        backend = _make_backend()
        backend.files.return_value = [_sdist_fi()]
        backend.download.side_effect = _download_side_effect(sdist_bytes)

        cache = _make_cache()
        service = _make_service(cache=cache, backend=backend)
        result = await service.get_metadata("pkg", "1.0.0")

        assert result is not None
        assert result.source == "sdist"
        assert result.source_filename == "test-package-1.0.0.tar.gz"
        assert result.dependencies is not None
        assert len(result.dependencies) == 2
        cache.store_archive.assert_called_once()

    async def test_sdist_dynamic_deps_falls_through(self) -> None:
        """Sdist with Dynamic Requires-Dist → fall through to wheel."""
        sdist_bytes = _make_sdist_bytes(_SAMPLE_METADATA_DYNAMIC_TEXT)
        wheel_bytes = _make_wheel_bytes()

        sdist = _sdist_fi(sha256="sdist_sha")
        wheel = _wheel_fi(sha256="wheel_sha")

        backend = _make_backend()
        backend.files.return_value = [sdist, wheel]

        call_count = 0

        async def _dl(
            fi: FileInfo,
            dest: Path,
            **_kwargs: object,
        ) -> DownloadResult:
            nonlocal call_count
            call_count += 1
            data = sdist_bytes if fi.dist_type == DistType.SDIST else wheel_bytes
            computed = hashlib.sha256(data).hexdigest()
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(data)
            return DownloadResult(
                path=dest,
                hash=HashDigest(sha256=computed, source="computed"),
                size_bytes=len(data),
            )

        backend.download.side_effect = _dl

        cache = _make_cache()
        service = _make_service(cache=cache, backend=backend)
        result = await service.get_metadata("pkg", "1.0.0")

        # Should have downloaded both sdist and wheel
        assert call_count == 2
        assert result is not None
        assert result.source == "wheel"
        assert result.dependencies is not None
        # Sdist metadata saved (partial) + wheel metadata saved
        assert cache.store_archive.call_count == 1  # sdist stored
        assert cache.save_metadata.call_count == 1  # wheel metadata saved
        assert cache.save_metadata.call_args.kwargs["filename"] == "test_package-1.0.0-py3-none-any.whl"

    async def test_sdist_download_failure(self) -> None:
        backend = _make_backend()
        backend.files.return_value = [_sdist_fi()]
        backend.download.side_effect = Exception("Network error")

        service = _make_service(backend=backend)
        result = await service.get_metadata("pkg", "1.0.0")

        assert result is None

    async def test_sdist_hash_mismatch(self) -> None:
        backend = _make_backend()
        backend.files.return_value = [_sdist_fi()]
        # Download succeeds but store_archive fails hash check
        sdist_bytes = _make_sdist_bytes()
        backend.download.side_effect = _download_side_effect(sdist_bytes)

        cache = _make_cache()
        cache.store_archive.side_effect = HashMismatchError("mismatch")
        service = _make_service(cache=cache, backend=backend)

        result = await service.get_metadata("pkg", "1.0.0")

        assert result is None


# ===================================================================
# Tests: PackageService.get_metadata() — wheel extraction
# ===================================================================


class TestGetMetadataWheel:
    """Wheel extraction path (PEP 658 (https://peps.python.org/pep-0658/) unavailable, no sdist)."""

    async def test_wheel_success(self) -> None:
        wheel_bytes = _make_wheel_bytes()
        backend = _make_backend()
        backend.files.return_value = [_wheel_fi()]
        backend.download.side_effect = _download_side_effect(wheel_bytes)

        cache = _make_cache()
        service = _make_service(cache=cache, backend=backend)
        result = await service.get_metadata("pkg", "1.0.0")

        assert result is not None
        assert result.source == "wheel"
        assert result.source_filename == "test_package-1.0.0-py3-none-any.whl"
        assert result.dependencies is not None
        cache.save_metadata.assert_called_once()
        assert cache.save_metadata.call_args.kwargs["filename"] == "test_package-1.0.0-py3-none-any.whl"

    async def test_wheel_download_failure(self) -> None:
        backend = _make_backend()
        backend.files.return_value = [_wheel_fi()]
        backend.download.side_effect = Exception("download error")

        cache = _make_cache()
        service = _make_service(cache=cache, backend=backend)
        result = await service.get_metadata("pkg", "1.0.0")

        # Falls through to final cache lookup
        assert result is None
        # Final cache lookup attempted
        assert cache.get_metadata.call_count == 2


# ===================================================================
# Tests: PackageService.get_metadata() — full fallback chain
# ===================================================================


class TestGetMetadataFullFallback:
    """End-to-end fallback chain."""

    async def test_all_fail_returns_none(self) -> None:
        backend = _make_backend()
        backend.files.return_value = []  # No files at all
        cache = _make_cache()
        service = _make_service(cache=cache, backend=backend)

        result = await service.get_metadata("pkg", "1.0.0")

        assert result is None

    async def test_backend_files_error(self) -> None:
        backend = _make_backend()
        backend.files.side_effect = Exception("API error")
        service = _make_service(backend=backend)

        result = await service.get_metadata("pkg", "1.0.0")

        assert result is None

    async def test_pep658_fail_sdist_success(self) -> None:
        """PEP 658 (https://peps.python.org/pep-0658/) unavailable → sdist extraction succeeds."""
        sdist_bytes = _make_sdist_bytes()
        backend = _make_backend()
        sdist = _sdist_fi()
        wheel_no_meta = _wheel_fi(metadata_available=False)
        backend.files.return_value = [sdist, wheel_no_meta]
        backend.download.side_effect = _download_side_effect(sdist_bytes)

        cache = _make_cache()
        service = _make_service(cache=cache, backend=backend)
        result = await service.get_metadata("pkg", "1.0.0")

        assert result is not None
        assert result.source == "sdist"

    async def test_final_cache_lookup_returns_partial(self) -> None:
        """When wheel fails, return partial sdist from cache."""
        sdist_bytes = _make_sdist_bytes(_SAMPLE_METADATA_DYNAMIC_TEXT)
        backend = _make_backend()
        backend.files.return_value = [
            _sdist_fi(),
            _wheel_fi(),  # wheel available but download will fail
        ]

        # Sdist download succeeds
        call_count = 0

        async def _dl(
            fi: FileInfo,
            dest: Path,
            **_kwargs: object,
        ) -> DownloadResult:
            nonlocal call_count
            call_count += 1
            if fi.dist_type == DistType.SDIST:
                data = sdist_bytes
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(data)
                computed = hashlib.sha256(data).hexdigest()
                return DownloadResult(
                    path=dest,
                    hash=HashDigest(sha256=computed, source="computed"),
                    size_bytes=len(data),
                )
            raise Exception("wheel download failed")

        backend.download.side_effect = _dl

        # After sdist is saved (with deps_known=False), the final cache
        # lookup should return the partial metadata
        partial_meta = PackageMetadata(
            dependencies=None,
            source="sdist",
            summary="Dynamic deps",
        )
        cache = _make_cache()
        # First call returns None (no cache), second returns partial
        cache.get_metadata.side_effect = [None, partial_meta]

        service = _make_service(cache=cache, backend=backend)
        result = await service.get_metadata("pkg", "1.0.0")

        assert result is not None
        assert result is partial_meta
        assert result.dependencies is None


# ===================================================================
# Tests: PackageService.get_metadata() — tag variant
# ===================================================================


class TestGetMetadataTag:
    """Test `--tag` parameter for wheel variant selection."""

    async def test_tag_found_pep658(self) -> None:
        backend = _make_backend()
        target_wheel = _wheel_fi(
            filename="pkg-1.0.0-cp312-cp312-win_amd64.whl",
            metadata_available=True,
            sha256="target_sha",
        )
        other_wheel = _wheel_fi(
            filename="pkg-1.0.0-py3-none-any.whl",
            sha256="other_sha",
        )
        backend.files.return_value = [target_wheel, other_wheel]
        backend.get_with_retry.return_value = _mock_response()

        cache = _make_cache()
        service = _make_service(cache=cache, backend=backend)
        result = await service.get_metadata(
            "pkg",
            "1.0.0",
            tag="cp312-cp312-win_amd64",
        )

        assert result is not None
        assert result.source == "pep658"
        assert result.source_filename == target_wheel.filename
        cache.save_metadata.assert_called_once()
        assert cache.save_metadata.call_args.kwargs["filename"] == target_wheel.filename

    async def test_tag_found_download(self) -> None:
        """Tag matches wheel without PEP 658 → downloads and extracts."""
        wheel_bytes = _make_wheel_bytes()
        backend = _make_backend()
        target_wheel = _wheel_fi(
            filename="pkg-1.0.0-cp312-cp312-linux.whl",
            metadata_available=False,
            sha256="target_sha",
        )
        backend.files.return_value = [target_wheel]
        backend.download.side_effect = _download_side_effect(wheel_bytes)

        cache = _make_cache()
        service = _make_service(cache=cache, backend=backend)
        result = await service.get_metadata(
            "pkg",
            "1.0.0",
            tag="cp312-cp312-linux",
        )

        assert result is not None
        assert result.source == "wheel"
        assert result.source_filename == "pkg-1.0.0-cp312-cp312-linux.whl"
        cache.save_metadata.assert_called_once()
        assert cache.save_metadata.call_args.kwargs["filename"] == "pkg-1.0.0-cp312-cp312-linux.whl"

    async def test_tag_not_found(self) -> None:
        backend = _make_backend()
        backend.files.return_value = [
            _wheel_fi(filename="pkg-1.0.0-py3-none-any.whl"),
        ]
        service = _make_service(backend=backend)

        with pytest.raises(TagNotFoundError) as exc_info:
            await service.get_metadata(
                "pkg",
                "1.0.0",
                tag="cp312-cp312-win_amd64",
            )

        assert "py3-none-any" in exc_info.value.available_tags

    async def test_tag_skips_yanked(self) -> None:
        backend = _make_backend()
        backend.files.return_value = [
            _wheel_fi(
                filename="pkg-1.0.0-cp312-cp312-linux.whl",
                yanked=True,
            ),
        ]
        service = _make_service(backend=backend)

        with pytest.raises(TagNotFoundError):
            await service.get_metadata(
                "pkg",
                "1.0.0",
                tag="cp312-cp312-linux",
            )

    async def test_tag_bypasses_cache(self) -> None:
        """Tag queries don't use the generic cache lookup."""
        backend = _make_backend()
        backend.files.return_value = [
            _wheel_fi(
                filename="pkg-1.0.0-cp312-cp312-linux.whl",
                metadata_available=True,
                sha256="wheel_sha",
            ),
        ]
        backend.get_with_retry.return_value = _mock_response()

        cache = _make_cache()
        # Cache has metadata but tag should bypass it
        cache.get_metadata.return_value = PackageMetadata(
            source="pep658",
        )
        service = _make_service(cache=cache, backend=backend)

        result = await service.get_metadata(
            "pkg",
            "1.0.0",
            tag="cp312-cp312-linux",
        )

        # Should NOT use cache metadata — fetched fresh for the specific tag
        assert result is not None
        assert result.source_filename == "pkg-1.0.0-cp312-cp312-linux.whl"
        # Cache lookup was not consulted for tag queries
        cache.get_metadata.assert_not_called()


# ===================================================================
# Tests: MetadataFetcher protocol
# ===================================================================


class TestMetadataFetcherProtocol:
    """`PackageService` satisfies the `MetadataFetcher` protocol."""

    def test_satisfies_protocol(self) -> None:
        """Verify `PackageService` is a `MetadataFetcher`."""
        service = _make_service()
        assert isinstance(service, MetadataFetcher)


# ===================================================================
# Tests: edge cases
# ===================================================================


class TestEdgeCases:
    """Miscellaneous edge cases."""

    def test_registry_property(self) -> None:
        """Return the backend's registry identifier."""
        backend = _make_backend(registry="test.pypi.org")
        service = _make_service(backend=backend)
        assert service.registry == "test.pypi.org"

    async def test_pep658_prefers_pure_python(self) -> None:
        """PEP 658 (https://peps.python.org/pep-0658/) selects py3-none-any over platform-specific wheels."""
        backend = _make_backend()
        pure = _wheel_fi(
            filename="pkg-1.0.0-py3-none-any.whl",
            metadata_available=True,
            sha256="pure_sha",
            size=1000,
        )
        platform_wheel = _wheel_fi(
            filename="pkg-1.0.0-cp312-cp312-linux.whl",
            metadata_available=True,
            sha256="platform_sha",
            size=500,
        )
        backend.files.return_value = [platform_wheel, pure]
        backend.get_with_retry.return_value = _mock_response()

        cache = _make_cache()
        service = _make_service(cache=cache, backend=backend)
        result = await service.get_metadata("pkg", "1.0.0")

        assert result is not None
        assert result.source_filename == pure.filename

    async def test_pep658_skips_yanked_wheels(self) -> None:
        """Yanked wheels are excluded from PEP 658 (https://peps.python.org/pep-0658/) candidates."""
        backend = _make_backend()
        backend.files.return_value = [
            _wheel_fi(
                metadata_available=True,
                yanked=True,
            ),
        ]
        service = _make_service(backend=backend)

        result = await service.get_metadata("pkg", "1.0.0")

        assert result is None
        # PEP 658 path was correctly skipped (no HTTP fetch attempted)
        backend.get_with_retry.assert_not_awaited()

    async def test_sdist_dynamic_requires_dist_sets_deps_known_false(self) -> None:
        """Verify that Dynamic `Requires-Dist` sets `deps_known=False`."""
        sdist_bytes = _make_sdist_bytes(_SAMPLE_METADATA_DYNAMIC_TEXT)
        backend = _make_backend()
        backend.files.return_value = [_sdist_fi()]
        backend.download.side_effect = _download_side_effect(sdist_bytes)

        cache = _make_cache()
        service = _make_service(cache=cache, backend=backend)
        await service.get_metadata("pkg", "1.0.0")

        # store_archive called with deps_known=False because
        # Requires-Dist is Dynamic in the sdist PKG-INFO.
        call_kwargs = cache.store_archive.call_args.kwargs
        assert call_kwargs["deps_known"] is False
