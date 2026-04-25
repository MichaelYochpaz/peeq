"""Tests for fetch_pep658_metadata()."""

from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING

import pytest

from peeq.metadata.pep658 import fetch_pep658_metadata
from peeq.models import HashDigest
from tests.test_metadata.conftest import (
    SAMPLE_METADATA,
    make_mock_backend,
    make_mock_response,
    make_sdist_file_info,
    make_wheel_file_info,
)

if TYPE_CHECKING:
    from unittest.mock import AsyncMock


class TestFetchPep658Metadata:
    """Test PEP 658 metadata fetching."""

    @pytest.fixture
    def backend(self) -> AsyncMock:
        return make_mock_backend()

    async def test_happy_path(self, backend: AsyncMock) -> None:
        """Fetch and parse PEP 658 metadata successfully."""
        wheel = make_wheel_file_info(metadata_available=True)
        backend.files.return_value = [wheel]
        backend.get_with_retry.return_value = make_mock_response()

        result = await fetch_pep658_metadata(backend, "test-package", "1.0.0")

        assert result is not None
        assert result.source == "pep658"
        assert result.summary == "A test package for unit tests"
        assert result.author == "Test Author"
        assert result.python_requires == ">=3.8"
        assert result.dependencies is not None
        assert len(result.dependencies) == 3

    async def test_metadata_url_constructed_correctly(
        self,
        backend: AsyncMock,
    ) -> None:
        """The metadata URL is {file_url}.metadata."""
        url = "https://files.example.com/pkg-1.0.0-py3-none-any.whl"
        wheel = make_wheel_file_info(url=url, metadata_available=True)
        backend.files.return_value = [wheel]
        backend.get_with_retry.return_value = make_mock_response()

        await fetch_pep658_metadata(backend, "pkg", "1.0.0")

        backend.get_with_retry.assert_awaited_once_with(
            f"{url}.metadata",
        )

    async def test_no_metadata_available_returns_none(
        self,
        backend: AsyncMock,
    ) -> None:
        """Return None when no wheel has metadata_available=True."""
        wheel = make_wheel_file_info(metadata_available=False)
        backend.files.return_value = [wheel]

        result = await fetch_pep658_metadata(backend, "pkg", "1.0.0")

        assert result is None
        backend.get_with_retry.assert_not_awaited()

    async def test_no_files_returns_none(self, backend: AsyncMock) -> None:
        """Return None when files() returns an empty list."""
        backend.files.return_value = []

        result = await fetch_pep658_metadata(backend, "pkg", "1.0.0")

        assert result is None

    async def test_files_raises_returns_none(self, backend: AsyncMock) -> None:
        """Return None when files() raises an exception."""
        backend.files.side_effect = RuntimeError("network error")

        result = await fetch_pep658_metadata(backend, "pkg", "1.0.0")

        assert result is None

    async def test_http_failure_returns_none(self, backend: AsyncMock) -> None:
        """Return None on non-success HTTP response."""
        wheel = make_wheel_file_info(metadata_available=True)
        backend.files.return_value = [wheel]
        backend.get_with_retry.return_value = make_mock_response(
            is_success=False,
            status_code=404,
        )

        result = await fetch_pep658_metadata(backend, "pkg", "1.0.0")

        assert result is None

    async def test_http_exception_returns_none(self, backend: AsyncMock) -> None:
        """Return None when the HTTP request raises an exception."""
        wheel = make_wheel_file_info(metadata_available=True)
        backend.files.return_value = [wheel]
        backend.get_with_retry.side_effect = RuntimeError("connection failed")

        result = await fetch_pep658_metadata(backend, "pkg", "1.0.0")

        assert result is None

    async def test_hash_verification_passes(self, backend: AsyncMock) -> None:
        """Metadata is accepted when hash verification passes."""
        content = SAMPLE_METADATA.encode("utf-8")
        expected_hash = hashlib.sha256(content).hexdigest()

        wheel = make_wheel_file_info(
            metadata_available=True,
            metadata_hash=HashDigest(sha256=expected_hash, source="registry"),
        )
        backend.files.return_value = [wheel]
        backend.get_with_retry.return_value = make_mock_response()

        result = await fetch_pep658_metadata(backend, "pkg", "1.0.0")

        assert result is not None
        assert result.source == "pep658"

    async def test_hash_verification_fails(self, backend: AsyncMock) -> None:
        """Return None when metadata hash doesn't match."""
        wheel = make_wheel_file_info(
            metadata_available=True,
            metadata_hash=HashDigest(sha256="wrong_hash", source="registry"),
        )
        backend.files.return_value = [wheel]
        backend.get_with_retry.return_value = make_mock_response()

        result = await fetch_pep658_metadata(backend, "pkg", "1.0.0")

        assert result is None

    async def test_prefers_pure_python_wheel(self, backend: AsyncMock) -> None:
        """Select py3-none-any wheel over platform-specific."""
        platform_wheel = make_wheel_file_info(
            filename="pkg-1.0.0-cp312-cp312-manylinux_x86_64.whl",
            url="https://files.example.com/pkg-1.0.0-cp312.whl",
            metadata_available=True,
            size=50000,
        )
        pure_wheel = make_wheel_file_info(
            filename="pkg-1.0.0-py3-none-any.whl",
            url="https://files.example.com/pkg-1.0.0-py3.whl",
            metadata_available=True,
            size=5000,
        )
        backend.files.return_value = [platform_wheel, pure_wheel]
        backend.get_with_retry.return_value = make_mock_response()

        await fetch_pep658_metadata(backend, "pkg", "1.0.0")

        # Should have fetched from the pure Python wheel URL
        backend.get_with_retry.assert_awaited_once_with(
            "https://files.example.com/pkg-1.0.0-py3.whl.metadata",
        )

    async def test_falls_back_to_platform_wheel(self, backend: AsyncMock) -> None:
        """Use platform-specific wheel when no pure Python wheel exists."""
        platform_wheel = make_wheel_file_info(
            filename="pkg-1.0.0-cp312-cp312-manylinux_x86_64.whl",
            url="https://files.example.com/pkg-1.0.0-cp312.whl",
            metadata_available=True,
            size=50000,
        )
        backend.files.return_value = [platform_wheel]
        backend.get_with_retry.return_value = make_mock_response()

        result = await fetch_pep658_metadata(backend, "pkg", "1.0.0")

        assert result is not None

    async def test_yanked_wheels_skipped(self, backend: AsyncMock) -> None:
        """Yanked wheels are not considered."""
        yanked_wheel = make_wheel_file_info(
            metadata_available=True,
            yanked=True,
        )
        backend.files.return_value = [yanked_wheel]

        result = await fetch_pep658_metadata(backend, "pkg", "1.0.0")

        assert result is None
        backend.get_with_retry.assert_not_awaited()

    async def test_sdist_files_ignored(self, backend: AsyncMock) -> None:
        """Sdist files are ignored (PEP 658 is wheel-only)."""
        sdist = make_sdist_file_info()
        backend.files.return_value = [sdist]

        result = await fetch_pep658_metadata(backend, "pkg", "1.0.0")

        assert result is None

    async def test_no_hash_skips_verification(self, backend: AsyncMock) -> None:
        """When no metadata_hash is set, skip hash verification."""
        wheel = make_wheel_file_info(
            metadata_available=True,
            metadata_hash=None,
        )
        backend.files.return_value = [wheel]
        backend.get_with_retry.return_value = make_mock_response()

        result = await fetch_pep658_metadata(backend, "pkg", "1.0.0")

        assert result is not None
