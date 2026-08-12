"""Tests for the backend base class and shared helpers."""

from __future__ import annotations

import hashlib
import socket
from typing import TYPE_CHECKING
from unittest.mock import AsyncMock, patch

import httpx
import pytest
import respx
from packaging.version import Version

from peeq.backends.base import (
    BackendError,
    PackageRepository,
    ResponseTooLargeError,
    _check_response_size,
    _parse_origin,
    _regex_version_fallback,
    _validate_url_not_internal,
    determine_dist_type,
    extract_hostname,
    parse_version_from_filename,
)
from peeq.backends.pypi import PyPIRepository
from peeq.backends.simple import SimpleRepository
from peeq.models import (
    DistType,
    DownloadResult,
    FileInfo,
    HashDigest,
    PackageInfo,
    VersionInfo,
)

if TYPE_CHECKING:
    from pathlib import Path

# ---------------------------------------------------------------------------
# Concrete subclass for testing
# ---------------------------------------------------------------------------


class _StubBackend(PackageRepository):
    """Minimal concrete subclass for testing the ABC."""

    backend_id = "stub"

    async def check(self, name: str) -> PackageInfo | None:
        return None

    async def versions(self, name: str) -> list[VersionInfo]:
        return []

    async def files(self, name: str, version: str) -> list[FileInfo]:
        return []

    async def download(
        self,
        file: FileInfo,
        dest: Path,
        *,
        max_download_bytes: int = 500 * 1024 * 1024,
    ) -> DownloadResult:
        return await self._download_file(
            file.url,
            dest,
            expected_hash=file.hash,
            max_download_bytes=max_download_bytes,
        )


# ---------------------------------------------------------------------------
# Auto-registration
# ---------------------------------------------------------------------------


class TestAutoRegistration:
    def test_stub_registered(self):
        assert PackageRepository.get_backend_class("stub") is _StubBackend

    def test_pypi_registered(self):
        assert PackageRepository.get_backend_class("pypi") is PyPIRepository

    def test_simple_registered(self):
        assert PackageRepository.get_backend_class("simple") is SimpleRepository


# ---------------------------------------------------------------------------
# Constructor and properties
# ---------------------------------------------------------------------------


class TestConstructor:
    def test_base_url_trailing_slash_stripped(self):
        backend = _StubBackend(base_url="https://example.com/simple/")
        assert backend.base_url == "https://example.com/simple"

    def test_registry_from_url(self):
        backend = _StubBackend(base_url="https://pypi.org/simple")
        assert backend.registry == "pypi.org"

    def test_registry_explicit_override(self):
        backend = _StubBackend(
            base_url="https://proxy.internal/simple",
            registry="internal",
        )
        assert backend.registry == "internal"

    def test_client_not_available_outside_context(self):
        backend = _StubBackend(base_url="https://example.com")
        with pytest.raises(RuntimeError, match="async context manager"):
            _ = backend.client


# ---------------------------------------------------------------------------
# Async context manager
# ---------------------------------------------------------------------------


class TestAsyncContextManager:
    async def test_client_available_inside_context(self):
        backend = _StubBackend(base_url="https://example.com")
        async with backend:
            client = backend.client
            assert isinstance(client, httpx.AsyncClient)
            assert "peeq/" in client.headers["user-agent"]

    async def test_client_none_after_exit(self):
        backend = _StubBackend(base_url="https://example.com")
        async with backend:
            pass
        with pytest.raises(RuntimeError, match="async context manager"):
            _ = backend.client


# ---------------------------------------------------------------------------
# _download_file
# ---------------------------------------------------------------------------


class TestDownloadFile:
    @respx.mock
    async def test_download_success(self, tmp_path: Path):
        content = b"hello world package data"
        expected_hash = hashlib.sha256(content).hexdigest()

        respx.get("https://files.example.com/pkg-1.0.tar.gz").mock(
            return_value=httpx.Response(200, content=content),
        )

        backend = _StubBackend(base_url="https://example.com")
        async with backend:
            dest = tmp_path / "downloads" / "pkg-1.0.tar.gz"
            result = await backend._download_file(
                "https://files.example.com/pkg-1.0.tar.gz",
                dest,
            )

        assert result.path == dest
        assert result.hash.sha256 == expected_hash
        assert result.hash.source == "computed"
        assert result.size_bytes == len(content)
        assert dest.read_bytes() == content

    @respx.mock
    async def test_download_creates_parent_dirs(self, tmp_path: Path):
        respx.get("https://files.example.com/pkg-1.0.tar.gz").mock(
            return_value=httpx.Response(200, content=b"data"),
        )

        backend = _StubBackend(base_url="https://example.com")
        async with backend:
            dest = tmp_path / "a" / "b" / "c" / "pkg-1.0.tar.gz"
            result = await backend._download_file(
                "https://files.example.com/pkg-1.0.tar.gz",
                dest,
            )

        assert dest.exists()
        assert result.size_bytes == 4

    @respx.mock
    async def test_download_with_hash_verification_pass(self, tmp_path: Path):
        content = b"verified content"
        sha256 = hashlib.sha256(content).hexdigest()

        respx.get("https://files.example.com/pkg-1.0.tar.gz").mock(
            return_value=httpx.Response(200, content=content),
        )

        backend = _StubBackend(base_url="https://example.com")
        async with backend:
            result = await backend._download_file(
                "https://files.example.com/pkg-1.0.tar.gz",
                tmp_path / "pkg-1.0.tar.gz",
                expected_hash=HashDigest(sha256=sha256, source="registry"),
            )

        assert result.hash.sha256 == sha256
        assert result.hash.source == "registry"

    @respx.mock
    async def test_download_hash_mismatch_removes_file(self, tmp_path: Path):
        respx.get("https://files.example.com/pkg-1.0.tar.gz").mock(
            return_value=httpx.Response(200, content=b"actual content"),
        )

        dest = tmp_path / "pkg-1.0.tar.gz"
        backend = _StubBackend(base_url="https://example.com")
        async with backend:
            with pytest.raises(BackendError, match="SHA-256 mismatch"):
                await backend._download_file(
                    "https://files.example.com/pkg-1.0.tar.gz",
                    dest,
                    expected_hash=HashDigest(
                        sha256="0" * 64,
                        source="registry",
                    ),
                )

        # File should be cleaned up
        assert not dest.exists()

    @respx.mock
    async def test_download_http_error(self, tmp_path: Path):
        respx.get("https://files.example.com/pkg-1.0.tar.gz").mock(
            return_value=httpx.Response(500),
        )

        backend = _StubBackend(base_url="https://example.com")
        async with backend:
            with pytest.raises(httpx.HTTPStatusError):
                await backend._download_file(
                    "https://files.example.com/pkg-1.0.tar.gz",
                    tmp_path / "pkg-1.0.tar.gz",
                )

    @respx.mock
    async def test_download_declared_size_exceeds_limit(self, tmp_path: Path):
        """Pre-flight Content-Length check rejects oversized downloads."""
        respx.get("https://files.example.com/big.tar.gz").mock(
            return_value=httpx.Response(
                200,
                headers={"content-length": "2000"},
                content=b"x" * 2000,
            ),
        )

        dest = tmp_path / "big.tar.gz"
        backend = _StubBackend(base_url="https://example.com")
        async with backend:
            with pytest.raises(BackendError, match="exceeds size limit"):
                await backend._download_file(
                    "https://files.example.com/big.tar.gz",
                    dest,
                    max_download_bytes=1000,
                )

    @respx.mock
    async def test_download_streaming_exceeds_limit(self, tmp_path: Path):
        """Cumulative streaming enforcement rejects oversized downloads.

        Simulates a lying server that declares a small Content-Length
        but actually sends more data than the limit allows.
        """
        respx.get("https://files.example.com/big.tar.gz").mock(
            return_value=httpx.Response(
                200,
                headers={"content-length": "500"},
                content=b"x" * 2000,
            ),
        )

        dest = tmp_path / "big.tar.gz"
        backend = _StubBackend(base_url="https://example.com")
        async with backend:
            with pytest.raises(BackendError, match="exceeded size limit"):
                await backend._download_file(
                    "https://files.example.com/big.tar.gz",
                    dest,
                    max_download_bytes=1000,
                )

        # Partial file should be cleaned up
        assert not dest.exists()

    @respx.mock
    async def test_download_within_limit(self, tmp_path: Path):
        """Download within the size limit succeeds."""
        content = b"small data"
        respx.get("https://files.example.com/small.tar.gz").mock(
            return_value=httpx.Response(200, content=content),
        )

        dest = tmp_path / "small.tar.gz"
        backend = _StubBackend(base_url="https://example.com")
        async with backend:
            result = await backend._download_file(
                "https://files.example.com/small.tar.gz",
                dest,
                max_download_bytes=1000,
            )

        assert result.size_bytes == len(content)
        assert dest.read_bytes() == content


# ---------------------------------------------------------------------------
# follow_redirects
# ---------------------------------------------------------------------------


class TestFollowRedirects:
    async def test_client_follows_redirects(self):
        """The httpx client should follow redirects (e.g., legacy API 301s)."""
        backend = _StubBackend(base_url="https://example.com")
        async with backend:
            assert backend.client.follow_redirects is True


# ---------------------------------------------------------------------------
# extract_hostname
# ---------------------------------------------------------------------------


class TestExtractHostname:
    @pytest.mark.parametrize(
        ("url", "expected"),
        [
            ("https://pypi.org/simple", "pypi.org"),
            ("https://pypi.org:443/simple", "pypi.org"),
            ("pypi.org", "pypi.org"),
            ("https://test.pypi.org/simple", "test.pypi.org"),
            ("http://192.168.1.1:8080/simple", "192.168.1.1"),
        ],
    )
    def test_extract_hostname(self, url: str, expected: str) -> None:
        assert extract_hostname(url) == expected


# ---------------------------------------------------------------------------
# determine_dist_type
# ---------------------------------------------------------------------------


class TestDetermineDistType:
    @pytest.mark.parametrize(
        ("filename", "expected"),
        [
            ("pkg-1.0-py3-none-any.whl", DistType.WHEEL),
            ("pkg-1.0.tar.gz", DistType.SDIST),
            ("pkg-1.0.zip", DistType.SDIST),
            ("pkg-1.0.egg", DistType.SDIST),
            ("pkg-1.0.unknown", DistType.SDIST),
        ],
    )
    def test_determine_dist_type(self, filename: str, expected: DistType) -> None:
        assert determine_dist_type(filename) == expected


# ---------------------------------------------------------------------------
# parse_version_from_filename
# ---------------------------------------------------------------------------


class TestParseVersionFromFilename:
    def test_wheel(self):
        v = parse_version_from_filename(
            "requests-2.31.0-py3-none-any.whl",
        )
        assert v == Version("2.31.0")

    def test_tar_gz(self):
        v = parse_version_from_filename("requests-2.31.0.tar.gz")
        assert v == Version("2.31.0")

    def test_zip(self):
        v = parse_version_from_filename("requests-2.31.0.zip")
        assert v == Version("2.31.0")

    def test_prerelease(self):
        v = parse_version_from_filename(
            "flask-3.0.0rc1-py3-none-any.whl",
        )
        assert v == Version("3.0.0rc1")

    def test_complex_name_with_dashes(self):
        v = parse_version_from_filename(
            "my-cool-package-1.2.3.tar.gz",
        )
        assert v == Version("1.2.3")

    def test_invalid_wheel_returns_none(self):
        assert parse_version_from_filename("not-a-wheel.whl") is None

    def test_unsupported_format_returns_none(self):
        assert parse_version_from_filename("package.rpm") is None

    def test_tar_bz2_fallback(self):
        v = parse_version_from_filename("requests-2.31.0.tar.bz2")
        assert v == Version("2.31.0")

    def test_egg_fallback(self):
        v = parse_version_from_filename("requests-2.31.0.egg")
        assert v == Version("2.31.0")

    def test_completely_unparseable(self):
        assert parse_version_from_filename("readme.txt") is None


# ---------------------------------------------------------------------------
# _regex_version_fallback
# ---------------------------------------------------------------------------


class TestRegexVersionFallback:
    def test_tar_bz2(self):
        v = _regex_version_fallback("package-1.2.3.tar.bz2")
        assert v == Version("1.2.3")

    def test_tar_xz(self):
        v = _regex_version_fallback("package-1.2.3.tar.xz")
        assert v == Version("1.2.3")

    def test_egg(self):
        v = _regex_version_fallback("package-1.2.3.egg")
        assert v == Version("1.2.3")

    def test_unknown_extension(self):
        assert _regex_version_fallback("package-1.2.3.deb") is None

    def test_no_version_in_name(self):
        assert _regex_version_fallback("justname.tar.bz2") is None

    def test_complex_version(self):
        v = _regex_version_fallback("my-lib-2.0.0rc1.tar.bz2")
        assert v == Version("2.0.0rc1")


# ---------------------------------------------------------------------------
# _parse_origin
# ---------------------------------------------------------------------------


class TestParseOrigin:
    def test_http_default_port(self):
        """http://host and http://host:80 produce the same origin."""
        assert _parse_origin("http://localhost/simple") == ("http", "localhost", 80)
        assert _parse_origin("http://localhost:80/simple") == ("http", "localhost", 80)

    def test_https_default_port(self):
        """https://host and https://host:443 produce the same origin."""
        assert _parse_origin("https://pypi.org/simple") == ("https", "pypi.org", 443)
        assert _parse_origin("https://pypi.org:443/simple") == (
            "https",
            "pypi.org",
            443,
        )

    def test_custom_port(self):
        assert _parse_origin("http://localhost:8080/simple") == (
            "http",
            "localhost",
            8080,
        )

    def test_ip_address(self):
        assert _parse_origin("http://192.168.1.50:8080/simple") == (
            "http",
            "192.168.1.50",
            8080,
        )

    def test_path_does_not_affect_origin(self):
        """Different paths on the same host are the same origin."""
        assert _parse_origin("http://localhost:8080/simple") == _parse_origin(
            "http://localhost:8080/packages/foo.tar.gz"
        )


# ---------------------------------------------------------------------------
# Origin-scoped SSRF exemption
# ---------------------------------------------------------------------------


class TestTrustedOriginInit:
    def test_trusted_origin_stored(self):
        backend = _StubBackend(base_url="http://localhost:8080/simple")
        assert backend._trusted_origin == ("http", "localhost", 8080)

    def test_trusted_origin_default_port(self):
        backend = _StubBackend(base_url="https://pypi.org/simple")
        assert backend._trusted_origin == ("https", "pypi.org", 443)


class TestOriginScopedSSRF:
    """Verify that same-origin URLs skip SSRF validation."""

    async def test_same_origin_skips_dns_resolution(self):
        """Same-origin requests bypass DNS resolution entirely."""
        with patch(
            "peeq.backends.base._resolve_and_validate_host",
            new_callable=AsyncMock,
        ) as mock_resolve:
            await _validate_url_not_internal(
                "http://localhost:8080/packages/foo.tar.gz",
                trusted_origin=("http", "localhost", 8080),
            )
            mock_resolve.assert_not_called()

    async def test_different_port_triggers_dns_resolution(self):
        """Different port is a different origin -- triggers validation."""
        with patch(
            "peeq.backends.base._resolve_and_validate_host",
            new_callable=AsyncMock,
        ) as mock_resolve:
            await _validate_url_not_internal(
                "http://localhost:6379/",
                trusted_origin=("http", "localhost", 8080),
            )
            mock_resolve.assert_called_once()

    async def test_different_hostname_triggers_dns_resolution(self):
        """Different hostname is a different origin -- triggers validation."""
        with patch(
            "peeq.backends.base._resolve_and_validate_host",
            new_callable=AsyncMock,
        ) as mock_resolve:
            await _validate_url_not_internal(
                "http://127.0.0.1:8080/packages/foo.tar.gz",
                trusted_origin=("http", "localhost", 8080),
            )
            mock_resolve.assert_called_once()

    async def test_different_scheme_triggers_dns_resolution(self):
        """Different scheme is a different origin -- triggers validation."""
        with patch(
            "peeq.backends.base._resolve_and_validate_host",
            new_callable=AsyncMock,
        ) as mock_resolve:
            await _validate_url_not_internal(
                "https://localhost:8080/packages/foo.tar.gz",
                trusted_origin=("http", "localhost", 8080),
            )
            mock_resolve.assert_called_once()

    async def test_no_trusted_origin_always_validates(self):
        """Without a trusted origin, all URLs are validated."""
        with patch(
            "peeq.backends.base._resolve_and_validate_host",
            new_callable=AsyncMock,
        ) as mock_resolve:
            await _validate_url_not_internal(
                "http://localhost:8080/packages/foo.tar.gz",
            )
            mock_resolve.assert_called_once()

    async def test_same_origin_allows_local_registry(self):
        """Local registry URL is allowed when it matches the trusted origin.

        localhost resolves to 127.0.0.1 (loopback), which would normally
        be blocked.  The origin exemption bypasses the IP check.
        """
        # Should not raise -- origin exemption fires before DNS resolution.
        await _validate_url_not_internal(
            "http://localhost:8080/packages/foo.tar.gz",
            trusted_origin=("http", "localhost", 8080),
        )

    async def test_cross_origin_blocks_local_request(self):
        """Cross-origin local URL is blocked (different port)."""
        # localhost:6379 resolves to 127.0.0.1, which is loopback.
        # Origin mismatch means SSRF check runs and blocks it.
        with pytest.raises(BackendError, match="SSRF"):
            await _validate_url_not_internal(
                "http://localhost:6379/",
                trusted_origin=("http", "localhost", 8080),
            )


# ---------------------------------------------------------------------------
# Integration: SSRF blocking with mocked DNS
# ---------------------------------------------------------------------------


class TestSSRFBlocking:
    """Verify that SSRF validation blocks requests to internal IPs."""

    async def test_blocks_link_local_metadata_ip(self):
        """Block request when DNS resolves to 169.254.169.254 (AWS metadata)."""
        # Simulate DNS returning the AWS metadata endpoint IP.
        fake_addr_info = [(socket.AF_INET, 0, 0, "", ("169.254.169.254", 0))]
        with patch(
            "peeq.backends.base.asyncio.get_running_loop",
        ) as mock_loop:
            mock_loop.return_value.getaddrinfo = AsyncMock(return_value=fake_addr_info)
            with pytest.raises(BackendError, match="SSRF"):
                await _validate_url_not_internal("http://evil-registry.com/latest/meta-data/")

    async def test_blocks_ipv6_mapped_loopback(self):
        """Block request when DNS resolves to ::ffff:127.0.0.1 (IPv6-mapped)."""
        # IPv6-mapped IPv4 loopback must be unwrapped and rejected.
        fake_addr_info = [(socket.AF_INET6, 0, 0, "", ("::ffff:127.0.0.1", 0, 0, 0))]
        with patch(
            "peeq.backends.base.asyncio.get_running_loop",
        ) as mock_loop:
            mock_loop.return_value.getaddrinfo = AsyncMock(return_value=fake_addr_info)
            with pytest.raises(BackendError, match="SSRF"):
                await _validate_url_not_internal("http://evil-registry.com/packages/evil.tar.gz")


# ---------------------------------------------------------------------------
# Integration: SSRF redirect-hook blocking
# ---------------------------------------------------------------------------


class TestSSRFRedirectHook:
    """Verify that the redirect event hook blocks redirects to internal IPs."""

    async def test_redirect_to_internal_ip_blocked(self):
        """302 redirect to an internal IP is blocked by the event hook."""
        backend = _StubBackend(base_url="https://pypi.org/simple")
        client = backend._create_client()
        # Extract the response hook from the client's event hooks.
        hooks = client.event_hooks.get("response", [])
        assert len(hooks) == 1, "Expected exactly one response hook"
        redirect_hook = hooks[0]

        # Build a fake 302 response redirecting to an internal IP.
        redirect_response = httpx.Response(
            status_code=302,
            headers={"location": "http://169.254.169.254/latest/meta-data/"},
            request=httpx.Request("GET", "https://pypi.org/simple/requests/"),
        )
        with pytest.raises(BackendError, match="SSRF"):
            await redirect_hook(redirect_response)

        await client.aclose()

    async def test_redirect_same_origin_allowed(self):
        """302 redirect to same-origin URL is allowed (e.g., name normalization)."""
        backend = _StubBackend(base_url="https://pypi.org/simple")
        client = backend._create_client()
        hooks = client.event_hooks.get("response", [])
        redirect_hook = hooks[0]

        # Same-origin redirect (e.g., /simple/Requests/ → /simple/requests/).
        redirect_response = httpx.Response(
            status_code=301,
            headers={"location": "https://pypi.org/simple/requests/"},
            request=httpx.Request("GET", "https://pypi.org/simple/Requests/"),
        )
        # Should NOT raise — same origin is trusted.
        await redirect_hook(redirect_response)

        await client.aclose()


# ---------------------------------------------------------------------------
# Integration: Response size limit
# ---------------------------------------------------------------------------


class TestResponseSizeLimit:
    """Verify that oversized responses are rejected."""

    def test_oversized_content_length_rejected(self):
        """Response with Content-Length exceeding limit raises error."""
        response = httpx.Response(
            status_code=200,
            headers={"content-length": "999999999999"},
            request=httpx.Request("GET", "https://pypi.org/simple/requests/"),
        )
        with pytest.raises(ResponseTooLargeError, match="exceeds size limit"):
            _check_response_size(response, max_bytes=50_000_000)

    def test_normal_content_length_allowed(self):
        """Response within the size limit does not raise."""
        response = httpx.Response(
            status_code=200,
            headers={"content-length": "1024"},
            request=httpx.Request("GET", "https://pypi.org/simple/requests/"),
        )
        # Should not raise.
        _check_response_size(response, max_bytes=50_000_000)

    def test_missing_content_length_small_body_allowed(self):
        """Response without Content-Length but small body passes."""
        response = httpx.Response(
            status_code=200,
            content=b"small",
            request=httpx.Request("GET", "https://pypi.org/simple/requests/"),
        )
        # Should not raise — body is under the limit.
        _check_response_size(response, max_bytes=50_000_000)

    def test_missing_content_length_oversized_body_rejected(self):
        """Chunked response with oversized body is caught post-materialization."""
        response = httpx.Response(
            status_code=200,
            content=b"x" * 2000,
            request=httpx.Request("GET", "https://pypi.org/simple/requests/"),
        )
        with pytest.raises(ResponseTooLargeError, match="exceeds size limit"):
            _check_response_size(response, max_bytes=1000)
