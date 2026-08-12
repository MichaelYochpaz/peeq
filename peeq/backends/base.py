"""Abstract base class for package repository backends.

Backends handle communication with package registries (PyPI, PEP 503 Simple
repositories, etc.).  They are intentionally simple --- just API calls and
downloads.  They do NOT handle caching or metadata extraction; those are the
service layer's responsibilities.

All HTTP requests include a `User-Agent: peeq/<version>` header, set
in the base class so all backends inherit it.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import random
import re
import socket
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, ClassVar
from urllib.parse import urlparse

import httpx
from packaging.utils import parse_sdist_filename, parse_wheel_filename
from packaging.version import InvalidVersion, Version

from peeq import APP_NAME, __version__
from peeq.models import (
    DistType,
    DownloadResult,
    HashDigest,
)
from peeq.sanitize import InternalIPError, validate_ip_not_internal

if TYPE_CHECKING:
    import sys
    from pathlib import Path

    from peeq.models import FileInfo, PackageInfo, VersionInfo

    if sys.version_info >= (3, 11):
        from typing import Self
    else:
        from typing_extensions import Self

logger = logging.getLogger(__name__)

_SHA256_BUF_SIZE: int = 256 * 1024  # 256 KB read chunks for streaming

# Retry configuration for transient HTTP failures (429, 5xx).
_MAX_RETRIES: int = 3
_RETRY_BASE_DELAY: float = 1.0  # seconds
_HTTP_TOO_MANY_REQUESTS: int = 429
_HTTP_SERVER_ERROR_MIN: int = 500

# Maximum size for non-streaming API responses (JSON, HTML, metadata).
# Prevents memory exhaustion from malicious registries serving
# arbitrarily large responses.
_MAX_API_RESPONSE_BYTES: int = 50 * 1024 * 1024  # 50 MB

# ---------------------------------------------------------------------------
# SSRF validation
# ---------------------------------------------------------------------------

# Origin = (scheme, hostname, port) — the same-origin unit of trust.
# URLs matching the user's --index-url origin are exempt from SSRF
# checks because the user explicitly chose that registry.
_Origin = tuple[str, str | None, int]

_DEFAULT_PORTS: dict[str, int] = {"http": 80, "https": 443}


def _parse_origin(url: str) -> _Origin:
    """Parse a URL into an origin tuple `(scheme, hostname, port)`.

    Default ports are normalized: `http://host` and `http://host:80`
    produce the same origin.  This follows the web Same-Origin Policy
    definition.

    Args:
        url: The URL to parse.

    Returns:
        A `(scheme, hostname, port)` tuple.
    """
    parsed = urlparse(url)
    scheme = parsed.scheme or "https"
    hostname = parsed.hostname
    port = parsed.port or _DEFAULT_PORTS.get(scheme, 443)
    return (scheme, hostname, port)


async def _resolve_and_validate_host(hostname: str, *, context: str) -> None:
    """Resolve *hostname* via async DNS and reject internal/private IPs.

    Shared validation logic for both pre-fetch URL checks
    (`_validate_url_not_internal`) and redirect interception
    (`_validate_redirect`).  Resolves all addresses for the hostname
    and raises `BackendError` if any resolve to internal/private IP
    ranges.

    Uses `loop.getaddrinfo()` for non-blocking DNS resolution —
    the synchronous `socket.getaddrinfo()` would block the event loop
    (can take seconds on DNS timeout, freezing all concurrent I/O).

    Args:
        hostname: DNS hostname to resolve.
        context: Human-readable description for error messages
            (e.g., `"request to 'http://...'"`).

    Raises:
        BackendError: If any resolved IP is internal/private.
    """
    try:
        loop = asyncio.get_running_loop()
        addr_infos = await loop.getaddrinfo(hostname, None, family=socket.AF_UNSPEC)
    except socket.gaierror:
        # DNS resolution failed — let httpx handle the error naturally.
        return

    for addr_info in addr_infos:
        ip_str = addr_info[4][0]
        try:
            validate_ip_not_internal(ip_str)
        except InternalIPError as exc:
            msg = f"SSRF protection: {context} blocked — {hostname} resolves to internal IP {ip_str}: {exc}"
            raise BackendError(msg) from exc


async def _validate_url_not_internal(
    url: str,
    *,
    trusted_origin: _Origin | None = None,
) -> None:
    """Validate that a URL's hostname does not resolve to an internal IP.

    Pre-fetch SSRF protection: called before every outbound HTTP
    request to catch direct attacks where a malicious registry returns
    internal URLs (e.g., `"http://169.254.169.254/latest/meta-data/"`)
    in its HTML/JSON responses.  The redirect hook in `_create_client`
    provides defense-in-depth for URLs that pass this check but
    redirect to internal addresses.

    URLs matching *trusted_origin* (the user's `--index-url`) are
    exempt.  The user explicitly chose that registry, so it is
    trusted input — not attacker-controlled.  Only cross-origin URLs
    (artifact hrefs from registry HTML/JSON responses) are checked.

    Args:
        url: The URL about to be fetched.
        trusted_origin: Origin tuple from the user's `--index-url`.
            URLs matching this exact origin skip validation.

    Raises:
        BackendError: If the hostname resolves to an internal/private IP.
    """
    parsed = urlparse(url)
    hostname = parsed.hostname
    if not hostname:
        return
    if trusted_origin is not None and _parse_origin(url) == trusted_origin:
        return
    await _resolve_and_validate_host(hostname, context=f"request to {url!r}")


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class BackendError(Exception):
    """Error communicating with a package registry."""


class ResponseTooLargeError(BackendError):
    """API response exceeds the maximum allowed size."""


def _check_response_size(response: httpx.Response, max_bytes: int = _MAX_API_RESPONSE_BYTES) -> None:
    """Check response size and reject oversized responses.

    Two layers of defense:

    1. **Pre-flight** — checks the `Content-Length` header when present.
       This catches well-behaved large responses before the body is read.
    2. **Post-materialization** — checks the actual body length after httpx
       materializes the response.  This catches chunked/streamed responses
       that omit `Content-Length` and would otherwise bypass the
       pre-flight check.

    Args:
        response: The httpx response to check.
        max_bytes: Maximum allowed response size in bytes.

    Raises:
        ResponseTooLargeError: If the response exceeds *max_bytes*.
    """
    # Layer 1: pre-flight Content-Length check (before body is read)
    content_length = response.headers.get("content-length")
    if content_length is not None:
        try:
            size = int(content_length)
        except ValueError:
            pass
        else:
            if size > max_bytes:
                msg = f"Response from {response.url} exceeds size limit: {size:,} bytes > {max_bytes:,} bytes"
                raise ResponseTooLargeError(msg)

    # Layer 2: post-materialization body size check.
    # httpx eagerly reads the full body for non-streaming requests,
    # so `response.content` is available after `await client.get()`.
    # This catches chunked responses that omitted Content-Length.
    actual_size = len(response.content)
    if actual_size > max_bytes:
        msg = f"Response from {response.url} exceeds size limit: {actual_size:,} bytes > {max_bytes:,} bytes"
        raise ResponseTooLargeError(msg)


# ---------------------------------------------------------------------------
# Abstract base class
# ---------------------------------------------------------------------------


class PackageRepository(ABC):
    """Abstract base for package repository backends.

    Backends are responsible for:

    - Checking if packages exist on a registry
    - Listing available versions
    - Listing available files (sdists, wheels) for a version
    - Downloading artifacts

    Backends are NOT responsible for:

    - Caching (handled by cache layer)
    - Metadata extraction (handled by metadata layer)
    - Output formatting (handled by output layer)

    Subclasses auto-register via `__init_subclass__`.  Set `backend_id`
    as a `ClassVar[str]` on each concrete backend.
    """

    _registry: ClassVar[dict[str, type[PackageRepository]]] = {}
    backend_id: ClassVar[str]

    def __init_subclass__(cls, **kwargs: object) -> None:
        super().__init_subclass__(**kwargs)
        if hasattr(cls, "backend_id"):
            PackageRepository._registry[cls.backend_id] = cls

    @classmethod
    def get_backend_class(
        cls,
        backend_id: str,
    ) -> type[PackageRepository] | None:
        """Look up a registered backend class by ID.

        Return `None` if *backend_id* is not registered.
        """
        return cls._registry.get(backend_id)

    @classmethod
    def registered_backend_ids(cls) -> list[str]:
        """Return sorted list of all registered backend identifiers."""
        return sorted(cls._registry)

    def __init__(
        self,
        *,
        base_url: str,
        registry: str | None = None,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._registry_name = registry or extract_hostname(base_url)
        self._trusted_origin = _parse_origin(base_url)
        self._client: httpx.AsyncClient | None = None

    @property
    def registry(self) -> str:
        """Registry identifier (e.g., `"pypi.org"`)."""
        return self._registry_name

    @property
    def base_url(self) -> str:
        """Base URL of the repository (without trailing slash)."""
        return self._base_url

    @property
    def simple_url(self) -> str:
        """PEP 503 Simple API root used for dependency resolution."""
        return self._base_url

    # ------------------------------------------------------------------
    # httpx client lifecycle
    # ------------------------------------------------------------------

    def _create_client(self) -> httpx.AsyncClient:
        """Create an httpx client with the standard User-Agent header.

        Enables `follow_redirects` because some registry endpoints
        (notably the PyPI legacy JSON API) issue 301 redirects for
        non-canonical package names.

        The redirect validation hook is a closure that captures the
        trusted origin.  Same-origin redirects (e.g., name
        normalization on a local registry) are allowed; cross-origin
        redirects to internal IPs are blocked.
        """
        trusted_origin = self._trusted_origin

        async def _validate_redirect(response: httpx.Response) -> None:
            if not (httpx.codes.MULTIPLE_CHOICES <= response.status_code < httpx.codes.BAD_REQUEST):
                return

            location = response.headers.get("location")
            if not location:
                return

            parsed = urlparse(location)
            hostname = parsed.hostname
            if not hostname:
                return

            if _parse_origin(location) == trusted_origin:
                return

            await _resolve_and_validate_host(hostname, context=f"redirect to {location!r}")

        return httpx.AsyncClient(
            headers={"User-Agent": f"{APP_NAME}/{__version__}"},
            timeout=30.0,
            follow_redirects=True,
            event_hooks={"response": [_validate_redirect]},
        )

    async def get_with_retry(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
    ) -> httpx.Response:
        """HTTP GET with retry and exponential backoff for transient errors.

        Retries on HTTP 429 (rate-limited) and 5xx (server errors).
        Uses exponential backoff with full jitter.  The Fastly CDN
        serving PyPI frequently omits `Retry-After` on 429 responses,
        so the backoff is time-based rather than header-driven.
        """
        await _validate_url_not_internal(url, trusted_origin=self._trusted_origin)
        response: httpx.Response | None = None
        for attempt in range(_MAX_RETRIES):
            response = await self.client.get(url, headers=headers or {})
            if response.status_code == _HTTP_TOO_MANY_REQUESTS or response.status_code >= _HTTP_SERVER_ERROR_MIN:
                if attempt == _MAX_RETRIES - 1:
                    # Last attempt — let the caller handle the error
                    return response
                delay = random.uniform(0, _RETRY_BASE_DELAY * (2**attempt))  # noqa: S311
                logger.debug(
                    "Retryable %d from %s (attempt %d/%d), backing off %.2fs",
                    response.status_code,
                    url,
                    attempt + 1,
                    _MAX_RETRIES,
                    delay,
                )
                await asyncio.sleep(delay)
                continue
            _check_response_size(response)
            return response

        assert response is not None  # _MAX_RETRIES >= 1  # noqa: S101
        _check_response_size(response)
        return response

    async def __aenter__(self) -> Self:
        self._client = self._create_client()
        return self

    async def __aexit__(self, *exc: object) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    @property
    def client(self) -> httpx.AsyncClient:
        """Active httpx client.  Raises if not in async context manager."""
        if self._client is None:
            msg = f"{type(self).__name__} must be used as an async context manager (async with ...)"
            raise RuntimeError(msg)
        return self._client

    # ------------------------------------------------------------------
    # Abstract methods
    # ------------------------------------------------------------------

    @abstractmethod
    async def check(self, name: str) -> PackageInfo | None:
        """Check if package exists, return basic info."""
        ...

    @abstractmethod
    async def versions(self, name: str) -> list[VersionInfo]:
        """List all available versions with yanked status."""
        ...

    @abstractmethod
    async def files(self, name: str, version: str) -> list[FileInfo]:
        """List available files for a version (sdists, wheels)."""
        ...

    @abstractmethod
    async def download(
        self,
        file: FileInfo,
        dest: Path,
        *,
        max_download_bytes: int = 500 * 1024 * 1024,
    ) -> DownloadResult:
        """Download a specific file to dest.  Returns result with hash info.

        Parameters
        ----------
        file:
            File metadata (URL, expected hash, etc.).
        dest:
            Local path to write the downloaded file.
        max_download_bytes:
            Maximum allowed download size in bytes.  Defaults to 500 MB.
            Pass the user's configured extraction limit to keep the
            pre-flight download check consistent with downstream limits.
        """
        ...

    # ------------------------------------------------------------------
    # Shared download implementation
    # ------------------------------------------------------------------

    async def _download_file(
        self,
        url: str,
        dest: Path,
        expected_hash: HashDigest | None = None,
        *,
        max_download_bytes: int = 500 * 1024 * 1024,
    ) -> DownloadResult:
        """Stream-download `url` to `dest` with SHA-256 verification.

        If `expected_hash` is provided and the computed digest does not
        match, the downloaded file is removed and `BackendError`
        is raised.

        Parameters
        ----------
        max_download_bytes:
            Maximum allowed download size in bytes.  Both the declared
            `Content-Length` and the actual streamed bytes are checked
            against this limit.  Defaults to 500 MB.
        """
        await _validate_url_not_internal(url, trusted_origin=self._trusted_origin)
        dest.parent.mkdir(parents=True, exist_ok=True)

        hasher = hashlib.sha256()
        size = 0
        exceeded = False

        async with self.client.stream("GET", url) as response:
            response.raise_for_status()
            # Pre-flight size check: reject downloads that declare a
            # Content-Length exceeding the configured maximum.  This
            # prevents starting a large download that would be rejected
            # later during extraction anyway.
            content_length = response.headers.get("content-length")
            if content_length is not None:
                try:
                    declared_size = int(content_length)
                except ValueError:
                    pass
                else:
                    if declared_size > max_download_bytes:
                        msg = (
                            f"Download from {url} exceeds size limit: "
                            f"{declared_size:,} bytes "
                            f"> {max_download_bytes:,} bytes"
                        )
                        raise BackendError(msg)
            with dest.open("wb") as f:
                async for chunk in response.aiter_bytes(
                    chunk_size=_SHA256_BUF_SIZE,
                ):
                    hasher.update(chunk)
                    f.write(chunk)
                    size += len(chunk)
                    if size > max_download_bytes:
                        exceeded = True
                        break

        # Cleanup must happen outside the `with dest.open(...)` block
        # because Windows locks open file handles.
        if exceeded:
            dest.unlink(missing_ok=True)
            msg = (
                f"Download from {url} exceeded size limit during "
                f"streaming: {size:,} bytes > {max_download_bytes:,} bytes"
            )
            raise BackendError(msg)

        computed = hasher.hexdigest()

        if expected_hash is not None and computed != expected_hash.sha256:
            dest.unlink(missing_ok=True)
            msg = f"SHA-256 mismatch for {dest.name}: expected {expected_hash.sha256}, got {computed}"
            raise BackendError(msg)

        hash_digest = HashDigest(
            sha256=computed,
            source=expected_hash.source if expected_hash else "computed",
        )
        return DownloadResult(path=dest, hash=hash_digest, size_bytes=size)


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def extract_hostname(url: str) -> str:
    """Extract hostname from a URL for registry identification."""
    parsed = urlparse(url)
    return parsed.hostname or url


def determine_dist_type(filename: str) -> DistType:
    """Determine distribution type from filename."""
    if filename.endswith(".whl"):
        return DistType.WHEEL
    return DistType.SDIST


def parse_version_from_filename(filename: str) -> Version | None:
    """Parse a PEP 440 version from a distribution filename.

    Uses `packaging.utils.parse_wheel_filename` for wheels and
    `packaging.utils.parse_sdist_filename` for sdists (`.tar.gz`,
    `.zip`).  Returns `None` for unparseable filenames.
    """
    try:
        if filename.endswith(".whl"):
            _name, ver, _build, _tags = parse_wheel_filename(filename)
            return ver
        if filename.endswith((".tar.gz", ".zip")):
            _name, ver = parse_sdist_filename(filename)
            return ver
    except Exception:
        logger.debug("Cannot parse version from filename: %s", filename)

    # .tar.bz2, .egg, etc. — not supported by packaging.utils
    # Try a best-effort regex parse for common patterns
    return _regex_version_fallback(filename)


def _regex_version_fallback(filename: str) -> Version | None:
    """Best-effort version extraction for non-standard filenames."""
    # Strip known suffixes
    for suffix in (".tar.bz2", ".tar.xz", ".tar", ".egg", ".exe", ".msi"):
        if filename.endswith(suffix):
            stem = filename[: -len(suffix)]
            break
    else:
        return None

    # Try "<name>-<version>" split from the right
    match = re.match(r"^(.+?)-(\d.*)$", stem)
    if match:
        try:
            return Version(match.group(2))
        except InvalidVersion:
            pass

    return None
