"""Shared test helpers for `peeq.service` tests.

Provides factory functions used across the service test suite.
Individual test modules import the helpers they need::

    from tests.test_service.conftest import _make_service, _make_cache
"""

from __future__ import annotations

import hashlib
import io
import tarfile
import zipfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, Mock

from peeq.models import (
    Dependency,
    DistType,
    DownloadResult,
    FileInfo,
    HashDigest,
    PackageMetadata,
)
from peeq.service import PackageService

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_SAMPLE_METADATA_TEXT = """\
Metadata-Version: 2.1
Name: test-package
Version: 1.0.0
Summary: A test package
Author: Test Author
Requires-Python: >=3.8
Requires-Dist: requests>=2.0
Requires-Dist: click>=7.0
"""

_SAMPLE_METADATA_DYNAMIC_TEXT = """\
Metadata-Version: 2.2
Name: dynamic-pkg
Version: 1.0.0
Summary: Dynamic deps
Dynamic: Requires-Dist
"""

# ---------------------------------------------------------------------------
# Factory functions
# ---------------------------------------------------------------------------


def _make_backend(*, registry: str = "pypi.org") -> AsyncMock:
    """Create a mock `PackageRepository`."""
    backend = AsyncMock()
    backend.registry = registry
    backend.files = AsyncMock(return_value=[])
    backend.versions = AsyncMock(return_value=[])
    backend.check = AsyncMock(return_value=None)
    backend.download = AsyncMock()
    backend.get_with_retry = AsyncMock()
    return backend


def _make_cache() -> MagicMock:
    """Create a mock `CacheManager`."""
    cache = MagicMock()
    cache.cache_dir = Path("test-cache")
    cache.get_package.return_value = None
    cache.get_metadata.return_value = None
    cache.get_archive_path.return_value = None
    cache.save_metadata.return_value = 1
    cache.upsert_package.return_value = 1
    return cache


def _make_service(
    *,
    cache: MagicMock | None = None,
    backend: AsyncMock | None = None,
) -> PackageService:
    """Create a `PackageService` with mock dependencies."""
    return PackageService(
        cache=cache or _make_cache(),
        backend=backend or _make_backend(),
    )


def _wheel_fi(  # noqa: PLR0913
    *,
    filename: str = "test_package-1.0.0-py3-none-any.whl",
    url: str = "https://files.example.com/test_package-1.0.0-py3-none-any.whl",
    sha256: str = "abc123",
    metadata_available: bool = False,
    metadata_hash: HashDigest | None = None,
    size: int | None = 5000,
    yanked: bool = False,
) -> FileInfo:
    """Create a wheel `FileInfo`."""
    return FileInfo(
        filename=filename,
        url=url,
        hash=HashDigest(sha256=sha256, source="registry"),
        dist_type=DistType.WHEEL,
        metadata_available=metadata_available,
        metadata_hash=metadata_hash,
        size=size,
        yanked=yanked,
    )


def _sdist_fi(
    *,
    filename: str = "test-package-1.0.0.tar.gz",
    url: str = "https://files.example.com/test-package-1.0.0.tar.gz",
    sha256: str = "def456",
    size: int | None = 10000,
    yanked: bool = False,
) -> FileInfo:
    """Create an sdist `FileInfo`."""
    return FileInfo(
        filename=filename,
        url=url,
        hash=HashDigest(sha256=sha256, source="registry"),
        dist_type=DistType.SDIST,
        size=size,
        yanked=yanked,
    )


def _make_sdist_bytes(
    metadata_text: str = _SAMPLE_METADATA_TEXT,
    *,
    root_dir: str = "test-package-1.0.0",
) -> bytes:
    """Create minimal sdist tar.gz bytes with PKG-INFO."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        data = metadata_text.encode("utf-8")
        info = tarfile.TarInfo(name=f"{root_dir}/PKG-INFO")
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def _make_wheel_bytes(
    metadata_text: str = _SAMPLE_METADATA_TEXT,
    *,
    dist_info: str = "test_package-1.0.0.dist-info",
) -> bytes:
    """Create minimal wheel (zip) bytes with METADATA."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(f"{dist_info}/METADATA", metadata_text)
        zf.writestr(f"{dist_info}/RECORD", "")
    return buf.getvalue()


def _dep(raw: str) -> Dependency:
    """Create a `Dependency` from a requirement string."""
    return Dependency.from_requirement_string(raw)


def _metadata(
    deps: list[Dependency] | None = None,
) -> PackageMetadata:
    """Create a `PackageMetadata` with the given dependencies."""
    return PackageMetadata(dependencies=deps)


def _mock_response(
    text: str = _SAMPLE_METADATA_TEXT,
    *,
    is_success: bool = True,
    status_code: int = 200,
) -> Mock:
    """Create a mock httpx.Response."""
    resp = Mock()
    resp.is_success = is_success
    resp.status_code = status_code
    resp.text = text
    resp.content = text.encode("utf-8")
    return resp


def _download_side_effect(
    archive_bytes: bytes,
    sha256: str | None = None,
) -> object:
    """Create a side_effect for backend.download that writes archive bytes."""
    computed = sha256 or hashlib.sha256(archive_bytes).hexdigest()

    async def _download(
        file_info: FileInfo,
        dest: Path,
        **_kwargs: object,
    ) -> DownloadResult:
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(archive_bytes)
        return DownloadResult(
            path=dest,
            hash=HashDigest(sha256=computed, source="computed"),
            size_bytes=len(archive_bytes),
        )

    return _download
