"""Shared fixtures for metadata extraction tests."""

from __future__ import annotations

import io
import tarfile
import zipfile
from typing import TYPE_CHECKING
from unittest.mock import AsyncMock, Mock

from peeq.models import DistType, FileInfo, HashDigest

if TYPE_CHECKING:
    from pathlib import Path

# ---------------------------------------------------------------------------
# Sample metadata text (reusable across tests)
# ---------------------------------------------------------------------------

SAMPLE_METADATA = """\
Metadata-Version: 2.1
Name: test-package
Version: 1.0.0
Summary: A test package for unit tests
Author: Test Author
Home-page: https://example.com
Requires-Python: >=3.8
License: MIT
Requires-Dist: requests>=2.0
Requires-Dist: click>=7.0
Requires-Dist: PySocks>=1.5.6; extra == "socks"
"""

SAMPLE_METADATA_MINIMAL = """\
Metadata-Version: 2.1
Name: minimal-pkg
Version: 0.1.0
"""

SAMPLE_METADATA_DYNAMIC = """\
Metadata-Version: 2.2
Name: dynamic-pkg
Version: 1.0.0
Summary: A package with dynamic deps
Author: Dynamic Author
Requires-Dist: placeholder-dep>=1.0
License: Placeholder License
Dynamic: Requires-Dist
Dynamic: License
"""

SAMPLE_METADATA_MULTI_DYNAMIC = """\
Metadata-Version: 2.2
Name: multi-dynamic
Version: 2.0.0
Requires-Dist: placeholder-dep>=1.0
License: Placeholder License
Requires-Python: >=3.8
Summary: Placeholder summary
Author: Placeholder Author
Home-page: https://placeholder.example.com
Dynamic: Requires-Dist
Dynamic: License
Dynamic: Requires-Python
Dynamic: Summary
Dynamic: Author
Dynamic: Home-page
"""


# ---------------------------------------------------------------------------
# FileInfo factories
# ---------------------------------------------------------------------------


def make_wheel_file_info(  # noqa: PLR0913
    *,
    filename: str = "test_package-1.0.0-py3-none-any.whl",
    url: str = "https://files.example.com/test_package-1.0.0-py3-none-any.whl",
    metadata_available: bool = False,
    metadata_hash: HashDigest | None = None,
    size: int | None = 5000,
    yanked: bool = False,
    sha256: str = "abc123",
) -> FileInfo:
    """Create a wheel `FileInfo` for testing."""
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


def make_sdist_file_info(
    *,
    filename: str = "test-package-1.0.0.tar.gz",
    url: str = "https://files.example.com/test-package-1.0.0.tar.gz",
    size: int | None = 10000,
    yanked: bool = False,
    sha256: str = "def456",
) -> FileInfo:
    """Create an sdist `FileInfo` for testing."""
    return FileInfo(
        filename=filename,
        url=url,
        hash=HashDigest(sha256=sha256, source="registry"),
        dist_type=DistType.SDIST,
        size=size,
        yanked=yanked,
    )


# ---------------------------------------------------------------------------
# Test archive creators
# ---------------------------------------------------------------------------


def create_test_wheel(
    path: Path,
    metadata_text: str = SAMPLE_METADATA,
    *,
    dist_info_name: str = "test_package-1.0.0.dist-info",
) -> None:
    """Create a minimal .whl (zip) file with METADATA."""
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr(f"{dist_info_name}/METADATA", metadata_text)
        zf.writestr(f"{dist_info_name}/RECORD", "")


def create_test_wheel_no_metadata(path: Path) -> None:
    """Create a .whl file without a METADATA file."""
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("test_package-1.0.0.dist-info/RECORD", "")
        zf.writestr("test_package/__init__.py", "")


def create_test_sdist(
    path: Path,
    pkg_info_text: str = SAMPLE_METADATA,
    *,
    root_dir: str = "test-package-1.0.0",
) -> None:
    """Create a minimal .tar.gz file with PKG-INFO."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        data = pkg_info_text.encode("utf-8")
        info = tarfile.TarInfo(name=f"{root_dir}/PKG-INFO")
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))
    path.write_bytes(buf.getvalue())


def create_test_sdist_root_pkg_info(
    path: Path,
    pkg_info_text: str = SAMPLE_METADATA,
) -> None:
    """Create a .tar.gz with PKG-INFO at the archive root (non-standard)."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        data = pkg_info_text.encode("utf-8")
        info = tarfile.TarInfo(name="PKG-INFO")
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))
    path.write_bytes(buf.getvalue())


def create_test_sdist_no_pkg_info(path: Path) -> None:
    """Create a .tar.gz without a PKG-INFO file."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        data = b"# empty module"
        info = tarfile.TarInfo(name="test-package-1.0.0/setup.py")
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))
    path.write_bytes(buf.getvalue())


# ---------------------------------------------------------------------------
# Mock backend helpers
# ---------------------------------------------------------------------------


def make_mock_backend() -> AsyncMock:
    """Create a mock `PackageRepository` backend for metadata tests."""
    backend = AsyncMock()
    backend.files = AsyncMock(return_value=[])
    backend.get_with_retry = AsyncMock()
    backend.download = AsyncMock()
    return backend


def make_mock_response(
    *,
    text: str = SAMPLE_METADATA,
    is_success: bool = True,
    status_code: int = 200,
) -> Mock:
    """Create a mock httpx.Response."""
    response = Mock()
    response.is_success = is_success
    response.status_code = status_code
    response.text = text
    response.content = text.encode("utf-8")
    return response
