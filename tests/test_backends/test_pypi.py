"""Tests for the PyPI repository backend."""

from __future__ import annotations

import hashlib
from datetime import timezone
from typing import TYPE_CHECKING

import httpx
import pytest
import respx
from packaging.version import Version

from peeq.backends.base import BackendError
from peeq.backends.pypi import (
    PYPI_BASE_URL,
    PyPIRepository,
    _determine_latest_version,
    _file_dict_to_model,
    _parse_upload_time,
    extract_files_for_version,
    extract_versions,
)
from peeq.models import DistType, FileInfo, HashDigest, VersionInfo

if TYPE_CHECKING:
    from pathlib import Path

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

SIMPLE_RESPONSE_V11 = {
    "meta": {"api-version": "1.1"},
    "name": "requests",
    "versions": ["2.28.0", "2.30.0", "2.31.0"],
    "files": [
        {
            "filename": "requests-2.31.0.tar.gz",
            "url": "https://files.pythonhosted.org/packages/requests-2.31.0.tar.gz",
            "hashes": {"sha256": "a" * 64},
            "requires-python": ">=3.7",
            "size": 110346,
        },
        {
            "filename": "requests-2.31.0-py3-none-any.whl",
            "url": "https://files.pythonhosted.org/packages/requests-2.31.0-py3-none-any.whl",
            "hashes": {"sha256": "b" * 64},
            "requires-python": ">=3.7",
            "core-metadata": {"sha256": "c" * 64},
            "size": 62574,
        },
        {
            "filename": "requests-2.30.0.tar.gz",
            "url": "https://files.pythonhosted.org/packages/requests-2.30.0.tar.gz",
            "hashes": {"sha256": "d" * 64},
            "requires-python": ">=3.7",
            "size": 109000,
        },
    ],
}

SIMPLE_RESPONSE_V10 = {
    "meta": {"api-version": "1.0"},
    "name": "requests",
    "files": [
        {
            "filename": "requests-2.31.0.tar.gz",
            "url": "https://files.pythonhosted.org/packages/requests-2.31.0.tar.gz",
            "hashes": {"sha256": "a" * 64},
            "requires-python": ">=3.7",
            "size": 110346,
        },
        {
            "filename": "requests-2.31.0-py3-none-any.whl",
            "url": "https://files.pythonhosted.org/packages/requests-2.31.0-py3-none-any.whl",
            "hashes": {"sha256": "b" * 64},
            "requires-python": ">=3.7",
            "core-metadata": True,
            "size": 62574,
        },
        {
            "filename": "requests-2.30.0.tar.gz",
            "url": "https://files.pythonhosted.org/packages/requests-2.30.0.tar.gz",
            "hashes": {"sha256": "d" * 64},
            "requires-python": ">=3.7",
            "size": 109000,
        },
    ],
}

LEGACY_JSON_RESPONSE = {
    "info": {
        "name": "requests",
        "version": "2.31.0",
        "summary": "Python HTTP for Humans.",
        "author": "Kenneth Reitz",
        "home_page": "https://requests.readthedocs.io",
    },
}


# ---------------------------------------------------------------------------
# Constructor
# ---------------------------------------------------------------------------


class TestPyPIConstructor:
    def test_default_urls(self):
        repo = PyPIRepository()
        assert repo.base_url == PYPI_BASE_URL
        assert repo.registry == "pypi.org"

    def test_custom_base_url(self):
        repo = PyPIRepository(base_url="https://test.pypi.org")
        assert repo.base_url == "https://test.pypi.org"
        assert repo.registry == "test.pypi.org"


# ---------------------------------------------------------------------------
# check()
# ---------------------------------------------------------------------------


class TestPyPICheck:
    @respx.mock
    async def test_check_existing_package(self):
        respx.get("https://pypi.org/simple/requests/").mock(
            return_value=httpx.Response(200, json=SIMPLE_RESPONSE_V11),
        )
        respx.get("https://pypi.org/pypi/requests/json").mock(
            return_value=httpx.Response(200, json=LEGACY_JSON_RESPONSE),
        )

        async with PyPIRepository() as repo:
            info = await repo.check("requests")

        assert info is not None
        assert info.name == "requests"
        assert info.latest_version == Version("2.31.0")
        assert info.version_count == 3
        assert info.summary == "Python HTTP for Humans."
        assert info.registry == "pypi.org"

    @respx.mock
    async def test_check_nonexistent_package(self):
        respx.get("https://pypi.org/simple/nonexistent/").mock(
            return_value=httpx.Response(404),
        )
        respx.get("https://pypi.org/pypi/nonexistent/json").mock(
            return_value=httpx.Response(404),
        )

        async with PyPIRepository() as repo:
            info = await repo.check("nonexistent")

        assert info is None

    @respx.mock
    async def test_check_summary_failure_still_works(self):
        """If the legacy JSON API fails, check() still returns info."""
        respx.get("https://pypi.org/simple/requests/").mock(
            return_value=httpx.Response(200, json=SIMPLE_RESPONSE_V11),
        )
        respx.get("https://pypi.org/pypi/requests/json").mock(
            return_value=httpx.Response(500),
        )

        async with PyPIRepository() as repo:
            info = await repo.check("requests")

        assert info is not None
        assert info.name == "requests"
        assert info.summary is None

    @respx.mock
    async def test_check_normalizes_name(self):
        respx.get("https://pypi.org/simple/my-package/").mock(
            return_value=httpx.Response(
                200,
                json={
                    "meta": {"api-version": "1.1"},
                    "name": "my-package",
                    "versions": ["1.0.0"],
                    "files": [],
                },
            ),
        )
        respx.get("https://pypi.org/pypi/my-package/json").mock(
            return_value=httpx.Response(404),
        )

        async with PyPIRepository() as repo:
            info = await repo.check("My_Package")

        assert info is not None
        assert info.name == "my-package"


# ---------------------------------------------------------------------------
# versions()
# ---------------------------------------------------------------------------


class TestPyPIVersions:
    @respx.mock
    async def test_versions_sorted_descending(self):
        respx.get("https://pypi.org/simple/requests/").mock(
            return_value=httpx.Response(200, json=SIMPLE_RESPONSE_V11),
        )

        async with PyPIRepository() as repo:
            versions = await repo.versions("requests")

        assert versions == [
            VersionInfo(version=Version("2.31.0"), requires_python=">=3.7"),
            VersionInfo(version=Version("2.30.0"), requires_python=">=3.7"),
            VersionInfo(version=Version("2.28.0")),  # No files in fixture
        ]

    @respx.mock
    async def test_versions_nonexistent(self):
        respx.get("https://pypi.org/simple/nonexistent/").mock(
            return_value=httpx.Response(404),
        )

        async with PyPIRepository() as repo:
            versions = await repo.versions("nonexistent")

        assert versions == []

    @respx.mock
    async def test_versions_from_filenames_fallback(self):
        """When the response has no `versions` key (API v1.0)."""
        respx.get("https://pypi.org/simple/requests/").mock(
            return_value=httpx.Response(200, json=SIMPLE_RESPONSE_V10),
        )

        async with PyPIRepository() as repo:
            versions = await repo.versions("requests")

        # Should extract versions from filenames
        assert Version("2.31.0") in [version.version for version in versions]
        assert Version("2.30.0") in [version.version for version in versions]

    @respx.mock
    async def test_versions_http_error(self):
        respx.get("https://pypi.org/simple/requests/").mock(
            return_value=httpx.Response(500),
        )

        async with PyPIRepository() as repo:
            with pytest.raises(BackendError, match="500"):
                await repo.versions("requests")


# ---------------------------------------------------------------------------
# files()
# ---------------------------------------------------------------------------


class TestPyPIFiles:
    @respx.mock
    async def test_files_for_version(self):
        respx.get("https://pypi.org/simple/requests/").mock(
            return_value=httpx.Response(200, json=SIMPLE_RESPONSE_V11),
        )

        async with PyPIRepository() as repo:
            files = await repo.files("requests", "2.31.0")

        assert len(files) == 2

        # Find the sdist
        sdist = next(f for f in files if f.dist_type == DistType.SDIST)
        assert sdist.filename == "requests-2.31.0.tar.gz"
        assert sdist.hash is not None
        assert sdist.hash.sha256 == "a" * 64
        assert sdist.hash.source == "registry"
        assert sdist.requires_python == ">=3.7"
        assert sdist.size == 110346

        # Find the wheel
        wheel = next(f for f in files if f.dist_type == DistType.WHEEL)
        assert wheel.filename == "requests-2.31.0-py3-none-any.whl"
        assert wheel.metadata_available is True
        assert wheel.metadata_hash is not None
        assert wheel.metadata_hash.sha256 == "c" * 64

    @respx.mock
    async def test_files_nonexistent_version(self):
        respx.get("https://pypi.org/simple/requests/").mock(
            return_value=httpx.Response(200, json=SIMPLE_RESPONSE_V11),
        )

        async with PyPIRepository() as repo:
            files = await repo.files("requests", "99.99.99")

        assert files == []

    @respx.mock
    async def test_files_nonexistent_package(self):
        respx.get("https://pypi.org/simple/nonexistent/").mock(
            return_value=httpx.Response(404),
        )

        async with PyPIRepository() as repo:
            files = await repo.files("nonexistent", "1.0.0")

        assert files == []


# ---------------------------------------------------------------------------
# download()
# ---------------------------------------------------------------------------


class TestPyPIDownload:
    @respx.mock
    async def test_download_with_hash(self, tmp_path: Path):
        content = b"fake sdist content"
        sha256 = hashlib.sha256(content).hexdigest()

        download_url = "https://files.pythonhosted.org/packages/requests-2.31.0.tar.gz"
        respx.get(download_url).mock(
            return_value=httpx.Response(200, content=content),
        )

        file_info = FileInfo(
            filename="requests-2.31.0.tar.gz",
            url=download_url,
            hash=HashDigest(sha256=sha256, source="registry"),
            dist_type=DistType.SDIST,
        )
        dest = tmp_path / "requests-2.31.0.tar.gz"

        async with PyPIRepository() as repo:
            result = await repo.download(file_info, dest)

        assert result.path == dest
        assert result.hash.sha256 == sha256
        assert result.hash.source == "registry"
        assert result.size_bytes == len(content)
        assert dest.read_bytes() == content


# ---------------------------------------------------------------------------
# extract_versions()
# ---------------------------------------------------------------------------


class TestExtractVersions:
    def test_with_versions_key(self):
        versions = extract_versions(SIMPLE_RESPONSE_V11)
        assert len(versions) == 3
        assert Version("2.31.0") in [version.version for version in versions]
        assert Version("2.30.0") in [version.version for version in versions]
        assert Version("2.28.0") in [version.version for version in versions]

    def test_without_versions_key(self):
        versions = extract_versions(SIMPLE_RESPONSE_V10)
        assert Version("2.31.0") in [version.version for version in versions]
        assert Version("2.30.0") in [version.version for version in versions]

    def test_empty_response(self):
        assert extract_versions({"files": []}) == []

    def test_unparseable_versions_skipped(self):
        data = {
            "versions": ["1.0.0", "not-a-version", "2.0.0"],
        }
        versions = extract_versions(data)
        assert len(versions) == 2
        assert Version("1.0.0") in [version.version for version in versions]
        assert Version("2.0.0") in [version.version for version in versions]

    def test_yanked_version_all_files_yanked(self):
        """All files for a version yanked with reason."""
        data = {
            "meta": {"api-version": "1.1"},
            "name": "pkg",
            "versions": ["1.0.0"],
            "files": [
                {
                    "filename": "pkg-1.0.0.tar.gz",
                    "url": "https://example.com/pkg-1.0.0.tar.gz",
                    "hashes": {"sha256": "a" * 64},
                    "yanked": "security issue",
                },
                {
                    "filename": "pkg-1.0.0-py3-none-any.whl",
                    "url": "https://example.com/pkg-1.0.0-py3-none-any.whl",
                    "hashes": {"sha256": "b" * 64},
                    "yanked": "security issue",
                },
            ],
        }
        versions = extract_versions(data)
        assert len(versions) == 1
        assert versions[0].version == Version("1.0.0")
        assert versions[0].yanked is True
        assert versions[0].yanked_reason == "security issue"

    def test_yanked_version_mixed_files(self):
        """One file yanked, one not — version is NOT yanked."""
        data = {
            "meta": {"api-version": "1.1"},
            "name": "pkg",
            "versions": ["1.0.0"],
            "files": [
                {
                    "filename": "pkg-1.0.0.tar.gz",
                    "url": "https://example.com/pkg-1.0.0.tar.gz",
                    "hashes": {"sha256": "a" * 64},
                    "yanked": "security issue",
                },
                {
                    "filename": "pkg-1.0.0-py3-none-any.whl",
                    "url": "https://example.com/pkg-1.0.0-py3-none-any.whl",
                    "hashes": {"sha256": "b" * 64},
                },
            ],
        }
        versions = extract_versions(data)
        assert len(versions) == 1
        assert versions[0].yanked is False

    def test_yanked_version_no_reason(self):
        """All files yanked with boolean true — no string reason."""
        data = {
            "meta": {"api-version": "1.1"},
            "name": "pkg",
            "versions": ["1.0.0"],
            "files": [
                {
                    "filename": "pkg-1.0.0.tar.gz",
                    "url": "https://example.com/pkg-1.0.0.tar.gz",
                    "hashes": {"sha256": "a" * 64},
                    "yanked": True,
                },
            ],
        }
        versions = extract_versions(data)
        assert len(versions) == 1
        assert versions[0].yanked is True
        assert versions[0].yanked_reason is None

    def test_requires_python_populated(self):
        """requires_python is extracted from files."""
        data = {
            "versions": ["1.0.0", "2.0.0"],
            "files": [
                {
                    "filename": "pkg-1.0.0-py3-none-any.whl",
                    "url": "https://example.com/pkg-1.0.0-py3-none-any.whl",
                    "hashes": {"sha256": "a" * 64},
                    "requires-python": ">=3.8",
                },
                {
                    "filename": "pkg-2.0.0-py3-none-any.whl",
                    "url": "https://example.com/pkg-2.0.0-py3-none-any.whl",
                    "hashes": {"sha256": "b" * 64},
                    "requires-python": ">=3.12",
                },
            ],
        }
        versions = extract_versions(data)
        by_version = {v.version: v for v in versions}
        assert by_version[Version("1.0.0")].requires_python == ">=3.8"
        assert by_version[Version("2.0.0")].requires_python == ">=3.12"

    def test_requires_python_none_when_absent(self):
        """requires_python is None when files lack the field."""
        data = {
            "versions": ["1.0.0"],
            "files": [
                {
                    "filename": "pkg-1.0.0.tar.gz",
                    "url": "https://example.com/pkg-1.0.0.tar.gz",
                    "hashes": {"sha256": "a" * 64},
                },
            ],
        }
        versions = extract_versions(data)
        assert versions[0].requires_python is None


# ---------------------------------------------------------------------------
# extract_files_for_version()
# ---------------------------------------------------------------------------


class TestExtractFilesForVersion:
    def test_filters_by_version(self):
        files = extract_files_for_version(SIMPLE_RESPONSE_V11, "2.31.0")
        assert len(files) == 2
        filenames = {f.filename for f in files}
        assert "requests-2.31.0.tar.gz" in filenames
        assert "requests-2.31.0-py3-none-any.whl" in filenames

    def test_no_match(self):
        files = extract_files_for_version(SIMPLE_RESPONSE_V11, "99.0.0")
        assert files == []


# ---------------------------------------------------------------------------
# _file_dict_to_model()
# ---------------------------------------------------------------------------


class TestFileDictToModel:
    def test_sdist_with_hash(self):
        f = _file_dict_to_model(
            {
                "filename": "pkg-1.0.tar.gz",
                "url": "https://example.com/pkg-1.0.tar.gz",
                "hashes": {"sha256": "abc123"},
                "requires-python": ">=3.8",
                "size": 50000,
            }
        )
        assert f.filename == "pkg-1.0.tar.gz"
        assert f.url == "https://example.com/pkg-1.0.tar.gz"
        assert f.hash == HashDigest(sha256="abc123", source="registry")
        assert f.requires_python == ">=3.8"
        assert f.dist_type == DistType.SDIST
        assert f.size == 50000
        assert f.metadata_available is False

    def test_wheel_with_core_metadata(self):
        """PEP 714: `core-metadata` is the current key name."""
        f = _file_dict_to_model(
            {
                "filename": "pkg-1.0-py3-none-any.whl",
                "url": "https://example.com/pkg-1.0-py3-none-any.whl",
                "hashes": {"sha256": "abc123"},
                "core-metadata": {"sha256": "meta_hash"},
            }
        )
        assert f.dist_type == DistType.WHEEL
        assert f.metadata_available is True
        assert f.metadata_hash == HashDigest(
            sha256="meta_hash",
            source="registry",
        )

    def test_wheel_with_dist_info_metadata_fallback(self):
        """Deprecated `dist-info-metadata` key still works as fallback."""
        f = _file_dict_to_model(
            {
                "filename": "pkg-1.0-py3-none-any.whl",
                "url": "https://example.com/pkg-1.0-py3-none-any.whl",
                "hashes": {"sha256": "abc123"},
                "dist-info-metadata": {"sha256": "meta_hash"},
            }
        )
        assert f.metadata_available is True
        assert f.metadata_hash is not None
        assert f.metadata_hash.sha256 == "meta_hash"

    def test_core_metadata_takes_precedence(self):
        """`core-metadata` wins over `dist-info-metadata`."""
        f = _file_dict_to_model(
            {
                "filename": "pkg-1.0-py3-none-any.whl",
                "url": "https://example.com/pkg-1.0-py3-none-any.whl",
                "hashes": {},
                "core-metadata": {"sha256": "correct"},
                "dist-info-metadata": {"sha256": "old"},
            }
        )
        assert f.metadata_hash is not None
        assert f.metadata_hash.sha256 == "correct"

    def test_metadata_true_without_hash(self):
        f = _file_dict_to_model(
            {
                "filename": "pkg-1.0-py3-none-any.whl",
                "url": "https://example.com/pkg-1.0-py3-none-any.whl",
                "hashes": {},
                "core-metadata": True,
            }
        )
        assert f.metadata_available is True
        assert f.metadata_hash is None

    def test_metadata_false(self):
        f = _file_dict_to_model(
            {
                "filename": "pkg-1.0-py3-none-any.whl",
                "url": "https://example.com/pkg-1.0-py3-none-any.whl",
                "hashes": {},
                "core-metadata": False,
            }
        )
        assert f.metadata_available is False

    def test_no_hash(self):
        f = _file_dict_to_model(
            {
                "filename": "pkg-1.0.tar.gz",
                "url": "https://example.com/pkg-1.0.tar.gz",
            }
        )
        assert f.hash is None

    def test_no_size(self):
        f = _file_dict_to_model(
            {
                "filename": "pkg-1.0.tar.gz",
                "url": "https://example.com/pkg-1.0.tar.gz",
                "hashes": {},
            }
        )
        assert f.size is None


# ---------------------------------------------------------------------------
# Custom base URL
# ---------------------------------------------------------------------------


class TestCustomBaseURL:
    @respx.mock
    async def test_custom_pypi_url(self):
        respx.get("https://internal.pypi.com/simple/requests/").mock(
            return_value=httpx.Response(
                200,
                json={
                    "meta": {"api-version": "1.1"},
                    "name": "requests",
                    "versions": ["1.0.0"],
                    "files": [],
                },
            ),
        )
        respx.get("https://internal.pypi.com/pypi/requests/json").mock(
            return_value=httpx.Response(200, json=LEGACY_JSON_RESPONSE),
        )

        repo = PyPIRepository(
            base_url="https://internal.pypi.com",
            registry="internal",
        )
        async with repo:
            info = await repo.check("requests")

        assert info is not None
        assert info.registry == "internal"


# ---------------------------------------------------------------------------
# _determine_latest_version()
# ---------------------------------------------------------------------------


class TestDetermineLatestVersion:
    def test_stable_versions_only(self):
        """When all versions are stable, return the max."""
        versions = [Version("1.0"), Version("2.0"), Version("1.5")]
        result = _determine_latest_version(versions)
        assert result == Version("2.0")

    def test_filters_out_prereleases(self):
        """Pre-releases should be filtered, returning the latest stable."""
        versions = [
            Version("1.9.0"),
            Version("2.0.0rc1"),
            Version("2.0.0a1"),
        ]
        result = _determine_latest_version(versions)
        assert result == Version("1.9.0")

    def test_filters_out_dev_releases(self):
        versions = [Version("1.0"), Version("2.0.dev1")]
        result = _determine_latest_version(versions)
        assert result == Version("1.0")

    def test_all_prereleases_fallback_to_max(self):
        """If all versions are pre-releases, return the highest."""
        versions = [Version("1.0a1"), Version("2.0rc1")]
        result = _determine_latest_version(versions)
        assert result == Version("2.0rc1")

    def test_legacy_info_preferred(self):
        """When legacy API provides version, use it regardless."""
        versions = [Version("1.0"), Version("2.0rc1")]
        legacy_info = {"version": "1.0"}
        result = _determine_latest_version(versions, legacy_info)
        assert result == Version("1.0")

    def test_legacy_info_unparseable_falls_back(self):
        """If legacy version string is garbage, fall back to filtering."""
        versions = [Version("1.0"), Version("2.0rc1")]
        legacy_info = {"version": "not-a-version"}
        result = _determine_latest_version(versions, legacy_info)
        assert result == Version("1.0")

    def test_legacy_info_none_falls_back(self):
        versions = [Version("1.0"), Version("2.0rc1")]
        result = _determine_latest_version(versions, None)
        assert result == Version("1.0")

    def test_legacy_info_empty_version_falls_back(self):
        versions = [Version("1.0"), Version("2.0rc1")]
        legacy_info = {"version": ""}
        result = _determine_latest_version(versions, legacy_info)
        assert result == Version("1.0")


# ---------------------------------------------------------------------------
# check() — latest version filtering
# ---------------------------------------------------------------------------


class TestPyPICheckLatestVersion:
    @respx.mock
    async def test_check_uses_legacy_version_as_latest(self):
        """check() should use the legacy API's version as latest stable."""
        respx.get("https://pypi.org/simple/pkg/").mock(
            return_value=httpx.Response(
                200,
                json={
                    "meta": {"api-version": "1.1"},
                    "name": "pkg",
                    "versions": ["1.0.0", "2.0.0rc1"],
                    "files": [],
                },
            ),
        )
        respx.get("https://pypi.org/pypi/pkg/json").mock(
            return_value=httpx.Response(
                200,
                json={"info": {"version": "1.0.0", "summary": "A package"}},
            ),
        )

        async with PyPIRepository() as repo:
            info = await repo.check("pkg")

        assert info is not None
        assert info.latest_version == Version("1.0.0")

    @respx.mock
    async def test_check_filters_prereleases_when_legacy_fails(self):
        """When legacy API fails, filter pre-releases locally."""
        respx.get("https://pypi.org/simple/pkg/").mock(
            return_value=httpx.Response(
                200,
                json={
                    "meta": {"api-version": "1.1"},
                    "name": "pkg",
                    "versions": ["1.0.0", "2.0.0rc1"],
                    "files": [],
                },
            ),
        )
        respx.get("https://pypi.org/pypi/pkg/json").mock(
            return_value=httpx.Response(500),
        )

        async with PyPIRepository() as repo:
            info = await repo.check("pkg")

        assert info is not None
        assert info.latest_version == Version("1.0.0")


# ---------------------------------------------------------------------------
# Yanked distribution parsing
# ---------------------------------------------------------------------------


class TestYankedParsing:
    def test_not_yanked_by_default(self):
        f = _file_dict_to_model(
            {
                "filename": "pkg-1.0.tar.gz",
                "url": "https://example.com/pkg-1.0.tar.gz",
                "hashes": {},
            }
        )
        assert f.yanked is False
        assert f.yanked_reason is None

    def test_yanked_boolean_true(self):
        f = _file_dict_to_model(
            {
                "filename": "pkg-1.0.tar.gz",
                "url": "https://example.com/pkg-1.0.tar.gz",
                "hashes": {},
                "yanked": True,
            }
        )
        assert f.yanked is True
        assert f.yanked_reason is None

    def test_yanked_boolean_false(self):
        f = _file_dict_to_model(
            {
                "filename": "pkg-1.0.tar.gz",
                "url": "https://example.com/pkg-1.0.tar.gz",
                "hashes": {},
                "yanked": False,
            }
        )
        assert f.yanked is False
        assert f.yanked_reason is None

    def test_yanked_with_reason_string(self):
        f = _file_dict_to_model(
            {
                "filename": "pkg-1.0.tar.gz",
                "url": "https://example.com/pkg-1.0.tar.gz",
                "hashes": {},
                "yanked": "Broken on Python 3.10",
            }
        )
        assert f.yanked is True
        assert f.yanked_reason == "Broken on Python 3.10"


# ---------------------------------------------------------------------------
# URL normalization
# ---------------------------------------------------------------------------


class TestURLNormalization:
    def test_absolute_url_preserved(self):
        f = _file_dict_to_model(
            {
                "filename": "pkg-1.0.tar.gz",
                "url": "https://cdn.example.com/pkg-1.0.tar.gz",
                "hashes": {},
            }
        )
        assert f.url == "https://cdn.example.com/pkg-1.0.tar.gz"

    def test_fragment_stripped(self):
        f = _file_dict_to_model(
            {
                "filename": "pkg-1.0.tar.gz",
                "url": "https://cdn.example.com/pkg-1.0.tar.gz#sha256=abc",
                "hashes": {},
            }
        )
        assert f.url == "https://cdn.example.com/pkg-1.0.tar.gz"
        assert "#" not in f.url

    def test_relative_url_resolved_with_page_url(self):
        f = _file_dict_to_model(
            {
                "filename": "pkg-1.0.tar.gz",
                "url": "../../packages/pkg-1.0.tar.gz",
                "hashes": {},
            },
            page_url="https://pypi.org/simple/pkg/",
        )
        assert f.url == "https://pypi.org/packages/pkg-1.0.tar.gz"

    def test_relative_url_with_fragment_resolved(self):
        f = _file_dict_to_model(
            {
                "filename": "pkg-1.0.tar.gz",
                "url": "../../packages/pkg-1.0.tar.gz#sha256=abc",
                "hashes": {},
            },
            page_url="https://pypi.org/simple/pkg/",
        )
        assert f.url == "https://pypi.org/packages/pkg-1.0.tar.gz"
        assert "#" not in f.url

    def test_no_page_url_uses_raw(self):
        """When page_url is empty, the raw URL is used as-is (minus fragment)."""
        f = _file_dict_to_model(
            {
                "filename": "pkg-1.0.tar.gz",
                "url": "https://cdn.example.com/pkg-1.0.tar.gz#sha256=abc",
                "hashes": {},
            }
        )
        assert f.url == "https://cdn.example.com/pkg-1.0.tar.gz"


# ---------------------------------------------------------------------------
# Retry behavior
# ---------------------------------------------------------------------------


class TestRetryBehavior:
    @pytest.mark.parametrize("error_code", [429, 500])
    @respx.mock
    async def test_retries_on_transient_error(self, error_code: int):
        """Transient HTTP errors should be retried, succeeding on the second attempt."""
        route = respx.get("https://pypi.org/simple/pkg/")
        route.side_effect = [
            httpx.Response(error_code),
            httpx.Response(
                200,
                json={
                    "meta": {"api-version": "1.1"},
                    "name": "pkg",
                    "versions": ["1.0.0"],
                    "files": [],
                },
            ),
        ]
        respx.get("https://pypi.org/pypi/pkg/json").mock(
            return_value=httpx.Response(404),
        )

        async with PyPIRepository() as repo:
            info = await repo.check("pkg")

        assert info is not None
        assert info.latest_version == Version("1.0.0")

    @respx.mock
    async def test_gives_up_after_max_retries(self):
        """After exhausting retries on 429, raise BackendError."""
        respx.get("https://pypi.org/simple/pkg/").mock(
            return_value=httpx.Response(429),
        )

        async with PyPIRepository() as repo:
            with pytest.raises(BackendError, match="429"):
                await repo._fetch_simple("pkg")

    @respx.mock
    async def test_no_retry_on_client_error(self):
        """4xx errors (except 429) should NOT be retried."""
        route = respx.get("https://pypi.org/simple/bad/").mock(
            return_value=httpx.Response(403),
        )

        async with PyPIRepository() as repo:
            with pytest.raises(BackendError, match="403"):
                await repo._fetch_simple("bad")

        assert route.call_count == 1


# ---------------------------------------------------------------------------
# JSON decode safety
# ---------------------------------------------------------------------------


class TestJSONDecodeSafety:
    @respx.mock
    async def test_invalid_json_raises_backend_error(self):
        """Malformed JSON should be caught and wrapped."""
        respx.get("https://pypi.org/simple/pkg/").mock(
            return_value=httpx.Response(
                200,
                content=b"this is not json",
                headers={"content-type": "text/html"},
            ),
        )

        async with PyPIRepository() as repo:
            with pytest.raises(BackendError, match="Invalid JSON"):
                await repo._fetch_simple("pkg")


# ---------------------------------------------------------------------------
# Per-session Simple API caching
# ---------------------------------------------------------------------------


class TestSimpleAPICaching:
    """Verify that _fetch_simple() results are cached per session."""

    @respx.mock
    async def test_single_http_request_for_multiple_calls(self):
        """Multiple method calls for the same package hit the API once."""
        route = respx.get("https://pypi.org/simple/requests/").mock(
            return_value=httpx.Response(200, json=SIMPLE_RESPONSE_V11),
        )
        # Legacy API needed by check()
        respx.get("https://pypi.org/pypi/requests/json").mock(
            return_value=httpx.Response(200, json=LEGACY_JSON_RESPONSE),
        )

        async with PyPIRepository() as repo:
            await repo.versions("requests")
            await repo.files("requests", "2.31.0")

        assert route.call_count == 1

    @respx.mock
    async def test_cache_not_shared_across_packages(self):
        """Different packages are fetched independently."""
        route_a = respx.get("https://pypi.org/simple/requests/").mock(
            return_value=httpx.Response(200, json=SIMPLE_RESPONSE_V11),
        )
        route_b = respx.get("https://pypi.org/simple/httpx/").mock(
            return_value=httpx.Response(404),
        )

        async with PyPIRepository() as repo:
            await repo.versions("requests")
            await repo.versions("httpx")

        assert route_a.call_count == 1
        assert route_b.call_count == 1

    @respx.mock
    async def test_404_cached(self):
        """A 404 response is also cached (no retry on second call)."""
        route = respx.get("https://pypi.org/simple/nonexistent/").mock(
            return_value=httpx.Response(404),
        )

        async with PyPIRepository() as repo:
            await repo.versions("nonexistent")
            await repo.versions("nonexistent")

        assert route.call_count == 1


# ---------------------------------------------------------------------------
# _parse_upload_time
# ---------------------------------------------------------------------------


class TestParseUploadTime:
    """Test `_parse_upload_time` ISO 8601 parsing."""

    def test_iso_with_z_suffix(self) -> None:
        """Parse ISO 8601 timestamp with 'Z' UTC suffix."""
        result = _parse_upload_time("2024-01-15T10:30:00Z")
        assert result is not None
        assert result.year == 2024
        assert result.month == 1
        assert result.day == 15
        assert result.hour == 10
        assert result.minute == 30
        assert result.tzinfo == timezone.utc

    def test_iso_with_utc_offset(self) -> None:
        """Parse ISO 8601 timestamp with '+00:00' suffix."""
        result = _parse_upload_time("2024-06-20T14:00:00+00:00")
        assert result is not None
        assert result.year == 2024
        assert result.month == 6
        assert result.day == 20

    def test_malformed_string(self) -> None:
        """Return None for malformed timestamp strings."""
        assert _parse_upload_time("not-a-date") is None

    def test_none_input(self) -> None:
        """Return None when input is None."""
        assert _parse_upload_time(None) is None

    def test_empty_string(self) -> None:
        """Return None when input is an empty string."""
        assert _parse_upload_time("") is None
