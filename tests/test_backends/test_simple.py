"""Tests for the Simple (PEP 503) repository backend."""

from __future__ import annotations

import hashlib
import logging
from typing import TYPE_CHECKING

import httpx
import pytest
import respx
from packaging.version import Version

from peeq.backends.base import BackendError
from peeq.backends.simple import (
    SimpleRepository,
    _extract_versions,
    _filter_files_for_version,
    _latest_stable,
    _parse_hash_from_fragment,
    _parse_metadata_attr,
    _SimpleHTMLParser,
)
from peeq.models import DistType, VersionInfo

if TYPE_CHECKING:
    from pathlib import Path

# ---------------------------------------------------------------------------
# Test HTML fixtures
# ---------------------------------------------------------------------------

SIMPLE_HTML = """\
<!DOCTYPE html>
<html>
<body>
<h1>Links for requests</h1>
<a href="../../packages/ab/cd/requests-2.31.0.tar.gz#sha256={sdist_hash}" \
data-requires-python="&gt;=3.7">requests-2.31.0.tar.gz</a>
<a href="../../packages/ef/gh/requests-2.31.0-py3-none-any.whl#sha256={whl_hash}" \
data-requires-python="&gt;=3.7" \
data-dist-info-metadata="sha256={meta_hash}">requests-2.31.0-py3-none-any.whl</a>
<a href="../../packages/ij/kl/requests-2.30.0.tar.gz#sha256={old_hash}" \
data-requires-python="&gt;=3.7">requests-2.30.0.tar.gz</a>
</body>
</html>
""".format(
    sdist_hash="a" * 64,
    whl_hash="b" * 64,
    meta_hash="c" * 64,
    old_hash="d" * 64,
)

SIMPLE_HTML_MINIMAL = """\
<!DOCTYPE html>
<html><body>
<a href="pkg-1.0.tar.gz#sha256=abc123">pkg-1.0.tar.gz</a>
</body></html>
"""

SIMPLE_HTML_WITH_YANKED = """\
<!DOCTYPE html>
<html><body>
<a href="pkg-1.0.tar.gz#sha256=abc123">pkg-1.0.tar.gz</a>
<a href="pkg-0.9.tar.gz#sha256=def456" data-yanked="security fix">pkg-0.9.tar.gz</a>
</body></html>
"""

BASE_URL = "https://simple.example.com"


# ---------------------------------------------------------------------------
# _SimpleHTMLParser
# ---------------------------------------------------------------------------


class TestSimpleHTMLParser:
    def test_parse_basic_html(self):
        parser = _SimpleHTMLParser()
        parser.feed(SIMPLE_HTML)

        assert len(parser.files) == 3

        f0 = parser.files[0]
        assert f0["filename"] == "requests-2.31.0.tar.gz"
        assert "sha256=" in (f0["href"] or "")
        assert f0["requires-python"] == ">=3.7"

    def test_parse_minimal_html(self):
        parser = _SimpleHTMLParser()
        parser.feed(SIMPLE_HTML_MINIMAL)

        assert len(parser.files) == 1
        assert parser.files[0]["filename"] == "pkg-1.0.tar.gz"

    def test_parse_yanked_with_reason(self):
        parser = _SimpleHTMLParser()
        parser.feed(SIMPLE_HTML_WITH_YANKED)

        assert len(parser.files) == 2
        assert parser.files[1]["data-yanked"] == "security fix"
        assert parser.files[0]["data-yanked"] is None

    def test_parse_yanked_bare_attribute(self):
        """Bare `data-yanked` (no value) means yanked with no reason.

        `html.parser` surfaces this as `("data-yanked", None)`.  The
        parser must NOT drop it --- presence alone means yanked (PEP 592).
        """
        parser = _SimpleHTMLParser()
        parser.feed(
            '<a href="pkg-1.0.tar.gz" data-yanked>pkg-1.0.tar.gz</a>',
        )
        assert len(parser.files) == 1
        # Normalised to "" (present but no reason), not None (absent).
        assert parser.files[0]["data-yanked"] == ""

    def test_empty_html(self):
        parser = _SimpleHTMLParser()
        parser.feed("<html><body></body></html>")
        assert parser.files == []

    def test_non_anchor_tags_ignored(self):
        parser = _SimpleHTMLParser()
        parser.feed(
            "<html><body>"
            "<h1>Links</h1>"
            "<p>Some text</p>"
            "<a href='pkg-1.0.tar.gz'>pkg-1.0.tar.gz</a>"
            "</body></html>",
        )
        assert len(parser.files) == 1

    # -- PEP 714: data-core-metadata vs data-dist-info-metadata ----------

    def test_metadata_legacy_attribute(self):
        """Legacy `data-dist-info-metadata` still works (stored as
        `core-metadata` internally)."""
        parser = _SimpleHTMLParser()
        parser.feed(
            '<a href="pkg-1.0.whl" '
            'data-dist-info-metadata="sha256=abc123">'
            "pkg-1.0.whl</a>",
        )
        assert parser.files[0]["core-metadata"] == "sha256=abc123"

    def test_metadata_modern_attribute(self):
        """PEP 714 `data-core-metadata` is parsed correctly."""
        parser = _SimpleHTMLParser()
        parser.feed(
            '<a href="pkg-1.0.whl" data-core-metadata="sha256=def456">pkg-1.0.whl</a>',
        )
        assert parser.files[0]["core-metadata"] == "sha256=def456"

    def test_metadata_pep714_preferred_over_legacy(self):
        """When both attributes are present, `data-core-metadata` wins."""
        parser = _SimpleHTMLParser()
        parser.feed(
            '<a href="pkg-1.0.whl" '
            'data-core-metadata="sha256=modern" '
            'data-dist-info-metadata="sha256=legacy">'
            "pkg-1.0.whl</a>",
        )
        assert parser.files[0]["core-metadata"] == "sha256=modern"

    def test_metadata_true(self):
        parser = _SimpleHTMLParser()
        parser.feed(
            '<a href="pkg-1.0.whl" data-core-metadata="true">pkg-1.0.whl</a>',
        )
        assert parser.files[0]["core-metadata"] == "true"

    # -- PEP 629: repository version meta tag ----------------------------

    def test_repository_version_meta_tag(self):
        parser = _SimpleHTMLParser()
        parser.feed(
            "<html><head>"
            '<meta name="pypi:repository-version" content="1.0">'
            "</head><body>"
            '<a href="pkg-1.0.tar.gz">pkg-1.0.tar.gz</a>'
            "</body></html>",
        )
        assert parser.repository_version == "1.0"
        assert len(parser.files) == 1

    def test_repository_version_absent(self):
        parser = _SimpleHTMLParser()
        parser.feed(SIMPLE_HTML_MINIMAL)
        assert parser.repository_version is None

    def test_unrelated_meta_tags_ignored(self):
        parser = _SimpleHTMLParser()
        parser.feed(
            "<html><head>"
            '<meta charset="utf-8">'
            '<meta name="generator" content="devpi">'
            "</head><body>"
            '<a href="pkg-1.0.tar.gz">pkg-1.0.tar.gz</a>'
            "</body></html>",
        )
        assert parser.repository_version is None
        assert len(parser.files) == 1

    # -- Filename fallback from href -------------------------------------

    def test_filename_fallback_from_href(self):
        """When anchor text is empty, derive filename from href path."""
        parser = _SimpleHTMLParser()
        parser.feed(
            '<a href="../../packages/pkg-1.0.tar.gz#sha256=abc"></a>',
        )
        assert len(parser.files) == 1
        assert parser.files[0]["filename"] == "pkg-1.0.tar.gz"

    def test_filename_fallback_absolute_url(self):
        """Filename fallback works with absolute URLs too."""
        parser = _SimpleHTMLParser()
        parser.feed(
            '<a href="https://cdn.example.com/path/pkg-2.0.whl#sha256=abc"></a>',
        )
        assert len(parser.files) == 1
        assert parser.files[0]["filename"] == "pkg-2.0.whl"

    def test_empty_href_and_text_skipped(self):
        """Anchors with neither href nor text are skipped."""
        parser = _SimpleHTMLParser()
        parser.feed('<a href=""></a>')
        assert parser.files == []

    # -- data-size -------------------------------------------------------

    def test_data_size_extracted(self):
        parser = _SimpleHTMLParser()
        parser.feed(
            '<a href="pkg-1.0.tar.gz" data-size="12345">pkg-1.0.tar.gz</a>',
        )
        assert parser.files[0]["data-size"] == "12345"

    def test_data_size_absent(self):
        parser = _SimpleHTMLParser()
        parser.feed(
            '<a href="pkg-1.0.tar.gz">pkg-1.0.tar.gz</a>',
        )
        assert parser.files[0]["data-size"] is None


# ---------------------------------------------------------------------------
# _parse_hash_from_fragment
# ---------------------------------------------------------------------------


class TestParseHashFromFragment:
    def test_sha256(self):
        h = _parse_hash_from_fragment("sha256=abc123")
        assert h is not None
        assert h.sha256 == "abc123"
        assert h.source == "registry"

    def test_empty_fragment(self):
        assert _parse_hash_from_fragment("") is None

    def test_no_sha256(self):
        assert _parse_hash_from_fragment("md5=abc123") is None

    def test_multiple_hashes(self):
        h = _parse_hash_from_fragment("md5=xxx&sha256=abc123")
        assert h is not None
        assert h.sha256 == "abc123"


# ---------------------------------------------------------------------------
# _parse_metadata_attr
# ---------------------------------------------------------------------------


class TestParseMetadataAttr:
    def test_none(self):
        avail, h = _parse_metadata_attr(None)
        assert avail is False
        assert h is None

    def test_false_string(self):
        avail, _h = _parse_metadata_attr("false")
        assert avail is False

    def test_true_string(self):
        avail, h = _parse_metadata_attr("true")
        assert avail is True
        assert h is None

    def test_sha256_hash(self):
        avail, h = _parse_metadata_attr("sha256=abc123")
        assert avail is True
        assert h is not None
        assert h.sha256 == "abc123"

    def test_case_insensitive_true(self):
        avail, _ = _parse_metadata_attr("True")
        assert avail is True

    def test_case_insensitive_false(self):
        avail, _ = _parse_metadata_attr("FALSE")
        assert avail is False


# ---------------------------------------------------------------------------
# _extract_versions
# ---------------------------------------------------------------------------


class TestExtractVersions:
    def test_basic(self):
        parser = _SimpleHTMLParser()
        parser.feed(SIMPLE_HTML)
        versions = _extract_versions(parser.files)
        assert Version("2.31.0") in [version.version for version in versions]
        assert Version("2.30.0") in [version.version for version in versions]

    def test_yanked_version_all_files_yanked(self):
        """All files for a version have data-yanked with reason."""
        files = [
            {
                "filename": "pkg-1.0.0.tar.gz",
                "href": "pkg-1.0.0.tar.gz",
                "data-yanked": "broken",
                "requires-python": None,
                "core-metadata": None,
                "data-size": None,
            },
            {
                "filename": "pkg-1.0.0-py3-none-any.whl",
                "href": "pkg-1.0.0-py3-none-any.whl",
                "data-yanked": "broken",
                "requires-python": None,
                "core-metadata": None,
                "data-size": None,
            },
        ]
        versions = _extract_versions(files)
        assert len(versions) == 1
        assert versions[0].version == Version("1.0.0")
        assert versions[0].yanked is True
        assert versions[0].yanked_reason == "broken"

    def test_yanked_version_bare_attribute(self):
        """Bare data-yanked (empty string) — yanked with no reason."""
        files = [
            {
                "filename": "pkg-1.0.0.tar.gz",
                "href": "pkg-1.0.0.tar.gz",
                "data-yanked": "",
                "requires-python": None,
                "core-metadata": None,
                "data-size": None,
            },
        ]
        versions = _extract_versions(files)
        assert len(versions) == 1
        assert versions[0].yanked is True
        assert versions[0].yanked_reason is None

    def test_yanked_version_mixed(self):
        """One file yanked, one not — version is NOT yanked."""
        files = [
            {
                "filename": "pkg-1.0.0.tar.gz",
                "href": "pkg-1.0.0.tar.gz",
                "data-yanked": "broken",
                "requires-python": None,
                "core-metadata": None,
                "data-size": None,
            },
            {
                "filename": "pkg-1.0.0-py3-none-any.whl",
                "href": "pkg-1.0.0-py3-none-any.whl",
                "data-yanked": None,
                "requires-python": None,
                "core-metadata": None,
                "data-size": None,
            },
        ]
        versions = _extract_versions(files)
        assert len(versions) == 1
        assert versions[0].yanked is False

    def test_empty(self):
        assert _extract_versions([]) == []

    def test_requires_python_populated(self):
        """requires_python is extracted from file entries."""
        files = [
            {
                "filename": "pkg-1.0.0-py3-none-any.whl",
                "href": "pkg-1.0.0-py3-none-any.whl",
                "data-yanked": None,
                "requires-python": ">=3.8",
                "core-metadata": None,
                "data-size": None,
            },
            {
                "filename": "pkg-2.0.0-py3-none-any.whl",
                "href": "pkg-2.0.0-py3-none-any.whl",
                "data-yanked": None,
                "requires-python": ">=3.12",
                "core-metadata": None,
                "data-size": None,
            },
        ]
        versions = _extract_versions(files)
        by_version = {v.version: v for v in versions}
        assert by_version[Version("1.0.0")].requires_python == ">=3.8"
        assert by_version[Version("2.0.0")].requires_python == ">=3.12"

    def test_requires_python_none_when_absent(self):
        """requires_python is None when files lack the attribute."""
        files = [
            {
                "filename": "pkg-1.0.0.tar.gz",
                "href": "pkg-1.0.0.tar.gz",
                "data-yanked": None,
                "requires-python": None,
                "core-metadata": None,
                "data-size": None,
            },
        ]
        versions = _extract_versions(files)
        assert versions[0].requires_python is None


# ---------------------------------------------------------------------------
# _filter_files_for_version
# ---------------------------------------------------------------------------


class TestFilterFilesForVersion:
    def test_filters_correctly(self):
        parser = _SimpleHTMLParser()
        parser.feed(SIMPLE_HTML)
        page_url = "https://simple.example.com/requests/"
        files = _filter_files_for_version(
            parser.files,
            "2.31.0",
            page_url,
        )

        assert len(files) == 2
        filenames = {f.filename for f in files}
        assert "requests-2.31.0.tar.gz" in filenames
        assert "requests-2.31.0-py3-none-any.whl" in filenames

    def test_resolves_relative_urls(self):
        parser = _SimpleHTMLParser()
        parser.feed(SIMPLE_HTML)
        page_url = "https://simple.example.com/requests/"
        files = _filter_files_for_version(
            parser.files,
            "2.31.0",
            page_url,
        )

        # URLs should be resolved from relative hrefs
        for f in files:
            assert f.url.startswith("https://simple.example.com/")
            assert "#" not in f.url  # Fragment stripped

    def test_extracts_hash_from_fragment(self):
        parser = _SimpleHTMLParser()
        parser.feed(SIMPLE_HTML)
        page_url = "https://simple.example.com/requests/"
        files = _filter_files_for_version(
            parser.files,
            "2.31.0",
            page_url,
        )

        sdist = next(f for f in files if f.dist_type == DistType.SDIST)
        assert sdist.hash is not None
        assert sdist.hash.sha256 == "a" * 64

    def test_extracts_metadata_attr(self):
        """Legacy `data-dist-info-metadata` flows through to FileInfo."""
        parser = _SimpleHTMLParser()
        parser.feed(SIMPLE_HTML)
        page_url = "https://simple.example.com/requests/"
        files = _filter_files_for_version(
            parser.files,
            "2.31.0",
            page_url,
        )

        wheel = next(f for f in files if f.dist_type == DistType.WHEEL)
        assert wheel.metadata_available is True
        assert wheel.metadata_hash is not None
        assert wheel.metadata_hash.sha256 == "c" * 64

    def test_pep714_metadata_on_fileinfo(self):
        """PEP 714 `data-core-metadata` populates FileInfo correctly."""
        html = (
            '<a href="pkg-1.0-py3-none-any.whl#sha256=aaa" '
            'data-core-metadata="sha256=meta999">'
            "pkg-1.0-py3-none-any.whl</a>"
        )
        parser = _SimpleHTMLParser()
        parser.feed(html)
        files = _filter_files_for_version(
            parser.files,
            "1.0",
            "https://r.example.com/pkg/",
        )
        assert len(files) == 1
        assert files[0].metadata_available is True
        assert files[0].metadata_hash is not None
        assert files[0].metadata_hash.sha256 == "meta999"

    def test_no_matching_version(self):
        parser = _SimpleHTMLParser()
        parser.feed(SIMPLE_HTML)
        page_url = "https://simple.example.com/requests/"
        files = _filter_files_for_version(
            parser.files,
            "99.0.0",
            page_url,
        )
        assert files == []

    def test_size_none_when_absent(self):
        """Size is None when no `data-size` attribute is present."""
        parser = _SimpleHTMLParser()
        parser.feed(SIMPLE_HTML)
        page_url = "https://simple.example.com/requests/"
        files = _filter_files_for_version(
            parser.files,
            "2.31.0",
            page_url,
        )
        for f in files:
            assert f.size is None

    def test_size_parsed_from_data_size(self):
        """`data-size` attribute is parsed into FileInfo.size."""
        html = (
            '<a href="pkg-1.0.tar.gz#sha256=abc" data-size="54321">pkg-1.0.tar.gz</a>'
        )
        parser = _SimpleHTMLParser()
        parser.feed(html)
        files = _filter_files_for_version(
            parser.files,
            "1.0",
            "https://r.example.com/pkg/",
        )
        assert len(files) == 1
        assert files[0].size == 54321

    def test_size_invalid_ignored(self):
        """Non-integer `data-size` is silently ignored."""
        html = (
            '<a href="pkg-1.0.tar.gz#sha256=abc" data-size="notanumber">'
            "pkg-1.0.tar.gz</a>"
        )
        parser = _SimpleHTMLParser()
        parser.feed(html)
        files = _filter_files_for_version(
            parser.files,
            "1.0",
            "https://r.example.com/pkg/",
        )
        assert files[0].size is None

    def test_absolute_urls_preserved(self):
        html = (
            '<a href="https://cdn.example.com/pkg-1.0.tar.gz#sha256=abc">'
            "pkg-1.0.tar.gz</a>"
        )
        parser = _SimpleHTMLParser()
        parser.feed(html)
        page_url = "https://simple.example.com/pkg/"
        files = _filter_files_for_version(parser.files, "1.0", page_url)
        assert len(files) == 1
        assert files[0].url == "https://cdn.example.com/pkg-1.0.tar.gz"

    # -- Yanked fields on FileInfo ---------------------------------------

    def test_yanked_file_fields(self):
        parser = _SimpleHTMLParser()
        parser.feed(SIMPLE_HTML_WITH_YANKED)
        page_url = "https://r.example.com/pkg/"
        files = _filter_files_for_version(parser.files, "0.9", page_url)

        assert len(files) == 1
        assert files[0].yanked is True
        assert files[0].yanked_reason == "security fix"

    def test_non_yanked_file_fields(self):
        parser = _SimpleHTMLParser()
        parser.feed(SIMPLE_HTML_WITH_YANKED)
        page_url = "https://r.example.com/pkg/"
        files = _filter_files_for_version(parser.files, "1.0", page_url)

        assert len(files) == 1
        assert files[0].yanked is False
        assert files[0].yanked_reason is None

    def test_yanked_bare_attribute_on_fileinfo(self):
        """Bare `data-yanked` → yanked=True, yanked_reason=None."""
        html = '<a href="pkg-1.0.tar.gz" data-yanked>pkg-1.0.tar.gz</a>'
        parser = _SimpleHTMLParser()
        parser.feed(html)
        files = _filter_files_for_version(
            parser.files,
            "1.0",
            "https://r.example.com/pkg/",
        )
        assert len(files) == 1
        assert files[0].yanked is True
        # Empty string reason → None (no meaningful reason)
        assert files[0].yanked_reason is None

    def test_yanked_empty_string_reason(self):
        """`data-yanked=""` → yanked=True, yanked_reason=None."""
        html = '<a href="pkg-1.0.tar.gz" data-yanked="">pkg-1.0.tar.gz</a>'
        parser = _SimpleHTMLParser()
        parser.feed(html)
        files = _filter_files_for_version(
            parser.files,
            "1.0",
            "https://r.example.com/pkg/",
        )
        assert files[0].yanked is True
        assert files[0].yanked_reason is None

    # -- Trailing slash defense ------------------------------------------

    def test_trailing_slash_added_to_page_url(self):
        """page_url without trailing slash still resolves correctly."""
        html = '<a href="pkg-1.0.tar.gz#sha256=abc">pkg-1.0.tar.gz</a>'
        parser = _SimpleHTMLParser()
        parser.feed(html)
        # No trailing slash — should be added defensively
        files = _filter_files_for_version(
            parser.files,
            "1.0",
            "https://r.example.com/simple/pkg",
        )
        assert len(files) == 1
        assert files[0].url == "https://r.example.com/simple/pkg/pkg-1.0.tar.gz"


# ---------------------------------------------------------------------------
# SimpleRepository.check()
# ---------------------------------------------------------------------------


class TestSimpleCheck:
    @respx.mock
    async def test_check_existing(self):
        respx.get(f"{BASE_URL}/requests/").mock(
            return_value=httpx.Response(200, text=SIMPLE_HTML),
        )

        async with SimpleRepository(base_url=BASE_URL) as repo:
            info = await repo.check("requests")

        assert info is not None
        assert info.name == "requests"
        assert info.latest_version == Version("2.31.0")
        assert info.version_count == 2
        assert info.summary is None  # Not available in PEP 503

    @respx.mock
    async def test_check_nonexistent(self):
        respx.get(f"{BASE_URL}/nonexistent/").mock(
            return_value=httpx.Response(404),
        )

        async with SimpleRepository(base_url=BASE_URL) as repo:
            info = await repo.check("nonexistent")

        assert info is None

    @respx.mock
    async def test_check_normalizes_name(self):
        respx.get(f"{BASE_URL}/my-package/").mock(
            return_value=httpx.Response(
                200,
                text='<a href="my-package-1.0.tar.gz">my-package-1.0.tar.gz</a>',
            ),
        )

        async with SimpleRepository(base_url=BASE_URL) as repo:
            info = await repo.check("My_Package")

        assert info is not None
        assert info.name == "my-package"


# ---------------------------------------------------------------------------
# SimpleRepository.versions()
# ---------------------------------------------------------------------------


class TestSimpleVersions:
    @respx.mock
    async def test_versions_sorted(self):
        respx.get(f"{BASE_URL}/requests/").mock(
            return_value=httpx.Response(200, text=SIMPLE_HTML),
        )

        async with SimpleRepository(base_url=BASE_URL) as repo:
            versions = await repo.versions("requests")

        assert versions == [
            VersionInfo(version=Version("2.31.0"), requires_python=">=3.7"),
            VersionInfo(version=Version("2.30.0"), requires_python=">=3.7"),
        ]

    @respx.mock
    async def test_versions_nonexistent(self):
        respx.get(f"{BASE_URL}/nope/").mock(
            return_value=httpx.Response(404),
        )

        async with SimpleRepository(base_url=BASE_URL) as repo:
            versions = await repo.versions("nope")

        assert versions == []

    @respx.mock
    async def test_versions_http_error(self):
        respx.get(f"{BASE_URL}/pkg/").mock(
            return_value=httpx.Response(500),
        )

        async with SimpleRepository(base_url=BASE_URL) as repo:
            with pytest.raises(BackendError, match="500"):
                await repo.versions("pkg")


# ---------------------------------------------------------------------------
# SimpleRepository.files()
# ---------------------------------------------------------------------------


class TestSimpleFiles:
    @respx.mock
    async def test_files_for_version(self):
        respx.get(f"{BASE_URL}/requests/").mock(
            return_value=httpx.Response(200, text=SIMPLE_HTML),
        )

        async with SimpleRepository(base_url=BASE_URL) as repo:
            files = await repo.files("requests", "2.31.0")

        assert len(files) == 2

    @respx.mock
    async def test_files_no_match(self):
        respx.get(f"{BASE_URL}/requests/").mock(
            return_value=httpx.Response(200, text=SIMPLE_HTML),
        )

        async with SimpleRepository(base_url=BASE_URL) as repo:
            files = await repo.files("requests", "99.0.0")

        assert files == []


# ---------------------------------------------------------------------------
# SimpleRepository.download()
# ---------------------------------------------------------------------------


class TestSimpleDownload:
    @respx.mock
    async def test_download(self, tmp_path: Path):
        content = b"package data"
        sha256 = hashlib.sha256(content).hexdigest()

        # Build HTML with the correct hash for the content
        html = f'<a href="pkg-1.0.tar.gz#sha256={sha256}">pkg-1.0.tar.gz</a>'
        respx.get(f"{BASE_URL}/pkg/").mock(
            return_value=httpx.Response(200, text=html),
        )
        respx.get(f"{BASE_URL}/pkg/pkg-1.0.tar.gz").mock(
            return_value=httpx.Response(200, content=content),
        )

        async with SimpleRepository(base_url=BASE_URL) as repo:
            files = await repo.files("pkg", "1.0")
            assert len(files) == 1

            dest = tmp_path / "pkg-1.0.tar.gz"
            result = await repo.download(files[0], dest)

        assert result.path == dest
        assert result.hash.sha256 == sha256
        assert result.hash.source == "registry"
        assert result.size_bytes == len(content)
        assert dest.read_bytes() == content


# ---------------------------------------------------------------------------
# Accept header and Content-Type validation
# ---------------------------------------------------------------------------


class TestContentNegotiation:
    @respx.mock
    async def test_accept_header_sent(self):
        """Verify the Accept header explicitly requests HTML (PEP 691)."""
        route = respx.get(f"{BASE_URL}/pkg/").mock(
            return_value=httpx.Response(200, text=SIMPLE_HTML_MINIMAL),
        )

        async with SimpleRepository(base_url=BASE_URL) as repo:
            await repo.check("pkg")

        assert route.called
        request = route.calls[0].request
        accept = request.headers.get("accept", "")
        assert "application/vnd.pypi.simple.v1+html" in accept
        assert "text/html" in accept

    @respx.mock
    async def test_json_content_type_rejected(self):
        """JSON response raises BackendError instead of silent failure."""
        respx.get(f"{BASE_URL}/pkg/").mock(
            return_value=httpx.Response(
                200,
                text='{"files": []}',
                headers={
                    "content-type": "application/vnd.pypi.simple.v1+json",
                },
            ),
        )

        async with SimpleRepository(base_url=BASE_URL) as repo:
            with pytest.raises(BackendError, match="JSON"):
                await repo.check("pkg")

    @respx.mock
    async def test_plain_json_content_type_rejected(self):
        """Plain `application/json` is also caught."""
        respx.get(f"{BASE_URL}/pkg/").mock(
            return_value=httpx.Response(
                200,
                text='{"files": []}',
                headers={"content-type": "application/json; charset=utf-8"},
            ),
        )

        async with SimpleRepository(base_url=BASE_URL) as repo:
            with pytest.raises(BackendError, match="JSON"):
                await repo.check("pkg")

    @respx.mock
    async def test_html_content_type_accepted(self):
        """Standard `text/html` responses are accepted normally."""
        respx.get(f"{BASE_URL}/pkg/").mock(
            return_value=httpx.Response(
                200,
                text=SIMPLE_HTML_MINIMAL,
                headers={"content-type": "text/html; charset=utf-8"},
            ),
        )

        async with SimpleRepository(base_url=BASE_URL) as repo:
            info = await repo.check("pkg")

        assert info is not None


# ---------------------------------------------------------------------------
# PEP 629: repository version warning
# ---------------------------------------------------------------------------


class TestRepositoryVersion:
    @respx.mock
    async def test_unsupported_major_version_warns(self, caplog):
        html = (
            "<html><head>"
            '<meta name="pypi:repository-version" content="2.0">'
            "</head><body>"
            '<a href="pkg-1.0.tar.gz">pkg-1.0.tar.gz</a>'
            "</body></html>"
        )
        respx.get(f"{BASE_URL}/pkg/").mock(
            return_value=httpx.Response(200, text=html),
        )

        with caplog.at_level(logging.WARNING):
            async with SimpleRepository(base_url=BASE_URL) as repo:
                info = await repo.check("pkg")

        # Should still return results (warn, not hard-fail)
        assert info is not None
        assert "version 2.0" in caplog.text
        assert "major version 1" in caplog.text

    @respx.mock
    async def test_supported_version_no_warning(self, caplog):
        html = (
            "<html><head>"
            '<meta name="pypi:repository-version" content="1.0">'
            "</head><body>"
            '<a href="pkg-1.0.tar.gz">pkg-1.0.tar.gz</a>'
            "</body></html>"
        )
        respx.get(f"{BASE_URL}/pkg/").mock(
            return_value=httpx.Response(200, text=html),
        )

        with caplog.at_level(logging.WARNING):
            async with SimpleRepository(base_url=BASE_URL) as repo:
                await repo.check("pkg")

        assert "version" not in caplog.text.lower() or "1.0" not in caplog.text

    @respx.mock
    async def test_missing_version_no_warning(self, caplog):
        """No meta tag → no warning (assume version 1.0)."""
        respx.get(f"{BASE_URL}/pkg/").mock(
            return_value=httpx.Response(200, text=SIMPLE_HTML_MINIMAL),
        )

        with caplog.at_level(logging.WARNING):
            async with SimpleRepository(base_url=BASE_URL) as repo:
                await repo.check("pkg")

        assert "version" not in caplog.text.lower()


# ---------------------------------------------------------------------------
# Registry and constructor
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Per-session Simple API caching
# ---------------------------------------------------------------------------


class TestSimpleAPICaching:
    """Verify that _fetch_simple_html() results are cached per session."""

    @respx.mock
    async def test_single_http_request_for_multiple_calls(self):
        """Multiple method calls for the same package hit the API once."""
        route = respx.get(f"{BASE_URL}/requests/").mock(
            return_value=httpx.Response(200, text=SIMPLE_HTML),
        )

        async with SimpleRepository(base_url=BASE_URL) as repo:
            await repo.versions("requests")
            await repo.files("requests", "2.31.0")

        assert route.call_count == 1

    @respx.mock
    async def test_cache_not_shared_across_packages(self):
        """Different packages are fetched independently."""
        route_a = respx.get(f"{BASE_URL}/requests/").mock(
            return_value=httpx.Response(200, text=SIMPLE_HTML),
        )
        route_b = respx.get(f"{BASE_URL}/httpx/").mock(
            return_value=httpx.Response(404),
        )

        async with SimpleRepository(base_url=BASE_URL) as repo:
            await repo.versions("requests")
            await repo.versions("httpx")

        assert route_a.call_count == 1
        assert route_b.call_count == 1

    @respx.mock
    async def test_404_cached(self):
        """A 404 response is also cached (no retry on second call)."""
        route = respx.get(f"{BASE_URL}/nonexistent/").mock(
            return_value=httpx.Response(404),
        )

        async with SimpleRepository(base_url=BASE_URL) as repo:
            await repo.versions("nonexistent")
            await repo.versions("nonexistent")

        assert route.call_count == 1


# ---------------------------------------------------------------------------
# _latest_stable
# ---------------------------------------------------------------------------


class TestLatestStable:
    """Test `_latest_stable` version selection."""

    def test_all_prereleases_fallback(self) -> None:
        """Return latest pre-release when no stable versions exist."""
        versions = [Version("1.0a1"), Version("2.0rc1"), Version("1.5b2")]
        result = _latest_stable(versions)
        assert result == Version("2.0rc1")

    def test_mix_stable_and_prerelease(self) -> None:
        """Return latest stable, ignoring pre-releases."""
        versions = [
            Version("1.0.0"),
            Version("2.0.0rc1"),
            Version("1.5.0"),
            Version("2.0.0a1"),
        ]
        result = _latest_stable(versions)
        assert result == Version("1.5.0")

    def test_single_version(self) -> None:
        """Return the only version when there is exactly one."""
        result = _latest_stable([Version("1.0.0")])
        assert result == Version("1.0.0")

    def test_single_prerelease(self) -> None:
        """Return the only pre-release when it is the sole version."""
        result = _latest_stable([Version("1.0.0a1")])
        assert result == Version("1.0.0a1")

    def test_dev_releases_excluded(self) -> None:
        """Dev releases are filtered alongside pre-releases."""
        versions = [Version("1.0.0"), Version("2.0.0.dev1")]
        result = _latest_stable(versions)
        assert result == Version("1.0.0")

    def test_all_dev_releases_fallback(self) -> None:
        """Return latest dev release when no stable versions exist."""
        versions = [Version("1.0.0.dev1"), Version("2.0.0.dev3")]
        result = _latest_stable(versions)
        assert result == Version("2.0.0.dev3")
