"""Tests for extract_sdist_metadata() and select_sdist()."""

from __future__ import annotations

import zipfile

from peeq.metadata.sdist import extract_sdist_metadata, select_sdist
from tests.test_metadata.conftest import (
    SAMPLE_METADATA,
    SAMPLE_METADATA_DYNAMIC,
    SAMPLE_METADATA_MULTI_DYNAMIC,
    create_test_sdist,
    create_test_sdist_no_pkg_info,
    create_test_sdist_root_pkg_info,
    make_sdist_file_info,
    make_wheel_file_info,
)


class TestExtractSdistMetadata:
    """Test sdist PKG-INFO extraction from local files."""

    def test_happy_path(self, tmp_path) -> None:
        """Extract PKG-INFO from a well-formed sdist."""
        sdist = tmp_path / "test-package-1.0.0.tar.gz"
        create_test_sdist(sdist)

        result = extract_sdist_metadata(sdist)

        assert result is not None
        assert result.source == "sdist"
        assert result.summary == "A test package for unit tests"
        assert result.author == "Test Author"
        assert result.homepage == "https://example.com"
        assert result.python_requires == ">=3.8"
        assert result.license == "MIT"
        assert result.dependencies is not None
        assert len(result.dependencies) == 3

    def test_pkg_info_not_found_returns_none(self, tmp_path) -> None:
        """Return None when PKG-INFO is not in the sdist."""
        sdist = tmp_path / "pkg-1.0.0.tar.gz"
        create_test_sdist_no_pkg_info(sdist)

        result = extract_sdist_metadata(sdist)

        assert result is None

    def test_nonexistent_file_returns_none(self, tmp_path) -> None:
        """Return None when the sdist file does not exist."""
        sdist = tmp_path / "does-not-exist-1.0.0.tar.gz"

        result = extract_sdist_metadata(sdist)

        assert result is None

    def test_pep643_dynamic_requires_dist(self, tmp_path) -> None:
        """Dynamic Requires-Dist results in dependencies=None."""
        sdist = tmp_path / "dynamic-pkg-1.0.0.tar.gz"
        create_test_sdist(
            sdist,
            SAMPLE_METADATA_DYNAMIC,
            root_dir="dynamic-pkg-1.0.0",
        )

        result = extract_sdist_metadata(sdist)

        assert result is not None
        assert result.source == "sdist"
        assert result.dependencies is None  # Dynamic => unknowable
        assert result.license is None  # Also dynamic

        # Non-dynamic fields should be preserved
        assert result.summary == "A package with dynamic deps"
        assert result.author == "Dynamic Author"

    def test_pep643_all_dynamic(self, tmp_path) -> None:
        """All fields dynamic results in all None."""
        sdist = tmp_path / "multi-dynamic-2.0.0.tar.gz"
        create_test_sdist(
            sdist,
            SAMPLE_METADATA_MULTI_DYNAMIC,
            root_dir="multi-dynamic-2.0.0",
        )

        result = extract_sdist_metadata(sdist)

        assert result is not None
        assert result.source == "sdist"
        assert result.dependencies is None
        assert result.license is None
        assert result.python_requires is None
        assert result.summary is None
        assert result.author is None
        assert result.homepage is None

    def test_pkg_info_at_root(self, tmp_path) -> None:
        """Handle PKG-INFO at archive root (non-standard layout)."""
        sdist = tmp_path / "pkg-1.0.0.tar.gz"
        create_test_sdist_root_pkg_info(sdist, SAMPLE_METADATA)

        result = extract_sdist_metadata(sdist)

        assert result is not None
        assert result.source == "sdist"
        assert result.summary == "A test package for unit tests"

    def test_corrupt_archive_returns_none(self, tmp_path) -> None:
        """Return None for a corrupted archive file."""
        sdist = tmp_path / "corrupt-1.0.0.tar.gz"
        sdist.write_bytes(b"not a tar file")

        result = extract_sdist_metadata(sdist)

        assert result is None

    def test_zip_sdist(self, tmp_path) -> None:
        """Extract metadata from a .zip sdist."""
        sdist = tmp_path / "pkg-1.0.0.zip"
        with zipfile.ZipFile(sdist, "w") as zf:
            zf.writestr("pkg-1.0.0/PKG-INFO", SAMPLE_METADATA)

        result = extract_sdist_metadata(sdist)

        assert result is not None
        assert result.source == "sdist"


class TestSelectSdist:
    """Test sdist selection from file lists."""

    def test_prefers_tar_gz_over_zip(self) -> None:
        """Select .tar.gz sdist over .zip sdist."""
        zip_sdist = make_sdist_file_info(
            filename="pkg-1.0.0.zip",
            url="https://example.com/pkg-1.0.0.zip",
        )
        targz_sdist = make_sdist_file_info(
            filename="pkg-1.0.0.tar.gz",
            url="https://example.com/pkg-1.0.0.tar.gz",
        )

        result = select_sdist([zip_sdist, targz_sdist])

        assert result is not None
        assert result.filename == "pkg-1.0.0.tar.gz"

    def test_falls_back_to_zip(self) -> None:
        """Use .zip sdist when no .tar.gz is available."""
        zip_sdist = make_sdist_file_info(
            filename="pkg-1.0.0.zip",
        )

        result = select_sdist([zip_sdist])

        assert result is not None
        assert result.filename == "pkg-1.0.0.zip"

    def test_no_sdists_returns_none(self) -> None:
        """Return None when no sdists are available."""
        assert select_sdist([]) is None

    def test_only_wheels_returns_none(self) -> None:
        """Return None when only wheels are available."""
        wheel = make_wheel_file_info()

        assert select_sdist([wheel]) is None

    def test_yanked_sdists_skipped(self) -> None:
        """Yanked sdists are not considered."""
        yanked_sdist = make_sdist_file_info(yanked=True)

        assert select_sdist([yanked_sdist]) is None
