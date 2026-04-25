"""Tests for extract_wheel_metadata() and select_wheel()."""

from __future__ import annotations

from peeq.metadata.wheel import extract_wheel_metadata, select_wheel
from tests.test_metadata.conftest import (
    create_test_wheel,
    create_test_wheel_no_metadata,
    make_sdist_file_info,
    make_wheel_file_info,
)


class TestExtractWheelMetadata:
    """Test wheel METADATA extraction from local files."""

    def test_happy_path(self, tmp_path) -> None:
        """Extract METADATA from a well-formed wheel."""
        whl = tmp_path / "test_package-1.0.0-py3-none-any.whl"
        create_test_wheel(whl)

        result = extract_wheel_metadata(whl)

        assert result is not None
        assert result.source == "wheel"
        assert result.summary == "A test package for unit tests"
        assert result.author == "Test Author"
        assert result.python_requires == ">=3.8"
        assert result.license == "MIT"
        assert result.dependencies is not None
        assert len(result.dependencies) == 3

    def test_metadata_not_found_returns_none(self, tmp_path) -> None:
        """Return None when METADATA is not in the wheel."""
        whl = tmp_path / "pkg-1.0.0-py3-none-any.whl"
        create_test_wheel_no_metadata(whl)

        result = extract_wheel_metadata(whl)

        assert result is None

    def test_nonexistent_file_returns_none(self, tmp_path) -> None:
        """Return None when the wheel file does not exist."""
        whl = tmp_path / "does-not-exist-1.0.0-py3-none-any.whl"

        result = extract_wheel_metadata(whl)

        assert result is None

    def test_different_dist_info_name(self, tmp_path) -> None:
        """Handle dist-info directories with non-standard normalization."""
        whl = tmp_path / "My_Package-1.0.0-py3-none-any.whl"
        create_test_wheel(whl, dist_info_name="My_Package-1.0.0.dist-info")

        result = extract_wheel_metadata(whl)

        assert result is not None
        assert result.source == "wheel"

    def test_corrupt_archive_returns_none(self, tmp_path) -> None:
        """Return None for a corrupted archive file."""
        whl = tmp_path / "corrupt-1.0.0-py3-none-any.whl"
        whl.write_bytes(b"not a zip file")

        result = extract_wheel_metadata(whl)

        assert result is None

    def test_custom_metadata_text(self, tmp_path) -> None:
        """Extract metadata from a wheel with custom content."""
        custom = """\
Metadata-Version: 2.1
Name: custom
Version: 2.0.0
Summary: Custom summary
Requires-Dist: numpy>=1.20
"""
        whl = tmp_path / "custom-2.0.0-py3-none-any.whl"
        create_test_wheel(whl, custom)

        result = extract_wheel_metadata(whl)

        assert result is not None
        assert result.summary == "Custom summary"
        assert result.dependencies is not None
        assert len(result.dependencies) == 1
        assert result.dependencies[0].name == "numpy"


class TestSelectWheel:
    """Test wheel selection from file lists."""

    def test_prefers_pure_python_wheel(self) -> None:
        """Select py3-none-any wheel over platform-specific."""
        platform_wheel = make_wheel_file_info(
            filename="pkg-1.0.0-cp312-cp312-manylinux_x86_64.whl",
            size=50000,
        )
        pure_wheel = make_wheel_file_info(
            filename="pkg-1.0.0-py3-none-any.whl",
            size=5000,
        )

        result = select_wheel([platform_wheel, pure_wheel])

        assert result is not None
        assert result.filename == "pkg-1.0.0-py3-none-any.whl"

    def test_falls_back_to_smallest_wheel(self) -> None:
        """Use smallest wheel when no pure Python wheel exists."""
        large_wheel = make_wheel_file_info(
            filename="pkg-1.0.0-cp312-cp312-manylinux_x86_64.whl",
            size=50000,
        )
        small_wheel = make_wheel_file_info(
            filename="pkg-1.0.0-cp312-cp312-win_amd64.whl",
            size=10000,
        )

        result = select_wheel([large_wheel, small_wheel])

        assert result is not None
        assert result.size == 10000

    def test_no_wheels_returns_none(self) -> None:
        """Return None when no wheels are available."""
        assert select_wheel([]) is None

    def test_only_sdists_returns_none(self) -> None:
        """Return None when only sdists are available."""
        sdist = make_sdist_file_info()

        assert select_wheel([sdist]) is None

    def test_yanked_wheels_skipped(self) -> None:
        """Yanked wheels are not considered."""
        yanked_wheel = make_wheel_file_info(yanked=True)

        assert select_wheel([yanked_wheel]) is None
