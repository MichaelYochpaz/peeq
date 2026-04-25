"""Tests for parse_email_metadata() and is_pure_python_wheel()."""

from __future__ import annotations

import pytest

from peeq.metadata.parsing import is_pure_python_wheel, parse_email_metadata
from tests.test_metadata.conftest import SAMPLE_METADATA, SAMPLE_METADATA_MINIMAL

# ---------------------------------------------------------------------------
# parse_email_metadata tests
# ---------------------------------------------------------------------------


class TestParseEmailMetadata:
    """Test the shared metadata parsing function."""

    def test_standard_fields(self) -> None:
        """Parse all standard fields from well-formed metadata."""
        result = parse_email_metadata(SAMPLE_METADATA, source="test")

        assert result.source == "test"
        assert result.summary == "A test package for unit tests"
        assert result.author == "Test Author"
        assert result.homepage == "https://example.com"
        assert result.python_requires == ">=3.8"
        assert result.license == "MIT"

    def test_dependencies_parsed(self) -> None:
        """Requires-Dist headers are parsed into Dependency objects."""
        result = parse_email_metadata(SAMPLE_METADATA, source="test")

        assert result.dependencies is not None
        assert len(result.dependencies) == 3

        names = [d.name for d in result.dependencies]
        assert "requests" in names
        assert "click" in names
        assert "pysocks" in names  # canonicalized

    def test_dependency_specifiers(self) -> None:
        """Version specifiers are correctly extracted."""
        result = parse_email_metadata(SAMPLE_METADATA, source="test")
        assert result.dependencies is not None

        requests_dep = next(d for d in result.dependencies if d.name == "requests")
        assert requests_dep.specifier == ">=2.0"

        click_dep = next(d for d in result.dependencies if d.name == "click")
        assert click_dep.specifier == ">=7.0"

    def test_dependency_markers(self) -> None:
        """Environment markers are correctly extracted."""
        result = parse_email_metadata(SAMPLE_METADATA, source="test")
        assert result.dependencies is not None

        socks_dep = next(d for d in result.dependencies if d.name == "pysocks")
        assert socks_dep.markers == 'extra == "socks"'

    def test_no_dependencies(self) -> None:
        """A package with no Requires-Dist headers gets an empty list."""
        result = parse_email_metadata(SAMPLE_METADATA_MINIMAL, source="test")

        assert result.dependencies is not None
        assert result.dependencies == []

    def test_missing_optional_fields(self) -> None:
        """Missing optional fields default to None."""
        result = parse_email_metadata(SAMPLE_METADATA_MINIMAL, source="test")

        assert result.summary is None
        assert result.author is None
        assert result.homepage is None
        assert result.python_requires is None
        assert result.license is None

    def test_dynamic_fields_filtering(self) -> None:
        """Fields listed in dynamic_fields are set to None."""
        text = """\
Metadata-Version: 2.2
Name: pkg
Version: 1.0.0
Summary: Test
Requires-Python: >=3.10
Requires-Dist: numpy
License: MIT
"""
        result = parse_email_metadata(
            text,
            source="test",
            dynamic_fields=["Requires-Dist", "License"],
        )

        # Dynamic fields should be None
        assert result.dependencies is None  # Requires-Dist is dynamic
        assert result.license is None  # License is dynamic

        # Non-dynamic fields should be preserved
        assert result.summary == "Test"
        assert result.python_requires == ">=3.10"

    def test_dynamic_fields_empty_list(self) -> None:
        """Empty dynamic_fields list has no effect."""
        result = parse_email_metadata(
            SAMPLE_METADATA,
            source="test",
            dynamic_fields=[],
        )

        assert result.dependencies is not None
        assert len(result.dependencies) == 3
        assert result.license == "MIT"

    def test_author_email_fallback(self) -> None:
        """Author-email is used when Author is absent."""
        text = """\
Metadata-Version: 2.1
Name: pkg
Version: 1.0.0
Author-email: author@example.com
"""
        result = parse_email_metadata(text, source="test")

        assert result.author == "author@example.com"

    def test_author_preferred_over_email(self) -> None:
        """Author is preferred when both Author and Author-email exist."""
        text = """\
Metadata-Version: 2.1
Name: pkg
Version: 1.0.0
Author: Real Name
Author-email: author@example.com
"""
        result = parse_email_metadata(text, source="test")

        assert result.author == "Real Name"

    def test_unparseable_requirement_skipped(self) -> None:
        """Invalid Requires-Dist values are skipped, not fatal."""
        text = """\
Metadata-Version: 2.1
Name: pkg
Version: 1.0.0
Requires-Dist: valid-pkg>=1.0
Requires-Dist: !!!invalid!!!
Requires-Dist: another-valid>=2.0
"""
        result = parse_email_metadata(text, source="test")

        assert result.dependencies is not None
        assert len(result.dependencies) == 2
        names = [d.name for d in result.dependencies]
        assert "valid-pkg" in names
        assert "another-valid" in names


# ---------------------------------------------------------------------------
# is_pure_python_wheel tests
# ---------------------------------------------------------------------------


class TestIsPurePythonWheel:
    """Test wheel tag classification."""

    @pytest.mark.parametrize(
        ("filename", "expected"),
        [
            pytest.param(
                "pkg-1.0.0-py3-none-any.whl",
                True,
                id="py3-none-any",
            ),
            pytest.param(
                "pkg-1.0.0-py2.py3-none-any.whl",
                True,
                id="py2.py3-none-any",
            ),
            pytest.param(
                "numpy-1.26.0-cp312-cp312-manylinux_x86_64.whl",
                False,
                id="platform-specific",
            ),
            pytest.param(
                "pkg.whl",
                False,
                id="malformed-short",
            ),
            pytest.param(
                "pkg-1.0.whl",
                False,
                id="too-few-parts",
            ),
        ],
    )
    def test_classification(self, filename: str, expected: bool) -> None:
        """Classify wheel filenames as pure Python or platform-specific."""
        assert is_pure_python_wheel(filename) is expected
