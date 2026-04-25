"""Unit tests for shared utility functions (`peeq.utils`).

Tests cover `extract_extra` and `group_dependencies` which handle
PEP 508 marker parsing and dependency grouping by extras.
"""

from __future__ import annotations

from peeq.utils import extract_extra, group_dependencies
from tests.test_output._helpers import _dep

# ---------------------------------------------------------------------------
# Tests: extract_extra
# ---------------------------------------------------------------------------


class TestExtractExtra:
    """Test extra name extraction from PEP 508 markers."""

    def test_no_markers(self) -> None:
        """Return None when dependency has no markers."""
        dep = _dep(markers=None)
        assert extract_extra(dep) is None

    def test_simple_extra(self) -> None:
        """Extract extra from simple `extra == "name"` marker."""
        dep = _dep(markers='extra == "socks"')
        assert extract_extra(dep) == "socks"

    def test_single_quotes(self) -> None:
        """Extract extra when single quotes are used."""
        dep = _dep(markers="extra == 'security'")
        assert extract_extra(dep) == "security"

    def test_compound_marker_with_extra(self) -> None:
        """Extract extra from compound marker expression."""
        dep = _dep(markers='extra == "dev" and python_version >= "3.8"')
        assert extract_extra(dep) == "dev"

    def test_markers_without_extra(self) -> None:
        """Return None when markers exist but contain no extra condition."""
        dep = _dep(markers='python_version >= "3.8"')
        assert extract_extra(dep) is None

    def test_no_whitespace_around_operator(self) -> None:
        """Handle no whitespace around `==`."""
        dep = _dep(markers='extra=="test"')
        assert extract_extra(dep) == "test"


# ---------------------------------------------------------------------------
# Tests: group_dependencies
# ---------------------------------------------------------------------------


class TestGroupDependencies:
    """Test dependency grouping into required and optional."""

    def test_empty_list(self) -> None:
        """Return empty required list and empty optional dict."""
        required, optional = group_dependencies([])
        assert required == []
        assert optional == {}

    def test_all_required(self) -> None:
        """All dependencies without extra markers go to required."""
        deps = [_dep("requests"), _dep("click")]
        required, optional = group_dependencies(deps)
        assert len(required) == 2
        assert optional == {}

    def test_all_optional(self) -> None:
        """All dependencies with extra markers go to optional."""
        deps = [
            _dep("pysocks", markers='extra == "socks"'),
            _dep("h2", markers='extra == "http2"'),
        ]
        required, optional = group_dependencies(deps)
        assert required == []
        assert "socks" in optional
        assert "http2" in optional

    def test_mixed(self) -> None:
        """Split correctly when both required and optional are present."""
        deps = [
            _dep("requests"),
            _dep("pysocks", markers='extra == "socks"'),
            _dep("click"),
        ]
        required, optional = group_dependencies(deps)
        assert len(required) == 2
        assert len(optional) == 1
        assert optional["socks"][0].name == "pysocks"

    def test_multiple_deps_same_extra(self) -> None:
        """Group multiple dependencies under the same extra."""
        deps = [
            _dep("sphinx", markers='extra == "docs"'),
            _dep("furo", markers='extra == "docs"'),
        ]
        required, optional = group_dependencies(deps)
        assert required == []
        assert len(optional["docs"]) == 2
