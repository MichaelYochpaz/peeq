"""Tests for `PackageService.diff_dependencies`.

All tests use mock-only unit tests with helper factories for
`Dependency` and `PackageMetadata`.  No real HTTP or database I/O.
"""

from __future__ import annotations

from peeq.models import Dependency
from tests.test_service.conftest import _make_service, _metadata

# ---------------------------------------------------------------------------
# Local helpers
# ---------------------------------------------------------------------------


def _dep(
    name: str,
    specifier: str = "",
    *,
    extras: list[str] | None = None,
    markers: str | None = None,
) -> Dependency:
    """Create a `Dependency` for testing."""
    return Dependency(
        name=name,
        specifier=specifier,
        extras=extras or [],
        markers=markers,
        raw=f"{name}{specifier}",
    )


# ---------------------------------------------------------------------------
# Basic diff tests
# ---------------------------------------------------------------------------


class TestDiffBasic:
    """Basic diff with added, removed, changed, and unchanged deps."""

    def test_added_dependency(self) -> None:
        """Dependency in target but not base is reported as added."""
        base = _metadata([_dep("requests", ">=2.0")])
        target = _metadata([_dep("requests", ">=2.0"), _dep("click", ">=7.0")])

        result = _make_service().diff_dependencies(base, target)

        assert len(result.added) == 1
        assert result.added[0].name == "click"
        assert result.unchanged_count == 1

    def test_removed_dependency(self) -> None:
        """Dependency in base but not target is reported as removed."""
        base = _metadata([_dep("requests", ">=2.0"), _dep("click", ">=7.0")])
        target = _metadata([_dep("requests", ">=2.0")])

        result = _make_service().diff_dependencies(base, target)

        assert len(result.removed) == 1
        assert result.removed[0].name == "click"
        assert result.unchanged_count == 1

    def test_changed_specifier(self) -> None:
        """Same dep name with different specifier is reported as changed."""
        base = _metadata([_dep("kubernetes", "==35.0.0a1")])
        target = _metadata([_dep("kubernetes", "==35.0.0")])

        result = _make_service().diff_dependencies(base, target)

        assert len(result.changed) == 1
        assert result.changed[0].name == "kubernetes"
        assert result.changed[0].old_specifier == "==35.0.0a1"
        assert result.changed[0].new_specifier == "==35.0.0"

    def test_unchanged_count(self) -> None:
        """Dependencies identical in both versions are counted."""
        deps = [_dep("requests", ">=2.0"), _dep("click", ">=7.0")]
        base = _metadata(deps)
        target = _metadata(deps)

        result = _make_service().diff_dependencies(base, target)

        assert result.unchanged_count == 2
        assert result.added == []
        assert result.removed == []
        assert result.changed == []

    def test_mixed_changes(self) -> None:
        """Mix of added, removed, changed, and unchanged deps."""
        base = _metadata(
            [
                _dep("requests", ">=2.0"),
                _dep("click", ">=7.0"),
                _dep("flask", ">=2.0"),
            ]
        )
        target = _metadata(
            [
                _dep("requests", ">=2.0"),
                _dep("click", ">=8.0"),
                _dep("httpx", ">=0.24"),
            ]
        )

        result = _make_service().diff_dependencies(base, target)

        assert result.unchanged_count == 1  # requests
        assert len(result.changed) == 1  # click specifier changed
        assert result.changed[0].name == "click"
        assert len(result.removed) == 1  # flask removed
        assert result.removed[0].name == "flask"
        assert len(result.added) == 1  # httpx added
        assert result.added[0].name == "httpx"


# ---------------------------------------------------------------------------
# Extras group tests
# ---------------------------------------------------------------------------


class TestDiffExtrasGroups:
    """Extras groups added/removed between versions."""

    def test_added_extras_group(self) -> None:
        """New extras group in target is detected."""
        base = _metadata([_dep("requests", ">=2.0")])
        target = _metadata(
            [
                _dep("requests", ">=2.0"),
                _dep("socks", ">=1.0", markers='extra == "socks"'),
            ]
        )

        result = _make_service().diff_dependencies(base, target)

        assert "socks" in result.added_extras
        assert result.added[0].name == "socks"

    def test_removed_extras_group(self) -> None:
        """Extras group removed from target is detected."""
        base = _metadata(
            [
                _dep("requests", ">=2.0"),
                _dep("socks", ">=1.0", markers='extra == "socks"'),
            ]
        )
        target = _metadata([_dep("requests", ">=2.0")])

        result = _make_service().diff_dependencies(base, target)

        assert "socks" in result.removed_extras
        assert result.removed[0].name == "socks"

    def test_dep_moving_from_core_to_extras(self) -> None:
        """Dependency moving from core to extras group appears as removed + added."""
        base = _metadata([_dep("socks", ">=1.0")])
        target = _metadata(
            [
                _dep("socks", ">=1.0", markers='extra == "proxy"'),
            ]
        )

        result = _make_service().diff_dependencies(base, target)

        # Removed from core
        assert len(result.removed) == 1
        assert result.removed[0].name == "socks"
        # Added to extras group
        assert len(result.added) == 1
        assert result.added[0].name == "socks"
        assert "proxy" in result.added_extras


# ---------------------------------------------------------------------------
# Marker and extras changes
# ---------------------------------------------------------------------------


class TestDiffMarkerChanges:
    """Marker changes detected on a matched dependency."""

    def test_marker_change_detected(self) -> None:
        """Same name, same specifier, different markers = changed."""
        base = _metadata(
            [
                _dep("colorama", ">=0.4", markers='sys_platform == "win32"'),
            ]
        )
        target = _metadata(
            [
                _dep("colorama", ">=0.4", markers='os_name == "nt"'),
            ]
        )

        result = _make_service().diff_dependencies(base, target)

        assert len(result.changed) == 1
        assert result.changed[0].old_markers == 'sys_platform == "win32"'
        assert result.changed[0].new_markers == 'os_name == "nt"'

    def test_marker_added(self) -> None:
        """Marker added where there was none before."""
        base = _metadata([_dep("colorama", ">=0.4")])
        target = _metadata(
            [
                _dep("colorama", ">=0.4", markers='sys_platform == "win32"'),
            ]
        )

        result = _make_service().diff_dependencies(base, target)

        assert len(result.changed) == 1
        assert result.changed[0].old_markers is None
        assert result.changed[0].new_markers == 'sys_platform == "win32"'


class TestDiffDependencyExtras:
    """Dependency extras changes (e.g., httpx -> httpx[http2])."""

    def test_extras_change_detected(self) -> None:
        """Same name, different requested extras = changed."""
        base = _metadata([_dep("httpx", ">=0.24")])
        target = _metadata([_dep("httpx", ">=0.24", extras=["http2"])])

        result = _make_service().diff_dependencies(base, target)

        assert len(result.changed) == 1
        assert result.changed[0].old_extras == ()
        assert result.changed[0].new_extras == ("http2",)

    def test_extras_removed(self) -> None:
        """Extras removed from a dependency."""
        base = _metadata([_dep("httpx", ">=0.24", extras=["http2"])])
        target = _metadata([_dep("httpx", ">=0.24")])

        result = _make_service().diff_dependencies(base, target)

        assert len(result.changed) == 1
        assert result.changed[0].old_extras == ("http2",)
        assert result.changed[0].new_extras == ()


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


class TestDiffEdgeCases:
    """Edge cases for diff computation."""

    def test_both_empty(self) -> None:
        """Both versions with zero deps produce clean empty diff."""
        base = _metadata([])
        target = _metadata([])

        result = _make_service().diff_dependencies(base, target)

        assert result.added == []
        assert result.removed == []
        assert result.changed == []
        assert result.unchanged_count == 0
        assert result.added_extras == []
        assert result.removed_extras == []

    def test_none_deps_treated_as_empty(self) -> None:
        """`None` dependencies treated as empty list for diffing."""
        base = _metadata(None)
        target = _metadata([_dep("requests", ">=2.0")])

        result = _make_service().diff_dependencies(base, target)

        assert len(result.added) == 1
        assert result.added[0].name == "requests"

    def test_name_normalization(self) -> None:
        """Dependencies with different name casing are matched."""
        base = _metadata([_dep("My-Package", ">=1.0")])
        target = _metadata([_dep("my-package", ">=2.0")])

        result = _make_service().diff_dependencies(base, target)

        # Should be detected as changed, not as removed + added
        assert len(result.changed) == 1
        assert result.added == []
        assert result.removed == []

    def test_extras_group_change_within_group(self) -> None:
        """Change within an extras group is detected with correct extras_group."""
        base = _metadata(
            [
                _dep("socks", ">=1.0", markers='extra == "proxy"'),
            ]
        )
        target = _metadata(
            [
                _dep("socks", ">=2.0", markers='extra == "proxy"'),
            ]
        )

        result = _make_service().diff_dependencies(base, target)

        assert len(result.changed) == 1
        assert result.changed[0].extras_group == "proxy"
        assert result.changed[0].old_specifier == ">=1.0"
        assert result.changed[0].new_specifier == ">=2.0"
