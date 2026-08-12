"""Unit tests for the `versions` CLI command.

Covers `--matching`, `--pre`, `--yanked`, `--limit`, and `--all`
flag behavior, error handling, and renderer argument contracts for
`peeq versions`.

All tests use mock-only isolation — no network or filesystem access.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from packaging.version import Version

from peeq.cli import _DEFAULT_VERSION_LIMIT, versions
from peeq.models import VersionInfo

# ---------------------------------------------------------------------------
# Helpers / factories
# ---------------------------------------------------------------------------


def _version_info(
    version: str,
    *,
    yanked: bool = False,
    yanked_reason: str | None = None,
) -> VersionInfo:
    """Create a `VersionInfo` with minimal defaults."""
    return VersionInfo(
        version=Version(version),
        yanked=yanked,
        yanked_reason=yanked_reason,
    )


def _make_versions(*specs: str) -> list[VersionInfo]:
    """Create a list of `VersionInfo` from version strings."""
    return [_version_info(s) for s in specs]


def _make_renderer() -> MagicMock:
    """Create a mock renderer with a `render_error` that records calls."""
    renderer = MagicMock()
    renderer.render_error = MagicMock()
    renderer.render_not_found = MagicMock()
    renderer.render_versions = MagicMock()
    return renderer


def _make_service(versions: list[VersionInfo]) -> AsyncMock:
    """Create a mock service whose `versions()` returns *versions*."""
    service = AsyncMock()
    service.versions = AsyncMock(return_value=versions)
    return service


# ---------------------------------------------------------------------------
# Tests: --matching filter correctness
# ---------------------------------------------------------------------------


class TestMatchingFilter:
    """Test that --matching filters version lists correctly."""

    async def test_gte_filter(self) -> None:
        """`>=2.0.0` includes only versions >= 2.0.0."""
        all_versions = _make_versions("3.0.0", "2.0.0", "1.5.0", "1.0.0")
        renderer = _make_renderer()
        service = _make_service(all_versions)

        with (
            patch("peeq.cli._get_renderer", return_value=renderer),
            patch("peeq.cli._open_service", return_value=_AsyncCtx(service)),
        ):
            await versions("testpkg", matching=">=2.0.0", pre=False)

        renderer.render_versions.assert_called_once()
        rendered_versions = renderer.render_versions.call_args.args[1]
        rendered_strs = [str(v.version) for v in rendered_versions]
        assert rendered_strs == ["3.0.0", "2.0.0"]

    async def test_lt_filter(self) -> None:
        """`<2.0.0` excludes versions >= 2.0.0."""
        all_versions = _make_versions("3.0.0", "2.0.0", "1.5.0", "1.0.0")
        renderer = _make_renderer()
        service = _make_service(all_versions)

        with (
            patch("peeq.cli._get_renderer", return_value=renderer),
            patch("peeq.cli._open_service", return_value=_AsyncCtx(service)),
        ):
            await versions("testpkg", matching="<2.0.0", pre=False)

        rendered_versions = renderer.render_versions.call_args.args[1]
        rendered_strs = [str(v.version) for v in rendered_versions]
        assert rendered_strs == ["1.5.0", "1.0.0"]

    async def test_exact_filter(self) -> None:
        """`==1.5.0` matches exactly one version."""
        all_versions = _make_versions("3.0.0", "2.0.0", "1.5.0", "1.0.0")
        renderer = _make_renderer()
        service = _make_service(all_versions)

        with (
            patch("peeq.cli._get_renderer", return_value=renderer),
            patch("peeq.cli._open_service", return_value=_AsyncCtx(service)),
        ):
            await versions("testpkg", matching="==1.5.0", pre=False)

        rendered_versions = renderer.render_versions.call_args.args[1]
        assert len(rendered_versions) == 1
        assert str(rendered_versions[0].version) == "1.5.0"

    async def test_compatible_release_filter(self) -> None:
        """`~=1.5.0` matches >=1.5.0, <1.6.0."""
        all_versions = _make_versions("2.0.0", "1.5.3", "1.5.0", "1.4.0")
        renderer = _make_renderer()
        service = _make_service(all_versions)

        with (
            patch("peeq.cli._get_renderer", return_value=renderer),
            patch("peeq.cli._open_service", return_value=_AsyncCtx(service)),
        ):
            await versions("testpkg", matching="~=1.5.0", pre=False)

        rendered_versions = renderer.render_versions.call_args.args[1]
        rendered_strs = [str(v.version) for v in rendered_versions]
        assert rendered_strs == ["1.5.3", "1.5.0"]

    async def test_compound_filter(self) -> None:
        """`>=1.0.0,<2.0.0` matches range intersection."""
        all_versions = _make_versions("3.0.0", "2.0.0", "1.5.0", "1.0.0", "0.9.0")
        renderer = _make_renderer()
        service = _make_service(all_versions)

        with (
            patch("peeq.cli._get_renderer", return_value=renderer),
            patch("peeq.cli._open_service", return_value=_AsyncCtx(service)),
        ):
            await versions("testpkg", matching=">=1.0.0,<2.0.0", pre=False)

        rendered_versions = renderer.render_versions.call_args.args[1]
        rendered_strs = [str(v.version) for v in rendered_versions]
        assert rendered_strs == ["1.5.0", "1.0.0"]


# ---------------------------------------------------------------------------
# Tests: --pre (pre-release handling)
# ---------------------------------------------------------------------------


class TestPreReleaseHandling:
    """Test that pre-release filtering follows PEP 440 semantics."""

    async def test_prerelease_excluded_by_default(self) -> None:
        """Pre-releases are excluded by default when --matching is used."""
        all_versions = _make_versions("2.0.0a1", "1.0.0", "0.9.0")
        renderer = _make_renderer()
        service = _make_service(all_versions)

        with (
            patch("peeq.cli._get_renderer", return_value=renderer),
            patch("peeq.cli._open_service", return_value=_AsyncCtx(service)),
        ):
            await versions("testpkg", matching=">=0.9.0", pre=False)

        rendered_versions = renderer.render_versions.call_args.args[1]
        rendered_strs = [str(v.version) for v in rendered_versions]
        assert rendered_strs == ["1.0.0", "0.9.0"]

    async def test_prerelease_included_with_pre_flag(self) -> None:
        """Pre-releases are included when --pre is set."""
        all_versions = _make_versions("2.0.0a1", "1.0.0", "0.9.0")
        renderer = _make_renderer()
        service = _make_service(all_versions)

        with (
            patch("peeq.cli._get_renderer", return_value=renderer),
            patch("peeq.cli._open_service", return_value=_AsyncCtx(service)),
        ):
            await versions("testpkg", matching=">=0.9.0", pre=True)

        rendered_versions = renderer.render_versions.call_args.args[1]
        rendered_strs = [str(v.version) for v in rendered_versions]
        assert rendered_strs == ["2.0.0a1", "1.0.0", "0.9.0"]

    async def test_prerelease_included_when_specifier_pins_pre(self) -> None:
        """Pre-releases match when specifier explicitly pins one (PEP 440)."""
        all_versions = _make_versions("2.0.0a1", "2.0.0a2", "1.0.0")
        renderer = _make_renderer()
        service = _make_service(all_versions)

        with (
            patch("peeq.cli._get_renderer", return_value=renderer),
            patch("peeq.cli._open_service", return_value=_AsyncCtx(service)),
        ):
            await versions("testpkg", matching="==2.0.0a1", pre=False)

        rendered_versions = renderer.render_versions.call_args.args[1]
        rendered_strs = [str(v.version) for v in rendered_versions]
        assert rendered_strs == ["2.0.0a1"]

    async def test_pre_without_matching_errors(self) -> None:
        """`--pre` without `--matching` is an error."""
        renderer = _make_renderer()

        with (
            patch("peeq.cli._get_renderer", return_value=renderer),
            pytest.raises(SystemExit, match="1"),
        ):
            await versions("testpkg", matching=None, pre=True)

        renderer.render_error.assert_called_once_with("--pre requires --matching")


# ---------------------------------------------------------------------------
# Tests: error cases
# ---------------------------------------------------------------------------


class TestErrorCases:
    """Test error handling for invalid input and zero-match scenarios."""

    async def test_invalid_specifier_renders_error(self) -> None:
        """Invalid specifier renders an error, not a traceback."""
        all_versions = _make_versions("1.0.0")
        renderer = _make_renderer()
        service = _make_service(all_versions)

        with (
            patch("peeq.cli._get_renderer", return_value=renderer),
            patch("peeq.cli._open_service", return_value=_AsyncCtx(service)),
            pytest.raises(SystemExit, match="1"),
        ):
            await versions("testpkg", matching="not_valid", pre=False)

        renderer.render_error.assert_called_once()
        msg = renderer.render_error.call_args.args[0]
        assert "Invalid specifier" in msg

    async def test_zero_match_produces_error(self) -> None:
        """Zero-match case produces a specific error message."""
        all_versions = _make_versions("1.0.0", "0.9.0")
        renderer = _make_renderer()
        service = _make_service(all_versions)

        with (
            patch("peeq.cli._get_renderer", return_value=renderer),
            patch("peeq.cli._open_service", return_value=_AsyncCtx(service)),
            pytest.raises(SystemExit, match="1"),
        ):
            await versions("testpkg", matching=">=99.0.0", pre=False)

        renderer.render_error.assert_called_once()
        msg = renderer.render_error.call_args.args[0]
        assert "testpkg" in msg
        assert ">=99.0.0" in msg


# ---------------------------------------------------------------------------
# Tests: composition with other flags
# ---------------------------------------------------------------------------


class TestFlagComposition:
    """Test that --matching composes correctly with --yanked and --limit."""

    async def test_matching_with_yanked(self) -> None:
        """`--matching` + `--yanked` filters yanked versions by specifier."""
        all_versions = [
            _version_info("3.0.0", yanked=True, yanked_reason="broken"),
            _version_info("2.0.0"),
            _version_info("1.0.0", yanked=True),
        ]
        renderer = _make_renderer()
        service = _make_service(all_versions)

        with (
            patch("peeq.cli._get_renderer", return_value=renderer),
            patch("peeq.cli._open_service", return_value=_AsyncCtx(service)),
        ):
            await versions("testpkg", yanked=True, matching=">=2.0.0", pre=False)

        rendered_versions = renderer.render_versions.call_args.args[1]
        rendered_strs = [str(v.version) for v in rendered_versions]
        # Only yanked version >= 2.0.0 should remain
        assert rendered_strs == ["3.0.0"]

    async def test_matching_with_limit(self) -> None:
        """`--limit` applies AFTER `--matching` filtering."""
        all_versions = _make_versions("5.0.0", "4.0.0", "3.0.0", "2.0.0", "1.0.0")
        renderer = _make_renderer()
        service = _make_service(all_versions)

        with (
            patch("peeq.cli._get_renderer", return_value=renderer),
            patch("peeq.cli._open_service", return_value=_AsyncCtx(service)),
        ):
            await versions("testpkg", limit=2, matching=">=2.0.0", pre=False)

        rendered_versions = renderer.render_versions.call_args.args[1]
        rendered_strs = [str(v.version) for v in rendered_versions]
        # 4 versions match (5.0, 4.0, 3.0, 2.0), limit shows first 2
        assert len(rendered_strs) == 2
        assert rendered_strs == ["5.0.0", "4.0.0"]


# ---------------------------------------------------------------------------
# Tests: renderer receives correct arguments
# ---------------------------------------------------------------------------


class TestRendererArguments:
    """Test that `render_versions` is called with correct kwargs."""

    async def test_original_total_passed_when_matching(self) -> None:
        """`original_total` is passed to renderer when --matching is active."""
        all_versions = _make_versions("3.0.0", "2.0.0", "1.0.0")
        renderer = _make_renderer()
        service = _make_service(all_versions)

        with (
            patch("peeq.cli._get_renderer", return_value=renderer),
            patch("peeq.cli._open_service", return_value=_AsyncCtx(service)),
        ):
            await versions("testpkg", matching=">=2.0.0", pre=False)

        call_kwargs = renderer.render_versions.call_args.kwargs
        assert call_kwargs["matching"] == ">=2.0.0"
        assert call_kwargs["original_total"] == 3

    async def test_original_total_none_without_matching(self) -> None:
        """`original_total` is None when --matching is not used."""
        all_versions = _make_versions("2.0.0", "1.0.0")
        renderer = _make_renderer()
        service = _make_service(all_versions)

        with (
            patch("peeq.cli._get_renderer", return_value=renderer),
            patch("peeq.cli._open_service", return_value=_AsyncCtx(service)),
        ):
            await versions("testpkg", pre=False)

        call_kwargs = renderer.render_versions.call_args.kwargs
        assert call_kwargs["matching"] is None
        assert call_kwargs["original_total"] is None

    async def test_total_reflects_filtered_count(self) -> None:
        """`total` arg reflects the count AFTER filtering."""
        all_versions = _make_versions("3.0.0", "2.0.0", "1.0.0")
        renderer = _make_renderer()
        service = _make_service(all_versions)

        with (
            patch("peeq.cli._get_renderer", return_value=renderer),
            patch("peeq.cli._open_service", return_value=_AsyncCtx(service)),
        ):
            await versions("testpkg", matching=">=2.0.0", pre=False)

        total_arg = renderer.render_versions.call_args.args[2]
        assert total_arg == 2  # 3.0.0 and 2.0.0


# ---------------------------------------------------------------------------
# Tests: --all and --limit flag interactions
# ---------------------------------------------------------------------------


class TestAllFlag:
    """Test that `--all` disables the default limit."""

    async def test_all_shows_everything(self) -> None:
        """`--all` returns all versions without slicing."""
        # 30 versions — more than the default limit
        all_versions = _make_versions(*(f"{i}.0.0" for i in range(30, 0, -1)))
        renderer = _make_renderer()
        service = _make_service(all_versions)

        with (
            patch("peeq.cli._get_renderer", return_value=renderer),
            patch("peeq.cli._open_service", return_value=_AsyncCtx(service)),
        ):
            await versions("testpkg", show_all=True, pre=False)

        rendered_versions = renderer.render_versions.call_args.args[1]
        total = renderer.render_versions.call_args.args[2]

        assert total == 30
        assert len(rendered_versions) == 30

    async def test_all_and_limit_conflict(self) -> None:
        """`--all` combined with `--limit` renders an error and exits."""
        renderer = _make_renderer()

        with (
            patch("peeq.cli._get_renderer", return_value=renderer),
            pytest.raises(SystemExit, match="1"),
        ):
            await versions("testpkg", show_all=True, limit=100, pre=False)

        renderer.render_error.assert_called_once_with("--all and --limit cannot be used together")


class TestDefaultLimit:
    """Test that the default limit truncates version lists."""

    async def test_default_limit_applied(self) -> None:
        """Versions are truncated to the default limit."""
        count = _DEFAULT_VERSION_LIMIT + 10
        all_versions = _make_versions(*(f"{i}.0.0" for i in range(count, 0, -1)))
        renderer = _make_renderer()
        service = _make_service(all_versions)

        with (
            patch("peeq.cli._get_renderer", return_value=renderer),
            patch("peeq.cli._open_service", return_value=_AsyncCtx(service)),
        ):
            await versions("testpkg", pre=False)

        rendered_versions = renderer.render_versions.call_args.args[1]
        total = renderer.render_versions.call_args.args[2]

        assert len(rendered_versions) == _DEFAULT_VERSION_LIMIT
        assert total == count

    async def test_small_list_unaffected(self) -> None:
        """Lists smaller than the default limit are not truncated."""
        all_versions = _make_versions("3.0.0", "2.0.0", "1.0.0")
        renderer = _make_renderer()
        service = _make_service(all_versions)

        with (
            patch("peeq.cli._get_renderer", return_value=renderer),
            patch("peeq.cli._open_service", return_value=_AsyncCtx(service)),
        ):
            await versions("testpkg", pre=False)

        rendered_versions = renderer.render_versions.call_args.args[1]
        assert len(rendered_versions) == 3

    async def test_negative_limit_rejected(self) -> None:
        """Negative `--limit` renders an error and exits."""
        renderer = _make_renderer()

        with (
            patch("peeq.cli._get_renderer", return_value=renderer),
            pytest.raises(SystemExit, match="1"),
        ):
            await versions("testpkg", limit=-1, pre=False)

        renderer.render_error.assert_called_once_with("--limit must be non-negative")

    async def test_limit_zero_shows_nothing(self) -> None:
        """`--limit 0` produces an empty display list."""
        all_versions = _make_versions("2.0.0", "1.0.0")
        renderer = _make_renderer()
        service = _make_service(all_versions)

        with (
            patch("peeq.cli._get_renderer", return_value=renderer),
            patch("peeq.cli._open_service", return_value=_AsyncCtx(service)),
        ):
            await versions("testpkg", limit=0, pre=False)

        rendered_versions = renderer.render_versions.call_args.args[1]
        assert len(rendered_versions) == 0


# ---------------------------------------------------------------------------
# Tests: --offset flag
# ---------------------------------------------------------------------------


class TestOffset:
    """Test that `--offset` skips items before applying `--limit`."""

    async def test_offset_skips_items(self) -> None:
        """`--offset 2` skips the first two versions."""
        all_versions = _make_versions("5.0.0", "4.0.0", "3.0.0", "2.0.0", "1.0.0")
        renderer = _make_renderer()
        service = _make_service(all_versions)

        with (
            patch("peeq.cli._get_renderer", return_value=renderer),
            patch("peeq.cli._open_service", return_value=_AsyncCtx(service)),
        ):
            await versions("testpkg", offset=2, limit=2, pre=False)

        rendered_versions = renderer.render_versions.call_args.args[1]
        rendered_strs = [str(v.version) for v in rendered_versions]
        assert rendered_strs == ["3.0.0", "2.0.0"]

    async def test_offset_with_default_limit(self) -> None:
        """`--offset` with default limit skips items and applies default cap."""
        count = _DEFAULT_VERSION_LIMIT + 10
        all_versions = _make_versions(*(f"{i}.0.0" for i in range(count, 0, -1)))
        renderer = _make_renderer()
        service = _make_service(all_versions)

        with (
            patch("peeq.cli._get_renderer", return_value=renderer),
            patch("peeq.cli._open_service", return_value=_AsyncCtx(service)),
        ):
            await versions("testpkg", offset=5, pre=False)

        rendered_versions = renderer.render_versions.call_args.args[1]
        total = renderer.render_versions.call_args.args[2]

        assert total == count
        assert len(rendered_versions) == _DEFAULT_VERSION_LIMIT
        # First displayed version should be the 6th (index 5)
        assert str(rendered_versions[0].version) == f"{count - 5}.0.0"

    async def test_offset_with_all(self) -> None:
        """`--all --offset N` shows everything from offset onward."""
        all_versions = _make_versions("5.0.0", "4.0.0", "3.0.0", "2.0.0", "1.0.0")
        renderer = _make_renderer()
        service = _make_service(all_versions)

        with (
            patch("peeq.cli._get_renderer", return_value=renderer),
            patch("peeq.cli._open_service", return_value=_AsyncCtx(service)),
        ):
            await versions("testpkg", show_all=True, offset=3, pre=False)

        rendered_versions = renderer.render_versions.call_args.args[1]
        rendered_strs = [str(v.version) for v in rendered_versions]
        assert rendered_strs == ["2.0.0", "1.0.0"]

    async def test_offset_beyond_total(self) -> None:
        """`--offset` beyond total produces an empty display list."""
        all_versions = _make_versions("2.0.0", "1.0.0")
        renderer = _make_renderer()
        service = _make_service(all_versions)

        with (
            patch("peeq.cli._get_renderer", return_value=renderer),
            patch("peeq.cli._open_service", return_value=_AsyncCtx(service)),
        ):
            await versions("testpkg", offset=10, pre=False)

        rendered_versions = renderer.render_versions.call_args.args[1]
        total = renderer.render_versions.call_args.args[2]
        assert len(rendered_versions) == 0
        assert total == 2

    async def test_negative_offset_rejected(self) -> None:
        """Negative `--offset` renders an error and exits."""
        renderer = _make_renderer()

        with (
            patch("peeq.cli._get_renderer", return_value=renderer),
            pytest.raises(SystemExit, match="1"),
        ):
            await versions("testpkg", offset=-1, pre=False)

        renderer.render_error.assert_called_once_with("--offset must be non-negative")

    async def test_offset_zero_is_noop(self) -> None:
        """`--offset 0` behaves identically to no offset."""
        all_versions = _make_versions("3.0.0", "2.0.0", "1.0.0")
        renderer = _make_renderer()
        service = _make_service(all_versions)

        with (
            patch("peeq.cli._get_renderer", return_value=renderer),
            patch("peeq.cli._open_service", return_value=_AsyncCtx(service)),
        ):
            await versions("testpkg", offset=0, pre=False)

        rendered_versions = renderer.render_versions.call_args.args[1]
        assert len(rendered_versions) == 3

    async def test_offset_with_matching(self) -> None:
        """`--offset` applies AFTER `--matching` filtering."""
        all_versions = _make_versions("5.0.0", "4.0.0", "3.0.0", "2.0.0", "1.0.0")
        renderer = _make_renderer()
        service = _make_service(all_versions)

        with (
            patch("peeq.cli._get_renderer", return_value=renderer),
            patch("peeq.cli._open_service", return_value=_AsyncCtx(service)),
        ):
            await versions("testpkg", matching=">=3.0.0", offset=1, limit=2, pre=False)

        rendered_versions = renderer.render_versions.call_args.args[1]
        rendered_strs = [str(v.version) for v in rendered_versions]
        # Matched: 5.0.0, 4.0.0, 3.0.0 → offset 1 → 4.0.0, 3.0.0
        assert rendered_strs == ["4.0.0", "3.0.0"]

    async def test_offset_passed_to_renderer(self) -> None:
        """`offset` kwarg is forwarded to the renderer."""
        all_versions = _make_versions("3.0.0", "2.0.0", "1.0.0")
        renderer = _make_renderer()
        service = _make_service(all_versions)

        with (
            patch("peeq.cli._get_renderer", return_value=renderer),
            patch("peeq.cli._open_service", return_value=_AsyncCtx(service)),
        ):
            await versions("testpkg", offset=1, pre=False)

        call_kwargs = renderer.render_versions.call_args.kwargs
        assert call_kwargs["offset"] == 1

    async def test_latest_version_passed_to_renderer(self) -> None:
        """`latest_version` kwarg reflects the first version before slicing."""
        all_versions = _make_versions("5.0.0", "4.0.0", "3.0.0")
        renderer = _make_renderer()
        service = _make_service(all_versions)

        with (
            patch("peeq.cli._get_renderer", return_value=renderer),
            patch("peeq.cli._open_service", return_value=_AsyncCtx(service)),
        ):
            await versions("testpkg", offset=2, pre=False)

        call_kwargs = renderer.render_versions.call_args.kwargs
        # latest_version should be 5.0.0 regardless of offset
        assert call_kwargs["latest_version"] == "5.0.0"


# ---------------------------------------------------------------------------
# Async context manager helper
# ---------------------------------------------------------------------------


class _AsyncCtx:
    """Minimal async context manager wrapping a mock service."""

    def __init__(self, service: AsyncMock) -> None:
        self._service = service

    async def __aenter__(self) -> AsyncMock:
        return self._service

    async def __aexit__(self, *args: object) -> None:
        pass
