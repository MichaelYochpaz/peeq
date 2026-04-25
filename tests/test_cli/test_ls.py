"""Unit tests for the `ls` CLI command.

Covers `--all`, `--limit`, `--prefix`, and `--recursive` flag
behavior, error handling, and renderer argument contracts for
`peeq ls`.

All tests use mock-only isolation — no network or filesystem access.
`build_ls_entries` runs with real data; only the service layer and
renderer are mocked.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from peeq.cli import _DEFAULT_LS_LIMIT, ls_cmd
from peeq.extraction import ArchiveMember

# ---------------------------------------------------------------------------
# Helpers / factories
# ---------------------------------------------------------------------------


class _AsyncCtx:
    """Minimal async context manager wrapping a mock service."""

    def __init__(self, service: AsyncMock) -> None:
        self._service = service

    async def __aenter__(self) -> AsyncMock:
        return self._service

    async def __aexit__(self, *args: object) -> None:
        pass


def _make_renderer() -> MagicMock:
    """Create a mock renderer with `render_ls` and error helpers."""
    renderer = MagicMock()
    renderer.render_error = MagicMock()
    renderer.render_not_found = MagicMock()
    renderer.render_ls = MagicMock()
    return renderer


def _make_service(members: list[ArchiveMember]) -> AsyncMock:
    """Create a mock service whose `list_artifact_files` returns *members*."""
    service = AsyncMock()
    service.list_artifact_files = AsyncMock(return_value=members)
    return service


async def _mock_resolve(*args: object, **kwargs: object) -> str:
    """Stub for `_resolve_version` that always returns `"1.0.0"`."""
    return "1.0.0"


def _root_files(count: int) -> list[ArchiveMember]:
    """Create *count* simple root-level file members."""
    return [
        ArchiveMember(path=f"file_{i:02d}.py", size=100, is_dir=False)
        for i in range(count)
    ]


# ---------------------------------------------------------------------------
# Tests: flag conflicts
# ---------------------------------------------------------------------------


class TestFlagConflicts:
    """Test that mutually exclusive flags are rejected."""

    async def test_all_and_limit_conflict(self) -> None:
        """`--all` combined with `--limit` renders an error and exits."""
        renderer = _make_renderer()

        with (
            patch("peeq.cli._get_renderer", return_value=renderer),
            pytest.raises(SystemExit, match="1"),
        ):
            await ls_cmd("testpkg", all_entries=True, limit=100)

        renderer.render_error.assert_called_once_with(
            "--all and --limit cannot be used together"
        )

    async def test_negative_limit_rejected(self) -> None:
        """Negative `--limit` renders an error and exits."""
        renderer = _make_renderer()

        with (
            patch("peeq.cli._get_renderer", return_value=renderer),
            pytest.raises(SystemExit, match="1"),
        ):
            await ls_cmd("testpkg", limit=-1)

        renderer.render_error.assert_called_once_with("--limit must be non-negative")


# ---------------------------------------------------------------------------
# Tests: default behavior
# ---------------------------------------------------------------------------


class TestDefaultBehavior:
    """Test default limit, prefix, and recursive flag forwarding."""

    async def test_default_limit_applied(self) -> None:
        """Default limit of 50 slices a 60-entry result."""
        members = _root_files(60)
        renderer = _make_renderer()
        service = _make_service(members)

        with (
            patch("peeq.cli._get_renderer", return_value=renderer),
            patch("peeq.cli._open_service", return_value=_AsyncCtx(service)),
            patch("peeq.cli._resolve_version", side_effect=_mock_resolve),
        ):
            await ls_cmd("testpkg")

        renderer.render_ls.assert_called_once()
        call_args = renderer.render_ls.call_args
        display = call_args.args[2]
        total = call_args.args[3]

        assert total == 60
        assert len(display) == _DEFAULT_LS_LIMIT

    async def test_prefix_passed_to_builder(self) -> None:
        """`--prefix` value is forwarded to the renderer."""
        members = [
            ArchiveMember(path="src/__init__.py", size=50, is_dir=False),
        ]
        renderer = _make_renderer()
        service = _make_service(members)

        with (
            patch("peeq.cli._get_renderer", return_value=renderer),
            patch("peeq.cli._open_service", return_value=_AsyncCtx(service)),
            patch("peeq.cli._resolve_version", side_effect=_mock_resolve),
        ):
            await ls_cmd("testpkg", prefix="src")

        call_kwargs = renderer.render_ls.call_args.kwargs
        assert call_kwargs["prefix"] == "src"

    async def test_recursive_flag(self) -> None:
        """`--recursive` is forwarded to the renderer."""
        members = [
            ArchiveMember(path="a/b.py", size=50, is_dir=False),
        ]
        renderer = _make_renderer()
        service = _make_service(members)

        with (
            patch("peeq.cli._get_renderer", return_value=renderer),
            patch("peeq.cli._open_service", return_value=_AsyncCtx(service)),
            patch("peeq.cli._resolve_version", side_effect=_mock_resolve),
        ):
            await ls_cmd("testpkg", recursive=True)

        call_kwargs = renderer.render_ls.call_args.kwargs
        assert call_kwargs["recursive"] is True


# ---------------------------------------------------------------------------
# Tests: --all flag
# ---------------------------------------------------------------------------


class TestAllFlag:
    """Test that `--all` disables the default limit."""

    async def test_all_shows_everything(self) -> None:
        """`--all` returns all entries without slicing."""
        members = _root_files(60)
        renderer = _make_renderer()
        service = _make_service(members)

        with (
            patch("peeq.cli._get_renderer", return_value=renderer),
            patch("peeq.cli._open_service", return_value=_AsyncCtx(service)),
            patch("peeq.cli._resolve_version", side_effect=_mock_resolve),
        ):
            await ls_cmd("testpkg", all_entries=True)

        call_args = renderer.render_ls.call_args
        display = call_args.args[2]
        total = call_args.args[3]

        assert total == 60
        assert len(display) == 60


# ---------------------------------------------------------------------------
# Tests: prefix with no match
# ---------------------------------------------------------------------------


class TestPrefixNoMatch:
    """Test that a non-existent prefix renders an error and exits."""

    async def test_nonexistent_prefix_errors(self) -> None:
        """Non-existent prefix renders an error and exits with code 1."""
        members = _root_files(5)
        renderer = _make_renderer()
        service = _make_service(members)

        with (
            patch("peeq.cli._get_renderer", return_value=renderer),
            patch("peeq.cli._open_service", return_value=_AsyncCtx(service)),
            patch("peeq.cli._resolve_version", side_effect=_mock_resolve),
            pytest.raises(SystemExit, match="1"),
        ):
            await ls_cmd("testpkg", prefix="nonexistent")

        renderer.render_error.assert_called_once()
        msg = renderer.render_error.call_args.args[0]
        assert "nonexistent" in msg
        assert "peeq ls testpkg" in msg
        renderer.render_ls.assert_not_called()

    async def test_existing_prefix_empty_dir(self) -> None:
        """Prefix that matches a known dir with no children renders ls."""
        # Archive has a dir entry but no files under it (edge case).
        members = [
            ArchiveMember(path="empty_dir/", size=0, is_dir=True),
            ArchiveMember(path="README.md", size=100, is_dir=False),
        ]
        renderer = _make_renderer()
        service = _make_service(members)

        with (
            patch("peeq.cli._get_renderer", return_value=renderer),
            patch("peeq.cli._open_service", return_value=_AsyncCtx(service)),
            patch("peeq.cli._resolve_version", side_effect=_mock_resolve),
        ):
            await ls_cmd("testpkg", prefix="empty_dir")

        renderer.render_ls.assert_called_once()
        call_args = renderer.render_ls.call_args
        display = call_args.args[2]
        assert display == []
