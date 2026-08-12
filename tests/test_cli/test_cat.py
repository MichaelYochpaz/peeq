"""Unit tests for the `cat` CLI command.

Covers `--full`, `--max-bytes` flag behavior, truncation logic,
and `_parse_byte_size` converter for `peeq cat`.

All tests use mock-only isolation — no network or filesystem access.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from peeq.cli import _parse_byte_size, cat_cmd

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
    """Create a mock renderer with `render_file_content` and error helpers."""
    renderer = MagicMock()
    renderer.render_error = MagicMock()
    renderer.render_not_found = MagicMock()
    renderer.render_file_content = MagicMock()
    return renderer


def _make_service(content: bytes) -> AsyncMock:
    """Create a mock service whose `get_file_content` returns *content*."""
    service = AsyncMock()
    service.get_file_content = AsyncMock(return_value=content)
    return service


async def _mock_resolve(*args: object, **kwargs: object) -> str:
    """Stub for `_resolve_version` that always returns `"1.0.0"`."""
    return "1.0.0"


# ---------------------------------------------------------------------------
# Tests: flag conflicts
# ---------------------------------------------------------------------------


class TestFlagConflicts:
    """Test that mutually exclusive flags are rejected."""

    async def test_full_and_max_bytes_conflict(self) -> None:
        """`--full` combined with `--max-bytes` renders an error and exits."""
        renderer = _make_renderer()

        with (
            patch("peeq.cli._get_renderer", return_value=renderer),
            pytest.raises(SystemExit, match="1"),
        ):
            await cat_cmd("testpkg", "README.md", full=True, max_bytes=1000)

        renderer.render_error.assert_called_once_with("--full and --max-bytes cannot be used together")

    async def test_negative_max_bytes_rejected(self) -> None:
        """Negative `--max-bytes` renders an error and exits."""
        renderer = _make_renderer()

        with (
            patch("peeq.cli._get_renderer", return_value=renderer),
            pytest.raises(SystemExit, match="1"),
        ):
            await cat_cmd("testpkg", "README.md", max_bytes=-1)

        renderer.render_error.assert_called_once_with("--max-bytes must be non-negative")


# ---------------------------------------------------------------------------
# Tests: default truncation behavior
# ---------------------------------------------------------------------------


class TestDefaultTruncation:
    """Test content truncation at the default 128 KiB limit."""

    async def test_default_truncation(self) -> None:
        """Content exceeding 128 KiB is truncated."""
        content = b"x" * 200_000
        renderer = _make_renderer()
        service = _make_service(content)

        with (
            patch("peeq.cli._get_renderer", return_value=renderer),
            patch("peeq.cli._open_service", return_value=_AsyncCtx(service)),
            patch("peeq.cli._resolve_version", side_effect=_mock_resolve),
        ):
            await cat_cmd("testpkg", "big.txt")

        renderer.render_file_content.assert_called_once()
        call_kwargs = renderer.render_file_content.call_args.kwargs
        assert call_kwargs["truncated"] is True

    async def test_small_content_not_truncated(self) -> None:
        """Content smaller than the limit is not truncated."""
        content = b"hello world"
        renderer = _make_renderer()
        service = _make_service(content)

        with (
            patch("peeq.cli._get_renderer", return_value=renderer),
            patch("peeq.cli._open_service", return_value=_AsyncCtx(service)),
            patch("peeq.cli._resolve_version", side_effect=_mock_resolve),
        ):
            await cat_cmd("testpkg", "small.txt")

        renderer.render_file_content.assert_called_once()
        call_kwargs = renderer.render_file_content.call_args.kwargs
        assert call_kwargs["truncated"] is False


# ---------------------------------------------------------------------------
# Tests: _parse_byte_size converter
# ---------------------------------------------------------------------------


class TestByteSizeParsing:
    """Test the `_parse_byte_size` cyclopts converter."""

    def test_kib_suffix(self) -> None:
        """`128KiB` parses to 131072 bytes."""
        assert _parse_byte_size(int, ["128KiB"]) == 131_072

    def test_mb_suffix(self) -> None:
        """`1MB` parses to 1000000 bytes."""
        assert _parse_byte_size(int, ["1MB"]) == 1_000_000

    def test_plain_integer(self) -> None:
        """Plain integer string parses to that number of bytes."""
        assert _parse_byte_size(int, ["65536"]) == 65_536

    def test_cyclopts_token_object(self) -> None:
        """Accept cyclopts `Token` objects (real CLI invocation path)."""
        from cyclopts import Token  # noqa: PLC0415

        token = Token(value="128KiB")
        assert _parse_byte_size(int, [token]) == 131_072
