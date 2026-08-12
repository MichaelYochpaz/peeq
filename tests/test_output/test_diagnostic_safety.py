"""Cross-renderer safety contract for generic diagnostic output."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from tests.test_output._helpers import (
    _agent_renderer,
    _json_renderer,
    _plain_renderer,
    _rich_renderer,
)

if TYPE_CHECKING:
    from collections.abc import Callable
    from io import StringIO

    from peeq.output.base import Renderer


@pytest.mark.parametrize(
    "renderer_factory",
    [_plain_renderer, _agent_renderer, _json_renderer, _rich_renderer],
    ids=["plain", "agent", "json", "pretty"],
)
def test_generic_errors_are_safe_in_every_format(
    renderer_factory: Callable[[], tuple[Renderer, StringIO]],
) -> None:
    """No format may expose secrets or active terminal controls."""
    renderer, stream = renderer_factory()
    renderer.render_error(
        "Request failed at https://user:top-secret@registry.example/simple?token=query-secret "
        "Authorization: Bearer header-secret\x1b[2J\x1b]0;changed-title\x07"
    )

    output = stream.getvalue()
    assert "Request failed" in output
    assert "registry.example/simple" in output
    assert "[redacted]" in output
    for secret in ("user", "top-secret", "query-secret", "header-secret"):
        assert secret not in output
    assert "\x1b" not in output
    assert "\x07" not in output
