"""Unit tests for conflict rendering across all output formats.

Tests cover the `header` parameter integration and
`additional_requirements` display for each renderer.
"""

from __future__ import annotations

import pytest

from peeq.resolver.models import ConflictInfo, ConflictRequirement
from tests.test_output._helpers import (
    _agent_renderer,
    _json_parse,
    _json_renderer,
    _plain_renderer,
    _rich_renderer,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _conflict(
    *,
    additional: list[ConflictRequirement] | None = None,
) -> ConflictInfo:
    """Create a sample `ConflictInfo`."""
    return ConflictInfo(
        package="kubernetes",
        requirements=[
            ConflictRequirement(
                package="pkg-a",
                version="==0.4.2",
                dependency="kubernetes==35.0.0a1",
            ),
            ConflictRequirement(
                package="pkg-b",
                version="==2.16.0",
                dependency="kubernetes>=8.0.0,<31",
                chain=["pkg-c[remote]==0.5.1"],
            ),
        ],
        message="No version of kubernetes satisfies all constraints",
        additional_requirements=additional or [],
    )


def _additional_req() -> ConflictRequirement:
    """Create a sample additional `ConflictRequirement`."""
    return ConflictRequirement(
        package="pkg-c[remote]",
        version="==0.5.1",
        dependency="kubernetes>=30.0.0",
    )


# ---------------------------------------------------------------------------
# Part A: Header rendering
# ---------------------------------------------------------------------------


class TestResolveHeaderPlain:
    """Plain renderer header behaviour."""

    def test_resolve_header_present(self) -> None:
        """`resolve` failure includes 'Resolution failed' header."""
        renderer, stream = _plain_renderer()
        renderer.render_conflicts([_conflict()], header="Resolution failed")
        output = stream.getvalue()
        assert output.startswith("Resolution failed\n")

    def test_conflicts_no_header(self) -> None:
        """`conflicts` output omits header."""
        renderer, stream = _plain_renderer()
        renderer.render_conflicts([_conflict()])
        output = stream.getvalue()
        assert output.startswith("CONFLICT:")


class TestResolveHeaderJSON:
    """JSON renderer header behaviour."""

    def test_resolve_header_present(self) -> None:
        """`resolve` failure JSON includes header and correct command."""
        renderer, stream = _json_renderer()
        renderer.render_conflicts([_conflict()], header="Resolution failed")
        data = _json_parse(stream)
        assert data["header"] == "Resolution failed"
        assert data["command"] == "resolve"

    def test_conflicts_no_header(self) -> None:
        """`conflicts` JSON has command=conflicts and no header key."""
        renderer, stream = _json_renderer()
        renderer.render_conflicts([_conflict()])
        data = _json_parse(stream)
        assert data["command"] == "conflicts"
        assert "header" not in data


class TestResolveHeaderAgent:
    """Agent renderer header behaviour."""

    def test_resolve_header_as_attribute(self) -> None:
        """`resolve` failure has header as XML attribute on conflicts tag."""
        renderer, stream = _agent_renderer()
        renderer.render_conflicts([_conflict()], header="Resolution failed")
        output = stream.getvalue()
        assert 'header="Resolution failed"' in output
        # Must be on the <conflicts> tag
        for line in output.splitlines():
            if "<conflicts" in line:
                assert 'header="Resolution failed"' in line
                break
        else:
            pytest.fail("<conflicts> tag not found")

    def test_conflicts_no_header_attribute(self) -> None:
        """`conflicts` output has no header attribute."""
        renderer, stream = _agent_renderer()
        renderer.render_conflicts([_conflict()])
        output = stream.getvalue()
        assert "header=" not in output


class TestResolveHeaderRich:
    """Rich renderer header behaviour."""

    def test_resolve_header_present(self) -> None:
        """`resolve` failure prints header before conflicts."""
        renderer, stream = _rich_renderer()
        renderer.render_conflicts([_conflict()], header="Resolution failed")
        output = stream.getvalue()
        # Header appears before first CONFLICT
        header_pos = output.find("Resolution failed")
        conflict_pos = output.find("CONFLICT:")
        assert header_pos != -1
        assert conflict_pos != -1
        assert header_pos < conflict_pos

    def test_conflicts_no_header(self) -> None:
        """`conflicts` output doesn't have header text before CONFLICT."""
        renderer, stream = _rich_renderer()
        renderer.render_conflicts([_conflict()])
        output = stream.getvalue()
        assert "Resolution failed" not in output


# ---------------------------------------------------------------------------
# Part B: Additional requirements rendering
# ---------------------------------------------------------------------------


class TestAdditionalRequirementsPlain:
    """Plain renderer additional requirements."""

    def test_additional_requirements_shown(self) -> None:
        """Additional requirements section is rendered."""
        renderer, stream = _plain_renderer()
        renderer.render_conflicts([_conflict(additional=[_additional_req()])])
        output = stream.getvalue()
        assert "Also constrains kubernetes" in output
        assert "pkg-c[remote]==0.5.1: kubernetes>=30.0.0" in output

    def test_no_additional_requirements(self) -> None:
        """No additional section when list is empty."""
        renderer, stream = _plain_renderer()
        renderer.render_conflicts([_conflict()])
        output = stream.getvalue()
        assert "Also constrains" not in output


class TestAdditionalRequirementsJSON:
    """JSON renderer additional requirements."""

    def test_additional_constraints_present(self) -> None:
        """Additional constraints appear in JSON."""
        renderer, stream = _json_renderer()
        renderer.render_conflicts([_conflict(additional=[_additional_req()])])
        data = _json_parse(stream)
        conflict = data["conflicts"][0]
        assert "additional_constraints" in conflict
        assert len(conflict["additional_constraints"]) == 1
        assert conflict["additional_constraints"][0]["requires"] == "kubernetes>=30.0.0"
        assert conflict["additional_constraints"][0]["required_by"] == "pkg-c[remote]==0.5.1"

    def test_no_additional_constraints_key(self) -> None:
        """No additional_constraints key when empty."""
        renderer, stream = _json_renderer()
        renderer.render_conflicts([_conflict()])
        data = _json_parse(stream)
        conflict = data["conflicts"][0]
        assert "additional_constraints" not in conflict


class TestAdditionalRequirementsAgent:
    """Agent renderer additional requirements."""

    def test_additional_requirements_shown(self) -> None:
        """Additional requirements section inside conflict tag."""
        renderer, stream = _agent_renderer()
        renderer.render_conflicts([_conflict(additional=[_additional_req()])])
        output = stream.getvalue()
        assert "Also constrains kubernetes" in output
        assert "pkg-c[remote]==0.5.1: kubernetes>=30.0.0" in output

    def test_no_additional_requirements(self) -> None:
        """No additional section when list is empty."""
        renderer, stream = _agent_renderer()
        renderer.render_conflicts([_conflict()])
        output = stream.getvalue()
        assert "Also constrains" not in output


class TestAdditionalRequirementsRich:
    """Rich renderer additional requirements."""

    def test_additional_requirements_shown(self) -> None:
        """Additional requirements section is rendered."""
        renderer, stream = _rich_renderer()
        renderer.render_conflicts([_conflict(additional=[_additional_req()])])
        output = stream.getvalue()
        assert "Also constrains kubernetes" in output
        assert "pkg-c[remote]==0.5.1" in output
        assert "kubernetes>=30.0.0" in output

    def test_no_additional_requirements(self) -> None:
        """No additional section when list is empty."""
        renderer, stream = _rich_renderer()
        renderer.render_conflicts([_conflict()])
        output = stream.getvalue()
        assert "Also constrains" not in output
