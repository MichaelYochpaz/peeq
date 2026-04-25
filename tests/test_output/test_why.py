"""Unit tests for `render_why` and `render_why_failed` across all formats.

Tests cover single-path, multi-path, direct requirement, and
failure rendering in plain, rich, json, and agent renderers.
"""

from __future__ import annotations

from peeq.resolver.models import (
    ConflictInfo,
    ConflictRequirement,
    PathHop,
    WhyPath,
    WhyResult,
)
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


def _single_path_result() -> WhyResult:
    """Create a `WhyResult` with a single 3-hop path."""
    return WhyResult(
        target="target-pkg",
        target_version="3.0.0",
        paths=[
            WhyPath(
                hops=[
                    PathHop(package="root-pkg", version="1.0.0"),
                    PathHop(
                        package="middle-pkg", version="2.0.0", requirement=">=2.0,<4"
                    ),
                    PathHop(package="target-pkg", version="3.0.0"),
                ]
            ),
        ],
    )


def _multi_path_result() -> WhyResult:
    """Create a `WhyResult` with two paths."""
    return WhyResult(
        target="target-pkg",
        target_version="3.0.0",
        paths=[
            WhyPath(
                hops=[
                    PathHop(package="root-a", version="1.0.0", requirement=">=2.0"),
                    PathHop(package="target-pkg", version="3.0.0"),
                ]
            ),
            WhyPath(
                hops=[
                    PathHop(package="root-b", version="2.0.0"),
                    PathHop(
                        package="middle-pkg",
                        version="1.5.0",
                        requirement=">=1.0",
                    ),
                    PathHop(package="target-pkg", version="3.0.0"),
                ]
            ),
        ],
    )


def _direct_result() -> WhyResult:
    """Create a `WhyResult` for a direct requirement."""
    return WhyResult(
        target="target-pkg",
        target_version="1.0.0",
        is_direct=True,
        paths=[],
    )


def _truncated_result() -> WhyResult:
    """Create a `WhyResult` with truncated flag set."""
    return WhyResult(
        target="target-pkg",
        target_version="1.0.0",
        truncated=True,
        paths=[
            WhyPath(
                hops=[
                    PathHop(package="root-pkg", version="1.0.0", requirement=">=0.5"),
                    PathHop(package="target-pkg", version="1.0.0"),
                ]
            ),
        ],
    )


def _conflict() -> ConflictInfo:
    """Create a sample `ConflictInfo` for failure tests."""
    return ConflictInfo(
        package="target-pkg",
        requirements=[
            ConflictRequirement(
                package="pkg-a",
                version="==0.4.2",
                dependency="target-pkg==35.0.0a1",
            ),
            ConflictRequirement(
                package="pkg-b",
                version="==2.16.0",
                dependency="target-pkg>=8.0.0,<31",
                chain=["root-pkg==0.5.1"],
            ),
        ],
    )


# ---------------------------------------------------------------------------
# Plain renderer tests
# ---------------------------------------------------------------------------


class TestRenderWhyPlain:
    """Plain renderer `render_why` tests."""

    def test_single_path(self) -> None:
        """Single-path output contains hop names, versions, and specifiers."""
        renderer, stream = _plain_renderer()
        renderer.render_why(_single_path_result())
        output = stream.getvalue()

        assert "target-pkg==3.0.0 is required for root-pkg:" in output
        assert "root-pkg 1.0.0" in output
        assert "middle-pkg 2.0.0" in output
        assert "target-pkg 3.0.0 (>=2.0,<4)" in output
        assert "1 path found" in output
        # Uses tree guides, not arrows
        assert "└──" in output
        assert "->" not in output

    def test_multiple_paths(self) -> None:
        """Multi-path output numbers paths."""
        renderer, stream = _plain_renderer()
        renderer.render_why(_multi_path_result())
        output = stream.getvalue()

        assert "Path 1:" in output
        assert "Path 2:" in output
        assert "2 paths found" in output

    def test_direct_requirement(self) -> None:
        """Direct requirement shows informational message with == notation."""
        renderer, stream = _plain_renderer()
        renderer.render_why(_direct_result())
        output = stream.getvalue()

        assert "target-pkg==1.0.0" in output
        assert "direct requirement" in output
        assert "not pulled in transitively" in output

    def test_truncated_notice(self) -> None:
        """Truncated result shows notice."""
        renderer, stream = _plain_renderer()
        renderer.render_why(_truncated_result())
        output = stream.getvalue()

        assert "results truncated" in output


class TestRenderWhyFailedPlain:
    """Plain renderer `render_why_failed` tests."""

    def test_failure_output(self) -> None:
        """Failure output contains header, conflicts, and guidance."""
        renderer, stream = _plain_renderer()
        renderer.render_why_failed("target-pkg", [_conflict()])
        output = stream.getvalue()

        assert "Resolution failed" in output
        assert "CONFLICT: target-pkg" in output
        assert "pkg-a==0.4.2 requires: target-pkg==35.0.0a1" in output
        assert "Path tracing is not available" in output
        assert "peeq conflicts" in output


# ---------------------------------------------------------------------------
# Rich renderer tests
# ---------------------------------------------------------------------------


class TestRenderWhyRich:
    """Rich renderer `render_why` tests."""

    def test_single_path(self) -> None:
        """Single-path output uses Tree with all hops and specifier."""
        renderer, stream = _rich_renderer()
        renderer.render_why(_single_path_result())
        output = stream.getvalue()

        assert "target-pkg==3.0.0" in output
        assert "root-pkg" in output
        assert "middle-pkg" in output
        assert "1 path found" in output
        # Tree guide characters replace manual -> arrows
        assert "->" not in output
        # Old "= target-pkg" resolution line is gone
        assert "= target-pkg" not in output

    def test_single_path_shows_version_and_specifier(self) -> None:
        """Intermediate hops show resolved version; specifier in parens."""
        renderer, stream = _rich_renderer()
        renderer.render_why(_single_path_result())
        output = stream.getvalue()

        # middle-pkg shows its resolved version (not just specifier)
        assert "middle-pkg 2.0.0" in output
        # target-pkg shows both version and incoming specifier
        assert "target-pkg 3.0.0" in output
        assert "(>=2.0,<4)" in output

    def test_header_includes_source(self) -> None:
        """Header mentions the source package being resolved."""
        renderer, stream = _rich_renderer()
        renderer.render_why(_single_path_result())
        output = stream.getvalue()

        assert "is required for root-pkg:" in output

    def test_single_path_no_duplicate_target(self) -> None:
        """Target appears once per path, not duplicated."""
        renderer, stream = _rich_renderer()
        renderer.render_why(_single_path_result())
        output = stream.getvalue()

        # The path body (between header and footer) should have target once
        body = output.split("\n\n", 1)[-1].split("path found")[0]
        assert body.count("target-pkg") == 1

    def test_multiple_paths(self) -> None:
        """Multi-path output numbers paths."""
        renderer, stream = _rich_renderer()
        renderer.render_why(_multi_path_result())
        output = stream.getvalue()

        assert "Path 1:" in output
        assert "Path 2:" in output
        assert "2 paths found" in output

    def test_direct_requirement(self) -> None:
        """Direct requirement shows informational message with == notation."""
        renderer, stream = _rich_renderer()
        renderer.render_why(_direct_result())
        output = stream.getvalue()

        assert "target-pkg==1.0.0" in output
        assert "direct requirement" in output

    def test_truncated_notice(self) -> None:
        """Truncated result shows notice."""
        renderer, stream = _rich_renderer()
        renderer.render_why(_truncated_result())
        output = stream.getvalue()

        assert "results truncated" in output

    def test_root_has_no_specifier(self) -> None:
        """Root node in the tree shows version without specifier parens."""
        renderer, stream = _rich_renderer()
        renderer.render_why(_single_path_result())
        output = stream.getvalue()

        # Find root-pkg in the tree body (skip the header line)
        body = output.split("\n\n", 1)[-1]
        for line in body.splitlines():
            if "root-pkg" in line:
                assert "1.0.0" in line
                assert "(" not in line
                break


class TestRenderWhyFailedRich:
    """Rich renderer `render_why_failed` tests."""

    def test_failure_output(self) -> None:
        """Failure output contains header and conflict details."""
        renderer, stream = _rich_renderer()
        renderer.render_why_failed("target-pkg", [_conflict()])
        output = stream.getvalue()

        assert "Resolution failed" in output
        assert "CONFLICT:" in output
        assert "Path tracing is not available" in output


# ---------------------------------------------------------------------------
# JSON renderer tests
# ---------------------------------------------------------------------------


class TestRenderWhyJSON:
    """JSON renderer `render_why` tests."""

    def test_single_path_structure(self) -> None:
        """JSON output has correct structure for single path."""
        renderer, stream = _json_renderer()
        renderer.render_why(_single_path_result())
        data = _json_parse(stream)

        assert data["command"] == "why"
        assert data["target"] == "target-pkg"
        assert data["target_version"] == "3.0.0"
        assert data["is_direct"] is False
        assert data["truncated"] is False
        assert len(data["paths"]) == 1

        hops = data["paths"][0]["hops"]
        assert len(hops) == 3
        assert hops[0]["package"] == "root-pkg"
        assert hops[1]["requirement"] == ">=2.0,<4"
        assert hops[2]["requirement"] is None

    def test_multiple_paths(self) -> None:
        """JSON output has multiple paths."""
        renderer, stream = _json_renderer()
        renderer.render_why(_multi_path_result())
        data = _json_parse(stream)

        assert len(data["paths"]) == 2

    def test_direct_requirement(self) -> None:
        """JSON output has is_direct=True for direct requirements."""
        renderer, stream = _json_renderer()
        renderer.render_why(_direct_result())
        data = _json_parse(stream)

        assert data["is_direct"] is True
        assert data["paths"] == []


class TestRenderWhyFailedJSON:
    """JSON renderer `render_why_failed` tests."""

    def test_failure_structure(self) -> None:
        """JSON failure output has correct structure."""
        renderer, stream = _json_renderer()
        renderer.render_why_failed("target-pkg", [_conflict()])
        data = _json_parse(stream)

        assert data["command"] == "why"
        assert data["target"] == "target-pkg"
        assert data["error"] == "Resolution failed"
        assert len(data["conflicts"]) == 1
        assert data["message"].startswith("Path tracing is not available")


# ---------------------------------------------------------------------------
# Agent renderer tests
# ---------------------------------------------------------------------------


class TestRenderWhyAgent:
    """Agent renderer `render_why` tests."""

    def test_single_path(self) -> None:
        """Agent output uses structured <path>/<hop> elements."""
        renderer, stream = _agent_renderer()
        renderer.render_why(_single_path_result())
        output = stream.getvalue()

        assert '<why target="target-pkg"' in output
        assert 'version="3.0.0"' in output
        assert 'paths="1"' in output
        assert "</why>" in output
        assert "<path>" in output
        assert "</path>" in output
        assert '<hop package="root-pkg" version="1.0.0" />' in output
        assert '<hop package="middle-pkg" version="2.0.0"' in output
        assert 'requires=">=2.0,<4"' in output
        assert '<hop package="target-pkg" version="3.0.0" />' in output

    def test_multiple_paths(self) -> None:
        """Agent output has multiple <path> elements."""
        renderer, stream = _agent_renderer()
        renderer.render_why(_multi_path_result())
        output = stream.getvalue()

        assert 'paths="2"' in output
        assert output.count("<path>") == 2
        assert output.count("</path>") == 2

    def test_direct_requirement(self) -> None:
        """Direct requirement renders as self-closing <why> tag."""
        renderer, stream = _agent_renderer()
        renderer.render_why(_direct_result())
        output = stream.getvalue()

        assert 'direct="true"' in output
        assert 'paths="0"' in output
        assert "/>" in output
        assert "</why>" not in output

    def test_truncated(self) -> None:
        """Truncated result has truncated attribute on <why>."""
        renderer, stream = _agent_renderer()
        renderer.render_why(_truncated_result())
        output = stream.getvalue()

        assert 'truncated="true"' in output
        assert 'paths="1"' in output

    def test_requires_on_parent_hop(self) -> None:
        """The requires attribute is on the parent hop, not the child."""
        renderer, stream = _agent_renderer()
        renderer.render_why(_single_path_result())
        output = stream.getvalue()

        # middle-pkg has requirement=">=2.0,<4" in the model (outgoing),
        # so requires= appears on middle-pkg, NOT on target-pkg.
        assert 'package="middle-pkg" version="2.0.0" requires=">=2.0,<4"' in output
        assert '<hop package="target-pkg" version="3.0.0" />' in output

    def test_specifier_preserved(self) -> None:
        """Version specifiers with < and > are preserved in attributes."""
        renderer, stream = _agent_renderer()
        result = WhyResult(
            target="h2",
            target_version="4.3.0",
            paths=[
                WhyPath(
                    hops=[
                        PathHop(
                            package="httpx",
                            version="0.28.1",
                            requirement="<5,>=3",
                        ),
                        PathHop(package="h2", version="4.3.0"),
                    ]
                ),
            ],
        )
        renderer.render_why(result)
        output = stream.getvalue()

        # < and > are preserved in attribute values, not entity-encoded
        assert 'requires="<5,>=3"' in output
        assert "&lt;" not in output
        assert "&gt;" not in output


class TestRenderWhyFailedAgent:
    """Agent renderer `render_why_failed` tests."""

    def test_failure_output(self) -> None:
        """Agent failure output has error attribute and conflict details."""
        renderer, stream = _agent_renderer()
        renderer.render_why_failed("target-pkg", [_conflict()])
        output = stream.getvalue()

        assert 'error="Resolution failed"' in output
        assert "CONFLICT: target-pkg" in output
        assert "Path tracing is not available" in output
        assert "</why>" in output
