"""Tests for `PackageService.why_dependencies()` and `find_paths()`.

Tests use `AsyncMock` for the service's resolver and metadata
methods, and verify BFS path tracing, edge enrichment, and edge cases.
"""

from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import AsyncMock

from packaging.version import Version

from peeq.resolver.models import (
    ResolvedDependency,
    SolverResult,
)
from peeq.service import find_paths
from tests.test_service.conftest import _dep, _make_service, _metadata

if TYPE_CHECKING:
    from peeq.models import PackageMetadata

# ---------------------------------------------------------------------------
# Local helpers
# ---------------------------------------------------------------------------


def _solver_result(
    resolved: list[ResolvedDependency],
) -> SolverResult:
    """Create a `SolverResult` from resolved dependencies."""
    return SolverResult(resolved=resolved, solver_id="uv")


def _dep_node(
    name: str,
    version: str,
    deps: list[str] | None = None,
) -> ResolvedDependency:
    """Create a `ResolvedDependency` node."""
    return ResolvedDependency(
        name=name,
        version=Version(version),
        dependencies=deps or [],
    )


# ---------------------------------------------------------------------------
# find_paths tests
# ---------------------------------------------------------------------------


class TestFindPaths:
    """Test the `find_paths` BFS algorithm."""

    def test_single_path(self) -> None:
        """Find a single path from root to target."""
        result = _solver_result(
            [
                _dep_node("root-pkg", "1.0.0", ["middle-pkg"]),
                _dep_node("middle-pkg", "2.0.0", ["target-pkg"]),
                _dep_node("target-pkg", "3.0.0"),
            ]
        )
        paths = find_paths(result, "target-pkg", {"root-pkg"})
        assert len(paths) == 1
        assert paths[0] == ["root-pkg", "middle-pkg", "target-pkg"]

    def test_multiple_paths(self) -> None:
        """Find multiple paths when target is reachable via different chains."""
        result = _solver_result(
            [
                _dep_node("root-a", "1.0.0", ["target-pkg"]),
                _dep_node("root-b", "2.0.0", ["middle", "target-pkg"]),
                _dep_node("middle", "1.5.0", ["target-pkg"]),
                _dep_node("target-pkg", "3.0.0"),
            ]
        )
        paths = find_paths(result, "target-pkg", {"root-a", "root-b"})
        assert len(paths) == 3
        # All paths end at target-pkg and start at a root
        for path in paths:
            assert path[0] in {"root-a", "root-b"}
            assert path[-1] == "target-pkg"

    def test_target_not_in_graph(self) -> None:
        """Return empty when target is not in the dependency graph."""
        result = _solver_result(
            [
                _dep_node("root-pkg", "1.0.0", ["other-pkg"]),
                _dep_node("other-pkg", "2.0.0"),
            ]
        )
        paths = find_paths(result, "nonexistent", {"root-pkg"})
        assert paths == []

    def test_target_is_root(self) -> None:
        """Return single-element path when target is itself a root."""
        result = _solver_result(
            [
                _dep_node("root-pkg", "1.0.0"),
            ]
        )
        # BFS starts at target; since it is itself a root, returns
        # single-element path immediately.
        paths = find_paths(result, "root-pkg", {"root-pkg"})
        assert len(paths) == 1
        assert paths[0] == ["root-pkg"]

    def test_cycle_protection(self) -> None:
        """Cycles in the dependency graph do not cause infinite loops."""
        result = _solver_result(
            [
                _dep_node("root-pkg", "1.0.0", ["pkg-a"]),
                _dep_node("pkg-a", "1.0.0", ["pkg-b"]),
                _dep_node("pkg-b", "1.0.0", ["pkg-a", "target-pkg"]),
                _dep_node("target-pkg", "1.0.0"),
            ]
        )
        paths = find_paths(result, "target-pkg", {"root-pkg"})
        assert len(paths) == 1
        assert paths[0] == ["root-pkg", "pkg-a", "pkg-b", "target-pkg"]
        # No package appears twice in any path
        for path in paths:
            assert len(path) == len(set(path))

    def test_max_paths_limit(self) -> None:
        """Respect max_paths limit and cap results."""
        # Create a wide graph where many roots lead to target
        nodes = [_dep_node(f"root-{i}", "1.0.0", ["target-pkg"]) for i in range(30)]
        nodes.append(_dep_node("target-pkg", "1.0.0"))
        result = _solver_result(nodes)
        roots = {f"root-{i}" for i in range(30)}

        paths = find_paths(result, "target-pkg", roots, max_paths=5)
        assert len(paths) == 5

    def test_direct_dependency(self) -> None:
        """Single hop from root to target."""
        result = _solver_result(
            [
                _dep_node("root-pkg", "1.0.0", ["target-pkg"]),
                _dep_node("target-pkg", "2.0.0"),
            ]
        )
        paths = find_paths(result, "target-pkg", {"root-pkg"})
        assert len(paths) == 1
        assert paths[0] == ["root-pkg", "target-pkg"]


# ---------------------------------------------------------------------------
# why_dependencies tests
# ---------------------------------------------------------------------------


class TestWhyDependencies:
    """Test `PackageService.why_dependencies()`."""

    async def test_single_path_trace(self) -> None:
        """Trace a single path from root to target."""
        result = _solver_result(
            [
                _dep_node("root-pkg", "1.0.0", ["middle-pkg"]),
                _dep_node("middle-pkg", "2.0.0", ["target-pkg"]),
                _dep_node("target-pkg", "3.0.0"),
            ]
        )
        service = _make_service()
        service.resolve_dependencies = AsyncMock(return_value=result)  # type: ignore[method-assign]
        service.get_metadata = AsyncMock(  # type: ignore[method-assign]
            return_value=_metadata(deps=[_dep("target-pkg>=2.0")]),
        )

        why_result = await service.why_dependencies(
            "target-pkg",
            ["root-pkg==1.0.0"],
        )

        assert why_result.target == "target-pkg"
        assert why_result.target_version == "3.0.0"
        assert len(why_result.paths) == 1
        assert not why_result.is_direct
        assert not why_result.truncated

        hops = why_result.paths[0].hops
        assert len(hops) == 3
        assert hops[0].package == "root-pkg"
        assert hops[1].package == "middle-pkg"
        assert hops[2].package == "target-pkg"

    async def test_multiple_paths(self) -> None:
        """Trace multiple paths to the target."""
        result = _solver_result(
            [
                _dep_node("root-a", "1.0.0", ["target-pkg"]),
                _dep_node("root-b", "2.0.0", ["target-pkg"]),
                _dep_node("target-pkg", "3.0.0"),
            ]
        )
        service = _make_service()
        service.resolve_dependencies = AsyncMock(return_value=result)  # type: ignore[method-assign]
        service.get_metadata = AsyncMock(  # type: ignore[method-assign]
            return_value=_metadata(deps=[_dep("target-pkg>=1.0")]),
        )

        why_result = await service.why_dependencies(
            "target-pkg",
            ["root-a==1.0.0", "root-b==2.0.0"],
        )

        assert len(why_result.paths) == 2

    async def test_target_not_in_tree(self) -> None:
        """Return empty paths when target is not in the resolved tree."""
        result = _solver_result(
            [
                _dep_node("root-pkg", "1.0.0", ["other-pkg"]),
                _dep_node("other-pkg", "2.0.0"),
            ]
        )
        service = _make_service()
        service.resolve_dependencies = AsyncMock(return_value=result)  # type: ignore[method-assign]

        why_result = await service.why_dependencies(
            "nonexistent",
            ["root-pkg==1.0.0"],
        )

        assert why_result.target_version == ""
        assert why_result.paths == []
        assert not why_result.is_direct

    async def test_target_is_root(self) -> None:
        """Return is_direct=True when target is a root requirement."""
        result = _solver_result(
            [
                _dep_node("target-pkg", "1.0.0", ["other-pkg"]),
                _dep_node("other-pkg", "2.0.0"),
            ]
        )
        service = _make_service()
        service.resolve_dependencies = AsyncMock(return_value=result)  # type: ignore[method-assign]

        why_result = await service.why_dependencies(
            "target-pkg",
            ["target-pkg==1.0.0"],
        )

        assert why_result.is_direct
        assert why_result.target_version == "1.0.0"
        assert why_result.paths == []

    async def test_truncated_when_max_paths_hit(self) -> None:
        """Set truncated flag when max_paths limit is reached."""
        # Create 25 roots all depending on target
        nodes = [_dep_node(f"root-{i}", "1.0.0", ["target-pkg"]) for i in range(25)]
        nodes.append(_dep_node("target-pkg", "1.0.0"))
        result = _solver_result(nodes)

        service = _make_service()
        service.resolve_dependencies = AsyncMock(return_value=result)  # type: ignore[method-assign]
        service.get_metadata = AsyncMock(  # type: ignore[method-assign]
            return_value=_metadata(deps=[_dep("target-pkg>=1.0")]),
        )

        reqs = [f"root-{i}==1.0.0" for i in range(25)]
        why_result = await service.why_dependencies("target-pkg", reqs)

        # max_paths defaults to 20
        assert len(why_result.paths) == 20
        assert why_result.truncated

    async def test_default_enriches_all_hops(self) -> None:
        """Default mode fetches metadata for all intermediate packages."""
        result = _solver_result(
            [
                _dep_node("root-pkg", "1.0.0", ["middle-pkg"]),
                _dep_node("middle-pkg", "2.0.0", ["target-pkg"]),
                _dep_node("target-pkg", "3.0.0"),
            ]
        )

        async def _meta_side_effect(
            name: str,
            version: str,
        ) -> PackageMetadata | None:
            if name == "root-pkg":
                return _metadata(deps=[_dep("middle-pkg>=1.5")])
            if name == "middle-pkg":
                return _metadata(deps=[_dep("target-pkg>=2.0,<4")])
            return None

        service = _make_service()
        service.resolve_dependencies = AsyncMock(return_value=result)  # type: ignore[method-assign]
        service.get_metadata = AsyncMock(  # type: ignore[method-assign]
            side_effect=_meta_side_effect,
        )

        why_result = await service.why_dependencies(
            "target-pkg",
            ["root-pkg==1.0.0"],
        )

        hops = why_result.paths[0].hops
        # Root should have requirement for middle-pkg
        assert hops[0].requirement == ">=1.5"
        # Middle should have requirement for target-pkg
        assert hops[1].requirement is not None
        assert ">=2.0" in hops[1].requirement
        assert "<4" in hops[1].requirement
        # Target has no requirement (no next hop)
        assert hops[2].requirement is None

    async def test_final_hop_only_mode(self) -> None:
        """all_hops=False fetches metadata only for direct parents of target."""
        result = _solver_result(
            [
                _dep_node("root-pkg", "1.0.0", ["middle-pkg"]),
                _dep_node("middle-pkg", "2.0.0", ["target-pkg"]),
                _dep_node("target-pkg", "3.0.0"),
            ]
        )

        service = _make_service()
        service.resolve_dependencies = AsyncMock(return_value=result)  # type: ignore[method-assign]
        service.get_metadata = AsyncMock(  # type: ignore[method-assign]
            return_value=_metadata(deps=[_dep("target-pkg>=2.0,<4")]),
        )

        why_result = await service.why_dependencies(
            "target-pkg",
            ["root-pkg==1.0.0"],
            all_hops=False,
        )

        hops = why_result.paths[0].hops
        # Root should NOT have a requirement (final-hop-only mode)
        assert hops[0].requirement is None
        # Middle (parent of target) should have the specifier
        assert hops[1].requirement is not None
        assert ">=2.0" in hops[1].requirement
        assert "<4" in hops[1].requirement
        # Target has no requirement (no next hop)
        assert hops[2].requirement is None

        # Only middle-pkg metadata was fetched (not root-pkg)
        service.get_metadata.assert_called_once_with("middle-pkg", "2.0.0")  # type: ignore[union-attr]

    async def test_metadata_fetch_failure_graceful(self) -> None:
        """Metadata fetch failure does not crash — requirement stays None."""
        result = _solver_result(
            [
                _dep_node("root-pkg", "1.0.0", ["target-pkg"]),
                _dep_node("target-pkg", "2.0.0"),
            ]
        )
        service = _make_service()
        service.resolve_dependencies = AsyncMock(return_value=result)  # type: ignore[method-assign]
        service.get_metadata = AsyncMock(  # type: ignore[method-assign]
            side_effect=RuntimeError("network error"),
        )

        why_result = await service.why_dependencies(
            "target-pkg",
            ["root-pkg==1.0.0"],
        )

        assert len(why_result.paths) == 1
        # Requirement is None because metadata fetch failed
        assert why_result.paths[0].hops[0].requirement is None

    async def test_passes_pre_flag(self) -> None:
        """The pre flag is passed through to resolve_dependencies."""
        result = _solver_result(
            [
                _dep_node("root-pkg", "1.0.0", ["target-pkg"]),
                _dep_node("target-pkg", "2.0.0a1"),
            ]
        )
        service = _make_service()
        service.resolve_dependencies = AsyncMock(return_value=result)  # type: ignore[method-assign]
        service.get_metadata = AsyncMock(return_value=None)  # type: ignore[method-assign]

        await service.why_dependencies(
            "target-pkg",
            ["root-pkg==1.0.0"],
            pre=True,
        )

        call_kwargs = service.resolve_dependencies.call_args  # type: ignore[union-attr]
        assert call_kwargs[1]["include_prereleases"] is True
