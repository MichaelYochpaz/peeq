"""Tests for `PackageService.enrich_conflicts()` and `_extract_exact_version`.

Tests use `AsyncMock` for the service's `get_metadata` method
and verify that supplementary lookups correctly populate
`additional_requirements` on `ConflictInfo` objects.
"""

from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import AsyncMock

import pytest

from peeq.resolver.models import ConflictInfo, ConflictRequirement
from peeq.service import _extract_exact_version
from tests.test_service.conftest import _dep, _make_service, _metadata

if TYPE_CHECKING:
    from peeq.models import PackageMetadata

# ---------------------------------------------------------------------------
# Local helpers
# ---------------------------------------------------------------------------


def _conflict(
    *,
    package: str = "kubernetes",
    requirements: list[ConflictRequirement] | None = None,
    message: str = "",
) -> ConflictInfo:
    """Create a `ConflictInfo` with sensible defaults."""
    if requirements is None:
        requirements = [
            ConflictRequirement(
                package="pkg-a",
                version="==1.0.0",
                dependency="kubernetes==35.0.0a1",
            ),
            ConflictRequirement(
                package="pkg-b",
                version="==2.0.0",
                dependency="kubernetes>=8.0.0,<31",
                chain=["pkg-c[extra]==0.5.1"],
            ),
        ]
    return ConflictInfo(
        package=package,
        requirements=requirements,
        message=message,
    )


# ---------------------------------------------------------------------------
# _extract_exact_version tests
# ---------------------------------------------------------------------------


class TestExtractExactVersion:
    """Test the `_extract_exact_version` helper."""

    @pytest.mark.parametrize(
        ("spec", "expected"),
        [
            ("1.2.3", "1.2.3"),
            ("==1.2.3", "1.2.3"),
            ("===1.2.3", "1.2.3"),
            ("==1.2.*", None),
            (">=1.2.3", None),
            ("<2.0", None),
            ("~=1.2", None),
            ("", None),
        ],
    )
    def test_extract_exact_version(self, spec: str, expected: str | None) -> None:
        assert _extract_exact_version(spec) == expected


# ---------------------------------------------------------------------------
# enrich_conflicts tests
# ---------------------------------------------------------------------------


class TestEnrichConflicts:
    """Test `PackageService.enrich_conflicts()`."""

    async def test_additional_requirements_found(self) -> None:
        """Supplementary lookup finds non-conflicting constraint."""

        # Only the chain entry (pkg-c) has an additional constraint.
        # Parents (pkg-a, pkg-b) return metadata with no kubernetes dep.
        async def _side_effect(name: str, version: str) -> PackageMetadata | None:
            if name == "pkg-c":
                return _metadata(deps=[_dep("kubernetes>=30.0.0")])
            return _metadata(deps=[_dep("requests>=2.0")])

        service = _make_service()
        service.get_metadata = AsyncMock(  # type: ignore[method-assign]
            side_effect=_side_effect,
        )

        conflicts = [_conflict()]
        enriched = await service.enrich_conflicts(conflicts)

        assert len(enriched) == 1
        assert len(enriched[0].additional_requirements) == 1
        req = enriched[0].additional_requirements[0]
        assert req.package == "pkg-c[extra]"
        assert req.version == "==0.5.1"
        assert req.dependency == "kubernetes>=30.0.0"

    async def test_no_additional_requirements(self) -> None:
        """No supplementary constraints found returns unchanged."""
        service = _make_service()
        # Metadata has no deps on the conflicting package
        service.get_metadata = AsyncMock(  # type: ignore[method-assign]
            return_value=_metadata(deps=[_dep("requests>=2.0")]),
        )

        conflicts = [_conflict()]
        enriched = await service.enrich_conflicts(conflicts)

        assert len(enriched) == 1
        assert enriched[0].additional_requirements == []

    async def test_get_metadata_returns_none(self) -> None:
        """`get_metadata` returning None is handled gracefully."""
        service = _make_service()
        service.get_metadata = AsyncMock(  # type: ignore[method-assign]
            return_value=None,
        )

        conflicts = [_conflict()]
        enriched = await service.enrich_conflicts(conflicts)

        assert len(enriched) == 1
        assert enriched[0].additional_requirements == []

    async def test_get_metadata_raises_exception(self) -> None:
        """`get_metadata` raising an exception is silently skipped."""
        service = _make_service()
        service.get_metadata = AsyncMock(  # type: ignore[method-assign]
            side_effect=RuntimeError("network error"),
        )

        conflicts = [_conflict()]
        enriched = await service.enrich_conflicts(conflicts)

        assert len(enriched) == 1
        assert enriched[0].additional_requirements == []

    async def test_non_exact_chain_entries_skipped(self) -> None:
        """Chain entries with range specifiers are skipped."""
        conflict = ConflictInfo(
            package="numpy",
            requirements=[
                ConflictRequirement(
                    package="pkg-a",
                    version="==1.0.0",
                    dependency="numpy>=1.23",
                    chain=["pkg-b>=2.0"],  # Range, not exact
                ),
            ],
        )
        service = _make_service()
        service.get_metadata = AsyncMock(  # type: ignore[method-assign]
            return_value=_metadata(deps=[_dep("numpy>=1.20")]),
        )

        enriched = await service.enrich_conflicts([conflict])

        assert len(enriched) == 1
        # pkg-a has exact version so it's fetched; pkg-b is range and skipped
        assert service.get_metadata.call_count == 1  # type: ignore[union-attr]
        call_args = service.get_metadata.call_args  # type: ignore[union-attr]
        assert call_args[0] == ("pkg-a", "1.0.0")

    async def test_extras_stripped_for_metadata_lookup(self) -> None:
        """Extras in chain entries are stripped for the metadata fetch."""
        conflict = ConflictInfo(
            package="kubernetes",
            requirements=[
                ConflictRequirement(
                    package="kfp",
                    version="==2.16.0",
                    dependency="kubernetes>=8.0.0,<31",
                    chain=["ragas[remote]==0.5.1"],
                ),
            ],
        )
        service = _make_service()
        service.get_metadata = AsyncMock(  # type: ignore[method-assign]
            return_value=_metadata(deps=[_dep("kubernetes>=30.0.0")]),
        )

        await service.enrich_conflicts([conflict])

        # get_metadata called with bare name (no extras) for both kfp and ragas
        calls = service.get_metadata.call_args_list  # type: ignore[union-attr]
        call_names = {c[0][0] for c in calls}
        assert "ragas" in call_names
        # Extras are not part of the name in metadata calls
        assert all("[" not in c[0][0] for c in calls)

    async def test_existing_requirements_not_duplicated(self) -> None:
        """Requirements already in the conflict proof are not re-added."""
        conflict = ConflictInfo(
            package="kubernetes",
            requirements=[
                ConflictRequirement(
                    package="kfp",
                    version="==2.16.0",
                    dependency="kubernetes>=8.0.0,<31",
                ),
            ],
        )
        service = _make_service()
        # Return the SAME constraint that's already in requirements
        service.get_metadata = AsyncMock(  # type: ignore[method-assign]
            return_value=_metadata(deps=[_dep("kubernetes>=8.0.0,<31")]),
        )

        enriched = await service.enrich_conflicts([conflict])

        assert len(enriched) == 1
        assert enriched[0].additional_requirements == []

    async def test_empty_conflicts_list(self) -> None:
        """Empty conflicts list returns empty."""
        service = _make_service()
        enriched = await service.enrich_conflicts([])
        assert enriched == []

    async def test_no_chains_no_exact_parents(self) -> None:
        """Conflict with range-only parents and no chains has nothing to fetch."""
        conflict = ConflictInfo(
            package="numpy",
            requirements=[
                ConflictRequirement(
                    package="pandas",
                    version=">=1.0",
                    dependency="numpy>=1.20",
                ),
            ],
        )
        service = _make_service()
        service.get_metadata = AsyncMock(  # type: ignore[method-assign]
            return_value=_metadata(deps=[]),
        )

        enriched = await service.enrich_conflicts([conflict])

        assert len(enriched) == 1
        assert enriched[0].additional_requirements == []
        # No exact version to fetch for parent
        service.get_metadata.assert_not_called()  # type: ignore[union-attr]

    async def test_metadata_with_none_dependencies(self) -> None:
        """Metadata with `dependencies=None` is handled gracefully."""
        service = _make_service()
        service.get_metadata = AsyncMock(  # type: ignore[method-assign]
            return_value=_metadata(deps=None),
        )

        conflicts = [_conflict()]
        enriched = await service.enrich_conflicts(conflicts)

        assert len(enriched) == 1
        assert enriched[0].additional_requirements == []

    async def test_frozen_model_not_mutated(self) -> None:
        """Original ConflictInfo is not mutated (model_copy used)."""

        async def _side_effect(name: str, version: str) -> PackageMetadata | None:
            if name == "pkg-c":
                return _metadata(deps=[_dep("kubernetes>=30.0.0")])
            return _metadata(deps=[_dep("requests>=2.0")])

        service = _make_service()
        service.get_metadata = AsyncMock(  # type: ignore[method-assign]
            side_effect=_side_effect,
        )

        original = _conflict()
        enriched = await service.enrich_conflicts([original])

        # Original unchanged
        assert original.additional_requirements == []
        # Enriched has new data
        assert len(enriched[0].additional_requirements) == 1
