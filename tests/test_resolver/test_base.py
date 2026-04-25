"""Tests for the DependencyResolver ABC and exceptions."""

from __future__ import annotations

import pytest

from peeq.resolver.base import (
    DependencyResolver,
    ResolutionImpossible,
    ResolutionTooDeep,
    UvNotFoundError,
)
from peeq.resolver.models import ConflictInfo, SolverResult, TargetEnvironment

# ---------------------------------------------------------------------------
# Auto-registration
# ---------------------------------------------------------------------------


class TestAutoRegistration:
    """Tests for __init_subclass__ auto-registration."""

    def test_uv_registered(self) -> None:
        solvers = DependencyResolver.registered_solvers()
        assert "uv" in solvers

    def test_custom_solver_registration(self) -> None:
        """A new subclass with solver_id is auto-registered."""

        class _TestSolver(DependencyResolver):
            solver_id = "_test_dummy"

            async def resolve(
                self,
                requirements: list[str],
                target_env: TargetEnvironment,
            ) -> SolverResult:
                return SolverResult(resolved=[], solver_id=self.solver_id)

        try:
            assert "_test_dummy" in DependencyResolver.registered_solvers()
            assert DependencyResolver.registered_solvers()["_test_dummy"] is _TestSolver
        finally:
            # Clean up to avoid polluting other tests.
            DependencyResolver._registry.pop("_test_dummy", None)

    def test_abstract_base_not_registered(self) -> None:
        """The ABC itself should not be in the registry."""
        assert "DependencyResolver" not in DependencyResolver.registered_solvers()


# ---------------------------------------------------------------------------
# get_solver
# ---------------------------------------------------------------------------


class TestGetSolver:
    """Tests for DependencyResolver.get_solver()."""

    def test_unknown_solver_raises_value_error(self) -> None:
        with pytest.raises(ValueError, match="Unknown solver"):
            DependencyResolver.get_solver("nonexistent_solver")

    def test_unavailable_solver_raises_runtime_error(self) -> None:
        """A solver that is registered but not available raises RuntimeError."""

        class _UnavailableSolver(DependencyResolver):
            solver_id = "_unavailable"

            @classmethod
            def available(cls) -> bool:
                return False

            async def resolve(
                self,
                requirements: list[str],
                target_env: TargetEnvironment,
            ) -> SolverResult:
                return SolverResult(resolved=[], solver_id=self.solver_id)

        try:
            with pytest.raises(UvNotFoundError, match="uv is required"):
                DependencyResolver.get_solver("_unavailable")
        finally:
            DependencyResolver._registry.pop("_unavailable", None)

    def test_available_default_is_true(self) -> None:
        """The default available() returns True."""

        class _DefaultAvailable(DependencyResolver):
            solver_id = "_default_avail"

            async def resolve(
                self,
                requirements: list[str],
                target_env: TargetEnvironment,
            ) -> SolverResult:
                return SolverResult(resolved=[], solver_id=self.solver_id)

        try:
            assert _DefaultAvailable.available() is True
        finally:
            DependencyResolver._registry.pop("_default_avail", None)


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class TestResolutionImpossible:
    """Tests for the ResolutionImpossible exception."""

    def test_message(self) -> None:
        exc = ResolutionImpossible("Cannot resolve numpy")
        assert str(exc) == "Cannot resolve numpy"
        assert exc.conflicts == []

    def test_with_conflicts(self) -> None:
        conflicts = [
            ConflictInfo(package="numpy", message="version conflict"),
        ]
        exc = ResolutionImpossible("Cannot resolve", conflicts=conflicts)
        assert len(exc.conflicts) == 1
        assert exc.conflicts[0].package == "numpy"


class TestResolutionTooDeep:
    """Tests for the ResolutionTooDeep exception."""

    def test_message(self) -> None:
        exc = ResolutionTooDeep("Too many rounds")
        assert str(exc) == "Too many rounds"
