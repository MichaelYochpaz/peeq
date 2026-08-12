"""Abstract base class for dependency resolvers.

Defines `DependencyResolver` with `__init_subclass__`
auto-registration (consistent with `PackageRepository`).
Concrete solvers set `solver_id` and implement `resolve`.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, ClassVar

from peeq import APP_NAME
from peeq.sanitize import sanitize_diagnostic

if TYPE_CHECKING:
    from peeq.resolver.models import (
        ConflictInfo,
        SolverResult,
        TargetEnvironment,
    )


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class ResolutionImpossible(Exception):  # noqa: N818
    """No set of package versions satisfies the given requirements.

    Carries structured `ConflictInfo` when available.

    Named with the `Impossible` suffix (not `Error`) following
    the established Python packaging convention.
    """

    def __init__(
        self,
        message: str,
        conflicts: list[ConflictInfo] | None = None,
    ) -> None:
        super().__init__(sanitize_diagnostic(message))
        self.conflicts: list[ConflictInfo] = conflicts or []


class ResolutionTooDeep(Exception):  # noqa: N818
    """The dependency graph is too deeply nested.

    Usually caused by a circular dependency or extreme backtracking.

    Named with the `TooDeep` suffix following the established
    Python packaging convention.
    """


class UvNotFoundError(RuntimeError):
    """The `uv` binary is not installed or not on `PATH`.

    Inherits from `RuntimeError` so existing broad `except
    RuntimeError` handlers in the CLI layer continue to work.
    """

    def __init__(self) -> None:
        super().__init__(
            "uv is required for dependency resolution but was not found.\n"
            "Install uv: https://docs.astral.sh/uv/getting-started/installation/\n"
            f"To bundle it as a dependency instead: pip install {APP_NAME}[uv]"
        )


# ---------------------------------------------------------------------------
# Abstract base class
# ---------------------------------------------------------------------------


class DependencyResolver(ABC):
    """Abstract base for dependency solvers.

    Subclasses auto-register via `__init_subclass__`.  Set `solver_id`
    as a `ClassVar[str]` on each concrete solver.

    Usage::

        solver = DependencyResolver.get_solver("uv", provider=provider)
        result = await solver.resolve(requirements, target_env)
    """

    _registry: ClassVar[dict[str, type[DependencyResolver]]] = {}
    solver_id: ClassVar[str]

    def __init_subclass__(cls, **kwargs: object) -> None:
        super().__init_subclass__(**kwargs)
        if hasattr(cls, "solver_id"):
            DependencyResolver._registry[cls.solver_id] = cls

    @abstractmethod
    async def resolve(
        self,
        requirements: list[str],
        target_env: TargetEnvironment,
    ) -> SolverResult:
        """Resolve requirements into concrete versions.

        Parameters
        ----------
        requirements:
            Registry-only PEP 508 requirement strings (e.g., `["flask>=2.0", "requests"]`).
        target_env:
            Target platform for marker evaluation.

        Returns
        -------
        SolverResult
            The resolved dependency graph.

        Raises
        ------
        ResolutionImpossible
            If no set of versions satisfies all constraints.
        ResolutionTooDeep
            If the resolver exceeded its backtracking budget.
        """
        ...

    @classmethod
    def available(cls) -> bool:
        """Whether this solver can be used in the current environment.

        Override in subclasses that depend on external tools (e.g.,
        `UvSolver` checks for the `uv` binary).
        """
        return True

    @classmethod
    def get_solver(
        cls,
        solver_id: str,
        **kwargs: object,
    ) -> DependencyResolver:
        """Look up a registered solver by ID and construct it.

        Raises
        ------
        ValueError
            If the solver ID is not registered.
        RuntimeError
            If the solver is registered but not available.
        """
        solver_cls = cls._registry.get(solver_id)
        if solver_cls is None:
            registered = ", ".join(sorted(cls._registry)) or "(none)"
            msg = f"Unknown solver {solver_id!r}. Registered solvers: {registered}"
            raise ValueError(msg)
        if not solver_cls.available():
            raise UvNotFoundError
        return solver_cls(**kwargs)

    @classmethod
    def registered_solvers(cls) -> dict[str, type[DependencyResolver]]:
        """Return a copy of the solver registry."""
        return dict(cls._registry)
