"""Data models for dependency resolution.

Contains `TargetEnvironment` (the platform to resolve for),
`SolverResult` (the successful resolution output), and
`ConflictInfo` (structured conflict details when resolution fails).
"""

from __future__ import annotations

import os
import platform
import sys

from pydantic import BaseModel, Field, field_validator

from peeq.models import PkgVersion
from peeq.sanitize import (
    DIAGNOSTIC_HINT_MAX_LENGTH,
    DIAGNOSTIC_MAX_HINTS,
    sanitize_diagnostic,
)

# ---------------------------------------------------------------------------
# Target environment
# ---------------------------------------------------------------------------


class TargetEnvironment(BaseModel, frozen=True):
    """Target platform for dependency resolution.

    Because peeq is an inspection tool, it resolves for arbitrary
    target environments --- not necessarily the host.  PEP 508 markers
    are evaluated against the user-specified target.

    Empty strings mean "unspecified" --- markers referencing unset values
    are treated as satisfied (permissive default).
    """

    python_version: str = ""
    """Two-part Python version, e.g., `"3.12"`.  Maps to both
    `python_version` and `python_full_version` markers."""

    os_name: str = ""
    """Value of `os.name`, e.g., `"posix"`, `"nt"`."""

    sys_platform: str = ""
    """Value of `sys.platform`, e.g., `"linux"`, `"win32"`,
    `"darwin"`."""

    platform_machine: str = ""
    """Value of `platform.machine()`, e.g., `"x86_64"`,
    `"aarch64"`."""

    def to_marker_env(self) -> dict[str, str]:
        """Convert to a dict for `packaging.markers.Marker.evaluate()`.

        Only includes keys with non-empty values so that unspecified
        markers fall through to the `packaging` library's defaults
        (which uses the current host values).
        """
        env: dict[str, str] = {}
        if self.python_version:
            env["python_version"] = self.python_version
            # python_full_version needs a micro component; default to .0
            if self.python_version.count(".") == 1:
                env["python_full_version"] = f"{self.python_version}.0"
            else:
                env["python_full_version"] = self.python_version
        if self.os_name:
            env["os_name"] = self.os_name
        if self.sys_platform:
            env["sys_platform"] = self.sys_platform
        if self.platform_machine:
            env["platform_machine"] = self.platform_machine
        return env

    @classmethod
    def current(cls) -> TargetEnvironment:
        """Create a `TargetEnvironment` matching the current host."""
        v = sys.version_info
        return cls(
            python_version=f"{v.major}.{v.minor}",
            os_name=os.name,
            sys_platform=sys.platform,
            platform_machine=platform.machine(),
        )


# ---------------------------------------------------------------------------
# Solver result
# ---------------------------------------------------------------------------


class DependencyEdge(BaseModel, frozen=True):
    """A dependency relationship with provenance details.

    Captures the extras and raw requirement string for a dependency
    edge in the resolution graph.  Used alongside the flat
    `ResolvedDependency.dependencies` name list to provide richer
    provenance for dependency graph display and conflict analysis.
    """

    name: str
    """Canonical package name."""

    extras: frozenset[str] = frozenset()
    """Extras that triggered this dependency (e.g.,
    `frozenset({"http2"})` when the parent depends on
    `httpx[http2]`)."""

    requirement: str = ""
    """Raw requirement string (e.g., `"kubernetes>=8.0.0,<31"`)."""


class ResolvedDependency(BaseModel, frozen=True):
    """A single resolved package in the dependency graph."""

    name: str
    """Canonical package name."""

    version: PkgVersion
    """Resolved version."""

    dependencies: list[str] = Field(default_factory=list)
    """Canonical names of direct dependencies within the resolution."""

    dependency_edges: list[DependencyEdge] = Field(default_factory=list)
    """Richer dependency edges with extras and requirement provenance."""


class SolverResult(BaseModel, frozen=True):
    """Successful dependency resolution output.

    Contains the resolved mapping (package name → version) and the
    dependency graph edges.
    """

    resolved: list[ResolvedDependency]
    """All resolved packages with their versions and direct dependencies."""

    solver_id: str
    """Which solver produced this result (e.g., `"uv"`)."""


# ---------------------------------------------------------------------------
# Conflict info
# ---------------------------------------------------------------------------


class ConflictRequirement(BaseModel, frozen=True):
    """A single requirement that contributes to a conflict."""

    package: str
    """The package that imposed this requirement."""

    version: str
    """Version (or specifier) of the package imposing the requirement."""

    dependency: str
    """The raw requirement string (e.g., `"numpy>=1.23,<1.27"`)."""

    chain: list[str] = Field(default_factory=list)
    """Dependency path from root to the package that imposed the
    requirement (ordered root → parent, PEP 508 strings).
    Empty for root/direct requirements."""


class ConflictInfo(BaseModel, frozen=True):
    """Structured information about a dependency conflict.

    Produced when resolution fails due to incompatible requirements.
    """

    package: str
    """The package whose versions could not be reconciled."""

    requirements: list[ConflictRequirement] = Field(default_factory=list)
    """The conflicting requirements from different parents."""

    message: str = ""
    """Human-readable summary of the conflict."""

    hints: list[str] = Field(default_factory=list)
    """Actionable hints from the solver (e.g., 'try --pre')."""

    additional_requirements: list[ConflictRequirement] = Field(default_factory=list)
    """Requirements on this package that don't contribute to the conflict
    but still constrain the solution space. Only covers packages within
    the conflict's dependency chains with exact version pins."""

    @field_validator("message")
    @classmethod
    def _sanitize_message(cls, value: str) -> str:
        """Bound conflict proof text before it reaches a renderer."""
        return sanitize_diagnostic(value, fallback="")

    @field_validator("hints")
    @classmethod
    def _sanitize_hints(cls, value: list[str]) -> list[str]:
        """Bound hint count and size before storing solver diagnostics."""
        hints = [
            sanitize_diagnostic(hint, max_length=DIAGNOSTIC_HINT_MAX_LENGTH, max_lines=1, fallback="")
            for hint in value[:DIAGNOSTIC_MAX_HINTS]
        ]
        return [hint for hint in hints if hint]


# ---------------------------------------------------------------------------
# Why command models
# ---------------------------------------------------------------------------


class PathHop(BaseModel, frozen=True):
    """A single hop in a dependency path."""

    package: str
    """Canonical package name."""

    version: str
    """Resolved version of this package."""

    requirement: str | None = None
    """The version specifier this package requires of the next hop
    (e.g., `'>=8.0.0,<31'`). `None` for the final node (the target itself)."""


class WhyPath(BaseModel, frozen=True):
    """A single dependency path from a root to the target."""

    hops: list[PathHop]
    """Ordered list of packages from root to target."""


class WhyResult(BaseModel, frozen=True):
    """Result of a `why` query."""

    target: str
    """The target package that was traced."""

    target_version: str
    """The resolved version of the target package."""

    paths: list[WhyPath]
    """All discovered paths from roots to the target."""

    is_direct: bool = False
    """`True` if the target is a direct (root) requirement."""

    truncated: bool = False
    """`True` if `max_paths` limit was hit and some paths were dropped."""
