"""Pluggable dependency resolver (uv backend).

Provides `DependencyResolver` ABC with auto-registration,
`PackageProvider` as the shared data bridge, and the `UvSolver`
backend (requires the `uv` binary).

Importing this module triggers `__init_subclass__` registration
for the uv solver.
"""

# Import solver module to trigger __init_subclass__ auto-registration.
from peeq.resolver import uv_solver as uv_solver
from peeq.resolver.base import (
    DependencyResolver,
    ResolutionImpossible,
    ResolutionTooDeep,
    UvNotFoundError,
)
from peeq.resolver.models import (
    ConflictInfo,
    ConflictRequirement,
    DependencyEdge,
    ResolvedDependency,
    SolverResult,
    TargetEnvironment,
)
from peeq.resolver.provider import MetadataFetcher, PackageProvider

__all__ = [
    "ConflictInfo",
    "ConflictRequirement",
    "DependencyEdge",
    "DependencyResolver",
    "MetadataFetcher",
    "PackageProvider",
    "ResolutionImpossible",
    "ResolutionTooDeep",
    "ResolvedDependency",
    "SolverResult",
    "TargetEnvironment",
    "UvNotFoundError",
]
