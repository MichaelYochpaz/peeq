"""Shared data bridge between peeq's data layer and the solver backend.

`PackageProvider` is peeq's own abstraction.  The `UvSolver` uses it
to access index URLs and pre-release settings when building the
`uv pip compile` command.

Data flow::

    Solver asks "what versions exist for numpy?"
      → Check cache (packages table)
      → Cache miss? → Fetch from backend (PEP 691 API)
      → Filter pre-releases, yanked, and python-incompatible versions
      → Return sorted version list

    Solver asks "what does numpy 1.26.0 depend on?"
      → Check cache (dependencies table)
      → Cache miss? → Fetch via metadata_fetcher
      → Evaluate markers against target environment
      → Return filtered dependency list
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from packaging.markers import Marker
from packaging.specifiers import SpecifierSet
from packaging.version import Version

from peeq.sanitize import sanitize_diagnostic

if TYPE_CHECKING:
    from collections.abc import Iterable

    from peeq.backends.base import PackageRepository
    from peeq.cache.manager import CacheManager
    from peeq.models import Dependency, PackageMetadata, VersionInfo
    from peeq.resolver.models import TargetEnvironment

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Protocol for metadata fetching (service layer will satisfy this)
# ---------------------------------------------------------------------------


@runtime_checkable
class MetadataFetcher(Protocol):
    """Protocol for fetching package metadata.

    The service layer's `PackageService.get_metadata` satisfies this.
    Defined as a protocol so the resolver module has no circular dependency
    on the service layer.
    """

    async def get_metadata(
        self,
        package: str,
        version: str,
    ) -> PackageMetadata | None:
        """Fetch metadata for a specific package version."""
        ...


# ---------------------------------------------------------------------------
# PackageProvider
# ---------------------------------------------------------------------------


class PackageProvider:
    """Provide package universe data to solvers.

    This is peeq's own abstraction sitting between the data layer
    (cache, backends, metadata) and solver backends.  It handles caching,
    filtering, and marker evaluation so solvers don't need to.

    Parameters
    ----------
    cache:
        Cache manager for local lookups.
    metadata_fetcher:
        Async metadata fetcher (typically the service layer).
    backend:
        Package repository backend for API queries.
    target_env:
        Target platform for marker evaluation.
    include_prereleases:
        Whether to include pre-release versions in resolution.
    """

    def __init__(
        self,
        cache: CacheManager,
        metadata_fetcher: MetadataFetcher,
        backend: PackageRepository,
        target_env: TargetEnvironment,
        *,
        include_prereleases: bool = False,
    ) -> None:
        self._cache = cache
        self._metadata_fetcher = metadata_fetcher
        self._backend = backend
        self._target_env = target_env
        self.include_prereleases = include_prereleases
        self._marker_env = target_env.to_marker_env()

        # In-memory caches to avoid redundant async calls within one
        # resolution session.  These are NOT persistent across sessions.
        self._versions_cache: dict[tuple[str, bool, bool], list[Version]] = {}
        self._deps_cache: dict[tuple[str, str], list[Dependency]] = {}
        self._yanked_cache: dict[tuple[str, str], bool] = {}

    @property
    def target_env(self) -> TargetEnvironment:
        """Target environment used for marker evaluation."""
        return self._target_env

    @property
    def backend(self) -> PackageRepository:
        """The backend repository being used."""
        return self._backend

    # ------------------------------------------------------------------
    # Version listing
    # ------------------------------------------------------------------

    async def get_versions(
        self,
        package: str,
        *,
        include_yanked: bool = False,
        requirements: Iterable[SpecifierSet] | None = None,
    ) -> list[Version]:
        """Return available versions for *package*, filtered and sorted.

        Versions are sorted in descending order (newest first).
        Pre-release versions are excluded unless `include_prereleases`
        is set or a requirement explicitly pins a pre-release via
        `==` (mirroring pip's behavior per
        PEP 440 — https://peps.python.org/pep-0440/).

        Parameters
        ----------
        include_yanked:
            When `False` (default), versions where all distribution
            files have been yanked (PEP 592) are excluded.
        requirements:
            Specifier sets from active requirements referencing this
            package.  When any specifier contains `==<pre_version>`,
            pre-release versions are admitted even when
            `include_prereleases` is globally `False`.

        Filtering also applies `requires-python` from the Simple API
        response: versions whose `Requires-Python` specifier excludes
        the target Python version are dropped.  Versions without a
        `Requires-Python` declaration pass through (permissive
        default).

        Yanked status from the backend's `VersionInfo`
        is pre-populated into `_yanked_cache`, avoiding per-version
        `is_yanked` calls (which would hit `backend.files()`).
        """
        # Determine if pre-releases should be admitted for this package.
        # Pre-releases are admitted when globally enabled OR when any
        # active requirement explicitly pins a pre-release via `==`
        # (mirrors pip's behavior).
        admit_prereleases = self.include_prereleases or (
            requirements is not None and _any_specifier_pins_prerelease(requirements)
        )

        cache_key = (package, include_yanked, admit_prereleases)
        if cache_key in self._versions_cache:
            return self._versions_cache[cache_key]

        version_infos = await self._backend.versions(package)

        # Pre-populate yanked cache from VersionInfo data.
        for version in version_infos:
            self._yanked_cache[(package, str(version.version))] = version.yanked

        filtered: list[Version] = []
        for version in version_infos:
            v = version.version
            if not admit_prereleases and (v.is_prerelease or v.is_devrelease):
                continue
            if not include_yanked and version.yanked:
                continue
            if not self._python_requires_compatible(version):
                continue
            filtered.append(v)

        # Sort descending (newest first).
        filtered.sort(reverse=True)
        self._versions_cache[cache_key] = filtered
        return filtered

    # ------------------------------------------------------------------
    # Dependency fetching
    # ------------------------------------------------------------------

    async def get_dependencies(
        self,
        package: str,
        version: str,
    ) -> list[Dependency]:
        """Return dependencies for *package*==*version*, markers evaluated.

        Dependencies whose PEP 508 markers do not match the target
        environment are excluded.  Parent-extra conditions (`extra == "..."`)
        are NOT evaluated here --- extras virtualization is the solver's
        responsibility.
        """
        key = (package, version)
        if key in self._deps_cache:
            return self._deps_cache[key]

        metadata = await self._metadata_fetcher.get_metadata(package, version)
        if metadata is None or metadata.dependencies is None:
            self._deps_cache[key] = []
            return []

        filtered = self._evaluate_markers(metadata.dependencies)
        self._deps_cache[key] = filtered
        return filtered

    # ------------------------------------------------------------------
    # Yanked status (lazy per-version)
    # ------------------------------------------------------------------

    async def is_yanked(self, package: str, version: str) -> bool:
        """Check if a specific version is yanked.

        A version is considered yanked if ALL of its files are yanked
        (PEP 592).  Results are cached per session.
        """
        key = (package, version)
        if key in self._yanked_cache:
            return self._yanked_cache[key]

        try:
            files = await self._backend.files(package, version)
            yanked = bool(files) and all(f.yanked for f in files)
        except Exception:
            logger.debug("Failed to check yanked status for %s %s", package, version)
            yanked = False

        self._yanked_cache[key] = yanked
        return yanked

    # ------------------------------------------------------------------
    # Python requires filtering
    # ------------------------------------------------------------------

    async def check_python_requires(
        self,
        package: str,
        version: str,
    ) -> bool:
        """Check if *version* is compatible with the target Python version.

        Returns `True` if compatible or if no `python_requires` is
        specified.  Returns `True` if no target Python version is set
        (permissive default).
        """
        if not self._target_env.python_version:
            return True

        metadata = await self._metadata_fetcher.get_metadata(package, version)
        if metadata is None or metadata.python_requires is None:
            return True

        try:
            spec = SpecifierSet(metadata.python_requires)
        except Exception:
            logger.debug(
                "Invalid python_requires for %s %s: %s",
                package,
                version,
                sanitize_diagnostic(metadata.python_requires),
            )
            return True

        target = self._target_env.python_version
        # SpecifierSet expects a full version; append .0 if needed.
        if target.count(".") == 1:
            target = f"{target}.0"
        return Version(target) in spec

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _python_requires_compatible(self, version_info: VersionInfo) -> bool:
        """Check if *version_info*'s `Requires-Python` allows the target.

        Returns `True` (permissive) when no target Python version is
        set, when the version has no `requires-python` declaration,
        or when the specifier is invalid.
        """
        if not self._target_env.python_version:
            return True
        if not version_info.requires_python:
            return True
        try:
            spec = SpecifierSet(version_info.requires_python)
        except Exception:
            logger.debug(
                "Invalid requires-python %r for %s, including version",
                sanitize_diagnostic(version_info.requires_python),
                version_info.version,
            )
            return True

        target = self._target_env.python_version
        # SpecifierSet expects a full version; append .0 if needed.
        if target.count(".") == 1:
            target = f"{target}.0"
        return Version(target) in spec

    def _evaluate_markers(
        self,
        dependencies: list[Dependency],
    ) -> list[Dependency]:
        """Filter dependencies by evaluating PEP 508 markers.

        Dependencies with `extra == "..."` markers are kept (extras
        virtualization is handled by the solver, not the provider).
        """
        result: list[Dependency] = []
        for dep in dependencies:
            if dep.markers is None:
                result.append(dep)
                continue

            # Keep dependencies gated on extras --- the solver handles
            # extras virtualization.
            if "extra ==" in dep.markers or "extra !=" in dep.markers:
                result.append(dep)
                continue

            try:
                marker = Marker(dep.markers)
                if marker.evaluate(self._marker_env or None):
                    result.append(dep)
            except Exception:
                logger.debug(
                    "Failed to evaluate marker %r, including dependency",
                    sanitize_diagnostic(dep.markers),
                )
                result.append(dep)

        return result


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------


def _any_specifier_pins_prerelease(
    specifier_sets: Iterable[SpecifierSet],
) -> bool:
    """Check if any specifier set explicitly pins a pre-release via `==`.

    Return `True` when at least one specifier uses the `==` operator
    with a version that `packaging` considers a pre-release (alpha,
    beta, rc, or dev).  This mirrors pip's behavior: pre-release
    versions are admitted when a requirement explicitly references one
    (e.g., `kubernetes==35.0.0a1`).
    """
    for spec_set in specifier_sets:
        for spec in spec_set:
            if spec.operator == "==":
                try:
                    if Version(spec.version).is_prerelease:
                        return True
                except Exception:
                    logger.debug("Unparseable version in specifier: %s", sanitize_diagnostic(str(spec)))
    return False
