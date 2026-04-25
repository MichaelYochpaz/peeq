"""Service layer orchestrating cache, metadata, resolver, and backends.

The `PackageService` is the orchestration layer that CLI commands
interact with.  It coordinates cache lookups, metadata extraction
(PEP 658 (https://peps.python.org/pep-0658/) → sdist → wheel fallback
chain), dependency resolution, and backend API communication.

Three distinct code paths:

- **Metadata queries** (`deps`, `info`): cache →
  PEP 658 (https://peps.python.org/pep-0658/) → sdist extraction →
  wheel extraction.
- **File inspection** (`show`, `download`): artifact cache/download →
  in-memory extraction.
- **Dependency resolution** (`resolve`, `conflicts`): PackageProvider →
  DependencyResolver.

Satisfies the `MetadataFetcher` protocol
via `PackageService.get_metadata`, allowing the resolver's
`PackageProvider` to fetch on-demand
metadata through the service layer's fallback chain without circular imports.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

from packaging.version import Version

from peeq.cache import CacheManager, HashMismatchError
from peeq.config import get_settings
from peeq.extraction import ExtractionError
from peeq.metadata import (
    extract_sdist_metadata,
    extract_wheel_metadata,
    select_sdist,
    select_wheel,
)
from peeq.metadata.parsing import is_pure_python_wheel, parse_email_metadata
from peeq.models import DistType, InfoReport, PackageInfo, VersionInfo
from peeq.resolver.base import DependencyResolver
from peeq.resolver.provider import PackageProvider
from peeq.sanitize import sanitize_filename

if TYPE_CHECKING:
    from peeq.backends.base import PackageRepository
    from peeq.extraction import ArchiveMember
    from peeq.models import (
        DepChange,
        Dependency,
        DepsDiff,
        FileInfo,
        PackageMetadata,
        VulnerabilityReport,
    )
    from peeq.resolver.models import (
        ConflictInfo,
        ConflictRequirement,
        SolverResult,
        TargetEnvironment,
        WhyPath,
        WhyResult,
    )

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class ArtifactNotAvailableError(Exception):
    """No distribution file (sdist or wheel) available for a version."""


class FileNotInArchiveError(Exception):
    """Requested file not found inside the cached archive."""


class TagNotFoundError(Exception):
    """Specified wheel tag does not match any available wheel.

    The `available_tags` attribute lists valid tags for the version.
    """

    def __init__(self, message: str, available_tags: list[str]) -> None:
        super().__init__(message)
        self.available_tags = available_tags


class _Pep658HashMismatchError(Exception):
    """Internal sentinel for PEP 658 hash verification failure in tag flow."""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _build_target_env(
    *,
    python_version: str | None = None,
    platform: str | None = None,
) -> TargetEnvironment:
    """Build a `TargetEnvironment` from optional CLI flags.

    When both flags are `None`, return the current host environment.
    """
    from peeq.resolver.models import TargetEnvironment  # noqa: PLC0415

    kwargs: dict[str, str] = {}
    if python_version:
        kwargs["python_version"] = python_version
    if platform:
        kwargs["sys_platform"] = platform
        if platform == "win32":
            kwargs["os_name"] = "nt"
        elif platform in ("linux", "darwin"):
            kwargs["os_name"] = "posix"

    if kwargs:
        return TargetEnvironment(**kwargs)
    return TargetEnvironment.current()


def _extract_exact_version(version_spec: str) -> str | None:
    """Return the bare version if the specifier pins exactly, else None.

    Handle `==X.Y.Z`, `===X.Y.Z`, and bare `X.Y.Z`.
    Return `None` for ranges (`>=`, `<`, `~=`, etc.).
    """
    if not version_spec:
        return None
    if version_spec.startswith("==="):
        return version_spec[3:]
    if version_spec.startswith("=="):
        v = version_spec[2:]
        return None if v.endswith(".*") else v
    if version_spec[0].isdigit():
        return version_spec
    return None


def _collect_fetch_targets(
    conflict: ConflictInfo,
    target_name: str,
) -> dict[tuple[str, str], str]:
    """Collect (name, version) -> display_name pairs for metadata lookups.

    Extract packages from conflict requirement parents and chain
    entries, skipping non-exact versions and the target package itself.
    """
    from packaging.requirements import (  # noqa: PLC0415
        InvalidRequirement,
        Requirement,
    )
    from packaging.utils import canonicalize_name  # noqa: PLC0415

    to_fetch: dict[tuple[str, str], str] = {}

    for req in conflict.requirements:
        parent_name = canonicalize_name(req.package)
        parent_version = _extract_exact_version(req.version)
        if parent_version and parent_name != target_name:
            to_fetch[(parent_name, parent_version)] = req.package

        for entry in req.chain:
            try:
                parsed = Requirement(entry)
            except InvalidRequirement:
                continue
            chain_name = canonicalize_name(parsed.name)
            chain_version = _extract_exact_version(str(parsed.specifier))
            if not chain_version or chain_name == target_name:
                continue
            extras_str = f"[{','.join(sorted(parsed.extras))}]" if parsed.extras else ""
            to_fetch[(chain_name, chain_version)] = (
                f"{canonicalize_name(parsed.name)}{extras_str}"
            )

    return to_fetch


def _build_existing_constraints(
    conflict: ConflictInfo,
) -> set[tuple[str, str]]:
    """Build a set of (parent_name, normalized_specifier) for dedup.

    Normalize specifiers via `packaging` so that ordering differences
    (e.g., `>=8.0.0,<31` vs `<31,>=8.0.0`) are handled correctly.
    """
    from packaging.requirements import (  # noqa: PLC0415
        InvalidRequirement,
        Requirement,
    )
    from packaging.utils import canonicalize_name  # noqa: PLC0415

    existing: set[tuple[str, str]] = set()
    for r in conflict.requirements:
        try:
            parsed_dep = Requirement(r.dependency)
            norm_spec = str(parsed_dep.specifier)
        except InvalidRequirement:
            norm_spec = r.dependency
        existing.add((canonicalize_name(r.package), norm_spec))
    return existing


# ---------------------------------------------------------------------------
# PackageService
# ---------------------------------------------------------------------------


class PackageService:
    """Orchestration layer for cache, metadata extraction, resolver, and backends.

    Three distinct code paths:

    - **Metadata queries** (`deps`, `info`): service layer orchestrates
      fallback (cache → PEP 658 (https://peps.python.org/pep-0658/) →
      sdist → wheel).
    - **File inspection** (`show`, `download`): go directly to artifact
      cache/download (sdist-first).
    - **Dependency resolution** (`resolve`, `conflicts`): go through
      `DependencyResolver` (pluggable solver).

    Satisfies the `MetadataFetcher`
    protocol via `get_metadata`.
    """

    def __init__(
        self,
        *,
        cache: CacheManager,
        backend: PackageRepository,
    ) -> None:
        self._cache = cache
        self._backend = backend

    @property
    def registry(self) -> str:
        """Return the registry identifier from the backend (e.g., `"pypi.org"`)."""
        return self._backend.registry

    # ------------------------------------------------------------------
    # Package-level queries
    # ------------------------------------------------------------------

    async def check(self, name: str) -> PackageInfo | None:
        """Check if *name* exists on the registry and return basic info.

        Use cached API data when available (TTL-based), otherwise fetch
        from the backend and cache the result.
        """
        cached = self._cache.get_package(self.registry, name)
        if cached is not None:
            versions_json = cached.get("available_versions")
            version_list = json.loads(versions_json) if versions_json else []
            latest = cached.get("latest_version")
            if latest is None:
                return None

            # Deserialize enriched fields from legacy_metadata column
            legacy_meta: dict[str, Any] = {}
            legacy_json = cached.get("legacy_metadata")
            if legacy_json:
                legacy_meta = json.loads(legacy_json)

            latest_release_date = None
            ts = legacy_meta.get("latest_release_date")
            if isinstance(ts, (int, float)):
                latest_release_date = datetime.fromtimestamp(
                    ts,
                    tz=timezone.utc,
                )

            return PackageInfo(
                name=cached["name"],
                latest_version=Version(latest),
                version_count=cached.get("version_count") or len(version_list),
                summary=cached.get("summary"),
                registry=self.registry,
                license=legacy_meta.get("license"),
                license_format=legacy_meta.get("license_format"),
                requires_python=legacy_meta.get("requires_python"),
                author=legacy_meta.get("author"),
                project_urls=legacy_meta.get("project_urls"),
                latest_release_date=latest_release_date,
            )

        info = await self._backend.check(name)
        if info is None:
            return None

        # Serialize enriched fields for the legacy_metadata column
        legacy_metadata_dict: dict[str, object] = {}
        if info.license is not None:
            legacy_metadata_dict["license"] = info.license
        if info.license_format is not None:
            legacy_metadata_dict["license_format"] = info.license_format
        if info.requires_python is not None:
            legacy_metadata_dict["requires_python"] = info.requires_python
        if info.author is not None:
            legacy_metadata_dict["author"] = info.author
        if info.project_urls is not None:
            legacy_metadata_dict["project_urls"] = info.project_urls
        if info.latest_release_date is not None:
            legacy_metadata_dict["latest_release_date"] = int(
                info.latest_release_date.timestamp()
            )

        legacy_metadata_json = (
            json.dumps(legacy_metadata_dict) if legacy_metadata_dict else None
        )

        # Cache the result (versions list capped by cache layer)
        version_infos = await self._backend.versions(name)
        self._cache.upsert_package(
            registry=self.registry,
            name=name,
            latest_version=str(info.latest_version),
            summary=info.summary,
            available_versions=[str(version.version) for version in version_infos],
            version_count=info.version_count,
            legacy_metadata=legacy_metadata_json,
        )
        return info

    async def info(  # noqa: C901, PLR0912, PLR0913, PLR0915
        self,
        name: str,
        *,
        include_versions: bool = False,
        include_vulns: bool = False,
        include_deps: bool = False,
        target_version: str | None = None,
        version_limit: int | None = 20,
    ) -> InfoReport | None:
        """Build a composite package report.

        Calls `check()`, and optionally `versions()`,
        `check_vulnerabilities()`, and `get_metadata()` based on
        the *include_** flags.  Heavy sections run concurrently via
        `asyncio.gather(return_exceptions=True)` so partial failures
        are captured in `InfoReport.errors` instead of crashing the
        entire report.
        """
        base_info = await self.check(name)
        if base_info is None:
            return None

        # Resolve target version
        errors: dict[str, str] = {}

        version_invalid = False
        if target_version is not None and target_version.lower() != "latest":
            resolved_version = target_version
            # Validate version exists
            try:
                all_versions = await self.versions(name)
                valid_versions = {str(v.version) for v in all_versions}
                if resolved_version not in valid_versions:
                    version_error = f"Version {resolved_version} not found for {name}"
                    if include_vulns:
                        errors["vulns"] = version_error
                    if include_deps:
                        errors["deps"] = version_error
                    version_invalid = True
            except Exception as exc:
                # If version validation fails, still try — the version
                # might exist
                logger.debug("Version validation failed: %s", exc)
        else:
            resolved_version = str(base_info.latest_version)

        # Build concurrent tasks based on flags.
        # Versions section is independent of target_version, so it runs
        # even when the target version is invalid.
        tasks: dict[str, Any] = {}
        if include_versions:
            tasks["versions"] = self.versions(name)
        if include_vulns and not version_invalid:
            tasks["vulns"] = self.check_vulnerabilities(
                name,
                resolved_version,
            )
        if include_deps and not version_invalid:
            tasks["deps"] = self.get_metadata(name, resolved_version)

        result_map: dict[str, Any] = {}
        if tasks:
            results = await asyncio.gather(
                *tasks.values(),
                return_exceptions=True,
            )
            result_map = dict(zip(tasks.keys(), results, strict=True))

        # Process results
        versions_list = None
        versions_total = None
        vuln_report = None
        metadata = None

        if "versions" in result_map:
            v = result_map["versions"]
            if isinstance(v, BaseException):
                errors["versions"] = str(v)
            else:
                versions_total = len(v)
                versions_list = v[:version_limit] if version_limit is not None else v

        if "vulns" in result_map:
            v = result_map["vulns"]
            if isinstance(v, BaseException):
                errors["vulns"] = str(v)
            else:
                vuln_report = v

        if "deps" in result_map:
            v = result_map["deps"]
            if isinstance(v, BaseException):
                errors["deps"] = str(v)
            elif v is None:
                errors["deps"] = f"No metadata available for {name}=={resolved_version}"
            else:
                metadata = v

        # When targeting a non-latest version, update requires_python
        # from the version's file list (the Simple API data is already
        # cached from check(), so this is essentially free).
        if not version_invalid and resolved_version != str(base_info.latest_version):
            try:
                version_files = await self.files(name, resolved_version)
                version_requires_python = next(
                    (f.requires_python for f in version_files if f.requires_python),
                    None,
                )
                base_info = base_info.model_copy(
                    update={"requires_python": version_requires_python}
                )
            except Exception as exc:
                logger.debug(
                    "Failed to fetch requires_python for %s==%s: %s",
                    name,
                    resolved_version,
                    exc,
                )

        return InfoReport(
            info=base_info,
            target_version=(
                resolved_version if (include_vulns or include_deps) else None
            ),
            versions=versions_list,
            versions_total=versions_total,
            vulnerabilities=vuln_report,
            metadata=metadata,
            errors=errors or None,
        )

    async def versions(self, name: str) -> list[VersionInfo]:
        """List all available versions with yanked status, sorted newest-first.

        Always fetch from the backend (cached `available_versions` is
        capped at 100 for storage efficiency).
        """
        return await self._backend.versions(name)

    async def files(self, name: str, version: str) -> list[FileInfo]:
        """List available files (sdists, wheels) for a version."""
        return await self._backend.files(name, version)

    # ------------------------------------------------------------------
    # Metadata queries (fallback chain)
    # ------------------------------------------------------------------

    async def get_metadata(  # noqa: PLR0911
        self,
        package: str,
        version: str,
        *,
        tag: str | None = None,
    ) -> PackageMetadata | None:
        """Get metadata via the full fallback chain.

        The service layer orchestrates: cache →
        PEP 658 (https://peps.python.org/pep-0658/) → sdist → wheel.
        Every extraction result is saved to cache unconditionally.
        When multiple rows exist for the same version, the cache query
        picks the best one (`ORDER BY deps_known DESC`, source priority).

        Parameters
        ----------
        package:
            Package name (will be used as-is; callers should normalize).
        version:
            Exact version string.
        tag:
            Optional 3-part wheel tag (e.g., `"cp312-cp312-win_amd64"`).
            When specified, metadata is extracted from the matching wheel
            variant instead of the default selection.
        """
        registry = self.registry

        # 1. Cache lookup (always first)
        if tag is None:
            cached = self._cache.get_metadata(registry, package, version)
            if cached is not None:
                return cached

        # 2. Tag-specific flow bypasses normal fallback
        if tag is not None:
            return await self._get_metadata_for_tag(
                package,
                version,
                tag,
            )

        # 3. Get file list (used for PEP 658 / sdist / wheel)
        try:
            files = await self._backend.files(package, version)
        except Exception:
            logger.debug(
                "Failed to list files for %s==%s",
                package,
                version,
                exc_info=True,
            )
            return None

        # 4. Try PEP 658 metadata (fast, no artifact download)
        metadata = await self._try_pep658(files, package, version)
        if metadata is not None:
            return metadata

        # 5. Try sdist (download to cache, extract PKG-INFO)
        metadata = await self._try_sdist(files, package, version)
        if metadata is not None and metadata.dependencies is not None:
            return metadata
        # Dynamic Requires-Dist → fall through to wheel

        # 6. Try wheel (download to temp, extract METADATA, delete temp)
        wheel_metadata = await self._try_wheel(files, package, version)
        if wheel_metadata is not None:
            return wheel_metadata

        # 7. Return whatever we have (possibly partial sdist, possibly None)
        return self._cache.get_metadata(registry, package, version)

    # ------------------------------------------------------------------
    # File inspection
    # ------------------------------------------------------------------

    async def get_file_content(
        self,
        package: str,
        version: str,
        path: str,
    ) -> bytes:
        """Extract and return a specific file from the cached artifact.

        This is a separate code path from metadata extraction.  File
        inspection requires the actual artifact (sdist preferred, wheel
        as fallback).  Metadata queries use
        PEP 658 (https://peps.python.org/pep-0658/) / wheel METADATA and
        may never download an artifact at all.

        Raises
        ------
        ArtifactNotAvailableError
            If no artifact (sdist or wheel) can be downloaded.
        FileNotInArchiveError
            If *path* is not found in the cached archive.
        """
        await self._ensure_artifact_cached(package, version)

        try:
            return self._cache.extract_file(
                self.registry,
                package,
                version,
                path,
            )
        except ExtractionError as exc:
            msg = f"File {path!r} not found in archive for {package}=={version}: {exc}"
            raise FileNotInArchiveError(msg) from exc

    async def list_artifact_files(
        self,
        package: str,
        version: str,
    ) -> list[ArchiveMember]:
        """List files inside the cached artifact.

        Download and cache the artifact first if not already cached.

        Raises
        ------
        ArtifactNotAvailableError
            If no artifact (sdist or wheel) can be downloaded.
        """
        await self._ensure_artifact_cached(package, version)
        return self._cache.list_archive(self.registry, package, version)

    async def download_package(
        self,
        package: str,
        version: str,
        dest: Path,
        *,
        extract: bool = False,
    ) -> Path:
        """Download a package to *dest*.

        Serve from cache if available, download and cache if not.
        When *extract* is `True`, extract the archive contents to *dest*
        (with PEP 706 (https://peps.python.org/pep-0706/) safety measures).
        Otherwise, copy the archive file.

        Returns the path to the downloaded/extracted output.

        Raises
        ------
        ArtifactNotAvailableError
            If no artifact (sdist or wheel) can be downloaded.
        """
        cached_path = await self._ensure_artifact_cached(package, version)

        if extract:
            dest.mkdir(parents=True, exist_ok=True)
            self._cache.extract_to_disk(
                self.registry,
                package,
                version,
                dest,
            )
            return dest

        dest.parent.mkdir(parents=True, exist_ok=True)
        out = dest / cached_path.name if dest.is_dir() else dest
        shutil.copy2(cached_path, out)
        return out

    # ------------------------------------------------------------------
    # Dependency resolution
    # ------------------------------------------------------------------

    async def resolve_dependencies(
        self,
        requirements: list[str],
        target_env: TargetEnvironment,
        *,
        include_prereleases: bool = False,
    ) -> SolverResult:
        """Resolve requirements into concrete versions.

        Create a `PackageProvider` and
        delegate to the uv solver backend.

        Parameters
        ----------
        requirements:
            PEP 508 (https://peps.python.org/pep-0508/) requirement strings
            (e.g., `["flask>=2.0", "requests"]`).
        target_env:
            Target platform for marker evaluation.
        include_prereleases:
            When `True`, include pre-release versions in resolution.

        Raises
        ------
        ResolutionImpossible
            If no set of versions satisfies all constraints.
        """
        provider = PackageProvider(
            cache=self._cache,
            metadata_fetcher=self,
            backend=self._backend,
            target_env=target_env,
            include_prereleases=include_prereleases,
        )
        solver = DependencyResolver.get_solver(
            "uv",
            provider=provider,
        )
        return await solver.resolve(requirements, target_env)

    # ------------------------------------------------------------------
    # Conflict enrichment
    # ------------------------------------------------------------------

    async def enrich_conflicts(
        self,
        conflicts: list[ConflictInfo],
    ) -> list[ConflictInfo]:
        """Add non-conflicting constraints to conflict data.

        For each conflict, fetch metadata for packages in the dependency
        chains and check whether they impose additional constraints on
        the conflicting package that aren't part of the conflict proof.
        """
        enriched: list[ConflictInfo] = []
        for conflict in conflicts:
            updated = await self._enrich_single_conflict(conflict)
            enriched.append(updated)
        return enriched

    async def _enrich_single_conflict(
        self,
        conflict: ConflictInfo,
    ) -> ConflictInfo:
        """Enrich a single conflict with supplementary lookups."""
        from packaging.utils import canonicalize_name  # noqa: PLC0415

        from peeq.resolver.models import ConflictRequirement  # noqa: PLC0415

        target_name = canonicalize_name(conflict.package)
        to_fetch = _collect_fetch_targets(conflict, target_name)

        if not to_fetch:
            return conflict

        # Fetch metadata concurrently
        tasks = [self.get_metadata(name, version) for name, version in to_fetch]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        existing = _build_existing_constraints(conflict)
        additional: list[ConflictRequirement] = []
        seen: set[tuple[str, str]] = set()

        for (pkg_name, pkg_version), metadata in zip(
            to_fetch,
            results,
            strict=True,
        ):
            if isinstance(metadata, BaseException) or metadata is None:
                continue
            if metadata.dependencies is None:
                continue
            display = to_fetch[(pkg_name, pkg_version)]
            for dep in metadata.dependencies:
                if canonicalize_name(dep.name) != target_name:
                    continue
                dep_str = f"{dep.name}{dep.specifier}" if dep.specifier else dep.name
                key = (pkg_name, dep.specifier)
                if key in existing or key in seen:
                    continue
                seen.add(key)
                additional.append(
                    ConflictRequirement(
                        package=display,
                        version=f"=={pkg_version}",
                        dependency=dep_str,
                    ),
                )

        if not additional:
            return conflict
        return conflict.model_copy(
            update={"additional_requirements": additional},
        )

    # ------------------------------------------------------------------
    # Why tracing
    # ------------------------------------------------------------------

    async def why_dependencies(  # noqa: PLR0913
        self,
        target: str,
        requirements: list[str],
        *,
        pre: bool = False,
        python_version: str | None = None,
        platform: str | None = None,
        all_hops: bool = True,
    ) -> WhyResult:
        """Trace dependency paths from requirements to a target package.

        Resolve the full dependency tree, then BFS backward from the
        target through the reverse adjacency map to find all paths
        from root requirements to the target.

        Args:
            target: Bare package name to trace (no version specifier).
            requirements: PEP 508 requirement strings.
            pre: Include pre-release versions in resolution.
            python_version: Target Python version (e.g., `"3.12"`).
            platform: Target platform (e.g., `"linux"`).
            all_hops: Fetch version specifiers at every hop.
                When `False`, only the final edge is enriched.

        Returns:
            A `WhyResult` with all discovered paths.

        Raises:
            ResolutionImpossible: If the requirements cannot be resolved.
        """
        from packaging.requirements import Requirement  # noqa: PLC0415
        from packaging.utils import canonicalize_name  # noqa: PLC0415

        from peeq.resolver.models import WhyResult  # noqa: PLC0415

        target_env = _build_target_env(
            python_version=python_version,
            platform=platform,
        )

        # Resolve the full dependency tree (may raise ResolutionImpossible)
        result = await self.resolve_dependencies(
            requirements,
            target_env,
            include_prereleases=pre,
        )

        # Extract canonical root names (cast to str for type compatibility)
        roots: set[str] = {
            str(canonicalize_name(Requirement(r).name)) for r in requirements
        }
        canonical_target = str(canonicalize_name(target))

        # Build version lookup from resolved packages
        version_lookup: dict[str, str] = {
            dep.name: str(dep.version) for dep in result.resolved
        }

        # Check if target is in the resolved packages
        if canonical_target not in version_lookup:
            return WhyResult(
                target=canonical_target,
                target_version="",
                paths=[],
                is_direct=False,
            )

        target_version = version_lookup[canonical_target]

        # Check if target is a direct (root) requirement
        if canonical_target in roots:
            return WhyResult(
                target=canonical_target,
                target_version=target_version,
                paths=[],
                is_direct=True,
            )

        # BFS to find paths
        max_paths = 20
        raw_paths = find_paths(result, canonical_target, roots, max_paths=max_paths)
        truncated = len(raw_paths) >= max_paths

        # Fetch edge specifiers and build WhyPath objects
        specifier_cache = await self._fetch_edge_specifiers(
            raw_paths, version_lookup, all_hops=all_hops
        )
        why_paths = _build_why_paths(
            raw_paths, version_lookup, specifier_cache, all_hops=all_hops
        )

        return WhyResult(
            target=canonical_target,
            target_version=target_version,
            paths=why_paths,
            is_direct=False,
            truncated=truncated,
        )

    async def _fetch_edge_specifiers(
        self,
        raw_paths: list[list[str]],
        version_lookup: dict[str, str],
        *,
        all_hops: bool = False,
    ) -> dict[tuple[str, str], str | None]:
        """Fetch metadata for packages in paths to extract edge specifiers.

        Return a cache mapping `(parent_name, child_name)` to the
        version specifier the parent imposes on the child.
        """
        from packaging.utils import canonicalize_name  # noqa: PLC0415

        # Determine which packages need metadata
        packages_to_fetch: set[str] = set()
        for path in raw_paths:
            if all_hops:
                for name in path[:-1]:
                    packages_to_fetch.add(name)
            elif len(path) >= 2:  # noqa: PLR2004
                packages_to_fetch.add(path[-2])

        if not packages_to_fetch:
            return {}

        # Fetch metadata concurrently
        fetch_list = sorted(n for n in packages_to_fetch if n in version_lookup)
        tasks = [self.get_metadata(name, version_lookup[name]) for name in fetch_list]
        results_meta = await asyncio.gather(*tasks, return_exceptions=True)

        # Build specifier cache
        specifier_cache: dict[tuple[str, str], str | None] = {}
        for pkg_name, metadata in zip(fetch_list, results_meta, strict=True):
            if isinstance(metadata, BaseException) or metadata is None:
                continue
            if metadata.dependencies is None:
                continue
            for dep in metadata.dependencies:
                dep_canonical = str(canonicalize_name(dep.name))
                specifier_cache[(pkg_name, dep_canonical)] = dep.specifier or None

        return specifier_cache

    # ------------------------------------------------------------------
    # Vulnerability checking
    # ------------------------------------------------------------------

    async def check_vulnerabilities(
        self,
        name: str,
        version: str,
    ) -> VulnerabilityReport:
        """Check for known vulnerabilities via the OSV database.

        Query the OSV API (https://google.github.io/osv.dev/api/) for
        vulnerabilities affecting *name* at *version*.  Results are NOT
        cached — security data should always be fresh.

        Parameters
        ----------
        name:
            Package name (will be normalized for the OSV query).
        version:
            Exact version string.

        Raises
        ------
        OSVError
            On HTTP errors or malformed responses from the OSV API.
        """
        from peeq.integrations.osv import OSVClient  # noqa: PLC0415

        async with OSVClient() as client:
            return await client.query(name, version)

    # ------------------------------------------------------------------
    # Dependency diff
    # ------------------------------------------------------------------

    def diff_dependencies(
        self,
        base: PackageMetadata,
        target: PackageMetadata,
    ) -> DepsDiff:
        """Compare dependencies between two package versions.

        Group both versions' dependencies into core and extras groups,
        then compute added, removed, changed, and unchanged sets.
        Dependencies are matched by canonicalized name within each
        extras group.  A dependency moving from core to an extras group
        appears as removed + added (since the extras group differs).

        Args:
            base: Metadata for the base (older) version.
            target: Metadata for the target (newer) version.

        Returns:
            A `DepsDiff` with all collected changes.
        """
        from packaging.utils import canonicalize_name  # noqa: PLC0415

        from peeq.models import DepChange, DepsDiff  # noqa: PLC0415
        from peeq.utils import group_dependencies  # noqa: PLC0415

        base_deps = base.dependencies or []
        target_deps = target.dependencies or []

        base_required, base_optional = group_dependencies(base_deps)
        target_required, target_optional = group_dependencies(target_deps)

        added: list[Dependency] = []
        removed: list[Dependency] = []
        changed: list[DepChange] = []
        unchanged_count = 0

        def _diff_group(
            base_group: list[Dependency],
            target_group: list[Dependency],
            extras_group: str | None,
        ) -> None:
            nonlocal unchanged_count

            base_lookup = {canonicalize_name(d.name): d for d in base_group}
            target_lookup = {canonicalize_name(d.name): d for d in target_group}

            all_names = dict.fromkeys([*base_lookup, *target_lookup])
            for name in all_names:
                in_base = base_lookup.get(name)
                in_target = target_lookup.get(name)

                if in_base is not None and in_target is None:
                    removed.append(in_base)
                elif in_base is None and in_target is not None:
                    added.append(in_target)
                elif in_base is not None and in_target is not None:
                    if (
                        in_base.specifier == in_target.specifier
                        and in_base.markers == in_target.markers
                        and in_base.extras == in_target.extras
                    ):
                        unchanged_count += 1
                    else:
                        changed.append(
                            DepChange(
                                name=name,
                                old_specifier=in_base.specifier,
                                new_specifier=in_target.specifier,
                                old_markers=in_base.markers,
                                new_markers=in_target.markers,
                                old_extras=tuple(in_base.extras),
                                new_extras=tuple(in_target.extras),
                                extras_group=extras_group,
                            )
                        )

        # Diff core deps
        _diff_group(base_required, target_required, None)

        # Diff extras groups present in both
        all_extras = dict.fromkeys([*sorted(base_optional), *sorted(target_optional)])
        for extra_name in all_extras:
            base_group = base_optional.get(extra_name, [])
            target_group = target_optional.get(extra_name, [])
            _diff_group(base_group, target_group, extra_name)

        # Extras groups added/removed
        base_extras_set = set(base_optional)
        target_extras_set = set(target_optional)
        added_extras = sorted(target_extras_set - base_extras_set)
        removed_extras = sorted(base_extras_set - target_extras_set)

        return DepsDiff(
            added=added,
            removed=removed,
            changed=changed,
            unchanged_count=unchanged_count,
            added_extras=added_extras,
            removed_extras=removed_extras,
        )

    # ------------------------------------------------------------------
    # Private helpers — PEP 658 (metadata via Simple API)
    # ------------------------------------------------------------------

    async def _try_pep658(
        self,
        files: list[FileInfo],
        package: str,
        version: str,
    ) -> PackageMetadata | None:
        """Try PEP 658 (https://peps.python.org/pep-0658/) metadata for the best wheel.

        Return `None` if no wheel with PEP 658 metadata is available
        or if the fetch fails.
        """
        # Select wheel with PEP 658 metadata
        candidates = [
            f
            for f in files
            if f.dist_type == DistType.WHEEL and f.metadata_available and not f.yanked
        ]
        if not candidates:
            logger.debug(
                "No wheel with PEP 658 metadata for %s==%s",
                package,
                version,
            )
            return None

        wheel = _select_best_wheel(candidates)

        # Fetch metadata
        metadata_url = f"{wheel.url}.metadata"
        try:
            response = await self._backend.get_with_retry(metadata_url)
        except Exception:
            logger.debug(
                "HTTP error fetching PEP 658 metadata for %s==%s",
                package,
                version,
                exc_info=True,
            )
            return None

        if not response.is_success:
            logger.debug(
                "PEP 658 metadata returned %d for %s==%s",
                response.status_code,
                package,
                version,
            )
            return None

        # Verify hash (if provided by registry)
        if wheel.metadata_hash is not None:
            computed = hashlib.sha256(response.content).hexdigest()
            if computed != wheel.metadata_hash.sha256:
                logger.warning(
                    "PEP 658 metadata hash mismatch for %s: expected %s, got %s",
                    wheel.filename,
                    wheel.metadata_hash.sha256,
                    computed,
                )
                return None

        # Parse
        metadata = parse_email_metadata(response.text, source="pep658")
        metadata.source_filename = wheel.filename

        # Save to cache (requires SHA256 of the wheel for the cache key)
        if wheel.hash is not None:
            self._cache.save_metadata(
                registry=self.registry,
                name=package,
                version=version,
                sha256=wheel.hash.sha256,
                sha256_source=wheel.hash.source,
                download_url=wheel.url,
                size_bytes=wheel.size,
                metadata=metadata,
                deps_known=True,
                filename=wheel.filename,
            )

        return metadata

    # ------------------------------------------------------------------
    # Private helpers — sdist extraction
    # ------------------------------------------------------------------

    async def _try_sdist(
        self,
        files: list[FileInfo],
        package: str,
        version: str,
    ) -> PackageMetadata | None:
        """Download sdist to cache, extract PKG-INFO, save metadata.

        Always save metadata to cache — even when `Requires-Dist` is
        Dynamic (`deps_known=FALSE`).  Non-Dynamic fields (License,
        Summary, Author) are usually valid and worth preserving.

        Return the metadata (possibly with `dependencies=None` for
        Dynamic `Requires-Dist`).  The caller checks
        `metadata.dependencies is not None` to decide whether to
        fall through to wheel extraction.
        """
        sdist = select_sdist(files)
        if sdist is None:
            logger.debug("No sdist for %s==%s", package, version)
            return None

        # Download to temp, extract metadata, then store archive + metadata
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp) / sanitize_filename(sdist.filename)
            try:
                _limit = get_settings().extraction.max_size_mb * 1024 * 1024
                await self._backend.download(
                    sdist,
                    tmp_path,
                    max_download_bytes=_limit,
                )
            except Exception:
                logger.debug(
                    "Failed to download sdist %s",
                    sdist.filename,
                    exc_info=True,
                )
                return None

            # Extract metadata before storing (need local file)
            metadata = extract_sdist_metadata(tmp_path)

            # Read archive bytes for cache storage
            archive_data = tmp_path.read_bytes()

        # Set source_filename on metadata
        if metadata is not None:
            metadata.source_filename = sdist.filename

        deps_known = metadata is not None and metadata.dependencies is not None

        # Store archive + metadata in cache (unconditionally)
        try:
            self._cache.store_archive(
                registry=self.registry,
                name=package,
                version=version,
                archive_data=archive_data,
                filename=sdist.filename,
                expected_sha256=sdist.hash.sha256 if sdist.hash else None,
                sha256_source=sdist.hash.source if sdist.hash else "computed",
                download_url=sdist.url,
                metadata=metadata,
                deps_known=deps_known,
            )
        except HashMismatchError:
            logger.warning(
                "SHA-256 mismatch storing sdist %s",
                sdist.filename,
            )
            return None

        return metadata

    # ------------------------------------------------------------------
    # Private helpers — wheel extraction
    # ------------------------------------------------------------------

    async def _try_wheel(
        self,
        files: list[FileInfo],
        package: str,
        version: str,
    ) -> PackageMetadata | None:
        """Download wheel to temp, extract METADATA, save metadata, delete.

        Wheels are NOT cached as archives for file inspection (only the
        metadata is cached).  The archive is downloaded to a temporary
        directory, metadata is extracted, and the temp file is deleted.
        """
        wheel = select_wheel(files)
        if wheel is None:
            logger.debug("No wheel for %s==%s", package, version)
            return None

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp) / sanitize_filename(wheel.filename)
            try:
                _limit = get_settings().extraction.max_size_mb * 1024 * 1024
                result = await self._backend.download(
                    wheel,
                    tmp_path,
                    max_download_bytes=_limit,
                )
            except Exception:
                logger.debug(
                    "Failed to download wheel %s",
                    wheel.filename,
                    exc_info=True,
                )
                return None

            metadata = extract_wheel_metadata(tmp_path)

        if metadata is None:
            return None

        metadata.source_filename = wheel.filename

        # Save metadata to cache (no archive_path — wheel is temp-only)
        self._cache.save_metadata(
            registry=self.registry,
            name=package,
            version=version,
            sha256=result.hash.sha256,
            sha256_source=result.hash.source,
            download_url=wheel.url,
            size_bytes=result.size_bytes,
            metadata=metadata,
            deps_known=True,
            filename=wheel.filename,
        )

        return metadata

    # ------------------------------------------------------------------
    # Private helpers — tag-specific metadata
    # ------------------------------------------------------------------

    async def _get_metadata_for_tag(  # noqa: C901, PLR0912
        self,
        package: str,
        version: str,
        tag: str,
    ) -> PackageMetadata | None:
        """Get metadata from a specific wheel variant identified by *tag*.

        Require the exact full 3-part tag
        (`{python}-{abi}-{platform}`).  On mismatch, raise
        `TagNotFoundError` listing available tags.
        """
        try:
            files = await self._backend.files(package, version)
        except Exception:
            logger.debug(
                "Failed to list files for %s==%s (tag %s)",
                package,
                version,
                tag,
                exc_info=True,
            )
            return None

        # Find matching wheel
        wheel = None
        available_tags: list[str] = []
        for f in files:
            if f.dist_type != DistType.WHEEL or f.yanked:
                continue
            file_tag = _extract_wheel_tag(f.filename)
            if file_tag is not None:
                available_tags.append(file_tag)
                if file_tag == tag:
                    wheel = f

        if wheel is None:
            msg = f"No wheel matching tag {tag!r} for {package}=={version}"
            raise TagNotFoundError(msg, available_tags)

        # Try PEP 658 (https://peps.python.org/pep-0658/) for this wheel
        if wheel.metadata_available:
            metadata_url = f"{wheel.url}.metadata"
            try:
                response = await self._backend.get_with_retry(metadata_url)
                if response.is_success:
                    # Verify hash (if provided by registry)
                    if wheel.metadata_hash is not None:
                        computed = hashlib.sha256(response.content).hexdigest()
                        if computed != wheel.metadata_hash.sha256:
                            logger.warning(
                                "PEP 658 metadata hash mismatch for %s "
                                "(tag %s): expected %s, got %s",
                                wheel.filename,
                                tag,
                                wheel.metadata_hash.sha256,
                                computed,
                            )
                            # Fall through to wheel download
                            raise _Pep658HashMismatchError

                    metadata = parse_email_metadata(
                        response.text,
                        source="pep658",
                    )
                    metadata.source_filename = wheel.filename
                    if wheel.hash is not None:
                        self._cache.save_metadata(
                            registry=self.registry,
                            name=package,
                            version=version,
                            sha256=wheel.hash.sha256,
                            sha256_source=wheel.hash.source,
                            download_url=wheel.url,
                            size_bytes=wheel.size,
                            metadata=metadata,
                            deps_known=True,
                            filename=wheel.filename,
                        )
                    return metadata
            except _Pep658HashMismatchError:
                pass  # Fall through to wheel download below
            except Exception:
                logger.debug(
                    "PEP 658 fetch failed for %s (tag %s), falling back to download",
                    wheel.filename,
                    tag,
                    exc_info=True,
                )

        # Download and extract from the wheel directly
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp) / sanitize_filename(wheel.filename)
            try:
                _limit = get_settings().extraction.max_size_mb * 1024 * 1024
                result = await self._backend.download(
                    wheel,
                    tmp_path,
                    max_download_bytes=_limit,
                )
            except Exception:
                logger.debug(
                    "Failed to download wheel %s",
                    wheel.filename,
                    exc_info=True,
                )
                return None

            metadata = extract_wheel_metadata(tmp_path)

        if metadata is None:
            return None

        metadata.source_filename = wheel.filename

        self._cache.save_metadata(
            registry=self.registry,
            name=package,
            version=version,
            sha256=result.hash.sha256,
            sha256_source=result.hash.source,
            download_url=wheel.url,
            size_bytes=result.size_bytes,
            metadata=metadata,
            deps_known=True,
            filename=wheel.filename,
        )
        return metadata

    # ------------------------------------------------------------------
    # Private helpers — artifact caching for file inspection
    # ------------------------------------------------------------------

    async def _ensure_artifact_cached(
        self,
        package: str,
        version: str,
    ) -> Path:
        """Ensure an artifact is downloaded and cached.

        Sdist preferred for file inspection (contains source, configs,
        license, tests, README, etc.).  Falls back to wheel when no
        sdist is published.

        Returns the absolute path to the cached archive.

        Raises
        ------
        ArtifactNotAvailableError
            If no downloadable artifact is available.
        """
        # Check cache first
        cached = self._cache.get_archive_path(
            self.registry,
            package,
            version,
        )
        if cached is not None:
            return cached

        # Get file list
        files = await self._backend.files(package, version)

        # Try sdist first (preferred for file inspection)
        sdist = select_sdist(files)
        if sdist is not None:
            path = await self._download_and_store(sdist, package, version)
            if path is not None:
                return path

        # Fall back to wheel
        wheel = select_wheel(files)
        if wheel is not None:
            path = await self._download_and_store(wheel, package, version)
            if path is not None:
                return path

        msg = f"No distribution file found for {package}=={version}"
        raise ArtifactNotAvailableError(msg)

    async def _download_and_store(
        self,
        file: FileInfo,
        package: str,
        version: str,
    ) -> Path | None:
        """Download a file and store it in the cache.

        Return the absolute path to the cached archive, or `None` on
        failure.
        """
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp) / sanitize_filename(file.filename)
            try:
                _limit = get_settings().extraction.max_size_mb * 1024 * 1024
                await self._backend.download(
                    file,
                    tmp_path,
                    max_download_bytes=_limit,
                )
            except Exception:
                logger.debug(
                    "Failed to download %s",
                    file.filename,
                    exc_info=True,
                )
                return None

            archive_data = tmp_path.read_bytes()

        try:
            store_result = self._cache.store_archive(
                registry=self.registry,
                name=package,
                version=version,
                archive_data=archive_data,
                filename=file.filename,
                expected_sha256=file.hash.sha256 if file.hash else None,
                sha256_source=file.hash.source if file.hash else "computed",
                download_url=file.url,
            )
        except HashMismatchError:
            logger.warning(
                "SHA-256 mismatch storing %s",
                file.filename,
            )
            return None

        return self._cache.cache_dir / store_result.archive_path


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------


def _select_best_wheel(candidates: list[FileInfo]) -> FileInfo:
    """Select the best wheel from a pre-filtered candidate list.

    Prefer pure-Python (`py3-none-any`) wheels, then the smallest.
    The caller must ensure *candidates* is non-empty.
    """
    for c in candidates:
        if is_pure_python_wheel(c.filename):
            return c

    return min(
        candidates,
        key=lambda f: f.size if f.size is not None else float("inf"),
    )


def _extract_wheel_tag(filename: str) -> str | None:
    """Extract the 3-part tag from a wheel filename.

    Wheel filename format:

        {name}-{version}(-{build})?-{python}-{abi}-{platform}.whl

    Return `"{python}-{abi}-{platform}"` or `None` if unparseable.
    """
    if not filename.endswith(".whl"):
        return None

    stem = filename[:-4]  # strip ".whl"
    parts = stem.split("-")

    # Minimum parts: name-version-python-abi-platform (5)
    # With build tag: name-version-build-python-abi-platform (6)
    if len(parts) < 5:  # noqa: PLR2004
        return None

    # Last 3 parts are always python-abi-platform
    return f"{parts[-3]}-{parts[-2]}-{parts[-1]}"


def _build_why_paths(
    raw_paths: list[list[str]],
    version_lookup: dict[str, str],
    specifier_cache: dict[tuple[str, str], str | None],
    *,
    all_hops: bool = False,
) -> list[WhyPath]:
    """Convert raw name-only paths into `WhyPath` objects with hops.

    Each hop gets a version from *version_lookup* and a requirement
    specifier from *specifier_cache* when applicable.
    """
    from peeq.resolver.models import PathHop, WhyPath  # noqa: PLC0415

    why_paths: list[WhyPath] = []
    for path in raw_paths:
        hops: list[PathHop] = []
        for i, name in enumerate(path):
            version = version_lookup.get(name, "")
            requirement: str | None = None
            if i < len(path) - 1:
                next_name = path[i + 1]
                should_enrich = all_hops or (i == len(path) - 2)
                if should_enrich:
                    requirement = specifier_cache.get((name, next_name))
            hops.append(PathHop(package=name, version=version, requirement=requirement))
        why_paths.append(WhyPath(hops=hops))
    return why_paths


def find_paths(
    result: SolverResult,
    target: str,
    roots: set[str],
    *,
    max_paths: int = 20,
) -> list[list[str]]:
    """Find all paths from root requirements to target package via BFS.

    Build a reverse adjacency map (child -> parents) from the resolved
    graph and BFS backward from the target.  When a path reaches a
    root, reverse it and collect.

    Args:
        result: Successful solver result with resolved dependency graph.
        target: Canonical name of the target package.
        roots: Set of canonical root requirement names.
        max_paths: Maximum number of paths to return.

    Returns:
        List of paths, each a list of canonical package names
        ordered root -> ... -> target.
    """
    from collections import deque  # noqa: PLC0415

    # Build reverse adjacency: child -> set of parents
    reverse: dict[str, set[str]] = {}
    for dep in result.resolved:
        for child in dep.dependencies:
            if child not in reverse:
                reverse[child] = set()
            reverse[child].add(dep.name)

    # BFS backward from target, tracking full paths
    paths: list[list[str]] = []
    queue: deque[list[str]] = deque([[target]])

    while queue and len(paths) < max_paths:
        current_path = queue.popleft()
        head = current_path[-1]

        if head in roots:
            paths.append(list(reversed(current_path)))
            continue

        for parent in sorted(reverse.get(head, set())):
            if parent not in current_path:  # cycle protection
                queue.append([*current_path, parent])

    return paths
