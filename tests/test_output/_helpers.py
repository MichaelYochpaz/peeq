"""Shared test helpers for output renderer tests.

Provides factory functions that create model instances with sensible
defaults.  Individual test modules import the helpers they need::

    from tests.test_output._helpers import _pkg_info, _metadata, _dep
"""

from __future__ import annotations

import json
from io import StringIO
from pathlib import Path
from typing import Any

from packaging.version import Version

from peeq.extraction import ArchiveMember
from peeq.models import (
    CacheStats,
    DepChange,
    Dependency,
    DepsDiff,
    DistType,
    FileInfo,
    InfoReport,
    PackageInfo,
    PackageMetadata,
    VulnerabilityInfo,
    VulnerabilityReport,
)
from peeq.output.agent import AgentRenderer
from peeq.output.base import LsEntry
from peeq.output.json import JSONRenderer
from peeq.output.plain import PlainRenderer
from peeq.output.rich import RichRenderer
from peeq.resolver.models import (
    ConflictInfo,
    ConflictRequirement,
    ResolvedDependency,
    SolverResult,
)


def _pkg_info(**kw: object) -> PackageInfo:
    """Create a `PackageInfo` with sensible defaults."""
    defaults: dict[str, object] = {
        "name": "requests",
        "latest_version": "2.31.0",
        "version_count": 142,
        "summary": "HTTP for Humans",
        "registry": "pypi.org",
    }
    defaults.update(kw)
    return PackageInfo(**defaults)  # ty: ignore[invalid-argument-type]


def _info_report(**kw: object) -> InfoReport:
    """Build a minimal InfoReport for testing."""
    return InfoReport(info=_pkg_info(**kw))


def _metadata(**kw: object) -> PackageMetadata:
    """Create a `PackageMetadata` with sensible defaults."""
    m = PackageMetadata()
    for key, val in kw.items():
        setattr(m, key, val)
    return m


def _dep(
    name: str = "requests",
    specifier: str = ">=2.0",
    *,
    extras: list[str] | None = None,
    markers: str | None = None,
    raw: str = "",
) -> Dependency:
    """Create a `Dependency` with sensible defaults."""
    return Dependency(
        name=name,
        specifier=specifier,
        extras=extras or [],
        markers=markers,
        raw=raw or f"{name}{specifier}",
    )


def _file_info(**kw: object) -> FileInfo:
    """Create a `FileInfo` with sensible defaults."""
    defaults: dict[str, object] = {
        "filename": "requests-2.31.0.tar.gz",
        "url": "https://files.pythonhosted.org/requests-2.31.0.tar.gz",
        "dist_type": DistType.SDIST,
        "size": 110_000,
        "requires_python": ">=3.7",
    }
    defaults.update(kw)
    return FileInfo(**defaults)  # ty: ignore[invalid-argument-type]


def _cache_stats(**kw: object) -> CacheStats:
    """Create a `CacheStats` with sensible defaults."""
    defaults: dict[str, object] = {
        "location": Path("/home/user/.cache/peeq"),
        "package_count": 15,
        "distribution_count": 23,
        "total_size_bytes": 45_200_000,
        "archived_count": 20,
        "metadata_only_count": 3,
    }
    defaults.update(kw)
    return CacheStats(**defaults)  # ty: ignore[invalid-argument-type]


def _solver_result(**kw: object) -> SolverResult:
    """Create a `SolverResult` with sensible defaults."""
    defaults: dict[str, object] = {
        "resolved": [
            ResolvedDependency(name="flask", version=Version("3.0.0")),
            ResolvedDependency(name="werkzeug", version=Version("3.0.1")),
        ],
        "solver_id": "uv",
    }
    defaults.update(kw)
    return SolverResult(**defaults)


def _conflict(**kw: object) -> ConflictInfo:
    """Create a `ConflictInfo` with sensible defaults."""
    defaults: dict[str, object] = {
        "package": "numpy",
        "requirements": [
            ConflictRequirement(
                package="tensorflow",
                version="2.15.0",
                dependency="numpy>=1.23,<1.27",
            ),
            ConflictRequirement(
                package="torch",
                version="2.0.0",
                dependency="numpy>=1.21",
            ),
        ],
        "message": "No compatible version found.",
    }
    defaults.update(kw)
    return ConflictInfo(**defaults)  # ty: ignore[invalid-argument-type]


def _vuln(
    *,
    vuln_id: str = "GHSA-test-1234",
    summary: str = "Test vulnerability",
    aliases: list[str] | None = None,
    severity_label: str | None = None,
    fixed_versions: list[str] | None = None,
) -> VulnerabilityInfo:
    """Create a `VulnerabilityInfo` with sensible defaults."""
    return VulnerabilityInfo(
        id=vuln_id,
        summary=summary,
        aliases=aliases or [],
        severity_label=severity_label,
        fixed_versions=fixed_versions or [],
    )


def _report(
    *,
    package: str = "requests",
    version: str = "2.25.0",
    vulns: list[VulnerabilityInfo] | None = None,
) -> VulnerabilityReport:
    """Create a `VulnerabilityReport` with sensible defaults."""
    return VulnerabilityReport(
        package=package,
        version=version,
        vulnerabilities=vulns or [],
    )


def _dep_change(**kw: object) -> DepChange:
    """Create a `DepChange` with sensible defaults."""
    defaults: dict[str, object] = {
        "name": "urllib3",
        "old_specifier": ">=1.21",
        "new_specifier": ">=2.0",
    }
    defaults.update(kw)
    return DepChange(**defaults)  # ty: ignore[invalid-argument-type]


def _deps_diff(**kw: object) -> DepsDiff:
    """Create a `DepsDiff` with sensible defaults."""
    defaults: dict[str, object] = {}
    defaults.update(kw)
    return DepsDiff(**defaults)  # ty: ignore[invalid-argument-type]


# ---------------------------------------------------------------------------
# Renderer factories
# ---------------------------------------------------------------------------


def _plain_renderer() -> tuple[PlainRenderer, StringIO]:
    """Create a `PlainRenderer` writing to a `StringIO` stream."""
    stream = StringIO()
    return PlainRenderer(stream=stream), stream


def _json_renderer() -> tuple[JSONRenderer, StringIO]:
    """Create a `JSONRenderer` writing to a `StringIO` stream."""
    stream = StringIO()
    return JSONRenderer(stream=stream), stream


def _json_parse(stream: StringIO) -> dict[str, Any]:
    """Parse the stream content as a single JSON document."""
    return json.loads(stream.getvalue())


def _agent_renderer() -> tuple[AgentRenderer, StringIO]:
    """Create an `AgentRenderer` writing to a `StringIO` stream."""
    stream = StringIO()
    return AgentRenderer(stream=stream), stream


def _rich_renderer() -> tuple[RichRenderer, StringIO]:
    """Create a `RichRenderer` writing to a `StringIO` stream.

    Uses `force_terminal=False` implicitly (`StringIO` is not a TTY)
    so Rich skips ANSI escape codes, making output easy to assert on.
    """
    stream = StringIO()
    return RichRenderer(stream=stream), stream


# ---------------------------------------------------------------------------
# Archive / listing factories
# ---------------------------------------------------------------------------


def _archive_member(
    path: str = "test.py",
    size: int = 42,
    is_dir: bool = False,
) -> ArchiveMember:
    """Create an `ArchiveMember` with sensible defaults."""
    return ArchiveMember(path=path, size=size, is_dir=is_dir)


def _ls_entry(  # noqa: PLR0913
    path: str = "test.py",
    is_dir: bool = False,
    size: int = 42,
    file_count: int = 0,
    subdir_count: int = 0,
    total_size: int = 0,
) -> LsEntry:
    """Create an `LsEntry` with sensible defaults."""
    return LsEntry(
        path=path,
        is_dir=is_dir,
        size=size,
        file_count=file_count,
        subdir_count=subdir_count,
        total_size=total_size,
    )
