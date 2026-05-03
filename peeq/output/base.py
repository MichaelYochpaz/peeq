"""Abstract base class for output renderers and format dispatch.

Defines `Renderer` with abstract methods for each CLI command
output, `OutputFormat` for format selection, and
`get_renderer` for constructing the appropriate renderer based
on format and TTY detection.
"""

from __future__ import annotations

import enum
import sys
from abc import ABC, abstractmethod
from collections import defaultdict
from dataclasses import dataclass
from typing import TYPE_CHECKING

from packaging.specifiers import InvalidSpecifier, Specifier, SpecifierSet
from packaging.version import InvalidVersion, Version

from peeq.globmatch import glob_match_any

if TYPE_CHECKING:
    from pathlib import Path
    from typing import Any, TextIO

    from peeq.extraction import ArchiveMember
    from peeq.models import (
        CacheStats,
        DepsDiff,
        FileInfo,
        InfoReport,
        PackageMetadata,
        VersionInfo,
        VulnerabilityInfo,
        VulnerabilityReport,
    )
    from peeq.resolver.models import ConflictInfo, SolverResult, WhyResult


# ---------------------------------------------------------------------------
# Output format enum
# ---------------------------------------------------------------------------


class OutputFormat(enum.Enum):
    """Output format for CLI commands.

    `PRETTY` and `PLAIN` are auto-detected based on TTY status when
    no explicit `--format` flag is given.  `AGENT` and `JSON` must
    always be requested explicitly.
    """

    PRETTY = "pretty"
    PLAIN = "plain"
    AGENT = "agent"
    JSON = "json"


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

_KIB = 1024
"""Kibibyte constant for size formatting."""


def format_size(size_bytes: int) -> str:
    """Format a byte count as a human-readable size string."""
    if size_bytes < _KIB:
        return f"{size_bytes} B"
    if size_bytes < _KIB**2:
        return f"{size_bytes / _KIB:.1f} KB"
    if size_bytes < _KIB**3:
        return f"{size_bytes / _KIB**2:.1f} MB"
    return f"{size_bytes / _KIB**3:.1f} GB"


def try_decode(content: bytes) -> str | None:
    """Try to decode bytes as UTF-8 text.

    Return the decoded string, or `None` if the content is binary.
    """
    try:
        return content.decode("utf-8")
    except (UnicodeDecodeError, ValueError):
        return None


def truncate_utf8(data: bytes, max_bytes: int) -> bytes:
    """Truncate bytes to at most *max_bytes* on a valid UTF-8 boundary.

    Back up 0-3 bytes from the cut point to avoid splitting a
    multi-byte UTF-8 codepoint.  If even backing up to offset 0
    fails, return `b""`.
    """
    if len(data) <= max_bytes:
        return data
    for offset in range(4):
        end = max_bytes - offset
        if end <= 0:
            return b""
        candidate = data[:end]
        try:
            candidate.decode("utf-8")
            return candidate
        except UnicodeDecodeError:
            continue
    return b""


@dataclass(frozen=True)
class VulnerabilityRecommendation:
    """Upgrade guidance derived from vulnerability fixed versions."""

    version: str
    """Highest known fixed version across reported vulnerabilities."""

    unresolved_count: int
    """Number of advisories that do not list a fixed version."""


def _version_sort_key(version: str) -> tuple[int, Version, str]:
    """Return a stable sort key that prefers valid PEP 440 versions."""
    try:
        return (1, Version(version), version)
    except InvalidVersion:
        return (0, Version("0"), version)


def build_vulnerability_recommendation(
    vulnerabilities: list[VulnerabilityInfo],
) -> VulnerabilityRecommendation | None:
    """Build upgrade guidance from known vulnerability fixed versions."""
    fixed_versions = {v for vuln in vulnerabilities for v in vuln.fixed_versions}
    if not fixed_versions:
        return None

    version = max(fixed_versions, key=_version_sort_key)
    unresolved_count = sum(1 for vuln in vulnerabilities if not vuln.fixed_versions)
    return VulnerabilityRecommendation(
        version=version, unresolved_count=unresolved_count
    )


def format_unfixed_vulnerability_note(unresolved_count: int) -> str:
    """Format a note for advisories that do not list a fixed version."""
    advisory = "advisory" if unresolved_count == 1 else "advisories"
    verb = "has" if unresolved_count == 1 else "have"
    return f"{unresolved_count} {advisory} {verb} no fixed version listed."


# Operator sort key: lower-bound operators first, then exclusions, then
# upper-bound operators.  Within each group, order is stable.
_OPERATOR_ORDER: dict[str, int] = {
    ">=": 0,
    ">": 1,
    "==": 2,
    "~=": 3,
    "===": 4,
    "!=": 5,
    "<": 6,
    "<=": 7,
}


def _specifier_sort_key(spec: Specifier) -> tuple[int, str]:
    return (_OPERATOR_ORDER.get(spec.operator, 99), str(spec))


def normalize_specifier_order(raw: str) -> str:
    """Reorder a PEP 440 specifier string so lower bounds come first.

    Returns the original string unchanged if parsing fails.
    """
    try:
        specs = list(SpecifierSet(raw))
    except InvalidSpecifier:
        return raw

    if len(specs) <= 1:
        return raw

    return ",".join(str(s) for s in sorted(specs, key=_specifier_sort_key))


# ---------------------------------------------------------------------------
# Directory listing model
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class LsEntry:
    """Entry in a directory listing (file or synthesized directory).

    Created by `build_ls_entries` from raw `ArchiveMember` data.
    Directories carry aggregate metadata; files carry their own size.
    """

    path: str
    """Relative path within the archive (trailing `/` for dirs)."""

    is_dir: bool
    """Whether this entry represents a directory."""

    size: int
    """File size in bytes (`0` for directories)."""

    file_count: int
    """Recursive total file count under a directory (`0` for files)."""

    subdir_count: int
    """Immediate child directory count (`0` for files)."""

    total_size: int
    """Recursive total bytes under a directory (`0` for files)."""


def has_prefix(members: list[ArchiveMember], prefix: str) -> bool:
    """Check whether *prefix* matches a directory in the archive.

    Returns `True` if any archive member is at or below *prefix*.
    Normalises the same way `build_ls_entries` does: `"src"`
    and `"src/"` are equivalent; matching is on directory boundaries.
    """
    stripped = prefix.strip("/")
    if not stripped:
        return True  # root always exists
    norm = stripped + "/"
    return any(
        (m.path == stripped and m.is_dir)
        or m.path.startswith(norm)
        or (m.is_dir and (m.path.rstrip("/") + "/") == norm)
        for m in members
    )


def _build_recursive_entries(
    members: list[ArchiveMember],
    norm_prefix: str,
    glob_patterns: list[str] | None,
) -> list[LsEntry]:
    """Build flat file entries for recursive mode, with optional glob filter."""
    result: list[LsEntry] = []
    for m in members:
        if m.is_dir:
            continue
        if norm_prefix and not m.path.startswith(norm_prefix):
            continue
        if glob_patterns:
            # Match against prefix-relative path (--prefix is "cd").
            rel = m.path[len(norm_prefix) :] if norm_prefix else m.path
            if not glob_match_any(rel, glob_patterns):
                continue
        result.append(
            LsEntry(
                path=m.path,
                is_dir=False,
                size=m.size,
                file_count=0,
                subdir_count=0,
                total_size=0,
            )
        )
    return result


def build_ls_entries(
    members: list[ArchiveMember],
    *,
    prefix: str | None = None,
    recursive: bool = False,
    glob_patterns: list[str] | None = None,
) -> list[LsEntry]:
    """Build a listing from raw archive members.

    Infer directories from file paths (some archives omit explicit
    directory entries), compute per-directory metadata, and return
    entries for one directory level (or all files in recursive mode).

    The algorithm is O(N) — a single pass over *members* with
    dict-based accumulators.

    Args:
        members: Raw archive members from extraction.
        prefix: Show entries under this path.  `"src"` and
            `"src/"` are equivalent.  Matches on directory
            boundaries (`"src"` does not match `"src_old/"`).
        recursive: When `True`, return a flat list of files
            (no directory entries), optionally filtered by *prefix*.
        glob_patterns: When set, filter entries to those matching
            any of the given glob patterns (OR semantics).  Matching
            is against the prefix-relative path.

    Returns:
        Sorted list of entries: directories first, then files,
        alphabetical within each group.  Empty list when *prefix*
        matches nothing.

    Raises:
        ValueError: If *glob_patterns* is set but *recursive* is
            `False` (glob filtering requires recursive mode).
    """
    if glob_patterns and not recursive:
        raise ValueError("glob_patterns requires recursive=True")

    # Normalise prefix: None / "" → root, "src" → "src/"
    norm_prefix = ""
    if prefix is not None:
        stripped = prefix.strip("/")
        if stripped:
            norm_prefix = stripped + "/"

    # -- Phase 1: accumulate per-directory stats (single pass) ------
    # Keyed by dir path like "a/b/".  Root scope is "".
    dir_files: dict[str, int] = defaultdict(int)
    dir_size: dict[str, int] = defaultdict(int)
    dir_subdirs: dict[str, set[str]] = defaultdict(set)
    known_dirs: set[str] = set()
    scope_files: dict[str, list[tuple[str, int]]] = defaultdict(list)

    for member in members:
        if member.is_dir:
            d = member.path if member.path.endswith("/") else member.path + "/"
            known_dirs.add(d)
            # Register in parent chain
            parts = d.rstrip("/").split("/")
            for i in range(len(parts)):
                dir_at_i = "/".join(parts[: i + 1]) + "/"
                known_dirs.add(dir_at_i)
                parent = "/".join(parts[:i]) + "/" if i > 0 else ""
                dir_subdirs[parent].add(dir_at_i)
            continue

        # Regular file
        path_parts = member.path.split("/")

        if len(path_parts) == 1:
            # File at root level — no parent directory
            scope_files[""].append((member.path, member.size))
            continue

        # Infer parent directories and accumulate stats
        parents: list[str] = []
        for i in range(1, len(path_parts)):
            parent_dir = "/".join(path_parts[:i]) + "/"
            parents.append(parent_dir)
            known_dirs.add(parent_dir)
            dir_files[parent_dir] += 1
            dir_size[parent_dir] += member.size

        # Register immediate-subdir relationships
        dir_subdirs[""].add(parents[0])
        for i in range(1, len(parents)):
            dir_subdirs[parents[i - 1]].add(parents[i])

        # Track as direct file in its immediate parent
        scope_files[parents[-1]].append((member.path, member.size))

    # -- Phase 2: prefix validation --------------------------------
    if norm_prefix and norm_prefix not in known_dirs:
        return []

    # -- Phase 3: build output entries -----------------------------
    if recursive:
        result = _build_recursive_entries(members, norm_prefix, glob_patterns)
        result.sort(key=lambda e: e.path)
        return result

    # Non-recursive: one level at the prefix scope
    entries: list[LsEntry] = [
        LsEntry(
            path=child_dir,
            is_dir=True,
            size=0,
            file_count=dir_files.get(child_dir, 0),
            subdir_count=len(dir_subdirs.get(child_dir, set())),
            total_size=dir_size.get(child_dir, 0),
        )
        for child_dir in dir_subdirs.get(norm_prefix, set())
    ]

    entries.extend(
        LsEntry(
            path=file_path,
            is_dir=False,
            size=file_size,
            file_count=0,
            subdir_count=0,
            total_size=0,
        )
        for file_path, file_size in scope_files.get(norm_prefix, [])
    )

    # Directories first, then files, alphabetical within each group
    entries.sort(key=lambda e: (not e.is_dir, e.path))
    return entries


# ---------------------------------------------------------------------------
# Abstract renderer
# ---------------------------------------------------------------------------


class Renderer(ABC):
    """Abstract base for output renderers.

    Each method corresponds to a CLI command's output.  CLI commands call
    the service layer, receive Pydantic models, and pass them to the
    renderer for formatting.  Renderers write directly to their output
    stream.
    """

    @abstractmethod
    def render_info(self, report: InfoReport) -> None:
        """Render package info report with optional sections."""
        ...

    @abstractmethod
    def render_versions(
        self,
        name: str,
        versions: list[VersionInfo],
        total: int,
        *,
        matching: str | None = None,
        original_total: int | None = None,
    ) -> None:
        """Render a version list (possibly limited by `--limit`)."""
        ...

    @abstractmethod
    def render_deps(
        self,
        name: str,
        version: str,
        metadata: PackageMetadata,
        *,
        tag: str | None = None,
    ) -> None:
        """Render package dependencies, grouped by extras."""
        ...

    @abstractmethod
    def render_deps_diff(
        self,
        name: str,
        from_version: str,
        to_version: str,
        diff: DepsDiff,
        *,
        tag: str | None = None,
    ) -> None:
        """Render dependency differences between two versions."""
        ...

    @abstractmethod
    def render_artifacts(
        self,
        name: str,
        version: str,
        files: list[FileInfo],
    ) -> None:
        """Render available distribution files for a version."""
        ...

    @abstractmethod
    def render_ls(  # noqa: PLR0913
        self,
        name: str,
        version: str,
        entries: list[LsEntry],
        total: int,
        *,
        prefix: str | None = None,
        recursive: bool = False,
        glob_patterns: list[str] | None = None,
    ) -> None:
        """Render archive directory listing or recursive file listing."""
        ...

    @abstractmethod
    def render_file_content(  # noqa: PLR0913
        self,
        name: str,
        version: str,
        path: str,
        content: bytes,
        *,
        truncated: bool = False,
        total_size: int | None = None,
    ) -> None:
        """Render the contents of a file extracted from an archive."""
        ...

    @abstractmethod
    def render_download(self, path: Path, *, extracted: bool = False) -> None:
        """Render download completion confirmation."""
        ...

    @abstractmethod
    def render_cache_info(self, stats: CacheStats) -> None:
        """Render cache statistics."""
        ...

    @abstractmethod
    def render_cache_clear(self, count: int, total_size_bytes: int) -> None:
        """Render cache clear results."""
        ...

    @abstractmethod
    def render_cache_dump(self, data: dict[str, Any]) -> None:
        """Render full cache dump (JSON export)."""
        ...

    @abstractmethod
    def render_cache_check(self, diagnostics: dict[str, Any]) -> None:
        """Render cache diagnostic results."""
        ...

    @abstractmethod
    def render_resolve(self, result: SolverResult) -> None:
        """Render dependency resolution results."""
        ...

    @abstractmethod
    def render_conflicts(
        self,
        conflicts: list[ConflictInfo],
        *,
        header: str | None = None,
    ) -> None:
        """Render dependency conflict details."""
        ...

    @abstractmethod
    def render_why(
        self,
        result: WhyResult,
    ) -> None:
        """Render dependency path trace results."""
        ...

    @abstractmethod
    def render_why_failed(
        self,
        target: str,
        conflicts: list[ConflictInfo],
    ) -> None:
        """Render why-command failure with embedded conflict details."""
        ...

    @abstractmethod
    def render_vulns(self, report: VulnerabilityReport) -> None:
        """Render vulnerability check results."""
        ...

    @abstractmethod
    def render_error(self, message: str) -> None:
        """Render an error message."""
        ...

    @abstractmethod
    def render_not_found(self, name: str) -> None:
        """Render a 'package not found' message."""
        ...


# ---------------------------------------------------------------------------
# Renderer dispatch
# ---------------------------------------------------------------------------


def get_renderer(
    fmt: OutputFormat | None = None,
    *,
    stream: TextIO | None = None,
) -> Renderer:
    """Create a renderer for the specified output format.

    When *fmt* is `None`, auto-detect based on TTY status:
    `pretty` when stdout is a TTY, `plain` when piped.

    Parameters
    ----------
    fmt:
        Output format.  `None` for auto-detection.
    stream:
        Output stream.  Defaults to `sys.stdout`.
    """
    if fmt is None:
        out = stream or sys.stdout
        fmt = OutputFormat.PRETTY if out.isatty() else OutputFormat.PLAIN

    if fmt is OutputFormat.PRETTY:
        from peeq.output.rich import RichRenderer  # noqa: PLC0415

        return RichRenderer(stream=stream)

    if fmt is OutputFormat.PLAIN:
        from peeq.output.plain import PlainRenderer  # noqa: PLC0415

        return PlainRenderer(stream=stream)

    if fmt is OutputFormat.AGENT:
        from peeq.output.agent import AgentRenderer  # noqa: PLC0415

        return AgentRenderer(stream=stream)

    from peeq.output.json import JSONRenderer  # noqa: PLC0415

    return JSONRenderer(stream=stream)
