"""Plain text renderer for non-interactive output.

Provides `PlainRenderer` for clean, undecorated text output
suitable for CI pipelines, log files, piped commands, and redirected
output.  No ANSI escape codes, no XML tags, no Rich formatting ---
just readable text that works everywhere.

Auto-selected when stdout is not a TTY (e.g. piped or redirected).
"""

from __future__ import annotations

import json
import sys
from typing import TYPE_CHECKING

from peeq import APP_NAME
from peeq.output.base import (
    LsEntry,
    Renderer,
    build_vulnerability_recommendation,
    format_size,
    format_unfixed_vulnerability_note,
    try_decode,
)
from peeq.sanitize import strip_control_chars
from peeq.utils import group_dependencies

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path
    from typing import Any, TextIO

    from peeq.models import (
        CacheStats,
        DepsDiff,
        FileInfo,
        InfoReport,
        PackageMetadata,
        VersionInfo,
        VulnerabilityReport,
    )
    from peeq.resolver.models import ConflictInfo, SolverResult, WhyPath, WhyResult


# ---------------------------------------------------------------------------
# Why path formatting helper (plain renderer only)
# ---------------------------------------------------------------------------


def _write_why_path(
    writeln: Callable[[str], None],
    path: WhyPath,
    *,
    multiple: bool = False,
) -> None:
    """Write a single dependency path as a tree with box-drawing guides.

    Each node shows `package version`, with the incoming version
    specifier (from the parent hop) appended in parentheses when
    present.  Paths are linear chains so every child uses `└──`.

    Args:
        writeln: Callable that writes a line with trailing newline.
        path: A single `WhyPath` to render.
        multiple: Use extra base indentation for numbered multi-path
            output.
    """
    hops = path.hops
    base = "    " if multiple else "  "

    # Root — no guide prefix
    writeln(f"{base}{hops[0].package} {hops[0].version}")

    # Remaining hops (intermediate + target)
    for j in range(1, len(hops)):
        guide = "    " * (j - 1) + "└── "
        hop = hops[j]
        label = f"{hop.package} {hop.version}"
        prev_req = hops[j - 1].requirement
        if prev_req:
            label += f" ({prev_req})"
        writeln(f"{base}{guide}{label}")


def _plain_range_label(showing: int, total: int, offset: int = 0) -> str:
    """Build a human-readable range label for windowed output.

    Uses 1-based inclusive ranges when offset > 0 (e.g. `"showing 41-80 of 200"`).
    Falls back to the simpler `"showing N of M"` / `"N"` form
    when offset is 0 for backward-compatible display.
    """
    if offset > 0:
        if showing == 0:
            return f"showing 0 of {total}"
        start = offset + 1
        end = offset + showing
        return f"showing {start}-{end} of {total}"
    if showing < total:
        return f"showing {showing} of {total}"
    return str(total)


class PlainRenderer(Renderer):
    """Plain text renderer for non-interactive environments.

    Produces clean, undecorated text without ANSI codes or XML tags.
    Uses dash lists for collections and key-value lines for metadata.
    Designed for CI pipelines, log files, and piped output.
    """

    def __init__(self, *, stream: TextIO | None = None) -> None:
        self._stream = stream or sys.stdout

    def _writeln(self, text: str = "") -> None:
        """Write a line of text with a trailing newline."""
        self._stream.write(text + "\n")

    def _write(self, text: str) -> None:
        """Write text without a trailing newline."""
        self._stream.write(text)

    @staticmethod
    def _safe(text: str) -> str:
        """Strip ANSI/OSC escape sequences from untrusted text."""
        return strip_control_chars(text)

    # -- Package queries ----------------------------------------------------

    def _render_info_base(self, report: InfoReport) -> None:
        """Render the base package info as key-value lines."""
        info = report.info
        latest = self._safe(str(info.latest_version))
        if info.latest_release_date is not None:
            latest += f" ({info.latest_release_date:%Y-%m-%d})"

        self._writeln(f"Package: {self._safe(info.name)}")
        if info.summary is not None:
            self._writeln(f"Summary: {self._safe(info.summary)}")
        self._writeln(f"Latest Version: {latest}")
        self._writeln(f"Versions: {info.version_count}")
        if info.license is not None:
            self._writeln(f"License: {self._safe(info.license)}")
        if info.author is not None:
            self._writeln(f"Author: {self._safe(info.author)}")
        self._writeln(f"Registry: {info.registry}")
        if info.project_urls:
            for label, url in info.project_urls.items():
                self._writeln(f"{self._safe(label)}: {self._safe(url)}")

    def render_info(self, report: InfoReport) -> None:
        """Render package info report with package overview and version details."""
        info = report.info
        self._render_info_base(report)

        # -- Versions section (package-level) -------------------------------
        if report.versions is not None:
            self._writeln()
            self.render_versions(
                info.name,
                report.versions,
                report.versions_total
                if report.versions_total is not None
                else len(report.versions),
                latest_version=str(info.latest_version),
            )

        # -- Version details section ----------------------------------------
        # Labeled separator — visually distinct from key-value lines so
        # readers can tell it scopes everything below, not just the next line.
        version = report.target_version or str(info.latest_version)
        is_latest = version == str(info.latest_version)
        header = f"Version {self._safe(version)}"
        if is_latest:
            header += " (latest)"
        self._writeln()
        self._writeln(f"--- {header} ---")

        if info.requires_python is not None:
            self._writeln(f"Python: {self._safe(info.requires_python)}")

        if report.target_version_yanked:
            msg = f"WARNING: Version {self._safe(version)} has been yanked"
            if report.target_version_yanked_reason:
                msg += f": {self._safe(report.target_version_yanked_reason)}"
            self._writeln(msg)

        if report.vulnerabilities is not None:
            self._writeln()
            self.render_vulns(report.vulnerabilities)

        if report.metadata is not None:
            self._writeln()
            self.render_deps(info.name, version, report.metadata)

        if report.errors:
            self._writeln()
            for section, message in report.errors.items():
                self._writeln(f"Error ({self._safe(section)}): {self._safe(message)}")

    def render_versions(  # noqa: PLR0913
        self,
        name: str,
        versions: list[VersionInfo],
        total: int,
        *,
        offset: int = 0,
        latest_version: str | None = None,
        yanked: bool = False,
        matching: str | None = None,
        original_total: int | None = None,
    ) -> None:
        """Render version list as a dash list."""
        safe_name = self._safe(name)
        showing = len(versions)
        kind = "yanked versions" if yanked else "versions"

        if not versions and offset > 0 and total > 0:
            self._writeln(
                f"No {kind} at offset {offset} for {safe_name} (total: {total})."
            )
            return

        has_more = (offset + showing) < total
        if matching and original_total is not None:
            if has_more or offset > 0:
                range_label = _plain_range_label(showing, total, offset)
                header = (
                    f"{safe_name} {kind}"
                    f" ({range_label}"
                    f" matching {self._safe(matching)};"
                    f" {original_total} total):"
                )
            else:
                header = (
                    f"{safe_name} {kind}"
                    f" ({total} of {original_total}"
                    f" matching {self._safe(matching)}):"
                )
        else:
            range_label = _plain_range_label(showing, total, offset)
            header = f"{safe_name} {kind} ({range_label}):"

        self._writeln(header)
        for version in versions:
            label = f"  - {self._safe(str(version.version))}"
            if version.release_date:
                label += f" ({version.release_date:%Y-%m-%d})"
            # Mark the latest version using the pre-computed value,
            # which stays correct regardless of offset.
            if latest_version and str(version.version) == latest_version:
                label += " (latest)"
            # Show (yanked) only when not in yanked-filter mode; when
            # --yanked is active the header already conveys it.
            # (yanked: reason) takes precedence over bare (yanked).
            if version.yanked_reason:
                label += f" (yanked: {self._safe(version.yanked_reason)})"
            elif version.yanked and not yanked:
                label += " (yanked)"
            self._writeln(label)

    def render_deps(
        self,
        name: str,
        version: str,
        metadata: PackageMetadata,
        *,
        tag: str | None = None,
    ) -> None:
        """Render dependencies as a dash list."""
        tag_label = f" ({self._safe(tag)})" if tag else ""
        header = (
            f"Dependencies for {self._safe(name)} {self._safe(version)}{tag_label}:"
        )

        if metadata.dependencies is None:
            self._writeln(header)
            self._writeln("Dependencies unknown (Requires-Dist marked as Dynamic)")
            if metadata.dynamic_fields:
                fields = ", ".join(self._safe(f) for f in metadata.dynamic_fields)
                self._writeln(f"Dynamic fields: {fields}")
            return

        if not metadata.dependencies:
            self._writeln(header)
            self._writeln("No dependencies.")
            return

        required, optional = group_dependencies(metadata.dependencies)

        self._writeln(header)
        for dep in required:
            spec = f" {self._safe(dep.specifier)}" if dep.specifier else ""
            self._writeln(f"  - {self._safe(dep.name)}{spec}")

        for extra_name, deps in sorted(optional.items()):
            self._writeln(f"\nOptional [{self._safe(extra_name)}]:")
            for dep in deps:
                spec = f" {self._safe(dep.specifier)}" if dep.specifier else ""
                self._writeln(f"  - {self._safe(dep.name)}{spec}")

        if metadata.source:
            source_info = f"\nSource: {self._safe(metadata.source)}"
            if metadata.source_filename:
                source_info += f" ({self._safe(metadata.source_filename)})"
            self._writeln(source_info)

    def render_deps_diff(  # noqa: PLR0912
        self,
        name: str,
        from_version: str,
        to_version: str,
        diff: DepsDiff,
        *,
        tag: str | None = None,
    ) -> None:
        """Render dependency differences as plain text."""
        tag_label = f" ({self._safe(tag)})" if tag else ""
        header = (
            f"Dependency changes for {self._safe(name)} "
            f"({self._safe(from_version)} -> {self._safe(to_version)}){tag_label}:"
        )
        self._writeln(header)

        # Changed
        self._writeln("\nChanged:")
        if diff.changed:
            for c in diff.changed:
                group = f" [{self._safe(c.extras_group)}]" if c.extras_group else ""
                self._writeln(
                    f"  {self._safe(c.name)}{group}"
                    f" {self._safe(c.old_specifier)} -> {self._safe(c.new_specifier)}"
                )
                if c.old_markers != c.new_markers:
                    old_m = self._safe(c.old_markers) if c.old_markers else "(none)"
                    new_m = self._safe(c.new_markers) if c.new_markers else "(none)"
                    self._writeln(f"    markers: {old_m} -> {new_m}")
                if c.old_extras != c.new_extras:
                    old_e = (
                        f"[{', '.join(self._safe(e) for e in c.old_extras)}]"
                        if c.old_extras
                        else "(none)"
                    )
                    new_e = (
                        f"[{', '.join(self._safe(e) for e in c.new_extras)}]"
                        if c.new_extras
                        else "(none)"
                    )
                    self._writeln(f"    extras: {old_e} -> {new_e}")
        else:
            self._writeln("  (none)")

        # Added
        self._writeln("\nAdded:")
        if diff.added:
            for dep in diff.added:
                spec = f" {self._safe(dep.specifier)}" if dep.specifier else ""
                self._writeln(f"  {self._safe(dep.name)}{spec}")
        else:
            self._writeln("  (none)")

        # Removed
        self._writeln("\nRemoved:")
        if diff.removed:
            for dep in diff.removed:
                spec = f" {self._safe(dep.specifier)}" if dep.specifier else ""
                self._writeln(f"  {self._safe(dep.name)}{spec}")
        else:
            self._writeln("  (none)")

        # Unchanged count
        label = "dependency" if diff.unchanged_count == 1 else "dependencies"
        self._writeln(f"\nUnchanged: {diff.unchanged_count} {label}")

        # Added/removed extras groups
        if diff.added_extras:
            groups = ", ".join(self._safe(g) for g in diff.added_extras)
            self._writeln(f"Added extras groups: {groups}")
        if diff.removed_extras:
            groups = ", ".join(self._safe(g) for g in diff.removed_extras)
            self._writeln(f"Removed extras groups: {groups}")

    def render_artifacts(
        self,
        name: str,
        version: str,
        files: list[FileInfo],
    ) -> None:
        """Render available distribution files as a dash list."""
        if not files:
            self._writeln(f"No files for {self._safe(name)} {self._safe(version)}.")
            return

        # Version-level yanked warning when ALL files are yanked
        all_yanked = all(f.yanked for f in files)
        if all_yanked:
            reason = next((f.yanked_reason for f in files if f.yanked_reason), None)
            msg = f"WARNING: Version {self._safe(version)} has been yanked"
            if reason:
                msg += f": {self._safe(reason)}"
            self._writeln(msg)
            self._writeln()

        self._writeln(
            f"Distribution artifacts for {self._safe(name)} {self._safe(version)}:"
        )
        for f in files:
            size = format_size(f.size) if f.size is not None else "unknown size"
            python = (
                f", Python {self._safe(f.requires_python)}" if f.requires_python else ""
            )
            yanked = ""
            if f.yanked:
                yanked_detail = (
                    f": {self._safe(f.yanked_reason)}" if f.yanked_reason else ""
                )
                yanked = f" (yanked{yanked_detail})"
            self._writeln(
                f"  - {self._safe(f.filename)} ({f.dist_type.value}, {size}{python}){yanked}"
            )

    def render_ls(  # noqa: PLR0913
        self,
        name: str,
        version: str,
        entries: list[LsEntry],
        total: int,
        *,
        offset: int = 0,
        prefix: str | None = None,
        recursive: bool = False,  # noqa: ARG002
        glob_patterns: list[str] | None = None,
    ) -> None:
        """Render archive directory listing as a dash list."""
        safe_name = self._safe(name)
        safe_version = self._safe(version)
        showing = len(entries)

        # Build header
        count_label = _plain_range_label(showing, total, offset)
        # Append " entries" only for the simple "N entries" / "N of M entries" forms.
        if offset == 0:
            count_label_full = (
                f"{showing} of {total} entries"
                if showing < total
                else f"{total} entries"
            )
        else:
            count_label_full = count_label
        prefix_label = f" under {self._safe(prefix)}" if prefix else ""
        glob_label = (
            f" matching {', '.join(self._safe(p) for p in glob_patterns)}"
            if glob_patterns
            else ""
        )
        header = f"Archive contents for {safe_name} {safe_version}{prefix_label}{glob_label} ({count_label_full}):"

        if not entries:
            if offset > 0 and total > 0:
                self._writeln(
                    f"No entries at offset {offset} for"
                    f" {safe_name} {safe_version}{prefix_label}"
                    f" (total: {total})."
                )
            elif glob_patterns:
                patterns = ", ".join(self._safe(p) for p in glob_patterns)
                self._writeln(
                    f"No files matched glob {patterns}"
                    f" for {safe_name} {safe_version}{prefix_label}."
                )
            else:
                self._writeln(
                    f"Archive contents for {safe_name} {safe_version}{prefix_label} (0 entries):"
                )
            return

        self._writeln(header)
        for entry in entries:
            if entry.is_dir:
                parts = [f"{entry.file_count} files"]
                if entry.subdir_count > 0:
                    parts.append(f"{entry.subdir_count} subdirs")
                detail = ", ".join(parts)
                self._writeln(f"  - {self._safe(entry.path)} (directory, {detail})")
            else:
                self._writeln(
                    f"  - {self._safe(entry.path)} ({format_size(entry.size)})"
                )

    # -- File inspection ----------------------------------------------------

    def render_file_content(  # noqa: PLR0913
        self,
        name: str,  # noqa: ARG002
        version: str,  # noqa: ARG002
        path: str,  # noqa: ARG002
        content: bytes,
        *,
        truncated: bool = False,  # noqa: ARG002
        total_size: int | None = None,  # noqa: ARG002
    ) -> None:
        """Render file content as plain text."""
        text = try_decode(content)
        if text is None:
            self._writeln(f"[Binary file, {format_size(len(content))}]")
        else:
            self._write(self._safe(text))
            if text and not text.endswith("\n"):
                self._writeln()

    def render_download(self, path: Path, *, extracted: bool = False) -> None:
        """Render download confirmation."""
        action = "Extracted to" if extracted else "Downloaded to"
        self._writeln(f"{action}: {path}")

    # -- Cache management ---------------------------------------------------

    def render_cache_info(self, stats: CacheStats) -> None:
        """Render cache statistics as key-value lines."""
        # Build size / limit display
        size_str = format_size(stats.total_size_bytes)
        if stats.limit_bytes is not None and stats.usage_percent is not None:
            limit_str = format_size(stats.limit_bytes)
            size_str = f"{size_str} / {limit_str} ({stats.usage_percent:.0f}%)"
            if stats.usage_percent > 100:  # noqa: PLR2004
                size_str += " — exceeds limit"
        else:
            size_str = f"{size_str} (no limit)"

        self._writeln(f"Location: {stats.location}")
        self._writeln(f"Packages: {stats.package_count}")
        self._writeln(
            f"Archives: {stats.archived_count} distributions"
            f" ({format_size(stats.total_size_bytes)})"
        )
        self._writeln(f"Metadata only: {stats.metadata_only_count} distributions")
        self._writeln(f"Cache size: {size_str}")
        if stats.oldest_entry:
            self._writeln(f"Oldest entry: {stats.oldest_entry:%Y-%m-%d %H:%M}")
        if stats.newest_entry:
            self._writeln(f"Newest entry: {stats.newest_entry:%Y-%m-%d %H:%M}")

    def render_cache_clear(self, count: int, total_size_bytes: int) -> None:
        """Render cache clear results."""
        if count == 0:
            self._writeln("No entries to clear.")
            return
        size_str = f" ({format_size(total_size_bytes)})" if total_size_bytes else ""
        self._writeln(f"Cleared {count} entries{size_str}.")

    def render_cache_dump(self, data: dict[str, Any]) -> None:
        """Render cache dump as plain JSON."""
        self._writeln(json.dumps(data, indent=2, default=str))

    def render_cache_check(self, diagnostics: dict[str, Any]) -> None:
        """Render cache diagnostics as key-value lines."""
        for key, value in diagnostics.items():
            self._writeln(f"{key}: {value}")

    # -- Dependency resolution ----------------------------------------------

    def render_resolve(self, result: SolverResult) -> None:
        """Render resolved dependency tree as a dash list."""
        count = len(result.resolved)
        self._writeln(f"Resolved {count} packages:")
        for pkg in sorted(result.resolved, key=lambda p: p.name):
            self._writeln(f"  - {self._safe(pkg.name)}=={self._safe(str(pkg.version))}")
        self._writeln(f"\nSolver: {result.solver_id}")

    def render_conflicts(
        self,
        conflicts: list[ConflictInfo],
        *,
        header: str | None = None,
    ) -> None:
        """Render dependency conflict details."""
        if header:
            self._writeln(self._safe(header))
            self._writeln()

        for conflict in conflicts:
            self._writeln(f"CONFLICT: {self._safe(conflict.package)}")
            self._writeln()
            for req in conflict.requirements:
                spec = (
                    f"{self._safe(req.package)}{self._safe(req.version)}"
                    if req.version
                    else self._safe(req.package)
                )
                self._writeln(f"  {spec} requires: {self._safe(req.dependency)}")
                if req.chain:
                    chain_str = " -> ".join(self._safe(c) for c in req.chain)
                    self._writeln(f"    via: {chain_str}")
                self._writeln()

            if conflict.additional_requirements:
                self._writeln(
                    f"  Also constrains {self._safe(conflict.package)}"
                    " (not part of the conflict):"
                )
                for req in conflict.additional_requirements:
                    spec = (
                        f"{self._safe(req.package)}{self._safe(req.version)}"
                        if req.version
                        else self._safe(req.package)
                    )
                    self._writeln(f"    {spec}: {self._safe(req.dependency)}")
                self._writeln()

            if conflict.message:
                self._writeln(self._safe(conflict.message))

            if conflict.hints:
                self._writeln()
                for hint in conflict.hints:
                    self._writeln(self._safe(hint))

    # -- Why tracing ------------------------------------------------------------

    def render_why(self, result: WhyResult) -> None:
        """Render dependency path trace results as plain text."""
        target_label = (
            f"{self._safe(result.target)}=={self._safe(result.target_version)}"
        )

        if result.is_direct:
            self._writeln(
                f"{target_label} is a direct requirement (not pulled in transitively)."
            )
            return

        source = self._safe(result.paths[0].hops[0].package)
        self._writeln(f"{target_label} is required for {source}:")

        def _safe_writeln(line: str) -> None:
            self._writeln(self._safe(line))

        multiple = len(result.paths) > 1
        for i, path in enumerate(result.paths):
            self._writeln()
            if multiple:
                self._writeln(f"  Path {i + 1}:")
            _write_why_path(_safe_writeln, path, multiple=multiple)

        path_count = len(result.paths)
        label = "path" if path_count == 1 else "paths"
        self._writeln()
        self._writeln(f"{path_count} {label} found")
        if result.truncated:
            self._writeln("(results truncated, more paths may exist)")

    def render_why_failed(
        self,
        target: str,
        conflicts: list[ConflictInfo],
    ) -> None:
        """Render why-command failure with embedded conflict details."""
        _ = target  # Used by other renderers; part of base class interface
        self._writeln("Resolution failed")
        self._writeln()

        for conflict in conflicts:
            self._writeln(f"CONFLICT: {self._safe(conflict.package)}")
            for req in conflict.requirements:
                spec = (
                    f"{self._safe(req.package)}{self._safe(req.version)}"
                    if req.version
                    else self._safe(req.package)
                )
                self._writeln(f"  {spec} requires: {self._safe(req.dependency)}")
                if req.chain:
                    chain_str = " -> ".join(self._safe(c) for c in req.chain)
                    self._writeln(f"    via: {chain_str}")
            self._writeln()

        self._writeln("Path tracing is not available when resolution fails.")
        self._writeln(f"Use '{APP_NAME} conflicts' for conflict details.")

    # -- Vulnerability checking -----------------------------------------------

    def render_vulns(self, report: VulnerabilityReport) -> None:
        """Render vulnerability report as plain text."""
        self._writeln(
            f"Vulnerabilities for {self._safe(report.package)} {self._safe(report.version)}:"
        )

        if not report.vulnerabilities:
            self._writeln("No known vulnerabilities.")
            return

        self._writeln()
        for vuln in report.vulnerabilities:
            self._writeln(f"ID: {self._safe(vuln.id)}")
            cves = [a for a in vuln.aliases if a.startswith("CVE-")]
            if cves:
                self._writeln(f"CVE: {', '.join(self._safe(c) for c in cves)}")
            severity = vuln.severity_label or (
                vuln.severity[0].type.replace("CVSS_", "CVSS ")
                if vuln.severity
                else None
            )
            if severity:
                self._writeln(f"Severity: {self._safe(severity)}")
            if vuln.summary:
                self._writeln(f"Summary: {self._safe(vuln.summary)}")
            if vuln.fixed_versions:
                self._writeln(
                    f"Fixed in: {', '.join(self._safe(v) for v in vuln.fixed_versions)}"
                )
            self._writeln()

        recommendation = build_vulnerability_recommendation(report.vulnerabilities)
        if recommendation is not None:
            self._writeln(f"Suggested upgrade: >= {self._safe(recommendation.version)}")
            if recommendation.unresolved_count:
                self._writeln(
                    "Note: "
                    f"{format_unfixed_vulnerability_note(recommendation.unresolved_count)}"
                )

    # -- Errors -------------------------------------------------------------

    def render_error(self, message: str) -> None:
        """Render an error message."""
        self._writeln(f"Error: {self._safe(message)}")

    def render_not_found(self, name: str) -> None:
        """Render a 'package not found' message."""
        self._writeln(f"Package {self._safe(name)!r} not found.")
