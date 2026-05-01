"""Rich-based terminal renderer for pretty output.

Provides `RichRenderer` using the Rich library for colorful
terminal output with panels, tables, and syntax highlighting.
Auto-selected when stdout is a TTY (`--format=pretty`).
"""

from __future__ import annotations

import json
import posixpath
import sys
from typing import TYPE_CHECKING

from rich.columns import Columns
from rich.console import Console, Group
from rich.markup import escape as rich_escape
from rich.padding import Padding
from rich.panel import Panel
from rich.rule import Rule
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text
from rich.theme import Theme
from rich.tree import Tree

from peeq import APP_NAME
from peeq.output.base import LsEntry, Renderer, format_size, try_decode
from peeq.utils import group_dependencies

if TYPE_CHECKING:
    from pathlib import Path
    from typing import Any, TextIO

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
    from peeq.resolver.models import ConflictInfo, SolverResult, WhyPath, WhyResult


# ---------------------------------------------------------------------------
# Lexer guessing
# ---------------------------------------------------------------------------

_LEXER_MAP: dict[str, str] = {
    ".py": "python",
    ".pyx": "cython",
    ".pyi": "python",
    ".toml": "toml",
    ".cfg": "ini",
    ".ini": "ini",
    ".json": "json",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".md": "markdown",
    ".rst": "rst",
    ".txt": "text",
    ".xml": "xml",
    ".html": "html",
    ".css": "css",
    ".js": "javascript",
    ".ts": "typescript",
    ".sh": "bash",
    ".bat": "batch",
    ".ps1": "powershell",
    ".c": "c",
    ".h": "c",
    ".cpp": "cpp",
    ".rs": "rust",
}


def _guess_lexer(filename: str) -> str:
    """Guess a Pygments lexer name from a filename extension."""
    _, ext = posixpath.splitext(filename)
    return _LEXER_MAP.get(ext.lower(), "text")


# ---------------------------------------------------------------------------
# Expected PRAGMA values for cache diagnostics
# ---------------------------------------------------------------------------

_EXPECTED_PRAGMAS: dict[str, tuple[object, str]] = {
    "journal_mode": ("wal", "WAL mode"),
    "synchronous": (1, "Sync level (NORMAL)"),
    "foreign_keys": (1, "Foreign keys"),
    "temp_store": (2, "Temp store (MEMORY)"),
    "quick_check": ("ok", "Integrity"),
}


# ---------------------------------------------------------------------------
# Centralized theme
# ---------------------------------------------------------------------------

# Style naming conventions:
# - Data display: noun describing the data type (version, filename, ...)
# - Status: adjective/outcome (success, warning, error, failure)
# - Severity: "severity." prefix + level name
# - Package/dependency names: intentionally unstyled (default foreground)
_THEME = Theme(
    {
        # -- Data display --
        "version": "cyan",
        "specifier": "dim",
        "constraint": "dim",
        "filename": "cyan",
        "filetype": "green",
        # -- Status --
        "success": "green",
        "warning": "yellow",
        "error": "bold red",
        "failure": "red",
        "yanked": "dim red",
        # -- Severity --
        "severity.critical": "bold red",
        "severity.high": "red",
        "severity.moderate": "yellow",
        "severity.medium": "yellow",
        "severity.low": "green",
        # -- Structure --
        "tree.guide": "dim",
    }
)


# ---------------------------------------------------------------------------
# Severity formatting
# ---------------------------------------------------------------------------

_SEVERITY_STYLES: dict[str, str] = {
    "CRITICAL": "severity.critical",
    "HIGH": "severity.high",
    "MODERATE": "severity.moderate",
    "MEDIUM": "severity.medium",
    "LOW": "severity.low",
}


def _format_severity_rich(vuln: VulnerabilityInfo) -> str:
    """Format vulnerability severity with Rich color markup.

    Prefer the text label from `database_specific.severity` (GHSA
    records), then fall back to the CVSS vector type.
    """
    label = vuln.severity_label
    if label:
        style = _SEVERITY_STYLES.get(label.upper(), "")
        safe_label = rich_escape(label)
        return f"[{style}]{safe_label}[/{style}]" if style else safe_label

    if vuln.severity:
        return rich_escape(vuln.severity[0].type.replace("CVSS_", "CVSS "))

    return "-"


# ---------------------------------------------------------------------------
# RichRenderer
# ---------------------------------------------------------------------------


class RichRenderer(Renderer):
    """Terminal renderer using Rich panels, tables, and syntax highlighting."""

    def __init__(self, *, stream: TextIO | None = None) -> None:
        self._console = Console(
            file=stream or sys.stdout, highlight=False, theme=_THEME
        )

    # -- Package queries ----------------------------------------------------

    def _build_info_base_lines(self, report: InfoReport) -> list[str]:
        """Build base package info lines for the unified panel."""
        info = report.info
        latest = rich_escape(str(info.latest_version))
        if info.latest_release_date is not None:
            latest += f" ({info.latest_release_date:%Y-%m-%d})"

        lines = [
            f"[bold]Package:[/bold]        {rich_escape(info.name)}",
        ]
        if info.summary is not None:
            lines.append(f"[bold]Summary:[/bold]        {rich_escape(info.summary)}")
        lines.append(f"[bold]Latest Version:[/bold] {latest}")
        lines.append(f"[bold]Versions:[/bold]       {info.version_count}")
        if info.license is not None:
            lines.append(f"[bold]License:[/bold]        {rich_escape(info.license)}")
        if info.author is not None:
            lines.append(f"[bold]Author:[/bold]         {rich_escape(info.author)}")
        lines.append(f"[bold]Registry:[/bold]       {info.registry}")
        if info.project_urls:
            lines.append("")
            lines.append("[bold]Project URLs:[/bold]")
            max_label_len = max(len(label) for label in info.project_urls)
            for label, url in info.project_urls.items():
                padded = f"{label}:".ljust(max_label_len + 1)
                lines.append(f"  {rich_escape(padded)} {rich_escape(url)}")

        return lines

    @staticmethod
    def _build_versions_grid(
        versions: list[VersionInfo],
        versions_total: int | None,
        *,
        columns: int = 3,
    ) -> list[str]:
        """Build a multi-column plain-text grid of versions.

        Each cell shows `version  date`.  Yanked versions use
        strikethrough + dim markup.  Returns lines ready for Rich
        markup rendering.
        """
        if not versions:
            return []

        # Determine fixed cell width from the longest version string
        max_ver_len = max(len(str(v.version)) for v in versions)
        # "version  YYYY-MM-DD" — version padded + 2 spaces + 10-char date
        cell_width = max_ver_len + 2 + 10

        lines: list[str] = []
        row_cells: list[str] = []
        for v in versions:
            ver_str = str(v.version)
            date_str = f"{v.release_date:%Y-%m-%d}" if v.release_date else " " * 10
            safe_ver = rich_escape(ver_str)
            # Pad based on original length for correct visual alignment
            padded_ver = safe_ver + " " * max(0, max_ver_len - len(ver_str))

            if v.yanked:
                cell = f"[dim strike]{padded_ver}  {date_str}[/dim strike]"
            else:
                cell = f"[version]{padded_ver}[/version]  [dim]{date_str}[/dim]"

            # Pad the visible content to cell_width for alignment
            # Rich markup is invisible, so pad the raw text
            visible_len = len(ver_str) + 2 + len(date_str)
            padding = " " * max(0, cell_width - visible_len)
            row_cells.append(cell + padding)

            if len(row_cells) == columns:
                lines.append("  " + "   ".join(row_cells))
                row_cells = []

        if row_cells:
            lines.append("  " + "   ".join(row_cells))

        if versions_total is not None and versions_total != len(versions):
            lines.append(
                f"  [dim]Showing {len(versions)} of {versions_total} versions[/dim]"
            )

        return lines

    def _build_vulns_section(
        self,
        report: VulnerabilityReport,
    ) -> list[str | Table]:
        """Build vulnerability section content for the unified panel.

        Returns a mix of markup strings and Rich Table objects.
        """
        header = f"Vulnerabilities for {rich_escape(report.package)} {rich_escape(report.version)}"
        parts: list[str | Table] = []

        if not report.vulnerabilities:
            parts.append(f"[bold]{header}:[/bold]")
            parts.append("  [success]No known vulnerabilities[/success]")
            return parts

        count = len(report.vulnerabilities)
        parts.append(f"[bold]{header} ({count} found):[/bold]")

        table = Table(show_edge=False, pad_edge=False, expand=False, show_lines=True)
        table.add_column("ID", style="bold")
        table.add_column("CVE")
        table.add_column("Severity")
        table.add_column("Fixed In")
        table.add_column("Summary")

        for vuln in report.vulnerabilities:
            cves = rich_escape(
                ", ".join(a for a in vuln.aliases if a.startswith("CVE-")) or "-"
            )
            severity = _format_severity_rich(vuln)
            fixed = rich_escape(", ".join(vuln.fixed_versions) or "-")
            summary = rich_escape(vuln.summary or "-")
            table.add_row(rich_escape(vuln.id), cves, severity, fixed, summary)

        parts.append(table)

        # Recommendation
        all_fixed = sorted(
            {v for vuln in report.vulnerabilities for v in vuln.fixed_versions}
        )
        if all_fixed:
            parts.append(
                f"  [bold]Recommendation:[/bold] Upgrade to >= {rich_escape(all_fixed[-1])}"
            )

        return parts

    @staticmethod
    def _build_deps_section(
        name: str,
        version: str,
        metadata: PackageMetadata,
    ) -> list[str]:
        """Build dependency section lines for the unified panel."""
        header = f"Dependencies for {rich_escape(name)} {rich_escape(version)}:"
        lines: list[str] = [f"[bold]{header}[/bold]"]

        if metadata.dependencies is None:
            lines.append(
                "  [warning]Dependencies unknown "
                "(Requires-Dist marked as Dynamic)[/warning]"
            )
            if metadata.dynamic_fields:
                fields = ", ".join(rich_escape(f) for f in metadata.dynamic_fields)
                lines.append(f"  [dim]Dynamic fields: {fields}[/dim]")
            return lines

        if not metadata.dependencies:
            lines.append("  [dim]No dependencies[/dim]")
            return lines

        required, optional = group_dependencies(metadata.dependencies)

        for dep in required:
            styled_spec = (
                f" [specifier]{rich_escape(dep.specifier)}[/specifier]"
                if dep.specifier
                else ""
            )
            lines.append(f"  - {rich_escape(dep.name)}{styled_spec}")

        for extra_name, deps in sorted(optional.items()):
            lines.append(f"  [bold]Optional \\[{rich_escape(extra_name)}]:[/bold]")
            for dep in deps:
                styled_spec = (
                    f" [specifier]{rich_escape(dep.specifier)}[/specifier]"
                    if dep.specifier
                    else ""
                )
                lines.append(f"  - {rich_escape(dep.name)}{styled_spec}")

        # Source provenance
        if metadata.source:
            source_info = f"Source: {rich_escape(metadata.source)}"
            if metadata.source_filename:
                source_info += f" ({rich_escape(metadata.source_filename)})"
            lines.append(f"  [dim]{source_info}[/dim]")

        return lines

    def render_info(self, report: InfoReport) -> None:
        """Render package info report as a single unified panel.

        Output is split into a package-overview section and a
        version-details section separated by a `Rule`.
        """
        info = report.info

        # Collect all renderables (strings and Rich objects) for the panel
        renderables: list[str | Table | Rule] = []

        # -- Package overview -----------------------------------------------
        base_lines = self._build_info_base_lines(report)
        renderables.append("\n".join(base_lines))

        if report.versions is not None:
            version_lines = self._build_versions_grid(
                report.versions, report.versions_total
            )
            if version_lines:
                renderables.append("")
                renderables.append("[bold]Versions:[/bold]")
                renderables.append("\n".join(version_lines))

        # -- Version details ------------------------------------------------
        version = report.target_version or str(info.latest_version)
        is_latest = version == str(info.latest_version)
        label = f"Version {rich_escape(version)}"
        if is_latest:
            label += " (latest)"
        renderables.append("")
        renderables.append(Rule(label, style="dim"))

        if info.requires_python is not None:
            renderables.append(
                f"[bold]Python:[/bold] {rich_escape(info.requires_python)}"
            )

        if report.target_version_yanked:
            msg = f"Version {rich_escape(version)} has been yanked"
            if report.target_version_yanked_reason:
                msg += f": {rich_escape(report.target_version_yanked_reason)}"
            renderables.append(f"[error]{msg}[/error]")

        if report.vulnerabilities is not None:
            vuln_parts = self._build_vulns_section(report.vulnerabilities)
            renderables.append("")
            renderables.extend(vuln_parts)

        if report.metadata is not None:
            dep_lines = self._build_deps_section(info.name, version, report.metadata)
            renderables.append("")
            renderables.append("\n".join(dep_lines))

        if report.errors:
            renderables.append("")
            for section, message in report.errors.items():
                renderables.append(
                    f"[failure]Error ({section}): {rich_escape(message)}[/failure]"
                )

        self._console.print(
            Panel(Group(*renderables), title=rich_escape(info.name), expand=False)
        )

    def render_versions(
        self,
        name: str,
        versions: list[VersionInfo],
        total: int,
        *,
        matching: str | None = None,
        original_total: int | None = None,
    ) -> None:
        """Render version list as a responsive multi-column grid."""
        safe_name = rich_escape(name)
        showing = len(versions)
        latest = rich_escape(str(versions[0].version)) if versions else None
        all_yanked = bool(versions) and all(v.yanked for v in versions)

        # -- Header ----------------------------------------------------------
        header = self._versions_header(
            safe_name,
            showing,
            total,
            latest,
            matching,
            original_total,
            all_yanked=all_yanked,
        )
        self._console.print(f"[bold]{header}[/bold]")

        if not versions:
            return

        # -- Grid body -------------------------------------------------------
        max_ver_len = max(len(str(v.version)) for v in versions)
        renderables: list[Text] = []
        for v in versions:
            ver_str = str(v.version)
            padded = ver_str.ljust(max_ver_len)
            use_strike = v.yanked and not all_yanked

            if v.release_date:
                date_str = f"{v.release_date:%Y-%m-%d}"
                if use_strike:
                    renderables.append(
                        Text(f"{padded} ({date_str})", style="dim strike")
                    )
                else:
                    renderables.append(
                        Text.assemble(
                            (padded, "version"),
                            (" (", "dim"),
                            (date_str, "dim"),
                            (")", "dim"),
                        )
                    )
            else:
                style = "dim strike" if use_strike else "version"
                renderables.append(Text(padded, style=style))

        grid = Columns(renderables, padding=(0, 3), equal=True)
        self._console.print(Padding(grid, (0, 0, 0, 2)))

        # -- Yanked-reasons footnote -----------------------------------------
        if any(v.yanked and v.yanked_reason for v in versions):
            self._console.print()
            self._console.print("[bold]Yanked:[/bold]")
            for vr in versions:
                if vr.yanked and vr.yanked_reason:
                    self._console.print(
                        f"  - [version]{rich_escape(str(vr.version))}[/version]:"
                        f" [yanked]{rich_escape(vr.yanked_reason)}[/yanked]"
                    )

    @staticmethod
    def _versions_header(  # noqa: PLR0913
        safe_name: str,
        showing: int,
        total: int,
        latest: str | None,
        matching: str | None,
        original_total: int | None,
        *,
        all_yanked: bool = False,
    ) -> str:
        """Build the header line for `render_versions`."""
        kind = "yanked versions" if all_yanked else "versions"

        if matching and original_total is not None:
            if showing < total:
                core = (
                    f"{safe_name} {kind} (showing {showing} of {total}"
                    f" matching {rich_escape(matching)};"
                    f" {original_total} total"
                )
            else:
                core = (
                    f"{safe_name} {kind} ({total} of {original_total}"
                    f" matching {rich_escape(matching)}"
                )
        elif showing < total:
            core = f"{safe_name} {kind} (showing {showing} of {total}"
        else:
            core = f"{safe_name} {kind} ({total}"

        suffix = f", latest: {latest}" if latest else ""
        return f"{core}{suffix}):"

    def render_deps(
        self,
        name: str,
        version: str,
        metadata: PackageMetadata,
        *,
        tag: str | None = None,
    ) -> None:
        """Render dependencies grouped by extras."""
        tag_label = f" ({rich_escape(tag)})" if tag else ""
        header = (
            f"Dependencies for {rich_escape(name)} {rich_escape(version)}{tag_label}:"
        )

        if metadata.dependencies is None:
            self._console.print(f"[bold]{header}[/bold]")
            self._console.print(
                "[warning]Dependencies unknown "
                "(Requires-Dist marked as Dynamic)[/warning]"
            )
            if metadata.dynamic_fields:
                fields = ", ".join(rich_escape(f) for f in metadata.dynamic_fields)
                self._console.print(f"[dim]Dynamic fields: {fields}[/dim]")
            return

        if not metadata.dependencies:
            self._console.print(f"[bold]{header}[/bold]")
            self._console.print("[dim]No dependencies[/dim]")
            return

        required, optional = group_dependencies(metadata.dependencies)

        self._console.print(f"[bold]{header}[/bold]")
        for dep in required:
            styled_spec = (
                f" [specifier]{rich_escape(dep.specifier)}[/specifier]"
                if dep.specifier
                else ""
            )
            self._console.print(f"  - {rich_escape(dep.name)}{styled_spec}")

        for extra_name, deps in sorted(optional.items()):
            self._console.print(
                f"\n[bold]Optional \\[{rich_escape(extra_name)}]:[/bold]"
            )
            for dep in deps:
                styled_spec = (
                    f" [specifier]{rich_escape(dep.specifier)}[/specifier]"
                    if dep.specifier
                    else ""
                )
                self._console.print(f"  - {rich_escape(dep.name)}{styled_spec}")

        # Source provenance (dim, non-intrusive)
        if metadata.source:
            source_info = f"Source: {rich_escape(metadata.source)}"
            if metadata.source_filename:
                source_info += f" ({rich_escape(metadata.source_filename)})"
            self._console.print(f"\n[dim]{source_info}[/dim]")

    def render_deps_diff(  # noqa: PLR0912
        self,
        name: str,
        from_version: str,
        to_version: str,
        diff: DepsDiff,
        *,
        tag: str | None = None,
    ) -> None:
        """Render dependency differences with colored sections."""
        tag_label = f" ({rich_escape(tag)})" if tag else ""
        header = (
            f"Dependency changes for {rich_escape(name)} "
            f"({rich_escape(from_version)} -> {rich_escape(to_version)}){tag_label}:"
        )
        self._console.print(f"[bold]{header}[/bold]")

        # Changed (yellow)
        self._console.print("\n[bold][warning]Changed:[/warning][/bold]")
        if diff.changed:
            for c in diff.changed:
                group = f" \\[{rich_escape(c.extras_group)}]" if c.extras_group else ""
                line = (
                    f"  {rich_escape(c.name)}{group} "
                    f"{rich_escape(c.old_specifier)} -> {rich_escape(c.new_specifier)}"
                )
                self._console.print(f"[warning]{line}[/warning]")
                if c.old_markers != c.new_markers:
                    old_m = rich_escape(c.old_markers) if c.old_markers else "(none)"
                    new_m = rich_escape(c.new_markers) if c.new_markers else "(none)"
                    self._console.print(
                        f"[warning]    markers: {old_m} -> {new_m}[/warning]"
                    )
                if c.old_extras != c.new_extras:
                    old_e = (
                        f"\\[{', '.join(rich_escape(e) for e in c.old_extras)}]"
                        if c.old_extras
                        else "(none)"
                    )
                    new_e = (
                        f"\\[{', '.join(rich_escape(e) for e in c.new_extras)}]"
                        if c.new_extras
                        else "(none)"
                    )
                    self._console.print(
                        f"[warning]    extras: {old_e} -> {new_e}[/warning]"
                    )
        else:
            self._console.print("  [dim](none)[/dim]")

        # Added (green)
        self._console.print("\n[bold][success]Added:[/success][/bold]")
        if diff.added:
            for dep in diff.added:
                spec = f" {rich_escape(dep.specifier)}" if dep.specifier else ""
                self._console.print(
                    f"  [success]{rich_escape(dep.name)}{spec}[/success]"
                )
        else:
            self._console.print("  [dim](none)[/dim]")

        # Removed (red)
        self._console.print("\n[bold][failure]Removed:[/failure][/bold]")
        if diff.removed:
            for dep in diff.removed:
                spec = f" {rich_escape(dep.specifier)}" if dep.specifier else ""
                self._console.print(
                    f"  [failure]{rich_escape(dep.name)}{spec}[/failure]"
                )
        else:
            self._console.print("  [dim](none)[/dim]")

        # Unchanged count
        label = "dependency" if diff.unchanged_count == 1 else "dependencies"
        self._console.print(f"\n[dim]Unchanged: {diff.unchanged_count} {label}[/dim]")

        # Added/removed extras groups
        if diff.added_extras:
            groups = ", ".join(rich_escape(g) for g in diff.added_extras)
            self._console.print(f"[success]Added extras groups: {groups}[/success]")
        if diff.removed_extras:
            groups = ", ".join(rich_escape(g) for g in diff.removed_extras)
            self._console.print(f"[failure]Removed extras groups: {groups}[/failure]")

    def render_artifacts(
        self,
        name: str,
        version: str,
        files: list[FileInfo],
    ) -> None:
        """Render available distribution files as a table."""
        safe_name = rich_escape(name)
        safe_version = rich_escape(version)
        if not files:
            self._console.print(f"[dim]No files for {safe_name} {safe_version}[/dim]")
            return

        any_yanked = any(f.yanked for f in files)
        all_yanked = any_yanked and all(f.yanked for f in files)

        # Version-level yanked banner when ALL files are yanked
        if all_yanked:
            reason = next((f.yanked_reason for f in files if f.yanked_reason), None)
            msg = f"Version {safe_version} has been yanked"
            if reason:
                msg += f": {rich_escape(reason)}"
            self._console.print(f"[error]{msg}[/error]")

        table = Table(title=f"Distribution artifacts for {safe_name} {safe_version}")
        table.add_column("Filename", style="filename")
        table.add_column("Type", style="filetype")
        table.add_column("Size", justify="right")
        table.add_column("Python", style="constraint")
        if any_yanked:
            table.add_column("Yanked", style="yanked")

        for f in files:
            size = format_size(f.size) if f.size is not None else "-"
            python = rich_escape(f.requires_python or "-")
            row = [rich_escape(f.filename), f.dist_type.value, size, python]
            if any_yanked:
                if f.yanked:
                    row.append(
                        rich_escape(f.yanked_reason) if f.yanked_reason else "Yes"
                    )
                else:
                    row.append("")
            table.add_row(*row)

        self._console.print(table)

    def render_ls(  # noqa: PLR0913
        self,
        name: str,
        version: str,
        entries: list[LsEntry],
        total: int,
        *,
        prefix: str | None = None,
        recursive: bool = False,  # noqa: ARG002
    ) -> None:
        """Render archive directory listing as a table."""
        safe_name = rich_escape(name)
        safe_version = rich_escape(version)

        if not entries:
            prefix_label = f" under {rich_escape(prefix)}" if prefix else ""
            self._console.print(
                f"[dim]Archive is empty for {safe_name} {safe_version}{prefix_label}[/dim]"
            )
            return

        # Build title with optional truncation and prefix info
        count_label = (
            f"showing {len(entries)} of {total}" if len(entries) < total else str(total)
        )
        prefix_label = f" under {rich_escape(prefix)}" if prefix else ""
        title = f"Archive contents for {safe_name} {safe_version}{prefix_label} ({count_label})"

        table = Table(title=title)
        table.add_column("Path", style="filename")
        table.add_column("Details", justify="right")

        for entry in entries:
            if entry.is_dir:
                parts = [f"{entry.file_count} files"]
                if entry.subdir_count > 0:
                    parts.append(f"{entry.subdir_count} subdirs")
                detail = ", ".join(parts)
                table.add_row(rich_escape(entry.path), detail)
            else:
                table.add_row(rich_escape(entry.path), format_size(entry.size))

        self._console.print(table)

    # -- File inspection ----------------------------------------------------

    def render_file_content(  # noqa: PLR0913
        self,
        name: str,
        version: str,
        path: str,
        content: bytes,
        *,
        truncated: bool = False,  # noqa: ARG002
        total_size: int | None = None,  # noqa: ARG002
    ) -> None:
        """Render file content with syntax highlighting."""
        text = try_decode(content)
        if text is None:
            self._console.print(
                f"[warning]Binary file ({format_size(len(content))})[/warning]"
            )
            return

        title = f"{rich_escape(name)} {rich_escape(version)} \u2014 {rich_escape(path)}"
        lexer = _guess_lexer(path)
        syntax = Syntax(text, lexer, theme="monokai", line_numbers=True)
        self._console.print(Panel(syntax, title=title, expand=True))

    def render_download(self, path: Path, *, extracted: bool = False) -> None:
        """Render download confirmation."""
        action = "Extracted to" if extracted else "Downloaded to"
        self._console.print(f"[success]{action}:[/success] {path}")

    # -- Cache management ---------------------------------------------------

    def render_cache_info(self, stats: CacheStats) -> None:
        """Render cache statistics as a panel."""
        # Build size / limit display
        size_str = format_size(stats.total_size_bytes)
        if stats.limit_bytes is not None and stats.usage_percent is not None:
            limit_str = format_size(stats.limit_bytes)
            size_str = f"{size_str} / {limit_str} ({stats.usage_percent:.0f}%)"
            if stats.usage_percent > 100:  # noqa: PLR2004
                size_str += " [failure]— exceeds limit[/failure]"
        else:
            size_str = f"{size_str} (no limit)"

        lines = [
            f"[bold]Location:[/bold]      {stats.location}",
            f"[bold]Packages:[/bold]      {stats.package_count}",
            f"[bold]Archives:[/bold]      {stats.archived_count} distributions ({format_size(stats.total_size_bytes)})",
            f"[bold]Metadata only:[/bold] {stats.metadata_only_count} distributions",
            f"[bold]Cache size:[/bold]    {size_str}",
        ]
        if stats.oldest_entry:
            lines.append(
                f"[bold]Oldest entry:[/bold]  {stats.oldest_entry:%Y-%m-%d %H:%M}"
            )
        if stats.newest_entry:
            lines.append(
                f"[bold]Newest entry:[/bold]  {stats.newest_entry:%Y-%m-%d %H:%M}"
            )
        self._console.print(Panel("\n".join(lines), title="Cache Info", expand=False))

    def render_cache_clear(self, count: int, total_size_bytes: int) -> None:
        """Render cache clear results."""
        if count == 0:
            self._console.print("[dim]No entries to clear[/dim]")
            return
        size_str = f" ({format_size(total_size_bytes)})" if total_size_bytes else ""
        self._console.print(f"[success]Cleared {count} entries{size_str}[/success]")

    def render_cache_dump(self, data: dict[str, Any]) -> None:
        """Render cache dump as syntax-highlighted JSON."""
        text = json.dumps(data, indent=2, default=str)
        syntax = Syntax(text, "json", theme="monokai")
        self._console.print(syntax)

    def render_cache_check(self, diagnostics: dict[str, Any]) -> None:
        """Render cache diagnostics as a pass/fail table."""
        table = Table(title="Cache Diagnostics")
        table.add_column("Check", style="bold")
        table.add_column("Value")
        table.add_column("Status")

        for key, (expected_val, label) in _EXPECTED_PRAGMAS.items():
            actual = diagnostics.get(key)
            if actual == expected_val:
                status = "[success]OK[/success]"
            else:
                status = f"[failure]FAIL (got {actual!r})[/failure]"
            table.add_row(label, str(actual), status)

        if "total_bytes" in diagnostics:
            table.add_row(
                "Database size",
                format_size(diagnostics["total_bytes"]),
                "",
            )
        if diagnostics.get("freelist_count", 0) > 0:
            table.add_row(
                "Free pages",
                str(diagnostics["freelist_count"]),
                "[warning]consider VACUUM[/warning]",
            )

        self._console.print(table)

    # -- Dependency resolution ----------------------------------------------

    def render_resolve(self, result: SolverResult) -> None:
        """Render resolved dependency tree."""
        count = len(result.resolved)
        self._console.print(f"[bold]Resolved {count} packages:[/bold]")
        for pkg in sorted(result.resolved, key=lambda p: p.name):
            self._console.print(
                f"  - {rich_escape(pkg.name)}==[version]{rich_escape(str(pkg.version))}[/version]"
            )
        self._console.print(f"\n[dim]Solver: {result.solver_id}[/dim]")

    def render_conflicts(
        self,
        conflicts: list[ConflictInfo],
        *,
        header: str | None = None,
    ) -> None:
        """Render dependency conflict details."""
        if header:
            self._console.print(f"[error]{rich_escape(header)}[/error]\n")

        for conflict in conflicts:
            self._console.print(
                f"[error]CONFLICT:[/error] [bold]{rich_escape(conflict.package)}[/bold]\n"
            )
            for req in conflict.requirements:
                spec = f"{req.package}{req.version}" if req.version else req.package
                self._console.print(
                    f"  {rich_escape(spec)} requires: {rich_escape(req.dependency)}"
                )
                if req.chain:
                    chain_str = " \u2192 ".join(req.chain)
                    self._console.print(f"    [dim]via: {rich_escape(chain_str)}[/dim]")
                self._console.print()

            if conflict.additional_requirements:
                self._console.print(
                    f"  [dim]Also constrains {rich_escape(conflict.package)}"
                    " (not part of the conflict):[/dim]"
                )
                for req in conflict.additional_requirements:
                    spec = f"{req.package}{req.version}" if req.version else req.package
                    self._console.print(
                        f"    [dim]{rich_escape(spec)}:"
                        f" {rich_escape(req.dependency)}[/dim]"
                    )
                self._console.print()

            if conflict.message:
                self._console.print(
                    f"[warning]{rich_escape(conflict.message)}[/warning]"
                )

            if conflict.hints:
                self._console.print()
                for hint in conflict.hints:
                    self._console.print(f"[dim]{rich_escape(hint)}[/dim]")

    # -- Why tracing ------------------------------------------------------------

    @staticmethod
    def _build_why_tree(path: WhyPath) -> Tree:
        """Build a Rich Tree for a single dependency path.

        Each node shows `package version`, with the incoming version
        specifier (from the parent hop) appended in dim parentheses
        when present.
        """
        hops = path.hops

        def _hop_label(index: int) -> Text:
            """Create a styled label for a single hop node."""
            hop = hops[index]
            label = Text.assemble(
                hop.package,
                " ",
                (hop.version, "version"),
            )
            # Incoming specifier: what the parent requires of this hop
            if index > 0:
                prev_req = hops[index - 1].requirement
                if prev_req:
                    label.append(" (", "specifier")
                    label.append(prev_req, "specifier")
                    label.append(")", "specifier")
            return label

        tree = Tree(_hop_label(0), guide_style="tree.guide")
        current = tree
        for j in range(1, len(hops)):
            current = current.add(_hop_label(j))
        return tree

    def render_why(self, result: WhyResult) -> None:
        """Render dependency path trace results with a Rich Tree."""
        target_label = f"[bold]{rich_escape(result.target)}=={rich_escape(result.target_version)}[/bold]"

        if result.is_direct:
            self._console.print(
                f"{target_label} is a direct requirement (not pulled in transitively)."
            )
            return

        source = f"[bold]{rich_escape(result.paths[0].hops[0].package)}[/bold]"
        self._console.print(f"{target_label} is required for {source}:")

        multiple = len(result.paths) > 1
        for i, path in enumerate(result.paths):
            self._console.print()
            if multiple:
                self._console.print(f"[bold]Path {i + 1}:[/bold]")
            self._console.print(self._build_why_tree(path))

        path_count = len(result.paths)
        label = "path" if path_count == 1 else "paths"
        self._console.print(f"\n[dim]{path_count} {label} found[/dim]")
        if result.truncated:
            self._console.print("[dim](results truncated, more paths may exist)[/dim]")

    def render_why_failed(
        self,
        target: str,
        conflicts: list[ConflictInfo],
    ) -> None:
        """Render why-command failure with embedded conflict details."""
        _ = target  # Used by other renderers; part of base class interface
        self._console.print("[error]Resolution failed[/error]\n")

        for conflict in conflicts:
            self._console.print(
                f"[error]CONFLICT:[/error] [bold]{rich_escape(conflict.package)}[/bold]"
            )
            for req in conflict.requirements:
                spec = f"{req.package}{req.version}" if req.version else req.package
                self._console.print(
                    f"  {rich_escape(spec)} requires: {rich_escape(req.dependency)}"
                )
                if req.chain:
                    chain_str = " \u2192 ".join(req.chain)
                    self._console.print(f"    [dim]via: {rich_escape(chain_str)}[/dim]")
            self._console.print()

        self._console.print(
            "[dim]Path tracing is not available when resolution fails.[/dim]"
        )
        self._console.print(
            f"[dim]Use '{APP_NAME} conflicts' for conflict details.[/dim]"
        )

    # -- Vulnerability checking -----------------------------------------------

    def render_vulns(self, report: VulnerabilityReport) -> None:
        """Render vulnerability report with color-coded severity."""
        header = f"Vulnerabilities for {rich_escape(report.package)} {rich_escape(report.version)}"

        if not report.vulnerabilities:
            self._console.print(
                Panel(
                    "[success]No known vulnerabilities[/success]",
                    title=header,
                    border_style="success",
                )
            )
            return

        count = len(report.vulnerabilities)
        table = Table(
            title=f"{header} ({count} found)",
            show_lines=True,
        )
        table.add_column("ID", style="bold")
        table.add_column("CVE")
        table.add_column("Severity")
        table.add_column("Fixed In")
        table.add_column("Summary")

        for vuln in report.vulnerabilities:
            cves = rich_escape(
                ", ".join(a for a in vuln.aliases if a.startswith("CVE-")) or "-"
            )
            severity = _format_severity_rich(vuln)
            fixed = rich_escape(", ".join(vuln.fixed_versions) or "-")
            summary = rich_escape(vuln.summary or "-")
            table.add_row(rich_escape(vuln.id), cves, severity, fixed, summary)

        self._console.print(table)

        # Recommendation: show the highest fixed version if available
        all_fixed = sorted(
            {v for vuln in report.vulnerabilities for v in vuln.fixed_versions}
        )
        if all_fixed:
            self._console.print(
                f"\n[bold]Recommendation:[/bold] Upgrade to >= {rich_escape(all_fixed[-1])}"
            )

    # -- Errors -------------------------------------------------------------

    def render_error(self, message: str) -> None:
        """Render an error message in red."""
        self._console.print(f"[error]Error:[/error] {rich_escape(message)}")

    def render_not_found(self, name: str) -> None:
        """Render a 'package not found' message."""
        self._console.print(
            f"[warning]Package '{rich_escape(name)}' not found[/warning]"
        )
