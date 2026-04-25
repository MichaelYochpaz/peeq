"""JSON renderer for structured machine-readable output.

Provides `JSONRenderer` that outputs structured JSON for
programmatic consumption by scripts, CI/CD pipelines, and tools.
Each render method writes a single JSON object to the output stream.
"""

from __future__ import annotations

import json
import sys
from typing import TYPE_CHECKING

from peeq import APP_NAME
from peeq.output.base import LsEntry, Renderer
from peeq.utils import extract_extra

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
        VulnerabilityReport,
    )
    from peeq.resolver.models import ConflictInfo, SolverResult, WhyResult


class JSONRenderer(Renderer):
    """Structured JSON output renderer.

    Each method writes a single JSON object to the output stream,
    suitable for programmatic parsing.
    """

    def __init__(self, *, stream: TextIO | None = None) -> None:
        self._stream = stream or sys.stdout

    def _output(self, data: dict[str, Any]) -> None:
        """Write a JSON object followed by a newline."""
        json.dump(data, self._stream, indent=2, default=str)
        self._stream.write("\n")

    # -- Package queries ----------------------------------------------------

    def render_info(self, report: InfoReport) -> None:
        """Render package info report as JSON."""
        data = {
            "command": "info",
            **report.model_dump(mode="json", exclude_none=True),
        }
        self._output(data)

    def render_versions(
        self,
        name: str,
        versions: list[VersionInfo],
        total: int,
        *,
        matching: str | None = None,
        original_total: int | None = None,
    ) -> None:
        """Render version list as JSON."""
        data: dict[str, Any] = {
            "command": "versions",
            "name": name,
            "versions": [
                {
                    "version": str(version.version),
                    "yanked": version.yanked,
                    "yanked_reason": version.yanked_reason,
                }
                for version in versions
            ],
            "showing": len(versions),
            "total": total,
        }
        if matching is not None:
            data["matching"] = matching
            data["matched"] = total
            data["total"] = original_total
        self._output(data)

    def render_deps(
        self,
        name: str,
        version: str,
        metadata: PackageMetadata,
        *,
        tag: str | None = None,
    ) -> None:
        """Render dependencies as JSON with extra grouping."""
        data: dict[str, Any] = {
            "command": "deps",
            "name": name,
            "version": version,
        }
        if tag:
            data["tag"] = tag

        if metadata.dependencies is None:
            data["dependencies"] = None
            data["deps_known"] = False
            if metadata.dynamic_fields:
                data["dynamic_fields"] = metadata.dynamic_fields
        elif not metadata.dependencies:
            data["dependencies"] = []
            data["deps_known"] = True
        else:
            deps_list: list[dict[str, Any]] = []
            for dep in metadata.dependencies:
                dep_dict: dict[str, Any] = {
                    "name": dep.name,
                    "specifier": dep.specifier,
                }
                if dep.extras:
                    dep_dict["extras"] = dep.extras
                if dep.markers:
                    dep_dict["markers"] = dep.markers
                extra = extract_extra(dep)
                if extra:
                    dep_dict["optional_extra"] = extra
                deps_list.append(dep_dict)
            data["dependencies"] = deps_list
            data["deps_known"] = True

        if metadata.source:
            data["source"] = metadata.source
        if metadata.source_filename:
            data["source_filename"] = metadata.source_filename

        self._output(data)

    def render_deps_diff(
        self,
        name: str,
        from_version: str,
        to_version: str,
        diff: DepsDiff,
        *,
        tag: str | None = None,
    ) -> None:
        """Render dependency differences as structured JSON."""
        data: dict[str, Any] = {
            "command": "deps_diff",
            "package": name,
            "from_version": from_version,
            "to_version": to_version,
        }
        if tag:
            data["tag"] = tag

        changed_list: list[dict[str, Any]] = []
        for c in diff.changed:
            entry: dict[str, Any] = {
                "name": c.name,
                "old_specifier": c.old_specifier,
                "new_specifier": c.new_specifier,
            }
            if c.old_markers is not None or c.new_markers is not None:
                entry["old_markers"] = c.old_markers
                entry["new_markers"] = c.new_markers
            if c.old_extras or c.new_extras:
                entry["old_extras"] = list(c.old_extras)
                entry["new_extras"] = list(c.new_extras)
            if c.extras_group is not None:
                entry["extras_group"] = c.extras_group
            changed_list.append(entry)

        added_list: list[dict[str, Any]] = []
        for dep in diff.added:
            dep_dict: dict[str, Any] = {
                "name": dep.name,
                "specifier": dep.specifier,
            }
            if dep.extras:
                dep_dict["extras"] = dep.extras
            if dep.markers:
                dep_dict["markers"] = dep.markers
            added_list.append(dep_dict)

        removed_list: list[dict[str, Any]] = []
        for dep in diff.removed:
            dep_dict = {
                "name": dep.name,
                "specifier": dep.specifier,
            }
            if dep.extras:
                dep_dict["extras"] = dep.extras
            if dep.markers:
                dep_dict["markers"] = dep.markers
            removed_list.append(dep_dict)

        data["changed"] = changed_list
        data["added"] = added_list
        data["removed"] = removed_list
        data["unchanged_count"] = diff.unchanged_count
        data["added_extras"] = diff.added_extras
        data["removed_extras"] = diff.removed_extras

        self._output(data)

    def render_artifacts(
        self,
        name: str,
        version: str,
        files: list[FileInfo],
    ) -> None:
        """Render file list as JSON."""
        all_yanked = bool(files) and all(f.yanked for f in files)
        version_yanked_reason: str | None = None
        if all_yanked:
            version_yanked_reason = next(
                (f.yanked_reason for f in files if f.yanked_reason), None
            )
        self._output(
            {
                "command": "artifacts",
                "name": name,
                "version": version,
                "yanked": all_yanked,
                "yanked_reason": version_yanked_reason,
                "artifacts": [
                    {
                        "filename": f.filename,
                        "dist_type": f.dist_type.value,
                        "size": f.size,
                        "requires_python": f.requires_python,
                        "yanked": f.yanked,
                        "yanked_reason": f.yanked_reason,
                        "metadata_available": f.metadata_available,
                    }
                    for f in files
                ],
            }
        )

    def render_ls(  # noqa: PLR0913
        self,
        name: str,
        version: str,
        entries: list[LsEntry],
        total: int,
        *,
        prefix: str | None = None,
        recursive: bool = False,
    ) -> None:
        """Render archive directory listing as JSON."""
        entries_list: list[dict[str, object]] = []
        for entry in entries:
            if entry.is_dir:
                entries_list.append(
                    {
                        "path": entry.path,
                        "type": "directory",
                        "file_count": entry.file_count,
                        "subdir_count": entry.subdir_count,
                        "total_size": entry.total_size,
                    }
                )
            else:
                entries_list.append(
                    {
                        "path": entry.path,
                        "type": "file",
                        "size": entry.size,
                    }
                )
        self._output(
            {
                "command": "ls",
                "package": name,
                "version": version,
                "recursive": recursive,
                "prefix": prefix,
                "showing": len(entries),
                "total": total,
                "truncated": len(entries) < total,
                "entries": entries_list,
            }
        )

    # -- File inspection ----------------------------------------------------

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
        """Render file content as JSON (text content only; binary omitted)."""
        try:
            text: str | None = content.decode("utf-8")
            encoding = "utf-8"
        except (UnicodeDecodeError, ValueError):
            text = None
            encoding = "binary"

        data: dict[str, Any] = {
            "command": "cat",
            "name": name,
            "version": version,
            "path": path,
            "encoding": encoding,
            "size_bytes": total_size if total_size is not None else len(content),
        }
        if text is not None:
            data["content"] = text
        if truncated and text is not None:
            data["truncated"] = True
            data["showing_bytes"] = len(content)
        self._output(data)

    def render_download(self, path: Path, *, extracted: bool = False) -> None:
        """Render download result as JSON."""
        self._output(
            {
                "command": "download",
                "path": str(path),
                "extracted": extracted,
            }
        )

    # -- Cache management ---------------------------------------------------

    def render_cache_info(self, stats: CacheStats) -> None:
        """Render cache statistics as JSON."""
        self._output(
            {
                "command": "cache_info",
                "location": str(stats.location),
                "package_count": stats.package_count,
                "distribution_count": stats.distribution_count,
                "archived_count": stats.archived_count,
                "metadata_only_count": stats.metadata_only_count,
                "total_size_bytes": stats.total_size_bytes,
                "limit_bytes": stats.limit_bytes,
                "usage_percent": (
                    round(stats.usage_percent, 1)
                    if stats.usage_percent is not None
                    else None
                ),
                "oldest_entry": (
                    stats.oldest_entry.isoformat() if stats.oldest_entry else None
                ),
                "newest_entry": (
                    stats.newest_entry.isoformat() if stats.newest_entry else None
                ),
            }
        )

    def render_cache_clear(self, count: int, total_size_bytes: int) -> None:
        """Render cache clear result as JSON."""
        self._output(
            {
                "command": "cache_clear",
                "count": count,
                "total_size_bytes": total_size_bytes,
            }
        )

    def render_cache_dump(self, data: dict[str, Any]) -> None:
        """Render full cache dump as JSON (pass-through)."""
        self._output({"command": "cache_dump", **data})

    def render_cache_check(self, diagnostics: dict[str, Any]) -> None:
        """Render cache diagnostics as JSON."""
        self._output(
            {
                "command": "cache_check",
                **diagnostics,
            }
        )

    # -- Dependency resolution ----------------------------------------------

    def render_resolve(self, result: SolverResult) -> None:
        """Render resolved packages as JSON."""
        self._output(
            {
                "command": "resolve",
                "solver": result.solver_id,
                "resolved": [
                    {
                        "name": pkg.name,
                        "version": str(pkg.version),
                        "dependencies": pkg.dependencies,
                    }
                    for pkg in sorted(result.resolved, key=lambda p: p.name)
                ],
            }
        )

    def render_conflicts(
        self,
        conflicts: list[ConflictInfo],
        *,
        header: str | None = None,
    ) -> None:
        """Render conflict details as JSON."""
        data: dict[str, Any] = {
            "command": "resolve" if header else "conflicts",
            "solver": "uv",
        }
        if header is not None:
            data["header"] = header

        conflict_list: list[dict[str, Any]] = []
        for c in conflicts:
            entry: dict[str, Any] = {
                "package": c.package,
                "constraints": [
                    {
                        "required_by": (
                            f"{r.package}{r.version}" if r.version else r.package
                        ),
                        "requires": r.dependency,
                        "chain": r.chain,
                    }
                    for r in c.requirements
                ],
                "hints": c.hints,
            }
            if c.additional_requirements:
                entry["additional_constraints"] = [
                    {
                        "required_by": (
                            f"{r.package}{r.version}" if r.version else r.package
                        ),
                        "requires": r.dependency,
                    }
                    for r in c.additional_requirements
                ]
            conflict_list.append(entry)

        data["conflicts"] = conflict_list
        self._output(data)

    # -- Why tracing ------------------------------------------------------------

    def render_why(self, result: WhyResult) -> None:
        """Render dependency path trace results as JSON."""
        data: dict[str, Any] = {
            "command": "why",
            "target": result.target,
            "target_version": result.target_version,
            "is_direct": result.is_direct,
            "truncated": result.truncated,
            "paths": [
                {
                    "hops": [
                        {
                            "package": hop.package,
                            "version": hop.version,
                            "requirement": hop.requirement,
                        }
                        for hop in path.hops
                    ]
                }
                for path in result.paths
            ],
        }
        self._output(data)

    def render_why_failed(
        self,
        target: str,
        conflicts: list[ConflictInfo],
    ) -> None:
        """Render why-command failure as JSON."""
        conflict_list: list[dict[str, Any]] = []
        for c in conflicts:
            entry: dict[str, Any] = {
                "package": c.package,
                "requirements": [
                    {
                        "name": r.package,
                        "version": r.version,
                        "specifier": r.dependency,
                    }
                    for r in c.requirements
                ],
            }
            conflict_list.append(entry)

        self._output(
            {
                "command": "why",
                "target": target,
                "error": "Resolution failed",
                "conflicts": conflict_list,
                "message": (
                    "Path tracing is not available when resolution fails. "
                    f"Use '{APP_NAME} conflicts' for conflict details."
                ),
            }
        )

    # -- Vulnerability checking -----------------------------------------------

    def render_vulns(self, report: VulnerabilityReport) -> None:
        """Render vulnerability report as JSON."""
        self._output(
            {
                "command": "vulns",
                "package": report.package,
                "version": report.version,
                "vulnerability_count": len(report.vulnerabilities),
                "vulnerabilities": [
                    {
                        "id": v.id,
                        "summary": v.summary,
                        "aliases": v.aliases,
                        "severity_label": v.severity_label,
                        "severity": [
                            {"type": s.type, "score": s.score} for s in v.severity
                        ],
                        "fixed_versions": v.fixed_versions,
                        "references": [
                            {"type": r.type, "url": r.url} for r in v.references
                        ],
                        "published": v.published,
                        "modified": v.modified,
                        "withdrawn": v.withdrawn,
                    }
                    for v in report.vulnerabilities
                ],
            }
        )

    # -- Errors -------------------------------------------------------------

    def render_error(self, message: str) -> None:
        """Render error as JSON."""
        self._output(
            {
                "error": True,
                "message": message,
            }
        )

    def render_not_found(self, name: str) -> None:
        """Render 'not found' as JSON."""
        self._output(
            {
                "error": True,
                "message": f"Package {name!r} not found",
                "name": name,
            }
        )
