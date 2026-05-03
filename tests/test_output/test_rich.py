"""Unit tests for the Rich output renderer (`peeq.output.rich`).

Tests capture `RichRenderer` output via `io.StringIO` (non-TTY, so
Rich omits ANSI escape codes).  Assertions
check for text content (package names, labels, version strings) rather
than pixel-perfect visual formatting.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from packaging.version import Version
from rich.table import Table

from peeq.models import (
    CvssSeverity,
    DistType,
    InfoReport,
    VersionInfo,
    VulnerabilityInfo,
    VulnerabilityReport,
)
from peeq.output.rich import RichRenderer
from tests.test_output._helpers import (
    _cache_stats,
    _conflict,
    _dep,
    _dep_change,
    _deps_diff,
    _file_info,
    _info_report,
    _ls_entry,
    _metadata,
    _pkg_info,
    _report,
    _solver_result,
    _vuln,
)
from tests.test_output._helpers import (
    _rich_renderer as _renderer,
)

# ---------------------------------------------------------------------------
# Tests: render_info
# ---------------------------------------------------------------------------


class TestRenderInfo:
    """Test package info rendering via Rich."""

    def test_basic(self) -> None:
        """Render package info with version section divider."""
        r, s = _renderer()
        r.render_info(_info_report())
        out = s.getvalue()
        assert "requests" in out
        assert "2.31.0" in out
        assert "142" in out
        assert "pypi.org" in out
        # Version section divider always present
        assert "Version 2.31.0 (latest)" in out

    def test_with_summary(self) -> None:
        """Summary appears in output."""
        r, s = _renderer()
        r.render_info(_info_report(summary="HTTP for Humans"))
        assert "HTTP for Humans" in s.getvalue()

    def test_without_summary(self) -> None:
        """No summary line when summary is None."""
        r, s = _renderer()
        r.render_info(_info_report(summary=None))
        assert "Summary" not in s.getvalue()

    def test_unified_panel_with_versions(self) -> None:
        """Versions section renders inside the same panel as base info."""
        r, s = _renderer()
        versions = [
            VersionInfo(
                version=Version("2.31.0"),
                release_date=datetime(2024, 6, 1, tzinfo=timezone.utc),
            ),
            VersionInfo(
                version=Version("2.30.0"),
                release_date=datetime(2024, 5, 1, tzinfo=timezone.utc),
            ),
            VersionInfo(
                version=Version("2.29.0"),
                release_date=datetime(2024, 4, 1, tzinfo=timezone.utc),
            ),
            VersionInfo(
                version=Version("2.28.0"),
                release_date=datetime(2024, 3, 1, tzinfo=timezone.utc),
            ),
        ]
        report = InfoReport(
            info=_pkg_info(),
            versions=versions,
            versions_total=4,
        )
        r.render_info(report)
        out = s.getvalue()
        # Base info and versions should be in the same output block
        assert "requests" in out
        assert "2.31.0" in out
        assert "2.30.0" in out
        assert "2024-06-01" in out
        assert "Versions" in out

    def test_unified_panel_versions_truncated(self) -> None:
        """'Showing N of M' appears when versions are truncated."""
        r, s = _renderer()
        versions = [
            VersionInfo(version=Version("2.31.0")),
        ]
        report = InfoReport(
            info=_pkg_info(),
            versions=versions,
            versions_total=142,
        )
        r.render_info(report)
        out = s.getvalue()
        assert "1" in out
        assert "142" in out
        assert "Showing" in out

    def test_unified_panel_yanked_version(self) -> None:
        """Yanked versions appear in the versions grid."""
        r, s = _renderer()
        versions = [
            VersionInfo(version=Version("2.31.0")),
            VersionInfo(version=Version("2.30.0"), yanked=True),
        ]
        report = InfoReport(
            info=_pkg_info(),
            versions=versions,
            versions_total=2,
        )
        r.render_info(report)
        out = s.getvalue()
        assert "2.30.0" in out

    def test_unified_panel_with_vulns_clean(self) -> None:
        """No-vulns message renders inside the unified panel."""
        r, s = _renderer()
        report = InfoReport(
            info=_pkg_info(),
            vulnerabilities=VulnerabilityReport(
                package="requests",
                version="2.31.0",
                vulnerabilities=[],
            ),
        )
        r.render_info(report)
        out = s.getvalue()
        assert "No known vulnerabilities" in out
        assert "requests" in out

    def test_unified_panel_with_vulns_found(self) -> None:
        """Vulnerability table renders inside the unified panel."""
        r, s = _renderer()
        vuln = VulnerabilityInfo(
            id="GHSA-test",
            summary="Test vuln",
            aliases=["CVE-2024-0001"],
            fixed_versions=["2.32.0"],
            severity_label="HIGH",
        )
        vulns_report = VulnerabilityReport(
            package="requests",
            version="2.31.0",
            vulnerabilities=[vuln],
        )
        report = InfoReport(
            info=_pkg_info(),
            vulnerabilities=vulns_report,
        )
        r.render_info(report)
        out = s.getvalue()
        assert "GHSA-test" in out
        assert "CVE-2024-0001" in out
        assert "Test vuln" in out
        assert "2.32.0" in out

        parts = r._build_vulns_section(vulns_report)
        vuln_table = next(part for part in parts if isinstance(part, Table))
        assert vuln_table.show_edge is True

    def test_unified_panel_with_deps(self) -> None:
        """Dependencies render inside the unified panel."""
        r, s = _renderer()
        report = InfoReport(
            info=_pkg_info(),
            metadata=_metadata(
                dependencies=[_dep("urllib3", ">=1.21"), _dep("certifi")]
            ),
        )
        r.render_info(report)
        out = s.getvalue()
        assert "urllib3" in out
        assert "certifi" in out
        assert "Dependencies" in out
        assert "requests" in out

    def test_unified_panel_with_no_deps(self) -> None:
        """Empty deps show 'No dependencies' inside the panel."""
        r, s = _renderer()
        report = InfoReport(
            info=_pkg_info(),
            metadata=_metadata(dependencies=[]),
        )
        r.render_info(report)
        out = s.getvalue()
        assert "No dependencies" in out

    def test_unified_panel_full(self) -> None:
        """All sections render inside a single unified panel."""
        r, s = _renderer()
        versions = [
            VersionInfo(
                version=Version("2.31.0"),
                release_date=datetime(2024, 6, 1, tzinfo=timezone.utc),
            ),
        ]
        report = InfoReport(
            info=_pkg_info(),
            versions=versions,
            versions_total=142,
            vulnerabilities=VulnerabilityReport(
                package="requests",
                version="2.31.0",
                vulnerabilities=[],
            ),
            metadata=_metadata(
                dependencies=[_dep("urllib3", ">=1.21")],
            ),
        )
        r.render_info(report)
        out = s.getvalue()
        # All sections present in same output
        assert "requests" in out
        assert "2.31.0" in out
        assert "2024-06-01" in out
        assert "No known vulnerabilities" in out
        assert "urllib3" in out
        assert "Dependencies" in out

    def test_unified_panel_errors(self) -> None:
        """Error messages appear inside the unified panel."""
        r, s = _renderer()
        report = InfoReport(
            info=_pkg_info(),
            errors={"vulns": "OSV API timeout"},
        )
        r.render_info(report)
        out = s.getvalue()
        assert "Error" in out
        assert "vulns" in out
        assert "OSV API timeout" in out

    def test_requires_python_in_version_section(self) -> None:
        """requires_python appears in the version section, not base info."""
        r, s = _renderer()
        r.render_info(_info_report(requires_python=">=3.8"))
        out = s.getvalue()
        assert "Python" in out
        assert ">=3.8" in out
        # Version divider present
        assert "Version 2.31.0 (latest)" in out

    def test_yanked_warning(self) -> None:
        """Yanked warning appears in the version section."""
        r, s = _renderer()
        report = InfoReport(
            info=_pkg_info(),
            target_version="2.30.0",
            target_version_yanked=True,
            target_version_yanked_reason="Security issue",
        )
        r.render_info(report)
        out = s.getvalue()
        assert "Version 2.30.0 has been yanked" in out
        assert "Security issue" in out
        # Version section divider present
        assert "Version 2.30.0" in out

    def test_yanked_warning_no_reason(self) -> None:
        """Yanked warning without reason has no trailing colon."""
        r, s = _renderer()
        report = InfoReport(
            info=_pkg_info(),
            target_version="2.30.0",
            target_version_yanked=True,
        )
        r.render_info(report)
        out = s.getvalue()
        assert "Version 2.30.0 has been yanked" in out
        assert "has been yanked:" not in out

    def test_no_yanked_warning_when_not_yanked(self) -> None:
        """No warning when version is not yanked."""
        r, s = _renderer()
        report = InfoReport(
            info=_pkg_info(),
            target_version="2.31.0",
            target_version_yanked=False,
        )
        r.render_info(report)
        out = s.getvalue()
        # "yanked" should not appear except in version section context
        assert "has been yanked" not in out

    def test_no_yanked_warning_when_unchecked(self) -> None:
        """No warning when yanked status is None (unchecked)."""
        r, s = _renderer()
        r.render_info(_info_report())
        assert "has been yanked" not in s.getvalue()


# ---------------------------------------------------------------------------
# Tests: render_versions
# ---------------------------------------------------------------------------


class TestRenderVersions:
    """Test version list rendering via Rich."""

    def test_full_list(self) -> None:
        """Render versions with header and grid."""
        r, s = _renderer()
        versions = [
            VersionInfo(version=Version("2.31.0")),
            VersionInfo(version=Version("2.30.0")),
        ]
        r.render_versions("requests", versions, total=2)
        out = s.getvalue()
        assert "requests" in out
        assert "2.31.0" in out
        assert "2.30.0" in out

    def test_limited(self) -> None:
        """Show 'showing X of Y' when limited."""
        r, s = _renderer()
        versions = [VersionInfo(version=Version("2.31.0"))]
        r.render_versions("requests", versions, total=142)
        out = s.getvalue()
        assert "showing" in out
        assert "1 of 142" in out

    def test_latest_in_header(self) -> None:
        """Latest version appears in the header line."""
        r, s = _renderer()
        versions = [
            VersionInfo(version=Version("2.31.0")),
            VersionInfo(version=Version("2.30.0")),
        ]
        r.render_versions("requests", versions, total=2)
        out = s.getvalue()
        assert "latest: 2.31.0" in out

    def test_yanked_strikethrough_in_grid(self) -> None:
        """Yanked version is rendered in the grid (with strikethrough style)."""
        r, s = _renderer()
        versions = [VersionInfo(version=Version("1.0.0"), yanked=True)]
        r.render_versions("pkg", versions, total=1)
        # Version string still appears in the output
        assert "1.0.0" in s.getvalue()

    def test_yanked_with_reason_in_footnote(self) -> None:
        """Yanked version with reason shows the reason in a footnote."""
        r, s = _renderer()
        versions = [
            VersionInfo(
                version=Version("1.0.0"),
                yanked=True,
                yanked_reason="security fix",
            ),
        ]
        r.render_versions("pkg", versions, total=1)
        out = s.getvalue()
        assert "Yanked:" in out
        assert "security fix" in out

    def test_yanked_without_reason_no_footnote(self) -> None:
        """Yanked version without a reason does not produce a footnote."""
        r, s = _renderer()
        versions = [VersionInfo(version=Version("1.0.0"), yanked=True)]
        r.render_versions("pkg", versions, total=1)
        assert "Yanked:" not in s.getvalue()

    def test_non_yanked_no_indicator(self) -> None:
        """Non-yanked version does not show yanked indicator."""
        r, s = _renderer()
        versions = [VersionInfo(version=Version("1.0.0"))]
        r.render_versions("pkg", versions, total=1)
        assert "Yanked:" not in s.getvalue()

    def test_release_date_shown(self) -> None:
        """Release date appears in the grid output."""
        r, s = _renderer()
        dt = datetime(2025, 6, 15, tzinfo=timezone.utc)
        versions = [VersionInfo(version=Version("1.0.0"), release_date=dt)]
        r.render_versions("pkg", versions, total=1)
        assert "2025-06-15" in s.getvalue()

    def test_mixed_length_versions_aligned(self) -> None:
        """Version cells are padded so dates align across rows.

        Regression test: .dev / .post / long pre-release suffixes used
        to break manual string-padding alignment.
        """
        versions = [
            VersionInfo(
                version=Version("1.84.0.dev2"),
                release_date=datetime(2026, 5, 1, tzinfo=timezone.utc),
            ),
            VersionInfo(
                version=Version("1.83.14"),
                release_date=datetime(2026, 4, 26, tzinfo=timezone.utc),
            ),
            VersionInfo(
                version=Version("1.83.9"),
                release_date=datetime(2026, 4, 17, tzinfo=timezone.utc),
            ),
        ]
        cells = RichRenderer._build_versions_cells(versions)
        # All cells should have the same plain-text width
        widths = [len(cell.plain) for cell in cells]
        assert len(set(widths)) == 1, f"Cell widths differ: {widths}"

    def test_grid_reduces_columns_on_narrow_terminal(self) -> None:
        """Grid uses fewer columns when they wouldn't fit."""
        versions = [
            VersionInfo(
                version=Version("1.84.0.dev2"),
                release_date=datetime(2026, 5, 1, tzinfo=timezone.utc),
            ),
            VersionInfo(
                version=Version("1.83.14"),
                release_date=datetime(2026, 4, 26, tzinfo=timezone.utc),
            ),
            VersionInfo(
                version=Version("1.83.9"),
                release_date=datetime(2026, 4, 17, tzinfo=timezone.utc),
            ),
        ]
        cells = RichRenderer._build_versions_cells(versions)
        cell_width = len(cells[0].plain)  # 24 chars for dev versions

        # Wide terminal: 3 columns fit
        wide_grid = RichRenderer._layout_text_grid(
            cells, available_width=cell_width * 3 + 6
        )
        assert wide_grid.row_count == 1

        # Narrow terminal: only 2 columns fit
        narrow_grid = RichRenderer._layout_text_grid(
            cells, available_width=cell_width * 2 + 3
        )
        assert narrow_grid.row_count == 2


# ---------------------------------------------------------------------------
# Tests: render_deps
# ---------------------------------------------------------------------------


class TestRenderDeps:
    """Test dependency rendering via Rich."""

    def test_with_dependencies(self) -> None:
        """Render required dependencies."""
        r, s = _renderer()
        meta = _metadata(dependencies=[_dep("urllib3", ">=1.21"), _dep("certifi")])
        r.render_deps("requests", "2.31.0", meta)
        out = s.getvalue()
        assert "requests" in out
        assert "2.31.0" in out
        assert "urllib3" in out
        assert "certifi" in out

    def test_with_tag(self) -> None:
        """Tag label appears in header."""
        r, s = _renderer()
        meta = _metadata(dependencies=[])
        r.render_deps("numpy", "1.26.0", meta, tag="cp312-cp312-win_amd64")
        assert "cp312-cp312-win_amd64" in s.getvalue()

    def test_no_dependencies(self) -> None:
        """Empty dependency list shows 'No dependencies'."""
        r, s = _renderer()
        meta = _metadata(dependencies=[])
        r.render_deps("empty-pkg", "1.0.0", meta)
        assert "No dependencies" in s.getvalue()

    def test_dynamic_dependencies(self) -> None:
        """None dependencies show Dynamic message."""
        r, s = _renderer()
        meta = _metadata(
            dependencies=None,
            dynamic_fields=["Requires-Dist"],
        )
        r.render_deps("dynamic-pkg", "1.0.0", meta)
        out = s.getvalue()
        assert "unknown" in out
        assert "Dynamic" in out

    def test_optional_extras(self) -> None:
        """Optional dependencies grouped by extra name."""
        r, s = _renderer()
        meta = _metadata(
            dependencies=[
                _dep("requests"),
                _dep("pysocks", markers='extra == "socks"'),
            ],
        )
        r.render_deps("httpx", "0.28.0", meta)
        out = s.getvalue()
        assert "socks" in out
        assert "pysocks" in out

    def test_dependency_groups_show_counts(self) -> None:
        """Dependency groups include item counts and omit list bullets."""
        r, s = _renderer()
        meta = _metadata(
            dependencies=[
                _dep("httpx", "==0.28.1"),
                _dep("openai", "==2.24.0"),
                _dep("gunicorn", "==23.0.0", markers='extra == "proxy"'),
                _dep("uvicorn", "==0.33.0", markers='extra == "proxy"'),
            ],
        )
        r.render_deps("pkg", "1.0.0", meta)
        out = s.getvalue()
        assert "Required (2):" in out
        assert "Optional [proxy] (2):" in out
        assert "httpx==0.28.1" in out
        # Blank line separates Required from Optional groups.
        assert "\n\nOptional [proxy]" in out
        assert "  - httpx" not in out

    def test_dependency_grid_reduces_columns_for_long_items(self) -> None:
        """Dependency grids adapt to long dependency cells."""
        deps = [
            _dep("azure-storage-file-datalake", "==12.20.0"),
            _dep("opentelemetry-exporter-otlp", "==1.28.0"),
            _dep("google-cloud-aiplatform", "==1.133.0"),
        ]
        cells = RichRenderer._build_dependency_cells(deps)
        cell_width = max(len(cell.plain) for cell in cells)

        wide_grid = RichRenderer._layout_text_grid(
            cells,
            available_width=cell_width * 3 + 6,
            max_columns=4,
        )
        assert wide_grid.row_count == 1

        narrow_grid = RichRenderer._layout_text_grid(
            cells,
            available_width=cell_width * 2 + 3,
            max_columns=4,
        )
        assert narrow_grid.row_count == 2

    def test_source_provenance(self) -> None:
        """Source info appears when available."""
        r, s = _renderer()
        meta = _metadata(
            dependencies=[_dep("click")],
            source="pep658",
            source_filename="pkg-1.0-py3-none-any.whl",
        )
        r.render_deps("pkg", "1.0.0", meta)
        out = s.getvalue()
        assert "pep658" in out
        assert "pkg-1.0-py3-none-any.whl" in out

    def test_dynamic_fields_listed(self) -> None:
        """Dynamic field names are listed when deps are unknown."""
        r, s = _renderer()
        meta = _metadata(
            dependencies=None,
            dynamic_fields=["Requires-Dist", "License"],
        )
        r.render_deps("pkg", "1.0.0", meta)
        out = s.getvalue()
        assert "Requires-Dist" in out
        assert "License" in out


# ---------------------------------------------------------------------------
# Tests: render_artifacts
# ---------------------------------------------------------------------------


class TestRenderArtifacts:
    """Test distribution artifact rendering via Rich."""

    def test_with_files(self) -> None:
        """Render file table with columns."""
        r, s = _renderer()
        files = [
            _file_info(),
            _file_info(
                filename="requests-2.31.0-py3-none-any.whl",
                dist_type=DistType.WHEEL,
            ),
        ]
        r.render_artifacts("requests", "2.31.0", files)
        out = s.getvalue()
        assert "requests-2.31.0.tar.gz" in out
        assert "requests-2.31.0-py3-none-any.whl" in out

    def test_empty_files(self) -> None:
        """Empty file list shows 'No files' message."""
        r, s = _renderer()
        r.render_artifacts("empty-pkg", "1.0.0", [])
        assert "No files" in s.getvalue()

    def test_yanked_file(self) -> None:
        """Yanked files show reason."""
        r, s = _renderer()
        files = [_file_info(yanked=True, yanked_reason="security fix")]
        r.render_artifacts("pkg", "1.0.0", files)
        assert "security fix" in s.getvalue()

    def test_yanked_column_hidden_when_none_yanked(self) -> None:
        """Yanked column is absent when no files are yanked."""
        r, s = _renderer()
        files = [_file_info(), _file_info(filename="pkg-1.0.0-py3-none-any.whl")]
        r.render_artifacts("pkg", "1.0.0", files)
        assert "Yanked" not in s.getvalue()

    def test_version_yanked_banner(self) -> None:
        """Banner appears when all files are yanked."""
        r, s = _renderer()
        files = [
            _file_info(yanked=True, yanked_reason="broken release"),
            _file_info(
                filename="pkg-1.0.0-py3-none-any.whl",
                dist_type=DistType.WHEEL,
                yanked=True,
                yanked_reason="broken release",
            ),
        ]
        r.render_artifacts("pkg", "1.0.0", files)
        out = s.getvalue()
        assert "has been yanked" in out
        assert "broken release" in out


# ---------------------------------------------------------------------------
# Tests: render_file_content
# ---------------------------------------------------------------------------


class TestRenderFileContent:
    """Test file content rendering via Rich."""

    def test_text_content(self) -> None:
        """Render text file content with panel output."""
        r, s = _renderer()
        r.render_file_content("requests", "2.31.0", "setup.py", b"print('hello')")
        out = s.getvalue()
        assert "print" in out
        assert "hello" in out

    def test_binary_content(self) -> None:
        """Binary content shows file size."""
        r, s = _renderer()
        r.render_file_content("pkg", "1.0.0", "data.bin", b"\x89PNG\r\n\x1a\n")
        out = s.getvalue()
        assert "Binary" in out


# ---------------------------------------------------------------------------
# Tests: render_download
# ---------------------------------------------------------------------------


class TestRenderDownload:
    """Test download confirmation rendering via Rich."""

    def test_downloaded(self) -> None:
        """Render download path."""
        r, s = _renderer()
        r.render_download(Path("/tmp/requests-2.31.0.tar.gz"))
        out = s.getvalue()
        assert "Downloaded to" in out

    def test_extracted(self) -> None:
        """Render extraction confirmation."""
        r, s = _renderer()
        r.render_download(Path("/tmp/requests-2.31.0"), extracted=True)
        assert "Extracted to" in s.getvalue()


# ---------------------------------------------------------------------------
# Tests: render_cache_info
# ---------------------------------------------------------------------------


class TestRenderCacheInfo:
    """Test cache statistics rendering via Rich."""

    def test_basic(self) -> None:
        """Render cache stats with key fields."""
        r, s = _renderer()
        r.render_cache_info(_cache_stats())
        out = s.getvalue()
        assert "15" in out
        assert "20 distributions" in out
        assert "3 distributions" in out

    def test_with_dates(self) -> None:
        """Date entries appear when present."""
        r, s = _renderer()
        stats = _cache_stats(
            oldest_entry=datetime(2024, 1, 15, 10, 30, tzinfo=timezone.utc),
            newest_entry=datetime(2024, 2, 8, 14, 0, tzinfo=timezone.utc),
        )
        r.render_cache_info(stats)
        out = s.getvalue()
        assert "2024-01-15" in out
        assert "2024-02-08" in out

    def test_without_dates(self) -> None:
        """No date lines when entries are None."""
        r, s = _renderer()
        r.render_cache_info(_cache_stats())
        out = s.getvalue()
        assert "Oldest" not in out
        assert "Newest" not in out


# ---------------------------------------------------------------------------
# Tests: render_cache_clear
# ---------------------------------------------------------------------------


class TestRenderCacheClear:
    """Test cache clear result rendering via Rich."""

    def test_cleared(self) -> None:
        """Render cleared count."""
        r, s = _renderer()
        r.render_cache_clear(8, 12_100_000)
        out = s.getvalue()
        assert "8 entries" in out

    def test_nothing_cleared(self) -> None:
        """Render message when nothing was cleared."""
        r, s = _renderer()
        r.render_cache_clear(0, 0)
        assert "No entries to clear" in s.getvalue()


# ---------------------------------------------------------------------------
# Tests: render_cache_dump
# ---------------------------------------------------------------------------


class TestRenderCacheDump:
    """Test cache dump rendering via Rich."""

    def test_json_output(self) -> None:
        """Render cache dump as formatted JSON."""
        r, s = _renderer()
        data = {"packages": [{"name": "requests"}]}
        r.render_cache_dump(data)
        out = s.getvalue()
        assert "requests" in out


# ---------------------------------------------------------------------------
# Tests: render_cache_check
# ---------------------------------------------------------------------------


class TestRenderCacheCheck:
    """Test cache diagnostics rendering via Rich."""

    def test_diagnostics_pass(self) -> None:
        """Render passing diagnostics with OK status."""
        r, s = _renderer()
        diag = {
            "journal_mode": "wal",
            "synchronous": 1,
            "foreign_keys": 1,
            "temp_store": 2,
            "quick_check": "ok",
        }
        r.render_cache_check(diag)
        out = s.getvalue()
        assert "OK" in out

    def test_diagnostics_fail(self) -> None:
        """Render failing diagnostic with FAIL status."""
        r, s = _renderer()
        diag = {
            "journal_mode": "delete",  # Expected "wal"
            "synchronous": 1,
            "foreign_keys": 1,
            "temp_store": 2,
            "quick_check": "ok",
        }
        r.render_cache_check(diag)
        out = s.getvalue()
        assert "FAIL" in out

    def test_free_pages_warning(self) -> None:
        """Render VACUUM suggestion when free pages exist."""
        r, s = _renderer()
        diag = {
            "journal_mode": "wal",
            "synchronous": 1,
            "foreign_keys": 1,
            "temp_store": 2,
            "quick_check": "ok",
            "freelist_count": 100,
        }
        r.render_cache_check(diag)
        assert "VACUUM" in s.getvalue()

    def test_database_size(self) -> None:
        """Render database size when total_bytes is present."""
        r, s = _renderer()
        diag = {
            "journal_mode": "wal",
            "synchronous": 1,
            "foreign_keys": 1,
            "temp_store": 2,
            "quick_check": "ok",
            "total_bytes": 2_097_152,
        }
        r.render_cache_check(diag)
        assert "2.0 MB" in s.getvalue()


# ---------------------------------------------------------------------------
# Tests: render_resolve
# ---------------------------------------------------------------------------


class TestRenderResolve:
    """Test resolution result rendering via Rich."""

    def test_basic(self) -> None:
        """Render resolved packages sorted by name."""
        r, s = _renderer()
        r.render_resolve(_solver_result())
        out = s.getvalue()
        assert "flask==3.0.0" in out
        assert "werkzeug==3.0.1" in out
        assert "uv" in out

    def test_count_in_header(self) -> None:
        """Package count appears in header."""
        r, s = _renderer()
        r.render_resolve(_solver_result())
        assert "2 " in s.getvalue()


# ---------------------------------------------------------------------------
# Tests: render_conflicts
# ---------------------------------------------------------------------------


class TestRenderConflicts:
    """Test conflict rendering via Rich."""

    def test_conflict(self) -> None:
        """Render conflict details."""
        r, s = _renderer()
        r.render_conflicts([_conflict()])
        out = s.getvalue()
        assert "CONFLICT:" in out
        assert "numpy" in out
        assert "tensorflow" in out
        assert "torch" in out

    def test_conflict_hints(self) -> None:
        """Hints from conflicts appear."""
        r, s = _renderer()
        r.render_conflicts([_conflict(hints=["Try upgrading tensorflow."])])
        assert "Try upgrading tensorflow." in s.getvalue()

    def test_per_conflict_message(self) -> None:
        """Per-conflict message appears."""
        r, s = _renderer()
        r.render_conflicts(
            [_conflict(message="Irreconcilable constraint")],
        )
        assert "Irreconcilable constraint" in s.getvalue()


# ---------------------------------------------------------------------------
# Tests: render_error / render_not_found
# ---------------------------------------------------------------------------


class TestRenderError:
    """Test error and not-found rendering via Rich."""

    def test_error(self) -> None:
        """Render error message."""
        r, s = _renderer()
        r.render_error("Something went wrong")
        out = s.getvalue()
        assert "Error" in out
        assert "Something went wrong" in out

    def test_not_found(self) -> None:
        """Render not-found message with package name."""
        r, s = _renderer()
        r.render_not_found("nonexistent-pkg")
        out = s.getvalue()
        assert "nonexistent-pkg" in out
        assert "not found" in out


# ---------------------------------------------------------------------------
# Tests: render_vulns
# ---------------------------------------------------------------------------


class TestRenderVulns:
    """Test vulnerability Rich rendering."""

    def test_no_vulnerabilities(self) -> None:
        """Show 'no known vulnerabilities' panel."""
        r, s = _renderer()
        r.render_vulns(_report())
        out = s.getvalue()
        assert "No known vulnerabilities" in out

    def test_vulnerability_in_table(self) -> None:
        """Render vulnerability ID and summary in table."""
        v = _vuln(
            vuln_id="GHSA-abcd",
            summary="SQL injection",
            aliases=["CVE-2024-1234"],
            severity_label="HIGH",
            fixed_versions=["2.31.0"],
        )
        r, s = _renderer()
        r.render_vulns(_report(vulns=[v]))
        out = s.getvalue()
        assert "GHSA-abcd" in out
        assert "CVE-2024-1234" in out
        assert "SQL injection" in out
        assert "2.31.0" in out

    def test_recommendation(self) -> None:
        """Show upgrade recommendation."""
        v = _vuln(fixed_versions=["3.0.0"])
        r, s = _renderer()
        r.render_vulns(_report(vulns=[v]))
        assert "3.0.0" in s.getvalue()
        assert "Suggested upgrade" in s.getvalue()

    def test_recommendation_notes_unfixed_advisories(self) -> None:
        """Call out advisories that do not list a fixed version."""
        fixed = _vuln(vuln_id="GHSA-fixed", fixed_versions=["3.0.0"])
        unfixed = _vuln(vuln_id="GHSA-unfixed", fixed_versions=[])
        r, s = _renderer()
        r.render_vulns(_report(vulns=[fixed, unfixed]))
        out = s.getvalue()
        assert "Suggested upgrade" in out
        assert "1 advisory has no fixed version listed." in out

    def test_no_recommendation_without_fixes(self) -> None:
        """No recommendation when no fixed versions exist."""
        v = _vuln(fixed_versions=[])
        r, s = _renderer()
        r.render_vulns(_report(vulns=[v]))
        assert "Suggested upgrade" not in s.getvalue()

    def test_header_includes_count(self) -> None:
        """Header shows vulnerability count."""
        vulns = [_vuln(vuln_id="GHSA-1"), _vuln(vuln_id="GHSA-2")]
        r, s = _renderer()
        r.render_vulns(_report(vulns=vulns))
        assert "2 found" in s.getvalue()

    def test_cvss_type_fallback(self) -> None:
        """Fall back to CVSS type when no severity label."""
        v = VulnerabilityInfo(
            id="GHSA-cvss",
            severity=[CvssSeverity(type="CVSS_V3", score="CVSS:3.1/AV:N")],
        )
        r, s = _renderer()
        r.render_vulns(_report(vulns=[v]))
        assert "CVSS V3" in s.getvalue()


# ---------------------------------------------------------------------------
# Tests: Console configuration
# ---------------------------------------------------------------------------


class TestConsoleConfig:
    """Test that Console is configured correctly for consistent styling."""

    def test_highlight_disabled(self) -> None:
        """Console has auto-highlighting disabled to prevent random coloring."""
        r, _ = _renderer()
        assert r._console._highlight is False

    def test_theme_attached(self) -> None:
        """Console uses the peeq theme with expected styles."""
        r, _ = _renderer()
        style = r._console.get_style("version")
        assert style.color is not None


# ---------------------------------------------------------------------------
# Tests: render_deps_diff
# ---------------------------------------------------------------------------


class TestRenderDepsDiff:
    """Test dependency diff rendering via Rich."""

    def test_changed_deps(self) -> None:
        """Render changed dependencies with version transitions."""
        r, s = _renderer()
        diff = _deps_diff(
            changed=[
                _dep_change(
                    name="urllib3",
                    old_specifier=">=1.21",
                    new_specifier=">=2.0",
                ),
            ],
            unchanged_count=3,
        )
        r.render_deps_diff("requests", "2.30.0", "2.31.0", diff)
        out = s.getvalue()
        assert "Dependency changes" in out
        assert "requests" in out
        assert "urllib3" in out
        assert ">=1.21" in out
        assert ">=2.0" in out

    def test_changed_markers(self) -> None:
        """Render marker changes for a dependency."""
        r, s = _renderer()
        diff = _deps_diff(
            changed=[
                _dep_change(
                    name="typing-extensions",
                    old_specifier=">=3.7",
                    new_specifier=">=3.7",
                    old_markers='python_version < "3.10"',
                    new_markers='python_version < "3.11"',
                ),
            ],
        )
        r.render_deps_diff("pkg", "1.0", "2.0", diff)
        out = s.getvalue()
        assert "markers:" in out

    def test_added_and_removed(self) -> None:
        """Render added and removed dependencies."""
        r, s = _renderer()
        diff = _deps_diff(
            added=[_dep("new-dep", ">=1.0")],
            removed=[_dep("old-dep", ">=0.5")],
        )
        r.render_deps_diff("pkg", "1.0", "2.0", diff)
        out = s.getvalue()
        assert "Added" in out
        assert "new-dep" in out
        assert "Removed" in out
        assert "old-dep" in out

    def test_empty_diff(self) -> None:
        """Render an empty diff with (none) for all sections."""
        r, s = _renderer()
        diff = _deps_diff(unchanged_count=5)
        r.render_deps_diff("pkg", "1.0", "2.0", diff)
        out = s.getvalue()
        assert "(none)" in out
        assert "Unchanged" in out
        assert "5" in out

    def test_tag_parameter(self) -> None:
        """Tag label appears in header."""
        r, s = _renderer()
        diff = _deps_diff()
        r.render_deps_diff("pkg", "1.0", "2.0", diff, tag="3.0.0 vs 2.0.0")
        assert "3.0.0 vs 2.0.0" in s.getvalue()

    def test_extras_groups(self) -> None:
        """Render added and removed extras groups."""
        r, s = _renderer()
        diff = _deps_diff(
            added_extras=["http2", "socks"],
            removed_extras=["dev"],
        )
        r.render_deps_diff("pkg", "1.0", "2.0", diff)
        out = s.getvalue()
        assert "http2" in out
        assert "socks" in out
        assert "dev" in out

    def test_unchanged_singular(self) -> None:
        """Render singular 'dependency' when count is 1."""
        r, s = _renderer()
        diff = _deps_diff(unchanged_count=1)
        r.render_deps_diff("pkg", "1.0", "2.0", diff)
        assert "1 dependency" in s.getvalue()


# ---------------------------------------------------------------------------
# Tests: render_versions with matching filter
# ---------------------------------------------------------------------------


class TestRenderVersionsMatching:
    """Test version list rendering with a version filter."""

    def test_matching_filter_no_truncation(self) -> None:
        """All matching versions shown — header omits 'showing'."""
        r, s = _renderer()
        versions = [
            VersionInfo(version=Version("2.31.0")),
            VersionInfo(version=Version("2.30.0")),
        ]
        r.render_versions(
            "requests",
            versions,
            total=2,
            matching=">=2.0",
            original_total=100,
        )
        out = s.getvalue()
        assert "2 of 100 matching >=2.0" in out

    def test_matching_filter_with_truncation(self) -> None:
        """Matching + limit: header shows showing, matched, and total."""
        r, s = _renderer()
        versions = [VersionInfo(version=Version("3.0.0"))]
        r.render_versions(
            "requests",
            versions,
            total=50,
            matching=">=2.0",
            original_total=200,
        )
        out = s.getvalue()
        assert "showing 1 of 50 matching >=2.0" in out
        assert "200 total" in out


# ---------------------------------------------------------------------------
# Tests: security — Rich markup injection prevention
# ---------------------------------------------------------------------------


class TestRichMarkupInjection:
    """Verify that attacker-controlled data cannot inject Rich markup."""

    def test_summary_rich_markup_injection(self) -> None:
        """Summary with Rich link markup does not create a clickable link."""
        r, s = _renderer()
        payload = "[link=https://evil.com]Click here[/link]"
        r.render_info(_info_report(summary=payload))
        out = s.getvalue()
        # If properly escaped, the literal bracket text appears in output.
        # If NOT escaped, Rich interprets it as a link tag and only
        # "Click here" appears (without surrounding bracket syntax).
        assert "[link=https://evil.com]" in out


# ---------------------------------------------------------------------------
# Tests: render_ls
# ---------------------------------------------------------------------------


class TestRenderLs:
    """Test archive directory listing rendering via Rich."""

    def test_table_rendered(self) -> None:
        """Output contains 'Archive contents' in table title."""
        r, s = _renderer()
        entries = [_ls_entry(path="setup.py", is_dir=False, size=42)]
        r.render_ls("pkg", "1.0.0", entries, total=1)
        out = s.getvalue()
        assert "Archive contents" in out

    def test_directory_details(self) -> None:
        """Directory shows file count in details column."""
        r, s = _renderer()
        entries = [
            _ls_entry(path="src/", is_dir=True, file_count=5, subdir_count=2),
        ]
        r.render_ls("pkg", "1.0.0", entries, total=1)
        out = s.getvalue()
        assert "5 files" in out
        assert "2 subdirs" in out

    def test_file_size(self) -> None:
        """File shows formatted size in details."""
        r, s = _renderer()
        entries = [_ls_entry(path="main.py", is_dir=False, size=2048)]
        r.render_ls("pkg", "1.0.0", entries, total=1)
        out = s.getvalue()
        assert "2.0 KB" in out

    def test_empty_archive(self) -> None:
        """Empty archive shows dim 'Archive is empty' message."""
        r, s = _renderer()
        r.render_ls("pkg", "1.0.0", [], total=0)
        out = s.getvalue()
        assert "Archive is empty" in out

    def test_truncated_header(self) -> None:
        """Showing < total shows 'showing X of Y' in title."""
        r, s = _renderer()
        entries = [_ls_entry(path="a.py", is_dir=False, size=10)]
        r.render_ls("pkg", "1.0.0", entries, total=50)
        out = s.getvalue()
        assert "showing" in out
        assert "1" in out
        assert "50" in out

    def test_directories_before_files(self) -> None:
        """Directories appear before files in output."""
        r, s = _renderer()
        entries = [
            _ls_entry(path="src/", is_dir=True, file_count=3),
            _ls_entry(path="setup.py", is_dir=False, size=100),
        ]
        r.render_ls("pkg", "1.0.0", entries, total=2)
        out = s.getvalue()
        dir_pos = out.index("src/")
        file_pos = out.index("setup.py")
        assert dir_pos < file_pos


class TestRenderLsRecursive:
    """Test recursive archive listing rendering via Rich."""

    def test_recursive_table(self) -> None:
        """Recursive listing shows file paths in table."""
        r, s = _renderer()
        entries = [
            _ls_entry(path="src/main.py", is_dir=False, size=100),
            _ls_entry(path="src/util.py", is_dir=False, size=200),
        ]
        r.render_ls("pkg", "1.0.0", entries, total=2, recursive=True)
        out = s.getvalue()
        assert "src/main.py" in out
        assert "src/util.py" in out


class TestRenderLsGlob:
    """Test glob-related messages in Rich rendering."""

    def test_no_matches_shows_glob_message(self) -> None:
        """Empty results with glob shows match-failure message, not empty archive."""
        r, s = _renderer()
        r.render_ls("pkg", "1.0.0", [], total=0, glob_patterns=["*.rs"])
        out = s.getvalue()
        assert "No files matched glob" in out
        assert "*.rs" in out
        assert "Archive is empty" not in out


# ---------------------------------------------------------------------------
# Tests: render_file_content (extended)
# ---------------------------------------------------------------------------


class TestRenderFileContentExtended:
    """Test extended file content rendering via Rich with truncation support."""

    def test_truncated_text_renders(self) -> None:
        """Truncated text still shows syntax panel."""
        r, s = _renderer()
        r.render_file_content(
            "pkg",
            "1.0.0",
            "big.py",
            b"x = 1\n",
            truncated=True,
            total_size=5000,
        )
        out = s.getvalue()
        assert "x = 1" in out

    def test_binary_with_truncation(self) -> None:
        """Binary with truncated=True shows binary warning."""
        r, s = _renderer()
        r.render_file_content(
            "pkg",
            "1.0.0",
            "data.bin",
            b"\x89PNG\r\n\x1a\n",
            truncated=True,
            total_size=10000,
        )
        out = s.getvalue()
        assert "Binary" in out
