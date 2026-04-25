"""Unit tests for the plain output renderer (`peeq.output.plain`).

Tests capture `PlainRenderer` output via `io.StringIO` and assert
on clean, undecorated text content.  No ANSI codes, no XML tags, no
Rich formatting --- just plain readable text.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest
from packaging.version import Version

from peeq.models import (
    CvssSeverity,
    DistType,
    VersionInfo,
    VulnerabilityInfo,
)
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
    _report,
    _solver_result,
    _vuln,
)
from tests.test_output._helpers import (
    _plain_renderer as _renderer,
)

# ---------------------------------------------------------------------------
# No XML tags / no Markdown table  (consolidated parametrized check)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("render_fn", "forbidden"),
    [
        pytest.param(
            lambda r: r.render_info(_info_report()),
            ["<package-info"],
            id="render_info",
        ),
        pytest.param(
            lambda r: r.render_versions(
                "pkg", [VersionInfo(version=Version("1.0.0"))], total=1
            ),
            ["<versions"],
            id="render_versions",
        ),
        pytest.param(
            lambda r: r.render_deps(
                "pkg", "1.0.0", _metadata(dependencies=[_dep("click")])
            ),
            ["<dependencies"],
            id="render_deps",
        ),
        pytest.param(
            lambda r: r.render_artifacts("requests", "2.31.0", [_file_info()]),
            ["<files", "|", "---"],
            id="render_artifacts",
        ),
        pytest.param(
            lambda r: r.render_file_content("pkg", "1.0.0", "f.py", b"x = 1"),
            ["<file-content"],
            id="render_file_content",
        ),
        pytest.param(
            lambda r: r.render_cache_info(_cache_stats()),
            ["<cache-info"],
            id="render_cache_info",
        ),
        pytest.param(
            lambda r: r.render_cache_clear(5, 1000),
            ["<cache-clear"],
            id="render_cache_clear",
        ),
        pytest.param(
            lambda r: r.render_cache_check({"key": "val"}),
            ["<cache-check"],
            id="render_cache_check",
        ),
        pytest.param(
            lambda r: r.render_resolve(_solver_result()),
            ["<resolution"],
            id="render_resolve",
        ),
        pytest.param(
            lambda r: r.render_conflicts([_conflict()]),
            ["<conflicts"],
            id="render_conflicts",
        ),
        pytest.param(
            lambda r: r.render_error("fail"),
            ["<error"],
            id="render_error",
        ),
        pytest.param(
            lambda r: r.render_not_found("pkg"),
            ["<not-found"],
            id="render_not_found",
        ),
        pytest.param(
            lambda r: r.render_vulns(_report(vulns=[_vuln()])),
            ["<vulnerabilities"],
            id="render_vulns",
        ),
        pytest.param(
            lambda r: r.render_ls("pkg", "1.0.0", [_ls_entry()], total=1),
            ["<archive-contents"],
            id="render_ls",
        ),
    ],
)
def test_no_xml_tags(render_fn: object, forbidden: list[str]) -> None:
    """Plain output contains no XML/agent-format tags or Markdown tables."""
    r, s = _renderer()
    render_fn(r)  # type: ignore[operator]
    out = s.getvalue()
    for pattern in forbidden:
        assert pattern not in out, f"Found {pattern!r} in plain output"


# ---------------------------------------------------------------------------
# Tests: render_info
# ---------------------------------------------------------------------------


class TestRenderInfo:
    """Test package info rendering."""

    def test_basic(self) -> None:
        """Render package info as key-value lines."""
        r, s = _renderer()
        r.render_info(_info_report())
        out = s.getvalue()
        assert "Package: requests" in out
        assert "Latest Version: 2.31.0" in out
        assert "Versions: 142" in out
        assert "Registry: pypi.org" in out

    def test_with_summary(self) -> None:
        """Summary is included in output."""
        r, s = _renderer()
        r.render_info(_info_report(summary="HTTP for Humans"))
        assert "Summary: HTTP for Humans" in s.getvalue()

    def test_without_summary(self) -> None:
        """No summary line when summary is None."""
        r, s = _renderer()
        r.render_info(_info_report(summary=None))
        assert "Summary:" not in s.getvalue()


# ---------------------------------------------------------------------------
# Tests: render_versions
# ---------------------------------------------------------------------------


class TestRenderVersions:
    """Test version list rendering."""

    def test_full_list(self) -> None:
        """Render all versions as a dash list."""
        r, s = _renderer()
        versions = [
            VersionInfo(version=Version("2.31.0")),
            VersionInfo(version=Version("2.30.0")),
        ]
        r.render_versions("requests", versions, total=2)
        out = s.getvalue()
        assert "requests versions (2):" in out
        assert "- 2.31.0 (latest)" in out
        assert "- 2.30.0" in out

    def test_limited(self) -> None:
        """Showing count differs from total when limited."""
        r, s = _renderer()
        versions = [VersionInfo(version=Version("2.31.0"))]
        r.render_versions("requests", versions, total=142)
        out = s.getvalue()
        assert "showing 1 of 142" in out

    def test_yanked_indicator(self) -> None:
        """Yanked version shows '(yanked)' suffix."""
        r, s = _renderer()
        versions = [VersionInfo(version=Version("1.0.0"), yanked=True)]
        r.render_versions("pkg", versions, total=1)
        assert "(yanked)" in s.getvalue()

    def test_yanked_with_reason(self) -> None:
        """Yanked version with reason shows '(yanked: reason)' suffix."""
        r, s = _renderer()
        versions = [
            VersionInfo(
                version=Version("1.0.0"),
                yanked=True,
                yanked_reason="security fix",
            ),
        ]
        r.render_versions("pkg", versions, total=1)
        assert "(yanked: security fix)" in s.getvalue()


# ---------------------------------------------------------------------------
# Tests: render_deps
# ---------------------------------------------------------------------------


class TestRenderDeps:
    """Test dependency rendering."""

    def test_with_dependencies(self) -> None:
        """Render dependencies as a dash list."""
        r, s = _renderer()
        meta = _metadata(dependencies=[_dep("urllib3", ">=1.21"), _dep("certifi")])
        r.render_deps("requests", "2.31.0", meta)
        out = s.getvalue()
        assert "Dependencies for requests 2.31.0:" in out
        assert "- urllib3 >=1.21" in out
        assert "- certifi >=2.0" in out

    def test_with_tag(self) -> None:
        """Tag appears in header when provided."""
        r, s = _renderer()
        meta = _metadata(dependencies=[])
        r.render_deps("numpy", "1.26.0", meta, tag="cp312-cp312-win_amd64")
        assert "(cp312-cp312-win_amd64)" in s.getvalue()

    def test_no_dependencies(self) -> None:
        """Empty dependency list renders 'No dependencies'."""
        r, s = _renderer()
        meta = _metadata(dependencies=[])
        r.render_deps("empty-pkg", "1.0.0", meta)
        assert "No dependencies." in s.getvalue()

    def test_dynamic_dependencies(self) -> None:
        """None dependencies render 'unknown (Dynamic)' message."""
        r, s = _renderer()
        meta = _metadata(
            dependencies=None,
            dynamic_fields=["Requires-Dist"],
        )
        r.render_deps("dynamic-pkg", "1.0.0", meta)
        out = s.getvalue()
        assert "unknown" in out
        assert "Dynamic" in out
        assert "Requires-Dist" in out

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
        assert "Optional [socks]:" in out
        assert "pysocks" in out

    def test_source_provenance(self) -> None:
        """Source info is included when available."""
        r, s = _renderer()
        meta = _metadata(
            dependencies=[_dep("click")],
            source="pep658",
            source_filename="pkg-1.0-py3-none-any.whl",
        )
        r.render_deps("pkg", "1.0.0", meta)
        out = s.getvalue()
        assert "Source: pep658" in out
        assert "pkg-1.0-py3-none-any.whl" in out


# ---------------------------------------------------------------------------
# Tests: render_artifacts
# ---------------------------------------------------------------------------


class TestRenderArtifacts:
    """Test distribution artifact rendering."""

    def test_with_files(self) -> None:
        """Render files as a dash list with details."""
        r, s = _renderer()
        files = [
            _file_info(),
            _file_info(
                filename="requests-2.31.0-py3-none-any.whl",
                dist_type=DistType.WHEEL,
                size=62_000,
            ),
        ]
        r.render_artifacts("requests", "2.31.0", files)
        out = s.getvalue()
        assert "Distribution artifacts for requests 2.31.0:" in out
        assert "- requests-2.31.0.tar.gz (sdist," in out
        assert "- requests-2.31.0-py3-none-any.whl (wheel," in out

    def test_empty_files(self) -> None:
        """Empty file list renders appropriate message."""
        r, s = _renderer()
        r.render_artifacts("empty-pkg", "1.0.0", [])
        assert "No files for empty-pkg 1.0.0." in s.getvalue()

    def test_yanked_file(self) -> None:
        """Yanked files show reason in output."""
        r, s = _renderer()
        files = [_file_info(yanked=True, yanked_reason="security fix")]
        r.render_artifacts("requests", "2.31.0", files)
        assert "security fix" in s.getvalue()

    def test_version_yanked_warning(self) -> None:
        """Version-level yanked warning when all files are yanked."""
        r, s = _renderer()
        files = [
            _file_info(yanked=True, yanked_reason="broken"),
            _file_info(
                filename="pkg-1.0.0-py3-none-any.whl",
                dist_type=DistType.WHEEL,
                yanked=True,
                yanked_reason="broken",
            ),
        ]
        r.render_artifacts("pkg", "1.0.0", files)
        out = s.getvalue()
        assert "WARNING: Version" in out
        assert "has been yanked" in out


# ---------------------------------------------------------------------------
# Tests: render_file_content
# ---------------------------------------------------------------------------


class TestRenderFileContent:
    """Test file content rendering."""

    def test_text_content(self) -> None:
        """Render text file content without header."""
        r, s = _renderer()
        r.render_file_content("requests", "2.31.0", "setup.py", b"print('hello')")
        out = s.getvalue()
        assert "print('hello')" in out

    def test_binary_content(self) -> None:
        """Binary file content shows size indicator."""
        r, s = _renderer()
        r.render_file_content("pkg", "1.0.0", "data.bin", b"\x89PNG\r\n\x1a\n")
        assert "Binary file" in s.getvalue()


# ---------------------------------------------------------------------------
# Tests: render_download
# ---------------------------------------------------------------------------


class TestRenderDownload:
    """Test download confirmation rendering."""

    def test_downloaded(self) -> None:
        """Render download confirmation with path."""
        r, s = _renderer()
        r.render_download(Path("/tmp/requests-2.31.0.tar.gz"))
        out = s.getvalue()
        assert "Downloaded to:" in out
        assert "requests-2.31.0.tar.gz" in out

    def test_extracted(self) -> None:
        """Render extraction confirmation."""
        r, s = _renderer()
        r.render_download(Path("/tmp/requests-2.31.0"), extracted=True)
        assert "Extracted to:" in s.getvalue()


# ---------------------------------------------------------------------------
# Tests: render_cache_info
# ---------------------------------------------------------------------------


class TestRenderCacheInfo:
    """Test cache statistics rendering."""

    def test_basic(self) -> None:
        """Render cache stats as key-value lines."""
        r, s = _renderer()
        r.render_cache_info(_cache_stats())
        out = s.getvalue()
        assert "Packages: 15" in out
        assert "Archives: 20 distributions" in out
        assert "Metadata only: 3 distributions" in out

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
    """Test cache clear result rendering."""

    def test_cleared(self) -> None:
        """Render cleared count and size."""
        r, s = _renderer()
        r.render_cache_clear(8, 12_100_000)
        out = s.getvalue()
        assert "Cleared 8 entries" in out

    def test_nothing_cleared(self) -> None:
        """Render message when nothing was cleared."""
        r, s = _renderer()
        r.render_cache_clear(0, 0)
        assert "No entries to clear." in s.getvalue()


# ---------------------------------------------------------------------------
# Tests: render_cache_dump
# ---------------------------------------------------------------------------


class TestRenderCacheDump:
    """Test cache dump rendering."""

    def test_json_output(self) -> None:
        """Render cache dump as plain JSON."""
        r, s = _renderer()
        data = {"packages": [{"name": "requests"}]}
        r.render_cache_dump(data)
        out = s.getvalue()
        assert "requests" in out


# ---------------------------------------------------------------------------
# Tests: render_cache_check
# ---------------------------------------------------------------------------


class TestRenderCacheCheck:
    """Test cache diagnostics rendering."""

    def test_diagnostics(self) -> None:
        """Render diagnostics as key-value lines."""
        r, s = _renderer()
        diag = {"journal_mode": "wal", "synchronous": 1, "quick_check": "ok"}
        r.render_cache_check(diag)
        out = s.getvalue()
        assert "journal_mode: wal" in out
        assert "quick_check: ok" in out


# ---------------------------------------------------------------------------
# Tests: render_resolve
# ---------------------------------------------------------------------------


class TestRenderResolve:
    """Test dependency resolution rendering."""

    def test_basic(self) -> None:
        """Render resolved packages as a dash list sorted by name."""
        r, s = _renderer()
        r.render_resolve(_solver_result())
        out = s.getvalue()
        assert "Resolved 2 packages:" in out
        assert "flask==3.0.0" in out
        assert "werkzeug==3.0.1" in out
        assert "Solver: uv" in out


# ---------------------------------------------------------------------------
# Tests: render_conflicts
# ---------------------------------------------------------------------------


class TestRenderConflicts:
    """Test conflict rendering."""

    def test_conflict(self) -> None:
        """Render conflict details as plain text."""
        r, s = _renderer()
        r.render_conflicts([_conflict()])
        out = s.getvalue()
        assert "CONFLICT: numpy" in out
        assert "tensorflow" in out
        assert "torch" in out

    def test_conflict_message(self) -> None:
        """Per-conflict message is included."""
        r, s = _renderer()
        r.render_conflicts([_conflict(message="Constraint clash")])
        assert "Constraint clash" in s.getvalue()


# ---------------------------------------------------------------------------
# Tests: render_error / render_not_found
# ---------------------------------------------------------------------------


class TestRenderError:
    """Test error and not-found rendering."""

    def test_error(self) -> None:
        """Render error as plain text."""
        r, s = _renderer()
        r.render_error("Something went wrong")
        out = s.getvalue()
        assert "Error: Something went wrong" in out

    def test_not_found(self) -> None:
        """Render not-found as plain text."""
        r, s = _renderer()
        r.render_not_found("nonexistent-pkg")
        out = s.getvalue()
        assert "Package 'nonexistent-pkg' not found." in out


# ---------------------------------------------------------------------------
# Tests: render_vulns
# ---------------------------------------------------------------------------


class TestRenderVulns:
    """Test vulnerability plain text rendering."""

    def test_header(self) -> None:
        """Output includes package name and version in header."""
        r, s = _renderer()
        r.render_vulns(_report())
        out = s.getvalue()
        assert "requests" in out
        assert "2.25.0" in out

    def test_no_vulnerabilities(self) -> None:
        """Show 'no known vulnerabilities' message."""
        r, s = _renderer()
        r.render_vulns(_report())
        assert "No known vulnerabilities" in s.getvalue()

    def test_vulnerability_fields(self) -> None:
        """Render vulnerability ID, CVE, severity, summary, fixed version."""
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
        assert "ID: GHSA-abcd" in out
        assert "CVE: CVE-2024-1234" in out
        assert "Severity: HIGH" in out
        assert "Summary: SQL injection" in out
        assert "Fixed in: 2.31.0" in out

    def test_recommendation(self) -> None:
        """Show upgrade recommendation."""
        v = _vuln(fixed_versions=["3.0.0"])
        r, s = _renderer()
        r.render_vulns(_report(vulns=[v]))
        assert "Recommendation: Upgrade to >= 3.0.0" in s.getvalue()

    def test_no_recommendation_without_fixes(self) -> None:
        """No recommendation when no fixed versions exist."""
        v = _vuln(fixed_versions=[])
        r, s = _renderer()
        r.render_vulns(_report(vulns=[v]))
        assert "Recommendation" not in s.getvalue()

    def test_cvss_type_fallback(self) -> None:
        """Fall back to CVSS type when no severity label."""
        v = VulnerabilityInfo(
            id="GHSA-cvss",
            severity=[CvssSeverity(type="CVSS_V3", score="CVSS:3.1/AV:N")],
        )
        r, s = _renderer()
        r.render_vulns(_report(vulns=[v]))
        assert "Severity: CVSS V3" in s.getvalue()

    def test_no_cve_line_when_empty(self) -> None:
        """Skip CVE line when no CVE aliases exist."""
        v = _vuln(aliases=["GHSA-other"])
        r, s = _renderer()
        r.render_vulns(_report(vulns=[v]))
        assert "CVE:" not in s.getvalue()


# ---------------------------------------------------------------------------
# Tests: render_deps_diff
# ---------------------------------------------------------------------------


class TestRenderDepsDiff:
    """Test dependency diff rendering."""

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
        assert "Dependency changes for requests" in out
        assert "2.30.0 -> 2.31.0" in out
        assert "urllib3" in out
        assert ">=1.21 -> >=2.0" in out

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
        assert '< "3.10"' in out
        assert '< "3.11"' in out

    def test_changed_extras(self) -> None:
        """Render extras changes for a dependency."""
        r, s = _renderer()
        diff = _deps_diff(
            changed=[
                _dep_change(
                    name="httpx",
                    old_specifier=">=0.24",
                    new_specifier=">=0.28",
                    old_extras=(),
                    new_extras=("http2",),
                ),
            ],
        )
        r.render_deps_diff("pkg", "1.0", "2.0", diff)
        out = s.getvalue()
        assert "extras:" in out
        assert "(none)" in out
        assert "[http2]" in out

    def test_added_and_removed(self) -> None:
        """Render added and removed dependencies."""
        r, s = _renderer()
        diff = _deps_diff(
            added=[_dep("new-dep", ">=1.0")],
            removed=[_dep("old-dep", ">=0.5")],
        )
        r.render_deps_diff("pkg", "1.0", "2.0", diff)
        out = s.getvalue()
        assert "Added:" in out
        assert "new-dep" in out
        assert "Removed:" in out
        assert "old-dep" in out

    def test_empty_diff(self) -> None:
        """Render an empty diff with all sections showing (none)."""
        r, s = _renderer()
        diff = _deps_diff(unchanged_count=5)
        r.render_deps_diff("pkg", "1.0", "2.0", diff)
        out = s.getvalue()
        assert out.count("(none)") == 3
        assert "Unchanged: 5 dependencies" in out

    def test_unchanged_singular(self) -> None:
        """Render singular 'dependency' when count is 1."""
        r, s = _renderer()
        diff = _deps_diff(unchanged_count=1)
        r.render_deps_diff("pkg", "1.0", "2.0", diff)
        assert "Unchanged: 1 dependency" in out if (out := s.getvalue()) else False

    def test_tag_parameter(self) -> None:
        """Tag appears in header when provided."""
        r, s = _renderer()
        diff = _deps_diff()
        r.render_deps_diff("pkg", "1.0", "2.0", diff, tag="3.0.0 vs 2.0.0")
        assert "(3.0.0 vs 2.0.0)" in s.getvalue()

    def test_extras_groups(self) -> None:
        """Render added and removed extras groups."""
        r, s = _renderer()
        diff = _deps_diff(
            added_extras=["http2", "socks"],
            removed_extras=["dev"],
        )
        r.render_deps_diff("pkg", "1.0", "2.0", diff)
        out = s.getvalue()
        assert "Added extras groups: http2, socks" in out
        assert "Removed extras groups: dev" in out

    def test_extras_group_on_change(self) -> None:
        """Extras group annotation appears on changed deps."""
        r, s = _renderer()
        diff = _deps_diff(
            changed=[
                _dep_change(
                    name="boto3",
                    old_specifier=">=1.0",
                    new_specifier=">=2.0",
                    extras_group="aws",
                ),
            ],
        )
        r.render_deps_diff("pkg", "1.0", "2.0", diff)
        assert "[aws]" in s.getvalue()


# ---------------------------------------------------------------------------
# Tests: render_versions with matching filter
# ---------------------------------------------------------------------------


class TestRenderVersionsMatching:
    """Test version list rendering with a version filter."""

    def test_matching_filter(self) -> None:
        """Render versions with matching filter info."""
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


# ---------------------------------------------------------------------------
# Tests: render_ls
# ---------------------------------------------------------------------------


class TestRenderLs:
    """Test archive directory listing rendering."""

    def test_mixed_entries(self) -> None:
        """Render directory and file entries with details."""
        r, s = _renderer()
        entries = [
            _ls_entry(
                path="src/", is_dir=True, file_count=5, subdir_count=2, total_size=1024
            ),
            _ls_entry(path="setup.py", is_dir=False, size=200),
        ]
        r.render_ls("pkg", "1.0.0", entries, total=2)
        out = s.getvalue()
        assert "src/" in out
        assert "directory" in out
        assert "5 files" in out
        assert "2 subdirs" in out
        assert "setup.py" in out

    def test_directory_with_subdirs(self) -> None:
        """Directory with subdir_count > 0 shows subdirs in detail."""
        r, s = _renderer()
        entries = [
            _ls_entry(path="src/", is_dir=True, file_count=10, subdir_count=3),
        ]
        r.render_ls("pkg", "1.0.0", entries, total=1)
        out = s.getvalue()
        assert "10 files" in out
        assert "3 subdirs" in out

    def test_directory_without_subdirs(self) -> None:
        """Directory with subdir_count=0 omits subdirs from detail."""
        r, s = _renderer()
        entries = [
            _ls_entry(path="src/", is_dir=True, file_count=4, subdir_count=0),
        ]
        r.render_ls("pkg", "1.0.0", entries, total=1)
        out = s.getvalue()
        assert "4 files" in out
        assert "subdirs" not in out

    def test_empty_archive(self) -> None:
        """Empty archive shows (0 entries) in header."""
        r, s = _renderer()
        r.render_ls("pkg", "1.0.0", [], total=0)
        out = s.getvalue()
        assert "(0 entries):" in out

    def test_only_files(self) -> None:
        """File-only listing has no 'directory' in output."""
        r, s = _renderer()
        entries = [
            _ls_entry(path="README.md", is_dir=False, size=100),
            _ls_entry(path="setup.py", is_dir=False, size=200),
        ]
        r.render_ls("pkg", "1.0.0", entries, total=2)
        out = s.getvalue()
        assert "directory" not in out

    def test_only_directories(self) -> None:
        """Directory-only listing shows (directory, ...) for each entry."""
        r, s = _renderer()
        entries = [
            _ls_entry(path="src/", is_dir=True, file_count=3, subdir_count=0),
            _ls_entry(path="tests/", is_dir=True, file_count=7, subdir_count=1),
        ]
        r.render_ls("pkg", "1.0.0", entries, total=2)
        out = s.getvalue()
        assert "(directory," in out
        assert "src/" in out
        assert "tests/" in out

    def test_with_prefix(self) -> None:
        """Prefix appears in header as 'under prefix'."""
        r, s = _renderer()
        entries = [_ls_entry(path="src/main.py", is_dir=False, size=50)]
        r.render_ls("pkg", "1.0.0", entries, total=1, prefix="src/")
        out = s.getvalue()
        assert "under src/" in out

    def test_truncated(self) -> None:
        """Showing < total shows 'X of Y entries' in header."""
        r, s = _renderer()
        entries = [_ls_entry(path="a.py", is_dir=False, size=10)]
        r.render_ls("pkg", "1.0.0", entries, total=50)
        out = s.getvalue()
        assert "1 of 50 entries" in out

    def test_not_truncated(self) -> None:
        """Showing == total shows just the count in header."""
        r, s = _renderer()
        entries = [
            _ls_entry(path="a.py", is_dir=False, size=10),
            _ls_entry(path="b.py", is_dir=False, size=20),
        ]
        r.render_ls("pkg", "1.0.0", entries, total=2)
        out = s.getvalue()
        assert "2 entries" in out
        assert " of " not in out

    def test_single_entry(self) -> None:
        """Single file entry renders correctly."""
        r, s = _renderer()
        entries = [_ls_entry(path="hello.py", is_dir=False, size=42)]
        r.render_ls("pkg", "1.0.0", entries, total=1)
        out = s.getvalue()
        assert "hello.py" in out
        assert "42 B" in out

    def test_trailing_slash_on_dirs(self) -> None:
        """Directory paths end with / in output."""
        r, s = _renderer()
        entries = [_ls_entry(path="lib/", is_dir=True, file_count=2)]
        r.render_ls("pkg", "1.0.0", entries, total=1)
        out = s.getvalue()
        assert "lib/" in out


class TestRenderLsRecursive:
    """Test recursive archive listing rendering."""

    def test_recursive_file_listing(self) -> None:
        """Recursive listing shows files with sizes."""
        r, s = _renderer()
        entries = [
            _ls_entry(path="src/main.py", is_dir=False, size=100),
            _ls_entry(path="src/util.py", is_dir=False, size=200),
        ]
        r.render_ls("pkg", "1.0.0", entries, total=2, recursive=True)
        out = s.getvalue()
        assert "src/main.py" in out
        assert "src/util.py" in out

    def test_recursive_truncated(self) -> None:
        """Truncated recursive listing shows counts."""
        r, s = _renderer()
        entries = [_ls_entry(path="a.py", is_dir=False, size=10)]
        r.render_ls("pkg", "1.0.0", entries, total=100, recursive=True)
        out = s.getvalue()
        assert "1 of 100 entries" in out

    def test_recursive_with_prefix(self) -> None:
        """Prefix appears in header with recursive listing."""
        r, s = _renderer()
        entries = [_ls_entry(path="src/a.py", is_dir=False, size=10)]
        r.render_ls("pkg", "1.0.0", entries, total=1, prefix="src/", recursive=True)
        out = s.getvalue()
        assert "under src/" in out


# ---------------------------------------------------------------------------
# Tests: render_file_content (extended)
# ---------------------------------------------------------------------------


class TestRenderFileContentExtended:
    """Test extended file content rendering with truncation support."""

    def test_truncated_text_renders_content(self) -> None:
        """Truncated text still renders the content."""
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

    def test_truncated_defaults_unchanged(self) -> None:
        """Default truncated=False renders same as before."""
        r, s = _renderer()
        r.render_file_content("pkg", "1.0.0", "f.py", b"hello\n")
        out = s.getvalue()
        assert "hello" in out

    def test_binary_ignores_truncation(self) -> None:
        """Binary content with truncated=True still shows binary placeholder."""
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
        assert "Binary file" in out
