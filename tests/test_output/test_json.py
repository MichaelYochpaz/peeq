"""Unit tests for the JSON output renderer (`peeq.output.json`).

Tests capture `JSONRenderer` output via `io.StringIO`, parse it with
`json.loads()`, and assert on keys, types, and values.  Every render
method includes a `"command"` key (except errors).
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from packaging.version import Version

from peeq.models import (
    CvssSeverity,
    DistType,
    InfoReport,
    VersionInfo,
    VulnerabilityInfo,
    VulnerabilityReference,
)
from peeq.resolver.models import (
    ResolvedDependency,
    SolverResult,
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
    _pkg_info,
    _report,
    _solver_result,
    _vuln,
)
from tests.test_output._helpers import (
    _json_parse as _parse,
)
from tests.test_output._helpers import (
    _json_renderer as _renderer,
)

# ---------------------------------------------------------------------------
# Tests: render_info
# ---------------------------------------------------------------------------


class TestRenderInfo:
    """Test package info JSON rendering."""

    def test_basic(self) -> None:
        """Render package info with all fields as JSON."""
        r, s = _renderer()
        r.render_info(_info_report())
        data = _parse(s)
        assert data["command"] == "info"
        assert data["info"]["name"] == "requests"
        assert data["info"]["latest_version"] == "2.31.0"
        assert data["info"]["version_count"] == 142
        assert data["info"]["summary"] == "HTTP for Humans"
        assert data["info"]["registry"] == "pypi.org"

    def test_null_summary(self) -> None:
        """Null summary is excluded from JSON output."""
        r, s = _renderer()
        r.render_info(_info_report(summary=None))
        data = _parse(s)
        assert "summary" not in data["info"]

    def test_yanked_fields_present(self) -> None:
        """Yanked fields appear in JSON when version is yanked."""
        r, s = _renderer()
        report = InfoReport(
            info=_pkg_info(),
            target_version="2.30.0",
            target_version_yanked=True,
            target_version_yanked_reason="Security issue",
        )
        r.render_info(report)
        data = _parse(s)
        assert data["target_version"] == "2.30.0"
        assert data["target_version_yanked"] is True
        assert data["target_version_yanked_reason"] == "Security issue"

    def test_yanked_false_included(self) -> None:
        """Checked-but-not-yanked emits false (not omitted)."""
        r, s = _renderer()
        report = InfoReport(
            info=_pkg_info(),
            target_version="2.31.0",
            target_version_yanked=False,
        )
        r.render_info(report)
        data = _parse(s)
        assert data["target_version_yanked"] is False
        assert "target_version_yanked_reason" not in data

    def test_yanked_unchecked_omitted(self) -> None:
        """Unchecked yanked status (None) is omitted from JSON."""
        r, s = _renderer()
        r.render_info(_info_report())
        data = _parse(s)
        assert "target_version_yanked" not in data
        assert "target_version_yanked_reason" not in data


# ---------------------------------------------------------------------------
# Tests: render_versions
# ---------------------------------------------------------------------------


class TestRenderVersions:
    """Test version list JSON rendering."""

    def test_basic(self) -> None:
        """Render version list with showing/total/truncated counts."""
        r, s = _renderer()
        versions = [
            VersionInfo(version=Version("2.31.0")),
            VersionInfo(version=Version("2.30.0")),
        ]
        r.render_versions("requests", versions, total=142)
        data = _parse(s)
        assert data["command"] == "versions"
        assert data["name"] == "requests"
        assert len(data["versions"]) == 2
        assert data["versions"][0]["version"] == "2.31.0"
        assert data["versions"][1]["version"] == "2.30.0"
        assert data["showing"] == 2
        assert data["total"] == 142
        assert data["truncated"] is True

    def test_not_truncated(self) -> None:
        """truncated is false when showing all versions."""
        r, s = _renderer()
        versions = [VersionInfo(version=Version("1.0.0"))]
        r.render_versions("pkg", versions, total=1)
        data = _parse(s)
        assert data["truncated"] is False

    def test_version_object_structure(self) -> None:
        """Version entries are objects with version, yanked, yanked_reason."""
        r, s = _renderer()
        versions = [VersionInfo(version=Version("1.0.0"))]
        r.render_versions("pkg", versions, total=1)
        data = _parse(s)
        v = data["versions"][0]
        assert "version" in v
        assert "yanked" in v
        assert "yanked_reason" in v
        assert v["version"] == "1.0.0"
        assert v["yanked"] is False
        assert v["yanked_reason"] is None

    def test_yanked_version(self) -> None:
        """Yanked version has yanked=true and reason in JSON."""
        r, s = _renderer()
        versions = [
            VersionInfo(
                version=Version("1.0.0"),
                yanked=True,
                yanked_reason="security fix",
            ),
        ]
        r.render_versions("pkg", versions, total=1)
        data = _parse(s)
        v = data["versions"][0]
        assert v["yanked"] is True
        assert v["yanked_reason"] == "security fix"


# ---------------------------------------------------------------------------
# Tests: render_deps
# ---------------------------------------------------------------------------


class TestRenderDeps:
    """Test dependency JSON rendering."""

    def test_with_dependencies(self) -> None:
        """Render dependencies with specifiers."""
        r, s = _renderer()
        meta = _metadata(dependencies=[_dep("urllib3", ">=1.21")])
        r.render_deps("requests", "2.31.0", meta)
        data = _parse(s)
        assert data["command"] == "deps"
        assert data["deps_known"] is True
        deps = data["dependencies"]
        assert len(deps) == 1
        assert deps[0]["name"] == "urllib3"
        assert deps[0]["specifier"] == ">=1.21"

    def test_with_tag(self) -> None:
        """Tag field is included when provided."""
        r, s = _renderer()
        meta = _metadata(dependencies=[])
        r.render_deps("numpy", "1.26.0", meta, tag="cp312-cp312-win_amd64")
        data = _parse(s)
        assert data["tag"] == "cp312-cp312-win_amd64"

    def test_no_dependencies(self) -> None:
        """Empty list renders as empty JSON array."""
        r, s = _renderer()
        meta = _metadata(dependencies=[])
        r.render_deps("pkg", "1.0.0", meta)
        data = _parse(s)
        assert data["dependencies"] == []
        assert data["deps_known"] is True

    def test_dynamic_dependencies(self) -> None:
        """None dependencies render as null with deps_known=false."""
        r, s = _renderer()
        meta = _metadata(
            dependencies=None,
            dynamic_fields=["Requires-Dist"],
        )
        r.render_deps("pkg", "1.0.0", meta)
        data = _parse(s)
        assert data["dependencies"] is None
        assert data["deps_known"] is False
        assert data["dynamic_fields"] == ["Requires-Dist"]

    def test_extras_on_dependency(self) -> None:
        """Dependency extras are included."""
        r, s = _renderer()
        meta = _metadata(
            dependencies=[_dep("httpx", ">=0.28", extras=["http2"])],
        )
        r.render_deps("pkg", "1.0.0", meta)
        data = _parse(s)
        assert data["dependencies"][0]["extras"] == ["http2"]

    def test_optional_extra_marker(self) -> None:
        """Dependencies with extra markers get optional_extra field."""
        r, s = _renderer()
        meta = _metadata(
            dependencies=[_dep("pysocks", markers='extra == "socks"')],
        )
        r.render_deps("pkg", "1.0.0", meta)
        data = _parse(s)
        assert data["dependencies"][0]["optional_extra"] == "socks"

    def test_source_provenance(self) -> None:
        """Source and source_filename are included when available."""
        r, s = _renderer()
        meta = _metadata(
            dependencies=[],
            source="pep658",
            source_filename="pkg-1.0-py3-none-any.whl",
        )
        r.render_deps("pkg", "1.0.0", meta)
        data = _parse(s)
        assert data["source"] == "pep658"
        assert data["source_filename"] == "pkg-1.0-py3-none-any.whl"


# ---------------------------------------------------------------------------
# Tests: render_artifacts
# ---------------------------------------------------------------------------


class TestRenderArtifacts:
    """Test distribution artifact JSON rendering."""

    def test_with_files(self) -> None:
        """Render file list with all fields."""
        r, s = _renderer()
        files = [_file_info(), _file_info(filename="pkg.whl", dist_type=DistType.WHEEL)]
        r.render_artifacts("requests", "2.31.0", files)
        data = _parse(s)
        assert data["command"] == "artifacts"
        assert len(data["artifacts"]) == 2
        assert data["artifacts"][0]["dist_type"] == "sdist"
        assert data["artifacts"][1]["dist_type"] == "wheel"

    def test_file_fields(self) -> None:
        """Each file entry has expected fields."""
        r, s = _renderer()
        files = [_file_info(yanked=True, yanked_reason="broken")]
        r.render_artifacts("pkg", "1.0.0", files)
        data = _parse(s)
        f = data["artifacts"][0]
        assert f["filename"] == "requests-2.31.0.tar.gz"
        assert f["size"] == 110_000
        assert f["requires_python"] == ">=3.7"
        assert f["yanked"] is True
        assert f["yanked_reason"] == "broken"

    def test_version_level_yanked_fields(self) -> None:
        """Top-level yanked fields when all files are yanked."""
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
        data = _parse(s)
        assert data["yanked"] is True
        assert data["yanked_reason"] == "broken release"

    def test_version_level_not_yanked(self) -> None:
        """Top-level yanked is false when not all files are yanked."""
        r, s = _renderer()
        files = [
            _file_info(yanked=True, yanked_reason="broken"),
            _file_info(filename="pkg-1.0.0-py3-none-any.whl", dist_type=DistType.WHEEL),
        ]
        r.render_artifacts("pkg", "1.0.0", files)
        data = _parse(s)
        assert data["yanked"] is False


# ---------------------------------------------------------------------------
# Tests: render_file_content
# ---------------------------------------------------------------------------


class TestRenderFileContent:
    """Test file content JSON rendering."""

    def test_text_content(self) -> None:
        """Render text file with content."""
        r, s = _renderer()
        r.render_file_content("pkg", "1.0.0", "setup.py", b"print('hello')")
        data = _parse(s)
        assert data["command"] == "cat"
        assert data["path"] == "setup.py"
        assert data["encoding"] == "utf-8"
        assert data["content"] == "print('hello')"
        assert data["size_bytes"] == 14

    def test_binary_content(self) -> None:
        """Binary content omits content field."""
        r, s = _renderer()
        r.render_file_content("pkg", "1.0.0", "data.bin", b"\x89PNG\r\n\x1a\n")
        data = _parse(s)
        assert data["encoding"] == "binary"
        assert "content" not in data
        assert data["size_bytes"] == 8


# ---------------------------------------------------------------------------
# Tests: render_download
# ---------------------------------------------------------------------------


class TestRenderDownload:
    """Test download result JSON rendering."""

    def test_downloaded(self) -> None:
        """Render download path and extracted flag."""
        r, s = _renderer()
        r.render_download(Path("/tmp/pkg-1.0.tar.gz"))
        data = _parse(s)
        assert data["command"] == "download"
        assert data["extracted"] is False

    def test_extracted(self) -> None:
        """Render extracted=true."""
        r, s = _renderer()
        r.render_download(Path("/tmp/pkg-1.0"), extracted=True)
        data = _parse(s)
        assert data["extracted"] is True


# ---------------------------------------------------------------------------
# Tests: render_cache_info
# ---------------------------------------------------------------------------


class TestRenderCacheInfo:
    """Test cache info JSON rendering."""

    def test_basic(self) -> None:
        """Render cache stats as JSON."""
        r, s = _renderer()
        r.render_cache_info(_cache_stats())
        data = _parse(s)
        assert data["command"] == "cache_info"
        assert data["package_count"] == 15
        assert data["distribution_count"] == 23
        assert data["archived_count"] == 20
        assert data["metadata_only_count"] == 3
        assert data["total_size_bytes"] == 45_200_000
        assert data["limit_bytes"] is None
        assert data["usage_percent"] is None

    def test_with_dates(self) -> None:
        """Date entries serialize as ISO format."""
        r, s = _renderer()
        stats = _cache_stats(
            oldest_entry=datetime(2024, 1, 15, 10, 30, tzinfo=timezone.utc),
            newest_entry=datetime(2024, 2, 8, 14, 0, tzinfo=timezone.utc),
        )
        r.render_cache_info(stats)
        data = _parse(s)
        assert data["oldest_entry"] == "2024-01-15T10:30:00+00:00"
        assert data["newest_entry"] == "2024-02-08T14:00:00+00:00"

    def test_without_dates(self) -> None:
        """Null dates serialize as JSON null."""
        r, s = _renderer()
        r.render_cache_info(_cache_stats())
        data = _parse(s)
        assert data["oldest_entry"] is None
        assert data["newest_entry"] is None


# ---------------------------------------------------------------------------
# Tests: render_cache_clear
# ---------------------------------------------------------------------------


class TestRenderCacheClear:
    """Test cache clear JSON rendering."""

    def test_cleared(self) -> None:
        """Render cleared count and size."""
        r, s = _renderer()
        r.render_cache_clear(8, 12_100_000)
        data = _parse(s)
        assert data["command"] == "cache_clear"
        assert data["count"] == 8
        assert data["total_size_bytes"] == 12_100_000

    def test_nothing_cleared(self) -> None:
        """Zero entries produces count=0."""
        r, s = _renderer()
        r.render_cache_clear(0, 0)
        data = _parse(s)
        assert data["count"] == 0


# ---------------------------------------------------------------------------
# Tests: render_cache_dump
# ---------------------------------------------------------------------------


class TestRenderCacheDump:
    """Test cache dump JSON rendering."""

    def test_passthrough(self) -> None:
        """Cache dump passes data through as JSON."""
        r, s = _renderer()
        data_in = {"packages": [{"name": "requests"}], "version": 2}
        r.render_cache_dump(data_in)
        data = _parse(s)
        assert data["packages"] == [{"name": "requests"}]
        assert data["version"] == 2


# ---------------------------------------------------------------------------
# Tests: render_cache_check
# ---------------------------------------------------------------------------


class TestRenderCacheCheck:
    """Test cache diagnostics JSON rendering."""

    def test_diagnostics(self) -> None:
        """Render diagnostics as JSON with command key."""
        r, s = _renderer()
        diag = {"journal_mode": "wal", "quick_check": "ok"}
        r.render_cache_check(diag)
        data = _parse(s)
        assert data["command"] == "cache_check"
        assert data["journal_mode"] == "wal"
        assert data["quick_check"] == "ok"


# ---------------------------------------------------------------------------
# Tests: render_resolve
# ---------------------------------------------------------------------------


class TestRenderResolve:
    """Test resolution result JSON rendering."""

    def test_basic(self) -> None:
        """Render resolved packages sorted by name."""
        r, s = _renderer()
        r.render_resolve(_solver_result())
        data = _parse(s)
        assert data["command"] == "resolve"
        assert data["solver"] == "uv"
        assert len(data["resolved"]) == 2
        # Sorted by name: flask before werkzeug
        assert data["resolved"][0]["name"] == "flask"
        assert data["resolved"][0]["version"] == "3.0.0"

    def test_resolved_dependencies(self) -> None:
        """Resolved packages include their dependency list."""
        r, s = _renderer()
        result = SolverResult(
            resolved=[
                ResolvedDependency(
                    name="flask",
                    version=Version("3.0.0"),
                    dependencies=["werkzeug", "jinja2"],
                ),
            ],
            solver_id="uv",
        )
        r.render_resolve(result)
        data = _parse(s)
        assert data["resolved"][0]["dependencies"] == ["werkzeug", "jinja2"]


# ---------------------------------------------------------------------------
# Tests: render_conflicts
# ---------------------------------------------------------------------------


class TestRenderConflicts:
    """Test conflict JSON rendering."""

    def test_conflict(self) -> None:
        """Render conflict details as JSON."""
        r, s = _renderer()
        r.render_conflicts([_conflict()])
        data = _parse(s)
        assert data["command"] == "conflicts"
        assert data["solver"] == "uv"
        assert len(data["conflicts"]) == 1
        c = data["conflicts"][0]
        assert c["package"] == "numpy"
        assert len(c["constraints"]) == 2
        req = c["constraints"][0]
        assert "required_by" in req
        assert "requires" in req
        assert "chain" in req

    def test_multiple_conflicts(self) -> None:
        """Multiple conflicts render as array."""
        r, s = _renderer()
        r.render_conflicts(
            [_conflict(), _conflict(package="scipy")],
        )
        data = _parse(s)
        assert len(data["conflicts"]) == 2


# ---------------------------------------------------------------------------
# Tests: render_error / render_not_found
# ---------------------------------------------------------------------------


class TestRenderError:
    """Test error and not-found JSON rendering."""

    def test_error(self) -> None:
        """Render error with error=true flag."""
        r, s = _renderer()
        r.render_error("Something went wrong")
        data = _parse(s)
        assert data["error"] is True
        assert data["message"] == "Something went wrong"

    def test_not_found(self) -> None:
        """Render not-found with package name."""
        r, s = _renderer()
        r.render_not_found("nonexistent-pkg")
        data = _parse(s)
        assert data["error"] is True
        assert data["name"] == "nonexistent-pkg"
        assert "not found" in data["message"]


# ---------------------------------------------------------------------------
# Tests: render_vulns
# ---------------------------------------------------------------------------


class TestRenderVulns:
    """Test vulnerability JSON rendering."""

    def test_no_vulnerabilities(self) -> None:
        """Render report with no vulnerabilities."""
        r, s = _renderer()
        r.render_vulns(_report())
        data = _parse(s)
        assert data["command"] == "vulns"
        assert data["package"] == "requests"
        assert data["version"] == "2.25.0"
        assert data["vulnerability_count"] == 0
        assert data["vulnerabilities"] == []

    def test_single_vulnerability(self) -> None:
        """Render report with one vulnerability."""
        v = _vuln(
            vuln_id="GHSA-abcd",
            summary="SQL injection",
            aliases=["CVE-2024-1234"],
            severity_label="HIGH",
            fixed_versions=["2.31.0"],
        )
        r, s = _renderer()
        r.render_vulns(_report(vulns=[v]))
        data = _parse(s)
        assert data["vulnerability_count"] == 1
        vuln_data = data["vulnerabilities"][0]
        assert vuln_data["id"] == "GHSA-abcd"
        assert vuln_data["summary"] == "SQL injection"
        assert "CVE-2024-1234" in vuln_data["aliases"]
        assert vuln_data["severity_label"] == "HIGH"
        assert vuln_data["fixed_versions"] == ["2.31.0"]

    def test_multiple_vulnerabilities(self) -> None:
        """Render report with multiple vulnerabilities."""
        vulns = [_vuln(vuln_id="GHSA-1"), _vuln(vuln_id="GHSA-2")]
        r, s = _renderer()
        r.render_vulns(_report(vulns=vulns))
        data = _parse(s)
        assert data["vulnerability_count"] == 2

    def test_severity_scores_serialized(self) -> None:
        """Include CVSS severity scores in JSON output."""
        v = VulnerabilityInfo(
            id="GHSA-cvss",
            severity=[CvssSeverity(type="CVSS_V3", score="CVSS:3.1/AV:N")],
        )
        r, s = _renderer()
        r.render_vulns(_report(vulns=[v]))
        data = _parse(s)
        sev = data["vulnerabilities"][0]["severity"]
        assert len(sev) == 1
        assert sev[0]["type"] == "CVSS_V3"
        assert sev[0]["score"] == "CVSS:3.1/AV:N"

    def test_references_serialized(self) -> None:
        """Include references in JSON output."""
        v = VulnerabilityInfo(
            id="GHSA-refs",
            references=[
                VulnerabilityReference(type="ADVISORY", url="https://nvd.nist.gov"),
            ],
        )
        r, s = _renderer()
        r.render_vulns(_report(vulns=[v]))
        data = _parse(s)
        refs = data["vulnerabilities"][0]["references"]
        assert len(refs) == 1
        assert refs[0]["type"] == "ADVISORY"
        assert refs[0]["url"] == "https://nvd.nist.gov"


# ---------------------------------------------------------------------------
# Tests: render_deps_diff
# ---------------------------------------------------------------------------


class TestRenderDepsDiff:
    """Test dependency diff JSON rendering."""

    def test_changed_deps(self) -> None:
        """Render changed dependencies as JSON."""
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
        data = _parse(s)
        assert data["command"] == "deps_diff"
        assert data["package"] == "requests"
        assert data["from_version"] == "2.30.0"
        assert data["to_version"] == "2.31.0"
        assert len(data["changed"]) == 1
        assert data["changed"][0]["name"] == "urllib3"
        assert data["changed"][0]["old_specifier"] == ">=1.21"
        assert data["changed"][0]["new_specifier"] == ">=2.0"
        assert data["unchanged_count"] == 3

    def test_changed_markers(self) -> None:
        """Render marker changes in JSON."""
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
        data = _parse(s)
        c = data["changed"][0]
        assert c["old_markers"] == 'python_version < "3.10"'
        assert c["new_markers"] == 'python_version < "3.11"'

    def test_changed_extras(self) -> None:
        """Render extras changes in JSON."""
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
        data = _parse(s)
        c = data["changed"][0]
        assert c["old_extras"] == []
        assert c["new_extras"] == ["http2"]

    def test_added_and_removed(self) -> None:
        """Render added and removed dependencies in JSON."""
        r, s = _renderer()
        diff = _deps_diff(
            added=[_dep("new-dep", ">=1.0")],
            removed=[_dep("old-dep", ">=0.5")],
        )
        r.render_deps_diff("pkg", "1.0", "2.0", diff)
        data = _parse(s)
        assert len(data["added"]) == 1
        assert data["added"][0]["name"] == "new-dep"
        assert data["added"][0]["specifier"] == ">=1.0"
        assert len(data["removed"]) == 1
        assert data["removed"][0]["name"] == "old-dep"

    def test_empty_diff(self) -> None:
        """Render an empty diff as JSON."""
        r, s = _renderer()
        diff = _deps_diff(unchanged_count=5)
        r.render_deps_diff("pkg", "1.0", "2.0", diff)
        data = _parse(s)
        assert data["changed"] == []
        assert data["added"] == []
        assert data["removed"] == []
        assert data["unchanged_count"] == 5

    def test_tag_parameter(self) -> None:
        """Tag field is included when provided."""
        r, s = _renderer()
        diff = _deps_diff()
        r.render_deps_diff("pkg", "1.0", "2.0", diff, tag="3.0.0 vs 2.0.0")
        data = _parse(s)
        assert data["tag"] == "3.0.0 vs 2.0.0"

    def test_tag_absent_when_none(self) -> None:
        """Tag field is absent when not provided."""
        r, s = _renderer()
        diff = _deps_diff()
        r.render_deps_diff("pkg", "1.0", "2.0", diff)
        data = _parse(s)
        assert "tag" not in data

    def test_extras_groups(self) -> None:
        """Render added and removed extras groups in JSON."""
        r, s = _renderer()
        diff = _deps_diff(
            added_extras=["http2", "socks"],
            removed_extras=["dev"],
        )
        r.render_deps_diff("pkg", "1.0", "2.0", diff)
        data = _parse(s)
        assert data["added_extras"] == ["http2", "socks"]
        assert data["removed_extras"] == ["dev"]

    def test_extras_group_on_change(self) -> None:
        """Extras group annotation on changed deps in JSON."""
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
        data = _parse(s)
        assert data["changed"][0]["extras_group"] == "aws"


# ---------------------------------------------------------------------------
# Tests: render_versions with matching filter
# ---------------------------------------------------------------------------


class TestRenderVersionsMatching:
    """Test version list rendering with a version filter."""

    def test_matching_filter(self) -> None:
        """Render versions with matching filter fields in JSON."""
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
        data = _parse(s)
        assert data["matching"] == ">=2.0"
        assert data["matched"] == 2
        assert data["total"] == 100
        assert data["truncated"] is False

    def test_matching_with_truncation(self) -> None:
        """Matching + limit: truncated is true when showing < matched."""
        r, s = _renderer()
        versions = [VersionInfo(version=Version("3.0.0"))]
        r.render_versions(
            "requests",
            versions,
            total=50,
            matching=">=2.0",
            original_total=200,
        )
        data = _parse(s)
        assert data["showing"] == 1
        assert data["matched"] == 50
        assert data["total"] == 200
        assert data["truncated"] is True


# ---------------------------------------------------------------------------
# Tests: render_ls
# ---------------------------------------------------------------------------


class TestRenderLs:
    """Test archive directory listing JSON rendering."""

    def test_basic_structure(self) -> None:
        """Render listing with command, package, version, entries list."""
        r, s = _renderer()
        entries = [_ls_entry(path="setup.py", is_dir=False, size=100)]
        r.render_ls("pkg", "1.0.0", entries, total=1)
        data = _parse(s)
        assert data["command"] == "ls"
        assert data["package"] == "pkg"
        assert data["version"] == "1.0.0"
        assert isinstance(data["entries"], list)
        assert len(data["entries"]) == 1

    def test_directory_entry_fields(self) -> None:
        """Directory entries have type, file_count, subdir_count, total_size."""
        r, s = _renderer()
        entries = [
            _ls_entry(
                path="src/",
                is_dir=True,
                file_count=5,
                subdir_count=2,
                total_size=1024,
            ),
        ]
        r.render_ls("pkg", "1.0.0", entries, total=1)
        data = _parse(s)
        entry = data["entries"][0]
        assert entry["type"] == "directory"
        assert entry["file_count"] == 5
        assert entry["subdir_count"] == 2
        assert entry["total_size"] == 1024

    def test_file_entry_fields(self) -> None:
        """File entries have type and size."""
        r, s = _renderer()
        entries = [_ls_entry(path="main.py", is_dir=False, size=42)]
        r.render_ls("pkg", "1.0.0", entries, total=1)
        data = _parse(s)
        entry = data["entries"][0]
        assert entry["type"] == "file"
        assert entry["size"] == 42

    def test_truncated_fields(self) -> None:
        """Showing < total sets truncated=true."""
        r, s = _renderer()
        entries = [_ls_entry(path="a.py", is_dir=False, size=10)]
        r.render_ls("pkg", "1.0.0", entries, total=50)
        data = _parse(s)
        assert data["truncated"] is True
        assert data["showing"] == 1
        assert data["total"] == 50

    def test_prefix_field(self) -> None:
        """Prefix value present in JSON output."""
        r, s = _renderer()
        entries = [_ls_entry(path="src/main.py", is_dir=False, size=10)]
        r.render_ls("pkg", "1.0.0", entries, total=1, prefix="src/")
        data = _parse(s)
        assert data["prefix"] == "src/"

    def test_recursive_mode(self) -> None:
        """Recursive flag present in JSON output."""
        r, s = _renderer()
        entries = [_ls_entry(path="src/main.py", is_dir=False, size=10)]
        r.render_ls("pkg", "1.0.0", entries, total=1, recursive=True)
        data = _parse(s)
        assert data["recursive"] is True

    def test_empty_archive(self) -> None:
        """Empty entries list renders as empty JSON array."""
        r, s = _renderer()
        r.render_ls("pkg", "1.0.0", [], total=0)
        data = _parse(s)
        assert data["entries"] == []
        assert data["showing"] == 0
        assert data["total"] == 0


class TestRenderLsRecursive:
    """Test recursive archive listing JSON rendering."""

    def test_recursive_entries(self) -> None:
        """Recursive listing contains only file entries."""
        r, s = _renderer()
        entries = [
            _ls_entry(path="src/main.py", is_dir=False, size=100),
            _ls_entry(path="src/util.py", is_dir=False, size=200),
        ]
        r.render_ls("pkg", "1.0.0", entries, total=2, recursive=True)
        data = _parse(s)
        assert data["recursive"] is True
        assert len(data["entries"]) == 2
        assert all(e["type"] == "file" for e in data["entries"])


# ---------------------------------------------------------------------------
# Tests: render_file_content (extended)
# ---------------------------------------------------------------------------


class TestRenderFileContentExtended:
    """Test extended file content JSON rendering with truncation support."""

    def test_truncated_fields(self) -> None:
        """Truncated text adds truncated and showing_bytes fields."""
        r, s = _renderer()
        content = b"x = 1\n"
        r.render_file_content(
            "pkg",
            "1.0.0",
            "big.py",
            content,
            truncated=True,
            total_size=5000,
        )
        data = _parse(s)
        assert data["truncated"] is True
        assert data["showing_bytes"] == len(content)
        assert data["size_bytes"] == 5000

    def test_not_truncated_no_extra_fields(self) -> None:
        """Default truncated=False has no truncated key."""
        r, s = _renderer()
        r.render_file_content("pkg", "1.0.0", "f.py", b"hello\n")
        data = _parse(s)
        assert "truncated" not in data

    def test_truncated_binary(self) -> None:
        """Binary content ignores truncation — no truncated/showing_bytes keys."""
        r, s = _renderer()
        r.render_file_content(
            "pkg",
            "1.0.0",
            "data.bin",
            b"\x89PNG\r\n\x1a\n",
            truncated=True,
            total_size=10000,
        )
        data = _parse(s)
        assert data["encoding"] == "binary"
        assert "truncated" not in data
        assert "showing_bytes" not in data
