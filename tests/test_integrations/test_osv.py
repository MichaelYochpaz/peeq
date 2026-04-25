"""Unit tests for the OSV vulnerability database client.

Tests use `respx` to mock HTTP requests to the OSV API.  No real
network calls are made.
"""

from __future__ import annotations

import json

import httpx
import pytest
import respx

from peeq.integrations.osv import (
    OSV_API_BASE,
    OSVClient,
    OSVError,
    _extract_fixed_versions,
    _extract_references,
    _extract_severity,
    _parse_timestamp,
    _parse_vulnerability,
)
from peeq.models import CvssSeverity, VulnerabilityReference

# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------

_QUERY_URL = f"{OSV_API_BASE}/v1/query"


def _vuln_response(  # noqa: PLR0913
    *,
    vuln_id: str = "GHSA-xxxx-yyyy-zzzz",
    summary: str = "Test vulnerability",
    aliases: list[str] | None = None,
    severity: list[dict[str, str]] | None = None,
    severity_label: str | None = None,
    fixed_versions: list[str] | None = None,
    published: str | None = "2024-05-06T14:20:59Z",
    withdrawn: str | None = None,
    references: list[dict[str, str]] | None = None,
) -> dict[str, object]:
    """Build a minimal OSV vulnerability response object."""
    vuln: dict[str, object] = {
        "id": vuln_id,
        "summary": summary,
        "aliases": aliases or [],
        "modified": "2026-01-01T00:00:00Z",
    }
    if published:
        vuln["published"] = published
    if severity:
        vuln["severity"] = severity
    if withdrawn:
        vuln["withdrawn"] = withdrawn
    if references:
        vuln["references"] = references

    db_specific: dict[str, object] = {}
    if severity_label:
        db_specific["severity"] = severity_label
    if db_specific:
        vuln["database_specific"] = db_specific

    affected: dict[str, object] = {
        "package": {"name": "test-pkg", "ecosystem": "PyPI"},
        "ranges": [],
    }
    if fixed_versions:
        affected["ranges"] = [
            {
                "type": "ECOSYSTEM",
                "events": [
                    {"introduced": "0"},
                    *[{"fixed": v} for v in fixed_versions],
                ],
            }
        ]
    vuln["affected"] = [affected]
    return vuln


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------


class TestParseTimestamp:
    """Tests for `_parse_timestamp`."""

    def test_valid_z_suffix(self) -> None:
        """Parse RFC 3339 timestamp with Z suffix."""
        result = _parse_timestamp("2024-05-06T14:20:59Z")
        assert result is not None
        assert result.year == 2024
        assert result.month == 5
        assert result.day == 6

    def test_valid_offset(self) -> None:
        """Parse RFC 3339 timestamp with explicit offset."""
        result = _parse_timestamp("2024-05-06T14:20:59+00:00")
        assert result is not None
        assert result.year == 2024

    def test_none_input(self) -> None:
        """Return None for None input."""
        assert _parse_timestamp(None) is None

    def test_invalid_string(self) -> None:
        """Return None for unparseable string."""
        assert _parse_timestamp("not-a-date") is None

    def test_fractional_seconds(self) -> None:
        """Parse timestamp with fractional seconds."""
        result = _parse_timestamp("2026-02-04T03:24:55.822549Z")
        assert result is not None
        assert result.year == 2026


class TestExtractSeverity:
    """Tests for `_extract_severity`."""

    def test_top_level_severity(self) -> None:
        """Extract severity from top-level array."""
        raw = {"severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N"}]}
        result = _extract_severity(raw)
        assert len(result) == 1
        assert result[0] == CvssSeverity(type="CVSS_V3", score="CVSS:3.1/AV:N")

    def test_affected_severity_fallback(self) -> None:
        """Fall back to affected[].severity when top-level is empty."""
        raw = {
            "affected": [{"severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:L"}]}]
        }
        result = _extract_severity(raw)
        assert len(result) == 1
        assert result[0].score == "CVSS:3.1/AV:L"

    def test_empty_severity(self) -> None:
        """Return empty list when no severity data exists."""
        assert _extract_severity({}) == []

    def test_skips_incomplete_entries(self) -> None:
        """Skip severity entries with empty or missing type or score."""
        raw = {
            "severity": [
                {"type": "CVSS_V3", "score": ""},
                {"type": "", "score": "CVSS:3.1/AV:N"},
                {"type": "CVSS_V3", "score": "valid"},
            ]
        }
        result = _extract_severity(raw)
        assert len(result) == 1
        assert result[0].score == "valid"


class TestExtractFixedVersions:
    """Tests for `_extract_fixed_versions`."""

    def test_single_fixed_version(self) -> None:
        """Extract a single fixed version from ECOSYSTEM range."""
        raw = {
            "affected": [
                {
                    "ranges": [
                        {
                            "type": "ECOSYSTEM",
                            "events": [{"introduced": "0"}, {"fixed": "1.2.3"}],
                        }
                    ]
                }
            ]
        }
        assert _extract_fixed_versions(raw) == ["1.2.3"]

    def test_multiple_fixed_versions(self) -> None:
        """Extract multiple fixed versions."""
        raw = {
            "affected": [
                {
                    "ranges": [
                        {
                            "type": "ECOSYSTEM",
                            "events": [
                                {"introduced": "0"},
                                {"fixed": "1.0.0"},
                                {"introduced": "2.0.0"},
                                {"fixed": "2.1.0"},
                            ],
                        }
                    ]
                }
            ]
        }
        assert _extract_fixed_versions(raw) == ["1.0.0", "2.1.0"]

    def test_deduplicates_fixed_versions(self) -> None:
        """Deduplicate fixed versions across multiple affected entries."""
        raw = {
            "affected": [
                {
                    "ranges": [
                        {
                            "type": "ECOSYSTEM",
                            "events": [{"introduced": "0"}, {"fixed": "1.0.0"}],
                        }
                    ]
                },
                {
                    "ranges": [
                        {
                            "type": "ECOSYSTEM",
                            "events": [{"introduced": "0"}, {"fixed": "1.0.0"}],
                        }
                    ]
                },
            ]
        }
        assert _extract_fixed_versions(raw) == ["1.0.0"]

    def test_ignores_git_ranges(self) -> None:
        """Skip GIT ranges (commit hashes, not versions)."""
        raw = {
            "affected": [
                {
                    "ranges": [
                        {
                            "type": "GIT",
                            "events": [{"introduced": "abc"}, {"fixed": "def"}],
                        }
                    ]
                }
            ]
        }
        assert _extract_fixed_versions(raw) == []

    def test_empty_affected(self) -> None:
        """Return empty list when no affected entries."""
        assert _extract_fixed_versions({}) == []


class TestExtractReferences:
    """Tests for `_extract_references`."""

    def test_extracts_references(self) -> None:
        """Extract references with type and URL."""
        raw = {
            "references": [
                {"type": "ADVISORY", "url": "https://example.com/advisory"},
                {"type": "FIX", "url": "https://example.com/fix"},
            ]
        }
        result = _extract_references(raw)
        assert len(result) == 2
        assert result[0] == VulnerabilityReference(
            type="ADVISORY", url="https://example.com/advisory"
        )

    def test_skips_empty_url(self) -> None:
        """Skip references with empty URL."""
        raw = {"references": [{"type": "WEB", "url": ""}]}
        assert _extract_references(raw) == []

    def test_default_type_web(self) -> None:
        """Default reference type to WEB when missing."""
        raw = {"references": [{"url": "https://example.com"}]}
        result = _extract_references(raw)
        assert result[0].type == "WEB"


class TestParseVulnerability:
    """Tests for `_parse_vulnerability`."""

    def test_full_vulnerability(self) -> None:
        """Parse a complete vulnerability record."""
        raw = _vuln_response(
            vuln_id="GHSA-test-1234",
            summary="XSS in templates",
            aliases=["CVE-2024-1234"],
            severity=[{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N"}],
            severity_label="HIGH",
            fixed_versions=["3.1.4"],
            references=[{"type": "ADVISORY", "url": "https://nvd.nist.gov"}],
        )
        result = _parse_vulnerability(raw)
        assert result.id == "GHSA-test-1234"
        assert result.summary == "XSS in templates"
        assert result.aliases == ["CVE-2024-1234"]
        assert result.severity_label == "HIGH"
        assert result.fixed_versions == ["3.1.4"]
        assert len(result.references) == 1
        assert result.published is not None
        assert not result.withdrawn

    def test_minimal_vulnerability(self) -> None:
        """Parse a vulnerability with minimal fields."""
        raw = {"id": "PYSEC-2021-42", "modified": "2023-01-01T00:00:00Z"}
        result = _parse_vulnerability(raw)
        assert result.id == "PYSEC-2021-42"
        assert result.summary is None
        assert result.aliases == []
        assert result.severity == []
        assert result.severity_label is None
        assert result.fixed_versions == []

    def test_withdrawn_vulnerability(self) -> None:
        """Detect withdrawn status."""
        raw = _vuln_response(withdrawn="2024-01-01T00:00:00Z")
        result = _parse_vulnerability(raw)
        assert result.withdrawn is True

    def test_non_string_severity_label_ignored(self) -> None:
        """Ignore non-string severity labels in database_specific."""
        raw = _vuln_response()
        raw["database_specific"] = {"severity": 42}
        result = _parse_vulnerability(raw)
        assert result.severity_label is None


# ---------------------------------------------------------------------------
# OSVClient tests (respx mocked HTTP)
# ---------------------------------------------------------------------------


class TestOSVClient:
    """Tests for `OSVClient.query`."""

    @respx.mock
    async def test_no_vulnerabilities(self) -> None:
        """Return empty report when OSV finds no vulnerabilities."""
        respx.post(_QUERY_URL).mock(
            return_value=httpx.Response(200, json={"vulns": []})
        )
        async with OSVClient() as client:
            report = await client.query("safe-pkg", "1.0.0")

        assert report.package == "safe-pkg"
        assert report.version == "1.0.0"
        assert report.vulnerabilities == []

    @respx.mock
    async def test_single_vulnerability(self) -> None:
        """Parse a single vulnerability from OSV response."""
        vuln = _vuln_response(
            vuln_id="GHSA-abcd-1234-efgh",
            summary="SQL injection",
            aliases=["CVE-2024-9999"],
            fixed_versions=["2.0.0"],
        )
        respx.post(_QUERY_URL).mock(
            return_value=httpx.Response(200, json={"vulns": [vuln]})
        )
        async with OSVClient() as client:
            report = await client.query("vuln-pkg", "1.0.0")

        assert len(report.vulnerabilities) == 1
        v = report.vulnerabilities[0]
        assert v.id == "GHSA-abcd-1234-efgh"
        assert v.summary == "SQL injection"
        assert "CVE-2024-9999" in v.aliases
        assert v.fixed_versions == ["2.0.0"]

    @respx.mock
    async def test_withdrawn_filtered(self) -> None:
        """Filter out withdrawn vulnerabilities."""
        active = _vuln_response(vuln_id="GHSA-active")
        withdrawn = _vuln_response(
            vuln_id="GHSA-withdrawn",
            withdrawn="2024-01-01T00:00:00Z",
        )
        respx.post(_QUERY_URL).mock(
            return_value=httpx.Response(200, json={"vulns": [active, withdrawn]})
        )
        async with OSVClient() as client:
            report = await client.query("pkg", "1.0.0")

        assert len(report.vulnerabilities) == 1
        assert report.vulnerabilities[0].id == "GHSA-active"

    @respx.mock
    async def test_pagination(self) -> None:
        """Handle paginated responses via next_page_token."""
        page1_vuln = _vuln_response(vuln_id="GHSA-page1")
        page2_vuln = _vuln_response(vuln_id="GHSA-page2")

        route = respx.post(_QUERY_URL)
        route.side_effect = [
            httpx.Response(
                200,
                json={
                    "vulns": [page1_vuln],
                    "next_page_token": "token123",
                },
            ),
            httpx.Response(200, json={"vulns": [page2_vuln]}),
        ]

        async with OSVClient() as client:
            report = await client.query("pkg", "1.0.0")

        assert len(report.vulnerabilities) == 2
        ids = {v.id for v in report.vulnerabilities}
        assert ids == {"GHSA-page1", "GHSA-page2"}

    @respx.mock
    async def test_request_payload_format(self) -> None:
        """Verify the request payload sent to OSV API."""
        route = respx.post(_QUERY_URL).mock(
            return_value=httpx.Response(200, json={"vulns": []})
        )
        async with OSVClient() as client:
            await client.query("my-package", "1.2.3")

        assert route.called
        request = route.calls[0].request
        body = json.loads(request.content)
        assert body["package"]["name"] == "my-package"
        assert body["package"]["ecosystem"] == "PyPI"
        assert body["version"] == "1.2.3"

    @respx.mock
    async def test_http_error_raises_osv_error(self) -> None:
        """Raise OSVError on HTTP transport errors."""
        respx.post(_QUERY_URL).mock(side_effect=httpx.ConnectError("fail"))

        async with OSVClient() as client:
            with pytest.raises(OSVError, match="HTTP error"):
                await client.query("pkg", "1.0.0")

    @respx.mock
    async def test_non_success_status_raises_osv_error(self) -> None:
        """Raise OSVError on non-2xx status codes."""
        respx.post(_QUERY_URL).mock(
            return_value=httpx.Response(500, text="Server Error")
        )
        async with OSVClient() as client:
            with pytest.raises(OSVError, match="500"):
                await client.query("pkg", "1.0.0")

    @respx.mock
    async def test_invalid_json_raises_osv_error(self) -> None:
        """Raise OSVError on malformed JSON response."""
        respx.post(_QUERY_URL).mock(
            return_value=httpx.Response(
                200,
                content=b"not json",
                headers={"content-type": "application/json"},
            )
        )
        async with OSVClient() as client:
            with pytest.raises(OSVError, match="Invalid JSON"):
                await client.query("pkg", "1.0.0")

    @respx.mock
    async def test_empty_response_body(self) -> None:
        """Handle response with no vulns key gracefully."""
        respx.post(_QUERY_URL).mock(return_value=httpx.Response(200, json={}))
        async with OSVClient() as client:
            report = await client.query("pkg", "1.0.0")

        assert report.vulnerabilities == []
