"""OSV (Open Source Vulnerabilities) database client.

Queries the OSV API (https://google.github.io/osv.dev/api/) to
check Python packages for known vulnerabilities.  Uses `POST /v1/query`
with ecosystem `"PyPI"` and handles pagination via `next_page_token`.

No authentication required.  No rate limits.  Response size limit is
32 MiB over HTTP/1.1 (no limit over HTTP/2).
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

import httpx

from peeq import APP_NAME
from peeq.models import (
    CvssSeverity,
    VulnerabilityInfo,
    VulnerabilityReference,
    VulnerabilityReport,
)

logger = logging.getLogger(__name__)

OSV_API_BASE = "https://api.osv.dev"
"""Base URL for the OSV REST API."""

_PYPI_ECOSYSTEM = "PyPI"
"""Case-sensitive ecosystem identifier for PyPI packages in OSV."""


class OSVError(Exception):
    """Error communicating with or parsing responses from the OSV API."""


class OSVClient:
    """Async client for the OSV vulnerability database.

    Uses httpx for HTTP requests.  The client manages its own
    connection lifecycle via async context manager.
    """

    def __init__(self, *, timeout: float = 30.0) -> None:
        self._client = httpx.AsyncClient(
            base_url=OSV_API_BASE,
            timeout=timeout,
            follow_redirects=True,
            headers={"User-Agent": APP_NAME},
        )

    async def __aenter__(self) -> OSVClient:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self._client.aclose()

    async def query(self, name: str, version: str) -> VulnerabilityReport:
        """Query OSV for vulnerabilities affecting *name* at *version*.

        Return a `VulnerabilityReport` containing
        all matching vulnerability records.  An empty `vulnerabilities`
        list means no known vulnerabilities.

        Handles pagination via `next_page_token` (rare for single-package
        queries, but required for correctness).

        Raises
        ------
        OSVError
            On HTTP errors or malformed responses.
        """
        all_vulns: list[dict[str, Any]] = []
        page_token: str | None = None

        while True:
            payload: dict[str, Any] = {
                "package": {
                    "name": name,
                    "ecosystem": _PYPI_ECOSYSTEM,
                },
                "version": version,
            }
            if page_token is not None:
                payload["page_token"] = page_token

            try:
                response = await self._client.post("/v1/query", json=payload)
            except httpx.HTTPError as exc:
                msg = f"HTTP error querying OSV for {name}=={version}: {exc}"
                raise OSVError(msg) from exc

            if not response.is_success:
                msg = f"OSV API returned {response.status_code} for {name}=={version}"
                raise OSVError(msg)

            try:
                data = response.json()
            except ValueError as exc:
                msg = f"Invalid JSON from OSV API for {name}=={version}"
                raise OSVError(msg) from exc

            vulns = data.get("vulns", [])
            all_vulns.extend(vulns)

            # Pagination: continue if there's a next page token
            page_token = data.get("next_page_token")
            if not page_token:
                break

        # Parse raw vulnerability dicts into models
        parsed = [_parse_vulnerability(v) for v in all_vulns]
        # Filter out withdrawn vulnerabilities
        parsed = [v for v in parsed if not v.withdrawn]

        return VulnerabilityReport(
            package=name,
            version=version,
            vulnerabilities=parsed,
        )


# ---------------------------------------------------------------------------
# Response parsing helpers
# ---------------------------------------------------------------------------


def _extract_severity(raw: dict[str, Any]) -> list[CvssSeverity]:
    """Extract CVSS severity entries from a vulnerability record.

    Check the top-level `severity` array first, then fall back to
    per-package `affected[].severity` entries.
    """
    result: list[CvssSeverity] = []
    for sev in raw.get("severity", []):
        sev_type = sev.get("type", "")
        sev_score = sev.get("score", "")
        if sev_type and sev_score:
            result.append(CvssSeverity(type=sev_type, score=sev_score))

    if not result:
        for affected in raw.get("affected", []):
            for sev in affected.get("severity", []):
                sev_type = sev.get("type", "")
                sev_score = sev.get("score", "")
                if sev_type and sev_score:
                    result.append(CvssSeverity(type=sev_type, score=sev_score))

    return result


def _extract_fixed_versions(raw: dict[str, Any]) -> list[str]:
    """Extract deduplicated fixed versions from `ECOSYSTEM` ranges."""
    fixed: list[str] = []
    for affected in raw.get("affected", []):
        for rng in affected.get("ranges", []):
            if rng.get("type") != "ECOSYSTEM":
                continue
            for event in rng.get("events", []):
                version = event.get("fixed")
                if version:
                    fixed.append(version)

    # Deduplicate while preserving order
    seen: set[str] = set()
    unique: list[str] = []
    for v in fixed:
        if v not in seen:
            seen.add(v)
            unique.append(v)
    return unique


def _extract_references(raw: dict[str, Any]) -> list[VulnerabilityReference]:
    """Extract reference links from a vulnerability record."""
    refs: list[VulnerabilityReference] = []
    for ref in raw.get("references", []):
        ref_type = ref.get("type", "WEB")
        ref_url = ref.get("url", "")
        if ref_url:
            refs.append(VulnerabilityReference(type=ref_type, url=ref_url))
    return refs


def _parse_vulnerability(raw: dict[str, Any]) -> VulnerabilityInfo:
    """Parse a single OSV vulnerability object into a `VulnerabilityInfo`."""
    # Extract text severity label from database_specific (GHSA records)
    severity_label = None
    db_specific = raw.get("database_specific", {})
    if isinstance(db_specific, dict):
        label = db_specific.get("severity")
        if isinstance(label, str):
            severity_label = label

    return VulnerabilityInfo(
        id=raw.get("id", ""),
        summary=raw.get("summary"),
        details=raw.get("details"),
        aliases=raw.get("aliases", []),
        severity=_extract_severity(raw),
        severity_label=severity_label,
        fixed_versions=_extract_fixed_versions(raw),
        references=_extract_references(raw),
        published=_parse_timestamp(raw.get("published")),
        modified=_parse_timestamp(raw.get("modified")),
        withdrawn="withdrawn" in raw,
    )


def _parse_timestamp(value: str | None) -> datetime | None:
    """Parse an RFC 3339 timestamp string to a UTC `datetime`.

    Return `None` if the value is `None` or cannot be parsed.
    """
    if value is None:
        return None
    try:
        # RFC 3339 timestamps end in "Z" — replace with +00:00 for fromisoformat
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
    except (ValueError, AttributeError):
        logger.debug("Failed to parse timestamp: %s", value)
        return None
