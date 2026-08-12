"""PyPI repository backend using PEP 691 JSON Simple API.

Uses the JSON-based Simple API
(PEP 691 (https://peps.python.org/pep-0691/)) as the primary API for
package discovery, version listing, and file URL retrieval.  The legacy
JSON API (`/pypi/<package>/json`) is used only to supplement with rich
metadata (summary, project URLs) not available in the Simple API response.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime
from typing import TYPE_CHECKING, Any, ClassVar
from urllib.parse import urldefrag, urljoin

import httpx
from packaging.utils import canonicalize_name
from packaging.version import Version

from peeq.models import (
    FileInfo,
    HashDigest,
    PackageInfo,
    VersionInfo,
)

if TYPE_CHECKING:
    from pathlib import Path

    from peeq.models import DownloadResult

from peeq.backends.base import (
    BackendError,
    PackageRepository,
    determine_dist_type,
    parse_version_from_filename,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_PEP691_ACCEPT = "application/vnd.pypi.simple.v1+json"
"""Content-Type for PEP 691 JSON Simple API requests."""

PYPI_BASE_URL = "https://pypi.org"
PYPI_REGISTRY = "pypi.org"


# ---------------------------------------------------------------------------
# PyPIRepository
# ---------------------------------------------------------------------------


class PyPIRepository(PackageRepository):
    """PyPI repository backend.

    Uses the JSON-based Simple API (PEP 691) as the primary interface.
    Falls back to the legacy JSON API for supplemental metadata (summary,
    project URLs) that the Simple API does not provide.

    The `releases` key in the legacy JSON API is deprecated and is not
    used.
    """

    backend_id: ClassVar[str] = "pypi"

    def __init__(
        self,
        *,
        base_url: str = PYPI_BASE_URL,
        registry: str | None = None,
    ) -> None:
        super().__init__(base_url=base_url, registry=registry)
        self._simple_url = f"{self._base_url}/simple"
        self._json_api_url = f"{self._base_url}/pypi"
        self._simple_cache: dict[str, dict[str, Any] | None] = {}

    @property
    def simple_url(self) -> str:
        """PEP 503/691 Simple API root used for dependency resolution."""
        return self._simple_url

    async def check(self, name: str) -> PackageInfo | None:
        """Check if a package exists on PyPI, returning basic info.

        Fetches the PEP 691 Simple API and legacy JSON API concurrently.
        The Simple API provides the version list; the legacy JSON API
        provides the summary and canonical latest stable version.
        """
        normalized = canonicalize_name(name)

        # Fetch both in parallel for latency
        simple_coro = self._fetch_simple(normalized)
        legacy_coro = self._fetch_legacy_info(normalized)
        simple_data, legacy_info = await asyncio.gather(
            simple_coro,
            legacy_coro,
        )

        if simple_data is None:
            return None

        version_infos = extract_versions(simple_data)
        if not version_infos:
            return None

        bare_versions = [version.version for version in version_infos]
        latest = _determine_latest_version(bare_versions, legacy_info)
        summary = legacy_info.get("summary") if legacy_info else None

        # --- Supplemental fields from the legacy JSON API ---------------
        license_value: str | None = None
        license_format: str | None = None
        requires_python: str | None = None
        author: str | None = None
        project_urls: dict[str, str] | None = None

        if legacy_info:
            # License: prefer PEP 639 SPDX expression over free-text
            license_expression = legacy_info.get("license_expression")
            if license_expression:
                license_value = license_expression
                license_format = "expression"
            else:
                raw_license = legacy_info.get("license")
                if raw_license:
                    license_value = raw_license
                    license_format = "text"

            requires_python = legacy_info.get("requires_python") or None
            author = legacy_info.get("author") or None
            if not author:
                author = legacy_info.get("maintainer") or None
            project_urls = legacy_info.get("project_urls") or None

        # Derive latest_release_date from Simple API version data
        latest_release_date: datetime | None = None
        for vi in version_infos:
            if vi.version == latest:
                latest_release_date = vi.release_date
                break

        return PackageInfo(
            name=simple_data.get("name", normalized),
            latest_version=latest,
            version_count=len(version_infos),
            summary=summary,
            license=license_value,
            license_format=license_format,
            requires_python=requires_python,
            author=author,
            project_urls=project_urls,
            latest_release_date=latest_release_date,
            registry=self._registry_name,
        )

    async def versions(self, name: str) -> list[VersionInfo]:
        """List all available versions with yanked status, sorted newest-first."""
        normalized = canonicalize_name(name)
        simple_data = await self._fetch_simple(normalized)
        if simple_data is None:
            return []
        return sorted(
            extract_versions(simple_data),
            key=lambda version: version.version,
            reverse=True,
        )

    async def files(self, name: str, version: str) -> list[FileInfo]:
        """List available files (sdists, wheels) for a specific version."""
        normalized = canonicalize_name(name)
        simple_data = await self._fetch_simple(normalized)
        if simple_data is None:
            return []
        page_url = f"{self._simple_url}/{normalized}/"
        return extract_files_for_version(simple_data, version, page_url)

    async def download(
        self,
        file: FileInfo,
        dest: Path,
        *,
        max_download_bytes: int = 500 * 1024 * 1024,
    ) -> DownloadResult:
        """Download a file to *dest*, verifying SHA-256 if available."""
        return await self._download_file(
            file.url,
            dest,
            expected_hash=file.hash,
            max_download_bytes=max_download_bytes,
        )

    # ------------------------------------------------------------------
    # PEP 691 Simple API
    # ------------------------------------------------------------------

    async def _fetch_simple(
        self,
        normalized_name: str,
    ) -> dict[str, Any] | None:
        """Fetch package data from PEP 691 JSON Simple API.

        Results are cached per session (per backend instance) to avoid
        redundant HTTP requests when multiple methods query the same
        package within a single CLI invocation.

        Returns the parsed JSON dict, or `None` if the package does
        not exist (404).  Raises `BackendError` on other failures.
        """
        if normalized_name in self._simple_cache:
            return self._simple_cache[normalized_name]

        url = f"{self._simple_url}/{normalized_name}/"
        try:
            response = await self.get_with_retry(
                url,
                headers={"Accept": _PEP691_ACCEPT},
            )
            if response.is_client_error and response.status_code == httpx.codes.NOT_FOUND:
                self._simple_cache[normalized_name] = None
                return None
            response.raise_for_status()
            data = response.json()
            self._simple_cache[normalized_name] = data
            return data
        except httpx.HTTPStatusError as exc:
            msg = f"PEP 691 request failed for {normalized_name}: {exc.response.status_code}"
            raise BackendError(msg) from exc
        except httpx.HTTPError as exc:
            msg = f"HTTP error fetching {normalized_name}: {exc}"
            raise BackendError(msg) from exc
        except (ValueError, KeyError) as exc:
            msg = f"Invalid JSON response from {url}: {exc}"
            raise BackendError(msg) from exc

    # ------------------------------------------------------------------
    # Legacy JSON API (supplemental)
    # ------------------------------------------------------------------

    async def _fetch_legacy_info(
        self,
        normalized_name: str,
    ) -> dict[str, Any] | None:
        """Fetch the `info` dict from the legacy JSON API.

        Best-effort: returns `None` on any error.  Never raises.
        The returned dict contains `version` (latest stable),
        `summary`, `author`, etc.
        """
        url = f"{self._json_api_url}/{normalized_name}/json"
        try:
            response = await self.get_with_retry(url)
            if not response.is_success:
                return None
            data = response.json()
            return data.get("info")
        except (httpx.HTTPError, ValueError, KeyError):
            logger.debug(
                "Failed to fetch legacy info for %s",
                normalized_name,
                exc_info=True,
            )
            return None


# ---------------------------------------------------------------------------
# PEP 691 response parsing
# ---------------------------------------------------------------------------


def _determine_latest_version(
    versions: list[Version],
    legacy_info: dict[str, Any] | None = None,
) -> Version:
    """Determine the latest *stable* version from a version list.

    Strategy (following the consultant's recommended pattern):

    1. If the legacy JSON API provided `info.version`, use it as the
       canonical latest stable version (PyPI computes this server-side,
       filtering pre-releases and yanked distributions).
    2. Otherwise, filter out pre-releases and dev releases from the
       version list and take the maximum.
    3. If *all* versions are pre-releases, fall back to the overall max.
    """
    # 1. Prefer legacy API's computed latest stable
    if legacy_info:
        legacy_version_str = legacy_info.get("version")
        if legacy_version_str:
            try:
                return Version(legacy_version_str)
            except Exception:
                logger.debug(
                    "Unparseable legacy version string: %s",
                    legacy_version_str,
                )

    # 2. Filter to stable releases
    stable = [v for v in versions if not v.is_prerelease and not v.is_devrelease]
    if stable:
        return max(stable)

    # 3. All pre-releases — return highest
    return max(versions)


def _parse_version_strings(raw: list[str]) -> list[Version]:
    """Parse a list of version strings, skipping invalid ones."""
    versions: list[Version] = []
    for v_str in raw:
        try:
            versions.append(Version(v_str))
        except Exception:  # noqa: PERF203
            logger.debug("Skipping unparseable version string: %s", v_str)
    return versions


def _parse_upload_time(
    raw: str | None,
    filename: str = "",
) -> datetime | None:
    """Parse a PEP 700 `upload-time` value into a timezone-aware datetime.

    Handles the `Z` UTC suffix that `datetime.fromisoformat` only
    supports from Python 3.11 onward.  Returns `None` on missing or
    malformed input.
    """
    if not raw:
        return None
    try:
        # Python 3.10 fromisoformat() does not accept the "Z" suffix.
        return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        logger.debug("Unparseable upload-time %r for %s", raw, filename)
        return None


def _build_release_date_map(
    files: list[dict[str, Any]],
) -> dict[Version, datetime]:
    """Build a per-version release date map from upload-time fields.

    Returns a dict mapping each version to its earliest upload time
    (PEP 700 (https://peps.python.org/pep-0700/)).  Versions without
    any parseable `upload-time` are absent from the dict.
    """
    version_times: dict[Version, list[datetime]] = {}
    for f in files:
        filename = f.get("filename", "")
        v = parse_version_from_filename(filename)
        if v is None:
            continue
        dt = _parse_upload_time(f.get("upload-time"), filename)
        if dt is None:
            continue
        version_times.setdefault(v, []).append(dt)

    return {v: min(times) for v, times in version_times.items()}


def extract_versions(data: dict[str, Any]) -> list[VersionInfo]:
    """Extract version list with yanked status from a PEP 691 response.

    Uses the `versions` key (PEP 700, API v1.1) if available for the
    version list, then cross-references the `files` array for
    per-version yanked status (PEP 592), earliest upload time
    (PEP 700 (https://peps.python.org/pep-0700/)), and
    `requires-python` (PEP 503).

    A version is considered yanked when ALL of its files are yanked.
    The yank reason is the first non-empty reason found across the
    version's files.
    """
    files = data.get("files", [])
    yanked_map = _build_yanked_map(files)
    release_date_map = _build_release_date_map(files)
    requires_python_map = _build_requires_python_map(files)

    if "versions" in data:
        versions = _parse_version_strings(data["versions"])
    else:
        versions = _unique_versions_from_filenames(files)

    result: list[VersionInfo] = []
    for v in versions:
        yanked, reason = yanked_map.get(v, (False, None))
        release_date = release_date_map.get(v)
        result.append(
            VersionInfo(
                version=v,
                yanked=yanked,
                yanked_reason=reason,
                release_date=release_date,
                requires_python=requires_python_map.get(v),
            )
        )
    return result


def _build_yanked_map(
    files: list[dict[str, Any]],
) -> dict[Version, tuple[bool, str | None]]:
    """Build a per-version yanked status map from the files array.

    Returns a dict mapping each version to `(all_yanked, first_reason)`.
    A version is yanked only if it has files and ALL of them are yanked.
    """
    version_files: dict[Version, list[dict[str, Any]]] = {}
    for f in files:
        filename = f.get("filename", "")
        v = parse_version_from_filename(filename)
        if v is not None:
            version_files.setdefault(v, []).append(f)

    result: dict[Version, tuple[bool, str | None]] = {}
    for v, v_files in version_files.items():
        all_yanked = all(bool(fd.get("yanked")) for fd in v_files)
        reason: str | None = None
        if all_yanked:
            for fd in v_files:
                raw = fd.get("yanked")
                if isinstance(raw, str) and raw:
                    reason = raw
                    break
        result[v] = (all_yanked, reason)
    return result


def _build_requires_python_map(
    files: list[dict[str, Any]],
) -> dict[Version, str]:
    """Build a per-version `requires-python` map from the files array.

    Returns a dict mapping each version to its `requires-python`
    specifier string.  Takes the first non-`None` value across the
    version's files (all files for a version should declare the same
    constraint, but we handle discrepancies defensively).
    """
    result: dict[Version, str] = {}
    for f in files:
        filename = f.get("filename", "")
        v = parse_version_from_filename(filename)
        if v is None or v in result:
            continue
        requires_python = f.get("requires-python")
        if requires_python:
            result[v] = requires_python
    return result


def _unique_versions_from_filenames(
    files: list[dict[str, Any]],
) -> list[Version]:
    """Extract unique versions by parsing distribution filenames."""
    seen: set[Version] = set()
    for f in files:
        filename = f.get("filename", "")
        version = parse_version_from_filename(filename)
        if version is not None:
            seen.add(version)
    return list(seen)


def extract_files_for_version(
    data: dict[str, Any],
    version: str,
    page_url: str = "",
) -> list[FileInfo]:
    """Extract `FileInfo` objects for *version*.

    Parameters
    ----------
    page_url:
        Base URL for resolving relative file URLs (see
        `_file_dict_to_model`).
    """
    target = Version(version)
    result: list[FileInfo] = []

    for f in data.get("files", []):
        filename = f.get("filename", "")
        file_version = parse_version_from_filename(filename)
        if file_version is None or file_version != target:
            continue
        result.append(_file_dict_to_model(f, page_url=page_url))

    return result


def _file_dict_to_model(
    f: dict[str, Any],
    page_url: str = "",
) -> FileInfo:
    """Convert a PEP 691 file dict to a `FileInfo`.

    Parameters
    ----------
    f:
        A single entry from the `files` array in a PEP 691 response.
    page_url:
        The URL of the project detail page (e.g.,
        `https://pypi.org/simple/requests/`).  Used to resolve relative
        file URLs against, per PEP 691 which permits relative paths.
    """
    filename = f["filename"]

    # Hash
    hashes = f.get("hashes", {})
    sha256 = hashes.get("sha256")
    file_hash = HashDigest(sha256=sha256, source="registry") if sha256 else None

    # PEP 658 / PEP 714 metadata availability.
    # PEP 714 renamed the key from `dist-info-metadata` to
    # `core-metadata`.  Try the current name first, then fall back to
    # the deprecated names for compatibility with older/private indexes.
    meta_data = f.get("core-metadata")
    if meta_data is None:
        meta_data = f.get("dist-info-metadata")
    if meta_data is None:
        meta_data = f.get("data-dist-info-metadata")

    metadata_available = False
    metadata_hash = None
    if isinstance(meta_data, bool):
        metadata_available = meta_data
    elif isinstance(meta_data, dict):
        metadata_available = True
        meta_sha256 = meta_data.get("sha256")
        if meta_sha256:
            metadata_hash = HashDigest(sha256=meta_sha256, source="registry")

    # URL: strip fragment and resolve against page URL.
    # PEP 691 allows relative URLs; PyPI always provides absolute URLs,
    # but private registries may use relative paths.  Fragments (e.g.,
    # `#sha256=...`) are a PEP 503 HTML leftover and must be removed
    # to avoid issues when deriving metadata URLs (PEP 658).
    raw_url = f.get("url", "")
    url_no_frag, _fragment = urldefrag(raw_url)
    url = urljoin(page_url, url_no_frag) if page_url else url_no_frag

    # PEP 592 yanked status.  The `yanked` key is either a boolean or
    # a non-empty string (the yank reason).
    yanked_raw = f.get("yanked", False)
    is_yanked = bool(yanked_raw)
    yanked_reason = yanked_raw if isinstance(yanked_raw, str) else None

    # PEP 700 upload-time.
    upload_time = _parse_upload_time(f.get("upload-time"), filename)

    return FileInfo(
        filename=filename,
        url=url,
        hash=file_hash,
        requires_python=f.get("requires-python"),
        dist_type=determine_dist_type(filename),
        size=f.get("size"),
        metadata_available=metadata_available,
        metadata_hash=metadata_hash,
        upload_time=upload_time,
        yanked=is_yanked,
        yanked_reason=yanked_reason,
    )
