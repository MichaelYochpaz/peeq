"""Generic PEP 503 Simple Repository backend.

Fallback backend for registries that don't support PEP 691 JSON responses.
Parses the HTML anchor tags from `/simple/<project>/` pages using the
stdlib `html.parser` --- no heavy dependencies like lxml or
BeautifulSoup are needed because the PEP 503 HTML is minimal.

Spec compliance:
- **PEP 503**: Core Simple API (anchor parsing, hash fragments, name
  normalization).
- **PEP 592**: Yanked files (`data-yanked` attribute).
- **PEP 629**: Repository versioning (`<meta name="pypi:repository-version">`
  tag --- parsed and warned on, not hard-failed).
- **PEP 658 / 714**: Core metadata availability (`data-core-metadata`
  preferred, `data-dist-info-metadata` as legacy fallback).
- **PEP 691**: Content negotiation --- explicitly requests HTML via the
  `Accept` header to prevent JSON responses from modern registries.

See also: https://peps.python.org/pep-0503/
"""

from __future__ import annotations

import contextlib
import logging
from html.parser import HTMLParser
from posixpath import basename as posix_basename
from typing import TYPE_CHECKING, ClassVar
from urllib.parse import urldefrag, urljoin, urlparse

import httpx
from packaging.utils import canonicalize_name
from packaging.version import Version

from peeq.models import (
    FileInfo,
    HashDigest,
    PackageInfo,
    VersionInfo,
)
from peeq.sanitize import sanitize_diagnostic

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

_SIMPLE_HTML_ACCEPT = "application/vnd.pypi.simple.v1+html, text/html;q=0.01"
"""Accept header requesting HTML from PEP 691-capable registries.

Explicitly disables JSON responses so that `_SimpleHTMLParser`
always receives parseable HTML.  The `text/html` fallback with a low
quality value ensures compatibility with pre-PEP 691 registries.
"""

_JSON_CONTENT_TYPES = frozenset(
    {
        "application/vnd.pypi.simple.v1+json",
        "application/json",
    }
)
"""Content-Types that indicate a JSON response (incompatible with our
HTML parser).  Checked after fetching to produce a clear error instead
of silently returning zero results."""

_SUPPORTED_REPO_MAJOR_VERSION = 1
"""Maximum supported major version of the Simple Repository API (PEP 629).
A response declaring a higher major version triggers a warning."""


# ---------------------------------------------------------------------------
# HTML parser
# ---------------------------------------------------------------------------


class _SimpleHTMLParser(HTMLParser):
    """Parse PEP 503 Simple API HTML into structured file dicts.

    Extracts `<a>` tags with their `href`, `data-requires-python`,
    `data-core-metadata` / `data-dist-info-metadata` (PEP 714),
    `data-yanked` (PEP 592), and `data-size` attributes.

    Also captures the `<meta name="pypi:repository-version">` tag
    (PEP 629) so callers can warn on unsupported major versions.
    """

    def __init__(self) -> None:
        super().__init__()
        self.files: list[dict[str, str | None]] = []
        self.repository_version: str | None = None
        self._current_attrs: dict[str, str | None] = {}
        self._in_anchor = False
        self._current_text = ""

    def handle_starttag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        if tag == "a":
            # Preserve all attributes including those with None values.
            # html.parser surfaces bare HTML attributes (e.g., a standalone
            # `data-yanked` without `="...""`) as `(name, None)`.
            # Dropping them would silently discard presence-meaningful
            # flags like `data-yanked` (PEP 592).
            self._current_attrs = dict(attrs)
            self._in_anchor = True
            self._current_text = ""
        elif tag == "meta":
            # PEP 629: <meta name="pypi:repository-version" content="1.0">
            attr_dict = dict(attrs)
            if attr_dict.get("name") == "pypi:repository-version":
                self.repository_version = attr_dict.get("content")

    def handle_data(self, data: str) -> None:
        if self._in_anchor:
            self._current_text += data

    def handle_endtag(self, tag: str) -> None:
        if tag != "a" or not self._in_anchor:
            return

        href = self._current_attrs.get("href", "") or ""
        filename = self._current_text.strip()

        # Fallback: derive filename from the href path segment when
        # anchor text is empty (some non-compliant registries).
        if href and not filename:
            url_no_frag, _ = urldefrag(href)
            filename = posix_basename(urlparse(url_no_frag).path)

        if href and filename:
            # PEP 714: prefer data-core-metadata over the legacy
            # data-dist-info-metadata.  Store under a neutral key.
            core_metadata = self._current_attrs.get("data-core-metadata")
            if core_metadata is None:
                core_metadata = self._current_attrs.get(
                    "data-dist-info-metadata",
                )

            # data-yanked: presence alone (even without a value) means
            # yanked.  html.parser gives None for bare attributes.
            # We normalise None → "" so downstream can distinguish
            # "present with no reason" from "not present at all".
            yanked_raw = self._current_attrs.get("data-yanked")
            has_yanked_attr = "data-yanked" in self._current_attrs
            yanked_value: str | None
            if has_yanked_attr:
                yanked_value = yanked_raw if yanked_raw is not None else ""
            else:
                yanked_value = None

            self.files.append(
                {
                    "filename": filename,
                    "href": href,
                    "requires-python": self._current_attrs.get(
                        "data-requires-python",
                    ),
                    "core-metadata": core_metadata,
                    "data-yanked": yanked_value,
                    "data-size": self._current_attrs.get("data-size"),
                }
            )

        self._in_anchor = False
        self._current_attrs = {}
        self._current_text = ""


# ---------------------------------------------------------------------------
# SimpleRepository
# ---------------------------------------------------------------------------


class SimpleRepository(PackageRepository):
    """Generic PEP 503 Simple Repository backend.

    Works with any registry that serves the PEP 503 HTML Simple API.
    No summary or rich metadata is available from this API --- only
    filenames, download URLs, hashes, and `requires-python` constraints.
    """

    backend_id: ClassVar[str] = "simple"

    def __init__(
        self,
        *,
        base_url: str,
        registry: str | None = None,
    ) -> None:
        super().__init__(base_url=base_url, registry=registry)
        self._simple_cache: dict[str, list[dict[str, str | None]] | None] = {}

    async def check(self, name: str) -> PackageInfo | None:
        """Check if a package exists, returning basic info.

        The PEP 503 HTML API does not provide a summary, so
        `summary` is always `None`.
        """
        normalized = canonicalize_name(name)
        parsed_files = await self._fetch_simple_html(normalized)
        if parsed_files is None:
            return None

        version_infos = _extract_versions(parsed_files)
        if not version_infos:
            return None

        bare_versions = [version.version for version in version_infos]
        return PackageInfo(
            name=normalized,
            latest_version=_latest_stable(bare_versions),
            version_count=len(version_infos),
            registry=self._registry_name,
        )

    async def versions(self, name: str) -> list[VersionInfo]:
        """List all available versions with yanked status, sorted newest-first."""
        normalized = canonicalize_name(name)
        parsed_files = await self._fetch_simple_html(normalized)
        if parsed_files is None:
            return []
        return sorted(
            _extract_versions(parsed_files),
            key=lambda version: version.version,
            reverse=True,
        )

    async def files(self, name: str, version: str) -> list[FileInfo]:
        """List available files (sdists, wheels) for a specific version."""
        normalized = canonicalize_name(name)
        parsed_files = await self._fetch_simple_html(normalized)
        if parsed_files is None:
            return []
        page_url = f"{self._base_url}/{normalized}/"
        return _filter_files_for_version(parsed_files, version, page_url)

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
    # PEP 503 HTML fetching
    # ------------------------------------------------------------------

    async def _fetch_simple_html(
        self,
        normalized_name: str,
    ) -> list[dict[str, str | None]] | None:
        """Fetch and parse the PEP 503 HTML page for a package.

        Results are cached per session (per backend instance) to avoid
        redundant HTTP requests when multiple methods query the same
        package within a single CLI invocation.

        Returns a list of parsed file dicts, or `None` if the package
        does not exist (404).

        Sends an explicit `Accept` header (PEP 691) to request HTML
        and validates the response `Content-Type` to detect registries
        that ignore the header and return JSON anyway.
        """
        if normalized_name in self._simple_cache:
            return self._simple_cache[normalized_name]

        url = f"{self._base_url}/{normalized_name}/"
        try:
            response = await self.get_with_retry(
                url,
                headers={"Accept": _SIMPLE_HTML_ACCEPT},
            )
            if response.is_client_error and response.status_code == httpx.codes.NOT_FOUND:
                self._simple_cache[normalized_name] = None
                return None
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            msg = f"PEP 503 request failed for {normalized_name}: {exc.response.status_code}"
            raise BackendError(msg) from None
        except httpx.HTTPError as exc:
            msg = f"HTTP error fetching {normalized_name}: {exc}"
            raise BackendError(msg) from None

        # Guard against registries that return JSON despite the Accept
        # header.  Feeding JSON into the HTML parser would silently
        # produce zero results.
        content_type = response.headers.get("content-type", "")
        media_type = content_type.split(";", 1)[0].strip().lower()
        if media_type in _JSON_CONTENT_TYPES:
            msg = (
                f"Registry returned JSON ({media_type}) for "
                f"{normalized_name}, but this backend expects HTML. "
                f"Use the PyPI backend or configure the registry to "
                f"serve HTML responses."
            )
            raise BackendError(msg)

        parser = _SimpleHTMLParser()
        parser.feed(response.text)

        # PEP 629: warn if repository declares an unsupported major
        # version.  We intentionally do NOT hard-fail --- enterprise
        # proxies and WAFs can inject unexpected version tags, and a
        # hard crash would sever the tool's utility entirely.
        if parser.repository_version is not None:
            try:
                major = int(parser.repository_version.split(".")[0])
                if major > _SUPPORTED_REPO_MAJOR_VERSION:
                    logger.warning(
                        "Repository %s declares API version %s "
                        "(this client supports major version %d). "
                        "Behavior may differ.",
                        sanitize_diagnostic(url),
                        sanitize_diagnostic(parser.repository_version),
                        _SUPPORTED_REPO_MAJOR_VERSION,
                    )
            except ValueError:
                logger.debug(
                    "Unparseable repository version: %s",
                    sanitize_diagnostic(parser.repository_version),
                )

        self._simple_cache[normalized_name] = parser.files
        return parser.files


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------


def _parse_hash_from_fragment(fragment: str) -> HashDigest | None:
    """Extract a SHA-256 hash from a URL fragment.

    PEP 503 encodes the hash as `#sha256=<hex>`.
    """
    if not fragment:
        return None
    for part in fragment.split("&"):
        if part.startswith("sha256="):
            return HashDigest(sha256=part[7:], source="registry")
    return None


def _parse_metadata_attr(
    attr_value: str | None,
) -> tuple[bool, HashDigest | None]:
    """Parse a PEP 658 / PEP 714 core-metadata attribute value.

    Works for both `data-core-metadata` (PEP 714, preferred) and
    `data-dist-info-metadata` (PEP 658, legacy) --- the caller
    resolves which attribute to pass.

    Returns `(metadata_available, metadata_hash)`.

    The attribute value can be:

    - `"true"` — metadata available, no hash
    - `"sha256=<hex>"` — metadata available with hash
    - `None` or `"false"` — not available
    """
    if attr_value is None or attr_value.lower() == "false":
        return False, None

    if attr_value.lower() == "true":
        return True, None

    if "sha256=" in attr_value:
        sha_val = attr_value.split("sha256=", 1)[1]
        return True, HashDigest(sha256=sha_val, source="registry")

    # Unknown value — treat as available without hash
    return True, None


def _latest_stable(versions: list[Version]) -> Version:
    """Return the latest stable version, falling back to overall max.

    Filters out pre-releases and dev releases.  If all versions are
    pre-releases, returns the highest pre-release.
    """
    stable = [v for v in versions if not v.is_prerelease and not v.is_devrelease]
    return max(stable) if stable else max(versions)


def _extract_versions(
    files: list[dict[str, str | None]],
) -> list[VersionInfo]:
    """Extract unique versions with yanked status from parsed HTML file entries.

    A version is considered yanked when ALL of its files are yanked
    (PEP 592).  The yank reason is the first non-empty reason found
    across the version's files.
    """
    # Group files by version
    version_files: dict[Version, list[dict[str, str | None]]] = {}
    for f in files:
        filename = f.get("filename", "") or ""
        version = parse_version_from_filename(filename)
        if version is not None:
            version_files.setdefault(version, []).append(f)

    result: list[VersionInfo] = []
    for v, v_files in version_files.items():
        # data-yanked: None = not present, "" = bare attribute, str = reason
        all_yanked = all(fd.get("data-yanked") is not None for fd in v_files)
        reason: str | None = None
        if all_yanked:
            for fd in v_files:
                raw = fd.get("data-yanked")
                if raw:  # Non-empty string reason
                    reason = raw
                    break

        # requires-python: take the first non-empty value across files.
        requires_python: str | None = None
        for fd in v_files:
            rp = fd.get("requires-python")
            if rp:
                requires_python = rp
                break

        result.append(
            VersionInfo(
                version=v,
                yanked=all_yanked,
                yanked_reason=reason,
                requires_python=requires_python,
            )
        )
    return result


def _filter_files_for_version(
    files: list[dict[str, str | None]],
    version: str,
    page_url: str,
) -> list[FileInfo]:
    """Filter parsed HTML files for a specific version.

    Args:
        page_url: Base URL for resolving relative file hrefs.  A trailing slash
            is enforced defensively --- misconfigured reverse proxies
            (Nginx, Artifactory) may strip it, which causes
            `urllib.parse.urljoin` to resolve relative paths against
            the wrong parent directory.
    """
    target = Version(version)
    result: list[FileInfo] = []

    # Defensive trailing-slash enforcement for correct urljoin behavior.
    if not page_url.endswith("/"):
        page_url += "/"

    for f in files:
        filename = f.get("filename", "") or ""
        file_version = parse_version_from_filename(filename)
        if file_version is None or file_version != target:
            continue

        href = f.get("href", "") or ""

        # Separate URL from hash fragment
        url_no_frag, fragment = urldefrag(href)

        # Resolve relative URLs against the page URL
        url = urljoin(page_url, url_no_frag)

        # Hash from URL fragment
        file_hash = _parse_hash_from_fragment(fragment)

        # PEP 658 / PEP 714 metadata (parser already resolved the
        # attribute priority: data-core-metadata > data-dist-info-metadata)
        metadata_available, metadata_hash = _parse_metadata_attr(
            f.get("core-metadata"),
        )

        # PEP 592 yanked status.  The parser normalises bare
        # `data-yanked` (no value) to `""` and absent to `None`.
        yanked_attr = f.get("data-yanked")
        is_yanked = yanked_attr is not None
        yanked_reason = yanked_attr or None

        # File size: not part of the PEP 503 HTML spec, but some
        # registries emit `data-size` anyway.  Parse if present.
        size_raw = f.get("data-size")
        size: int | None = None
        if size_raw is not None:
            with contextlib.suppress(ValueError, TypeError):
                size = int(size_raw)

        result.append(
            FileInfo(
                filename=filename,
                url=url,
                hash=file_hash,
                requires_python=f.get("requires-python"),
                dist_type=determine_dist_type(filename),
                size=size,
                metadata_available=metadata_available,
                metadata_hash=metadata_hash,
                yanked=is_yanked,
                yanked_reason=yanked_reason,
            ),
        )

    return result
