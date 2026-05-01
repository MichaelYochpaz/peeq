"""Domain models for peeq.

All models use Pydantic v2 BaseModel. Most are frozen (immutable) since they
represent snapshots of external data. The exception is `PackageMetadata`,
which is mutable because it is assembled in stages during cache reads.

Type reference
--------------
- `PkgVersion`: `Annotated[packaging.version.Version, ...]` with a custom
  Pydantic core schema so it validates from `str` and serializes back to
  `str`.
- `Dependency`: structured representation of a PEP 508 requirement string.
  Primary constructor is the `from_requirement_string()` classmethod.
- `ImportName`: an import name declared by a package per
  PEP 794 (https://peps.python.org/pep-0794/).
- `PackageMetadata`: unified metadata returned by all extraction functions.
  `dependencies`, `source`, `source_filename`, and `dynamic_fields`
  are excluded from JSON blob serialization (they live in dedicated database
  columns and tables).
"""

from __future__ import annotations

import enum
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, Any, Literal

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name
from packaging.version import Version
from pydantic import BaseModel, Field, GetCoreSchemaHandler, GetJsonSchemaHandler
from pydantic_core import core_schema

if TYPE_CHECKING:
    from pydantic.json_schema import JsonSchemaValue


# ---------------------------------------------------------------------------
# PkgVersion — custom Pydantic type wrapping packaging.version.Version
# ---------------------------------------------------------------------------


class _PkgVersionAnnotation:
    """Pydantic annotation that bridges `packaging.version.Version`.

    Accepts `str` (JSON and Python) or an existing `Version` instance
    (Python only). Always serializes to the string representation.
    """

    @classmethod
    def __get_pydantic_core_schema__(
        cls,
        _source_type: Any,
        _handler: GetCoreSchemaHandler,
    ) -> core_schema.CoreSchema:
        def _validate_from_str(value: str) -> Version:
            return Version(value)

        from_str_schema = core_schema.chain_schema(
            [
                core_schema.str_schema(),
                core_schema.no_info_plain_validator_function(_validate_from_str),
            ]
        )

        return core_schema.json_or_python_schema(
            json_schema=from_str_schema,
            python_schema=core_schema.union_schema(
                [
                    core_schema.is_instance_schema(Version),
                    from_str_schema,
                ]
            ),
            serialization=core_schema.plain_serializer_function_ser_schema(
                str,
            ),
        )

    @classmethod
    def __get_pydantic_json_schema__(
        cls,
        _core_schema: core_schema.CoreSchema,
        handler: GetJsonSchemaHandler,
    ) -> JsonSchemaValue:
        return handler(core_schema.str_schema())


PkgVersion = Annotated[Version, _PkgVersionAnnotation]
"""A `packaging.version.Version` that Pydantic can validate and serialize.

Accepts version strings like `"1.2.3"` or `"2.0.0rc1"` and produces a
`Version` instance. Serializes back to the normalized string form.
"""


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class DistType(str, enum.Enum):
    """Distribution type for a package artifact."""

    SDIST = "sdist"
    WHEEL = "wheel"


# ---------------------------------------------------------------------------
# Frozen value objects
# ---------------------------------------------------------------------------


class HashDigest(BaseModel, frozen=True):
    """SHA-256 digest of a cached archive file.

    `source` indicates whether the hash was provided by the package registry
    (trustworthy — the registry computed it from the uploaded artifact) or
    computed locally after download (self-verified only).
    """

    sha256: str
    source: Literal["registry", "computed"]


class Dependency(BaseModel, frozen=True):
    """A single package dependency parsed from a PEP 508 requirement string.

    The `extras` field refers to extras of THIS dependency (e.g.,
    `["http2"]` for `httpx[http2]`). Parent-extra conditions (e.g.,
    `extra == "socks"`) live in the `markers` field as environment
    markers — this matches `packaging.Requirement` semantics.

    Primary constructor is `from_requirement_string()`. Direct kwargs
    are for testing and database reconstruction.
    """

    name: str
    """Normalized package name (lowercase, separators become `-`)."""

    specifier: str = ""
    """Version specifier, e.g., `">=1.21.1,<3"`. Empty if unconstrained."""

    extras: list[str] = []
    """Extras requested from this dependency, e.g., `["http2"]`."""

    markers: str | None = None
    """PEP 508 environment markers, e.g., `'python_version >= "3.8"'`."""

    raw: str = ""
    """Original requirement string for round-trip fidelity."""

    @classmethod
    def from_requirement_string(cls, raw: str) -> Dependency:
        """Parse a PEP 508 requirement string into a `Dependency`.

        Names are normalized via `packaging.utils.canonicalize_name()`
        for consistent database index lookups.
        """
        req = Requirement(raw)
        return cls(
            name=canonicalize_name(req.name),
            specifier=str(req.specifier),
            extras=sorted(req.extras),
            markers=str(req.marker) if req.marker else None,
            raw=raw,
        )


class PackageInfo(BaseModel, frozen=True):
    """Basic package information from a registry API response.

    Returned by `PackageRepository.check()`.
    """

    name: str
    latest_version: PkgVersion
    version_count: int
    summary: str | None = None
    license: str | None = None
    """License string — SPDX expression or free text."""
    license_format: str | None = None
    """`"expression"` (SPDX, PEP 639) or `"text"` (deprecated `License` header)."""
    requires_python: str | None = None
    """Python version specifier (e.g., `">=3.8"`)."""
    author: str | None = None
    """Package author name."""
    project_urls: dict[str, str] | None = None
    """Mapping of label to URL (e.g., `{"Source": "https://..."}`)."""
    latest_release_date: datetime | None = None
    """Upload time of the latest release (UTC, or `None`)."""
    registry: str = "pypi.org"


class VersionInfo(BaseModel, frozen=True):
    """Version with yanked status from a registry API response.

    A version is considered yanked when ALL of its distribution files
    are yanked (PEP 592 (https://peps.python.org/pep-0592/)).  The
    reason is the first non-empty yank reason found across the
    version's files, or `None` if all files are yanked without a
    stated reason.

    Returned by `PackageRepository.versions()`.
    """

    version: PkgVersion
    yanked: bool = False
    """Whether all files for this version have been yanked."""
    yanked_reason: str | None = None
    """First non-empty maintainer-provided yank reason, if any."""
    release_date: datetime | None = None
    """Earliest upload time across the version's files (UTC, or `None`)."""
    requires_python: str | None = None
    """`Requires-Python` specifier from the Simple API (PEP 503), if any."""


class FileInfo(BaseModel, frozen=True):
    """A single file (sdist or wheel) available for download from a registry.

    Returned by `PackageRepository.files()`.
    """

    filename: str
    url: str
    hash: HashDigest | None = None
    requires_python: str | None = None
    dist_type: DistType
    size: int | None = None
    metadata_available: bool = False
    """Whether PEP 658 metadata is available for this file."""
    metadata_hash: HashDigest | None = None
    """Hash of the PEP 658 metadata file, if provided by the registry."""
    upload_time: datetime | None = None
    """Upload timestamp from PEP 700 `upload-time` (UTC, or `None`)."""
    yanked: bool = False
    """Whether the file has been yanked by the maintainer (PEP 592)."""
    yanked_reason: str | None = None
    """Maintainer-provided reason for the yank, if any."""


class DownloadResult(BaseModel, frozen=True):
    """Result of downloading and verifying a package artifact."""

    path: Path
    hash: HashDigest
    size_bytes: int


class ImportName(BaseModel, frozen=True):
    """An import name declared by a package per PEP 794.

    PEP 794 (https://peps.python.org/pep-0794/) adds two multi-use headers
    mapping distribution names to importable Python module names.  The
    `; private` modifier signals that the name is not part of the
    project's public API.
    """

    name: str
    """The importable Python name (e.g., `"PIL"`, `"sklearn"`)."""

    private: bool = False
    """Whether this name is marked with `; private` in the metadata."""


class CacheStats(BaseModel, frozen=True):
    """Aggregate statistics for the local cache.

    Returned by `peeq cache info`.
    """

    location: Path
    package_count: int
    distribution_count: int
    total_size_bytes: int
    archived_count: int = 0
    """Number of distributions with a cached archive file on disk."""
    metadata_only_count: int = 0
    """Number of distributions with metadata only (archive evicted or never stored)."""
    limit_bytes: int | None = None
    """Configured cache size limit in bytes, or `None` if unlimited."""
    usage_percent: float | None = None
    """Current usage as a percentage of the limit, or `None` if unlimited."""
    oldest_entry: datetime | None = None
    newest_entry: datetime | None = None


# ---------------------------------------------------------------------------
# Vulnerability models (OSV API)
# ---------------------------------------------------------------------------


class CvssSeverity(BaseModel, frozen=True):
    """CVSS severity score from the OSV vulnerability record.

    The `score` is a CVSS vector string (not a numeric value).  The
    `type` indicates the CVSS version: `"CVSS_V2"`, `"CVSS_V3"`,
    or `"CVSS_V4"`.
    """

    type: str
    """CVSS type identifier (e.g., `"CVSS_V3"`)."""

    score: str
    """CVSS vector string (e.g., `"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N"`)."""


class VulnerabilityReference(BaseModel, frozen=True):
    """A reference link from a vulnerability record.

    Reference types include `ADVISORY`, `FIX`, `REPORT`, `WEB`,
    `PACKAGE`, and others defined by the
    OSV schema (https://ossf.github.io/osv-schema/).
    """

    type: str
    """Reference type (e.g., `"ADVISORY"`, `"FIX"`)."""

    url: str
    """URL of the reference."""


class VulnerabilityInfo(BaseModel, frozen=True):
    """A single known vulnerability from the OSV database.

    Populated from the OSV API (https://google.github.io/osv.dev/api/)
    `POST /v1/query` response.  CVE identifiers live in the `aliases`
    list.  Fixed versions are extracted from `affected[].ranges[].events`
    where an event has a `fixed` key.
    """

    id: str
    """OSV identifier (e.g., `"GHSA-h75v-3vvj-5mfj"`, `"PYSEC-2021-66"`)."""

    summary: str | None = None
    """One-line English summary (recommended ≤120 chars)."""

    details: str | None = None
    """Extended description in CommonMark Markdown."""

    aliases: list[str] = []
    """Cross-references (CVE IDs and other database IDs)."""

    severity: list[CvssSeverity] = []
    """Top-level CVSS scores.  May be empty for some records."""

    severity_label: str | None = None
    """Text severity label from `database_specific.severity` (GHSA records).

    Values: `"LOW"`, `"MODERATE"`, `"HIGH"`, `"CRITICAL"`, or `None`.
    """

    fixed_versions: list[str] = []
    """Versions that fix this vulnerability (from `affected[].ranges[].events[].fixed`)."""

    references: list[VulnerabilityReference] = []
    """Advisory, fix, and other reference links."""

    published: datetime | None = None
    """When the vulnerability was first published (UTC)."""

    modified: datetime | None = None
    """When the record was last modified (UTC)."""

    withdrawn: bool = False
    """Whether the vulnerability has been retracted."""


class VulnerabilityReport(BaseModel, frozen=True):
    """Vulnerability report for a specific package version.

    Returned by `check_vulnerabilities`.
    """

    package: str
    """Package name as queried."""

    version: str
    """Version string as queried."""

    vulnerabilities: list[VulnerabilityInfo] = []
    """Known vulnerabilities affecting this version (may be empty)."""


# ---------------------------------------------------------------------------
# Mutable model — assembled in stages during cache reads
# ---------------------------------------------------------------------------


class PackageMetadata(BaseModel):
    """Unified metadata returned by all metadata extraction functions.

    Fields are optional because not every source can provide every field.

    **Not frozen** — assembled in stages during cache reads:

    1. JSON blob  ->  scalar fields (`python_requires`, `license`, etc.)
    2. `metadata_source` column  ->  `source`
    3. `filename` column  ->  `source_filename`
    4. `dynamic_fields` column  ->  `dynamic_fields`
    5. `dependencies` table  ->  `dependencies`
    6. `deps_known` column  ->  `None` vs `[]` disambiguation

    Serialization contract:

    - **Write**: `model.model_dump(mode="json",
      exclude={"dependencies", "source", "source_filename", "dynamic_fields"})`
      produces the JSON blob for the `distributions.metadata` column.
      `dependencies` go to the `dependencies` table.
      `source` goes to `metadata_source` column.
      `source_filename` goes to `filename` column.
      `dynamic_fields` goes to `dynamic_fields` column.
      `license_format`, `import_names`, `import_namespaces` live in
      the JSON blob.
    - **Read**: Deserialize JSON blob, then set `.source` from column,
      `.source_filename` from column, `.dynamic_fields` from column,
      and `.dependencies` from table rows (or leave `None` if
      `deps_known=FALSE`).
    """

    # -- Data fields --------------------------------------------------------

    dependencies: list[Dependency] | None = None
    python_requires: str | None = None
    license: str | None = None
    license_format: str | None = None
    """`"expression"` (SPDX, PEP 639) or `"text"` (deprecated header)."""

    summary: str | None = None
    author: str | None = None
    homepage: str | None = None

    import_names: list[ImportName] | None = None
    """PEP 794 `Import-Name` — names the project exclusively provides."""

    import_namespaces: list[ImportName] | None = None
    """PEP 794 `Import-Namespace` — shared namespace packages."""

    # -- Provenance and diagnostics -----------------------------------------

    source: str | None = None
    """Which extraction function provided this metadata (e.g., `"pep658"`)."""

    source_filename: str | None = None
    """Original filename metadata came from (e.g., `"requests-2.31.0-py3-none-any.whl"`)."""

    dynamic_fields: list[str] | None = None
    """PEP 643 Dynamic field names (e.g., `["Requires-Dist", "License"]`)."""


# ---------------------------------------------------------------------------
# Composite report — info command
# ---------------------------------------------------------------------------


class InfoReport(BaseModel):
    """Composite report for the `info` command.

    Sections are populated based on CLI flags (`--versions`, `--vulns`,
    `--deps`, `--full`).  `None` means the section was not requested.
    """

    info: PackageInfo
    """Base package information (always present)."""

    target_version: str | None = None
    """Resolved version this report targets (explicit `--version` or latest)."""

    versions: list[VersionInfo] | None = None
    """Version list (populated when `--versions` or `--full` is set)."""

    versions_total: int | None = None
    """Total version count (for 'showing N of M' display when truncated)."""

    vulnerabilities: VulnerabilityReport | None = None
    """Vulnerability report (populated when `--vulns` or `--full` is set)."""

    metadata: PackageMetadata | None = None
    """Package metadata with dependencies (populated when `--deps` or `--full` is set)."""

    target_version_yanked: bool | None = None
    """Whether the targeted version has been yanked (PEP 592).

    `None` means yanked status was not checked (no version data fetched).
    """

    target_version_yanked_reason: str | None = None
    """Maintainer-provided yank reason, if any."""

    errors: dict[str, str] | None = None
    """Per-section error messages for partial failures (section name → message)."""


# ---------------------------------------------------------------------------
# Dependency diff models
# ---------------------------------------------------------------------------


class DepChange(BaseModel, frozen=True):
    """A dependency whose specifier, markers, or extras changed between versions."""

    name: str
    """Canonical package name."""

    old_specifier: str
    """Version specifier in the base version."""

    new_specifier: str
    """Version specifier in the target version."""

    old_markers: str | None = None
    """Environment markers in the base version."""

    new_markers: str | None = None
    """Environment markers in the target version."""

    old_extras: tuple[str, ...] = ()
    """Requested extras in the base version (e.g., `('http2',)` for `httpx[http2]`)."""

    new_extras: tuple[str, ...] = ()
    """Requested extras in the target version."""

    extras_group: str | None = None
    """The extras group this dependency belongs to, or `None` for core."""


class DepsDiff(BaseModel, frozen=True):
    """Dependency differences between two versions of a package."""

    added: list[Dependency] = Field(default_factory=list)
    """Dependencies present in the target but not the base."""

    removed: list[Dependency] = Field(default_factory=list)
    """Dependencies present in the base but not the target."""

    changed: list[DepChange] = Field(default_factory=list)
    """Dependencies with matching name but different specifier, markers, or extras."""

    unchanged_count: int = 0
    """Number of dependencies identical in both versions."""

    added_extras: list[str] = Field(default_factory=list)
    """Extras groups present in the target but not the base."""

    removed_extras: list[str] = Field(default_factory=list)
    """Extras groups present in the base but not the target."""
