"""In-memory archive extraction with resource limits.

Extracts files from tar.gz and .whl (zip) archives without writing to disk.
This eliminates path-traversal attack surfaces (Zip Slip / Tar Slip) for
normal operations.  The `download --extract` command is the only code path
that writes extracted files to disk — and it must use PEP 706 safety (see
`extract_archive_to_disk`).

Resource limits protect against decompression bombs.  Defaults are configured
via `ExtractionConfig` and can be overridden through
environment variables or the config file.  See `peeq.config` for
details.
"""

from __future__ import annotations

import sys
import tarfile
import zipfile
from dataclasses import dataclass, field
from typing import IO, TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterable
    from pathlib import Path

    from peeq.config import ExtractionConfig

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_MB = 1024 * 1024


# ---------------------------------------------------------------------------
# Custom exceptions
# ---------------------------------------------------------------------------


class ExtractionError(Exception):
    """Base exception for extraction failures."""


class ExtractionLimitExceededError(ExtractionError):
    """A resource limit was exceeded during extraction."""


class ExtractionFileNotFoundError(ExtractionError):
    """The requested file was not found in the archive."""


class UnsupportedArchiveFormatError(ExtractionError):
    """The archive format is not supported."""


# ---------------------------------------------------------------------------
# Resource limits
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ExtractionLimits:
    """Resource limits for archive extraction.

    All sizes are in bytes internally.  Use `from_config` to construct
    from an `ExtractionConfig` instance (megabyte
    values are converted to bytes).
    """

    max_total_bytes: int = 500 * _MB
    max_file_count: int = 50_000
    max_single_file_bytes: int = 100 * _MB

    @classmethod
    def from_config(cls, config: ExtractionConfig) -> ExtractionLimits:
        """Create limits from an `ExtractionConfig`."""
        return cls(
            max_total_bytes=config.max_size_mb * _MB,
            max_file_count=config.max_files,
            max_single_file_bytes=config.max_file_size_mb * _MB,
        )


# ---------------------------------------------------------------------------
# Archive member metadata
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ArchiveMember:
    """Metadata for a single file inside an archive."""

    path: str
    """Relative path within the archive (forward slashes, no leading `/`)."""

    size: int
    """Uncompressed size in bytes (`0` for directories)."""

    is_dir: bool
    """Whether this member is a directory."""


# ---------------------------------------------------------------------------
# In-memory extraction results
# ---------------------------------------------------------------------------


@dataclass
class ExtractionResult:
    """Result of listing or extracting archive contents."""

    members: list[ArchiveMember] = field(default_factory=list)
    """All members that were enumerated (respecting limits)."""

    total_uncompressed_bytes: int = 0
    """Sum of uncompressed file sizes seen so far."""

    file_count: int = 0
    """Number of regular files (not directories) seen so far."""


# ---------------------------------------------------------------------------
# Public API — in-memory operations (safe: no disk writes)
# ---------------------------------------------------------------------------


def list_archive(
    archive_path: Path,
    *,
    limits: ExtractionLimits | None = None,
) -> list[ArchiveMember]:
    """List all files in an archive without extracting.

    Paths are relative to the package root.  For archives with a single
    top-level directory (standard sdist layout), the root directory
    prefix is stripped and the directory entry itself is excluded.

    Parameters
    ----------
    archive_path:
        Path to a `.tar.gz` or `.whl` (zip) archive on disk.
    limits:
        Resource limits.  Only `max_file_count` is enforced (to prevent
        pathological enumeration).  Defaults to `ExtractionLimits`
        defaults.

    Returns
    -------
    list[ArchiveMember]
        Sorted list of archive members with paths relative to the
        package root.

    Raises
    ------
    UnsupportedArchiveFormatError
        If the archive type cannot be detected.
    ExtractionLimitExceededError
        If the file count exceeds the configured limit.
    """
    if limits is None:
        from peeq.config import get_settings  # noqa: PLC0415

        limits = ExtractionLimits.from_config(get_settings().extraction)

    kind = _detect_archive_kind(archive_path)

    if kind == "tar":
        return _list_tar(archive_path, limits)
    return _list_zip(archive_path, limits)


def extract_file(
    archive_path: Path,
    member_path: str,
    *,
    limits: ExtractionLimits | None = None,
) -> bytes:
    """Extract a single file from an archive into memory.

    *member_path* is relative to the package root.  For archives with a
    single top-level directory (standard sdist layout), the root prefix
    is prepended automatically before lookup.

    Parameters
    ----------
    archive_path:
        Path to a `.tar.gz` or `.whl` (zip) archive on disk.
    member_path:
        Path relative to the package root (forward slashes).
    limits:
        Resource limits.  `max_single_file_bytes` is enforced.  Defaults
        to `ExtractionLimits` defaults.

    Returns
    -------
    bytes
        Uncompressed file content.

    Raises
    ------
    ExtractionFileNotFoundError
        If *member_path* is not found in the archive.
    ExtractionLimitExceededError
        If the file exceeds the single-file size limit.
    UnsupportedArchiveFormatError
        If the archive type cannot be detected.
    """
    if limits is None:
        from peeq.config import get_settings  # noqa: PLC0415

        limits = ExtractionLimits.from_config(get_settings().extraction)

    kind = _detect_archive_kind(archive_path)

    if kind == "tar":
        return _extract_file_tar(archive_path, member_path, limits)
    return _extract_file_zip(archive_path, member_path, limits)


def extract_all(
    archive_path: Path,
    *,
    limits: ExtractionLimits | None = None,
) -> dict[str, bytes]:
    """Extract all files from an archive into memory.

    Keys are paths relative to the package root.  For archives with a
    single top-level directory (standard sdist layout), the root prefix
    is stripped from all keys.

    Parameters
    ----------
    archive_path:
        Path to a `.tar.gz` or `.whl` (zip) archive on disk.
    limits:
        Resource limits.  All limits are enforced.

    Returns
    -------
    dict[str, bytes]
        Mapping of paths (relative to package root) to their
        uncompressed content.  Directories are excluded.

    Raises
    ------
    ExtractionLimitExceededError
        If any resource limit is exceeded.
    UnsupportedArchiveFormatError
        If the archive type cannot be detected.
    """
    if limits is None:
        from peeq.config import get_settings  # noqa: PLC0415

        limits = ExtractionLimits.from_config(get_settings().extraction)

    kind = _detect_archive_kind(archive_path)

    if kind == "tar":
        return _extract_all_tar(archive_path, limits)
    return _extract_all_zip(archive_path, limits)


# ---------------------------------------------------------------------------
# Public API — disk extraction (for `download --extract`)
# ---------------------------------------------------------------------------


def extract_archive_to_disk(
    archive_path: Path,
    dest: Path,
    *,
    limits: ExtractionLimits | None = None,
) -> list[Path]:
    """Extract an archive to disk with PEP 706 safety.

    On Python 3.12+ uses `tarfile.data_filter`.  On 3.10/3.11 applies
    a manual safety shim that validates paths, rejects symlinks outside
    the destination, and blocks device files.

    Parameters
    ----------
    archive_path:
        Path to a `.tar.gz` or `.whl` (zip) archive.
    dest:
        Directory to extract into (created if missing).
    limits:
        Resource limits.  All limits are enforced.

    Returns
    -------
    list[Path]
        Sorted list of extracted file paths (relative to *dest*).

    Raises
    ------
    ExtractionLimitExceededError
        If any resource limit is exceeded.
    ExtractionError
        If a member fails safety validation (path traversal, symlinks, etc.).
    UnsupportedArchiveFormatError
        If the archive type cannot be detected.
    """
    if limits is None:
        from peeq.config import get_settings  # noqa: PLC0415

        limits = ExtractionLimits.from_config(get_settings().extraction)

    dest.mkdir(parents=True, exist_ok=True)
    kind = _detect_archive_kind(archive_path)

    if kind == "tar":
        return _extract_tar_to_disk(archive_path, dest, limits)
    return _extract_zip_to_disk(archive_path, dest, limits)


# ---------------------------------------------------------------------------
# Archive type detection
# ---------------------------------------------------------------------------


def _detect_archive_kind(path: Path) -> str:
    """Detect archive type from the file extension.

    Returns `"tar"` or `"zip"`.
    """
    name = path.name.lower()
    if name.endswith((".tar.gz", ".tgz", ".tar.bz2", ".tar.xz", ".tar")):
        return "tar"
    if name.endswith((".whl", ".zip")):
        return "zip"
    msg = f"Unsupported archive format: {path.name}"
    raise UnsupportedArchiveFormatError(msg)


# ---------------------------------------------------------------------------
# Root prefix detection
# ---------------------------------------------------------------------------


def _detect_root_prefix(names: Iterable[str]) -> str:
    """Detect a common single root directory prefix from archive member names.

    Standard sdist archives wrap all files inside a top-level directory
    named `{name}-{version}/` (per
    PEP 625 (https://peps.python.org/pep-0625/)).  If all members
    share a single top-level directory and at least one member is nested
    inside it, return that directory name (without trailing slash).
    Otherwise return an empty string.

    This is used to present archive paths relative to the package root,
    hiding the implementation detail of the sdist root directory from
    callers.
    """
    roots: set[str] = set()
    any_nested = False

    for raw in names:
        name = raw.rstrip("/")
        if not name:
            continue
        parts = name.split("/", 1)
        top = parts[0]
        if not top:
            continue
        roots.add(top)
        if len(roots) > 1:
            return ""
        if len(parts) > 1 and parts[1]:
            any_nested = True

    if len(roots) == 1 and any_nested:
        return roots.pop()
    return ""


# ---------------------------------------------------------------------------
# tar.gz helpers
# ---------------------------------------------------------------------------


def _list_tar(
    archive_path: Path,
    limits: ExtractionLimits,
) -> list[ArchiveMember]:
    members: list[ArchiveMember] = []
    file_count = 0

    with tarfile.open(archive_path, "r:*") as tf:
        root_prefix = _detect_root_prefix(tf.getnames())
        prefix_slash = f"{root_prefix}/" if root_prefix else ""

        for info in tf.getmembers():
            path = info.name

            # Strip root prefix from paths
            if prefix_slash:
                if path.rstrip("/") == root_prefix:
                    continue  # Skip the root directory entry itself
                path = path.removeprefix(prefix_slash)

            if not path or path == "/":
                continue

            is_dir = info.isdir()
            if not is_dir:
                file_count += 1
                if file_count > limits.max_file_count:
                    msg = (
                        f"Archive exceeds max file count "
                        f"({limits.max_file_count:,} files)"
                    )
                    raise ExtractionLimitExceededError(msg)

            members.append(
                ArchiveMember(
                    path=path,
                    size=info.size,
                    is_dir=is_dir,
                )
            )

    return sorted(members, key=lambda m: m.path)


def _extract_file_tar(
    archive_path: Path,
    member_path: str,
    limits: ExtractionLimits,
) -> bytes:
    with tarfile.open(archive_path, "r:*") as tf:
        root_prefix = _detect_root_prefix(tf.getnames())
        resolved = f"{root_prefix}/{member_path}" if root_prefix else member_path

        try:
            info = tf.getmember(resolved)
        except KeyError:
            msg = f"File not found in archive: {member_path}"
            raise ExtractionFileNotFoundError(msg) from None

        if info.isdir():
            msg = f"Path is a directory, not a file: {member_path}"
            raise ExtractionFileNotFoundError(msg)

        if info.size > limits.max_single_file_bytes:
            msg = (
                f"File {member_path} ({info.size:,} bytes) exceeds max "
                f"single file size ({limits.max_single_file_bytes:,} bytes)"
            )
            raise ExtractionLimitExceededError(msg)

        f = tf.extractfile(info)
        if f is None:
            msg = f"Cannot extract file (not a regular file): {member_path}"
            raise ExtractionFileNotFoundError(msg)

        return _read_with_limit(f, info.size, limits.max_single_file_bytes)


def _extract_all_tar(
    archive_path: Path,
    limits: ExtractionLimits,
) -> dict[str, bytes]:
    result: dict[str, bytes] = {}
    total_bytes = 0
    file_count = 0

    with tarfile.open(archive_path, "r:*") as tf:
        root_prefix = _detect_root_prefix(tf.getnames())
        prefix_slash = f"{root_prefix}/" if root_prefix else ""

        for info in tf.getmembers():
            if info.isdir() or not info.isreg():
                continue

            # Strip root prefix from path
            path = info.name
            if prefix_slash:
                if path.startswith(prefix_slash):
                    path = path[len(prefix_slash) :]
                elif path.rstrip("/") == root_prefix:
                    continue

            if not path:
                continue

            file_count += 1
            if file_count > limits.max_file_count:
                msg = (
                    f"Archive exceeds max file count ({limits.max_file_count:,} files)"
                )
                raise ExtractionLimitExceededError(msg)

            if info.size > limits.max_single_file_bytes:
                msg = (
                    f"File {path} ({info.size:,} bytes) exceeds max "
                    f"single file size ({limits.max_single_file_bytes:,} bytes)"
                )
                raise ExtractionLimitExceededError(msg)

            total_bytes += info.size
            if total_bytes > limits.max_total_bytes:
                msg = (
                    f"Archive exceeds max total uncompressed size "
                    f"({limits.max_total_bytes:,} bytes)"
                )
                raise ExtractionLimitExceededError(msg)

            f = tf.extractfile(info)
            if f is None:
                continue

            result[path] = _read_with_limit(f, info.size, limits.max_single_file_bytes)

    return result


def _extract_tar_to_disk(
    archive_path: Path,
    dest: Path,
    limits: ExtractionLimits,
) -> list[Path]:
    """Extract tar archive to disk with PEP 706 safety."""
    extracted: list[Path] = []
    total_bytes = 0
    file_count = 0

    with tarfile.open(archive_path, "r:*") as tf:
        for info in tf.getmembers():
            if info.isdir():
                continue

            file_count += 1
            if file_count > limits.max_file_count:
                msg = (
                    f"Archive exceeds max file count ({limits.max_file_count:,} files)"
                )
                raise ExtractionLimitExceededError(msg)

            if info.size > limits.max_single_file_bytes:
                msg = (
                    f"File {info.name} ({info.size:,} bytes) exceeds max "
                    f"single file size ({limits.max_single_file_bytes:,} bytes)"
                )
                raise ExtractionLimitExceededError(msg)

            total_bytes += info.size
            if total_bytes > limits.max_total_bytes:
                msg = (
                    f"Archive exceeds max total uncompressed size "
                    f"({limits.max_total_bytes:,} bytes)"
                )
                raise ExtractionLimitExceededError(msg)

            # PEP 706 safety: validate and extract
            if sys.version_info >= (3, 12):
                _extract_tar_member_312(tf, info, dest)
            else:
                _extract_tar_member_safe(tf, info, dest)

            extracted.append(dest / info.name)

    return sorted(extracted)


def _extract_tar_member_312(
    tf: tarfile.TarFile,
    info: tarfile.TarInfo,
    dest: Path,
) -> None:
    """Extract a tar member using Python 3.12+ `data_filter`."""
    tf.extract(info, path=dest, filter="data")


def _extract_tar_member_safe(
    tf: tarfile.TarFile,
    info: tarfile.TarInfo,
    dest: Path,
) -> None:
    """Extract a tar member with manual safety shim for Python 3.10/3.11.

    Validates against:
    - Path traversal (`..` components)
    - Absolute paths
    - Symlinks that escape the destination
    - Device files (block/char devices, FIFOs)
    """
    # Reject device files and FIFOs
    if info.isblk() or info.ischr() or info.isfifo():
        msg = f"Refusing to extract special file: {info.name}"
        raise ExtractionError(msg)

    # Reject absolute paths
    if info.name.startswith(("/", "\\")):
        msg = f"Refusing to extract absolute path: {info.name}"
        raise ExtractionError(msg)

    # Resolve the target path and ensure it stays within dest
    target = (dest / info.name).resolve()
    dest_resolved = dest.resolve()
    if not target.is_relative_to(dest_resolved):
        msg = f"Path traversal detected: {info.name}"
        raise ExtractionError(msg)

    # Handle symlinks: reject if they point outside dest
    if info.issym() or info.islnk():
        if info.issym():
            link_target = (target.parent / info.linkname).resolve()
        else:
            link_target = (dest / info.linkname).resolve()

        if not link_target.is_relative_to(dest_resolved):
            msg = f"Symlink escapes destination: {info.name} -> {info.linkname}"
            raise ExtractionError(msg)

    # Safe to extract — create parent dirs
    target.parent.mkdir(parents=True, exist_ok=True)

    if info.isreg():
        f = tf.extractfile(info)
        if f is not None:
            with target.open("wb") as out:
                out.write(f.read())
    elif info.issym():
        target.symlink_to(info.linkname)
    elif info.islnk():
        link_src = dest / info.linkname
        if link_src.exists():
            target.hardlink_to(link_src)


# ---------------------------------------------------------------------------
# zip helpers (for .whl files)
# ---------------------------------------------------------------------------


def _list_zip(
    archive_path: Path,
    limits: ExtractionLimits,
) -> list[ArchiveMember]:
    members: list[ArchiveMember] = []
    file_count = 0

    with zipfile.ZipFile(archive_path, "r") as zf:
        # Only strip root prefix for sdist zips, not wheels.
        is_wheel = archive_path.name.lower().endswith(".whl")
        root_prefix = "" if is_wheel else _detect_root_prefix(zf.namelist())
        prefix_slash = f"{root_prefix}/" if root_prefix else ""

        for info in zf.infolist():
            path = info.filename

            # Strip root prefix from paths
            if prefix_slash:
                if path.rstrip("/") == root_prefix:
                    continue  # Skip the root directory entry itself
                path = path.removeprefix(prefix_slash)

            if not path or path == "/":
                continue

            is_dir = info.is_dir()
            if not is_dir:
                file_count += 1
                if file_count > limits.max_file_count:
                    msg = (
                        f"Archive exceeds max file count "
                        f"({limits.max_file_count:,} files)"
                    )
                    raise ExtractionLimitExceededError(msg)

            members.append(
                ArchiveMember(
                    path=path,
                    size=info.file_size,
                    is_dir=is_dir,
                )
            )

    return sorted(members, key=lambda m: m.path)


def _extract_file_zip(
    archive_path: Path,
    member_path: str,
    limits: ExtractionLimits,
) -> bytes:
    with zipfile.ZipFile(archive_path, "r") as zf:
        # Only resolve root prefix for sdist zips, not wheels.
        is_wheel = archive_path.name.lower().endswith(".whl")
        root_prefix = "" if is_wheel else _detect_root_prefix(zf.namelist())
        resolved = f"{root_prefix}/{member_path}" if root_prefix else member_path

        try:
            info = zf.getinfo(resolved)
        except KeyError:
            msg = f"File not found in archive: {member_path}"
            raise ExtractionFileNotFoundError(msg) from None

        if info.is_dir():
            msg = f"Path is a directory, not a file: {member_path}"
            raise ExtractionFileNotFoundError(msg)

        # Pre-check declared size (fast reject), but don't trust it —
        # the actual decompressed size may differ (decompression bomb).
        if info.file_size > limits.max_single_file_bytes:
            msg = (
                f"File {member_path} ({info.file_size:,} bytes) exceeds max "
                f"single file size ({limits.max_single_file_bytes:,} bytes)"
            )
            raise ExtractionLimitExceededError(msg)

        with zf.open(resolved) as f:
            return _read_with_limit(f, info.file_size, limits.max_single_file_bytes)


def _extract_all_zip(
    archive_path: Path,
    limits: ExtractionLimits,
) -> dict[str, bytes]:
    result: dict[str, bytes] = {}
    total_bytes = 0
    file_count = 0

    with zipfile.ZipFile(archive_path, "r") as zf:
        # Only strip root prefix for sdist zips, not wheels.
        is_wheel = archive_path.name.lower().endswith(".whl")
        root_prefix = "" if is_wheel else _detect_root_prefix(zf.namelist())
        prefix_slash = f"{root_prefix}/" if root_prefix else ""

        for info in zf.infolist():
            if info.is_dir():
                continue

            # Strip root prefix from path
            path = info.filename
            if prefix_slash:
                if path.startswith(prefix_slash):
                    path = path[len(prefix_slash) :]
                elif path.rstrip("/") == root_prefix:
                    continue

            if not path:
                continue

            file_count += 1
            if file_count > limits.max_file_count:
                msg = (
                    f"Archive exceeds max file count ({limits.max_file_count:,} files)"
                )
                raise ExtractionLimitExceededError(msg)

            # Pre-check declared sizes (fast reject for obviously
            # oversized files), but actual limits are enforced by
            # _read_with_limit during decompression.
            if info.file_size > limits.max_single_file_bytes:
                msg = (
                    f"File {path} ({info.file_size:,} bytes) exceeds "
                    f"max single file size "
                    f"({limits.max_single_file_bytes:,} bytes)"
                )
                raise ExtractionLimitExceededError(msg)

            with zf.open(info.filename) as f:
                data = _read_with_limit(f, info.file_size, limits.max_single_file_bytes)

            total_bytes += len(data)
            if total_bytes > limits.max_total_bytes:
                msg = (
                    f"Archive exceeds max total uncompressed size "
                    f"({limits.max_total_bytes:,} bytes)"
                )
                raise ExtractionLimitExceededError(msg)

            result[path] = data

    return result


def _extract_zip_to_disk(
    archive_path: Path,
    dest: Path,
    limits: ExtractionLimits,
) -> list[Path]:
    """Extract zip archive to disk with path traversal protection."""
    extracted: list[Path] = []
    total_bytes = 0
    file_count = 0
    dest_resolved = dest.resolve()

    with zipfile.ZipFile(archive_path, "r") as zf:
        for info in zf.infolist():
            if info.is_dir():
                continue

            file_count += 1
            if file_count > limits.max_file_count:
                msg = (
                    f"Archive exceeds max file count ({limits.max_file_count:,} files)"
                )
                raise ExtractionLimitExceededError(msg)

            # Pre-check declared sizes (fast reject), but enforce actual
            # byte limits during decompression to defend against zip bombs
            # that lie about their uncompressed size in the header.
            if info.file_size > limits.max_single_file_bytes:
                msg = (
                    f"File {info.filename} ({info.file_size:,} bytes) exceeds "
                    f"max single file size "
                    f"({limits.max_single_file_bytes:,} bytes)"
                )
                raise ExtractionLimitExceededError(msg)

            # Path traversal protection — use is_relative_to instead of
            # the startswith anti-pattern (already fixed above by Item 1).
            target = (dest / info.filename).resolve()
            if not target.is_relative_to(dest_resolved):
                msg = f"Path traversal detected: {info.filename}"
                raise ExtractionError(msg)

            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info) as src:
                data = _read_with_limit(
                    src, info.file_size, limits.max_single_file_bytes
                )

            total_bytes += len(data)
            if total_bytes > limits.max_total_bytes:
                msg = (
                    f"Archive exceeds max total uncompressed size "
                    f"({limits.max_total_bytes:,} bytes)"
                )
                raise ExtractionLimitExceededError(msg)

            target.write_bytes(data)

            extracted.append(dest / info.filename)

    return sorted(extracted)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _read_with_limit(
    f: IO[bytes],
    declared_size: int,
    max_bytes: int,
) -> bytes:
    """Read from a file-like object, enforcing a byte limit.

    Checks the declared size first (fast reject), then reads with a cap
    to defend against archives that lie about member sizes.
    """
    if declared_size > max_bytes:
        msg = f"File size ({declared_size:,} bytes) exceeds limit ({max_bytes:,} bytes)"
        raise ExtractionLimitExceededError(msg)

    # Read up to max_bytes + 1 to detect if the file is actually larger
    # than declared (malicious archive lying about size).
    data = f.read(max_bytes + 1)
    if len(data) > max_bytes:
        msg = (
            f"File actual size exceeds limit ({max_bytes:,} bytes) — "
            f"archive may be lying about member sizes"
        )
        raise ExtractionLimitExceededError(msg)

    return data
