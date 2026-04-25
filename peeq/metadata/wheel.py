"""Wheel metadata extraction -- extract METADATA from a local wheel file.

Extract the `METADATA` file from a wheel's `.dist-info/` directory
and parse it into a `PackageMetadata`.

This module is I/O-bound only to local files.  Download decisions are
the service layer's responsibility.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from peeq.config import get_settings
from peeq.extraction import (
    ExtractionError,
    ExtractionLimits,
    extract_file,
    list_archive,
)
from peeq.metadata.parsing import is_pure_python_wheel, parse_email_metadata
from peeq.models import DistType, FileInfo, PackageMetadata

if TYPE_CHECKING:
    from pathlib import Path

logger = logging.getLogger(__name__)

# A path with exactly 2 parts (e.g., "pkg.dist-info/METADATA") is one level deep.
_ONE_LEVEL_DEEP = 2


def extract_wheel_metadata(path: Path) -> PackageMetadata | None:
    """Extract and parse METADATA from a local `.whl` file.

    Scan the archive for `*.dist-info/METADATA` (name normalization may
    vary between the wheel filename and the `.dist-info` directory name,
    so we scan rather than construct the path).

    Return `None` if the METADATA file cannot be found or parsed.
    """
    # 1. Find METADATA in the wheel
    metadata_member = _find_metadata_in_wheel(path)
    if metadata_member is None:
        logger.debug("METADATA not found in wheel %s", path.name)
        return None

    # 2. Extract and parse METADATA
    try:
        raw_bytes = extract_file(
            path,
            metadata_member,
            limits=ExtractionLimits.from_config(get_settings().extraction),
        )
        text = raw_bytes.decode("utf-8")
    except (ExtractionError, UnicodeDecodeError) as exc:
        logger.debug("Failed to extract METADATA from %s: %s", path.name, exc)
        return None

    return parse_email_metadata(text, source="wheel")


# ---------------------------------------------------------------------------
# Wheel selection (exported for service layer use)
# ---------------------------------------------------------------------------


def select_wheel(files: list[FileInfo]) -> FileInfo | None:
    """Select the best wheel for metadata extraction.

    Prefer pure-Python wheels (`py3-none-any`) because they are the
    smallest and most likely to contain representative metadata.  Fall
    back to the smallest available wheel.
    """
    candidates = [f for f in files if f.dist_type == DistType.WHEEL and not f.yanked]

    if not candidates:
        return None

    # Prefer pure-Python wheels
    for c in candidates:
        if is_pure_python_wheel(c.filename):
            return c

    # Fall back to smallest wheel (unknown size sorts last)
    candidates.sort(key=lambda f: f.size if f.size is not None else float("inf"))
    return candidates[0]


# ---------------------------------------------------------------------------
# METADATA discovery
# ---------------------------------------------------------------------------


def _find_metadata_in_wheel(wheel_path: Path) -> str | None:
    """Find the `METADATA` file inside a wheel archive.

    Scan archive members for `*.dist-info/METADATA` rather than
    constructing the path, because name normalization may vary between
    the wheel filename and the `.dist-info` directory name.

    Return the archive member path, or `None` if not found.
    """
    try:
        members = list_archive(wheel_path)
    except Exception:
        # list_archive raises ExtractionError for known issues, but the
        # underlying zipfile/tarfile may also raise BadZipFile, ReadError,
        # FileNotFoundError, etc.  Return None for any failure.
        return None

    for member in members:
        if member.is_dir:
            continue
        # Match: {anything}.dist-info/METADATA (exactly one directory deep)
        parts = member.path.split("/")
        if (
            len(parts) == _ONE_LEVEL_DEEP
            and parts[0].endswith(".dist-info")
            and parts[1] == "METADATA"
        ):
            return member.path

    return None
