"""Sdist metadata extraction -- extract PKG-INFO from a local sdist file.

Extract the `PKG-INFO` file from a source distribution and parse it
into a `PackageMetadata`.  Unlike wheel
`METADATA`, sdist `PKG-INFO` may contain `Dynamic` fields
(PEP 643 (https://peps.python.org/pep-0643/)) that are not resolved
until build time -- these are treated as unknown (`None`).

This module is I/O-bound only to local files.  Download decisions are
the service layer's responsibility.
"""

from __future__ import annotations

import logging
from email.parser import Parser
from typing import TYPE_CHECKING

from peeq.config import get_settings
from peeq.extraction import (
    ExtractionError,
    ExtractionLimits,
    extract_file,
    list_archive,
)
from peeq.metadata.parsing import parse_email_metadata
from peeq.models import DistType, FileInfo, PackageMetadata

if TYPE_CHECKING:
    from pathlib import Path

logger = logging.getLogger(__name__)

_EMAIL_PARSER = Parser()


def extract_sdist_metadata(path: Path) -> PackageMetadata | None:
    """Extract and parse PKG-INFO from a local sdist archive.

    Handle PEP 643 (https://peps.python.org/pep-0643/) `Dynamic`
    fields: any metadata field declared as Dynamic is treated as unknown
    (`None`) rather than trusting the placeholder value.  When
    `Requires-Dist` is Dynamic, the returned `PackageMetadata` has
    `dependencies=None` (not `[]`), signaling "unknowable" to the
    cache layer's `deps_known` flag.

    Return `None` if the PKG-INFO file cannot be found or parsed.
    """
    # 1. Find PKG-INFO in the sdist
    pkg_info_path = _find_pkg_info(path)
    if pkg_info_path is None:
        logger.debug("PKG-INFO not found in sdist %s", path.name)
        return None

    # 2. Extract PKG-INFO
    try:
        raw_bytes = extract_file(
            path,
            pkg_info_path,
            limits=ExtractionLimits.from_config(get_settings().extraction),
        )
        text = raw_bytes.decode("utf-8")
    except (ExtractionError, UnicodeDecodeError) as exc:
        logger.debug("Failed to extract PKG-INFO from %s: %s", path.name, exc)
        return None

    # 3. Parse Dynamic fields (PEP 643)
    dynamic_fields = _extract_dynamic_fields(text)

    # 4. Parse the metadata
    metadata = parse_email_metadata(
        text,
        source="sdist",
        dynamic_fields=dynamic_fields,
    )

    # 5. Preserve Dynamic field names for diagnostic display
    if dynamic_fields:
        metadata.dynamic_fields = dynamic_fields

    return metadata


# ---------------------------------------------------------------------------
# Sdist selection (exported for service layer use)
# ---------------------------------------------------------------------------


def select_sdist(files: list[FileInfo]) -> FileInfo | None:
    """Select the sdist from the file list.

    Prefer `.tar.gz` over `.zip`.  Return `None` if no sdist is
    available.
    """
    candidates = [f for f in files if f.dist_type == DistType.SDIST and not f.yanked]

    if not candidates:
        return None

    # Prefer .tar.gz over .zip
    for c in candidates:
        if c.filename.endswith(".tar.gz"):
            return c

    return candidates[0]


# ---------------------------------------------------------------------------
# PKG-INFO discovery
# ---------------------------------------------------------------------------


def _find_pkg_info(sdist_path: Path) -> str | None:
    """Find the `PKG-INFO` file inside an sdist archive.

    `list_archive` strips the sdist root directory prefix (e.g.,
    `{name}-{version}/`), so `PKG-INFO` always appears at the
    package root regardless of the original archive layout.

    Return the archive member path, or `None` if not found.
    """
    try:
        members = list_archive(sdist_path)
    except Exception:
        # list_archive raises ExtractionError for known issues, but the
        # underlying tarfile/zipfile may also raise ReadError, BadZipFile,
        # FileNotFoundError, etc.  Return None for any failure.
        return None

    for member in members:
        if not member.is_dir and member.path == "PKG-INFO":
            return member.path

    return None


# ---------------------------------------------------------------------------
# PEP 643 Dynamic field extraction
# ---------------------------------------------------------------------------


def _extract_dynamic_fields(text: str) -> list[str]:
    """Extract PEP 643 (https://peps.python.org/pep-0643/) `Dynamic` header values.

    Return a list of metadata field names that are declared as Dynamic
    (e.g., `["Requires-Dist", "License"]`).  Return an empty list if
    no Dynamic headers are present.
    """
    msg = _EMAIL_PARSER.parsestr(text)
    return msg.get_all("Dynamic") or []
