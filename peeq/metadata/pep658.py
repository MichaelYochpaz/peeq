"""PEP 658 metadata fetching -- fetch metadata without downloading the artifact.

PEP 658 (https://peps.python.org/pep-0658/) defines a
`{filename}.metadata` endpoint on the Simple API that serves the wheel's
`METADATA` file directly.  This is the fastest metadata source: a single
small HTTP request (~2-10 KB) with no artifact download.

Availability:

- Fully deployed on PyPI for **wheels** since May 2023.
- PyPI does NOT serve PEP 658 metadata for sdists (source metadata is
  often dynamic -- PEP 643 (https://peps.python.org/pep-0643/)).
- Private registries have inconsistent support.

When PEP 658 is unavailable (no wheels with `metadata_available=True`),
`fetch_pep658_metadata` returns `None` and the service layer falls
through to sdist/wheel extraction.
"""

from __future__ import annotations

import hashlib
import logging
from typing import TYPE_CHECKING

from peeq.metadata.parsing import is_pure_python_wheel, parse_email_metadata
from peeq.models import DistType, FileInfo, PackageMetadata

if TYPE_CHECKING:
    from peeq.backends.base import PackageRepository

logger = logging.getLogger(__name__)


async def fetch_pep658_metadata(
    backend: PackageRepository,
    package: str,
    version: str,
) -> PackageMetadata | None:
    """Fetch PEP 658 metadata for *package*==*version*.

    Return `None` if no wheel with PEP 658 metadata is available,
    or if the HTTP request fails.
    """
    # 1. Get file list for this version
    try:
        files = await backend.files(package, version)
    except Exception:
        logger.debug(
            "Failed to list files for %s==%s",
            package,
            version,
            exc_info=True,
        )
        return None

    # 2. Find a wheel with PEP 658 metadata available
    wheel = _select_metadata_wheel(files)
    if wheel is None:
        logger.debug(
            "No wheel with PEP 658 metadata for %s==%s",
            package,
            version,
        )
        return None

    # 3. Construct metadata URL (PEP 658: append .metadata to file URL)
    metadata_url = f"{wheel.url}.metadata"

    # 4. Fetch the metadata
    try:
        response = await backend.get_with_retry(metadata_url)
    except Exception:
        logger.debug(
            "HTTP error fetching PEP 658 metadata for %s==%s from %s",
            package,
            version,
            metadata_url,
            exc_info=True,
        )
        return None

    if not response.is_success:
        logger.debug(
            "PEP 658 metadata request returned %d for %s==%s",
            response.status_code,
            package,
            version,
        )
        return None

    # 5. Verify hash if the registry provided one
    if wheel.metadata_hash is not None:
        computed = hashlib.sha256(response.content).hexdigest()
        if computed != wheel.metadata_hash.sha256:
            logger.warning(
                "PEP 658 metadata hash mismatch for %s: expected %s, got %s",
                wheel.filename,
                wheel.metadata_hash.sha256,
                computed,
            )
            return None

    # 6. Parse the metadata
    return parse_email_metadata(response.text, source="pep658")


# ---------------------------------------------------------------------------
# Wheel selection
# ---------------------------------------------------------------------------


def _select_metadata_wheel(files: list[FileInfo]) -> FileInfo | None:
    """Select the best wheel with PEP 658 metadata available.

    Prefer `py3-none-any` (pure Python, universal) wheels because they
    are the smallest and most likely to have representative metadata.
    Fall back to any wheel with `metadata_available=True`.
    """
    candidates = [
        f
        for f in files
        if f.dist_type == DistType.WHEEL and f.metadata_available and not f.yanked
    ]

    if not candidates:
        return None

    # Prefer py3-none-any wheels (pure Python, universal)
    for c in candidates:
        if is_pure_python_wheel(c.filename):
            return c

    # Fall back to any wheel with metadata available (prefer smallest)
    candidates.sort(key=lambda f: f.size or 0)
    return candidates[0]
