"""Shared metadata parsing helpers.

Provides `parse_email_metadata` for parsing RFC 822-style metadata
(used by both wheel `METADATA` and sdist `PKG-INFO` files), and
`is_pure_python_wheel` for wheel tag classification.

This module is I/O-free — it operates on in-memory strings only.
"""

from __future__ import annotations

import logging
from email.parser import Parser

from peeq.models import Dependency, PackageMetadata

logger = logging.getLogger(__name__)

# Header names in core metadata (RFC 822 style).
_REQUIRES_DIST = "Requires-Dist"
_REQUIRES_PYTHON = "Requires-Python"
_LICENSE = "License"
_SUMMARY = "Summary"
_AUTHOR = "Author"
_AUTHOR_EMAIL = "Author-email"
_HOME_PAGE = "Home-page"
_DYNAMIC = "Dynamic"

# Map from header name to PackageMetadata field name.
_HEADER_TO_FIELD: dict[str, str] = {
    _REQUIRES_PYTHON: "python_requires",
    _LICENSE: "license",
    _SUMMARY: "summary",
    _AUTHOR: "author",
    _HOME_PAGE: "homepage",
}

# Wheel filename format: {name}-{version}(-{build})?-{python}-{abi}-{platform}.whl
# After rsplit("-", maxsplit=3), a valid filename produces at least 4 parts.
_WHEEL_FILENAME_MIN_PARTS = 4

_EMAIL_PARSER = Parser()


# ---------------------------------------------------------------------------
# Shared metadata parsing
# ---------------------------------------------------------------------------


def parse_email_metadata(
    text: str,
    *,
    source: str,
    dynamic_fields: list[str] | None = None,
) -> PackageMetadata:
    """Parse RFC 822-style metadata into a `PackageMetadata`.

    This format is shared by wheel `METADATA` and sdist `PKG-INFO`
    files.  Uses `email.parser` from the standard library.

    Parameters
    ----------
    text:
        Raw text content of the metadata file.
    source:
        The source identifier (e.g., `"pep658"`, `"wheel"`, `"sdist"`).
    dynamic_fields:
        PEP 643 `Dynamic` header values.  Any metadata field listed
        here is treated as unknown (set to `None`) rather than trusting
        the placeholder value.  Only relevant for sdist `PKG-INFO`.
    """
    msg = _EMAIL_PARSER.parsestr(text)
    dynamic = set(dynamic_fields or [])

    # --- Dependencies ---
    deps_dynamic = _REQUIRES_DIST in dynamic
    dependencies: list[Dependency] | None

    if deps_dynamic:
        # PEP 643: Requires-Dist is declared Dynamic -- the sdist's
        # PKG-INFO value cannot be trusted.  Signal "unknowable" via None.
        dependencies = None
    else:
        raw_deps = msg.get_all(_REQUIRES_DIST) or []
        parsed: list[Dependency] = []
        for raw in raw_deps:
            try:
                parsed.append(Dependency.from_requirement_string(raw))
            except Exception:  # noqa: PERF203
                logger.debug("Skipping unparseable requirement: %s", raw)
        dependencies = parsed

    # --- Scalar fields (with Dynamic filtering) ---
    def _get(header: str) -> str | None:
        return None if header in dynamic else msg.get(header)

    author = _get(_AUTHOR)
    if author is None and _AUTHOR not in dynamic:
        author = msg.get(_AUTHOR_EMAIL)

    return PackageMetadata(
        dependencies=dependencies,
        source=source,
        python_requires=_get(_REQUIRES_PYTHON),
        license=_get(_LICENSE),
        summary=_get(_SUMMARY),
        author=author,
        homepage=_get(_HOME_PAGE),
    )


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def is_pure_python_wheel(filename: str) -> bool:
    """Check if a wheel filename indicates a pure Python package.

    Pure Python wheels have tags like `py3-none-any` or `py2.py3-none-any`.
    """
    parts = filename.removesuffix(".whl").rsplit("-", maxsplit=3)
    if len(parts) < _WHEEL_FILENAME_MIN_PARTS:
        return False
    # parts[-3] = python tag, parts[-2] = abi tag, parts[-1] = platform tag
    return parts[-2] == "none" and parts[-1] == "any"
