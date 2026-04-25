"""Shared utility functions for dependency grouping and extra extraction.

Provides `extract_extra` and `group_dependencies` for separating
dependencies into required and optional (extras-gated) groups.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from peeq.models import Dependency

_EXTRA_RE = re.compile(r'extra\s*==\s*["\']([^"\']+)["\']')


def extract_extra(dep: Dependency) -> str | None:
    """Extract the extra name from a dependency's environment markers.

    Return the extra name if the markers contain an `extra == "..."`
    condition, or `None` if the dependency is unconditional or has
    only non-extra markers.
    """
    if dep.markers is None:
        return None
    match = _EXTRA_RE.search(dep.markers)
    return match.group(1) if match else None


def group_dependencies(
    deps: list[Dependency],
) -> tuple[list[Dependency], dict[str, list[Dependency]]]:
    """Separate dependencies into required and optional groups.

    Return `(required, optional)` where *optional* is a dict mapping
    extra names to their gated dependencies.
    """
    required: list[Dependency] = []
    optional: dict[str, list[Dependency]] = {}

    for dep in deps:
        extra = extract_extra(dep)
        if extra is None:
            required.append(dep)
        else:
            optional.setdefault(extra, []).append(dep)

    return required, optional
