"""Best-effort parser for `uv` resolver error output.

Extracts structured conflict information from `uv pip compile`
stderr when resolution fails.  `uv` is invoked as a subprocess and
does not expose a machine-readable error format, so this module
parses the natural-language PubGrub proof chains that `uv` emits.

The parser is designed for graceful degradation: if any extraction
step fails (e.g., because `uv` changes its output format), the
cleaned raw text is returned as the conflict message.  The public
entry point `_parse_uv_error` **never raises**.

Pipeline stages:

1. **Normalize** — strip decorative framing glyphs, ANSI codes,
   and separate trailing `hint:`/`help:` blocks.
2. **Extract** — best-effort regex extraction of `depends on` and
   `you require` clauses from premise lines, with pivot detection.
3. **Assemble** — build `ConflictInfo` objects from extracted
   data, falling back to cleaned raw text when extraction yields
   nothing.
"""

from __future__ import annotations

import logging
import re

from packaging.utils import canonicalize_name

from peeq.resolver.models import ConflictInfo, ConflictRequirement

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Compiled patterns
# ---------------------------------------------------------------------------

# ANSI escape codes (colors, cursor movement).
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")

# Decorative framing glyphs emitted by miette (uv's error reporter).
# We only strip these specific characters from the start of lines,
# preserving indentation used for structural elements (version
# inventories, `all of:` blocks).
_FRAME_CHARS = frozenset("\u00d7\u2570\u2500\u25b6\u2502")

# `X depends on Y` in a premise clause.
#
# Group `parent`: package specifier with optional extras `[...]`
#   and/or markers `{...}`, followed by a version specifier.
# Group `dep`: dependency specifier (package name + version range).
#
# Examples:
#   `scipy==1.7.0 depends on numpy>=1.16.5,<1.23.0`
#   `llama-stack-provider-ragas[remote]==0.5.1 depends on kfp>=2.5.0`
#   `astroid{python_full_version < '3.11'}==3.2.4 depends on ...`
_DEPENDS_ON_RE = re.compile(
    r"(?P<parent>\S+(?:\[[^\]]+\])?(?:\{[^}]+\})?"  # name[extras]{markers}
    r"(?:[=<>~!]+\S*)?)"  # version specifier
    r"\s+depends\s+on\s+"
    r"(?P<dep>\S+)",  # dependency specifier
)

# `you require X` (root requirement).  Also matches the variants
# `your project depends on X` and `your workspace requires X`.
_YOU_REQUIRE_RE = re.compile(
    r"(?:you\s+require|your\s+\w+\s+(?:depends\s+on|requires))\s+"
    r"(?P<req>\S+)",
)

# ---------------------------------------------------------------------------
# Stage 1: Normalize
# ---------------------------------------------------------------------------


_HEADER_RE = re.compile(
    r"^\s*[\u00d7x]\s+No solution found[^:]*:\s*$",
    re.IGNORECASE,
)
"""Match the miette error header line."""


def _split_body_and_hints(
    text: str,
) -> tuple[list[str], list[str]]:
    """Separate proof body lines from trailing hint/help blocks."""
    raw_lines: list[str] = []
    hint_lines: list[str] = []
    in_hints = False

    for raw_line in text.splitlines():
        stripped = raw_line.strip()
        if stripped.startswith(("hint:", "help:")):
            in_hints = True
        if in_hints:
            hint_lines.append(stripped)
        elif not _HEADER_RE.match(raw_line):
            # Replace miette box-drawing glyphs with spaces.
            cleaned = raw_line
            for glyph in ("\u2570\u2500\u25b6", "\u2502"):  # ╰─▶, │
                cleaned = cleaned.replace(glyph, " ")
            raw_lines.append(cleaned)

    return raw_lines, hint_lines


def _dedent_lines(lines: list[str]) -> list[str]:
    """Remove common leading whitespace, preserving relative indent."""
    non_empty = [ln for ln in lines if ln.strip()]
    if not non_empty:
        return list(lines)
    min_indent = min(len(ln) - len(ln.lstrip()) for ln in non_empty)
    result = [ln[min_indent:] if len(ln) > min_indent else ln.lstrip() for ln in lines]
    # Trim leading/trailing blank lines.
    while result and not result[-1].strip():
        result.pop()
    while result and not result[0].strip():
        result.pop(0)
    return result


def _normalize(stderr: str) -> tuple[str, list[str]]:
    """Normalize raw `uv` stderr into clean proof text and hints.

    Strips the miette error frame, then dedents the proof body so
    that structural indentation (version inventories, `all of:`
    blocks) is preserved as relative indentation.

    Returns a `(proof_body, hints)` tuple where *proof_body* is the
    cleaned proof chain and *hints* is a list of `hint:`/`help:`
    blocks extracted from the end of the output.
    """
    text = _ANSI_RE.sub("", stderr)
    raw_lines, hint_lines = _split_body_and_hints(text)
    body_lines = _dedent_lines(raw_lines)
    proof_body = "\n".join(body_lines)

    # Group hint lines into individual hint blocks.
    hints: list[str] = []
    current_hint: list[str] = []
    for line in hint_lines:
        if line.startswith(("hint:", "help:")) and current_hint:
            hints.append(" ".join(current_hint))
            current_hint = []
        if line:
            current_hint.append(line)
    if current_hint:
        hints.append(" ".join(current_hint))

    return proof_body, hints


# ---------------------------------------------------------------------------
# Stage 2: Extract
# ---------------------------------------------------------------------------


def _split_specifier(spec: str) -> tuple[str, str]:
    """Split a package specifier into `(name, version_part)`.

    Handles extras (`pkg[extra]==1.0`), markers
    (`pkg{marker}==1.0`), and bare names (`pkg`).

    Examples::

        >>> _split_specifier("scipy==1.7.0")
        ('scipy', '==1.7.0')
        >>> _split_specifier("kfp>=2.5.0,<=2.8.0")
        ('kfp', '>=2.5.0,<=2.8.0')
        >>> _split_specifier("pkg[extra]>=1.0")
        ('pkg[extra]', '>=1.0')
        >>> _split_specifier("numpy")
        ('numpy', '')
    """
    # Find the first version operator character.
    for i, ch in enumerate(spec):
        if ch in "=<>~!":
            return spec[:i], spec[i:]
    return spec, ""


def _get_premise_text(line: str) -> str | None:
    """Extract the premise portion of a proof line.

    PubGrub lines have the form::

        Because <premise> and <premise>, we can conclude that <conclusion>.

    This returns the text before `we can conclude` for lines that
    start with `Because` or `And because`.  Lines that are pure
    conclusions or back-references (`we know from (N)`) return
    `None`.
    """
    stripped = line.strip()
    lower = stripped.lower()

    # Pure back-reference lines have no new premise data.
    if lower.startswith("and because we know from"):
        return None

    # Lines starting with "Because" or "And because" contain premises.
    is_because = lower.startswith(("because ", "and because "))
    # Lines starting with "and " in compound clauses (e.g.,
    # "and kfp>=2.5.0 depends on ...") also contain premises.
    is_continuation = lower.startswith("and ") and "depends on" in lower

    if not is_because and not is_continuation:
        # Not a premise line, but may contain "you require".
        if "you require" in lower or "your " in lower:
            return stripped
        return None

    # Truncate at "we can conclude" to isolate premise data.
    conclude_idx = lower.find(", we can conclude")
    if conclude_idx != -1:
        return stripped[:conclude_idx]
    return stripped


def _add_root_requirement(
    text: str,
    by_dep: dict[str, list[ConflictRequirement]],
    root_reqs: list[ConflictRequirement],
    seen: set[tuple[str, str, str]],
) -> None:
    """Extract `you require X` patterns and record them."""
    for m in _YOU_REQUIRE_RE.finditer(text):
        req_spec = m.group("req").rstrip(".,;")
        dep_name, dep_version = _split_specifier(req_spec)
        dep_str = f"{dep_name}{dep_version}" if dep_version else dep_name
        key = ("(root)", "", dep_str)
        if key not in seen:
            seen.add(key)
            cr = ConflictRequirement(
                package="(root)",
                version="",
                dependency=dep_str,
            )
            root_reqs.append(cr)
            canon = canonicalize_name(dep_name.split("[")[0])
            by_dep.setdefault(canon, []).append(cr)

    # Handle "you require X and Y" — the `and` between two
    # root requirements.  The regex only captures the first one,
    # so look for additional specifiers after `and`.
    lower = text.lower()
    you_idx = lower.find("you require")
    if you_idx == -1:
        your_idx = lower.find("your ")
        if your_idx == -1:
            return
        you_idx = your_idx

    remainder = text[you_idx:]
    # Split on " and " to find additional requirements.
    parts = re.split(r"\s+and\s+", remainder)
    for part in parts[1:]:
        # Each part after the first "and" is a bare specifier.
        spec = part.strip().rstrip(".,;")
        if not spec or spec.lower().startswith(("we ", "your ")):
            continue
        dep_name, dep_version = _split_specifier(spec)
        dep_str = f"{dep_name}{dep_version}" if dep_version else dep_name
        key = ("(root)", "", dep_str)
        if key not in seen:
            seen.add(key)
            cr = ConflictRequirement(
                package="(root)",
                version="",
                dependency=dep_str,
            )
            root_reqs.append(cr)
            canon = canonicalize_name(dep_name.split("[")[0])
            by_dep.setdefault(canon, []).append(cr)


def _extract(
    proof_body: str,
) -> tuple[dict[str, list[ConflictRequirement]], list[ConflictRequirement]]:
    """Extract structured conflict data from the proof body.

    Returns `(by_dep, root_reqs)` where:

    - *by_dep* maps each dependency target name to the list of
      `ConflictRequirement` objects that constrain it.
    - *root_reqs* is a list of root (user) requirements.
    """
    by_dep: dict[str, list[ConflictRequirement]] = {}
    root_reqs: list[ConflictRequirement] = []
    seen: set[tuple[str, str, str]] = set()

    for line in proof_body.splitlines():
        stripped = line.strip()
        if not stripped:
            continue

        # Skip lines with `one of:` or `all of:` — these are
        # disjunctive/conjunctive blocks that don't map to the
        # conjunctive ConflictRequirement model.
        if "one of:" in stripped or "all of:" in stripped:
            continue

        # Get the premise portion (before "we can conclude").
        premise = _get_premise_text(stripped)
        if premise is None:
            continue

        # Extract `depends on` relationships from the premise.
        for m in _DEPENDS_ON_RE.finditer(premise):
            parent_spec = m.group("parent").rstrip(".,;")
            dep_spec = m.group("dep").rstrip(".,;")

            parent_name, parent_version = _split_specifier(parent_spec)
            dep_name, dep_version = _split_specifier(dep_spec)

            dep_str = f"{dep_name}{dep_version}" if dep_version else dep_name
            key = (parent_name, parent_version, dep_str)
            if key not in seen:
                seen.add(key)
                cr = ConflictRequirement(
                    package=parent_name,
                    version=parent_version,
                    dependency=dep_str,
                )
                canon = canonicalize_name(dep_name.split("[")[0])
                by_dep.setdefault(canon, []).append(cr)

        # Extract root requirements.
        lower = premise.lower()
        if "you require" in lower or "your " in lower:
            _add_root_requirement(premise, by_dep, root_reqs, seen)

    return by_dep, root_reqs


# A pivot must be constrained by at least this many distinct parents.
_MIN_PIVOT_PARENTS = 2

# Pseudo-packages that should not be treated as pivot packages.
_PSEUDO_PACKAGES = frozenset({"python"})


def _find_pivot(by_dep: dict[str, list[ConflictRequirement]]) -> str | None:
    """Identify the pivot package (the one with incompatible constraints).

    The pivot is the dependency target that has constraints from
    multiple different parent packages.  Filter out pseudo-packages
    like `Python`.
    """
    best: str | None = None
    best_count = 0

    for dep_name, reqs in by_dep.items():
        if dep_name in _PSEUDO_PACKAGES:
            continue

        # Count distinct parents.
        parents = {r.package for r in reqs}
        if len(parents) >= _MIN_PIVOT_PARENTS and len(reqs) > best_count:
            best = dep_name
            best_count = len(reqs)

    return best


# ---------------------------------------------------------------------------
# Stage 3: Assemble
# ---------------------------------------------------------------------------


def _build_chain(
    parent_name: str,
    by_dep: dict[str, list[ConflictRequirement]],
    root_packages: frozenset[str],
) -> list[str]:
    """Walk *by_dep* backwards from *parent_name* to a root requirement.

    Returns an ordered list of PEP 508 strings (root → parent).
    Uses BFS to find the shortest path.  Returns an empty list if
    the parent is a root requirement or no path is found.
    """
    canon_parent = canonicalize_name(parent_name.split("[", maxsplit=1)[0])
    if canon_parent in root_packages:
        return []

    # BFS from canon_parent back to a root.
    queue: list[tuple[str, list[str]]] = [(canon_parent, [])]
    visited: set[str] = {canon_parent}

    while queue:
        current, path = queue.pop(0)
        for reqs in by_dep.values():
            for req in reqs:
                req_canon = canonicalize_name(
                    req.dependency.split("[")[0]
                    .split(">")[0]
                    .split("<")[0]
                    .split("=")[0]
                    .split("!")[0]
                    .split("~")[0]
                )
                if req_canon != current:
                    continue
                # Found a parent that depends on `current`.
                parent_canon = canonicalize_name(req.package.split("[")[0])
                spec = f"{req.package}{req.version}" if req.version else req.package
                new_path = [*path, spec]
                if parent_canon in root_packages or req.package == "(root)":
                    # Reached root — reverse to get root → parent order.
                    new_path.reverse()
                    return new_path
                if parent_canon not in visited:
                    visited.add(parent_canon)
                    queue.append((parent_canon, new_path))

    return []


def _assemble(
    proof_body: str,
    hints: list[str],
    by_dep: dict[str, list[ConflictRequirement]],
    root_reqs: list[ConflictRequirement],
) -> tuple[list[ConflictInfo], str]:
    """Build `ConflictInfo` list and global summary message.

    When structured extraction succeeded (pivot found), produces
    a `ConflictInfo` per pivot with provenance chains.  When
    extraction failed, produces a single `ConflictInfo` with
    the full proof text as message.
    """
    pivot = _find_pivot(by_dep)

    conflicts: list[ConflictInfo] = []

    # Collect root package names for chain building.
    root_packages = frozenset(
        canonicalize_name(
            r.dependency.split("[")[0]
            .split(">")[0]
            .split("<")[0]
            .split("=")[0]
            .split("!")[0]
            .split("~")[0]
        )
        for r in root_reqs
    )

    if pivot is not None:
        # Enrich each requirement with a provenance chain.
        enriched_reqs: list[ConflictRequirement] = []
        for req in by_dep[pivot]:
            chain = _build_chain(req.package, by_dep, root_packages)
            enriched_reqs.append(
                ConflictRequirement(
                    package=req.package,
                    version=req.version,
                    dependency=req.dependency,
                    chain=chain,
                )
            )

        conflicts.append(
            ConflictInfo(
                package=pivot,
                requirements=enriched_reqs,
                message=f"No version of {pivot} satisfies all constraints",
                hints=hints,
            )
        )
        summary = f"No version of {pivot} satisfies all constraints"
    else:
        # Fallback — could not identify a pivot.
        conflicts.append(
            ConflictInfo(
                package="(unknown)",
                message=proof_body,
                hints=hints,
            )
        )
        summary = "Could not resolve dependencies"

    return conflicts, summary


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def _parse_uv_error(stderr: str) -> tuple[list[ConflictInfo], str]:
    """Parse `uv` stderr into structured conflicts and a summary.

    Returns `(conflicts, summary)` where *conflicts* is a list of
    `ConflictInfo` objects and *summary* is a short global
    message suitable for the `ResolutionImpossible` exception.

    **Never raises.**  On any parsing failure, falls back to the
    cleaned raw text with a generic summary.
    """
    try:
        proof_body, hints = _normalize(stderr)
        by_dep, root_reqs = _extract(proof_body)
        return _assemble(proof_body, hints, by_dep, root_reqs)
    except Exception:
        logger.debug("Failed to parse uv error output, using raw text", exc_info=True)
        # Ultimate fallback — return cleaned text as-is.
        cleaned = _ANSI_RE.sub("", stderr).strip()
        return (
            [ConflictInfo(package="(unknown)", message=cleaned)],
            "Could not resolve dependencies",
        )
