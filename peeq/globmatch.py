"""Path-aware glob matching for archive member paths.

Thin wrapper around `wcmatch.glob` providing `find -name`
semantics for matching POSIX-style archive paths without filesystem
access.  Patterns without `/` match the basename at any depth;
patterns with `/` match the full relative path.

Glob syntax:

- `*`   — any sequence of non-`/` characters (single segment)
- `?`   — any single non-`/` character
- `**`  — zero or more path segments (must be a complete segment)
- `[…]` — character class; `[!…]` or `[^…]` for negation
- `\\`  — escape character (`\\*` matches a literal `*`)
- Case-sensitive always

All paths and patterns use forward slashes regardless of host OS.
"""

from __future__ import annotations

from functools import lru_cache

from wcmatch import glob as wcglob

_MAX_PATTERN_LENGTH = 1024

# Force consistent behavior across all platforms and Python versions.
# PATHNAME is auto-forced by wcmatch in globmatch/compile/translate.
_FLAGS = (
    wcglob.GLOBSTAR  # Enable ** for recursive directory matching
    | wcglob.DOTMATCH  # Match dot-prefixed segments (.github, .env)
    | wcglob.FORCEUNIX  # Always use / as separator (archive paths)
    | wcglob.CASE  # Always case-sensitive (explicit; redundant with FORCEUNIX)
    | wcglob.MATCHBASE  # find -name: slash-free patterns match basename at any depth
)


class InvalidGlobError(ValueError):
    """Raised for malformed or unsupported glob patterns."""


def _validate_pattern(pattern: str) -> None:
    """Reject invalid patterns before compilation."""
    if not pattern:
        raise InvalidGlobError("empty glob pattern")
    if len(pattern) > _MAX_PATTERN_LENGTH:
        raise InvalidGlobError(f"glob pattern exceeds maximum length ({_MAX_PATTERN_LENGTH} chars)")
    if pattern.startswith("/"):
        raise InvalidGlobError("glob pattern must be relative (no leading '/')")
    if "//" in pattern:
        raise InvalidGlobError("glob pattern contains empty path segment (//)")
    if pattern.endswith("/"):
        raise InvalidGlobError(
            "glob pattern with trailing '/' is not supported (--glob filters files, not directories)"
        )

    # Reject unmatched '[' — wcmatch treats it as a literal per POSIX,
    # but in archive paths a bare '[' is almost certainly a typo.
    i = 0
    while i < len(pattern):
        if pattern[i] == "\\" and i + 1 < len(pattern):
            i += 2
            continue
        if pattern[i] == "[":
            close = pattern.find("]", i + 1)
            if close == -1:
                raise InvalidGlobError(
                    f"unmatched '[' in glob pattern: {pattern!r};"
                    r" escape as '\[' to match a literal '['"
                )
            i = close + 1
        else:
            i += 1


@lru_cache(maxsize=256)
def _get_matcher(patterns: tuple[str, ...]) -> wcglob.WcMatcher:
    """Validate, compile, and cache a matcher for the given patterns.

    Uses `wcglob.compile` to produce a reusable
    `WcMatcher`.  The `limit=0` disables
    the default 1000-pattern ceiling — safe because `BRACE` is
    not enabled, so no expansion can occur.
    """
    for pat in patterns:
        _validate_pattern(pat)
    try:
        return wcglob.compile(list(patterns), flags=_FLAGS, limit=0)
    except Exception as exc:
        # wcmatch exception types (PatternLimitException, etc.) live
        # in private modules — catch broadly and wrap.
        raise InvalidGlobError(f"invalid glob pattern: {exc}") from exc


def glob_match(path: str, pattern: str) -> bool:
    """Test whether *path* matches *pattern*.

    Uses `find -name` semantics for patterns without `/`
    (basename match at any depth) and full-path matching for
    patterns containing `/`.

    Args:
        path: POSIX-style archive member path (no leading `/`).
        pattern: Glob pattern to match against.

    Returns:
        `True` if the path matches.

    Raises:
        InvalidGlobError: If *pattern* is malformed.
    """
    return _get_matcher((pattern,)).match(path)


def glob_match_any(path: str, patterns: list[str]) -> bool:
    """Return `True` if *path* matches any pattern (OR semantics)."""
    if not patterns:
        return False
    return _get_matcher(tuple(patterns)).match(path)


def validate_glob_patterns(patterns: list[str]) -> None:
    """Validate a list of glob patterns.

    Compiles each pattern (populating the cache for later matching)
    and raises `InvalidGlobError` on the first invalid one.
    """
    for pattern in patterns:
        _validate_pattern(pattern)
        try:
            _get_matcher((pattern,))
        except InvalidGlobError:
            raise
        except Exception as exc:
            raise InvalidGlobError(f"invalid glob pattern {pattern!r}: {exc}") from exc


def glob_escape(s: str) -> str:
    """Escape glob metacharacters so *s* matches literally.

    Uses backslash escaping (`\\*`, `\\?`, `\\[`).
    """
    return wcglob.escape(s, unix=True)
