"""Unit tests for peeq.globmatch — path-aware glob matching via wcmatch."""

from __future__ import annotations

import pytest

from peeq.globmatch import (
    InvalidGlobError,
    glob_escape,
    glob_match,
    glob_match_any,
    validate_glob_patterns,
)

# ---------------------------------------------------------------------------
# Tests: glob_match — basename semantics (no slash in pattern)
# ---------------------------------------------------------------------------


class TestGlobMatchBasename:
    """Patterns without '/' match against the basename at any depth."""

    @pytest.mark.parametrize(
        ("path", "pattern", "expected"),
        [
            ("api.py", "*.py", True),
            ("src/requests/api.py", "*.py", True),
            ("src/requests/api.pyc", "*.py", False),
            ("tests/test_api.py", "test_*", True),
            ("tests/foo_test.py", "test_*", False),
            ("setup.py", "setup.py", True),
            ("src/setup.py", "setup.py", True),
            # ? wildcard
            ("test_api.py", "test_???.py", True),
            ("test_ab.py", "test_???.py", False),
            ("src/test_api.py", "test_???.py", True),
            # Single * matches any basename
            ("foo", "*", True),
            ("src/bar", "*", True),
        ],
    )
    def test_basename_match(self, path: str, pattern: str, expected: bool) -> None:
        assert glob_match(path, pattern) is expected


# ---------------------------------------------------------------------------
# Tests: glob_match — full path semantics (slash in pattern)
# ---------------------------------------------------------------------------


class TestGlobMatchFullPath:
    """Patterns with '/' match against the full relative path."""

    @pytest.mark.parametrize(
        ("path", "pattern", "expected"),
        [
            # * does not cross /
            ("src/api.py", "src/*.py", True),
            ("src/pkg/api.py", "src/*.py", False),
            ("src/api.txt", "src/*.py", False),
            # ** leading
            ("api.py", "**/*.py", True),
            ("a/b/c.py", "**/*.py", True),
            # ** middle — zero dirs
            ("a/b", "a/**/b", True),
            ("a/x/b", "a/**/b", True),
            ("a/x/y/b", "a/**/b", True),
            ("a/x/y/c", "a/**/b", False),
            # ** trailing
            ("src/x", "src/**", True),
            ("src/x/y/z", "src/**", True),
            ("other", "src/**", False),
            # ** with deeper paths
            ("src/api.py", "src/**/*.py", True),
            ("src/pkg/api.py", "src/**/*.py", True),
            ("src/a/b/c/deep.py", "src/**/*.py", True),
            ("tests/api.py", "src/**/*.py", False),
        ],
    )
    def test_full_path_match(self, path: str, pattern: str, expected: bool) -> None:
        assert glob_match(path, pattern) is expected


# ---------------------------------------------------------------------------
# Tests: glob_match — bare ** and edge cases
# ---------------------------------------------------------------------------


class TestGlobMatchStarStar:
    """Edge cases for ** at various positions."""

    @pytest.mark.parametrize(
        ("path", "pattern", "expected"),
        [
            # Bare ** matches everything
            ("a/b/c.py", "**", True),
            ("file.txt", "**", True),
            # Consecutive ** collapsed
            ("a/b/c.py", "**/**", True),
            ("file.txt", "**/**", True),
            ("a/b/c.py", "a/**/**/c.py", True),
            ("a/c.py", "a/**/**/c.py", True),
            # Multi-level **
            ("a/x/b/y/c", "a/**/b/**/c", True),
            ("a/b/c", "a/**/b/**/c", True),
        ],
    )
    def test_starstar_edge_cases(self, path: str, pattern: str, expected: bool) -> None:
        assert glob_match(path, pattern) is expected


# ---------------------------------------------------------------------------
# Tests: glob_match — character classes
# ---------------------------------------------------------------------------


class TestGlobMatchCharClasses:
    """Bracket expressions [...]."""

    @pytest.mark.parametrize(
        ("path", "pattern", "expected"),
        [
            ("a.py", "[ab].py", True),
            ("c.py", "[ab].py", False),
            # Negation with !
            ("c.py", "[!ab].py", True),
            ("a.py", "[!ab].py", False),
            # Ranges
            ("file1.txt", "file[0-9].txt", True),
            ("filea.txt", "file[0-9].txt", False),
        ],
    )
    def test_char_classes(self, path: str, pattern: str, expected: bool) -> None:
        assert glob_match(path, pattern) is expected

    def test_caret_is_negation(self) -> None:
        """[^abc] is negation (Bash convention), same as [!abc]."""
        assert glob_match("x.py", "[^ab].py") is True
        assert glob_match("a.py", "[^ab].py") is False
        assert glob_match("b.py", "[^ab].py") is False

    def test_regex_metachar_in_bracket_class(self) -> None:
        r"""Regex metacharacters inside bracket classes are literal."""
        # [.] matches only '.', not any character (regex wildcard leak)
        assert glob_match("..py", "[.].py") is True
        assert glob_match("a.py", "[.].py") is False
        assert glob_match("+.py", "[+].py") is True


# ---------------------------------------------------------------------------
# Tests: case sensitivity
# ---------------------------------------------------------------------------


class TestGlobMatchCaseSensitive:
    """Matching is always case-sensitive."""

    def test_case_mismatch(self) -> None:
        assert glob_match("API.py", "api.py") is False
        assert glob_match("api.py", "API.py") is False

    def test_case_exact(self) -> None:
        assert glob_match("api.py", "api.py") is True


# ---------------------------------------------------------------------------
# Tests: dotfile matching (DOTMATCH flag)
# ---------------------------------------------------------------------------


class TestGlobMatchDotfiles:
    """Wildcards match dot-prefixed files and directories."""

    def test_dotfile_at_root(self) -> None:
        assert glob_match(".gitignore", ".*") is True
        assert glob_match(".gitignore", "*") is True

    def test_dotfile_nested(self) -> None:
        assert glob_match(".github/workflows/ci.yml", "*.yml") is True

    def test_dotdir_with_globstar(self) -> None:
        assert glob_match(".github/workflows/ci.yml", "**/*.yml") is True


# ---------------------------------------------------------------------------
# Tests: regex metacharacters in paths are literal
# ---------------------------------------------------------------------------


class TestGlobMatchRegexMetachars:
    """Regex metacharacters in paths and patterns are literal."""

    @pytest.mark.parametrize(
        ("path", "pattern", "expected"),
        [
            # '.' is literal, not regex wildcard
            ("file.py", "file.py", True),
            ("fileXpy", "file.py", False),
            # '+', '(', ')' are literal
            ("data+1.txt", "data+1.txt", True),
            ("func().py", "func().py", True),
        ],
    )
    def test_regex_metachar_literal(
        self, path: str, pattern: str, expected: bool
    ) -> None:
        assert glob_match(path, pattern) is expected


# ---------------------------------------------------------------------------
# Tests: disabled features are literal
# ---------------------------------------------------------------------------


class TestGlobDisabledFeatures:
    """BRACE and EXTGLOB are disabled — their syntax is literal."""

    def test_brace_is_literal(self) -> None:
        """{a,b} matches the literal string, not as expansion."""
        assert glob_match("{a,b}.py", "{a,b}.py") is True
        assert glob_match("a.py", "{a,b}.py") is False

    def test_extglob_is_literal(self) -> None:
        """@(a|b) is not special without EXTGLOB."""
        assert glob_match("@(a|b).py", "@(a|b).py") is True
        assert glob_match("a.py", "@(a|b).py") is False


# ---------------------------------------------------------------------------
# Tests: backslash escaping
# ---------------------------------------------------------------------------


class TestGlobBackslashEscape:
    r"""Backslash is an escape character in patterns (FORCEUNIX)."""

    def test_escaped_star_matches_literal(self) -> None:
        assert glob_match("*.py", r"\*.py") is True
        assert glob_match("api.py", r"\*.py") is False

    def test_escaped_question_matches_literal(self) -> None:
        assert glob_match("?.py", r"\?.py") is True
        assert glob_match("a.py", r"\?.py") is False


# ---------------------------------------------------------------------------
# Tests: input validation
# ---------------------------------------------------------------------------


class TestGlobValidation:
    """Invalid patterns raise InvalidGlobError."""

    @pytest.mark.parametrize(
        ("pattern", "fragment"),
        [
            ("", "empty"),
            ("/abs.py", "relative"),
            ("a//b.py", "empty path segment"),
            ("src/", "trailing '/'"),
        ],
    )
    def test_invalid_patterns(self, pattern: str, fragment: str) -> None:
        with pytest.raises(InvalidGlobError, match=fragment):
            glob_match("anything", pattern)

    def test_max_length(self) -> None:
        with pytest.raises(InvalidGlobError, match="maximum length"):
            glob_match("anything", "a" * 1025)

    @pytest.mark.parametrize(
        "pattern",
        [
            "[invalid",
            "abc[",
            "[abc][def",
            "src/[partial",
        ],
    )
    def test_unmatched_bracket_rejected(self, pattern: str) -> None:
        with pytest.raises(InvalidGlobError, match=r"unmatched '\['"):
            glob_match("anything", pattern)

    @pytest.mark.parametrize(
        "pattern",
        [
            "[abc]",
            "[!abc]",
            "[^abc]",
            "[]abc]",
            "[!]abc]",
            "[a-z]",
            "[-abc]",
            "[abc-]",
            "[[]",
            r"[\\]]",
            "[[abc]]",
            r"\[notabracket",
        ],
    )
    def test_valid_bracket_patterns_accepted(self, pattern: str) -> None:
        # Must not raise — pattern is structurally valid.
        glob_match("anything", pattern)


# ---------------------------------------------------------------------------
# Tests: validate_glob_patterns
# ---------------------------------------------------------------------------


class TestValidateGlobPatterns:
    """Direct tests for the validate_glob_patterns function."""

    def test_valid_patterns_pass(self) -> None:
        validate_glob_patterns(["*.py", "*.pyi", "src/**/*.txt"])

    def test_invalid_pattern_raises(self) -> None:
        with pytest.raises(InvalidGlobError, match="empty"):
            validate_glob_patterns(["*.py", "", "*.txt"])

    def test_empty_list_passes(self) -> None:
        validate_glob_patterns([])


# ---------------------------------------------------------------------------
# Tests: glob_match_any (OR semantics)
# ---------------------------------------------------------------------------


class TestGlobMatchAny:
    """Multiple patterns with OR semantics."""

    def test_matches_first(self) -> None:
        assert glob_match_any("api.py", ["*.py", "*.pyi"]) is True

    def test_matches_second(self) -> None:
        assert glob_match_any("api.pyi", ["*.py", "*.pyi"]) is True

    def test_matches_none(self) -> None:
        assert glob_match_any("api.txt", ["*.py", "*.pyi"]) is False

    def test_empty_list_returns_false(self) -> None:
        assert glob_match_any("api.py", []) is False


# ---------------------------------------------------------------------------
# Tests: glob_escape
# ---------------------------------------------------------------------------


class TestGlobEscape:
    """Metacharacter escaping — tested via round-trips."""

    @pytest.mark.parametrize(
        "path",
        [
            "file*.txt",
            "file?.txt",
            "file[0].txt",
            "normal.txt",
            "hello-world",
            "src/main.py",
            "data (1).txt",
        ],
    )
    def test_escape_round_trip(self, path: str) -> None:
        """Escaped path matches itself literally."""
        assert glob_match(path, glob_escape(path)) is True

    def test_escaped_star_does_not_match_wildcard(self) -> None:
        """Escaped '*' does not act as a wildcard."""
        assert glob_match("api.txt", glob_escape("*.txt")) is False

    def test_no_metacharacters_unchanged(self) -> None:
        assert glob_escape("normal.txt") == "normal.txt"
