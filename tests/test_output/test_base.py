"""Unit tests for output base module helpers and renderer dispatch.

Tests cover `format_size`, `try_decode` from `peeq.output.base`,
`extract_extra` and `group_dependencies` from `peeq.utils`, the
`OutputFormat` enum, and the `get_renderer` factory.
"""

from __future__ import annotations

from io import StringIO
from typing import ClassVar
from unittest.mock import MagicMock

import pytest

from peeq.output.agent import AgentRenderer
from peeq.output.base import (
    OutputFormat,
    format_size,
    get_renderer,
    try_decode,
)
from peeq.output.json import JSONRenderer
from peeq.output.plain import PlainRenderer
from peeq.output.rich import RichRenderer

# ---------------------------------------------------------------------------
# Tests: format_size
# ---------------------------------------------------------------------------


class TestFormatSize:
    """Test byte count formatting."""

    @pytest.mark.parametrize(
        ("size", "expected"),
        [
            (0, "0 B"),
            (512, "512 B"),
            (1023, "1023 B"),
            (1024, "1.0 KB"),
            (1536, "1.5 KB"),
            (1024**2, "1.0 MB"),
            (int(2.5 * 1024**2), "2.5 MB"),
            (1024**3, "1.0 GB"),
            (int(1.5 * 1024**3), "1.5 GB"),
        ],
    )
    def test_format_size(self, size: int, expected: str) -> None:
        assert format_size(size) == expected


# ---------------------------------------------------------------------------
# Tests: try_decode
# ---------------------------------------------------------------------------


class TestTryDecode:
    """Test UTF-8 byte decoding."""

    def test_valid_utf8(self) -> None:
        """Decode valid UTF-8 bytes to string."""
        assert try_decode(b"hello world") == "hello world"

    def test_utf8_with_unicode(self) -> None:
        """Decode valid UTF-8 with non-ASCII characters."""
        text = "caf\u00e9 \u2603"
        assert try_decode(text.encode("utf-8")) == text

    def test_binary_content(self) -> None:
        """Return None for non-UTF-8 binary content."""
        assert try_decode(b"\x89PNG\r\n\x1a\n\x00\x00") is None

    def test_empty_bytes(self) -> None:
        """Decode empty bytes to empty string."""
        assert try_decode(b"") == ""


# ---------------------------------------------------------------------------
# Tests: OutputFormat
# ---------------------------------------------------------------------------


class TestOutputFormat:
    """Test OutputFormat enum values."""

    def test_values(self) -> None:
        """Enum contains pretty, plain, agent, and json."""
        assert OutputFormat.PRETTY.value == "pretty"
        assert OutputFormat.PLAIN.value == "plain"
        assert OutputFormat.AGENT.value == "agent"
        assert OutputFormat.JSON.value == "json"

    def test_all_members(self) -> None:
        """Exactly four members exist."""
        assert len(OutputFormat) == 4


# ---------------------------------------------------------------------------
# Tests: get_renderer
# ---------------------------------------------------------------------------


class TestGetRenderer:
    """Test renderer dispatch and TTY auto-detection."""

    def test_explicit_pretty(self) -> None:
        """Explicit PRETTY format returns RichRenderer."""
        renderer = get_renderer(OutputFormat.PRETTY)
        assert isinstance(renderer, RichRenderer)

    def test_explicit_plain(self) -> None:
        """Explicit PLAIN format returns PlainRenderer."""
        renderer = get_renderer(OutputFormat.PLAIN)
        assert isinstance(renderer, PlainRenderer)

    def test_explicit_agent(self) -> None:
        """Explicit AGENT format returns AgentRenderer."""
        renderer = get_renderer(OutputFormat.AGENT)
        assert isinstance(renderer, AgentRenderer)

    def test_explicit_json(self) -> None:
        """Explicit JSON format returns JSONRenderer."""
        renderer = get_renderer(OutputFormat.JSON)
        assert isinstance(renderer, JSONRenderer)

    def test_auto_detect_tty(self) -> None:
        """Auto-detect returns RichRenderer when stream is a TTY."""
        stream = MagicMock()
        stream.isatty.return_value = True
        renderer = get_renderer(stream=stream)
        assert isinstance(renderer, RichRenderer)

    def test_auto_detect_piped(self) -> None:
        """Auto-detect returns PlainRenderer when stream is piped."""
        stream = MagicMock()
        stream.isatty.return_value = False
        renderer = get_renderer(stream=stream)
        assert isinstance(renderer, PlainRenderer)

    def test_plain_renderer_stores_stream(self) -> None:
        """Custom stream is passed to the PlainRenderer."""
        stream = StringIO()
        renderer = PlainRenderer(stream=stream)
        assert renderer._stream is stream


# ---------------------------------------------------------------------------
# Tests: truncate_utf8
# ---------------------------------------------------------------------------

from peeq.extraction import ArchiveMember  # noqa: E402
from peeq.output.base import build_ls_entries, has_prefix, truncate_utf8  # noqa: E402


class TestTruncateUtf8:
    """Test UTF-8-safe byte truncation."""

    def test_ascii_within_limit(self) -> None:
        """Return content unchanged when shorter than limit."""
        data = b"hello"
        assert truncate_utf8(data, 10) == data

    def test_ascii_exact_boundary(self) -> None:
        """Return content unchanged when exactly at limit."""
        data = b"hello"
        assert truncate_utf8(data, 5) == data

    def test_ascii_truncated(self) -> None:
        """Truncate ASCII content to max_bytes."""
        assert truncate_utf8(b"hello world", 5) == b"hello"

    def test_2byte_utf8_safe_boundary(self) -> None:
        """Keep complete 2-byte char when boundary falls after it."""
        # é = \xc3\xa9 (2 bytes); cutting at 2 keeps the full char
        data = "é".encode() + b"x"  # b"\xc3\xa9x"
        assert truncate_utf8(data, 2) == "é".encode()

    def test_2byte_utf8_split(self) -> None:
        """Back up 1 byte when boundary splits a 2-byte char."""
        # "aé" = b"a\xc3\xa9" — cutting at 2 gives b"a\xc3" (invalid)
        data = "aé".encode()
        assert truncate_utf8(data, 2) == b"a"

    def test_3byte_utf8_split(self) -> None:
        """Back up when boundary splits a 3-byte char."""
        # ™ = \xe2\x84\xa2 (3 bytes)
        # "a™" = b"a\xe2\x84\xa2" — cutting at 2 gives b"a\xe2" (invalid)
        data = "a™".encode()
        assert truncate_utf8(data, 2) == b"a"

    def test_4byte_utf8_split_at_byte_3(self) -> None:
        """Back up when boundary splits a 4-byte char at byte 3."""
        # 💥 = \xf0\x9f\x92\xa5 (4 bytes)
        # "a💥" = b"a\xf0\x9f\x92\xa5" — cutting at 4 gives b"a\xf0\x9f\x92"
        data = "a💥".encode()
        assert truncate_utf8(data, 4) == b"a"

    def test_multibyte_at_offset_0(self) -> None:
        """Return empty bytes when max_bytes < char width at start."""
        # ™ = 3 bytes; max_bytes=1 forces backup past offset 0
        data = "™".encode()
        assert truncate_utf8(data, 1) == b""

    def test_empty_content(self) -> None:
        """Return empty bytes for empty input."""
        assert truncate_utf8(b"", 10) == b""

    @pytest.mark.parametrize(
        "text",
        [
            "café",
            "日本語",
            "Hello 🌍!",
            "résumé ™",
            "🎉🎊🎈",
        ],
    )
    def test_result_always_decodes(self, text: str) -> None:
        """Verify truncated result always produces valid UTF-8."""
        data = text.encode("utf-8")
        for max_bytes in range(1, len(data) + 1):
            result = truncate_utf8(data, max_bytes)
            result.decode("utf-8")  # Must not raise


# ---------------------------------------------------------------------------
# Tests: build_ls_entries
# ---------------------------------------------------------------------------


class TestBuildLsEntries:
    """Test directory listing construction from archive members."""

    def test_inferred_directories(self) -> None:
        """Infer directory entry from file paths."""
        members = [ArchiveMember(path="src/main.py", size=100, is_dir=False)]
        entries = build_ls_entries(members)
        assert len(entries) == 1
        assert entries[0].path == "src/"
        assert entries[0].is_dir is True
        assert entries[0].file_count == 1

    def test_explicit_empty_directory(self) -> None:
        """Preserve explicit empty directory with file_count=0."""
        members = [ArchiveMember(path="empty/", size=0, is_dir=True)]
        entries = build_ls_entries(members)
        assert len(entries) == 1
        assert entries[0].path == "empty/"
        assert entries[0].is_dir is True
        assert entries[0].file_count == 0

    def test_explicit_and_inferred_dedup(self) -> None:
        """Deduplicate directory appearing as both explicit and inferred."""
        members = [
            ArchiveMember(path="src/", size=0, is_dir=True),
            ArchiveMember(path="src/main.py", size=100, is_dir=False),
        ]
        entries = build_ls_entries(members)
        dir_entries = [e for e in entries if e.path == "src/"]
        assert len(dir_entries) == 1
        assert dir_entries[0].file_count == 1

    def test_archive_only_dirs(self) -> None:
        """Archive with only directory entries has file_count=0 for each."""
        members = [
            ArchiveMember(path="a/", size=0, is_dir=True),
            ArchiveMember(path="b/", size=0, is_dir=True),
        ]
        entries = build_ls_entries(members)
        assert len(entries) == 2
        assert all(e.is_dir for e in entries)
        assert all(e.file_count == 0 for e in entries)

    def test_prefix_boundary_matching(self) -> None:
        """Prefix 'src' matches 'src/' but not 'src_old/'."""
        members = [
            ArchiveMember(path="src/main.py", size=100, is_dir=False),
            ArchiveMember(path="src_old/legacy.py", size=200, is_dir=False),
        ]
        entries = build_ls_entries(members, prefix="src")
        paths = [e.path for e in entries]
        assert "src/main.py" in paths
        assert all("src_old" not in p for p in paths)

    def test_prefix_normalization(self) -> None:
        """'src' and 'src/' produce identical results."""
        members = [
            ArchiveMember(path="src/main.py", size=100, is_dir=False),
        ]
        result_bare = build_ls_entries(members, prefix="src")
        result_slash = build_ls_entries(members, prefix="src/")
        assert result_bare == result_slash

    def test_nonmatching_prefix(self) -> None:
        """Non-matching prefix returns empty list."""
        members = [ArchiveMember(path="src/main.py", size=100, is_dir=False)]
        assert build_ls_entries(members, prefix="doesnotexist/") == []

    def test_recursive_files_only(self) -> None:
        """Recursive mode returns files only, no directories."""
        members = [
            ArchiveMember(path="src/", size=0, is_dir=True),
            ArchiveMember(path="src/main.py", size=100, is_dir=False),
            ArchiveMember(path="src/utils.py", size=50, is_dir=False),
        ]
        entries = build_ls_entries(members, recursive=True)
        assert all(not e.is_dir for e in entries)
        assert len(entries) == 2

    def test_recursive_with_prefix(self) -> None:
        """Recursive with prefix filters to files under that prefix."""
        members = [
            ArchiveMember(path="src/main.py", size=100, is_dir=False),
            ArchiveMember(path="tests/test_main.py", size=50, is_dir=False),
        ]
        entries = build_ls_entries(members, prefix="src", recursive=True)
        assert len(entries) == 1
        assert entries[0].path == "src/main.py"

    def test_file_count_recursive(self) -> None:
        """Directory file_count includes all descendant files."""
        members = [
            ArchiveMember(path="a/f1.py", size=10, is_dir=False),
            ArchiveMember(path="a/b/f2.py", size=20, is_dir=False),
            ArchiveMember(path="a/b/c/f3.py", size=30, is_dir=False),
        ]
        entries = build_ls_entries(members)
        a_entry = next(e for e in entries if e.path == "a/")
        assert a_entry.file_count == 3

    def test_subdir_count_immediate(self) -> None:
        """Count only immediate child directories, not grandchildren."""
        members = [
            ArchiveMember(path="a/b/f1.py", size=10, is_dir=False),
            ArchiveMember(path="a/b/c/f2.py", size=20, is_dir=False),
        ]
        entries = build_ls_entries(members)
        a_entry = next(e for e in entries if e.path == "a/")
        # "a/" has one immediate child dir "a/b/"; "a/b/c/" is a grandchild
        assert a_entry.subdir_count == 1

    def test_directories_first_sort(self) -> None:
        """Sort directories before files, alphabetical within groups."""
        members = [
            ArchiveMember(path="z_file.py", size=10, is_dir=False),
            ArchiveMember(path="a_file.py", size=20, is_dir=False),
            ArchiveMember(path="m_dir/inner.py", size=30, is_dir=False),
            ArchiveMember(path="b_dir/inner.py", size=40, is_dir=False),
        ]
        entries = build_ls_entries(members)
        assert entries[0].path == "b_dir/"
        assert entries[0].is_dir is True
        assert entries[1].path == "m_dir/"
        assert entries[1].is_dir is True
        assert entries[2].path == "a_file.py"
        assert entries[2].is_dir is False
        assert entries[3].path == "z_file.py"
        assert entries[3].is_dir is False

    def test_flat_archive_no_dirs(self) -> None:
        """Return only file entries when no paths contain '/'."""
        members = [
            ArchiveMember(path="setup.py", size=50, is_dir=False),
            ArchiveMember(path="README.md", size=100, is_dir=False),
        ]
        entries = build_ls_entries(members)
        assert all(not e.is_dir for e in entries)
        assert len(entries) == 2

    def test_total_size_sum(self) -> None:
        """Sum recursive file sizes into total_size."""
        members = [
            ArchiveMember(path="pkg/a.py", size=100, is_dir=False),
            ArchiveMember(path="pkg/b.py", size=200, is_dir=False),
            ArchiveMember(path="pkg/sub/c.py", size=300, is_dir=False),
        ]
        entries = build_ls_entries(members)
        pkg_entry = next(e for e in entries if e.path == "pkg/")
        assert pkg_entry.total_size == 600


# ---------------------------------------------------------------------------
# Tests: has_prefix
# ---------------------------------------------------------------------------


class TestHasPrefix:
    """Test archive prefix existence checks."""

    _MEMBERS: ClassVar[list[ArchiveMember]] = [
        ArchiveMember(path="src/pkg/__init__.py", size=10, is_dir=False),
        ArchiveMember(path="src/pkg/utils.py", size=20, is_dir=False),
        ArchiveMember(path="tests/test_main.py", size=30, is_dir=False),
        ArchiveMember(path="README.md", size=40, is_dir=False),
    ]

    def test_existing_prefix(self) -> None:
        """Return True for a prefix that matches files."""
        assert has_prefix(self._MEMBERS, "src/") is True

    def test_existing_prefix_no_trailing_slash(self) -> None:
        """Return True when prefix omits trailing slash."""
        assert has_prefix(self._MEMBERS, "src") is True

    def test_nested_prefix(self) -> None:
        """Return True for a nested prefix."""
        assert has_prefix(self._MEMBERS, "src/pkg/") is True

    def test_nonexistent_prefix(self) -> None:
        """Return False for a prefix that matches nothing."""
        assert has_prefix(self._MEMBERS, "nonexistent/") is False

    def test_partial_name_no_match(self) -> None:
        """Return False when prefix is a partial directory name."""
        assert has_prefix(self._MEMBERS, "sr") is False

    def test_empty_prefix(self) -> None:
        """Return True for empty string (root always exists)."""
        assert has_prefix(self._MEMBERS, "") is True

    def test_explicit_dir_entry(self) -> None:
        """Return True when archive contains an explicit directory entry."""
        members = [
            ArchiveMember(path="lib/", size=0, is_dir=True),
        ]
        assert has_prefix(members, "lib") is True

    def test_file_valued_prefix_returns_false(self) -> None:
        """A file matching the prefix name is not a valid directory prefix."""
        members = [
            ArchiveMember(path="src", size=100, is_dir=False),
        ]
        assert has_prefix(members, "src") is False

    def test_empty_archive(self) -> None:
        """Return False for any prefix on an empty archive."""
        assert has_prefix([], "src/") is False


# ---------------------------------------------------------------------------
# Tests: build_ls_entries with glob_patterns
# ---------------------------------------------------------------------------


class TestBuildLsEntriesGlob:
    """Test glob filtering in build_ls_entries."""

    _MEMBERS: ClassVar[list[ArchiveMember]] = [
        ArchiveMember(path="src/pkg/", size=0, is_dir=True),
        ArchiveMember(path="src/pkg/__init__.py", size=10, is_dir=False),
        ArchiveMember(path="src/pkg/api.py", size=100, is_dir=False),
        ArchiveMember(path="src/pkg/utils.py", size=50, is_dir=False),
        ArchiveMember(path="tests/test_api.py", size=30, is_dir=False),
        ArchiveMember(path="tests/test_utils.py", size=40, is_dir=False),
        ArchiveMember(path="setup.py", size=20, is_dir=False),
        ArchiveMember(path="README.md", size=80, is_dir=False),
    ]

    def test_glob_filters_by_extension(self) -> None:
        """Glob '*.py' returns only Python files."""
        entries = build_ls_entries(self._MEMBERS, recursive=True, glob_patterns=["*.py"])
        assert len(entries) == 6
        assert all(e.path.endswith(".py") for e in entries)

    def test_glob_filters_by_prefix_pattern(self) -> None:
        """Glob 'test_*' matches test files at any depth."""
        entries = build_ls_entries(self._MEMBERS, recursive=True, glob_patterns=["test_*"])
        paths = [e.path for e in entries]
        assert "tests/test_api.py" in paths
        assert "tests/test_utils.py" in paths
        assert len(entries) == 2

    def test_glob_with_prefix_scope(self) -> None:
        """Glob + prefix: glob matches against prefix-relative path."""
        entries = build_ls_entries(
            self._MEMBERS,
            prefix="src/pkg",
            recursive=True,
            glob_patterns=["*.py"],
        )
        paths = [e.path for e in entries]
        assert "src/pkg/__init__.py" in paths
        assert "src/pkg/api.py" in paths
        assert "src/pkg/utils.py" in paths
        # Files outside prefix are excluded
        assert "tests/test_api.py" not in paths
        assert "setup.py" not in paths
        assert len(entries) == 3

    def test_glob_or_semantics(self) -> None:
        """Multiple globs use OR semantics."""
        entries = build_ls_entries(self._MEMBERS, recursive=True, glob_patterns=["*.py", "*.md"])
        assert len(entries) == 7

    def test_glob_no_matches(self) -> None:
        """Glob matching nothing returns empty list."""
        entries = build_ls_entries(self._MEMBERS, recursive=True, glob_patterns=["*.rs"])
        assert entries == []

    def test_glob_with_path_pattern(self) -> None:
        """Slash pattern matches full (prefix-relative) path."""
        entries = build_ls_entries(self._MEMBERS, recursive=True, glob_patterns=["tests/*.py"])
        paths = [e.path for e in entries]
        assert "tests/test_api.py" in paths
        assert "tests/test_utils.py" in paths
        assert len(entries) == 2

    def test_glob_none_means_no_filter(self) -> None:
        """glob_patterns=None applies no filtering."""
        entries = build_ls_entries(self._MEMBERS, recursive=True, glob_patterns=None)
        assert len(entries) == 7

    def test_glob_prefix_relative_matching(self) -> None:
        """Slash pattern is relative to prefix, not full archive path."""
        entries = build_ls_entries(
            self._MEMBERS,
            prefix="src",
            recursive=True,
            glob_patterns=["pkg/*.py"],
        )
        paths = [e.path for e in entries]
        assert "src/pkg/__init__.py" in paths
        assert "src/pkg/api.py" in paths
        assert len(entries) == 3

    def test_glob_without_recursive_raises(self) -> None:
        """glob_patterns with recursive=False raises ValueError."""
        with pytest.raises(ValueError, match="recursive"):
            build_ls_entries(self._MEMBERS, recursive=False, glob_patterns=["*.py"])

    def test_glob_prefix_matchbase_interaction(self) -> None:
        """Basename pattern with prefix matches via MATCHBASE."""
        entries = build_ls_entries(
            self._MEMBERS,
            prefix="src",
            recursive=True,
            glob_patterns=["*.py"],
        )
        paths = [e.path for e in entries]
        assert "src/pkg/__init__.py" in paths
        assert "src/pkg/api.py" in paths
        assert "src/pkg/utils.py" in paths
        assert len(entries) == 3
