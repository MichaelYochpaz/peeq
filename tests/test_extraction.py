"""Tests for peeq.extraction — in-memory archive extraction."""

from __future__ import annotations

import io
import sys
import tarfile
import zipfile
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

from peeq.config import ExtractionConfig
from peeq.extraction import (
    ArchiveMember,
    ExtractionError,
    ExtractionFileNotFoundError,
    ExtractionLimitExceededError,
    ExtractionLimits,
    UnsupportedArchiveFormatError,
    _read_with_limit,
    extract_all,
    extract_archive_to_disk,
    extract_file,
    list_archive,
)

# ---------------------------------------------------------------------------
# Helpers — create test archives
# ---------------------------------------------------------------------------

_MB = 1024 * 1024


def _make_tar_gz(tmp_path: Path, files: dict[str, bytes]) -> Path:
    """Create a tar.gz archive at *tmp_path* / `test.tar.gz`."""
    archive_path = tmp_path / "test.tar.gz"
    with tarfile.open(archive_path, "w:gz") as tf:
        for name, data in files.items():
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return archive_path


def _make_tar_gz_with_dir(tmp_path: Path, files: dict[str, bytes]) -> Path:
    """Create a tar.gz archive with a top-level directory entry."""
    archive_path = tmp_path / "test.tar.gz"
    with tarfile.open(archive_path, "w:gz") as tf:
        # Add a directory entry
        dir_info = tarfile.TarInfo(name="pkg-1.0.0/")
        dir_info.type = tarfile.DIRTYPE
        tf.addfile(dir_info)

        for name, data in files.items():
            info = tarfile.TarInfo(name=f"pkg-1.0.0/{name}")
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return archive_path


def _make_zip(tmp_path: Path, files: dict[str, bytes]) -> Path:
    """Create a .whl (zip) archive at *tmp_path* / `test.whl`."""
    archive_path = tmp_path / "test.whl"
    with zipfile.ZipFile(archive_path, "w") as zf:
        for name, data in files.items():
            zf.writestr(name, data)
    return archive_path


# ---------------------------------------------------------------------------
# Parametrized fixture — archive factory for both formats
# ---------------------------------------------------------------------------


@pytest.fixture(params=["tar", "zip"])
def archive_factory(
    request: pytest.FixtureRequest, tmp_path: Path
) -> Callable[[dict[str, bytes]], Path]:
    """Provide an archive creator for both tar.gz and zip formats.

    Each parametrized variant returns a callable that takes a
    `dict[str, bytes]` of filenames to content and returns the
    archive `Path`.
    """
    if request.param == "tar":
        return lambda files: _make_tar_gz(tmp_path, files)
    return lambda files: _make_zip(tmp_path, files)


# ---------------------------------------------------------------------------
# ExtractionLimits
# ---------------------------------------------------------------------------


class TestExtractionLimits:
    """Extraction limits configuration and defaults."""

    def test_defaults(self) -> None:
        limits = ExtractionLimits()
        assert limits.max_total_bytes == 500 * _MB
        assert limits.max_file_count == 50_000
        assert limits.max_single_file_bytes == 100 * _MB

    def test_from_config_defaults(self) -> None:
        config = ExtractionConfig()
        limits = ExtractionLimits.from_config(config)
        assert limits.max_total_bytes == 500 * _MB
        assert limits.max_file_count == 50_000
        assert limits.max_single_file_bytes == 100 * _MB

    def test_from_config_custom(self) -> None:
        config = ExtractionConfig(max_size_mb=10, max_files=100, max_file_size_mb=5)
        limits = ExtractionLimits.from_config(config)
        assert limits.max_total_bytes == 10 * _MB
        assert limits.max_file_count == 100
        assert limits.max_single_file_bytes == 5 * _MB

    def test_frozen(self) -> None:
        limits = ExtractionLimits()
        with pytest.raises(AttributeError):
            limits.max_total_bytes = 999  # ty: ignore[invalid-assignment]


# ---------------------------------------------------------------------------
# Archive type detection
# ---------------------------------------------------------------------------


class TestArchiveDetection:
    """Archive format detection from file extensions."""

    def test_tar_gz(self, tmp_path: Path) -> None:
        archive = _make_tar_gz(tmp_path, {"f.txt": b"hello"})
        members = list_archive(archive)
        assert len(members) == 1

    def test_whl_zip(self, tmp_path: Path) -> None:
        archive = _make_zip(tmp_path, {"f.txt": b"hello"})
        members = list_archive(archive)
        assert len(members) == 1

    def test_unsupported_format(self, tmp_path: Path) -> None:
        bad = tmp_path / "test.exe"
        bad.write_bytes(b"not an archive")
        with pytest.raises(UnsupportedArchiveFormatError, match=r"test\.exe"):
            list_archive(bad)

    def test_tgz_extension(self, tmp_path: Path) -> None:
        """Files ending in .tgz should be detected as tar."""
        archive = _make_tar_gz(tmp_path, {"f.txt": b"hello"})
        renamed = archive.with_suffix(".tgz")
        archive.rename(renamed)
        members = list_archive(renamed)
        assert len(members) == 1


# ---------------------------------------------------------------------------
# list_archive (both formats)
# ---------------------------------------------------------------------------


class TestListArchive:
    """Tests for list_archive that apply to both tar.gz and zip formats."""

    def test_list_files(
        self, archive_factory: Callable[[dict[str, bytes]], Path]
    ) -> None:
        """Listing returns sorted member paths."""
        files = {"a.txt": b"aaa", "b.txt": b"bbb", "c.txt": b"ccc"}
        archive = archive_factory(files)
        members = list_archive(archive)
        assert len(members) == 3
        names = [m.path for m in members]
        assert names == sorted(names)

    def test_member_metadata(
        self, archive_factory: Callable[[dict[str, bytes]], Path]
    ) -> None:
        """Member carries correct path, size, and is_dir flag."""
        data = b"x" * 42
        archive = archive_factory({"test.py": data})
        members = list_archive(archive)
        assert len(members) == 1
        assert members[0].path == "test.py"
        assert members[0].size == 42
        assert members[0].is_dir is False

    def test_file_count_limit(
        self, archive_factory: Callable[[dict[str, bytes]], Path]
    ) -> None:
        """Exceeding the file-count limit raises ExtractionLimitExceededError."""
        files = {f"file{i}.txt": b"data" for i in range(5)}
        archive = archive_factory(files)
        limits = ExtractionLimits(max_file_count=3)
        with pytest.raises(ExtractionLimitExceededError, match="file count"):
            list_archive(archive, limits=limits)


# ---------------------------------------------------------------------------
# list_archive — tar-specific
# ---------------------------------------------------------------------------


class TestListArchiveTar:
    """Tar-specific list_archive tests (directory entries, root prefix)."""

    def test_list_with_directory_strips_root_prefix(self, tmp_path: Path) -> None:
        """Root dir entry is stripped; only inner files remain."""
        files = {"README.md": b"# Hello", "setup.py": b"setup()"}
        archive = _make_tar_gz_with_dir(tmp_path, files)
        members = list_archive(archive)
        dirs = [m for m in members if m.is_dir]
        regular = [m for m in members if not m.is_dir]
        assert len(dirs) == 0
        assert len(regular) == 2
        names = [m.path for m in regular]
        assert "README.md" in names
        assert "setup.py" in names

    def test_nested_dirs_preserved_after_stripping(self, tmp_path: Path) -> None:
        """Nested subdirectories inside the root dir are preserved."""
        archive_path = tmp_path / "test.tar.gz"
        with tarfile.open(archive_path, "w:gz") as tf:
            # Root dir
            d = tarfile.TarInfo(name="pkg-1.0.0/")
            d.type = tarfile.DIRTYPE
            tf.addfile(d)
            # Nested subdir
            d = tarfile.TarInfo(name="pkg-1.0.0/src/")
            d.type = tarfile.DIRTYPE
            tf.addfile(d)
            # File inside nested subdir
            info = tarfile.TarInfo(name="pkg-1.0.0/src/main.py")
            info.size = 5
            tf.addfile(info, io.BytesIO(b"hello"))

        members = list_archive(archive_path)
        paths = [m.path for m in members]
        dirs = [m for m in members if m.is_dir]
        # Nested subdir is preserved (tarfile may omit trailing slash)
        assert any(m.path.rstrip("/") == "src" for m in dirs)
        assert "src/main.py" in paths
        # Root dir entry itself should be excluded
        assert not any("pkg-1.0.0" in p for p in paths)


# ---------------------------------------------------------------------------
# extract_file (both formats)
# ---------------------------------------------------------------------------


class TestExtractFile:
    """Tests for extract_file that apply to both tar.gz and zip formats."""

    def test_extract_existing(
        self, archive_factory: Callable[[dict[str, bytes]], Path]
    ) -> None:
        """Extracting an existing file returns its content."""
        content = b"Hello, world!"
        archive = archive_factory({"greeting.txt": content})
        result = extract_file(archive, "greeting.txt")
        assert result == content

    def test_file_not_found(
        self, archive_factory: Callable[[dict[str, bytes]], Path]
    ) -> None:
        """Requesting a missing file raises ExtractionFileNotFoundError."""
        archive = archive_factory({"a.txt": b"data"})
        with pytest.raises(ExtractionFileNotFoundError, match=r"missing\.txt"):
            extract_file(archive, "missing.txt")

    def test_single_file_size_limit(
        self, archive_factory: Callable[[dict[str, bytes]], Path]
    ) -> None:
        """Exceeding the single-file size limit raises ExtractionLimitExceededError."""
        data = b"x" * 1024
        archive = archive_factory({"big.txt": data})
        limits = ExtractionLimits(max_single_file_bytes=512)
        with pytest.raises(ExtractionLimitExceededError, match="single file"):
            extract_file(archive, "big.txt", limits=limits)


# ---------------------------------------------------------------------------
# extract_file — tar-specific
# ---------------------------------------------------------------------------


class TestExtractFileTar:
    """Tar-specific extract_file tests (root-dir resolution, directory rejection)."""

    def test_extract_from_root_dir_archive(self, tmp_path: Path) -> None:
        """Extract a file using a path relative to the package root."""
        content = b"# README"
        archive = _make_tar_gz_with_dir(tmp_path, {"README.md": content})
        # User passes "README.md", not "pkg-1.0.0/README.md"
        result = extract_file(archive, "README.md")
        assert result == content

    def test_extract_directory_raises(self, tmp_path: Path) -> None:
        """Extracting a directory raises ExtractionFileNotFoundError."""
        archive_path = tmp_path / "test.tar.gz"
        with tarfile.open(archive_path, "w:gz") as tf:
            # Two top-level entries so no root prefix is detected
            d = tarfile.TarInfo(name="subdir/")
            d.type = tarfile.DIRTYPE
            tf.addfile(d)
            info = tarfile.TarInfo(name="subdir/f.txt")
            info.size = 4
            tf.addfile(info, io.BytesIO(b"data"))
            info = tarfile.TarInfo(name="other.txt")
            info.size = 5
            tf.addfile(info, io.BytesIO(b"hello"))
        with pytest.raises(ExtractionFileNotFoundError, match="directory"):
            extract_file(archive_path, "subdir/")


# ---------------------------------------------------------------------------
# extract_all (both formats)
# ---------------------------------------------------------------------------


class TestExtractAll:
    """Tests for extract_all that apply to both tar.gz and zip formats."""

    def test_extract_all(
        self, archive_factory: Callable[[dict[str, bytes]], Path]
    ) -> None:
        """Extracting all files returns the complete file mapping."""
        files = {"a.txt": b"aaa", "b.txt": b"bbb"}
        archive = archive_factory(files)
        result = extract_all(archive)
        assert result == files

    def test_file_count_limit(
        self, archive_factory: Callable[[dict[str, bytes]], Path]
    ) -> None:
        """Exceeding the file-count limit raises ExtractionLimitExceededError."""
        files = {f"f{i}.txt": b"x" for i in range(10)}
        archive = archive_factory(files)
        limits = ExtractionLimits(max_file_count=5)
        with pytest.raises(ExtractionLimitExceededError, match="file count"):
            extract_all(archive, limits=limits)

    def test_total_size_limit(
        self, archive_factory: Callable[[dict[str, bytes]], Path]
    ) -> None:
        """Exceeding the total-size limit raises ExtractionLimitExceededError."""
        files = {f"f{i}.txt": b"x" * 100 for i in range(5)}
        archive = archive_factory(files)
        # 500 bytes total, limit to 300
        limits = ExtractionLimits(max_total_bytes=300)
        with pytest.raises(ExtractionLimitExceededError, match="total uncompressed"):
            extract_all(archive, limits=limits)


# ---------------------------------------------------------------------------
# extract_all — tar-specific
# ---------------------------------------------------------------------------


class TestExtractAllTar:
    """Tar-specific extract_all tests (directory skipping, prefix stripping)."""

    def test_skips_directories_and_strips_prefix(self, tmp_path: Path) -> None:
        """Root prefix is stripped from keys; directory entries excluded."""
        files = {"README.md": b"hello"}
        archive = _make_tar_gz_with_dir(tmp_path, files)
        result = extract_all(archive)
        assert "pkg-1.0.0/" not in result
        assert "pkg-1.0.0/README.md" not in result
        assert "README.md" in result
        assert result["README.md"] == b"hello"

    def test_single_file_limit_in_extract_all(self, tmp_path: Path) -> None:
        """A single oversized file inside the archive triggers the limit."""
        files = {"small.txt": b"ok", "big.txt": b"x" * 1024}
        archive = _make_tar_gz(tmp_path, files)
        limits = ExtractionLimits(max_single_file_bytes=512)
        with pytest.raises(ExtractionLimitExceededError, match="single file"):
            extract_all(archive, limits=limits)


# ---------------------------------------------------------------------------
# extract_archive_to_disk (both formats)
# ---------------------------------------------------------------------------


class TestExtractToDisk:
    """Tests for extract_archive_to_disk that apply to both formats."""

    def test_extract_to_disk(
        self, archive_factory: Callable[[dict[str, bytes]], Path], tmp_path: Path
    ) -> None:
        """Files are extracted to disk with correct content and structure."""
        files = {"hello.txt": b"world", "sub/nested.py": b"import os"}
        archive = archive_factory(files)
        dest = tmp_path / "output"
        extracted = extract_archive_to_disk(archive, dest)
        assert len(extracted) == 2
        assert (dest / "hello.txt").read_bytes() == b"world"
        assert (dest / "sub" / "nested.py").read_bytes() == b"import os"

    def test_file_count_limit(
        self, archive_factory: Callable[[dict[str, bytes]], Path], tmp_path: Path
    ) -> None:
        """Exceeding the file-count limit raises ExtractionLimitExceededError."""
        files = {f"f{i}.txt": b"x" for i in range(10)}
        archive = archive_factory(files)
        dest = tmp_path / "output"
        limits = ExtractionLimits(max_file_count=5)
        with pytest.raises(ExtractionLimitExceededError, match="file count"):
            extract_archive_to_disk(archive, dest, limits=limits)


# ---------------------------------------------------------------------------
# extract_archive_to_disk — tar-specific
# ---------------------------------------------------------------------------


class TestExtractToDiskTar:
    """Tar-specific extract_archive_to_disk tests (dir creation, limits, security)."""

    def test_creates_dest_dir(self, tmp_path: Path) -> None:
        archive = _make_tar_gz(tmp_path, {"f.txt": b"data"})
        dest = tmp_path / "a" / "b" / "c"
        assert not dest.exists()
        extract_archive_to_disk(archive, dest)
        assert dest.exists()
        assert (dest / "f.txt").read_bytes() == b"data"

    def test_total_size_limit(self, tmp_path: Path) -> None:
        files = {f"f{i}.txt": b"x" * 200 for i in range(5)}
        archive = _make_tar_gz(tmp_path, files)
        dest = tmp_path / "output"
        limits = ExtractionLimits(max_total_bytes=500)
        with pytest.raises(ExtractionLimitExceededError, match="total uncompressed"):
            extract_archive_to_disk(archive, dest, limits=limits)

    @pytest.mark.skipif(
        sys.version_info < (3, 12),
        reason="Path traversal protection on 3.10/3.11 uses manual shim",
    )
    def test_path_traversal_blocked_312(self, tmp_path: Path) -> None:
        """On 3.12+, `data_filter` blocks path traversal."""
        archive_path = tmp_path / "evil.tar.gz"
        with tarfile.open(archive_path, "w:gz") as tf:
            info = tarfile.TarInfo(name="../../../etc/passwd")
            info.size = 4
            tf.addfile(info, io.BytesIO(b"evil"))

        dest = tmp_path / "output"
        # Python 3.12+ data_filter raises various exceptions for path
        # traversal (FilterError or its subclasses).
        with pytest.raises((Exception, OSError), match=r"\.\."):
            extract_archive_to_disk(archive_path, dest)

    @pytest.mark.skipif(
        sys.version_info >= (3, 12),
        reason="Manual shim only used on 3.10/3.11",
    )
    def test_path_traversal_blocked_manual_shim(self, tmp_path: Path) -> None:
        """On 3.10/3.11, the manual shim blocks path traversal."""
        archive_path = tmp_path / "evil.tar.gz"
        with tarfile.open(archive_path, "w:gz") as tf:
            info = tarfile.TarInfo(name="../../../etc/passwd")
            info.size = 4
            tf.addfile(info, io.BytesIO(b"evil"))

        dest = tmp_path / "output"
        with pytest.raises(ExtractionError, match=r"[Pp]ath traversal"):
            extract_archive_to_disk(archive_path, dest)

    @pytest.mark.skipif(
        sys.version_info >= (3, 12),
        reason="Manual shim only used on 3.10/3.11",
    )
    def test_absolute_path_blocked(self, tmp_path: Path) -> None:
        """Manual shim rejects absolute paths."""
        archive_path = tmp_path / "evil.tar.gz"
        with tarfile.open(archive_path, "w:gz") as tf:
            info = tarfile.TarInfo(name="/etc/passwd")
            info.size = 4
            tf.addfile(info, io.BytesIO(b"evil"))

        dest = tmp_path / "output"
        with pytest.raises(ExtractionError, match="absolute path"):
            extract_archive_to_disk(archive_path, dest)

    @pytest.mark.skipif(
        sys.version_info >= (3, 12),
        reason="Manual shim only used on 3.10/3.11",
    )
    def test_device_file_blocked(self, tmp_path: Path) -> None:
        """Manual shim rejects device files."""
        archive_path = tmp_path / "evil.tar.gz"
        with tarfile.open(archive_path, "w:gz") as tf:
            info = tarfile.TarInfo(name="evil_dev")
            info.type = tarfile.BLKTYPE
            tf.addfile(info)

        dest = tmp_path / "output"
        with pytest.raises(ExtractionError, match="special file"):
            extract_archive_to_disk(archive_path, dest)


# ---------------------------------------------------------------------------
# extract_archive_to_disk — zip-specific
# ---------------------------------------------------------------------------


class TestExtractToDiskZip:
    """Zip-specific extract_archive_to_disk tests (path traversal)."""

    def test_path_traversal_blocked(self, tmp_path: Path) -> None:
        """Zip path traversal (Zip Slip) is blocked."""
        archive_path = tmp_path / "evil.whl"
        with zipfile.ZipFile(archive_path, "w") as zf:
            zf.writestr("../../../etc/passwd", b"evil")

        dest = tmp_path / "output"
        with pytest.raises(ExtractionError, match=r"[Pp]ath traversal"):
            extract_archive_to_disk(archive_path, dest)


# ---------------------------------------------------------------------------
# Root prefix detection and stripping
# ---------------------------------------------------------------------------


class TestRootPrefixStripping:
    """Test that sdist root directory prefixes are handled transparently."""

    def test_tar_without_root_dir_no_stripping(self, tmp_path: Path) -> None:
        """Flat archive (no root dir): paths unchanged."""
        files = {"a.txt": b"aaa", "b.txt": b"bbb"}
        archive = _make_tar_gz(tmp_path, files)
        members = list_archive(archive)
        paths = [m.path for m in members]
        assert paths == ["a.txt", "b.txt"]

    def test_zip_with_root_dir_strips_prefix(self, tmp_path: Path) -> None:
        """Zip sdist with root dir: prefix stripped from paths."""
        archive_path = tmp_path / "test.zip"
        with zipfile.ZipFile(archive_path, "w") as zf:
            zf.writestr("pkg-1.0.0/setup.py", b"setup()")
            zf.writestr("pkg-1.0.0/README.md", b"# Hello")
        members = list_archive(archive_path)
        paths = [m.path for m in members]
        assert "setup.py" in paths
        assert "README.md" in paths
        assert all("pkg-1.0.0" not in p for p in paths)

    def test_zip_without_root_dir_no_stripping(self, tmp_path: Path) -> None:
        """Wheel-like zip (multiple top-level entries): no stripping."""
        archive = _make_zip(
            tmp_path,
            {
                "pkg/__init__.py": b"",
                "pkg-1.0.0.dist-info/METADATA": b"Name: pkg",
            },
        )
        members = list_archive(archive)
        paths = [m.path for m in members]
        assert "pkg/__init__.py" in paths
        assert "pkg-1.0.0.dist-info/METADATA" in paths

    def test_extract_file_zip_resolves_root_prefix(self, tmp_path: Path) -> None:
        """extract_file auto-prepends root prefix for zip sdists."""
        content = b"[project]\nname = 'test'"
        archive_path = tmp_path / "test.zip"
        with zipfile.ZipFile(archive_path, "w") as zf:
            zf.writestr("pkg-1.0.0/pyproject.toml", content)
        result = extract_file(archive_path, "pyproject.toml")
        assert result == content

    def test_extract_all_zip_strips_root_prefix(self, tmp_path: Path) -> None:
        """extract_all returns keys without root prefix for zip sdists."""
        archive_path = tmp_path / "test.zip"
        with zipfile.ZipFile(archive_path, "w") as zf:
            zf.writestr("pkg-1.0.0/a.py", b"import os")
            zf.writestr("pkg-1.0.0/b.py", b"import sys")
        result = extract_all(archive_path)
        assert set(result.keys()) == {"a.py", "b.py"}

    def test_single_file_at_root_no_stripping(self, tmp_path: Path) -> None:
        """A single file at root (no directory) is not treated as a prefix."""
        archive = _make_tar_gz(tmp_path, {"setup.py": b"setup()"})
        members = list_archive(archive)
        assert len(members) == 1
        assert members[0].path == "setup.py"

    def test_error_message_uses_user_path(self, tmp_path: Path) -> None:
        """Error messages show the user-provided path, not the resolved one."""
        archive = _make_tar_gz_with_dir(tmp_path, {"a.txt": b"data"})
        with pytest.raises(ExtractionFileNotFoundError, match=r"missing\.txt"):
            extract_file(archive, "missing.txt")


# ---------------------------------------------------------------------------
# Size limit enforcement (via extract_file pre-checks)
# ---------------------------------------------------------------------------


class TestReadWithLimit:
    """Size limit enforcement via streaming reads."""

    def test_declared_size_exceeds_limit(self, tmp_path: Path) -> None:
        """File whose declared size exceeds the limit is rejected."""
        data = b"x" * 2048
        archive = _make_tar_gz(tmp_path, {"big.txt": data})
        limits = ExtractionLimits(max_single_file_bytes=1024)
        with pytest.raises(ExtractionLimitExceededError):
            extract_file(archive, "big.txt", limits=limits)


# ---------------------------------------------------------------------------
# ArchiveMember dataclass
# ---------------------------------------------------------------------------


class TestArchiveMember:
    """ArchiveMember dataclass immutability."""

    def test_frozen(self) -> None:
        m = ArchiveMember(path="test.py", size=42, is_dir=False)
        with pytest.raises(AttributeError):
            m.path = "other.py"  # ty: ignore[invalid-assignment]


# ---------------------------------------------------------------------------
# Lying archive defense (_read_with_limit streaming check)
# ---------------------------------------------------------------------------


class TestLyingArchiveDefense:
    """Test defense against archives that lie about member sizes.

    `_read_with_limit` reads up to `max_bytes + 1` from the stream
    and raises when the actual byte count exceeds the limit.  Python's
    `tarfile.ExFileObject` already caps reads at the declared header
    size, so this defence is a belt-and-suspenders layer against
    non-standard or manipulated IO sources.
    """

    def test_stream_exceeding_limit_rejected(self) -> None:
        """Reject stream whose actual bytes far exceed the limit."""
        declared = 100  # Under the limit — passes the declared-size check
        actual = b"x" * 10_000  # Much larger than both declared and limit
        max_bytes = 500

        with pytest.raises(ExtractionLimitExceededError, match="lying"):
            _read_with_limit(io.BytesIO(actual), declared, max_bytes)

    def test_stream_one_byte_over_limit_rejected(self) -> None:
        """Reject stream one byte over the limit via streaming read."""
        data = b"x" * 501  # Exactly one byte over the 500-byte limit
        with pytest.raises(ExtractionLimitExceededError, match="lying"):
            _read_with_limit(io.BytesIO(data), 100, 500)

    def test_stream_within_limit_accepted(self) -> None:
        """Accept stream whose actual bytes are under the limit."""
        data = b"x" * 400
        result = _read_with_limit(io.BytesIO(data), 400, 500)
        assert result == data

    def test_stream_exactly_at_limit_accepted(self) -> None:
        """Accept stream whose actual bytes equal the limit exactly."""
        data = b"x" * 500
        result = _read_with_limit(io.BytesIO(data), 500, 500)
        assert result == data

    def test_declared_size_over_limit_fast_rejected(self) -> None:
        """Reject when declared size exceeds the limit before reading."""
        with pytest.raises(ExtractionLimitExceededError, match="exceeds limit"):
            _read_with_limit(io.BytesIO(b""), 1000, 500)

    def test_lying_tar_detected_via_extract_file(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Detect lying tar stream through the extract_file public API.

        Python's `tarfile.ExFileObject` caps reads at the declared
        header size, so a genuinely lying tar cannot be constructed
        through the tarfile API alone.  This test monkeypatches
        `extractfile` to return an oversized stream, simulating an
        IO source that ignores the declared size.
        """
        archive = _make_tar_gz(tmp_path, {"payload.bin": b"x" * 100})
        limits = ExtractionLimits(max_single_file_bytes=500)

        original = tarfile.TarFile.extractfile

        def _patched(self, member):
            name = member.name if isinstance(member, tarfile.TarInfo) else str(member)
            if name.endswith("payload.bin"):
                return io.BytesIO(b"x" * 10_000)
            return original(self, member)

        monkeypatch.setattr(tarfile.TarFile, "extractfile", _patched)

        with pytest.raises(ExtractionLimitExceededError, match="lying"):
            extract_file(archive, "payload.bin", limits=limits)


# ---------------------------------------------------------------------------
# Malicious archive safety (symlink / hardlink escape)
# ---------------------------------------------------------------------------


class TestMaliciousArchiveSafety:
    """Test rejection of malicious tar members that escape the destination.

    On Python 3.12+ the built-in `data_filter` blocks these attacks.
    On 3.10/3.11 the manual safety shim in `_extract_tar_member_safe`
    performs the same checks.  Tests use the public
    `extract_archive_to_disk` API so they pass on all supported
    Python versions.
    """

    def test_symlink_escape_blocked(self, tmp_path: Path) -> None:
        """Reject symlink pointing outside the extraction destination."""
        archive_path = tmp_path / "evil.tar.gz"
        with tarfile.open(archive_path, "w:gz") as tf:
            info = tarfile.TarInfo(name="escape_link")
            info.type = tarfile.SYMTYPE
            info.linkname = "../../etc/passwd"
            tf.addfile(info)

        dest = tmp_path / "output"
        # ExtractionError on 3.10/3.11 (manual shim),
        # tarfile.TarError subclass on 3.12+ (data_filter).
        with pytest.raises((ExtractionError, tarfile.TarError)):
            extract_archive_to_disk(archive_path, dest)

    def test_hardlink_escape_blocked(self, tmp_path: Path) -> None:
        """Reject hardlink pointing outside the extraction destination."""
        archive_path = tmp_path / "evil.tar.gz"
        with tarfile.open(archive_path, "w:gz") as tf:
            info = tarfile.TarInfo(name="escape_hardlink")
            info.type = tarfile.LNKTYPE
            info.linkname = "../../etc/passwd"
            tf.addfile(info)

        dest = tmp_path / "output"
        with pytest.raises((ExtractionError, tarfile.TarError)):
            extract_archive_to_disk(archive_path, dest)
