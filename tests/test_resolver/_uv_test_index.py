"""Deterministic local package indexes for real-uv resolver tests."""

from __future__ import annotations

import gzip
import io
import tarfile
import zipfile
from dataclasses import dataclass
from typing import TYPE_CHECKING

from packaging.utils import canonicalize_name

if TYPE_CHECKING:
    from pathlib import Path

_FIXED_ZIP_TIME = (2020, 1, 1, 0, 0, 0)


@dataclass(frozen=True)
class WheelPackage:
    """Definition of a tiny pure-Python wheel in the test index."""

    name: str
    version: str
    requires_dist: tuple[str, ...] = ()


@dataclass(frozen=True)
class UvTestIndex:
    """Paths and URLs for the controlled uv package-index fixture."""

    primary_root: Path
    secondary_root: Path
    build_sentinel: Path

    @property
    def primary_url(self) -> str:
        """Return the primary PEP 503 Simple API URL."""
        return f"{(self.primary_root / 'simple').as_uri()}/"

    @property
    def secondary_url(self) -> str:
        """Return the secondary PEP 503 Simple API URL."""
        return f"{(self.secondary_root / 'simple').as_uri()}/"


def build_uv_test_index(root: Path) -> UvTestIndex:
    """Build two deterministic local PEP 503 indexes under `root`."""
    primary_root = root / "primary"
    secondary_root = root / "secondary"
    build_sentinel = root / "build-backend-executed"

    primary_packages = (
        WheelPackage(
            "peeq-fixture-root",
            "1.0.0",
            (
                "peeq-fixture-child==1.0.0",
                'peeq-fixture-extra==1.0.0; extra == "feature"',
                'peeq-fixture-marker==1.0.0; python_version >= "3.10"',
            ),
        ),
        WheelPackage("peeq-fixture-child", "1.0.0"),
        WheelPackage("peeq-fixture-extra", "1.0.0"),
        WheelPackage("peeq-fixture-marker", "1.0.0"),
        WheelPackage(
            "peeq-fixture-conflict-left",
            "1.0.0",
            ("peeq-fixture-shared<2",),
        ),
        WheelPackage(
            "peeq-fixture-conflict-right",
            "1.0.0",
            ("peeq-fixture-shared>=2",),
        ),
        WheelPackage("peeq-fixture-shared", "1.0.0"),
        WheelPackage("peeq-fixture-shared", "2.0.0"),
        WheelPackage("peeq-fixture-collision", "1.0.0"),
    )
    secondary_packages = (WheelPackage("peeq-fixture-collision", "2.0.0"),)

    for package in primary_packages:
        _add_wheel(primary_root, package)
    for package in secondary_packages:
        _add_wheel(secondary_root, package)
    _write_wheel_project_indexes(primary_root, primary_packages)
    _write_wheel_project_indexes(secondary_root, secondary_packages)
    _add_source_only_package(primary_root, build_sentinel)

    _write_root_index(primary_root, (*primary_packages,))
    _write_root_index(secondary_root, secondary_packages)
    return UvTestIndex(primary_root, secondary_root, build_sentinel)


def _add_wheel(index_root: Path, package: WheelPackage) -> None:
    """Add one tiny wheel and its project page to an index."""
    wheel_name = package.name.replace("-", "_")
    filename = f"{wheel_name}-{package.version}-py3-none-any.whl"
    wheel_path = index_root / "packages" / filename
    wheel_path.parent.mkdir(parents=True, exist_ok=True)

    dist_info = f"{wheel_name}-{package.version}.dist-info"
    metadata_lines = [
        "Metadata-Version: 2.3",
        f"Name: {package.name}",
        f"Version: {package.version}",
        "Requires-Python: >=3.10",
        *(f"Requires-Dist: {requirement}" for requirement in package.requires_dist),
        "",
    ]
    members = {
        f"{wheel_name}/__init__.py": "",
        f"{dist_info}/METADATA": "\n".join(metadata_lines),
        f"{dist_info}/WHEEL": (
            "Wheel-Version: 1.0\nGenerator: peeq-test-suite\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
        ),
    }
    record_path = f"{dist_info}/RECORD"
    members[record_path] = "".join(f"{path},,\n" for path in (*members, record_path))

    with zipfile.ZipFile(wheel_path, "w") as archive:
        for path, content in members.items():
            info = zipfile.ZipInfo(path, _FIXED_ZIP_TIME)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            archive.writestr(info, content.encode())


def _add_source_only_package(index_root: Path, build_sentinel: Path) -> None:
    """Add a valid dynamic-metadata sdist with a sentinel build backend."""
    name = "peeq-fixture-source-only"
    version = "1.0.0"
    filename = f"{name.replace('-', '_')}-{version}.tar.gz"
    archive_path = index_root / "packages" / filename
    archive_path.parent.mkdir(parents=True, exist_ok=True)

    pyproject = '[build-system]\nrequires = []\nbuild-backend = "sentinel_backend"\nbackend-path = ["."]\n'
    backend = f'''"""Controlled test backend that records every hook execution."""

from pathlib import Path


def _write_sentinel():
    Path({str(build_sentinel)!r}).write_text("executed", encoding="utf-8")


def get_requires_for_build_wheel(config_settings=None):
    _write_sentinel()
    return []


def prepare_metadata_for_build_wheel(metadata_directory, config_settings=None):
    _write_sentinel()
    dist_info = Path(metadata_directory) / "peeq_fixture_source_only-1.0.0.dist-info"
    dist_info.mkdir()
    (dist_info / "METADATA").write_text(
        "Metadata-Version: 2.3\\n"
        "Name: peeq-fixture-source-only\\n"
        "Version: 1.0.0\\n",
        encoding="utf-8",
    )
    return dist_info.name


def build_wheel(wheel_directory, config_settings=None, metadata_directory=None):
    _write_sentinel()
    raise RuntimeError("The controlled test backend must never build a wheel")
'''
    root = f"{name.replace('-', '_')}-{version}"
    with (
        archive_path.open("wb") as raw_file,
        gzip.GzipFile(filename="", mode="wb", fileobj=raw_file, mtime=0) as gzip_file,
        tarfile.open(fileobj=gzip_file, mode="w") as archive,
    ):
        _add_tar_text(archive, f"{root}/pyproject.toml", pyproject)
        _add_tar_text(archive, f"{root}/sentinel_backend.py", backend)

    _write_project_index(index_root, name, [filename])


def _write_wheel_project_indexes(
    index_root: Path,
    packages: tuple[WheelPackage, ...],
) -> None:
    """Write one project page containing every wheel version for each name."""
    filenames_by_name: dict[str, list[str]] = {}
    for package in packages:
        filename = f"{package.name.replace('-', '_')}-{package.version}-py3-none-any.whl"
        filenames_by_name.setdefault(package.name, []).append(filename)

    for name, filenames in filenames_by_name.items():
        _write_project_index(index_root, name, filenames)


def _add_tar_text(archive: tarfile.TarFile, path: str, content: str) -> None:
    """Add one deterministic UTF-8 text member to a tar archive."""
    data = content.encode()
    info = tarfile.TarInfo(path)
    info.size = len(data)
    info.mode = 0o644
    info.mtime = 0
    archive.addfile(info, io.BytesIO(data))


def _write_project_index(index_root: Path, name: str, filenames: list[str]) -> None:
    """Write a PEP 503 project page for the provided artifacts."""
    project_dir = index_root / "simple" / canonicalize_name(name)
    project_dir.mkdir(parents=True, exist_ok=True)
    links = "\n".join(f'<a href="../../packages/{filename}">{filename}</a><br>' for filename in sorted(filenames))
    project_dir.joinpath("index.html").write_text(
        f"<!doctype html>\n<html><body>\n{links}\n</body></html>\n",
        encoding="utf-8",
    )


def _write_root_index(index_root: Path, packages: tuple[WheelPackage, ...]) -> None:
    """Write the root PEP 503 page used for fixture inspection."""
    names: list[str] = sorted({str(canonicalize_name(package.name)) for package in packages})
    if index_root.name == "primary":
        names.append("peeq-fixture-source-only")
    links = "\n".join(f'<a href="{name}/">{name}</a><br>' for name in names)
    simple_root = index_root / "simple"
    simple_root.mkdir(parents=True, exist_ok=True)
    simple_root.joinpath("index.html").write_text(
        f"<!doctype html>\n<html><body>\n{links}\n</body></html>\n",
        encoding="utf-8",
    )
