"""Tests for peeq.models."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from packaging.requirements import InvalidRequirement
from packaging.version import Version
from pydantic import ValidationError

from peeq.models import (
    CacheStats,
    CvssSeverity,
    Dependency,
    DistType,
    DownloadResult,
    FileInfo,
    HashDigest,
    PackageInfo,
    PackageMetadata,
    VersionInfo,
    VulnerabilityInfo,
    VulnerabilityReference,
    VulnerabilityReport,
)

# ---------------------------------------------------------------------------
# HashDigest
# ---------------------------------------------------------------------------


class TestHashDigest:
    def test_invalid_source_rejected(self):
        with pytest.raises(ValidationError):
            HashDigest(sha256="abc", source="unknown")  # ty: ignore[invalid-argument-type]

    def test_frozen(self):
        h = HashDigest(sha256="abc", source="registry")
        with pytest.raises(ValidationError):
            h.sha256 = "xyz"  # ty: ignore[invalid-assignment]

    def test_roundtrip_json(self):
        h = HashDigest(sha256="abc123", source="registry")
        data = json.loads(h.model_dump_json())
        assert data == {"sha256": "abc123", "source": "registry"}
        h2 = HashDigest.model_validate(data)
        assert h2 == h


# ---------------------------------------------------------------------------
# PkgVersion
# ---------------------------------------------------------------------------


class TestPkgVersion:
    def test_from_string(self):
        info = PackageInfo(name="pkg", latest_version="1.2.3", version_count=1)  # ty: ignore[invalid-argument-type]
        assert isinstance(info.latest_version, Version)
        assert str(info.latest_version) == "1.2.3"

    def test_from_version_instance(self):
        v = Version("2.0.0rc1")
        info = PackageInfo(name="pkg", latest_version=v, version_count=1)
        assert info.latest_version is v

    def test_serialization(self):
        info = PackageInfo(name="pkg", latest_version="1.0.0", version_count=5)  # ty: ignore[invalid-argument-type]
        data = json.loads(info.model_dump_json())
        assert data["latest_version"] == "1.0.0"

    def test_deserialization_from_json(self):
        raw = '{"name": "pkg", "latest_version": "3.0.0", "version_count": 1}'
        info = PackageInfo.model_validate_json(raw)
        assert isinstance(info.latest_version, Version)
        assert str(info.latest_version) == "3.0.0"

    def test_normalization(self):
        """PEP 440 normalizes versions (e.g., leading zeros stripped)."""
        info = PackageInfo(name="pkg", latest_version="01.02.03", version_count=1)  # ty: ignore[invalid-argument-type]
        assert str(info.latest_version) == "1.2.3"

    def test_invalid_version_rejected(self):
        with pytest.raises(ValidationError):
            PackageInfo(name="pkg", latest_version="not-a-version!", version_count=1)  # ty: ignore[invalid-argument-type]


# ---------------------------------------------------------------------------
# Dependency
# ---------------------------------------------------------------------------


class TestDependency:
    def test_from_requirement_string_simple(self):
        dep = Dependency.from_requirement_string("requests>=2.28")
        assert dep.name == "requests"
        assert dep.specifier == ">=2.28"
        assert dep.extras == []
        assert dep.markers is None
        assert dep.raw == "requests>=2.28"

    def test_from_requirement_string_with_extras(self):
        dep = Dependency.from_requirement_string("httpx[http2]>=0.28")
        assert dep.name == "httpx"
        assert dep.specifier == ">=0.28"
        assert dep.extras == ["http2"]

    def test_from_requirement_string_with_markers(self):
        dep = Dependency.from_requirement_string('PySocks>=1.5.6; extra == "socks"')
        assert dep.name == "pysocks"  # normalized
        assert dep.specifier == ">=1.5.6"
        assert dep.markers == 'extra == "socks"'
        assert dep.raw == 'PySocks>=1.5.6; extra == "socks"'

    def test_name_normalization(self):
        """Names are normalized: lowercase, separators become hyphens."""
        dep = Dependency.from_requirement_string("My_Package.Name")
        assert dep.name == "my-package-name"

    def test_unconstrained(self):
        dep = Dependency.from_requirement_string("numpy")
        assert dep.name == "numpy"
        assert dep.specifier == ""
        assert dep.extras == []
        assert dep.markers is None

    def test_multiple_extras_sorted(self):
        dep = Dependency.from_requirement_string("pkg[z,a,m]")
        assert dep.extras == ["a", "m", "z"]

    def test_complex_specifier(self):
        dep = Dependency.from_requirement_string("charset-normalizer>=2,<4,!=3.0.0")
        assert dep.name == "charset-normalizer"
        assert ">=2" in dep.specifier
        assert "<4" in dep.specifier
        assert "!=3.0.0" in dep.specifier

    def test_frozen(self):
        dep = Dependency.from_requirement_string("numpy>=1.21")
        with pytest.raises(ValidationError):
            dep.name = "other"  # ty: ignore[invalid-assignment]

    def test_roundtrip_json(self):
        dep = Dependency.from_requirement_string("httpx[http2]>=0.28")
        data = json.loads(dep.model_dump_json())
        dep2 = Dependency.model_validate(data)
        assert dep2 == dep

    def test_direct_kwargs(self):
        """Direct construction works for DB reconstruction."""
        dep = Dependency(
            name="numpy",
            specifier=">=1.21",
            raw="numpy>=1.21",
        )
        assert dep.name == "numpy"
        assert dep.specifier == ">=1.21"

    def test_invalid_requirement_raises(self):
        with pytest.raises(InvalidRequirement):
            Dependency.from_requirement_string("not a valid req!!!")


# ---------------------------------------------------------------------------
# PackageInfo
# ---------------------------------------------------------------------------


class TestPackageInfo:
    def test_frozen(self):
        info = PackageInfo(name="pkg", latest_version="1.0.0", version_count=1)  # ty: ignore[invalid-argument-type]
        with pytest.raises(ValidationError):
            info.name = "other"  # ty: ignore[invalid-assignment]


# ---------------------------------------------------------------------------
# VersionInfo
# ---------------------------------------------------------------------------


class TestVersionInfo:
    def test_frozen(self):
        vi = VersionInfo(version="1.0.0")  # ty: ignore[invalid-argument-type]
        with pytest.raises(ValidationError):
            vi.version = "2.0.0"  # ty: ignore[invalid-assignment]

    def test_json_roundtrip(self):
        vi = VersionInfo(version="1.2.3", yanked=True, yanked_reason="bad release")  # ty: ignore[invalid-argument-type]
        data = json.loads(vi.model_dump_json())
        assert data["version"] == "1.2.3"
        assert data["yanked"] is True
        assert data["yanked_reason"] == "bad release"

        restored = VersionInfo.model_validate(data)
        assert str(restored.version) == "1.2.3"
        assert restored.yanked is True


# ---------------------------------------------------------------------------
# FileInfo
# ---------------------------------------------------------------------------


class TestFileInfo:
    def test_frozen(self):
        f = FileInfo(
            filename="pkg-1.0.tar.gz",
            url="https://example.com/pkg",
            dist_type=DistType.SDIST,
        )
        with pytest.raises(ValidationError):
            f.filename = "other"  # ty: ignore[invalid-assignment]


# ---------------------------------------------------------------------------
# DownloadResult
# ---------------------------------------------------------------------------


class TestDownloadResult:
    def test_frozen(self):
        r = DownloadResult(
            path=Path("downloads/pkg-1.0.tar.gz"),
            hash=HashDigest(sha256="abc", source="registry"),
            size_bytes=100,
        )
        with pytest.raises(ValidationError):
            r.size_bytes = 200  # ty: ignore[invalid-assignment]


# ---------------------------------------------------------------------------
# CacheStats
# ---------------------------------------------------------------------------


class TestCacheStats:
    def test_frozen(self):
        s = CacheStats(
            location=Path("cache/peeq"),
            package_count=0,
            distribution_count=0,
            total_size_bytes=0,
        )
        with pytest.raises(ValidationError):
            s.package_count = 5  # ty: ignore[invalid-assignment]


# ---------------------------------------------------------------------------
# PackageMetadata
# ---------------------------------------------------------------------------


class TestPackageMetadata:
    def test_mutable(self):
        """PackageMetadata is intentionally NOT frozen for staged assembly."""
        m = PackageMetadata()

        # Stage 1: JSON blob provides scalar fields
        m.python_requires = ">=3.10"
        m.license = "MIT"
        assert m.python_requires == ">=3.10"

        # Stage 2: metadata_source column provides source
        m.source = "wheel"
        assert m.source == "wheel"

        # Stage 3: dependencies table provides deps
        m.dependencies = [Dependency.from_requirement_string("requests>=2.28")]
        assert len(m.dependencies) == 1

    def test_serialization_excludes_deps_and_source(self):
        """The JSON blob for the DB excludes dependencies and source."""
        m = PackageMetadata(
            dependencies=[
                Dependency.from_requirement_string("numpy>=1.21"),
            ],
            python_requires=">=3.8",
            license="MIT",
            summary="A package",
            author="Test Author",
            homepage="https://example.com",
            source="pep658",
        )
        blob = m.model_dump(mode="json", exclude={"dependencies", "source"})
        assert "dependencies" not in blob
        assert "source" not in blob
        assert blob["python_requires"] == ">=3.8"
        assert blob["license"] == "MIT"
        assert blob["summary"] == "A package"
        assert blob["author"] == "Test Author"
        assert blob["homepage"] == "https://example.com"

    def test_json_blob_roundtrip(self):
        """Simulate the DB write/read cycle for the JSON blob."""
        original = PackageMetadata(
            dependencies=[
                Dependency.from_requirement_string("httpx[http2]>=0.28"),
            ],
            python_requires=">=3.10",
            license="MIT",
            summary="Test",
            author="Author",
            homepage="https://example.com",
            source="wheel",
        )

        # Write: serialize blob excluding deps and source
        blob_json = original.model_dump_json(exclude={"dependencies", "source"})

        # Read stage 1: deserialize blob
        restored = PackageMetadata.model_validate_json(blob_json)
        assert restored.dependencies is None  # not in blob
        assert restored.source is None  # not in blob
        assert restored.python_requires == ">=3.10"

        # Read stage 2: set source from column
        restored.source = "wheel"
        assert restored.source == "wheel"

        # Read stage 3: set dependencies from table
        restored.dependencies = [
            Dependency.from_requirement_string("httpx[http2]>=0.28"),
        ]
        assert len(restored.dependencies) == 1
        assert restored.dependencies[0].name == "httpx"
        assert restored.dependencies[0].extras == ["http2"]

    def test_deps_none_vs_empty_list(self):
        """None means 'unknown/unknowable', [] means 'no dependencies'."""
        unknown = PackageMetadata(dependencies=None)
        no_deps = PackageMetadata(dependencies=[])
        assert unknown.dependencies is None
        assert no_deps.dependencies == []
        assert unknown.dependencies != no_deps.dependencies


# ---------------------------------------------------------------------------
# Vulnerability models
# ---------------------------------------------------------------------------


class TestCvssSeverity:
    """Tests for `CvssSeverity`."""

    def test_frozen(self):
        """CvssSeverity is immutable."""
        s = CvssSeverity(type="CVSS_V3", score="x")
        with pytest.raises(ValidationError):
            s.type = "CVSS_V4"  # ty: ignore[invalid-assignment]

    def test_json_roundtrip(self):
        """Serialize to JSON and back."""
        s = CvssSeverity(type="CVSS_V3", score="CVSS:3.1/AV:N")
        data = json.loads(s.model_dump_json())
        assert data["type"] == "CVSS_V3"
        assert data["score"] == "CVSS:3.1/AV:N"
        restored = CvssSeverity.model_validate(data)
        assert restored == s


class TestVulnerabilityReference:
    """Tests for `VulnerabilityReference`."""

    def test_frozen(self):
        """VulnerabilityReference is immutable."""
        ref = VulnerabilityReference(type="FIX", url="https://example.com")
        with pytest.raises(ValidationError):
            ref.url = "other"  # ty: ignore[invalid-assignment]


class TestVulnerabilityInfo:
    """Tests for `VulnerabilityInfo`."""

    def test_frozen(self):
        """VulnerabilityInfo is immutable."""
        v = VulnerabilityInfo(id="GHSA-test")
        with pytest.raises(ValidationError):
            v.id = "other"  # ty: ignore[invalid-assignment]

    def test_json_roundtrip(self):
        """Serialize to JSON and back."""
        v = VulnerabilityInfo(
            id="PYSEC-2021-42",
            summary="Test vuln",
            aliases=["CVE-2021-42"],
            fixed_versions=["1.0.0"],
        )
        data = json.loads(v.model_dump_json())
        assert data["id"] == "PYSEC-2021-42"
        restored = VulnerabilityInfo.model_validate(data)
        assert restored == v


class TestVulnerabilityReport:
    """Tests for `VulnerabilityReport`."""

    def test_frozen(self):
        """VulnerabilityReport is immutable."""
        r = VulnerabilityReport(package="pkg", version="1.0.0")
        with pytest.raises(ValidationError):
            r.package = "other"  # ty: ignore[invalid-assignment]
