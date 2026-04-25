"""Tests for resolver data models."""

from __future__ import annotations

import os
import platform
import sys

import pytest
from packaging.version import Version
from pydantic import ValidationError

from peeq.resolver.models import (
    ConflictInfo,
    ConflictRequirement,
    DependencyEdge,
    ResolvedDependency,
    SolverResult,
    TargetEnvironment,
)

# ---------------------------------------------------------------------------
# TargetEnvironment
# ---------------------------------------------------------------------------


class TestTargetEnvironment:
    """Tests for TargetEnvironment model."""

    def test_defaults_are_empty(self) -> None:
        env = TargetEnvironment()
        assert env.python_version == ""
        assert env.os_name == ""
        assert env.sys_platform == ""
        assert env.platform_machine == ""

    def test_frozen(self) -> None:
        env = TargetEnvironment(python_version="3.12")
        with pytest.raises(ValidationError):
            env.python_version = "3.13"  # type: ignore[misc]

    def test_to_marker_env_empty(self) -> None:
        env = TargetEnvironment()
        assert env.to_marker_env() == {}

    def test_to_marker_env_python_version_two_part(self) -> None:
        env = TargetEnvironment(python_version="3.12")
        marker_env = env.to_marker_env()
        assert marker_env["python_version"] == "3.12"
        assert marker_env["python_full_version"] == "3.12.0"

    def test_to_marker_env_python_version_three_part(self) -> None:
        env = TargetEnvironment(python_version="3.12.1")
        marker_env = env.to_marker_env()
        assert marker_env["python_version"] == "3.12.1"
        assert marker_env["python_full_version"] == "3.12.1"

    def test_to_marker_env_all_fields(self) -> None:
        env = TargetEnvironment(
            python_version="3.11",
            os_name="posix",
            sys_platform="linux",
            platform_machine="x86_64",
        )
        marker_env = env.to_marker_env()
        assert marker_env["python_version"] == "3.11"
        assert marker_env["python_full_version"] == "3.11.0"
        assert marker_env["os_name"] == "posix"
        assert marker_env["sys_platform"] == "linux"
        assert marker_env["platform_machine"] == "x86_64"

    def test_to_marker_env_partial(self) -> None:
        env = TargetEnvironment(os_name="nt", sys_platform="win32")
        marker_env = env.to_marker_env()
        assert "python_version" not in marker_env
        assert marker_env["os_name"] == "nt"
        assert marker_env["sys_platform"] == "win32"

    def test_current(self) -> None:
        env = TargetEnvironment.current()
        v = sys.version_info
        assert env.python_version == f"{v.major}.{v.minor}"
        assert env.os_name == os.name
        assert env.sys_platform == sys.platform
        assert env.platform_machine == platform.machine()

    def test_json_roundtrip(self) -> None:
        env = TargetEnvironment(
            python_version="3.12",
            os_name="posix",
            sys_platform="linux",
            platform_machine="x86_64",
        )
        data = env.model_dump(mode="json")
        restored = TargetEnvironment.model_validate(data)
        assert restored == env


# ---------------------------------------------------------------------------
# ResolvedDependency
# ---------------------------------------------------------------------------


class TestResolvedDependency:
    """Tests for ResolvedDependency model."""

    def test_construction(self) -> None:
        dep = ResolvedDependency(
            name="requests",
            version=Version("2.31.0"),
            dependencies=["certifi", "urllib3"],
        )
        assert dep.name == "requests"
        assert dep.version == Version("2.31.0")
        assert dep.dependencies == ["certifi", "urllib3"]

    def test_default_empty_dependencies(self) -> None:
        dep = ResolvedDependency(name="click", version=Version("8.0.0"))
        assert dep.dependencies == []

    def test_default_empty_dependency_edges(self) -> None:
        dep = ResolvedDependency(name="click", version=Version("8.0.0"))
        assert dep.dependency_edges == []

    def test_dependency_edges_populated(self) -> None:
        dep = ResolvedDependency(
            name="requests",
            version=Version("2.31.0"),
            dependencies=["urllib3"],
            dependency_edges=[
                DependencyEdge(
                    name="urllib3",
                    requirement="urllib3>=1.21.1,<3",
                ),
            ],
        )
        assert len(dep.dependency_edges) == 1
        assert dep.dependency_edges[0].name == "urllib3"
        assert dep.dependency_edges[0].requirement == "urllib3>=1.21.1,<3"

    def test_frozen(self) -> None:
        dep = ResolvedDependency(name="click", version=Version("8.0.0"))
        with pytest.raises(ValidationError):
            dep.name = "other"  # type: ignore[misc]

    def test_version_from_string(self) -> None:
        dep = ResolvedDependency(name="click", version="8.0.0")  # type: ignore[arg-type]
        assert dep.version == Version("8.0.0")


# ---------------------------------------------------------------------------
# SolverResult
# ---------------------------------------------------------------------------


class TestSolverResult:
    """Tests for SolverResult model."""

    def test_construction(self) -> None:
        result = SolverResult(
            resolved=[
                ResolvedDependency(
                    name="flask", version=Version("3.0.0"), dependencies=["click"]
                ),
                ResolvedDependency(
                    name="click", version=Version("8.1.0"), dependencies=[]
                ),
            ],
            solver_id="uv",
        )
        assert len(result.resolved) == 2
        assert result.solver_id == "uv"

    def test_empty_resolution(self) -> None:
        result = SolverResult(resolved=[], solver_id="uv")
        assert result.resolved == []

    def test_frozen(self) -> None:
        result = SolverResult(resolved=[], solver_id="uv")
        with pytest.raises(ValidationError):
            result.solver_id = "other"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# ConflictRequirement
# ---------------------------------------------------------------------------


class TestConflictRequirement:
    """Tests for ConflictRequirement model."""

    def test_construction(self) -> None:
        req = ConflictRequirement(
            package="tensorflow",
            version="2.15.0",
            dependency="numpy>=1.23,<1.27",
        )
        assert req.package == "tensorflow"
        assert req.version == "2.15.0"
        assert req.dependency == "numpy>=1.23,<1.27"
        assert req.chain == []

    def test_frozen(self) -> None:
        req = ConflictRequirement(package="pkg", version="1.0", dependency="dep>=1.0")
        with pytest.raises(ValidationError):
            req.package = "other"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# ConflictInfo
# ---------------------------------------------------------------------------


class TestConflictInfo:
    """Tests for ConflictInfo model."""

    def test_construction(self) -> None:
        conflict = ConflictInfo(
            package="numpy",
            requirements=[
                ConflictRequirement(
                    package="tensorflow",
                    version="2.15.0",
                    dependency="numpy>=1.23,<1.27",
                ),
                ConflictRequirement(
                    package="torch",
                    version="2.0.0",
                    dependency="numpy>=1.21.0",
                ),
            ],
            message="No version of numpy satisfies both constraints",
        )
        assert conflict.package == "numpy"
        assert len(conflict.requirements) == 2
        assert conflict.message != ""

    def test_defaults(self) -> None:
        conflict = ConflictInfo(package="numpy")
        assert conflict.requirements == []
        assert conflict.message == ""
        assert conflict.hints == []

    def test_frozen(self) -> None:
        conflict = ConflictInfo(package="numpy")
        with pytest.raises(ValidationError):
            conflict.package = "other"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# DependencyEdge
# ---------------------------------------------------------------------------


class TestDependencyEdge:
    """Tests for DependencyEdge model."""

    def test_construction(self) -> None:
        edge = DependencyEdge(
            name="numpy",
            extras=frozenset({"testing"}),
            requirement="numpy[testing]>=1.23",
        )
        assert edge.name == "numpy"
        assert edge.extras == frozenset({"testing"})
        assert edge.requirement == "numpy[testing]>=1.23"

    def test_defaults(self) -> None:
        edge = DependencyEdge(name="click")
        assert edge.extras == frozenset()
        assert edge.requirement == ""

    def test_frozen(self) -> None:
        edge = DependencyEdge(name="click")
        with pytest.raises(ValidationError):
            edge.name = "other"  # type: ignore[misc]

    def test_json_roundtrip(self) -> None:
        edge = DependencyEdge(
            name="httpx",
            extras=frozenset({"http2"}),
            requirement="httpx[http2]>=0.28",
        )
        data = edge.model_dump(mode="json")
        restored = DependencyEdge.model_validate(data)
        assert restored.name == edge.name
        assert restored.extras == edge.extras
        assert restored.requirement == edge.requirement
