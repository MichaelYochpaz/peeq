"""Tests for the UvSolver backend."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from packaging.specifiers import SpecifierSet

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib  # ty: ignore[unresolved-import]

from peeq.resolver.base import ResolutionImpossible, UvNotFoundError
from peeq.resolver.models import TargetEnvironment
from peeq.resolver.provider import PackageProvider
from peeq.resolver.uv_solver import (
    _MIN_UV_VERSION,
    UvSolver,
    _check_uv_version,
    _find_uv,
    _to_uv_platform,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def mock_provider() -> PackageProvider:
    """Create a minimal mock PackageProvider for UvSolver."""
    mock_cache = MagicMock()
    mock_fetcher = AsyncMock()
    mock_backend = AsyncMock()
    mock_backend.base_url = "https://pypi.org"
    return PackageProvider(
        cache=mock_cache,
        metadata_fetcher=mock_fetcher,
        backend=mock_backend,
        target_env=TargetEnvironment(python_version="3.12"),
    )


# ---------------------------------------------------------------------------
# UvSolver.available()
# ---------------------------------------------------------------------------


class TestAvailable:
    """Tests for UvSolver.available()."""

    def test_available_when_uv_found(self) -> None:
        with patch("peeq.resolver.uv_solver._find_uv", return_value="/usr/bin/uv"):
            assert UvSolver.available() is True

    def test_not_available_when_uv_missing(self) -> None:
        with patch("peeq.resolver.uv_solver._find_uv", return_value=None):
            assert UvSolver.available() is False


# ---------------------------------------------------------------------------
# _find_uv()
# ---------------------------------------------------------------------------


class TestFindUv:
    """Tests for the _find_uv() helper."""

    def test_returns_env_var_when_set(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Return PEEQ_UV_BIN value when the env var is set."""
        monkeypatch.setenv("PEEQ_UV_BIN", "/custom/uv")
        assert _find_uv() == "/custom/uv"


# ---------------------------------------------------------------------------
# _check_uv_version()
# ---------------------------------------------------------------------------


class TestCheckUvVersion:
    """Tests for the _check_uv_version() helper."""

    def test_below_minimum_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Raise RuntimeError when uv version is below minimum."""
        monkeypatch.setattr("peeq.resolver.uv_solver._uv_version_checked", False)
        mock_result = MagicMock()
        mock_result.stdout = "uv 0.2.0 (abc123 2024-01-01)"
        with (
            patch("subprocess.run", return_value=mock_result),
            pytest.raises(RuntimeError, match=r"uv >= 0\.3\.0"),
        ):
            _check_uv_version("/usr/bin/uv")

    def test_above_minimum_succeeds(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """No error when uv version meets the minimum."""
        monkeypatch.setattr("peeq.resolver.uv_solver._uv_version_checked", False)
        mock_result = MagicMock()
        mock_result.stdout = "uv 99.0.0 (abc123 2026-01-01)"
        with patch("subprocess.run", return_value=mock_result):
            _check_uv_version("/usr/bin/uv")  # Should not raise

    def test_parse_failure_skips_silently(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Skip version check without crashing when output is unparseable."""
        monkeypatch.setattr("peeq.resolver.uv_solver._uv_version_checked", False)
        with patch("subprocess.run", side_effect=OSError("spawn failed")):
            _check_uv_version("/usr/bin/uv")  # Should not raise


# ---------------------------------------------------------------------------
# Output parsing
# ---------------------------------------------------------------------------


class TestParseOutput:
    """Tests for UvSolver._parse_output() with annotated split format."""

    def test_single_parent_annotation(self, mock_provider: PackageProvider) -> None:
        """Single `# via <parent>` annotation populates forward edges."""
        solver = UvSolver(provider=mock_provider)
        output = (
            "click==8.1.7\n"
            "    # via flask\n"
            "flask==3.0.0\n"
            "    # via -r /tmp/abc123/requirements.in\n"
        )
        result = solver._parse_output(output)
        deps = {r.name: r.dependencies for r in result.resolved}
        # flask -> click (forward edge derived from "click via flask")
        assert deps["flask"] == ["click"]
        # click has no children
        assert deps["click"] == []

    def test_multi_parent_annotation(self, mock_provider: PackageProvider) -> None:
        """Multi-parent `# via` block produces reverse edges from each parent."""
        solver = UvSolver(provider=mock_provider)
        output = (
            "flask==3.0.0\n"
            "    # via -r /tmp/abc123/requirements.in\n"
            "jinja2==3.1.6\n"
            "    # via flask\n"
            "markupsafe==3.0.3\n"
            "    # via\n"
            "    #   flask\n"
            "    #   jinja2\n"
            "werkzeug==3.0.1\n"
            "    # via flask\n"
        )
        result = solver._parse_output(output)
        deps = {r.name: r.dependencies for r in result.resolved}
        # flask depends on jinja2, markupsafe, and werkzeug
        assert deps["flask"] == ["jinja2", "markupsafe", "werkzeug"]
        # jinja2 depends on markupsafe
        assert deps["jinja2"] == ["markupsafe"]
        # leaf nodes
        assert deps["markupsafe"] == []
        assert deps["werkzeug"] == []

    def test_root_requirements_filtered(self, mock_provider: PackageProvider) -> None:
        """`# via -r <path>` pseudo-parents are filtered out."""
        solver = UvSolver(provider=mock_provider)
        output = "flask==3.0.0\n    # via -r /tmp/abc123/requirements.in\n"
        result = solver._parse_output(output)
        assert len(result.resolved) == 1
        assert result.resolved[0].dependencies == []

    def test_no_annotations(self, mock_provider: PackageProvider) -> None:
        """Packages without `# via` annotations get empty dependencies."""
        solver = UvSolver(provider=mock_provider)
        output = "flask==3.0.0\nclick==8.1.7\n"
        result = solver._parse_output(output)
        for dep in result.resolved:
            assert dep.dependencies == []

    def test_mixed_roots_and_children(self, mock_provider: PackageProvider) -> None:
        """Some packages are roots (`-r` parent), some have real parents."""
        solver = UvSolver(provider=mock_provider)
        output = (
            "click==8.1.7\n"
            "    # via flask\n"
            "flask==3.0.0\n"
            "    # via -r /tmp/req.in\n"
            "itsdangerous==2.2.0\n"
            "    # via flask\n"
            "jinja2==3.1.6\n"
            "    # via flask\n"
            "markupsafe==3.0.3\n"
            "    # via jinja2\n"
            "werkzeug==3.1.3\n"
            "    # via flask\n"
        )
        result = solver._parse_output(output)
        deps = {r.name: r.dependencies for r in result.resolved}
        # flask is the root — depends on click, itsdangerous, jinja2, werkzeug
        assert deps["flask"] == ["click", "itsdangerous", "jinja2", "werkzeug"]
        # jinja2 depends on markupsafe
        assert deps["jinja2"] == ["markupsafe"]
        # Leaf nodes have no dependencies
        assert deps["click"] == []
        assert deps["itsdangerous"] == []
        assert deps["markupsafe"] == []
        assert deps["werkzeug"] == []

    def test_empty_output(self, mock_provider: PackageProvider) -> None:
        solver = UvSolver(provider=mock_provider)
        result = solver._parse_output("")
        assert result.resolved == []

    def test_result_sorted_by_name(self, mock_provider: PackageProvider) -> None:
        solver = UvSolver(provider=mock_provider)
        output = "zebra==1.0.0\napple==2.0.0\nmango==3.0.0\n"
        result = solver._parse_output(output)
        names = [r.name for r in result.resolved]
        assert names == ["apple", "mango", "zebra"]

    def test_ignores_comments_and_flags(self, mock_provider: PackageProvider) -> None:
        """Top-level comments and flag lines are skipped."""
        solver = UvSolver(provider=mock_provider)
        output = (
            "# This is a comment\n--index-url https://pypi.org/simple\nflask==3.0.0\n"
        )
        result = solver._parse_output(output)
        assert len(result.resolved) == 1
        assert result.resolved[0].name == "flask"

    def test_ignores_blank_lines(self, mock_provider: PackageProvider) -> None:
        solver = UvSolver(provider=mock_provider)
        output = "flask==3.0.0\n\n\nclick==8.0.0\n"
        result = solver._parse_output(output)
        assert len(result.resolved) == 2

    def test_skips_unparseable_lines(self, mock_provider: PackageProvider) -> None:
        solver = UvSolver(provider=mock_provider)
        output = "flask==3.0.0\nnot-a-valid-line!!!\nclick==8.0.0\n"
        result = solver._parse_output(output)
        names = {r.name for r in result.resolved}
        assert "flask" in names
        assert "click" in names

    def test_normalizes_names(self, mock_provider: PackageProvider) -> None:
        solver = UvSolver(provider=mock_provider)
        output = "Flask==3.0.0\nPyYAML==6.0.0\n"
        result = solver._parse_output(output)
        names = {r.name for r in result.resolved}
        assert "flask" in names
        assert "pyyaml" in names

    def test_solver_id(self, mock_provider: PackageProvider) -> None:
        solver = UvSolver(provider=mock_provider)
        output = "flask==3.0.0\n"
        result = solver._parse_output(output)
        assert result.solver_id == "uv"

    def test_dependencies_sorted(self, mock_provider: PackageProvider) -> None:
        """Forward edges are sorted alphabetically."""
        solver = UvSolver(provider=mock_provider)
        output = (
            "zebra==1.0.0\n"
            "    # via root\n"
            "apple==2.0.0\n"
            "    # via root\n"
            "mango==3.0.0\n"
            "    # via root\n"
            "root==1.0.0\n"
            "    # via -r /tmp/req.in\n"
        )
        result = solver._parse_output(output)
        deps = {r.name: r.dependencies for r in result.resolved}
        assert deps["root"] == ["apple", "mango", "zebra"]


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------


class TestHandleError:
    """Tests for UvSolver._handle_error()."""

    def test_conflict_error(self, mock_provider: PackageProvider) -> None:
        solver = UvSolver(provider=mock_provider)
        with pytest.raises(ResolutionImpossible):
            solver._handle_error("No solution found: conflict between a and b")

    def test_no_versions_error(self, mock_provider: PackageProvider) -> None:
        solver = UvSolver(provider=mock_provider)
        with pytest.raises(ResolutionImpossible):
            solver._handle_error("No versions found for nonexistent-package")

    def test_package_not_found(self, mock_provider: PackageProvider) -> None:
        solver = UvSolver(provider=mock_provider)
        with pytest.raises(ResolutionImpossible):
            solver._handle_error("Package not found: foobar")

    def test_generic_error(self, mock_provider: PackageProvider) -> None:
        solver = UvSolver(provider=mock_provider)
        with pytest.raises(RuntimeError, match="uv pip compile failed"):
            solver._handle_error("Some unknown error")


# ---------------------------------------------------------------------------
# Command building
# ---------------------------------------------------------------------------


class TestBuildCommand:
    """Tests for UvSolver._build_command()."""

    def test_basic_command(
        self, mock_provider: PackageProvider, tmp_path: Path
    ) -> None:
        solver = UvSolver(provider=mock_provider)

        req_file = tmp_path / "requirements.in"
        cmd = solver._build_command(
            "uv",
            req_file,
            TargetEnvironment(python_version="3.12"),
        )
        assert cmd[0] == "uv"
        assert "pip" in cmd
        assert "compile" in cmd
        assert "--no-header" in cmd
        assert "--no-config" in cmd
        assert "--annotation-style" in cmd
        assert cmd[cmd.index("--annotation-style") + 1] == "split"
        assert "--color" in cmd
        assert cmd[cmd.index("--color") + 1] == "never"
        assert "--quiet" in cmd
        assert "--no-annotate" not in cmd
        assert str(req_file) in cmd

    def test_custom_index_not_in_args(self, tmp_path: Path) -> None:
        """Index URL must not appear in CLI args (credential exposure)."""
        mock_cache = MagicMock()
        mock_fetcher = AsyncMock()
        mock_backend = AsyncMock()
        mock_backend.base_url = "https://private.registry.com"
        provider = PackageProvider(
            cache=mock_cache,
            metadata_fetcher=mock_fetcher,
            backend=mock_backend,
            target_env=TargetEnvironment(),
        )
        solver = UvSolver(provider=provider)

        req_file = tmp_path / "requirements.in"
        cmd = solver._build_command("uv", req_file, TargetEnvironment())
        assert "--default-index" not in cmd
        assert "--index-url" not in cmd
        assert "https://private.registry.com" not in cmd

    def test_python_version_flag(
        self, mock_provider: PackageProvider, tmp_path: Path
    ) -> None:
        solver = UvSolver(provider=mock_provider)

        req_file = tmp_path / "requirements.in"
        cmd = solver._build_command(
            "uv",
            req_file,
            TargetEnvironment(python_version="3.11"),
        )
        idx = cmd.index("--python-version")
        assert cmd[idx + 1] == "3.11"

    def test_platform_flag(
        self, mock_provider: PackageProvider, tmp_path: Path
    ) -> None:
        solver = UvSolver(provider=mock_provider)

        req_file = tmp_path / "requirements.in"
        cmd = solver._build_command(
            "uv",
            req_file,
            TargetEnvironment(sys_platform="linux"),
        )
        idx = cmd.index("--python-platform")
        assert cmd[idx + 1] == "linux"

    def test_prerelease_allow_flag(self, tmp_path: Path) -> None:
        """Include --prerelease=allow when prereleases are enabled."""
        mock_cache = MagicMock()
        mock_fetcher = AsyncMock()
        mock_backend = AsyncMock()
        mock_backend.base_url = "https://pypi.org"
        provider = PackageProvider(
            cache=mock_cache,
            metadata_fetcher=mock_fetcher,
            backend=mock_backend,
            target_env=TargetEnvironment(python_version="3.12"),
            include_prereleases=True,
        )
        solver = UvSolver(provider=provider)

        req_file = tmp_path / "requirements.in"
        cmd = solver._build_command(
            "uv",
            req_file,
            TargetEnvironment(python_version="3.12"),
        )
        assert "--prerelease=allow" in cmd

    def test_prerelease_default_flag(
        self, mock_provider: PackageProvider, tmp_path: Path
    ) -> None:
        """Include --prerelease=if-necessary-or-explicit by default."""
        solver = UvSolver(provider=mock_provider)

        req_file = tmp_path / "requirements.in"
        cmd = solver._build_command(
            "uv",
            req_file,
            TargetEnvironment(python_version="3.12"),
        )
        assert "--prerelease=if-necessary-or-explicit" in cmd
        assert "--prerelease=allow" not in cmd


# ---------------------------------------------------------------------------
# UvSolver.resolve()
# ---------------------------------------------------------------------------


class TestResolve:
    """Tests for UvSolver.resolve()."""

    async def test_successful_resolution(
        self,
        mock_provider: PackageProvider,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Return SolverResult when uv exits with return code 0."""
        monkeypatch.setattr("peeq.resolver.uv_solver._uv_version_checked", True)
        solver = UvSolver(provider=mock_provider)
        stdout = (
            b"click==8.1.7\n"
            b"    # via flask\n"
            b"flask==3.0.0\n"
            b"    # via -r /tmp/requirements.in\n"
        )

        mock_proc = AsyncMock()
        mock_proc.returncode = 0
        mock_proc.communicate.return_value = (stdout, b"")

        with (
            patch("peeq.resolver.uv_solver._find_uv", return_value="/usr/bin/uv"),
            patch(
                "asyncio.create_subprocess_exec",
                new_callable=AsyncMock,
                return_value=mock_proc,
            ),
        ):
            result = await solver.resolve(
                ["flask"], TargetEnvironment(python_version="3.12")
            )

        assert result.solver_id == "uv"
        names = {r.name for r in result.resolved}
        assert "flask" in names
        assert "click" in names
        deps = {r.name: r.dependencies for r in result.resolved}
        assert deps["flask"] == ["click"]

    async def test_resolution_conflict(
        self,
        mock_provider: PackageProvider,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Raise ResolutionImpossible when uv reports a conflict."""
        monkeypatch.setattr("peeq.resolver.uv_solver._uv_version_checked", True)
        solver = UvSolver(provider=mock_provider)

        mock_proc = AsyncMock()
        mock_proc.returncode = 1
        mock_proc.communicate.return_value = (
            b"",
            b"error: No solution found when resolving: conflict between a and b",
        )

        with (
            patch("peeq.resolver.uv_solver._find_uv", return_value="/usr/bin/uv"),
            patch(
                "asyncio.create_subprocess_exec",
                new_callable=AsyncMock,
                return_value=mock_proc,
            ),
            pytest.raises(ResolutionImpossible),
        ):
            await solver.resolve(["a", "b"], TargetEnvironment(python_version="3.12"))

    async def test_subprocess_timeout(
        self,
        mock_provider: PackageProvider,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Raise ResolutionImpossible when subprocess exceeds timeout."""
        monkeypatch.setattr("peeq.resolver.uv_solver._uv_version_checked", True)
        solver = UvSolver(provider=mock_provider)

        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(side_effect=asyncio.TimeoutError)

        with (
            patch("peeq.resolver.uv_solver._find_uv", return_value="/usr/bin/uv"),
            patch(
                "asyncio.create_subprocess_exec",
                new_callable=AsyncMock,
                return_value=mock_proc,
            ),
            pytest.raises(ResolutionImpossible, match="timed out"),
        ):
            await solver.resolve(["flask"], TargetEnvironment(python_version="3.12"))

    async def test_custom_index_via_env_var(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Pass custom index URL via UV_INDEX_URL env var, not CLI args."""
        monkeypatch.setattr("peeq.resolver.uv_solver._uv_version_checked", True)

        mock_cache = MagicMock()
        mock_fetcher = AsyncMock()
        mock_backend = AsyncMock()
        mock_backend.base_url = "https://user:token@private.registry.com/simple/"
        provider = PackageProvider(
            cache=mock_cache,
            metadata_fetcher=mock_fetcher,
            backend=mock_backend,
            target_env=TargetEnvironment(),
        )
        solver = UvSolver(provider=provider)

        stdout = b"flask==3.0.0\n    # via -r /tmp/requirements.in\n"
        mock_proc = AsyncMock()
        mock_proc.returncode = 0
        mock_proc.communicate.return_value = (stdout, b"")

        with (
            patch("peeq.resolver.uv_solver._find_uv", return_value="/usr/bin/uv"),
            patch(
                "asyncio.create_subprocess_exec",
                new_callable=AsyncMock,
                return_value=mock_proc,
            ) as mock_exec,
        ):
            await solver.resolve(["flask"], TargetEnvironment())

        # URL must not appear in CLI args (prevents credential exposure via ps).
        args = mock_exec.call_args.args
        for arg in args:
            assert "@" not in str(arg), f"Credentials leaked in CLI arg: {arg}"

        # URL must be in the env dict.
        env = mock_exec.call_args.kwargs["env"]
        assert env["UV_INDEX_URL"] == (
            "https://user:token@private.registry.com/simple/"
        )

    async def test_binary_not_found(
        self,
        mock_provider: PackageProvider,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Raise UvNotFoundError when uv binary is not found at exec time."""
        monkeypatch.setattr("peeq.resolver.uv_solver._uv_version_checked", True)
        solver = UvSolver(provider=mock_provider)

        with (
            patch("peeq.resolver.uv_solver._find_uv", return_value="/usr/bin/uv"),
            patch(
                "asyncio.create_subprocess_exec",
                new_callable=AsyncMock,
                side_effect=FileNotFoundError("uv not found"),
            ),
            pytest.raises(UvNotFoundError, match="uv is required"),
        ):
            await solver.resolve(["flask"], TargetEnvironment(python_version="3.12"))


# ---------------------------------------------------------------------------
# Platform mapping
# ---------------------------------------------------------------------------


class TestToUvPlatform:
    """Tests for the _to_uv_platform() helper."""

    # -- Specific triplets (sys_platform + platform_machine) ----------------

    @pytest.mark.parametrize(
        ("sys_platform", "platform_machine", "expected"),
        [
            ("linux", "x86_64", "x86_64-unknown-linux-gnu"),
            ("linux", "aarch64", "aarch64-unknown-linux-gnu"),
            ("darwin", "x86_64", "x86_64-apple-darwin"),
            ("darwin", "arm64", "aarch64-apple-darwin"),
            ("darwin", "aarch64", "aarch64-apple-darwin"),
            ("win32", "AMD64", "x86_64-pc-windows-msvc"),
            ("win32", "x86_64", "x86_64-pc-windows-msvc"),
            ("win32", "ARM64", "aarch64-pc-windows-msvc"),
            ("win32", "aarch64", "aarch64-pc-windows-msvc"),
        ],
        ids=[
            "linux-x86_64",
            "linux-aarch64",
            "macos-x86_64",
            "macos-arm64",
            "macos-aarch64",
            "windows-AMD64",
            "windows-x86_64",
            "windows-ARM64",
            "windows-aarch64",
        ],
    )
    def test_specific_triplet(
        self, sys_platform: str, platform_machine: str, expected: str
    ) -> None:
        env = TargetEnvironment(
            sys_platform=sys_platform, platform_machine=platform_machine
        )
        assert _to_uv_platform(env) == expected

    # -- Generic fallback (sys_platform only) -------------------------------

    @pytest.mark.parametrize(
        ("sys_platform", "platform_machine", "expected"),
        [
            ("linux", None, "linux"),
            ("win32", None, "windows"),
            ("darwin", None, "macos"),
            ("linux", "sparc64", "linux"),
        ],
        ids=[
            "linux-generic",
            "windows-generic",
            "macos-generic",
            "unrecognized-machine-falls-back",
        ],
    )
    def test_generic_fallback(
        self, sys_platform: str, platform_machine: str | None, expected: str
    ) -> None:
        env = TargetEnvironment(
            sys_platform=sys_platform,
            **({"platform_machine": platform_machine} if platform_machine else {}),
        )
        assert _to_uv_platform(env) == expected

    # -- None/empty cases ---------------------------------------------------

    @pytest.mark.parametrize(
        ("sys_platform", "expected"),
        [
            ("freebsd", None),
            (None, None),
        ],
        ids=[
            "unknown-platform",
            "empty-platform",
        ],
    )
    def test_returns_none(self, sys_platform: str | None, expected: None) -> None:
        env = TargetEnvironment(
            **({"sys_platform": sys_platform} if sys_platform else {})
        )
        assert _to_uv_platform(env) is expected


# ---------------------------------------------------------------------------
# _MIN_UV_VERSION / pyproject.toml sync
# ---------------------------------------------------------------------------


class TestMinUvVersionSync:
    """Verify _MIN_UV_VERSION stays in sync with pyproject.toml."""

    def test_min_version_matches_pyproject(self) -> None:
        """_MIN_UV_VERSION must match the uv floor in [project.optional-dependencies]."""
        pyproject_path = Path(__file__).resolve().parents[2] / "pyproject.toml"
        with pyproject_path.open("rb") as f:
            pyproject = tomllib.load(f)

        uv_deps = pyproject["project"]["optional-dependencies"]["uv"]
        # Extract the specifier from the first (and only) entry, e.g. "uv>=0.4"
        assert len(uv_deps) == 1, "Expected exactly one uv optional dependency"
        spec = SpecifierSet(uv_deps[0].removeprefix("uv"))

        assert str(_MIN_UV_VERSION) in spec, (
            f"_MIN_UV_VERSION ({_MIN_UV_VERSION}) is not satisfied by "
            f"pyproject.toml uv floor ({uv_deps[0]})"
        )
