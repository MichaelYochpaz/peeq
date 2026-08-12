"""Dependency solver using the `uv` CLI.

Invokes `uv pip compile` via subprocess for dependency resolution.
Requires the `uv` binary to be installed and detectable on
`$PATH` (or overridden via the `PEEQ_UV_BIN` env var).

Output is requested in `--annotation-style split` format so that
`# via` comments are parsed into forward dependency edges.
"""

from __future__ import annotations

import asyncio
import logging
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name
from packaging.version import Version

from peeq import APP_NAME
from peeq.resolver.base import (
    DependencyResolver,
    ResolutionImpossible,
    UvNotFoundError,
)
from peeq.resolver.models import (
    ResolvedDependency,
    SolverResult,
)
from peeq.resolver.uv_error_parser import _parse_uv_error
from peeq.sanitize import (
    UnsafeRequirementError,
    redact_url_credentials,
    validate_requirement_string,
)

if TYPE_CHECKING:
    from peeq.resolver.models import TargetEnvironment
    from peeq.resolver.provider import PackageProvider

logger = logging.getLogger(__name__)

# Timeout for the uv subprocess (seconds).
_UV_TIMEOUT: int = 120

# Minimum supported uv version.  Below this, peeq raises with an
# upgrade message.  Keep in sync with the version floor in
# [project.optional-dependencies] uv in pyproject.toml.
_MIN_UV_VERSION = Version("0.3.0")

# Module-level cache for the version check (run once per process).
_uv_version_checked: bool = False


def _find_uv() -> str | None:
    """Locate the `uv` binary.

    Checks `PEEQ_UV_BIN` first (explicit override), then falls
    back to `shutil.which("uv")` for PATH discovery.
    """
    explicit = os.environ.get(f"{APP_NAME.upper()}_UV_BIN")
    if explicit:
        return explicit
    return shutil.which("uv")


def _check_uv_version(uv_bin: str) -> None:
    """Verify *uv_bin* meets the minimum version requirement.

    Runs once per process.  Raises `RuntimeError` if below
    the minimum.
    """
    global _uv_version_checked  # noqa: PLW0603
    if _uv_version_checked:
        return

    try:
        result = subprocess.run(  # noqa: S603
            [uv_bin, "--version"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        # Output format: "uv 0.10.10 (8c730aaad 2026-03-13)"
        version_str = result.stdout.strip().split()[1]
        version = Version(version_str)
    except Exception:
        logger.debug("Could not determine uv version, skipping check")
        _uv_version_checked = True
        return

    if version < _MIN_UV_VERSION:
        msg = (
            f"{APP_NAME} requires uv >= {_MIN_UV_VERSION} (found {version}).\n"
            "Update uv: uv self update\n"
            "Full installation guide: https://docs.astral.sh/uv/getting-started/installation/"
        )
        raise RuntimeError(msg)

    _uv_version_checked = True


class UvSolver(DependencyResolver):
    """Dependency solver using the `uv` CLI.

    Requires the `uv` binary (detectable via `$PATH` or
    `$PEEQ_UV_BIN`).  Uses `uv pip compile` to resolve
    dependencies into pinned versions.
    """

    solver_id = "uv"

    def __init__(self, *, provider: PackageProvider) -> None:
        self._provider = provider

    @classmethod
    def available(cls) -> bool:
        """Check if `uv` is installed and detectable."""
        return _find_uv() is not None

    async def resolve(
        self,
        requirements: list[str],
        target_env: TargetEnvironment,
    ) -> SolverResult:
        """Resolve requirements using `uv pip compile`.

        Writes requirements to a temporary file, invokes `uv`, and
        parses the output.
        """
        if not requirements:
            msg = "At least one requirement is required"
            raise UnsafeRequirementError(msg)

        # Validate the complete supported requirement subset before locating
        # or executing uv and before creating a temporary requirements file.
        for requirement in requirements:
            validate_requirement_string(requirement)

        uv_bin = _find_uv()
        if uv_bin is None:
            raise UvNotFoundError

        _check_uv_version(uv_bin)

        with tempfile.TemporaryDirectory() as tmp_dir:
            req_file = Path(tmp_dir) / "requirements.in"
            req_file.write_text("\n".join(requirements) + "\n")

            cmd = self._build_command(uv_bin, req_file, target_env)
            logger.debug("Running uv: %s", " ".join(redact_url_credentials(arg) for arg in cmd))

            # UV_NO_WRAP disables prose line wrapping in uv's error
            # output (a public env var since uv v0.0.5, used by uv's
            # own test suite).  This makes each PubGrub proof clause
            # a single line, simplifying regex extraction in the
            # error parser.
            env = {**os.environ, "UV_NO_WRAP": "1"}

            # Pass custom index URL via environment variable (not CLI
            # argument) to avoid exposing credentials in process listings.
            base_url = self._provider.backend.base_url
            if "pypi.org" not in base_url:
                env["UV_INDEX_URL"] = base_url

            try:
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    env=env,
                )
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(),
                    timeout=_UV_TIMEOUT,
                )
            except (TimeoutError, asyncio.TimeoutError) as exc:
                msg = f"uv subprocess timed out after {_UV_TIMEOUT}s"
                raise ResolutionImpossible(msg) from exc
            except FileNotFoundError as exc:
                raise UvNotFoundError from exc

            if proc.returncode != 0:
                error_text = stderr.decode("utf-8", errors="replace").strip()
                self._handle_error(error_text)

            output = stdout.decode("utf-8", errors="replace")
            return self._parse_output(output)

    def _build_command(
        self,
        uv_bin: str,
        req_file: Path,
        target_env: TargetEnvironment,
    ) -> list[str]:
        """Build the `uv pip compile` command."""
        cmd = [
            uv_bin,
            "pip",
            "compile",
            str(req_file),
            "--no-header",
            "--no-config",
            "--no-build",
            "--no-python-downloads",
            "--annotation-style",
            "split",
            "--color",
            "never",
            "--quiet",
        ]

        # NOTE: Custom index URL is passed via UV_INDEX_URL env var
        # in resolve(), not as a CLI argument.  This prevents credential
        # exposure in process listings (e.g. ps, /proc, Task Manager).

        # Target Python version.
        if target_env.python_version:
            cmd.extend(["--python-version", target_env.python_version])

        # Target platform (uv uses its own naming convention).
        if target_env.sys_platform:
            platform_str = _to_uv_platform(target_env)
            if platform_str:
                cmd.extend(["--python-platform", platform_str])

        # Pre-release policy.
        if self._provider.include_prereleases:
            cmd.append("--prerelease=allow")
        else:
            cmd.append("--prerelease=if-necessary-or-explicit")

        return cmd

    def _parse_output(self, output: str) -> SolverResult:
        """Parse `uv pip compile` annotated output into a `SolverResult`.

        Expects `--annotation-style split` format where `# via`
        comments appear on separate lines below each package::

            click==8.1.7
                # via flask
            markupsafe==3.0.3
                # via
                #   flask
                #   jinja2

        **Pass 1** — collect packages and reverse edges (child → parents).
        **Pass 2** — invert into forward edges and build
        `ResolvedDependency` objects.
        """
        # -- Pass 1: parse packages and reverse edges -----------------------
        packages: dict[str, Version] = {}
        reverse_edges: dict[str, list[str]] = {}
        current_name: str | None = None

        for raw_line in output.strip().splitlines():
            line = raw_line.strip()

            if not line:
                continue

            # Indented line → annotation for the current package.
            if raw_line.startswith((" ", "\t")):
                if current_name is not None:
                    self._collect_annotation(line, current_name, reverse_edges)
                continue

            # Top-level line — skip comments and flags.
            if line.startswith(("#", "-")):
                continue

            # Package specifier line: "name==version"
            try:
                req = Requirement(line)
                name = canonicalize_name(req.name)
                version_str = str(req.specifier).lstrip("=")
                packages[name] = Version(version_str)
                current_name = name
            except Exception:
                logger.debug("Skipping unparseable uv output line: %s", line)
                current_name = None

        # -- Pass 2: invert reverse edges and build result ------------------
        resolved_names = set(packages)

        forward_edges: dict[str, list[str]] = {}
        for child, parents in reverse_edges.items():
            for parent in parents:
                # Only keep parents that exist in the resolved set.
                # This filters pseudo-parents like "-r /tmp/.../requirements.in".
                if parent in resolved_names:
                    forward_edges.setdefault(parent, []).append(child)

        resolved = [
            ResolvedDependency(
                name=name,
                version=version,
                dependencies=sorted(forward_edges.get(name, [])),
            )
            for name, version in packages.items()
        ]
        resolved.sort(key=lambda r: r.name)
        return SolverResult(resolved=resolved, solver_id="uv")

    @staticmethod
    def _collect_annotation(
        line: str,
        current_name: str,
        reverse_edges: dict[str, list[str]],
    ) -> None:
        """Parse a single `# via` annotation line into *reverse_edges*.

        Handles both single-parent (`# via flask`) and multi-parent
        (`#   flask`) forms.  The bare `# via` header (multi-parent
        form) is silently skipped.
        """
        if line == "# via":
            return

        if line.startswith("# via "):
            parent = canonicalize_name(line[6:].strip())
            reverse_edges.setdefault(current_name, []).append(parent)
            return

        if line.startswith("#"):
            parent = canonicalize_name(line.lstrip("#").strip())
            if parent:
                reverse_edges.setdefault(current_name, []).append(parent)

    def _handle_error(self, error_text: str) -> None:
        """Convert uv error output to an appropriate exception.

        Resolution failures (conflicts, missing packages) are routed
        through `_parse_uv_error` for structured extraction.
        Non-resolution errors (auth, network, internal) raise
        `RuntimeError` directly.
        """
        lower = error_text.lower()

        if "no solution" in lower or "conflict" in lower:
            conflicts, summary = _parse_uv_error(error_text)
            raise ResolutionImpossible(summary, conflicts=conflicts)

        if "package not found" in lower or "no versions" in lower:
            conflicts, summary = _parse_uv_error(error_text)
            raise ResolutionImpossible(summary, conflicts=conflicts)

        msg = f"uv pip compile failed: {error_text}"
        raise RuntimeError(msg)


# Specific (sys_platform, platform_machine) -> uv platform triplet.
# Used when both values are available to produce architecture-aware
# resolution (important for ML/AI packages with platform-specific wheels).
_PLATFORM_MAP: dict[tuple[str, str], str] = {
    ("linux", "x86_64"): "x86_64-unknown-linux-gnu",
    ("linux", "aarch64"): "aarch64-unknown-linux-gnu",
    ("darwin", "x86_64"): "x86_64-apple-darwin",
    ("darwin", "arm64"): "aarch64-apple-darwin",  # macOS reports "arm64"
    ("darwin", "aarch64"): "aarch64-apple-darwin",
    ("win32", "x86_64"): "x86_64-pc-windows-msvc",
    ("win32", "AMD64"): "x86_64-pc-windows-msvc",  # Windows reports "AMD64"
    ("win32", "aarch64"): "aarch64-pc-windows-msvc",
    ("win32", "ARM64"): "aarch64-pc-windows-msvc",  # Windows reports "ARM64"
}

# Generic sys_platform -> uv platform.  Used as a fallback when
# platform_machine is not provided or not recognized.
_GENERIC_PLATFORM_MAP: dict[str, str] = {
    "linux": "linux",
    "win32": "windows",
    "darwin": "macos",
}


def _to_uv_platform(target_env: TargetEnvironment) -> str | None:
    """Convert a `TargetEnvironment` to uv's `--python-platform` value.

    When both `sys_platform` and `platform_machine` are available
    and recognized, returns a specific platform triplet (e.g.
    `x86_64-unknown-linux-gnu`) so that uv can distinguish
    architecture-specific wheels.

    Falls back to a generic platform name (`linux`, `windows`,
    `macos`) when `platform_machine` is absent or unrecognized.

    Returns `None` when `sys_platform` itself is unknown.
    """
    if target_env.sys_platform and target_env.platform_machine:
        specific = _PLATFORM_MAP.get((target_env.sys_platform, target_env.platform_machine))
        if specific is not None:
            return specific

    return _GENERIC_PLATFORM_MAP.get(target_env.sys_platform)
