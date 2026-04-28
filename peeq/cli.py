"""Command-line interface for peeq.

Entry point for `pyproject.toml`::

    [project.scripts]
    peeq = "peeq.cli:main"

Uses Cyclopts with a meta app for global options (`--format`,
`--no-cache`, `--index-url`, `--backend`).  All package commands
are async --- Cyclopts manages the event loop automatically.
"""

from __future__ import annotations

import logging
import tempfile
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Annotated

from cyclopts import App, Group, Parameter
from cyclopts.exceptions import CycloptsError
from pydantic import ByteSize, TypeAdapter

from peeq import APP_NAME, __version__
from peeq.output.base import (
    OutputFormat,
    build_ls_entries,
    format_size,
    has_prefix,
    truncate_utf8,
    try_decode,
)

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from peeq.output.base import Renderer
    from peeq.resolver.models import TargetEnvironment
    from peeq.service import PackageService

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------

app = App(
    name=APP_NAME,
    help=(
        "Investigate Python package metadata, dependencies, and known vulnerabilities.\n\n"
        f"If you are an AI agent, run '{APP_NAME} skill show' for usage instructions optimized for AI agents."
    ),
    # Disable built-in --version flag to avoid collision with subcommand
    # --version parameters. Handled manually in the launcher instead.
    version_flags=[],
)

cache_app = App(name="cache", help="Cache management commands.")
app.command(cache_app)

config_app = App(name="config", help="Configuration commands.")
app.command(config_app)

skill_app = App(name="skill", help="Agent skill commands.")
app.command(skill_app)

# Place global options in their own help-page group
app.meta.group_parameters = Group("Global Options", sort_key=0)
app["--help"].group = "Global Options"

# ---------------------------------------------------------------------------
# Session state (populated by meta launcher, consumed by commands)
# ---------------------------------------------------------------------------


@dataclass
class _SessionState:
    """Mutable session state shared between meta launcher and commands."""

    output_format: OutputFormat | None = None
    no_cache: bool = False
    index_url: str | None = None
    backend_type: str | None = None


_state = _SessionState()

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _get_renderer() -> Renderer:
    """Create a renderer based on the current session state."""
    from peeq.output import get_renderer  # noqa: PLC0415

    return get_renderer(_state.output_format)


@asynccontextmanager
async def _open_service() -> AsyncIterator[PackageService]:
    """Create and yield a `PackageService` with an active backend.

    When `--no-cache` is set, use a temporary directory that is
    discarded after the command completes.
    """
    from peeq.backends import get_backend  # noqa: PLC0415
    from peeq.cache import CacheManager  # noqa: PLC0415
    from peeq.service import PackageService as _Svc  # noqa: PLC0415

    backend = get_backend(_state.index_url, backend_type=_state.backend_type)

    if _state.no_cache:
        with tempfile.TemporaryDirectory() as tmp:
            cache = CacheManager(Path(tmp))
            async with backend:
                yield _Svc(cache=cache, backend=backend)
    else:
        cache = CacheManager.default()
        async with backend:
            try:
                yield _Svc(cache=cache, backend=backend)
            finally:
                cache.maybe_evict()


async def _resolve_version(
    service: PackageService,
    package: str,
    version: str | None,
) -> str | None:
    """Resolve a version string, defaulting to latest if *version* is `None`.

    The literal string `"latest"` (case-insensitive) is treated the same
    as `None` — i.e. it resolves to the newest published version.

    Return `None` if the package does not exist on the registry.
    """
    if version is not None and version.lower() != "latest":
        return version

    info = await service.check(package)
    if info is None:
        return None
    return str(info.latest_version)


async def _render_version_hint(
    service: PackageService,
    renderer: Renderer,
    package: str,
) -> None:
    """Show the latest version and a `peeq versions` suggestion.

    Called from error handlers when a user-specified version has no
    downloadable distribution file.  `service.check()` is cached after
    the first call, so this adds negligible overhead.
    """
    info = await service.check(package)
    if info is not None:
        renderer.render_error(
            f"Latest version: {info.latest_version}. "
            f"Run '{APP_NAME} versions {package}' to see all available versions."
        )


def _build_target_env(
    *,
    python: str | None = None,
    platform: str | None = None,
) -> TargetEnvironment:
    """Build a `TargetEnvironment` from CLI flags.

    When both flags are `None`, return the current host environment.
    """
    from peeq.resolver.models import TargetEnvironment  # noqa: PLC0415

    kwargs: dict[str, str] = {}
    if python:
        kwargs["python_version"] = python
    if platform:
        kwargs["sys_platform"] = platform
        # Infer os_name from sys_platform
        if platform == "win32":
            kwargs["os_name"] = "nt"
        elif platform in ("linux", "darwin"):
            kwargs["os_name"] = "posix"

    if kwargs:
        return TargetEnvironment(**kwargs)
    return TargetEnvironment.current()


_DEFAULT_VERSION_LIMIT: int = 20
"""Default maximum number of versions to show in `info` and `versions`."""

_DEFAULT_LS_LIMIT: int = 50
"""Default maximum number of entries to show in directory listings."""

_DEFAULT_CAT_MAX_BYTES: int = 131_072  # 128 KiB
"""Default maximum bytes of text content to show from `cat`."""

_DURATION_SUFFIXES: dict[str, int] = {"s": 1, "m": 60, "h": 3600, "d": 86400}


def _parse_duration(value: str) -> int:
    """Parse a duration string (e.g., `"30d"`, `"2h"`) to seconds.

    Supported suffixes: `s` (seconds), `m` (minutes), `h` (hours),
    `d` (days).

    Raises:
        ValueError: If *value* is empty, has an unknown suffix, or a non-integer amount.
    """
    if not value:
        msg = "Duration cannot be empty"
        raise ValueError(msg)

    suffix = value[-1].lower()
    if suffix not in _DURATION_SUFFIXES:
        msg = f"Unknown duration suffix {suffix!r}. Use s, m, h, or d"
        raise ValueError(msg)

    try:
        amount = int(value[:-1])
    except ValueError:
        msg = f"Invalid duration: {value!r}"
        raise ValueError(msg) from None

    if amount < 0:
        msg = f"Duration must be positive, got {amount}"
        raise ValueError(msg)

    return amount * _DURATION_SUFFIXES[suffix]


_BYTE_SIZE_ADAPTER: TypeAdapter[ByteSize] = TypeAdapter(ByteSize)
"""Module-level adapter for parsing byte-size strings like `128KiB`."""


def _parse_byte_size(type_: type, tokens: list) -> int:  # noqa: ARG001
    """Parse a byte-size string (e.g. `128KiB`, `1MB`) into an `int`.

    Used as a cyclopts converter for the `--max-bytes` parameter.
    Cyclopts passes `Token` objects whose `.value` holds the
    raw CLI string.
    """
    raw = tokens[0].value if hasattr(tokens[0], "value") else tokens[0]
    return int(_BYTE_SIZE_ADAPTER.validate_python(raw))


# ---------------------------------------------------------------------------
# Meta app (global options)
# ---------------------------------------------------------------------------


@app.meta.default
def launcher(
    *tokens: Annotated[str, Parameter(show=False, allow_leading_hyphen=True)],
    fmt: Annotated[
        OutputFormat | None,
        Parameter(
            name=["--format", "-f"],
            help="Output format: pretty, plain, agent, json. Auto-detected by default.",
        ),
    ] = None,
    no_cache: Annotated[
        bool,
        Parameter(
            name="--no-cache",
            negative="",
            show_default=False,
            help="Bypass cache entirely (don't read or write).",
        ),
    ] = False,
    index_url: Annotated[
        str | None,
        Parameter(
            name=["--index-url", "-i"],
            help="Package index URL. Defaults to https://pypi.org.",
        ),
    ] = None,
    backend: Annotated[
        str | None,
        Parameter(
            name="--backend",
            help="Backend type override: pypi, simple.",
        ),
    ] = None,
    verbose: Annotated[
        bool,
        Parameter(
            name=["--verbose", "-v"],
            negative="",
            show_default=False,
            help="Enable verbose logging.",
        ),
    ] = False,
) -> None:
    """Investigate Python package metadata, dependencies, and known vulnerabilities."""
    if verbose:
        logging.basicConfig(
            level=logging.DEBUG,
            format="%(name)s: %(message)s",
        )

    _state.output_format = fmt
    _state.no_cache = no_cache
    _state.index_url = index_url
    _state.backend_type = backend

    # Handle --version at the base level only. Subcommands define their
    # own --version parameter for specifying a package version, so the
    # built-in cyclopts version flag is disabled (version_flags=[]) and
    # we check for it here before dispatching to subcommands.
    if tokens == ("--version",):
        print(f"{APP_NAME} {__version__}")  # noqa: T201
        return

    # Dispatch to the matched subcommand.  When a bare subcommand name
    # is given without any arguments (e.g. `peeq show`), show its
    # help page instead of printing a "missing argument" error.
    try:
        app(tokens, exit_on_error=False, print_error=False)
    except CycloptsError:
        if len(tokens) == 1 and not tokens[0].startswith("-") and tokens[0] in app:
            app((*tokens, "--help"))
            return
        # Not a bare subcommand — re-dispatch with default error handling.
        app(tokens)


# ---------------------------------------------------------------------------
# Package commands
# ---------------------------------------------------------------------------


@app.command
async def info(  # noqa: PLR0913
    package: Annotated[str, Parameter(help="Package name.")],
    *,
    versions: Annotated[
        bool,
        Parameter(
            name="--versions",
            show_default=False,
            help="Include version list in the report.",
        ),
    ] = False,
    vulns: Annotated[
        bool,
        Parameter(
            name="--vulns",
            show_default=False,
            help="Include vulnerability scan (queries OSV database).",
        ),
    ] = False,
    deps: Annotated[
        bool,
        Parameter(
            name="--deps",
            show_default=False,
            help="Include dependency list.",
        ),
    ] = False,
    full: Annotated[
        bool,
        Parameter(
            name="--full",
            show_default=False,
            help="Include all optional sections (versions, vulnerabilities, dependencies).",
        ),
    ] = False,
    version: Annotated[
        str | None,
        Parameter(
            name="--version",
            help="Target version for deps/vulns sections. Defaults to latest.",
        ),
    ] = None,
    limit: Annotated[
        int | None,
        Parameter(
            name="--limit",
            help="Maximum number of versions to show.",
        ),
    ] = _DEFAULT_VERSION_LIMIT,
) -> None:
    """Show package info with optional report sections.

    Displays basic package information by default. Use flags to include
    additional sections: version history, vulnerability scan, and
    dependency list.
    """
    renderer = _get_renderer()

    # Reject no-op flag combinations
    if version is not None and not (deps or vulns or full):
        renderer.render_error("--version requires --deps, --vulns, or --full")
        raise SystemExit(1)

    if limit != _DEFAULT_VERSION_LIMIT and not (versions or full):
        renderer.render_error("--limit requires --versions or --full")
        raise SystemExit(1)

    async with _open_service() as service:
        try:
            report = await service.info(
                package,
                include_versions=versions or full,
                include_vulns=vulns or full,
                include_deps=deps or full,
                target_version=version,
                version_limit=limit,
            )
        except Exception as exc:
            renderer.render_error(str(exc))
            raise SystemExit(1) from None

    if report is None:
        renderer.render_not_found(package)
        raise SystemExit(1)

    renderer.render_info(report)


@app.command
async def versions(  # noqa: PLR0913
    package: Annotated[str, Parameter(help="Package name.")],
    *,
    limit: Annotated[
        int | None,
        Parameter(
            name="--limit",
            help="Maximum number of versions to show.",
        ),
    ] = _DEFAULT_VERSION_LIMIT,
    show_all: Annotated[
        bool,
        Parameter(
            name="--all",
            help="Show all versions (no limit).",
        ),
    ] = False,
    yanked: Annotated[
        bool,
        Parameter(
            name="--yanked",
            show_default=False,
            help="Show only yanked versions with their reasons.",
        ),
    ] = False,
    matching: Annotated[
        str | None,
        Parameter(
            name="--matching",
            help='PEP 440 specifier to filter versions (e.g., ">=8.0.0,<31").',
        ),
    ] = None,
    pre: Annotated[
        bool,
        Parameter(
            name=["--pre", "--prerelease"],
            show_default=False,
            help="Include pre-release versions in --matching filter.",
        ),
    ] = False,
) -> None:
    """List all available versions of a package."""
    renderer = _get_renderer()

    # Validate flag conflicts
    if show_all and limit != _DEFAULT_VERSION_LIMIT:
        renderer.render_error("--all and --limit cannot be used together")
        raise SystemExit(1)

    if limit is not None and limit < 0:
        renderer.render_error("--limit must be non-negative")
        raise SystemExit(1)

    if show_all:
        limit = None

    if pre and not matching:
        renderer.render_error("--pre requires --matching")
        raise SystemExit(1)

    async with _open_service() as service:
        try:
            all_versions = await service.versions(package)
        except Exception as exc:
            renderer.render_error(str(exc))
            raise SystemExit(1) from None

    if yanked:
        all_versions = [v for v in all_versions if v.yanked]

    if not all_versions:
        if yanked:
            renderer.render_error(f"No yanked versions found for {package}.")
        else:
            renderer.render_not_found(package)
        raise SystemExit(1)

    original_total: int | None = None
    if matching:
        from packaging.specifiers import InvalidSpecifier, SpecifierSet  # noqa: PLC0415

        try:
            spec = SpecifierSet(matching)
        except InvalidSpecifier as exc:
            renderer.render_error(f"Invalid specifier: {exc}")
            raise SystemExit(1) from None
        original_total = len(all_versions)
        matched = set(
            spec.filter(
                (v.version for v in all_versions),
                prereleases=True if pre else None,
            )
        )
        all_versions = [v for v in all_versions if v.version in matched]

    if not all_versions and matching:
        renderer.render_error(f"No versions of {package} match {matching}")
        raise SystemExit(1)

    total = len(all_versions)
    display = all_versions[:limit] if limit is not None else all_versions
    renderer.render_versions(
        package,
        display,
        total,
        matching=matching,
        original_total=original_total,
    )


@app.command
async def deps(  # noqa: C901, PLR0912, PLR0915
    package: Annotated[str, Parameter(help="Package name.")],
    *,
    version: Annotated[
        str | None,
        Parameter(
            name="--version",
            help="Specific version. Defaults to latest.",
        ),
    ] = None,
    tag: Annotated[
        str | None,
        Parameter(
            name="--tag",
            help=(
                "Wheel tag for platform-specific metadata "
                "(e.g., cp312-cp312-win_amd64)."
            ),
        ),
    ] = None,
    diff: Annotated[
        str | None,
        Parameter(
            name="--diff",
            help="Compare dependencies against this version.",
        ),
    ] = None,
) -> None:
    """Show package dependencies."""
    from peeq.service import TagNotFoundError  # noqa: PLC0415

    renderer = _get_renderer()

    # --diff requires --version to establish a base
    if diff is not None and version is None:
        renderer.render_error("--diff requires --version")
        raise SystemExit(1)

    async with _open_service() as service:
        resolved_version = await _resolve_version(service, package, version)
        if resolved_version is None:
            renderer.render_not_found(package)
            raise SystemExit(1)

        # -- Diff mode ------------------------------------------------------
        if diff is not None:
            diff_version = await _resolve_version(service, package, diff)
            if diff_version is None:
                renderer.render_not_found(package)
                raise SystemExit(1)

            try:
                base_meta = await service.get_metadata(
                    package, resolved_version, tag=tag
                )
                target_meta = await service.get_metadata(package, diff_version, tag=tag)
            except TagNotFoundError as exc:
                renderer.render_error(str(exc))
                if exc.available_tags:
                    renderer.render_error(
                        f"Available tags: {', '.join(sorted(exc.available_tags))}"
                    )
                raise SystemExit(1) from None
            except Exception as exc:
                renderer.render_error(str(exc))
                raise SystemExit(1) from None

            if base_meta is None or base_meta.dependencies is None:
                renderer.render_error(
                    f"Cannot diff: dependencies for {package}=={resolved_version} "
                    "are not available (marked as dynamic)"
                )
                raise SystemExit(1)
            if target_meta is None or target_meta.dependencies is None:
                renderer.render_error(
                    f"Cannot diff: dependencies for {package}=={diff_version} "
                    "are not available (marked as dynamic)"
                )
                raise SystemExit(1)

            diff_result = service.diff_dependencies(base_meta, target_meta)
            renderer.render_deps_diff(
                package,
                resolved_version,
                diff_version,
                diff_result,
                tag=tag,
            )
            return

        # -- Normal mode ----------------------------------------------------
        try:
            metadata = await service.get_metadata(
                package,
                resolved_version,
                tag=tag,
            )
        except TagNotFoundError as exc:
            renderer.render_error(str(exc))
            if exc.available_tags:
                renderer.render_error(
                    f"Available tags: {', '.join(sorted(exc.available_tags))}"
                )
            raise SystemExit(1) from None
        except Exception as exc:
            renderer.render_error(str(exc))
            raise SystemExit(1) from None

    if metadata is None:
        renderer.render_error(
            f"No metadata available for {package}=={resolved_version}"
        )
        raise SystemExit(1)

    renderer.render_deps(package, resolved_version, metadata, tag=tag)


@app.command(name="artifacts")
async def artifacts_cmd(
    package: Annotated[str, Parameter(help="Package name.")],
    *,
    version: Annotated[
        str | None,
        Parameter(
            name="--version",
            help="Specific version. Defaults to latest.",
        ),
    ] = None,
) -> None:
    """List distribution artifacts (wheels, sdists) for a version."""
    renderer = _get_renderer()
    async with _open_service() as service:
        resolved_version = await _resolve_version(service, package, version)
        if resolved_version is None:
            renderer.render_not_found(package)
            raise SystemExit(1)

        try:
            file_list = await service.files(package, resolved_version)
        except Exception as exc:
            renderer.render_error(str(exc))
            raise SystemExit(1) from None

    renderer.render_artifacts(package, resolved_version, file_list)


@app.command(name="ls")
async def ls_cmd(  # noqa: PLR0913
    package: Annotated[str, Parameter(help="Package name.")],
    *,
    version: Annotated[
        str | None,
        Parameter(
            name="--version",
            help="Specific version. Defaults to latest.",
        ),
    ] = None,
    limit: Annotated[
        int | None,
        Parameter(
            name="--limit",
            help="Maximum number of entries to show.",
        ),
    ] = _DEFAULT_LS_LIMIT,
    all_entries: Annotated[
        bool,
        Parameter(
            name="--all",
            negative="",
            show_default=False,
            help="Show all entries (no limit).",
        ),
    ] = False,
    prefix: Annotated[
        str | None,
        Parameter(
            name="--prefix",
            help="Show entries under this path (e.g., src/).",
        ),
    ] = None,
    recursive: Annotated[
        bool,
        Parameter(
            name=["--recursive", "-r"],
            show_default=False,
            help="Flat recursive file listing instead of directory navigation.",
        ),
    ] = False,
) -> None:
    """List paths inside a package archive."""
    renderer = _get_renderer()

    # Validate flag conflicts
    if all_entries and limit != _DEFAULT_LS_LIMIT:
        renderer.render_error("--all and --limit cannot be used together")
        raise SystemExit(1)

    if limit is not None and limit < 0:
        renderer.render_error("--limit must be non-negative")
        raise SystemExit(1)

    if all_entries:
        limit = None

    async with _open_service() as service:
        resolved_version = await _resolve_version(service, package, version)
        if resolved_version is None:
            renderer.render_not_found(package)
            raise SystemExit(1)

        try:
            members = await service.list_artifact_files(package, resolved_version)
        except Exception as exc:
            renderer.render_error(str(exc))
            raise SystemExit(1) from None

    entries = build_ls_entries(members, prefix=prefix, recursive=recursive)

    if not entries and prefix is not None and not has_prefix(members, prefix):
        renderer.render_error(
            f"No directory '{prefix}' in archive for"
            f" {package} {resolved_version}."
            f" Use 'peeq ls {package}' to see available paths."
        )
        raise SystemExit(1)

    total = len(entries)
    display = entries[:limit] if limit is not None else entries
    renderer.render_ls(
        package,
        resolved_version,
        display,
        total,
        prefix=prefix,
        recursive=recursive,
    )


@app.command(name="cat")
async def cat_cmd(
    package: Annotated[str, Parameter(help="Package name.")],
    path: Annotated[str, Parameter(help="File path inside the package archive.")],
    *,
    version: Annotated[
        str | None,
        Parameter(
            name="--version",
            help="Specific version. Defaults to latest.",
        ),
    ] = None,
    max_bytes: Annotated[
        int,
        Parameter(
            name="--max-bytes",
            help="Maximum bytes of text output. Accepts size suffixes (e.g. 128KiB, 1MB).",
            converter=_parse_byte_size,
            show_default=format_size,
        ),
    ] = _DEFAULT_CAT_MAX_BYTES,
    full: Annotated[
        bool,
        Parameter(
            name="--full",
            show_default=False,
            help="Show complete content (no byte limit).",
        ),
    ] = False,
) -> None:
    """Print a file from inside a package archive."""
    import sys as _sys  # noqa: PLC0415

    from peeq.service import (  # noqa: PLC0415
        ArtifactNotAvailableError,
        FileNotInArchiveError,
    )

    renderer = _get_renderer()

    # Validate flag conflicts
    if full and max_bytes != _DEFAULT_CAT_MAX_BYTES:
        renderer.render_error("--full and --max-bytes cannot be used together")
        raise SystemExit(1)

    if max_bytes < 0:
        renderer.render_error("--max-bytes must be non-negative")
        raise SystemExit(1)

    if full:
        max_bytes_resolved: int | None = None
    else:
        max_bytes_resolved = max_bytes

    async with _open_service() as service:
        resolved_version = await _resolve_version(service, package, version)
        if resolved_version is None:
            renderer.render_not_found(package)
            raise SystemExit(1)

        try:
            content = await service.get_file_content(package, resolved_version, path)
        except FileNotInArchiveError as exc:
            renderer.render_error(str(exc))
            raise SystemExit(1) from None
        except ArtifactNotAvailableError as exc:
            renderer.render_error(str(exc))
            await _render_version_hint(service, renderer, package)
            raise SystemExit(1) from None
        except Exception as exc:
            renderer.render_error(str(exc))
            raise SystemExit(1) from None

    # Determine text vs binary on the FULL content first
    is_text = try_decode(content) is not None
    is_truncated = False
    original_size = len(content)

    if is_text and max_bytes_resolved is not None and len(content) > max_bytes_resolved:
        content = truncate_utf8(content, max_bytes_resolved)
        is_truncated = True
        _sys.stderr.write(
            f"[Truncated after {format_size(max_bytes_resolved)}; "
            f"file is {format_size(original_size)}. "
            "Use --full for complete output.]\n"
        )

    renderer.render_file_content(
        package,
        resolved_version,
        path,
        content,
        truncated=is_truncated,
        total_size=original_size if is_truncated else None,
    )


@app.command
async def download(
    package: Annotated[str, Parameter(help="Package name.")],
    *,
    version: Annotated[
        str | None,
        Parameter(
            name="--version",
            help="Specific version. Defaults to latest.",
        ),
    ] = None,
    output_dir: Annotated[
        Path,
        Parameter(
            name=["--output-dir", "-o"],
            help="Output directory. Defaults to current directory.",
        ),
    ] = Path(),
    extract: Annotated[
        bool,
        Parameter(
            name="--extract",
            show_default=False,
            help=("Extract archive contents instead of copying."),
        ),
    ] = False,
) -> None:
    """Download a package archive.

    Serve from cache if available, download if not.
    """
    from peeq.service import ArtifactNotAvailableError  # noqa: PLC0415

    renderer = _get_renderer()
    async with _open_service() as service:
        resolved_version = await _resolve_version(service, package, version)
        if resolved_version is None:
            renderer.render_not_found(package)
            raise SystemExit(1)

        try:
            result_path = await service.download_package(
                package, resolved_version, output_dir, extract=extract
            )
        except ArtifactNotAvailableError as exc:
            renderer.render_error(str(exc))
            await _render_version_hint(service, renderer, package)
            raise SystemExit(1) from None
        except Exception as exc:
            renderer.render_error(str(exc))
            raise SystemExit(1) from None

    renderer.render_download(result_path, extracted=extract)


# ---------------------------------------------------------------------------
# Vulnerability checking
# ---------------------------------------------------------------------------


@app.command
async def vulns(
    package: Annotated[str, Parameter(help="Package name.")],
    *,
    version: Annotated[
        str | None,
        Parameter(
            name="--version",
            help="Specific version. Defaults to latest.",
        ),
    ] = None,
) -> None:
    """Check for known vulnerabilities via the OSV database.

    Queries the OSV API (https://osv.dev) for known security vulnerabilities
    affecting the specified package version.

    Vulnerability results are always fetched live, not cached.
    """
    from peeq.integrations.osv import OSVError  # noqa: PLC0415

    renderer = _get_renderer()
    async with _open_service() as service:
        resolved_version = await _resolve_version(service, package, version)
        if resolved_version is None:
            renderer.render_not_found(package)
            raise SystemExit(1)

        try:
            report = await service.check_vulnerabilities(
                package,
                resolved_version,
            )
        except OSVError as exc:
            renderer.render_error(str(exc))
            raise SystemExit(1) from None
        except Exception as exc:
            renderer.render_error(str(exc))
            raise SystemExit(1) from None

    renderer.render_vulns(report)


# ---------------------------------------------------------------------------
# Dependency resolution commands
# ---------------------------------------------------------------------------


@app.command
async def resolve(
    requirements: Annotated[
        list[str],
        Parameter(
            help=(
                'PEP 508 requirement strings (e.g., "requests>=2.31.0", "flask==3.0.0").'
            ),
        ),
    ],
    *,
    pre: Annotated[
        bool,
        Parameter(
            name=["--pre", "--prerelease"],
            show_default=False,
            help="Include pre-release versions in resolution.",
        ),
    ] = False,
    python: Annotated[
        str | None,
        Parameter(
            name="--python",
            help="Target Python version (e.g., 3.12).",
        ),
    ] = None,
    platform: Annotated[
        str | None,
        Parameter(
            name="--platform",
            help="Target platform: linux, win32, darwin.",
        ),
    ] = None,
) -> None:
    """Resolve full dependency tree for one or more requirements.

    Arguments are PEP 508 requirement strings — not bare package names.

    Pin versions with specifiers: "requests==2.31.0", "flask>=3.0".
    """
    from peeq.resolver.base import (  # noqa: PLC0415
        ResolutionImpossible,
        ResolutionTooDeep,
    )

    renderer = _get_renderer()
    target = _build_target_env(python=python, platform=platform)

    async with _open_service() as service:
        try:
            result = await service.resolve_dependencies(
                requirements,
                target,
                include_prereleases=pre,
            )
        except ResolutionImpossible as exc:
            enriched = await service.enrich_conflicts(exc.conflicts)
            renderer.render_conflicts(enriched, header="Resolution failed")
            raise SystemExit(1) from None
        except (ResolutionTooDeep, ValueError, RuntimeError) as exc:
            renderer.render_error(str(exc))
            raise SystemExit(1) from None

    renderer.render_resolve(result)


@app.command
async def conflicts(
    requirements: Annotated[
        list[str],
        Parameter(
            help=(
                'PEP 508 requirement strings (e.g., "requests>=2.31.0", "flask==3.0.0").'
            ),
        ),
    ],
    *,
    pre: Annotated[
        bool,
        Parameter(
            name=["--pre", "--prerelease"],
            help="Include pre-release versions in resolution (default: on for conflicts).",
        ),
    ] = True,
    python: Annotated[
        str | None,
        Parameter(
            name="--python",
            help="Target Python version (e.g., 3.12).",
        ),
    ] = None,
    platform: Annotated[
        str | None,
        Parameter(
            name="--platform",
            help="Target platform: linux, win32, darwin.",
        ),
    ] = None,
) -> None:
    """Check if packages can be installed together.

    Pre-release versions are included by default so that pinned
    pre-release constraints are evaluated correctly.  Use `--no-pre`
    to restrict resolution to stable versions only.

    Arguments are PEP 508 requirement strings — not bare package names.

    Pin versions with specifiers: "requests==2.31.0", "flask>=3.0".

    If resolution succeeds, display the resolved tree. If it fails, display the conflicting requirements.
    """
    from peeq.resolver.base import (  # noqa: PLC0415
        ResolutionImpossible,
        ResolutionTooDeep,
    )

    renderer = _get_renderer()
    target = _build_target_env(python=python, platform=platform)

    async with _open_service() as service:
        try:
            result = await service.resolve_dependencies(
                requirements,
                target,
                include_prereleases=pre,
            )
        except ResolutionImpossible as exc:
            enriched = await service.enrich_conflicts(exc.conflicts)
            renderer.render_conflicts(enriched)
            raise SystemExit(1) from None
        except (ResolutionTooDeep, ValueError, RuntimeError) as exc:
            renderer.render_error(str(exc))
            raise SystemExit(1) from None

    # No conflicts — resolution succeeded
    renderer.render_resolve(result)


@app.command
async def why(
    requirements: Annotated[
        list[str],
        Parameter(
            help=(
                'PEP 508 requirement strings (e.g., "requests>=2.31.0", "flask==3.0.0").'
            ),
        ),
    ],
    *,
    target_package: Annotated[
        str,
        Parameter(
            name=["-d", "--dependency"],
            help="Package name to trace (bare name, no version specifier).",
        ),
    ],
    pre: Annotated[
        bool,
        Parameter(
            name=["--pre", "--prerelease"],
            show_default=False,
            help="Include pre-release versions in resolution.",
        ),
    ] = False,
    python: Annotated[
        str | None,
        Parameter(
            name="--python",
            help="Target Python version (e.g., 3.12).",
        ),
    ] = None,
    platform: Annotated[
        str | None,
        Parameter(
            name="--platform",
            help="Target platform: linux, win32, darwin.",
        ),
    ] = None,
) -> None:
    """Trace why a package appears in the dependency tree.

    Show all dependency paths from root requirements to a target
    package, answering "why is X in my dependency tree?"
    """
    from peeq.resolver.base import (  # noqa: PLC0415
        ResolutionImpossible,
        ResolutionTooDeep,
    )

    renderer = _get_renderer()

    async with _open_service() as service:
        try:
            result = await service.why_dependencies(
                target_package,
                requirements,
                pre=pre,
                python_version=python,
                platform=platform,
                all_hops=True,
            )
        except ResolutionImpossible as exc:
            enriched = await service.enrich_conflicts(exc.conflicts)
            renderer.render_why_failed(target_package, enriched)
            raise SystemExit(1) from None
        except (ResolutionTooDeep, ValueError, RuntimeError) as exc:
            renderer.render_error(str(exc))
            raise SystemExit(1) from None

    # Target not found in resolution
    if not result.paths and not result.is_direct:
        renderer.render_error(
            f"Package {target_package!r} is not a dependency of the given requirements."
        )
        raise SystemExit(1)

    renderer.render_why(result)


# ---------------------------------------------------------------------------
# Cache commands
# ---------------------------------------------------------------------------


@cache_app.command(name="path")
def cache_path_cmd() -> None:
    """Print the cache directory path.

    Outputs the resolved cache root directory path with no extra
    formatting, suitable for shell scripting (e.g., `cd $(peeq cache path)`).
    """
    from peeq.config import get_settings  # noqa: PLC0415

    print(get_settings().cache.dir)  # noqa: T201


@cache_app.command(name="info")
def cache_info() -> None:
    """Show cache statistics (location, size, entry counts)."""
    from peeq.cache import CacheManager  # noqa: PLC0415

    renderer = _get_renderer()
    cache = CacheManager.default()
    stats = cache.get_stats()
    renderer.render_cache_info(stats)


@cache_app.command
def clear(
    *,
    older_than: Annotated[
        str | None,
        Parameter(
            name="--older-than",
            help="Only clear entries older than this (e.g., 30d, 2h, 1m).",
        ),
    ] = None,
) -> None:
    """Clear cached data.

    Without `--older-than`, delete everything (database + archives).
    With `--older-than`, evict only stale entries.
    """
    from peeq.cache import CacheManager  # noqa: PLC0415

    renderer = _get_renderer()
    cache = CacheManager.default()

    older_seconds: int | None = None
    if older_than is not None:
        try:
            older_seconds = _parse_duration(older_than)
        except ValueError as exc:
            renderer.render_error(str(exc))
            raise SystemExit(1) from None

    stats_before = cache.get_stats()
    count = cache.clear(older_than_seconds=older_seconds)
    renderer.render_cache_clear(count, stats_before.total_size_bytes)


@cache_app.command
def dump() -> None:
    """Export full cache index as JSON for debugging."""
    from peeq.cache import CacheManager  # noqa: PLC0415

    renderer = _get_renderer()
    cache = CacheManager.default()
    data = cache.dump()
    renderer.render_cache_dump(data)


@cache_app.command(name="check")
def cache_check() -> None:
    """Run PRAGMA verification and integrity checks on the cache database."""
    from peeq.cache import CacheManager  # noqa: PLC0415

    renderer = _get_renderer()
    cache = CacheManager.default()
    diagnostics = cache.check()
    renderer.render_cache_check(diagnostics)


# ---------------------------------------------------------------------------
# Config commands
# ---------------------------------------------------------------------------


@config_app.command(name="path")
def config_path() -> None:
    """Print the configuration file path.

    Outputs the resolved config file path with no extra
    formatting, suitable for shell scripting (e.g., `cat $(peeq config path)`).
    """
    from peeq.config import _default_config_path  # noqa: PLC0415

    print(_default_config_path())  # noqa: T201


# ---------------------------------------------------------------------------
# Skill commands
# ---------------------------------------------------------------------------


@skill_app.command(name="show")
def skill_show() -> None:
    """Print agent skill instructions optimized for AI agents.

    Outputs a Markdown document with detailed usage instructions
    designed for AI agent consumption.

    Use this instead of `--help`
    when operating as an AI agent.
    """
    path = Path(__file__).parent / "skill" / "main.md"
    print(path.read_text(encoding="utf-8"), end="")  # noqa: T201


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    """CLI entry point for `pyproject.toml` console_scripts."""
    import sys  # noqa: PLC0415

    # Ensure consistent UTF-8 output on all platforms (prevents
    # UnicodeEncodeError on Windows with locale encodings like cp1255).
    # reconfigure() is only available on TextIOWrapper, not on every
    # stream object (e.g. pytest capture streams), hence the getattr guard.
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            reconfigure(encoding="utf-8")

    app.meta()
