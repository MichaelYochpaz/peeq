# Contributing to peeq

## Development Setup

### Prerequisites

- Python 3.10+
- [uv](https://docs.astral.sh/uv/)

### Getting Started

1. Clone the repository:

   ```bash
   git clone https://github.com/MichaelYochpaz/peeq.git
   cd peeq
   ```

2. Install all dependencies:

   ```bash
   uv sync
   ```

3. Install pre-commit hooks:

    ```bash
    uv run prek install
    ```

## Running Checks

After making changes, run all checks with a single command:

```bash
uv run prek run --all-files
```

This runs linting, formatting, type checking, and tests.

> [pre-commit](https://pre-commit.com/) is a compatible alternative if you prefer it over `prek`: `pre-commit run --all-files`

### Individual Commands

When you need to run a specific check:

- **Lint**: `uv run ruff check --fix`
- **Format**: `uv run ruff format`
- **Type check**: `uv run ty check`
- **Tests**: `uv run pytest`
- **Docs preview**: `uv run zensical serve`
- **Docs build**: `uv run zensical build`

## Coding Standards

### Lint-Enforced Conventions

The following are enforced by ruff and caught automatically when running checks.
See `pyproject.toml` for the full rule set.

- **`from __future__ import annotations`** at the top of every `.py` file,
  after the module docstring (`FA`).
- **Absolute imports only** — no relative imports (`TID`).
- **f-strings** for all string formatting except logging calls (`FLY`).
- **`pathlib.Path`** for all file operations — no `os.path` (`PTH`).
- **`raise ... from err`** inside `except` blocks (`B904`).
- **Lazy `%`-style formatting** in logging calls — no f-strings, so messages
  are only interpolated when the log level is active (`G004`).

### Docstrings

Use [Google-style](https://google.github.io/styleguide/pyguide.html#38-comments-and-docstrings) docstrings.
Use imperative mood for function/method summary lines ("Return", "Fetch", "Parse") and descriptive mood for class and module summary lines.
Use single backticks for all inline code in docstrings and comments.
Every `.py` file must have a module-level docstring.

```python
def fetch_metadata(package: str, version: str) -> PackageMetadata:
    """Fetch metadata for a specific package version.

    Args:
        package (str): The normalized package name.
        version (str): The version string
            (PEP 440 — https://peps.python.org/pep-0440/).

    Returns:
        PackageMetadata: The resolved package metadata.

    Raises:
        PackageNotFoundError: If the package does not exist on the registry.
    """
```

### Type Annotations

Type annotations are required for all public function signatures.
Use modern syntax ([PEP 604](https://peps.python.org/pep-0604/) `X | Y` unions, `list[str]` instead of `List[str]`).
Type correctness is enforced by [ty](https://docs.astral.sh/ty/).

### File Paths

Use `Path.replace()` for atomic file moves — `Path.rename()` raises `FileExistsError` on Windows when the destination exists, while `Path.replace()` atomically replaces it cross-platform.

### PEP References

When referencing a PEP in code comments, docstrings, or documentation, include a link to the canonical page:

```python
# Supports PEP 658 (https://peps.python.org/pep-0658/) metadata endpoints
```

Format: `PEP NNN (https://peps.python.org/pep-NNNN/)`, where `NNNN` is the zero-padded PEP number.

### Error Handling

Define custom exception classes in the module that raises them.

### Async

- Use `httpx.AsyncClient` for all HTTP calls (never sync `httpx.Client`).
- Never hold open database cursors across `await` points — this blocks WAL checkpointing and causes unbounded WAL growth.
- Always `fetchall()` or `fetchone()` before yielding to the event loop.

## Documentation

The docs site (`docs/`) is built with [Zensical](https://zensical.org/) and configured in `zensical.toml`.
Update docs when adding or changing user-facing features.

### Agent Skill

peeq includes an internal [Agent Skill](https://agentskills.io/what-are-skills) — on-demand instructions that teach AI agents how to use the CLI.
The skill content lives under `peeq/skill/` and is printed via `peeq skill show`.
After changes to CLI commands, flags, or output behavior, check whether the skill files need updating.

## Testing

### Test Structure

Tests mirror the package structure: `tests/test_<module>.py` for root modules, `tests/test_<subpackage>/` for subpackages.

### Patterns

- **HTTP mocking**: Use [respx](https://lundberg.github.io/respx/) for backend
  tests (async-native router pattern).
- **Async mocking**: Use `AsyncMock` for async interfaces, `MagicMock` for sync.
- **Database tests**: Use the `tmp_path` fixture for isolated file-based SQLite DBs.
- **Helper factories**: Create `_metadata()`, `_dep()`, `_pkg_info()` helpers per test file for readable test data construction.
- **pytest-asyncio**: Uses `auto` mode (`asyncio_mode = "auto"` in `pyproject.toml`).
  Do **not** override the `event_loop` fixture — it was removed in pytest-asyncio v1.0+.

### Coverage

New features and bug fixes should include tests.
Focus on tests that catch regressions — avoid low-value assertions (e.g., testing that a constructor sets an attribute).

Run tests with coverage:

```bash
uv run pytest --cov=peeq --cov-report=term-missing
```

### Running a Single Test

```bash
uv run pytest tests/test_models.py -v                            # Single file
uv run pytest tests/test_models.py::TestDependency::test_parse   # Single test
```

## Security

### Threat Model

All data from package registries (PyPI, private indexes) is **untrusted**. Package names, summaries, authors, URLs, filenames, yanked reasons, vulnerability descriptions, and file contents are attacker-controlled input. peeq never installs or executes packages — it extracts metadata only. Apply correct escaping to all untrusted values in render methods — see sanitization helpers in `peeq/sanitize.py`.

### Testing Requirements

Security-sensitive code changes must include adversarial-input tests:

- **Output renderers**: Include payloads with `<script>`, `</tag>`, `[link=...]`, ANSI sequences in package metadata.
- **Archive extraction**: Include archives with `../../` paths, oversized members, and symlinks escaping the destination.
- **Network handlers**: Include redirects to `169.254.169.254`, `127.0.0.1`, and `::ffff:` IPv6-mapped addresses.
- **Filenames**: Include traversal patterns (`../`), Windows reserved names (`CON`), and empty strings.
- **Requirement strings**: Include embedded newlines, null bytes, and leading dashes.

### Security-Sensitive Files

Changes to these files should be reviewed with security in mind:

- `peeq/sanitize.py` — All sanitization/escaping helpers
- `peeq/extraction.py` — Decompression bombs, path traversal
- `peeq/output/agent.py` — XML injection / prompt injection
- `peeq/output/rich.py` — Rich markup injection
- `peeq/output/plain.py` — ANSI/OSC injection
- `peeq/backends/base.py` — SSRF, response size limits
- `peeq/service.py` — Filename paths, download orchestration
- `peeq/cache/manager.py` — Filename paths, credential storage
- `peeq/resolver/uv_solver.py` — Requirement injection, credential leakage

## Commit Messages

This project follows [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/) with project-specific types and scopes.
Format: `<type>(<scope>): <description>` — scope is recommended but not required.

### Types

Select the first matching type:

1. `revert` — undoes a previous commit
2. `docs` — documentation only (docs site, docstrings, code comments) — no functional change
3. `test` — tests only — no production code change
4. `chore` — build system, CI, tooling, dependencies — no production code change
5. `fix` — corrects wrong or broken production behavior (not for adding something absent — that's `feat`)
6. `refactor` — restructured production code without changing behavior (if uncertain whether behavior changed, use `feat`)
7. `feat` — **default**; everything else — new features, behavioral changes, capability additions

### Scopes

Scopes are optional. When used, the scope is the **module or subpackage name** from `peeq/`: `backends`, `cache`, `cli`, `config`, `database`, `extraction`, `integrations`, `metadata`, `models`, `output`, `resolver`, `sanitize`, `service`, `skill`, `utils`.

Fixed scopes for non-package paths:

| Path(s) | Scope |
|---------|-------|
| `docs/`, `zensical.toml`, `assets/` | `site` |
| `.github/` | `ci` |
| `pyproject.toml`, `.pre-commit-config.yaml` (when not tied to a module) | `build` |
| `AGENTS.md`, `CONTRIBUTING.md`, `README.md`, `.gitignore` | `repo` |
| `peeq-skill/` | `skill` |
| `CHANGELOG.md` | `changelog` |
| `tests/conftest.py` (shared test infra) | `tests` |

When tests change alongside the module they test, scope to the module. When a commit spans multiple modules, scope to the primary one. For `pyproject.toml`, scope to the module if the change exclusively serves it; otherwise use `build`.

### Descriptions

- Imperative mood, lowercase after colon: `add`, `remove`, `update`
- No trailing period
- Describe purpose and impact, not implementation details
- Revert format: `revert(<original-scope>): revert "<original-subject>"`

### Examples

```
feat(resolver): add PEP 658 metadata endpoint support
fix(backends): handle timeout on large package indexes
docs(site): add private registry configuration guide
chore(ci): update Python matrix to include 3.14
refactor(output): extract shared table formatting logic
test(cache): add expiration edge-case coverage
chore(build): bump minimum httpx version to 0.28
```

## Pull Requests

All PRs are squash-merged. The PR title becomes the commit message on `main`.
Following the Conventional Commits format above is appreciated but not
enforced — the maintainer may adjust the PR title before merging for clarity
and consistency. Individual commits within a PR can be informal.

Git authorship tracks contributors automatically via squash merge.
