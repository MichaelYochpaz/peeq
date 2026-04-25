# Command Reference

peeq provides commands for inspecting Python packages, resolving dependencies, and managing the local cache.
Every command works directly against a package registry — no installation required.

## Commands

### Inspection

| Command | Description |
|---------|-------------|
| [`info`](info.md) | Show package metadata with optional version history, vulnerability scan, and dependency list. |
| [`versions`](versions.md) | List available versions with filtering by specifier, limit, or yanked status. |
| [`deps`](deps.md) | Show package dependencies, with optional diff between versions. |
| [`artifacts`](artifacts.md) | List distribution artifacts (wheels, sdists) for a version. |
| [`cat`](cat.md) | Print a file from inside a package archive. |
| [`ls`](ls.md) | List file paths inside a package archive. |
| [`download`](download.md) | Download a package archive or extract its contents to disk. |

### Resolution & Security

| Command | Description |
|---------|-------------|
| [`vulns`](vulns.md) | Check for known vulnerabilities via the OSV database. |
| [`resolve`](resolve.md) | Resolve a full dependency tree for one or more PEP 508 requirements. |
| [`conflicts`](conflicts.md) | Check if packages can be installed together. |
| [`why`](why.md) | Trace why a package appears in the dependency tree. |

### System

| Command | Description |
|---------|-------------|
| [`cache`](cache.md) | Cache management — view stats, clear entries, check integrity. |
| `config path` | Print the configuration file path. See [Configuration](../configuration.md). |
| `skill show` | Print agent skill instructions for AI agents. See [Agent Skill](../ai-agents/skill.md). |

## Global options

These options apply to every command.

| Option | Description |
|--------|-------------|
| `--format`, `-f` | Output format: `pretty`, `plain`, `agent`, `json`. Auto-detected by default (see below). |
| `--no-cache` | Bypass the cache entirely — don't read from or write to it. |
| `--index-url`, `-i` | Package index URL. Defaults to `https://pypi.org`. |
| `--backend` | Backend type override: `pypi` (PEP 691 JSON) or `simple` (PEP 503 HTML). Auto-detected by default. |
| `--verbose`, `-v` | Enable verbose logging. |

Use `peeq --version` to print the version number and exit.

### Output format auto-detection

When `--format` is not specified, peeq selects a format automatically:

- **Terminal (TTY)** — `pretty` format with Rich panels, tables, and syntax highlighting.
- **Piped or redirected** — `plain` format with clean text and no ANSI codes.

The `agent` and `json` formats are never auto-selected.
Use `--format agent` or `--format json` explicitly.

### Version defaulting

Most commands accept a `--version` option to target a specific package release.
When omitted, peeq defaults to the **latest non-yanked version**.
