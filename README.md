<p align="center">
  <img src="https://raw.githubusercontent.com/MichaelYochpaz/peeq/main/assets/logo-wordmark.svg" alt="peeq" width="360">
</p>

<p align="center">
  <a href="https://pypi.org/project/peeq/"><img src="https://img.shields.io/pypi/v/peeq" alt="PyPI"></a>
  <a href="https://pypi.org/project/peeq/"><img src="https://img.shields.io/pypi/pyversions/peeq" alt="Python"></a>
  <a href="https://codecov.io/gh/MichaelYochpaz/peeq"><img src="https://codecov.io/gh/MichaelYochpaz/peeq/graph/badge.svg" alt="Coverage"></a>
  <a href="LICENSE"><img src="https://img.shields.io/pypi/l/peeq" alt="License"></a>
</p>

Investigate Python package metadata, dependencies, files, versions, and vulnerability data from published artifacts on PyPI and private registries — without installing packages.

Provides structured, token-efficient output for AI agents alongside rich
terminal output for human users.

> [!NOTE]
> **Transparency note:** This project is developed with heavy use of AI coding agents.  
> Although most code is AI-generated, architecture and design are human-guided and reviewed, and all changes are tested.

## Features

- 🔍 **Inspect without installing** — query metadata, dependencies, and files from published artifacts — no install required.
- 🌳 **Dependency analysis** — resolve dependency trees, detect conflicts, and compare versions.
- 📄 **Read package files** — inspect `pyproject.toml`, `LICENSE`, and other files directly from a published distribution.
- 🛡️ **Vulnerability scanning** — check packages against the [OSV database](https://osv.dev) for known security vulnerabilities.
- 🤖 **Built for AI agents** — built-in agent skill for tool discovery and `--format agent` for structured, token-efficient output.
- 🔒 **Private registry support** — works with any PEP 503-compatible package index via `--index-url`.
- ⚡ **Persistent caching** — avoid redundant network requests with an SQLite-backed local cache.

## peeq vs pip / uv

| Task | pip / uv | peeq |
|------|----------|------|
| View package metadata | Install, then `pip show` / `uv pip show` | `peeq info <pkg>` |
| View dependencies | Download artifact, extract, parse metadata | `peeq deps <pkg>` |
| Compare deps across versions | Custom scripts | `peeq deps <pkg> --version X --diff Y` |
| Read a file from a package | Download, extract, navigate to file | `peeq cat <pkg> pyproject.toml` |
| Check for vulnerabilities | Separate vulnerability scanner | `peeq vulns <pkg>` |
| Resolve dependency tree | Trial install in isolated environment | `peeq resolve "pkg>=1.0"` |
| Check for conflicts | Custom scripts or trial-and-error installs | `peeq conflicts "pkgA" "pkgB"` |
| Trace why a package is needed | Manual dependency graph tracing | `peeq why "requests>=2.31" -d urllib3` |

## Installation

Requires Python 3.10+.

```bash
# Install globally with uv (recommended)
uv tool install peeq

# Install with pip
pip install peeq
```

### Zero-install with uvx

If you have `uv` installed, you can also run peeq directly without installing it.  
For example:

```bash
uvx peeq info requests
```

> [!IMPORTANT]
> [uv](https://docs.astral.sh/uv/) is the recommended installation method.  
> Additionally, commands like `resolve`, `conflicts`, and `why` utilize `uv` and require it to be installed.
> See the [installation docs](https://peeq.michaelyo.dev/installation/) for details.

## Commands

| Command | Description |
|---------|-------------|
| `info` | Show package metadata with optional sections |
| `versions` | List available versions with filtering |
| `deps` | Show dependencies with diff and wheel tag support |
| `artifacts` | List distribution artifacts (wheels, sdists) for a version |
| `cat` | Print a file from inside a package archive |
| `ls` | List paths inside a package archive |
| `download` | Download a package archive |
| `vulns` | Check for known vulnerabilities (OSV) |
| `resolve` | Resolve full dependency tree |
| `conflicts` | Check if packages can coexist |
| `why` | Trace why a package is in the dependency tree |
| `cache` | Cache management (info, clear, check, dump) |
| `config` | Configuration management (file path) |
| `skill` | Show agent skill instructions |

[Full documentation](https://peeq.michaelyo.dev/)

## Agent Skill

peeq includes a built-in [Agent Skill](https://agentskills.io/what-are-skills) — structured instructions that teach AI agents how to use peeq for package research.

### Install

Download [`SKILL.md`](peeq-skill/peeq/SKILL.md) and place it in a `peeq/` directory within your agent platform's skill directory.

See the [skill documentation](https://peeq.michaelyo.dev/ai-agents/skill/) for integration options.

> [!TIP]
> Agents can also load peeq's skill by running `peeq skill show` directly.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, coding standards, and testing guidelines.

## License

[MIT](LICENSE)
