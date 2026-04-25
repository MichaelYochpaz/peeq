---
title: Overview
hide:
  - toc
---

<div style="text-align: center; margin-bottom: 1.5em;">
  <img src="images/logo-wordmark.svg" alt="peeq" style="width: min(360px, 80%); height: auto;">
</div>

**Investigate Python package metadata, dependencies, and known vulnerabilities. Built for developers and AI agents.**

Works directly with published artifacts on PyPI and private registries —
no download or installation required.

## Features

- 🔍 **Inspect without installing** — query metadata, dependencies, and files from published artifacts — no install required.
- 🌳 **Dependency analysis** — resolve dependency trees, detect conflicts, and compare versions.
- 🤖 **Built for AI agents** — built-in [agent skill](ai-agents/skill.md) for tool discovery and [`--format agent`](ai-agents/index.md) for structured, token-efficient output.
- 📄 **Read package files** — inspect `pyproject.toml`, `LICENSE`, and other files directly from a published distribution.
- 🛡️ **Vulnerability scanning** — check packages against the [OSV database](https://osv.dev) for known security vulnerabilities.
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

## Getting started

- **[Installation](installation.md)** — install peeq and verify your setup.
- **[Quickstart](quickstart.md)** — hands-on walkthrough of core commands.
