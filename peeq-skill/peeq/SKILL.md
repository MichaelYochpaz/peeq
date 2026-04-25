---
name: peeq
description: >-
  peeq is a CLI tool for investigating Python packages from PyPI and
  private package indexes. Use when researching or auditing a Python
  package. Examples: checking a package's license or compliance,
  inspecting package contents or dependencies, checking for known
  vulnerabilities, resolving or debugging dependency conflicts,
  verifying version compatibility. Supports downloading package
  archives (sdist / wheel) or reading specific files from within them
  (pyproject.toml, LICENSE, etc.).
compatibility: "Requires uv."
---

# peeq

peeq is a CLI for inspecting Python packages from PyPI and private
package indexes. It reads metadata, dependencies, versions, files,
and known vulnerabilities without installing packages or running
their code.

## Command Reference

**Run `uvx peeq skill show` to load the full command reference, output formats, and workflows.**

If `uvx` is not available, see the
[installation guide](https://raw.githubusercontent.com/MichaelYochpaz/peeq/refs/heads/main/docs/installation.md).
