---
title: Overview
hide:
  - toc
---

<section class="peeq-hero" markdown>
<div class="peeq-hero__copy" markdown>

<div class="peeq-hero__mark" markdown>
![peeq](images/logo-wordmark-light.svg#only-light){ .peeq-hero__logo }
![peeq](images/logo-wordmark-dark.svg#only-dark){ .peeq-hero__logo }
</div>

<p class="peeq-kicker">Peek inside Python packages</p>

<h1 class="peeq-hero__headline">Investigate metadata, dependencies, and known vulnerabilities.</h1>

<p class="peeq-hero__lede">peeq reads metadata, dependencies, files, versions, and vulnerability data from PyPI and private registries — without downloading, installing, or executing packages.</p>

<div class="peeq-hero__actions" markdown>
[Install peeq](installation.md){ .md-button .md-button--primary }
[Quickstart](quickstart.md){ .md-button }
</div>

</div>
<div class="peeq-hero__demo">
<div class="peeq-terminal">
<div class="peeq-terminal__chrome" aria-hidden="true">
<span class="peeq-terminal__dot peeq-terminal__dot--red"></span>
<span class="peeq-terminal__dot peeq-terminal__dot--amber"></span>
<span class="peeq-terminal__dot peeq-terminal__dot--green"></span>
</div>
<pre class="peeq-terminal__body"><code><span class="peeq-t--prompt">$</span> <span class="peeq-t--cmd">peeq info requests</span>
<span class="peeq-t--label">Package:</span>           requests
<span class="peeq-t--label">Summary:</span>           Python HTTP for Humans.
<span class="peeq-t--label">Latest Version:</span>    2.33.1 <span class="peeq-t--muted">(2026-03-30)</span>
<span class="peeq-t--label">Versions:</span>          156
<span class="peeq-t--label">License:</span>           Apache-2.0
<span class="peeq-t--label">Registry:</span>          pypi.org
<span class="peeq-t--label">Documentation:</span>     https://requests.readthedocs.io
<span class="peeq-t--label">Source:</span>            https://github.com/psf/requests

<span class="peeq-t--muted">--- Version 2.33.1 (latest) ---</span>
<span class="peeq-t--label">Python:</span> &gt;=3.10</code></pre>
</div>
</div>
</section>

## Why peeq

<div class="grid cards peeq-feature-grid" markdown>

-   <span class="peeq-card-icon" aria-hidden="true">🔍</span> **Inspect without installing**

    Query metadata, dependencies, and files from published artifacts — no install required.

-   <span class="peeq-card-icon" aria-hidden="true">🌳</span> **Dependency analysis**

    Resolve dependency trees, detect conflicts, compare versions, and trace why packages appear.

-   <span class="peeq-card-icon" aria-hidden="true">🤖</span> **Built for AI agents**

    Use the built-in [agent skill](ai-agents/skill.md) and [`--format agent`](ai-agents/index.md) for structured, token-efficient output.

-   <span class="peeq-card-icon" aria-hidden="true">📄</span> **Read package files**

    Inspect `pyproject.toml`, `LICENSE`, and other files directly from a published distribution.

-   <span class="peeq-card-icon" aria-hidden="true">🛡️</span> **Vulnerability scanning**

    Check packages against the [OSV database](https://osv.dev) for known security vulnerabilities.

-   <span class="peeq-card-icon" aria-hidden="true">🔒</span> **Private registry support**

    Works with any PEP 503-compatible package index via `--index-url`.

</div>

## peeq vs pip / uv

<div class="peeq-table-wrap" markdown>

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

</div>

## Getting started

<div class="grid cards peeq-next-grid" markdown>

-   **Install peeq**

    Set up peeq with `uv tool install` or `pip`, then verify the CLI is available.

    [Installation →](installation.md)

-   **Try the core workflow**

    Inspect `requests`, view dependencies, read files, and check vulnerabilities.

    [Quickstart →](quickstart.md)

-   **Explore every command**

    Browse package inspection, dependency resolution, security, and cache commands.

    [Command reference →](commands/index.md)

</div>
