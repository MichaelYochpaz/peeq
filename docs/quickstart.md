# Quickstart

This walkthrough demonstrates peeq's core commands using the `requests` package.
Each example shows the command and its output.

## Get package info

Start by inspecting a package with `peeq info`:

```
$ peeq info requests
Package: requests
Summary: Python HTTP for Humans.
Latest Version: 2.33.1 (2026-03-30)
Versions: 156
License: Apache-2.0
Registry: pypi.org
Documentation: https://requests.readthedocs.io
Source: https://github.com/psf/requests

--- Version 2.33.1 (latest) ---
Python: >=3.10
```

The `info` command shows package metadata from the registry.
Add `--full` to include versions, dependencies, and vulnerability data in a single report:

```bash
peeq info requests --full
```

## List versions

Use `peeq versions` to see available releases:

```
$ peeq versions requests --limit 5
requests versions (showing 5 of 156):
  - 2.33.1 (2026-03-30) (latest)
  - 2.33.0 (2026-03-25)
  - 2.32.5 (2025-08-18)
  - 2.32.4 (2025-06-09)
  - 2.32.3 (2024-05-29)
```

Filter versions with PEP 440 specifiers using `--matching`:

```bash
peeq versions requests --matching ">=2.30,<2.33"
```

## View dependencies

Use `peeq deps` to see what a package depends on:

```
$ peeq deps requests
Dependencies for requests 2.33.1:
  - charset-normalizer <4,>=2
  - idna <4,>=2.5
  - urllib3 <3,>=1.26
  - certifi >=2023.5.7

Optional [socks]:
  - pysocks !=1.5.7,>=1.5.6

Optional [use-chardet-on-py3]:
  - chardet <8,>=3.0.2

Source: pep658 (requests-2.33.1-py3-none-any.whl)
```

When no `--version` is specified, peeq defaults to the latest version.
Use `--version` to target a specific release, or `--diff` to compare dependencies between two versions:

```bash
peeq deps requests --version 2.28.0 --diff 2.33.0
```

## Inspect a file

Use `peeq cat` to read any file from a package's distribution archive:

```
$ peeq cat requests pyproject.toml
[build-system]
requires = ["setuptools>=61.0"]
build-backend = "setuptools.build_meta"

[project]
name = "requests"
description = "Python HTTP for Humans."
readme = "README.md"
license = {text = "Apache-2.0"}
requires-python = ">=3.10"
dependencies = [
    "charset_normalizer>=2,<4",
    "idna>=2.5,<4",
    "urllib3>=1.26,<3",
    "certifi>=2023.5.7"
]
...
```

This inspects files from the *published artifact on PyPI* — what users actually install — not a source repository checkout.

## Check for vulnerabilities

Use `peeq vulns` to query the [OSV database](https://osv.dev) for known vulnerabilities:

```
$ peeq vulns requests
Vulnerabilities for requests 2.33.1:
No known vulnerabilities.
```

## Output formats

peeq automatically adapts its output based on context:

- **Terminal** — rich formatting with panels, colors, and tables (`pretty` format).
- **Piped or redirected** — clean text with no ANSI codes (`plain` format).

The examples in this guide show `plain` output.
To explicitly select a format, use `--format` / `-f`:

```bash
peeq info requests --format=json     # Structured JSON
peeq info requests --format=agent    # XML tags optimized for AI agents
```

## Next steps

- Browse the [command reference](commands/index.md) for the full list of commands, options, and detailed examples.
