# info

Show package metadata with optional sections for version history, vulnerability scan, and dependency list.

## Usage

```
peeq info <package> [options]
```

## Arguments

| Argument | Description |
|----------|-------------|
| `package` | Package name. **Required.** |

## Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--versions` | flag | off | Include version list in the report. |
| `--vulns` | flag | off | Include vulnerability scan (queries the OSV database). |
| `--deps` | flag | off | Include dependency list. |
| `--full` | flag | off | Include all optional sections (versions, vulnerabilities, dependencies). |
| `--version` | string | latest | Target version for the `--deps` and `--vulns` sections. |
| `--limit` | integer | `20` | Maximum number of versions to show. |

### Option interaction rules

- `--version` requires at least one of `--deps`, `--vulns`, or `--full`.
  It targets the deps and vulns sections — without one of these flags, there is nothing to apply it to.
- `--limit` only takes effect when `--versions` or `--full` is active.
  Changing `--limit` without one of these flags produces an error.
- `--full` is equivalent to passing `--versions --vulns --deps` together.

## Examples

### Basic package info

```
$ peeq info requests
Package: requests
Summary: Python HTTP for Humans.
Latest Version: 2.33.1 (2026-03-30)
Versions: 156
License: Apache-2.0
Python: >=3.10
Registry: pypi.org
Documentation: https://requests.readthedocs.io
Source: https://github.com/psf/requests
```

### Include version history

```
$ peeq info requests --versions --limit 5
Package: requests
Summary: Python HTTP for Humans.
Latest Version: 2.33.1 (2026-03-30)
Versions: 156
License: Apache-2.0
Python: >=3.10
Registry: pypi.org
Documentation: https://requests.readthedocs.io
Source: https://github.com/psf/requests

requests versions (showing 5 of 156):
  - 2.33.1 (latest)
  - 2.33.0
  - 2.32.5
  - 2.32.4
  - 2.32.3
```

### Vulnerability scan for a specific version

```
$ peeq info requests --version 2.31.0 --vulns
Package: requests
Summary: Python HTTP for Humans.
Latest Version: 2.33.1 (2026-03-30)
Versions: 156
License: Apache-2.0
Python: >=3.7
Registry: pypi.org
Documentation: https://requests.readthedocs.io
Source: https://github.com/psf/requests

Vulnerabilities for requests 2.31.0:

ID: GHSA-9hjg-9r4m-mvj7
CVE: CVE-2024-47081
Severity: MODERATE
Summary: Requests vulnerable to .netrc credentials leak via malicious URLs
Fixed in: 2.32.4

ID: GHSA-9wx4-h78v-vm56
CVE: CVE-2024-35195
Severity: MODERATE
Summary: Requests `Session` object does not verify requests after making first request with verify=False
Fixed in: 2.32.0

ID: GHSA-gc5v-m9x4-r6x2
CVE: CVE-2026-25645
Severity: MODERATE
Summary: Requests has Insecure Temp File Reuse in its extract_zipped_paths() utility function
Fixed in: 2.33.0

Recommendation: Upgrade to >= 2.33.0
```

### Full report

Use `--full` to include versions, vulnerabilities, and dependencies in a single report:

```bash
peeq info requests --full
```

This is equivalent to running `peeq info requests --versions --vulns --deps`.

## See also

- [`versions`](versions.md) — list and filter versions independently.
- [`deps`](deps.md) — view dependencies with diff and wheel tag options.
- [`vulns`](vulns.md) — standalone vulnerability check.
