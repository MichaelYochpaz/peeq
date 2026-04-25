# vulns

Check for known security vulnerabilities affecting a package version.
Queries the [OSV](https://osv.dev) (Open Source Vulnerabilities) database.

## Usage

```
peeq vulns <package> [options]
```

## Arguments

| Argument | Description |
|----------|-------------|
| `package` | Package name. **Required.** |

## Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--version` | string | latest | Specific version to check. |

## How it works

peeq queries the [OSV API](https://osv.dev) for vulnerabilities affecting the specified package in the PyPI ecosystem.
The query is scoped to an exact version — it returns only vulnerabilities that affect the version you specify (or the latest version, by default).

Each vulnerability in the report includes:

- **ID** — the OSV identifier (typically a GHSA ID).
- **CVE** — the associated CVE alias, if one exists.
- **Severity** — a severity label (e.g., MODERATE, HIGH) from the advisory database.
- **Summary** — a brief description of the vulnerability.
- **Fixed in** — the version(s) where the vulnerability was patched.

When vulnerabilities are found, peeq shows a recommendation with the minimum version that fixes all reported issues.

No authentication or API keys are required.
The OSV API is free and has no rate limits.

## Examples

### Check the latest version

```
$ peeq vulns requests
Vulnerabilities for requests 2.33.1:

No known vulnerabilities.
```

### Check an older version

```
$ peeq vulns requests --version 2.31.0
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

## See also

- [`info`](info.md) — include a vulnerability scan as part of a broader package report with `--vulns` or `--full`.
