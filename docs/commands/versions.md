# versions

List all available versions of a package, with options to limit results, filter by PEP 440 specifier, or show only yanked versions.

## Usage

```
peeq versions <package> [options]
```

## Arguments

| Argument | Description |
|----------|-------------|
| `package` | Package name. **Required.** |

## Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--limit` | integer | all | Maximum number of versions to show. |
| `--yanked` | flag | off | Show only yanked versions with their yank reasons. |
| `--matching` | string | -- | PEP 440 version specifier to filter versions (e.g., `">=2.0,<3"`). |
| `--pre`, `--prerelease` | flag | off | Include pre-release versions when using `--matching`. |

### Option interaction rules

- `--pre` requires `--matching`. Pre-release filtering only applies when a specifier is active.

### PEP 440 specifiers

The `--matching` option accepts standard [PEP 440](https://peps.python.org/pep-0440/) version specifiers. Multiple constraints can be combined with commas:

| Specifier | Meaning |
|-----------|---------|
| `>=2.0` | Version 2.0 or later |
| `<3` | Below version 3 |
| `>=2.0,<3` | Between 2.0 (inclusive) and 3 (exclusive) |
| `~=2.28` | Compatible release: `>=2.28,<3.0` |
| `!=2.32.1` | Exclude a specific version |

## Examples

### List recent versions

```
$ peeq versions requests --limit 5
requests versions (showing 5 of 156):
  - 2.33.1 (latest)
  - 2.33.0
  - 2.32.5
  - 2.32.4
  - 2.32.3
```

### Filter with a version specifier

```
$ peeq versions requests --matching ">=2.30,<2.33"
requests versions (8 of 156 matching >=2.30,<2.33):
  - 2.32.5 (latest)
  - 2.32.4
  - 2.32.3
  - 2.32.2
  - 2.32.1 (yanked: Yanked due to conflicts with CVE-2024-35195 mitigation )
  - 2.32.0 (yanked: Yanked due to conflicts with CVE-2024-35195 mitigation)
  - 2.31.0
  - 2.30.0
```

Yanked versions appear in the output with their yank reason when they match the specifier.
They are included in the count but are not considered "latest."

### Show only yanked versions

```
$ peeq versions requests --yanked
requests versions (2):
  - 2.32.1 (latest) (yanked: Yanked due to conflicts with CVE-2024-35195 mitigation )
  - 2.32.0 (yanked: Yanked due to conflicts with CVE-2024-35195 mitigation)
```

## See also

- [`info`](info.md) — include a version list as part of a broader package report with `--versions`.
