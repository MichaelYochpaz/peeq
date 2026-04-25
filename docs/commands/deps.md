# deps

Show package dependencies, with optional diff between two versions or platform-specific metadata via wheel tags.

## Usage

```
peeq deps <package> [options]
```

## Arguments

| Argument | Description |
|----------|-------------|
| `package` | Package name. **Required.** |

## Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--version` | string | latest | Specific version to inspect. |
| `--tag` | string | -- | Wheel tag for platform-specific metadata (e.g., `cp312-cp312-win_amd64`). |
| `--diff` | string | -- | Compare dependencies against this version. |

### Option interaction rules

- `--diff` requires `--version`.
  The `--version` value is the base version; `--diff` is the version to compare against.
  The output shows what changed between the two.

## Dependency output

Dependencies are grouped into **required** (installed unconditionally) and **optional** (installed only when a specific extra is requested).
The output also shows the metadata source — either `pep658` (fetched via PEP 658 metadata endpoint) or `extracted` (parsed from a downloaded archive).

## Diff mode

When `--diff` is specified, peeq compares the dependency lists of two versions and reports:

- **Changed** — dependencies present in both versions but with different version specifiers.
- **Added** — dependencies in the target version that are not in the base version.
- **Removed** — dependencies in the base version that are not in the target version.
- **Unchanged** — a count of dependencies that are identical in both versions.

## Wheel tags

By default, peeq reads metadata from the first available distribution file (typically a universal wheel).
Use `--tag` to select a specific wheel when a package ships platform-specific builds with different dependency sets.

A wheel tag has three parts: `{python}-{abi}-{platform}`. Examples:

| Tag | Meaning |
|-----|---------|
| `cp312-cp312-win_amd64` | CPython 3.12, Windows x64 |
| `cp311-cp311-manylinux_2_17_x86_64` | CPython 3.11, Linux x64 |
| `cp312-cp312-macosx_11_0_arm64` | CPython 3.12, macOS ARM |

Use [`artifacts`](artifacts.md) to see which distribution artifacts (and tags) are available for a version.

## Examples

### View dependencies

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

### Dependencies for a specific version

```
$ peeq deps requests --version 2.28.0
Dependencies for requests 2.28.0:
  - charset-normalizer ~=2.0.0
  - idna <4,>=2.5
  - urllib3 <1.27,>=1.21.1
  - certifi >=2017.4.17

Optional [socks]:
  - pysocks !=1.5.7,>=1.5.6

Optional [use-chardet-on-py3]:
  - chardet <5,>=3.0.2

Source: pep658 (requests-2.28.0-py3-none-any.whl)
```

### Compare dependencies between versions

```
$ peeq deps requests --version 2.28.0 --diff 2.33.1
Dependency changes for requests (2.28.0 -> 2.33.1):

Changed:
  charset-normalizer ~=2.0.0 -> <4,>=2
  urllib3 <1.27,>=1.21.1 -> <3,>=1.26
  certifi >=2017.4.17 -> >=2023.5.7
  chardet [use-chardet-on-py3] <5,>=3.0.2 -> <8,>=3.0.2

Added:
  (none)

Removed:
  (none)

Unchanged: 2 dependencies
```

## See also

- [`info`](info.md) — include dependencies as part of a broader report with `--deps`.
- [`resolve`](resolve.md) — resolve a full dependency tree from PEP 508 requirements.
- [`artifacts`](artifacts.md) — list distribution artifacts to find wheel tags for `--tag`.
