# cat

Print a file from inside a package archive.
This reads from the *published artifact on the registry* — what users actually install — not a source repository checkout.

## Usage

```
peeq cat <package> <path> [options]
```

## Arguments

| Argument | Description |
|----------|-------------|
| `package` | Package name. **Required.** |
| `path` | File path inside the package archive. **Required.** |

## Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--version` | string | latest | Specific version to inspect. |
| `--max-bytes` | string | 128KiB | Maximum bytes of text output. Accepts size suffixes: `128KiB`, `1MB`, `65536`. |
| `--full` | flag | — | Show complete content (no byte limit). |

## Path format

The `path` argument is a relative path inside the distribution archive. Common files:

| Path | Contents |
|------|----------|
| `pyproject.toml` | Build configuration and project metadata |
| `LICENSE` | License text |
| `PKG-INFO` | Package metadata (auto-generated) |
| `<package>/__init__.py` | Package entry point |

The archive structure depends on the distribution type (wheel vs. sdist) and the package's build configuration.

Binary files are detected automatically and display a placeholder with the file size instead of raw bytes.

## Notes

- Output is limited to 128 KiB by default to prevent oversized output in pipelines and agent contexts.
- Accepts size suffixes: `128KiB`, `1MB`, `65536`.
- Truncation applies to text content only — binary files always show a placeholder regardless of `--max-bytes`.

## Examples

### Read a project file

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
...
```

### Read the license

```bash
peeq cat requests LICENSE
```

### Read a source file from a specific version

```bash
peeq cat requests requests/api.py --version 2.28.0
```

### Save a file locally

With `--format plain` (auto-selected when piped or redirected), `cat` outputs the raw file content with no decoration — suitable for saving or piping to other tools:

```bash
peeq cat requests pyproject.toml --full > pyproject.toml
peeq cat requests LICENSE --version 2.28.0 | head -5
```

## See also

- [`artifacts`](artifacts.md) — list distribution artifacts (wheels, sdists) for a version.
- [`ls`](ls.md) — list file paths inside a package archive.
- [`download`](download.md) — download and optionally extract the full archive to disk.
