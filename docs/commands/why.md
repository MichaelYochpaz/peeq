# why

Trace why a package appears in the dependency tree.
Shows all dependency paths from root requirements to a target package, answering "why is X in my dependency tree?"

Requires [uv](https://docs.astral.sh/uv/) to be installed.
See [Installation](../installation.md#dependency-resolution) for setup details.

## Usage

```
peeq why <requirements>... --dependency <package> [options]
```

## Arguments

| Argument | Description |
|----------|-------------|
| `requirements` | One or more PEP 508 requirement strings that form the dependency tree to search. **Required.** |

## Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `-d`, `--dependency` | string | — | Package name to trace (bare name, no version specifier). **Required.** |
| `--pre`, `--prerelease` | flag | off | Include pre-release versions in resolution. |
| `--python` | string | current | Target Python version (e.g., `3.12`). |
| `--platform` | string | current | Target platform: `linux`, `win32`, `darwin`. |

## Examples

### Trace a transitive dependency

```
$ peeq why "requests>=2.31.0" -d certifi
certifi==2026.2.25 is required for requests:

  requests 2.33.1
  └── certifi 2026.2.25 (>=2023.5.7)

1 path found
```

`certifi` is a direct dependency of `requests`, so there is one path with two hops.

### Multiple paths

When a package is pulled in by multiple parents, all paths are shown:

```
$ peeq why "flask>=3.0" -d markupsafe
markupsafe==3.0.3 is required for flask:

  Path 1:
    flask 3.1.3
    └── markupsafe 3.0.3 (>=2.1.1)

  Path 2:
    flask 3.1.3
    └── jinja2 3.1.6 (>=3.1.2)
        └── markupsafe 3.0.3 (>=2.0)

  Path 3:
    flask 3.1.3
    └── werkzeug 3.1.8 (>=3.1.0)
        └── markupsafe 3.0.3 (>=2.1.1)

3 paths found
```

`markupsafe` is required through three independent paths: directly by Flask, and transitively through Jinja2 and Werkzeug.
Each hop shows the resolved version and the version specifier imposed by its parent.

### Target not found

If the target package is not in the dependency tree, peeq reports an error:

```
$ peeq why "flask>=3.0" -d numpy
Error: Package 'numpy' is not a dependency of the given requirements.
```

## See also

- [`resolve`](resolve.md) — resolve the full dependency tree without tracing a specific package.
- [`conflicts`](conflicts.md) — check whether requirements are compatible.
- [`deps`](deps.md) — view declared dependencies for a single package version.
