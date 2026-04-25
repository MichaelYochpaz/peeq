# Installation

## Prerequisites

- **Python 3.10** or later.
- **[uv](https://docs.astral.sh/uv/)** — recommended for installation. Also required at runtime by the `resolve`, `conflicts`, and `why` commands.

## Install peeq

=== "uv"

    Install as a global CLI tool:

    ```bash
    uv tool install peeq
    ```

=== "pip"

    ```bash
    pip install peeq
    ```

### Zero-install with uvx

Run peeq without installing it:

```bash
uvx peeq info requests
```

This downloads peeq into a temporary environment and runs it immediately.
Useful for one-off inspections, but repeated use is slower than a permanent install.

## As a project dependency

If you want peeq available inside a project's virtual environment:

=== "uv"

    ```bash
    uv add peeq
    ```

=== "pip"

    ```bash
    pip install peeq
    ```

## Verify installation

```bash
peeq --version
```

If installed correctly, this prints peeq's version number.

## Dependency resolution

Three commands — `resolve`, `conflicts`, and `why` — use [uv](https://docs.astral.sh/uv/) as a resolution backend.

If you installed peeq with `uv tool install`, uv is already on your PATH and these commands work out of the box.

For CI pipelines or automation environments where uv is not globally installed, bundle it as a dependency instead:

```bash
pip install peeq[uv]
```

All other commands (`info`, `versions`, `deps`, `artifacts`, `cat`, `ls`, `download`, `vulns`, and all `cache` subcommands) work without uv.
