# conflicts

Check whether a set of packages can be installed together.
If resolution succeeds, display the resolved tree.
If it fails, display the conflicting requirements.

Requires [uv](https://docs.astral.sh/uv/) to be installed.
See [Installation](../installation.md#dependency-resolution) for setup details.

## Usage

```
peeq conflicts <requirements>... [options]
```

## Arguments

| Argument | Description |
|----------|-------------|
| `requirements` | One or more PEP 508 requirement strings. **Required.** |

Arguments are [PEP 508](https://peps.python.org/pep-0508/) requirement strings — not bare package names.
Pin or constrain versions with specifiers (e.g., `"requests==2.31.0"`, `"flask>=3.0"`).

## Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--pre`, `--prerelease` | flag | **on** | Include pre-release versions in resolution. Use `--no-pre` to restrict to stable versions only. |
| `--python` | string | current | Target Python version (e.g., `3.12`). |
| `--platform` | string | current | Target platform: `linux`, `win32`, `darwin`. |

### Difference from `resolve`

`conflicts` is functionally identical to [`resolve`](resolve.md), with one key difference: **pre-release versions are included by default**.
This ensures that pinned pre-release constraints are evaluated correctly when checking compatibility.

Use `--no-pre` to restrict resolution to stable versions only.

## Examples

### Compatible requirements

When all requirements are compatible, `conflicts` shows the resolved tree — the same output as `resolve`:

```
$ peeq conflicts "flask>=3.0" "click>=8.0"
Resolved 8 packages:
  - blinker==1.9.0
  - click==8.3.1
  - colorama==0.4.6
  - flask==3.1.3
  - itsdangerous==2.2.0
  - jinja2==3.1.6
  - markupsafe==3.0.3
  - werkzeug==3.1.8

Solver: uv
```

### Incompatible requirements

When requirements conflict, `conflicts` shows the specific constraints that are incompatible:

```
$ peeq conflicts "django>=4.2,<5" "django>=5.0"
CONFLICT: (unknown)

Because you require django>=4.2,<5 and django>=5.0, we can conclude
that your requirements are unsatisfiable.
```

### Cross-platform check

```bash
peeq conflicts "torch>=2.0" "tensorflow>=2.15" --python 3.12 --platform linux
```

## See also

- [`resolve`](resolve.md) — resolve dependencies with pre-releases off by default.
- [`why`](why.md) — trace why a specific package appears in the dependency tree.
