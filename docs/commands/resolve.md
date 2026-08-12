# resolve

Resolve the full dependency tree for one or more requirements, producing a flat list of pinned package versions.

Requires [uv](https://docs.astral.sh/uv/) to be installed.
See [Installation](../installation.md#dependency-resolution) for setup details.

## Usage

```
peeq resolve <requirements>... [options]
```

## Arguments

| Argument | Description |
|----------|-------------|
| `requirements` | One or more registry package requirements. **Required.** |

peeq supports the registry-only subset of [PEP 508](https://peps.python.org/pep-0508/): package names, extras, version specifiers, and environment markers.
You can pin or constrain versions with specifiers (e.g., `"requests==2.31.0"`, `"flask>=3.0"`), while a bare name like `"requests"` resolves to the latest compatible version.

Direct URLs, VCS references, local paths, editable requirements, wheels, source archives, and requirements-file directives are rejected.
Packages available only as source distributions also fail when resolving them would require executing a build backend.

Quote each requirement in your shell to prevent specifier characters (`>`, `<`, `!`) from being interpreted.

### Resolver isolation

peeq resolves against the exact Simple API endpoint selected by `--index-url`. It disables uv configuration-file discovery and does not inherit `UV_*`, `PIP_*`, active-virtual-environment, or Conda settings that could silently change the package universe, build policy, Python selection, TLS verification, or cache behavior.

Standard proxy variables (`HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, and `NO_PROXY`) and certificate variables (`SSL_CERT_FILE`, `SSL_CERT_DIR`, and `SSL_CLIENT_CERT`) remain available for corporate and private-registry networking. uv uses an isolated temporary cache and credential store for each peeq resolution.

## Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--pre`, `--prerelease` | flag | off | Include pre-release versions in resolution. |
| `--python` | string | current | Target Python version (e.g., `3.12`). |
| `--platform` | string | current | Target platform: `linux`, `win32`, `darwin`. |

### Cross-platform resolution

By default, peeq resolves for the current host environment.
Use `--python` and `--platform` to resolve for a different target:

```bash
peeq resolve "requests>=2.31.0" --python 3.12 --platform linux
```

This evaluates [PEP 508 environment markers](https://peps.python.org/pep-0508/#environment-markers) against the specified target, so platform-conditional dependencies are included or excluded correctly.

## Examples

### Resolve a single requirement

```
$ peeq resolve "flask>=3.0"
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

### Resolve multiple requirements

```
$ peeq resolve "requests>=2.31.0" "flask>=3.0"
Resolved 13 packages:
  - blinker==1.9.0
  - certifi==2026.2.25
  - charset-normalizer==3.4.7
  - click==8.3.1
  - colorama==0.4.6
  - flask==3.1.3
  - idna==3.11
  - itsdangerous==2.2.0
  - jinja2==3.1.6
  - markupsafe==3.0.3
  - requests==2.33.1
  - urllib3==2.6.3
  - werkzeug==3.1.8

Solver: uv
```

### Resolve for a different platform

```
$ peeq resolve "requests>=2.31.0" --python 3.12 --platform linux
Resolved 5 packages:
  - certifi==2026.2.25
  - charset-normalizer==3.4.7
  - idna==3.11
  - requests==2.33.1
  - urllib3==2.6.3

Solver: uv
```

Note that `colorama` is absent — it is only required on Windows.

### Handle conflicts

When requirements are incompatible, `resolve` exits with an error and displays the conflicting constraints:

```
$ peeq resolve "django>=4.2,<5" "django>=5.0"
CONFLICT: (unknown)

Because you require django>=4.2,<5 and django>=5.0, we can conclude
that your requirements are unsatisfiable.
```

Use [`conflicts`](conflicts.md) for the same behavior with pre-release versions included by default.

## See also

- [`conflicts`](conflicts.md) — check compatibility with pre-releases enabled by default.
- [`why`](why.md) — trace why a specific package appears in the resolved tree.
- [`deps`](deps.md) — view declared dependencies for a single package.
