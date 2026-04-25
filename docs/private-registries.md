# Private Registries

peeq can query any Python package index that implements the PyPI JSON API ([PEP 691](https://peps.python.org/pep-0691/)) or the Simple Repository API ([PEP 503](https://peps.python.org/pep-0503/)).

## Specifying a custom index

Use `--index-url` (or `-i`) to point peeq at a different registry:

```bash
peeq info my-package --index-url https://private.registry/simple/
peeq versions my-package -i https://private.registry/simple/
```

All commands support `--index-url`.
The URL should point to the base of the index (the root that contains package name directories).

## Backend types

peeq supports two backend types:

| Backend | Protocol | Used for |
|---------|----------|----------|
| `pypi` | PEP 691 JSON API | PyPI and compatible registries that serve JSON responses. |
| `simple` | PEP 503 Simple API | Generic Python package indexes that serve HTML responses. |

### Auto-detection

By default, peeq auto-detects the backend:

- **Known domains** (`pypi.org`, `test.pypi.org`) — uses the `pypi` backend.
- **All other URLs** — defaults to the `simple` backend.

### Manual override

Use `--backend` to force a specific backend type:

```bash
peeq info my-package -i https://custom.registry/ --backend pypi
peeq info my-package -i https://custom.registry/ --backend simple
```

This is useful when a registry supports PEP 691 JSON but is not on a known domain, or when auto-detection picks the wrong backend.

## Examples

### Private PEP 503 server

```bash
peeq info my-internal-package -i https://devpi.internal.example.com/root/pypi/simple/
peeq deps my-internal-package -i https://devpi.internal.example.com/root/pypi/simple/
```

### TestPyPI

```bash
peeq info my-package -i https://test.pypi.org
```

TestPyPI is a known PyPI domain, so the `pypi` backend is auto-selected.

## Limitations

- **Authentication** — peeq does not currently support authenticated registries (no token, basic auth, or keyring integration).
  Only unauthenticated indexes are supported.
- **Backend scope** — `--index-url` applies to a single command invocation.
  There is no persistent index configuration in the config file.

## See also

- [Command Reference](commands/index.md) — all commands support `--index-url` and `--backend` as global options.
