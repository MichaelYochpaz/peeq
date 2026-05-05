# ls

List file paths inside a package's distribution archive.
This shows the internal directory structure of the published artifact — useful for discovering paths to use with [`cat`](cat.md).

## Usage

```
peeq ls <package> [options]
```

## Arguments

| Argument | Description |
|----------|-------------|
| `package` | Package name. **Required.** |

## Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--version` | string | latest | Specific version to inspect. |
| `--limit` | integer | 50 | Maximum entries to show. |
| `--all` | flag | — | Show all entries (no limit). |
| `--offset` | integer | 0 | Skip the first N entries before applying `--limit`. |
| `--prefix` | string | — | Show entries under this path (e.g., `src/`). |
| `-r`, `--recursive` | flag | — | Flat recursive file listing. |
| `-g`, `--glob` | string | — | Recursively search for files matching a glob pattern (implies `-r`). Repeatable with OR semantics. |

## Notes

- Shows up to 50 entries by default. Use `--all` to show all entries.
- `--offset` skips entries after filtering (`--prefix`, `--glob`), before `--limit`. Can combine with `--all` to skip N entries and show the rest.
- Paths shown are archive-relative — use them directly with `cat`.
- In non-recursive mode (default), directories are shown with file counts and subdirectory counts.

## Glob patterns

`-g` / `--glob` filters archive contents by glob pattern. Patterns use standard glob syntax (`*`, `**`, `?`, `[...]`) with a few behaviors worth knowing:

**Basename matching** — Patterns without `/` match the filename at any depth, like `find -name`. The pattern `*.py` matches `setup.py`, `src/api.py`, and `src/pkg/utils.py` alike.

**Full-path matching** — Patterns containing `/` match against the full relative path. `src/*.py` matches `src/api.py` but not `src/pkg/api.py` (because `*` doesn't cross `/`). Use `**` for recursive descent: `src/**/*.py` matches `.py` files at any depth under `src/`.

**Prefix-relative matching** — When `--prefix` is set, patterns match against the path relative to the prefix. With `--prefix src/`, the pattern `pkg/*.py` matches `src/pkg/api.py` (tested against `pkg/api.py`). This is equivalent to `-g "src/pkg/*.py"` without `--prefix`.

Matching is always case-sensitive. Wildcards match dotfiles (e.g., `*` matches `.gitignore`). Always quote patterns to prevent shell expansion.

## Examples

### Non-recursive (default)

```bash
peeq ls requests
```

### Prefix drill-down

```bash
peeq ls requests --prefix src/
```

### Recursive listing

```bash
peeq ls requests -r
```

### Glob search

Find all Python files:

```bash
peeq ls requests -g "*.py"
```

Multiple patterns combine with OR semantics:

```bash
peeq ls requests -g "*.py" -g "*.json"
```

Search within a subdirectory:

```bash
peeq ls flask -g "test_*" --prefix tests/
```

Match files at a specific directory level:

```bash
peeq ls flask -g "src/**/*.py"
```

### Combined

```bash
peeq ls requests --prefix src/ -r --all
```

### Specific version

```bash
peeq ls requests --version 2.28.0
```

### Paginate with offset

```bash
peeq ls requests -r --limit 20 --offset 20
```

## See also

- [`cat`](cat.md) — print a specific file from inside the archive.
- [`artifacts`](artifacts.md) — list distribution artifacts (wheels, sdists) on the registry.
- [`download`](download.md) — download and optionally extract the full archive to disk.
