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
| `--prefix` | string | — | Show entries under this path (e.g., `src/`). |
| `-r`, `--recursive` | flag | — | Flat recursive file listing. |

## Notes

- Shows up to 50 entries by default. Use `--all` to show all entries.
- Paths shown are archive-relative — use them directly with `cat`.
- In non-recursive mode (default), directories are shown with file counts and subdirectory counts.

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

### Combined

```bash
peeq ls requests --prefix src/ -r --all
```

### List archive contents for a specific version

```bash
peeq ls requests --version 2.28.0
```

## See also

- [`cat`](cat.md) — print a specific file from inside the archive.
- [`artifacts`](artifacts.md) — list distribution artifacts (wheels, sdists) on the registry.
- [`download`](download.md) — download and optionally extract the full archive to disk.
