# download

Download a package archive to the local filesystem.
Serves from cache if available, downloads from the registry if not.

## Usage

```
peeq download <package> [options]
```

## Arguments

| Argument | Description |
|----------|-------------|
| `package` | Package name. **Required.** |

## Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--version` | string | latest | Specific version to download. |
| `--output-dir`, `-o` | path | `.` (current directory) | Output directory for the downloaded file or extracted contents. |
| `--extract` | flag | off | Extract archive contents instead of copying the archive file. |

## Examples

### Download a package archive

```
$ peeq download requests
Downloaded to: .
```

This places the archive file (e.g., `requests-2.33.1-py3-none-any.whl`) in the current directory.

### Download to a specific directory

```bash
peeq download requests -o ./vendor
```

### Extract archive contents

```
$ peeq download requests --extract
Extracted to: .
```

With `--extract`, the archive contents are extracted into the output directory instead of copying the archive file itself.
This is useful for reading or modifying package source without manually unpacking.

### Download a specific version

```bash
peeq download requests --version 2.28.0 -o ./archives
```

## See also

- [`artifacts`](artifacts.md) — list distribution artifacts before downloading.
- [`cat`](cat.md) — print a file from inside an archive without downloading.
