# artifacts

List distribution artifacts (wheels, sdists) available for a package version on the registry.

## Usage

```
peeq artifacts <package> [options]
```

## Arguments

| Argument | Description |
|----------|-------------|
| `package` | Package name. **Required.** |

## Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--version` | string | latest | Specific version to inspect. |

## Examples

### List distribution artifacts

```
$ peeq artifacts requests
Distribution artifacts for requests 2.33.1:
  - requests-2.33.1-py3-none-any.whl (wheel, 63.4 KB, Python >=3.10)
  - requests-2.33.1.tar.gz (sdist, 131.0 KB, Python >=3.10)
```

Each entry shows the filename, distribution type (wheel or sdist), file size, and required Python version.

For packages with platform-specific builds, this list includes one entry per wheel tag.
Use the filenames to identify wheel tags for the [`deps --tag`](deps.md) option.

## See also

- [`cat`](cat.md) — print a file from inside an archive.
- [`ls`](ls.md) — list file paths inside a package archive.
- [`download`](download.md) — download the archive to disk.
- [`deps`](deps.md) — use `--tag` to read dependencies from a specific wheel.
