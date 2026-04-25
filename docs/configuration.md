# Configuration

peeq loads settings from a TOML configuration file, environment variables, and field defaults.
CLI flags override all other sources for the duration of a single command.

## Configuration file

The configuration file is located at the platform-standard config directory:

| Platform | Path |
|----------|------|
| Linux | `~/.config/peeq/config.toml` |
| macOS | `~/Library/Application Support/peeq/config.toml` |
| Windows | `%LOCALAPPDATA%\peeq\config.toml` |

To print the exact path for your system:

```bash
peeq config path
```

The file is optional — peeq works with sensible defaults if no config file exists.

## Priority order

Settings are resolved from highest to lowest priority:

1. **CLI flags** — e.g., `--no-cache`, `--format`, `--index-url`
2. **Environment variables** — `PEEQ_` prefix (see below)
3. **TOML config file** — if it exists
4. **Field defaults** — built-in defaults

## Full example

A `config.toml` with all settings at their default values:

```toml
[cache]
dir = "~/.cache/peeq"           # Platform-dependent default
api_ttl_seconds = 3600          # 1 hour
max_size_mb = 2000              # 2 GB

[extraction]
max_size_mb = 500               # Maximum total uncompressed size
max_files = 50000               # Maximum files per archive
max_file_size_mb = 100          # Maximum single file size
```

## Settings reference

### `[cache]`

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `dir` | path | platform-dependent | Root directory for all cache data (database + archives). |
| `api_ttl_seconds` | integer | `3600` | TTL in seconds for cached registry API data (package listings, metadata). |
| `max_size_mb` | integer | `2000` | Maximum total size of cached archive files in megabytes. Set to `0` for unlimited. |

When the cache exceeds `max_size_mb`, the least recently used archives are evicted automatically.
Metadata entries are preserved even after their archives are evicted, so repeated lookups still avoid API calls.

### `[extraction]`

Resource limits for archive extraction.
These protect against [decompression bombs](https://en.wikipedia.org/wiki/Zip_bomb) when using `cat`, `ls`, `download --extract`, and dependency metadata extraction.

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `max_size_mb` | integer | `500` | Maximum total uncompressed size in megabytes. |
| `max_files` | integer | `50000` | Maximum number of files in an archive. |
| `max_file_size_mb` | integer | `100` | Maximum size of a single extracted file in megabytes. |

## Environment variables

All settings can be overridden with environment variables using the `PEEQ_` prefix. Nested keys use `_` as a delimiter:

| Setting | Environment variable |
|---------|---------------------|
| `cache.dir` | `PEEQ_CACHE_DIR` |
| `cache.api_ttl_seconds` | `PEEQ_CACHE_API_TTL_SECONDS` |
| `cache.max_size_mb` | `PEEQ_CACHE_MAX_SIZE_MB` |
| `extraction.max_size_mb` | `PEEQ_EXTRACTION_MAX_SIZE_MB` |
| `extraction.max_files` | `PEEQ_EXTRACTION_MAX_FILES` |
| `extraction.max_file_size_mb` | `PEEQ_EXTRACTION_MAX_FILE_SIZE_MB` |

Environment variables take priority over the TOML config file but are overridden by CLI flags.

## See also

- [`cache`](commands/cache.md) — manage the cache (clear, inspect, check).
