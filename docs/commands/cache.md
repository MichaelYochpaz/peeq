# cache

Manage the local cache.
peeq caches registry API responses and downloaded archives to avoid redundant network requests.

## How the cache works

The cache has two layers:

- **SQLite index** — stores package metadata (version lists, dependency info) with a configurable TTL (default: 1 hour).
  This makes repeated lookups near-instant.
- **Archive storage** — stores downloaded `.whl` and `.tar.gz` files on disk.
  Subject to a size limit (default: 2 GB), with automatic LRU eviction when the limit is exceeded.

When the archive size limit is hit, peeq evicts the least recently used archives first.
Metadata entries are preserved even after their archives are evicted, so subsequent lookups still avoid API calls.

The cache is shared across all backends and index URLs.

## Subcommands

### `cache path`

Print the cache directory path.
Output is unformatted, suitable for shell scripting.

```
$ peeq cache path
~/.cache/peeq
```

Useful in scripts:

```bash
ls $(peeq cache path)
```

### `cache info`

Show cache statistics: location, entry counts, sizes, and usage against the configured limit.

```
$ peeq cache info
Location: ~/.cache/peeq
Packages: 5
Archives: 4 distributions (11.6 MB)
Metadata only: 10 distributions
Cache size: 11.6 MB / 2.0 GB (1%)
Oldest entry: 2026-03-28 23:03
Newest entry: 2026-04-03 16:09
```

- **Packages** — distinct package names in the index.
- **Archives** — distributions with downloaded archive files on disk.
- **Metadata only** — distributions where metadata was fetched (via PEP 658) but no archive was downloaded.
- **Cache size** — total archive size vs. the configured `max_size_mb` limit.

### `cache clear`

Delete cached data.
Without options, deletes everything (database + archives).
With `--older-than`, evicts only stale entries.

```
$ peeq cache clear
Cleared 14 entries (11.6 MB).
```

#### `--older-than`

Only clear entries older than the specified duration.
Supports duration suffixes:

| Suffix | Unit |
|--------|------|
| `s` | Seconds |
| `m` | Minutes |
| `h` | Hours |
| `d` | Days |

```bash
peeq cache clear --older-than 30d
peeq cache clear --older-than 2h
```

### `cache dump`

Export the full cache index as JSON for debugging.
Outputs the raw SQLite contents including timestamps, file paths, and metadata.

```bash
peeq cache dump
```

The output is a JSON object, regardless of the `--format` flag.

### `cache check`

Run integrity checks on the cache database.
Useful for diagnosing corruption issues.

```
$ peeq cache check
journal_mode: wal
synchronous: 1
foreign_keys: 1
temp_store: 2
total_bytes: 57344
freelist_count: 0
quick_check: ok
```

A `quick_check: ok` result means the database is healthy.
If it reports errors, clear the cache with `peeq cache clear` to rebuild it.

## Bypassing the cache

Use the `--no-cache` global option to skip the cache entirely for a single command.
This uses a temporary directory that is discarded after the command completes:

```bash
peeq info requests --no-cache
```

See [Configuration](../configuration.md) for cache directory and size limit settings.

## See also

- [Configuration](../configuration.md) — configure cache directory, TTL, and size limits.
