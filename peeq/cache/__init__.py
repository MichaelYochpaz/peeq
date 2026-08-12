"""Caching layer: SQLite index + archive file storage.

Public API
----------
- `CacheManager` — orchestrates SQLite index + archive file storage.

Exceptions
----------
- `HashMismatchError` — SHA-256 verification failed.
- `ArchiveNotCachedError` — archive not in cache.
- `UnsafeArchivePathError` — archive path escaped the cache root.
"""

from peeq.cache.manager import (
    ArchiveNotCachedError,
    CacheManager,
    HashMismatchError,
    StoreResult,
    UnsafeArchivePathError,
)

__all__ = [
    "ArchiveNotCachedError",
    "CacheManager",
    "HashMismatchError",
    "StoreResult",
    "UnsafeArchivePathError",
]
