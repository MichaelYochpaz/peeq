"""Caching layer: SQLite index + archive file storage.

Public API
----------
- `CacheManager` — orchestrates SQLite index + archive file storage.

Exceptions
----------
- `HashMismatchError` — SHA-256 verification failed.
- `ArchiveNotCachedError` — archive not in cache.
"""

from peeq.cache.manager import (
    ArchiveNotCachedError,
    CacheManager,
    HashMismatchError,
    StoreResult,
)

__all__ = [
    "ArchiveNotCachedError",
    "CacheManager",
    "HashMismatchError",
    "StoreResult",
]
