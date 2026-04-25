"""SQLite database layer for the peeq cache index.

Public API
----------
- `open_cache_db` — context manager for database connections.
- `queries` — typed query functions.
- `schema` — schema version constants.
"""

from peeq.database.connection import open_cache_db
from peeq.database.queries import ensure_package
from peeq.database.schema import (
    CURRENT_METADATA_SCHEMA_VERSION,
    CURRENT_SCHEMA_VERSION,
)

__all__ = [
    "CURRENT_METADATA_SCHEMA_VERSION",
    "CURRENT_SCHEMA_VERSION",
    "ensure_package",
    "open_cache_db",
]
