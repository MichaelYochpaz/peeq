"""Tests for database connection lifecycle and PRAGMA configuration."""

from __future__ import annotations

import sqlite3
from unittest.mock import patch

from peeq.database.connection import open_cache_db
from peeq.database.schema import CURRENT_SCHEMA_VERSION


class TestOpenCacheDb:
    """Tests for the open_cache_db context manager."""

    def test_creates_database_file(self, tmp_path):
        with open_cache_db(tmp_path) as conn:
            assert conn is not None
        assert (tmp_path / "cache.db").exists()

    def test_creates_parent_directories(self, tmp_path):
        nested = tmp_path / "deep" / "nested" / "dir"
        with open_cache_db(nested):
            pass
        assert (nested / "cache.db").exists()

    def test_tables_created(self, tmp_path):
        with open_cache_db(tmp_path) as conn:
            tables = conn.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name").fetchall()
            table_names = [r[0] for r in tables]
        assert "packages" in table_names
        assert "distributions" in table_names
        assert "dependencies" in table_names

    def test_indices_created(self, tmp_path):
        with open_cache_db(tmp_path) as conn:
            indices = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='index' AND name LIKE 'idx_%' ORDER BY name"
            ).fetchall()
            index_names = [r[0] for r in indices]
        assert "idx_distributions_sha256" in index_names
        assert "idx_distributions_last_accessed" in index_names
        assert "idx_dep_name" in index_names
        assert "idx_dep_distribution" in index_names

    def test_row_factory_is_row(self, tmp_path):
        with open_cache_db(tmp_path) as conn:
            assert conn.row_factory is sqlite3.Row


class TestPragmas:
    """Verify PRAGMAs are applied correctly."""

    def test_wal_mode(self, tmp_path):
        with open_cache_db(tmp_path) as conn:
            mode = conn.execute("PRAGMA journal_mode;").fetchone()[0]
        assert mode == "wal"

    def test_synchronous_normal(self, tmp_path):
        with open_cache_db(tmp_path) as conn:
            sync = conn.execute("PRAGMA synchronous;").fetchone()[0]
        # 1 = NORMAL
        assert sync == 1

    def test_foreign_keys_enabled(self, tmp_path):
        with open_cache_db(tmp_path) as conn:
            fk = conn.execute("PRAGMA foreign_keys;").fetchone()[0]
        assert fk == 1

    def test_temp_store_memory(self, tmp_path):
        with open_cache_db(tmp_path) as conn:
            ts = conn.execute("PRAGMA temp_store;").fetchone()[0]
        # 2 = MEMORY
        assert ts == 2

    def test_busy_timeout(self, tmp_path):
        with open_cache_db(tmp_path) as conn:
            bt = conn.execute("PRAGMA busy_timeout;").fetchone()[0]
        assert bt == 5000

    def test_cache_size(self, tmp_path):
        with open_cache_db(tmp_path) as conn:
            cs = conn.execute("PRAGMA cache_size;").fetchone()[0]
        assert cs == -4000

    def test_journal_size_limit(self, tmp_path):
        with open_cache_db(tmp_path) as conn:
            jsl = conn.execute("PRAGMA journal_size_limit;").fetchone()[0]
        assert jsl == 4194304


class TestWindowsRetry:
    """Test the _connect_with_retry logic."""

    def test_non_windows_no_retry(self, tmp_path):
        """On non-Windows, connect directly (no retry loop)."""
        with patch("peeq.database.connection.platform") as mock_platform:
            mock_platform.system.return_value = "Linux"
            with open_cache_db(tmp_path) as conn:
                assert conn is not None

    def test_windows_retry_on_error(self, tmp_path):
        """On Windows, connection succeeds on first try when no lock contention."""
        with patch("peeq.database.connection.platform") as mock_platform:
            mock_platform.system.return_value = "Windows"
            # Should work on first try (no actual antivirus lock)
            with open_cache_db(tmp_path) as conn:
                assert conn is not None


class TestSchemaVersioning:
    """Test schema version mismatch handling."""

    def test_schema_version_set(self, tmp_path):
        with open_cache_db(tmp_path) as conn:
            version = conn.execute("PRAGMA user_version;").fetchone()[0]
        assert version == CURRENT_SCHEMA_VERSION

    def test_schema_recreated_on_mismatch(self, tmp_path):
        """If schema version differs, tables are dropped and recreated."""
        # Create initial schema
        with open_cache_db(tmp_path) as conn, conn:
            conn.execute("INSERT INTO packages (registry, name, fetched_at) VALUES ('pypi.org', 'test', 1000)")

        # Manually bump user_version to simulate a future version
        db_path = tmp_path / "cache.db"
        raw_conn = sqlite3.connect(str(db_path))
        raw_conn.execute("PRAGMA user_version = 999;")
        raw_conn.close()

        # Re-open — should detect mismatch and recreate
        with open_cache_db(tmp_path) as conn:
            version = conn.execute("PRAGMA user_version;").fetchone()[0]
            assert version == CURRENT_SCHEMA_VERSION
            # Old data should be gone
            count = conn.execute("SELECT COUNT(*) FROM packages").fetchone()[0]
            assert count == 0
