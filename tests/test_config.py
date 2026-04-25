"""Tests for peeq.config — centralized configuration."""

from __future__ import annotations

from pathlib import Path

import pytest

from peeq.config import (
    CacheConfig,
    ExtractionConfig,
    Settings,
    get_settings,
    reset_settings,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _clear_settings_cache() -> None:
    """Ensure each test starts with a fresh settings cache."""
    reset_settings()


# ---------------------------------------------------------------------------
# CacheConfig defaults
# ---------------------------------------------------------------------------


class TestCacheConfig:
    def test_defaults(self) -> None:
        config = CacheConfig()
        assert isinstance(config.dir, Path)
        assert "peeq" in str(config.dir)
        assert config.api_ttl_seconds == 3600

    def test_custom_values(self, tmp_path: Path) -> None:
        config = CacheConfig(dir=tmp_path, api_ttl_seconds=7200)
        assert config.dir == tmp_path
        assert config.api_ttl_seconds == 7200


# ---------------------------------------------------------------------------
# ExtractionConfig defaults
# ---------------------------------------------------------------------------


class TestExtractionConfig:
    def test_defaults(self) -> None:
        config = ExtractionConfig()
        assert config.max_size_mb == 500
        assert config.max_files == 50_000
        assert config.max_file_size_mb == 100

    def test_custom_values(self) -> None:
        config = ExtractionConfig(max_size_mb=10, max_files=100, max_file_size_mb=5)
        assert config.max_size_mb == 10
        assert config.max_files == 100
        assert config.max_file_size_mb == 5


# ---------------------------------------------------------------------------
# Settings — defaults
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Settings — environment variable overrides
# ---------------------------------------------------------------------------


class TestSettingsEnvVars:
    def test_cache_dir(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        monkeypatch.setenv("PEEQ_CACHE_DIR", str(tmp_path))
        settings = Settings()
        assert settings.cache.dir == tmp_path

    def test_cache_api_ttl(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("PEEQ_CACHE_API_TTL_SECONDS", "7200")
        settings = Settings()
        assert settings.cache.api_ttl_seconds == 7200

    def test_extraction_max_size_mb(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("PEEQ_EXTRACTION_MAX_SIZE_MB", "10")
        settings = Settings()
        assert settings.extraction.max_size_mb == 10

    def test_extraction_max_files(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("PEEQ_EXTRACTION_MAX_FILES", "100")
        settings = Settings()
        assert settings.extraction.max_files == 100

    def test_extraction_max_file_size_mb(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("PEEQ_EXTRACTION_MAX_FILE_SIZE_MB", "5")
        settings = Settings()
        assert settings.extraction.max_file_size_mb == 5

    def test_multiple_overrides(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.setenv("PEEQ_CACHE_DIR", str(tmp_path))
        monkeypatch.setenv("PEEQ_CACHE_API_TTL_SECONDS", "600")
        monkeypatch.setenv("PEEQ_EXTRACTION_MAX_SIZE_MB", "250")
        settings = Settings()
        assert settings.cache.dir == tmp_path
        assert settings.cache.api_ttl_seconds == 600
        assert settings.extraction.max_size_mb == 250
        # Non-overridden values keep defaults
        assert settings.extraction.max_files == 50_000
        assert settings.extraction.max_file_size_mb == 100

    def test_partial_nested_override(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Overriding one field in a sub-model doesn't reset others."""
        monkeypatch.setenv("PEEQ_EXTRACTION_MAX_FILES", "999")
        settings = Settings()
        assert settings.extraction.max_files == 999
        assert settings.extraction.max_size_mb == 500  # Kept default
        assert settings.extraction.max_file_size_mb == 100  # Kept default


# ---------------------------------------------------------------------------
# Settings — TOML config file
# ---------------------------------------------------------------------------


class TestSettingsToml:
    def test_toml_loading(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """Settings loads values from a TOML config file."""
        config_dir = tmp_path / "config"
        config_dir.mkdir()
        config_file = config_dir / "config.toml"
        config_file.write_text(
            "[cache]\napi_ttl_seconds = 9999\n\n[extraction]\nmax_size_mb = 42\n"
        )

        # Patch _default_config_path to point to our test file
        monkeypatch.setattr("peeq.config._default_config_path", lambda: config_file)

        settings = Settings()
        assert settings.cache.api_ttl_seconds == 9999
        assert settings.extraction.max_size_mb == 42
        # Non-specified values keep defaults
        assert settings.extraction.max_files == 50_000

    def test_env_overrides_toml(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """Environment variables take priority over TOML values."""
        config_dir = tmp_path / "config"
        config_dir.mkdir()
        config_file = config_dir / "config.toml"
        config_file.write_text("[extraction]\nmax_size_mb = 42\n")

        monkeypatch.setattr("peeq.config._default_config_path", lambda: config_file)
        monkeypatch.setenv("PEEQ_EXTRACTION_MAX_SIZE_MB", "999")

        settings = Settings()
        # Env wins over TOML
        assert settings.extraction.max_size_mb == 999

    def test_missing_toml_is_ok(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """If the config file doesn't exist, settings still work."""
        nonexistent = tmp_path / "nope" / "config.toml"
        monkeypatch.setattr("peeq.config._default_config_path", lambda: nonexistent)

        settings = Settings()
        # All defaults
        assert settings.cache.api_ttl_seconds == 3600
        assert settings.extraction.max_size_mb == 500


# ---------------------------------------------------------------------------
# Settings — init overrides
# ---------------------------------------------------------------------------


class TestSettingsInit:
    def test_init_kwargs(self, tmp_path: Path) -> None:
        settings = Settings(
            cache=CacheConfig(dir=tmp_path, api_ttl_seconds=123),
            extraction=ExtractionConfig(max_size_mb=7),
        )
        assert settings.cache.dir == tmp_path
        assert settings.cache.api_ttl_seconds == 123
        assert settings.extraction.max_size_mb == 7

    def test_init_overrides_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Init kwargs beat env vars (highest priority)."""
        monkeypatch.setenv("PEEQ_EXTRACTION_MAX_SIZE_MB", "999")
        settings = Settings(
            extraction=ExtractionConfig(max_size_mb=7),
        )
        assert settings.extraction.max_size_mb == 7


# ---------------------------------------------------------------------------
# get_settings / reset_settings
# ---------------------------------------------------------------------------


class TestGetSettings:
    def test_cached(self) -> None:
        s1 = get_settings()
        s2 = get_settings()
        assert s1 is s2

    def test_reset_clears_cache(self) -> None:
        s1 = get_settings()
        reset_settings()
        s2 = get_settings()
        assert s1 is not s2
