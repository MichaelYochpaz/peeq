"""Centralized configuration for peeq.

Settings are loaded from (highest to lowest priority):

1. Explicit `__init__` keyword arguments
2. Environment variables (`PEEQ_` prefix, `_` nested delimiter)
3. TOML config file (platform-dependent path via `platformdirs`)
4. Field defaults

CLI arguments (cyclopts) override settings at the command level.
"""

from __future__ import annotations

import functools
from pathlib import Path

import platformdirs
from pydantic import BaseModel, Field
from pydantic_settings import (
    BaseSettings,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
    TomlConfigSettingsSource,
)

from peeq import APP_NAME

# ---------------------------------------------------------------------------
# Path helpers
# ---------------------------------------------------------------------------


def _default_cache_dir() -> Path:
    """Platform-standard cache directory via `platformdirs`."""
    return Path(platformdirs.user_cache_dir(appname=APP_NAME, appauthor=False))


def _default_config_path() -> Path:
    """Platform-standard config file path via `platformdirs`."""
    return (
        Path(platformdirs.user_config_dir(appname=APP_NAME, appauthor=False))
        / "config.toml"
    )


# ---------------------------------------------------------------------------
# Cache
# ---------------------------------------------------------------------------


class CacheConfig(BaseModel):
    """Cache storage settings."""

    dir: Path = Field(default_factory=_default_cache_dir)
    """Root directory for all cache data (database + archives)."""

    api_ttl_seconds: int = 3600
    """TTL in seconds for cached registry API data (package listings)."""

    max_size_mb: int = Field(default=2000, ge=0)
    """Maximum total size of cached archive files in megabytes.

    When the cache exceeds this limit, the least recently used archives
    are evicted (metadata is preserved for fast cache hits).
    Set to `0` to disable the limit (unlimited growth).
    """


# ---------------------------------------------------------------------------
# Extraction
# ---------------------------------------------------------------------------


class ExtractionConfig(BaseModel):
    """Resource limits for archive extraction (decompression bomb protection).

    All size values are in **megabytes** (converted to bytes internally by
    `ExtractionLimits`).
    """

    max_size_mb: int = 500
    """Maximum total uncompressed size in megabytes."""

    max_files: int = 50_000
    """Maximum number of files in an archive."""

    max_file_size_mb: int = 100
    """Maximum size of a single file in megabytes."""


# ---------------------------------------------------------------------------
# Root settings
# ---------------------------------------------------------------------------


class Settings(BaseSettings):
    """Application-wide settings for peeq.

    Priority (highest to lowest):

    1. Explicit `__init__` keyword arguments
    2. Environment variables (`PEEQ_` prefix)
    3. TOML config file (`~/.config/peeq/config.toml` or platform
       equivalent)
    4. Field defaults
    """

    model_config = SettingsConfigDict(
        env_prefix=f"{APP_NAME.upper()}_",
        env_nested_delimiter="_",
        env_nested_max_split=1,
    )

    cache: CacheConfig = Field(default_factory=CacheConfig)
    extraction: ExtractionConfig = Field(default_factory=ExtractionConfig)

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,  # noqa: ARG003
        file_secret_settings: PydanticBaseSettingsSource,  # noqa: ARG003
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        """Configure settings sources with optional TOML file."""
        sources: list[PydanticBaseSettingsSource] = [
            init_settings,
            env_settings,
        ]

        config_path = _default_config_path()
        if config_path.exists():
            sources.append(
                TomlConfigSettingsSource(settings_cls, toml_file=config_path)
            )

        return tuple(sources)


# ---------------------------------------------------------------------------
# Singleton access
# ---------------------------------------------------------------------------


@functools.lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Load and cache application settings.

    The result is cached for the lifetime of the process.  Call
    `reset_settings` to force a reload (mainly for testing).
    """
    return Settings()


def reset_settings() -> None:
    """Clear the cached settings instance.

    Intended for testing --- forces the next `get_settings` call
    to reload from environment / config file.
    """
    get_settings.cache_clear()
