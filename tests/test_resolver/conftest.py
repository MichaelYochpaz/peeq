"""Fixtures for resolver tests."""

from __future__ import annotations

import os
import shutil
from typing import TYPE_CHECKING

import pytest

from tests.test_resolver._uv_test_index import UvTestIndex, build_uv_test_index

if TYPE_CHECKING:
    from pathlib import Path


@pytest.fixture
def real_uv_bin() -> str:
    """Return the selected real uv executable or skip when unavailable."""
    requested = os.environ.get("PEEQ_TEST_UV_BIN", "uv")
    resolved = shutil.which(requested)
    if resolved is None:
        pytest.skip(f"real uv executable not found: {requested}")
    return resolved


@pytest.fixture
def uv_test_index(tmp_path: Path) -> UvTestIndex:
    """Build the controlled, network-free uv package indexes."""
    return build_uv_test_index(tmp_path / "uv-index")
