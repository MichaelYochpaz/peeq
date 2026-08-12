"""Test fixtures for backend tests."""

from __future__ import annotations

import functools
import ssl
from typing import Any

import httpx
import pytest

# ---------------------------------------------------------------------------
# Performance: both fixtures below are safe because @respx.mock intercepts
# all HTTP at the transport level — no real network or TLS handshakes occur.
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def zero_retry_delay(monkeypatch: pytest.MonkeyPatch) -> None:
    """Eliminate real backoff sleeps in backend retry-path tests."""
    # Backend tests assert retry behavior, not wall-clock backoff; zeroing the
    # base delay preserves retry attempts while avoiding real sleeps.
    monkeypatch.setattr("peeq.backends.base._RETRY_BASE_DELAY", 0.0)


@pytest.fixture(scope="session")
def _cached_ssl_ctx() -> ssl.SSLContext:
    """Create a single verified SSL context for the entire test session."""
    return ssl.create_default_context()


@pytest.fixture(autouse=True)
def _reuse_ssl_ctx(monkeypatch: pytest.MonkeyPatch, _cached_ssl_ctx: ssl.SSLContext) -> None:
    """Reuse a cached SSL context to skip per-test CA certificate loading."""
    original_init = httpx.AsyncClient.__init__

    @functools.wraps(original_init)
    def patched_init(self: httpx.AsyncClient, *args: Any, **kwargs: Any) -> None:
        # Only inject when the caller relies on the default (verify=True);
        # tests that explicitly pass verify= keep their own value.
        if kwargs.get("verify", True) is True:
            kwargs["verify"] = _cached_ssl_ctx
        original_init(self, *args, **kwargs)

    monkeypatch.setattr(httpx.AsyncClient, "__init__", patched_init)
