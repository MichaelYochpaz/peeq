"""Tests for backend auto-detection and registration."""

from __future__ import annotations

import httpx
import pytest
import respx

from peeq.backends.pypi import PyPIRepository
from peeq.backends.registry import get_backend, probe_backend
from peeq.backends.simple import SimpleRepository

# ---------------------------------------------------------------------------
# get_backend()
# ---------------------------------------------------------------------------


class TestGetBackend:
    def test_default_is_pypi(self):
        backend = get_backend()
        assert isinstance(backend, PyPIRepository)
        assert backend.registry == "pypi.org"

    def test_pypi_org_detected(self):
        backend = get_backend("https://pypi.org")
        assert isinstance(backend, PyPIRepository)

    def test_test_pypi_detected(self):
        backend = get_backend("https://test.pypi.org")
        assert isinstance(backend, PyPIRepository)

    def test_unknown_url_defaults_to_simple(self):
        backend = get_backend("https://devpi.internal/root/pypi")
        assert isinstance(backend, SimpleRepository)

    def test_explicit_pypi_override(self):
        backend = get_backend(
            "https://custom.server.com",
            backend_type="pypi",
        )
        assert isinstance(backend, PyPIRepository)

    def test_explicit_simple_override(self):
        backend = get_backend(
            "https://pypi.org",  # Even for pypi.org, if overridden
            backend_type="simple",
        )
        assert isinstance(backend, SimpleRepository)

    def test_unknown_backend_type_raises(self):
        with pytest.raises(ValueError, match="Unknown backend type"):
            get_backend(backend_type="artifactory")

    def test_custom_registry_name(self):
        backend = get_backend(
            "https://devpi.internal/root/pypi",
            registry="devpi",
        )
        assert backend.registry == "devpi"

    def test_trailing_slash_stripped(self):
        backend = get_backend("https://pypi.org/")
        assert backend.base_url == "https://pypi.org"


# ---------------------------------------------------------------------------
# probe_backend()
# ---------------------------------------------------------------------------


class TestProbeBackend:
    @respx.mock
    async def test_pep691_detected(self):
        respx.get("https://custom.server.com/").mock(
            return_value=httpx.Response(
                200,
                headers={
                    "content-type": "application/vnd.pypi.simple.v1+json",
                },
                json={"meta": {"api-version": "1.0"}},
            ),
        )

        backend = await probe_backend("https://custom.server.com")
        assert isinstance(backend, PyPIRepository)

    @respx.mock
    async def test_html_only_falls_to_simple(self):
        respx.get("https://simple-only.server.com/").mock(
            return_value=httpx.Response(
                200,
                headers={"content-type": "text/html"},
                text="<html><body>simple index</body></html>",
            ),
        )

        backend = await probe_backend("https://simple-only.server.com")
        assert isinstance(backend, SimpleRepository)

    @respx.mock
    async def test_http_error_falls_to_simple(self):
        respx.get("https://flaky.server.com/").mock(
            side_effect=httpx.ConnectError("connection refused"),
        )

        backend = await probe_backend("https://flaky.server.com")
        assert isinstance(backend, SimpleRepository)

    @respx.mock
    async def test_custom_registry_passed_through(self):
        respx.get("https://custom.server.com/").mock(
            return_value=httpx.Response(
                200,
                headers={
                    "content-type": "application/vnd.pypi.simple.v1+json",
                },
                json={},
            ),
        )

        backend = await probe_backend(
            "https://custom.server.com",
            registry="custom",
        )
        assert backend.registry == "custom"

    @respx.mock
    async def test_trailing_slash_handled(self):
        respx.get("https://server.com/simple/").mock(
            return_value=httpx.Response(
                200,
                headers={"content-type": "text/html"},
            ),
        )

        backend = await probe_backend("https://server.com/simple/")
        assert isinstance(backend, SimpleRepository)
        assert backend.base_url == "https://server.com/simple"
