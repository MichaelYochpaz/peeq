"""Backend auto-detection and registration.

Provides `get_backend` --- the primary entry point for creating a
`PackageRepository` instance from a URL
and/or explicit backend type override.

Resolution order:

1. Explicit `backend_type` override (`--backend pypi` / `--backend simple`)
2. Known-domain detection (`pypi.org`, `test.pypi.org`)
3. Probe-based detection (try PEP 691, fall back to PEP 503)
4. Default to `SimpleRepository`
"""

from __future__ import annotations

import logging

import httpx

from peeq import APP_NAME, __version__
from peeq.backends.base import PackageRepository, extract_hostname
from peeq.backends.pypi import PYPI_BASE_URL, PyPIRepository
from peeq.backends.simple import SimpleRepository

logger = logging.getLogger(__name__)

# Domains that are known PyPI instances
_PYPI_DOMAINS: frozenset[str] = frozenset({"pypi.org", "test.pypi.org"})

_PEP691_ACCEPT = "application/vnd.pypi.simple.v1+json"


def get_backend(
    url: str | None = None,
    *,
    backend_type: str | None = None,
    registry: str | None = None,
) -> PackageRepository:
    """Create a backend for the given *url*.

    Parameters
    ----------
    url:
        Repository base URL.  Defaults to `https://pypi.org`.
    backend_type:
        Explicit backend override (`"pypi"` or `"simple"`).  If
        provided, skips auto-detection.
    registry:
        Override the registry name used in cache keys.  Defaults to the
        hostname extracted from *url*.

    Returns
    -------
    PackageRepository
        An uninitialized backend instance.  Use as an async context
        manager to activate the HTTP client::

            backend = get_backend()
            async with backend:
                info = await backend.check("requests")

    Raises
    ------
    ValueError
        If *backend_type* is not a recognized backend identifier.
    """
    if url is None:
        url = PYPI_BASE_URL

    # 1. Explicit override
    if backend_type is not None:
        cls = PackageRepository.get_backend_class(backend_type)
        if cls is None:
            known = ", ".join(PackageRepository.registered_backend_ids())
            msg = f"Unknown backend type: {backend_type!r}. Available: {known}"
            raise ValueError(msg)
        return cls(base_url=url, registry=registry)

    # 2. Known-domain detection
    hostname = extract_hostname(url)
    if hostname in _PYPI_DOMAINS:
        return PyPIRepository(base_url=url, registry=registry)

    # 3. Default to Simple for unknown URLs
    #    (probe_backend can be used for async detection if needed)
    return SimpleRepository(base_url=url, registry=registry)


async def probe_backend(
    url: str,
    *,
    registry: str | None = None,
    timeout: float = 10.0,
) -> PackageRepository:
    """Probe *url* to detect the best backend.

    Tries a PEP 691 JSON request first.  If the server responds with a
    JSON content type, returns a `PyPIRepository`.  Otherwise
    falls back to `SimpleRepository`.

    This function creates a temporary httpx client for the probe request.
    The returned backend is **not** initialized --- use as an async
    context manager.
    """
    url = url.rstrip("/")
    probe_url = f"{url}/"

    async with httpx.AsyncClient(
        headers={"User-Agent": f"{APP_NAME}/{__version__}"},
        timeout=timeout,
    ) as client:
        try:
            response = await client.get(
                probe_url,
                headers={"Accept": _PEP691_ACCEPT},
            )
            ct = response.headers.get("content-type", "")
            if "application/vnd.pypi.simple" in ct and "json" in ct:
                logger.debug("Probe detected PEP 691 support at %s", url)
                return PyPIRepository(base_url=url, registry=registry)
        except httpx.HTTPError:
            logger.debug(
                "PEP 691 probe failed for %s, falling back to Simple",
                url,
                exc_info=True,
            )

    logger.debug("Using Simple backend for %s", url)
    return SimpleRepository(base_url=url, registry=registry)
