"""Repository backends (PyPI, generic PEP 503 Simple).

Importing this module triggers `__init_subclass__` auto-registration
for all concrete backends.
"""

from peeq.backends.base import BackendError, PackageRepository
from peeq.backends.pypi import PyPIRepository
from peeq.backends.registry import get_backend, probe_backend
from peeq.backends.simple import SimpleRepository

__all__ = [
    "BackendError",
    "PackageRepository",
    "PyPIRepository",
    "SimpleRepository",
    "get_backend",
    "probe_backend",
]
