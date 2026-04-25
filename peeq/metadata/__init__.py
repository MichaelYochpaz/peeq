"""Metadata extraction functions (PEP 658, wheel, sdist).

Three standalone functions for extracting package metadata from different
sources.  The service layer orchestrates the fallback chain; this module
provides the extraction logic only.
"""

from peeq.metadata.parsing import is_pure_python_wheel, parse_email_metadata
from peeq.metadata.pep658 import fetch_pep658_metadata
from peeq.metadata.sdist import extract_sdist_metadata, select_sdist
from peeq.metadata.wheel import extract_wheel_metadata, select_wheel

__all__ = [
    "extract_sdist_metadata",
    "extract_wheel_metadata",
    "fetch_pep658_metadata",
    "is_pure_python_wheel",
    "parse_email_metadata",
    "select_sdist",
    "select_wheel",
]
