"""Tests for `PackageService.check_vulnerabilities`."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from peeq.integrations.osv import OSVError
from peeq.models import VulnerabilityReport
from tests.test_service.conftest import _make_service


class TestCheckVulnerabilities:
    """Tests for `PackageService.check_vulnerabilities`."""

    async def test_delegates_to_osv_client(self) -> None:
        """Verify the service delegates to OSVClient.query."""
        mock_report = VulnerabilityReport(
            package="requests", version="2.25.0", vulnerabilities=[]
        )

        with patch(
            "peeq.integrations.osv.OSVClient",
        ) as mock_client_cls:
            mock_client_instance = AsyncMock()
            mock_client_instance.query.return_value = mock_report
            mock_client_instance.__aenter__ = AsyncMock(
                return_value=mock_client_instance
            )
            mock_client_instance.__aexit__ = AsyncMock(return_value=None)
            mock_client_cls.return_value = mock_client_instance

            service = _make_service()
            result = await service.check_vulnerabilities("requests", "2.25.0")

        assert result.package == "requests"
        assert result.version == "2.25.0"
        assert result.vulnerabilities == []
        mock_client_instance.query.assert_awaited_once_with("requests", "2.25.0")

    async def test_propagates_osv_error(self) -> None:
        """OSVError from the client propagates to the caller."""
        with patch(
            "peeq.integrations.osv.OSVClient",
        ) as mock_client_cls:
            mock_client_instance = AsyncMock()
            mock_client_instance.query.side_effect = OSVError("API down")
            mock_client_instance.__aenter__ = AsyncMock(
                return_value=mock_client_instance
            )
            mock_client_instance.__aexit__ = AsyncMock(return_value=None)
            mock_client_cls.return_value = mock_client_instance

            service = _make_service()
            with pytest.raises(OSVError, match="API down"):
                await service.check_vulnerabilities("pkg", "1.0.0")
