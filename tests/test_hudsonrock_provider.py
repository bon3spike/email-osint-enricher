"""Tests for HudsonRock provider."""

import pytest
import json
from unittest.mock import AsyncMock, patch, MagicMock

from email_osint_enricher.providers.hudsonrock_provider import HudsonRockProvider
from email_osint_enricher.providers.base import ProviderContext
from email_osint_enricher.schemas import HudsonRockResult


@pytest.fixture
def provider(tmp_path):
    return HudsonRockProvider(timeout=10, raw_output_dir=tmp_path / "raw" / "hudsonrock")


@pytest.fixture
def context():
    return ProviderContext(email="test@gmail.com", email_normalized="test@gmail.com")


@pytest.mark.asyncio
async def test_should_run(provider, context):
    assert await provider.should_run(context) is True


@pytest.mark.asyncio
async def test_run_compromised(provider, context):
    mock_data = {
        "stealers": [
            {
                "total_corporate_services": 10,
                "total_user_services": 500,
                "date_compromised": "2025-01-15T10:00:00.000Z",
                "computer_name": "DESKTOP-ABC",
                "operating_system": "Windows 10 Pro",
                "malware_path": "C:\\Users\\test\\bad.exe",
                "antiviruses": [],
                "ip": "1.2.3.4",
                "top_passwords": ["p***1"],
                "top_logins": ["t***@gmail.com"],
            },
            {
                "total_corporate_services": 5,
                "total_user_services": 200,
                "date_compromised": "2024-06-01T00:00:00.000Z",
                "computer_name": "Not Found",
                "operating_system": "Not Found",
                "malware_path": "Not Found",
                "antiviruses": [],
                "ip": "Not Found",
                "top_passwords": [],
                "top_logins": [],
            },
        ]
    }

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = mock_data

    with patch("email_osint_enricher.providers.hudsonrock_provider.httpx.AsyncClient") as mock_client:
        mock_client.return_value.__aenter__ = AsyncMock(return_value=MagicMock(
            get=AsyncMock(return_value=mock_resp)
        ))
        mock_client.return_value.__aexit__ = AsyncMock(return_value=False)

        result = await provider.run(context)

    assert isinstance(result, HudsonRockResult)
    assert result.checked is True
    assert result.success is True
    assert result.is_compromised is True
    assert result.stealers_count == 2
    assert result.total_corporate_services == 15
    assert result.total_user_services == 700
    assert "2025-01-15" in result.compromised_dates
    assert result.latest_compromise_date == "2025-01-15"
    assert result.confidence_score == 0.7  # 1 <= stealers < 3


@pytest.mark.asyncio
async def test_run_clean(provider, context):
    mock_data = {"stealers": []}

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = mock_data

    with patch("email_osint_enricher.providers.hudsonrock_provider.httpx.AsyncClient") as mock_client:
        mock_client.return_value.__aenter__ = AsyncMock(return_value=MagicMock(
            get=AsyncMock(return_value=mock_resp)
        ))
        mock_client.return_value.__aexit__ = AsyncMock(return_value=False)

        result = await provider.run(context)

    assert result.success is True
    assert result.is_compromised is False
    assert result.stealers_count == 0
    assert result.confidence_score == 0.1


@pytest.mark.asyncio
async def test_run_rate_limited(provider, context):
    mock_resp = MagicMock()
    mock_resp.status_code = 429

    with patch("email_osint_enricher.providers.hudsonrock_provider.httpx.AsyncClient") as mock_client:
        mock_client.return_value.__aenter__ = AsyncMock(return_value=MagicMock(
            get=AsyncMock(return_value=mock_resp)
        ))
        mock_client.return_value.__aexit__ = AsyncMock(return_value=False)

        result = await provider.run(context)

    assert result.error == "rate_limited"
    assert result.success is False


def test_normalize_result(provider):
    result = HudsonRockResult(
        checked=True,
        success=True,
        is_compromised=True,
        stealers_count=2,
        confidence_score=0.7,
    )
    norm = provider.normalize_result(result)
    assert norm["hudsonrock_checked"] is True
    assert norm["hudsonrock_is_compromised"] is True
    assert norm["hudsonrock_stealers_count"] == 2
