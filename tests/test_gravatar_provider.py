"""Tests for Gravatar provider."""

import pytest
from unittest.mock import AsyncMock, patch, MagicMock

from email_osint_enricher.providers.gravatar_provider import GravatarProvider
from email_osint_enricher.providers.base import ProviderContext
from email_osint_enricher.schemas import GravatarResult


@pytest.fixture
def provider(tmp_path):
    return GravatarProvider(timeout=10, raw_output_dir=tmp_path / "raw" / "gravatar")


@pytest.fixture
def context():
    return ProviderContext(email="test@gmail.com", email_normalized="test@gmail.com")


@pytest.mark.asyncio
async def test_should_run(provider, context):
    assert await provider.should_run(context) is True


@pytest.mark.asyncio
async def test_run_with_profile(provider, context):
    mock_data = {
        "entry": [
            {
                "displayName": "johndoe",
                "name": {"formatted": "John Doe"},
                "profileUrl": "https://gravatar.com/johndoe",
                "aboutMe": "Developer from NYC",
                "currentLocation": "New York",
                "photos": [{"value": "https://gravatar.com/avatar/abc123"}],
                "accounts": [
                    {"shortname": "github", "url": "https://github.com/johndoe", "display": "johndoe"},
                    {"shortname": "twitter", "url": "https://twitter.com/johndoe", "display": "@johndoe"},
                ],
                "urls": [{"value": "https://johndoe.dev"}],
            }
        ]
    }

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = mock_data

    with patch("email_osint_enricher.providers.gravatar_provider.httpx.AsyncClient") as mock_client:
        mock_client.return_value.__aenter__ = AsyncMock(return_value=MagicMock(
            get=AsyncMock(return_value=mock_resp)
        ))
        mock_client.return_value.__aexit__ = AsyncMock(return_value=False)

        result = await provider.run(context)

    assert isinstance(result, GravatarResult)
    assert result.checked is True
    assert result.success is True
    assert result.has_profile is True
    assert result.display_name == "johndoe"
    assert result.full_name == "John Doe"
    assert result.location == "New York"
    assert result.linked_accounts_count == 2
    assert "github" in result.linked_accounts[0]
    assert result.about_me == "Developer from NYC"
    assert result.confidence_score > 0.5


@pytest.mark.asyncio
async def test_run_no_profile(provider, context):
    mock_resp = MagicMock()
    mock_resp.status_code = 404

    with patch("email_osint_enricher.providers.gravatar_provider.httpx.AsyncClient") as mock_client:
        mock_client.return_value.__aenter__ = AsyncMock(return_value=MagicMock(
            get=AsyncMock(return_value=mock_resp)
        ))
        mock_client.return_value.__aexit__ = AsyncMock(return_value=False)

        result = await provider.run(context)

    assert result.success is True
    assert result.has_profile is False
    assert result.confidence_score == 0.0


def test_normalize_result(provider):
    result = GravatarResult(
        checked=True,
        success=True,
        has_profile=True,
        display_name="johndoe",
        full_name="John Doe",
        linked_accounts=["github: https://github.com/jd"],
        linked_accounts_count=1,
        confidence_score=0.6,
    )
    norm = provider.normalize_result(result)
    assert norm["gravatar_has_profile"] is True
    assert norm["gravatar_full_name"] == "John Doe"
    assert "github" in norm["gravatar_linked_accounts"]
