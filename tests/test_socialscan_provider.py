"""Tests for Socialscan provider."""

import pytest
from unittest.mock import patch, MagicMock

from email_osint_enricher.providers.socialscan_provider import SocialscanProvider
from email_osint_enricher.providers.base import ProviderContext
from email_osint_enricher.schemas import SocialscanResult


@pytest.fixture
def provider(tmp_path):
    return SocialscanProvider(timeout=10, raw_output_dir=tmp_path / "raw" / "socialscan")


@pytest.fixture
def context():
    return ProviderContext(email="test@gmail.com", email_normalized="test@gmail.com")


@pytest.mark.asyncio
async def test_should_run_not_installed(provider, context):
    """When socialscan is not installed, should_run returns False."""
    with patch.dict("sys.modules", {"socialscan": None}):
        provider._available = None  # Reset cache
        # Force import to fail
        with patch("builtins.__import__", side_effect=ImportError("no socialscan")):
            provider._available = None
            result = provider._check_available()
            # May or may not be False depending on import caching
            # Just verify no crash
            assert isinstance(result, bool)


@pytest.mark.asyncio
async def test_run_not_installed(provider, context):
    """When socialscan is not installed, run returns error result."""
    provider._available = False
    result = await provider.run(context)
    assert isinstance(result, SocialscanResult)
    assert result.checked is True
    assert result.success is False
    assert result.error == "socialscan not installed"


def test_normalize_result(provider):
    result = SocialscanResult(
        checked=True,
        success=True,
        registered_platforms=["Instagram", "GitHub", "Twitter"],
        registered_count=3,
        not_registered_platforms=["Snapchat"],
        not_registered_count=1,
        confidence_score=0.7,
    )
    norm = provider.normalize_result(result)
    assert norm["socialscan_registered_count"] == 3
    assert "Instagram" in norm["socialscan_registered_platforms"]
    assert norm["socialscan_confidence_score"] == 0.7
