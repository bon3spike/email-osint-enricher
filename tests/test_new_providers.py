"""Tests for new providers (v0.2): EmailRep, Mosint, EmailCrawlr."""

import asyncio
import json
from unittest.mock import patch, AsyncMock, MagicMock

import pytest

from email_osint_enricher.providers.base import ProviderContext
from email_osint_enricher.providers.emailrep_provider import EmailRepProvider
from email_osint_enricher.providers.mosint_provider import MosintProvider
from email_osint_enricher.providers.emailcrawlr_provider import EmailCrawlrProvider
from email_osint_enricher.scoring import merge_profiles
from email_osint_enricher.schemas import BlackbirdResult, MaigretResult, ProfileEntry


def _ctx(email="test@gmail.com"):
    return ProviderContext(email=email)


# ── EmailRep tests ───────────────────────────────────────────────────────────

class TestEmailRepProvider:

    def test_normalize_result(self):
        p = EmailRepProvider()
        from email_osint_enricher.schemas import EmailRepResult
        r = EmailRepResult(checked=True, success=True, reputation="high",
                           references=5, risk_score=0.1)
        norm = p.normalize_result(r)
        assert norm["emailrep_reputation"] == "high"
        assert norm["emailrep_references"] == 5

    @pytest.mark.asyncio
    async def test_mocked_emailrep_high_reputation(self):
        p = EmailRepProvider()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "email": "test@gmail.com",
            "reputation": "high",
            "suspicious": False,
            "references": 10,
            "details": {
                "profiles": ["twitter", "github"],
                "deliverable": True,
                "domain_exists": True,
                "data_breach": False,
                "malicious_activity": False,
                "spam": False,
            },
        }

        with patch("email_osint_enricher.providers.emailrep_provider.httpx.AsyncClient") as mock_client:
            instance = AsyncMock()
            instance.get = AsyncMock(return_value=mock_resp)
            instance.__aenter__ = AsyncMock(return_value=instance)
            instance.__aexit__ = AsyncMock(return_value=False)
            mock_client.return_value = instance

            result = await p.run(_ctx())
            assert result.success is True
            assert result.reputation == "high"
            assert result.suspicious is False
            assert result.risk_score == 0.0
            assert result.references == 10

    @pytest.mark.asyncio
    async def test_mocked_emailrep_suspicious(self):
        p = EmailRepProvider()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "reputation": "low",
            "suspicious": True,
            "references": 0,
            "details": {"malicious_activity": True, "spam": True},
        }

        with patch("email_osint_enricher.providers.emailrep_provider.httpx.AsyncClient") as mock_client:
            instance = AsyncMock()
            instance.get = AsyncMock(return_value=mock_resp)
            instance.__aenter__ = AsyncMock(return_value=instance)
            instance.__aexit__ = AsyncMock(return_value=False)
            mock_client.return_value = instance

            result = await p.run(_ctx())
            assert result.success is True
            assert result.suspicious is True
            assert result.risk_score >= 0.7  # suspicious + malicious + spam


# ── Mosint tests ─────────────────────────────────────────────────────────────

class TestMosintProvider:

    @pytest.mark.asyncio
    async def test_binary_not_found(self):
        """Missing binary should fail gracefully, not crash."""
        p = MosintProvider(command="mosint_nonexistent_binary_12345")
        result = await p.run(_ctx())
        assert result.checked is True
        assert result.success is False
        assert result.error == "binary_not_found"

    def test_normalize_result(self):
        p = MosintProvider()
        from email_osint_enricher.schemas import MosintResult
        r = MosintResult(checked=True, success=True, findings_count=5,
                         social_signal=True, confidence_score=0.8)
        norm = p.normalize_result(r)
        assert norm["mosint_findings_count"] == 5
        assert norm["mosint_social_signal"] is True




# ── EmailCrawlr tests ───────────────────────────────────────────────────────

class TestEmailCrawlrProvider:

    @pytest.mark.asyncio
    async def test_no_api_key_skips(self):
        """No API key should skip gracefully."""
        p = EmailCrawlrProvider(api_key="")
        assert await p.should_run(_ctx()) is False

    @pytest.mark.asyncio
    async def test_no_api_key_run_returns_error(self):
        p = EmailCrawlrProvider(api_key="")
        result = await p.run(_ctx())
        assert result.checked is True
        assert result.success is False
        assert result.error == "no_api_key"


# ── Profile merge tests ─────────────────────────────────────────────────────

class TestMergeProfiles:

    def test_dedup_by_normalized_url(self):
        bb = BlackbirdResult(success=True, profiles_list=[
            "https://github.com/user1",
            "https://GitHub.com/user1/",  # same after normalization
            "https://twitter.com/user1",
        ])
        profiles = merge_profiles(blackbird=bb)
        assert len(profiles) == 2

    def test_multi_provider_confidence_boost(self):
        bb = BlackbirdResult(success=True, profiles_list=["https://github.com/user1"])
        m = MaigretResult(success=True, profiles_list=["https://github.com/user1"])
        profiles = merge_profiles(blackbird=bb, maigret=m)
        assert len(profiles) == 1
        assert profiles[0].confidence > 50
        assert "," in profiles[0].source_provider  # multiple providers

    def test_empty_merge(self):
        assert merge_profiles() == []

    def test_short_urls_filtered(self):
        bb = BlackbirdResult(success=True, profiles_list=["http://x"])
        profiles = merge_profiles(blackbird=bb)
        assert len(profiles) == 0
