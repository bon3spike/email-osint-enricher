"""Tests for BaseProvider, ProviderContext."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from email_osint_enricher.providers.base import BaseProvider, ProviderContext
from email_osint_enricher.providers import PROVIDER_REGISTRY


class TestProviderContext:
    def test_default_context(self):
        ctx = ProviderContext(email="test@gmail.com")
        assert ctx.email == "test@gmail.com"
        assert ctx.email_normalized == ""
        assert ctx.username_candidates == []
        assert ctx.profiles_found == []
        assert ctx.is_google_email is False

    def test_context_with_profiles(self):
        ctx = ProviderContext(
            email="test@gmail.com",
            profiles_found=["https://twitter.com/test", "https://github.com/test"],
        )
        assert len(ctx.profiles_found) == 2

    def test_context_with_usernames(self):
        ctx = ProviderContext(
            email="john.doe@gmail.com",
            username_candidates=["john.doe", "johndoe", "john_doe"],
        )
        assert len(ctx.username_candidates) == 3


class TestProviderRegistry:
    def test_all_providers_registered(self):
        expected = {
            "holehe", "blackbird", "maigret", "sherlock",
            "phone_extractor",
            "emailrep", "mosint", "emailcrawlr",
        }
        assert set(PROVIDER_REGISTRY.keys()) == expected

    def test_all_providers_have_name(self):
        for name, cls in PROVIDER_REGISTRY.items():
            assert cls.name == name, f"Provider {cls.__name__} has name={cls.name}, expected {name}"

    def test_all_providers_are_base_provider(self):
        for name, cls in PROVIDER_REGISTRY.items():
            assert issubclass(cls, BaseProvider), f"{cls.__name__} must extend BaseProvider"
