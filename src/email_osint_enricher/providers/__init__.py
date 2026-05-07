"""OSINT provider wrappers."""

from email_osint_enricher.providers.base import BaseProvider, ProviderContext, ProviderResult
from email_osint_enricher.providers.ghunt_provider import GHuntProvider
from email_osint_enricher.providers.holehe_provider import HoleheProvider
from email_osint_enricher.providers.blackbird_provider import BlackbirdProvider
from email_osint_enricher.providers.maigret_provider import MaigretProvider
from email_osint_enricher.providers.sherlock_provider import SherlockProvider
from email_osint_enricher.providers.h8mail_provider import H8mailProvider
from email_osint_enricher.providers.phone_extractor import PhoneExtractorProvider
from email_osint_enricher.providers.emailrep_provider import EmailRepProvider
from email_osint_enricher.providers.mosint_provider import MosintProvider
from email_osint_enricher.providers.emailcrawlr_provider import EmailCrawlrProvider

# Реестр всех провайдеров (порядок = порядок выполнения в pipeline)
PROVIDER_REGISTRY: dict[str, type[BaseProvider]] = {
    "ghunt": GHuntProvider,
    "holehe": HoleheProvider,
    "blackbird": BlackbirdProvider,
    "maigret": MaigretProvider,
    "sherlock": SherlockProvider,
    "h8mail": H8mailProvider,
    "emailrep": EmailRepProvider,
    "mosint": MosintProvider,
    "emailcrawlr": EmailCrawlrProvider,
    "phone_extractor": PhoneExtractorProvider,  # always last — uses profiles from all
}

# Provider metadata for --list-providers
PROVIDER_META: dict[str, dict] = {
    "ghunt":                {"default_enabled": True,  "requires_api_key": False, "binary": "ghunt"},
    "holehe":               {"default_enabled": True,  "requires_api_key": False, "binary": "holehe"},
    "blackbird":            {"default_enabled": True,  "requires_api_key": False, "binary": "blackbird"},
    "maigret":              {"default_enabled": True,  "requires_api_key": False, "binary": "maigret"},
    "sherlock":             {"default_enabled": False, "requires_api_key": False, "binary": "sherlock"},
    "h8mail":               {"default_enabled": True,  "requires_api_key": False, "binary": "h8mail"},
    "emailrep":             {"default_enabled": True,  "requires_api_key": False, "binary": None, "api_key_env": "EMAILREP_API_KEY"},
    "mosint":               {"default_enabled": False, "requires_api_key": False, "binary": "mosint"},
    "emailcrawlr":          {"default_enabled": False, "requires_api_key": True,  "binary": None, "api_key_env": "EMAILCRAWLR_API_KEY"},
    "phone_extractor":      {"default_enabled": True,  "requires_api_key": False, "binary": None},
}

__all__ = [
    "BaseProvider", "ProviderContext", "ProviderResult",
    "GHuntProvider", "HoleheProvider", "BlackbirdProvider",
    "MaigretProvider", "SherlockProvider", "H8mailProvider",
    "PhoneExtractorProvider", "EmailRepProvider", "MosintProvider",
    "EmailCrawlrProvider",
    "PROVIDER_REGISTRY", "PROVIDER_META",
]
