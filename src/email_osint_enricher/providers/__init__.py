"""OSINT provider wrappers."""

from email_osint_enricher.providers.base import BaseProvider, ProviderContext, ProviderResult
from email_osint_enricher.providers.holehe_provider import HoleheProvider
from email_osint_enricher.providers.blackbird_provider import BlackbirdProvider
from email_osint_enricher.providers.maigret_provider import MaigretProvider
from email_osint_enricher.providers.sherlock_provider import SherlockProvider
from email_osint_enricher.providers.phone_extractor import PhoneExtractorProvider
from email_osint_enricher.providers.emailrep_provider import EmailRepProvider
from email_osint_enricher.providers.mosint_provider import MosintProvider
from email_osint_enricher.providers.emailcrawlr_provider import EmailCrawlrProvider
from email_osint_enricher.providers.hudsonrock_provider import HudsonRockProvider
from email_osint_enricher.providers.gravatar_provider import GravatarProvider
from email_osint_enricher.providers.socialscan_provider import SocialscanProvider

# Реестр всех провайдеров (порядок = порядок выполнения в pipeline)
PROVIDER_REGISTRY: dict[str, type[BaseProvider]] = {
    "holehe": HoleheProvider,
    "blackbird": BlackbirdProvider,
    "maigret": MaigretProvider,
    "sherlock": SherlockProvider,
    "emailrep": EmailRepProvider,
    "mosint": MosintProvider,
    "emailcrawlr": EmailCrawlrProvider,
    "hudsonrock": HudsonRockProvider,
    "gravatar": GravatarProvider,
    "socialscan": SocialscanProvider,
    "phone_extractor": PhoneExtractorProvider,  # always last — uses profiles from all
}

# Provider metadata for --list-providers
PROVIDER_META: dict[str, dict] = {
    "holehe":               {"default_enabled": True,  "requires_api_key": False, "binary": "holehe"},
    "blackbird":            {"default_enabled": True,  "requires_api_key": False, "binary": "blackbird"},
    "maigret":              {"default_enabled": True,  "requires_api_key": False, "binary": "maigret"},
    "sherlock":             {"default_enabled": False, "requires_api_key": False, "binary": "sherlock"},
    "emailrep":             {"default_enabled": True,  "requires_api_key": False, "binary": None, "api_key_env": "EMAILREP_API_KEY"},
    "mosint":               {"default_enabled": False, "requires_api_key": False, "binary": "mosint"},
    "emailcrawlr":          {"default_enabled": False, "requires_api_key": True,  "binary": None, "api_key_env": "EMAILCRAWLR_API_KEY"},
    "hudsonrock":           {"default_enabled": True,  "requires_api_key": False, "binary": None},
    "gravatar":             {"default_enabled": True,  "requires_api_key": False, "binary": None},
    "socialscan":           {"default_enabled": False, "requires_api_key": False, "binary": None, "pip": "socialscan"},
    "phone_extractor":      {"default_enabled": True,  "requires_api_key": False, "binary": None},
}

__all__ = [
    "BaseProvider", "ProviderContext", "ProviderResult",
    "HoleheProvider", "BlackbirdProvider",
    "MaigretProvider", "SherlockProvider",
    "PhoneExtractorProvider", "EmailRepProvider", "MosintProvider",
    "EmailCrawlrProvider", "HudsonRockProvider", "GravatarProvider",
    "SocialscanProvider",
    "PROVIDER_REGISTRY", "PROVIDER_META",
]
