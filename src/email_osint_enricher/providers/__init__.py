"""OSINT provider wrappers."""

from email_osint_enricher.providers.ghunt_provider import GHuntProvider
from email_osint_enricher.providers.holehe_provider import HoleheProvider

__all__ = ["GHuntProvider", "HoleheProvider"]
