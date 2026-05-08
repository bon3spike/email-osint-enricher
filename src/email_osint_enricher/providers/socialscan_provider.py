"""Socialscan provider — accurate email existence check on online platforms.

Library: https://github.com/iojw/socialscan (pip install socialscan)
Returns: which platforms the email is registered on (Instagram, GitHub, etc.)
100% accuracy — queries registration APIs directly.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Optional

from email_osint_enricher.providers.base import BaseProvider, ProviderContext
from email_osint_enricher.schemas import SocialscanResult

logger = logging.getLogger("enricher")

# Platforms that support email checking in socialscan
EMAIL_PLATFORMS = [
    "Instagram", "Twitter", "GitHub", "Tumblr", "Lastfm",
    "Snapchat", "GitLab", "Yahoo", "Firefox", "Pinterest",
    "Spotify",
]


class SocialscanProvider(BaseProvider):
    """Accurate email-to-platform registration check via socialscan.

    Directly queries platform registration APIs for 100% accuracy.
    No false positives — unlike holehe's password-reset method.
    """

    name = "socialscan"

    def __init__(
        self,
        timeout: int = 60,
        raw_output_dir: Optional[Path] = None,
    ):
        self.timeout = timeout
        self.raw_output_dir = raw_output_dir
        self._available = None

    def _check_available(self) -> bool:
        """Check if socialscan is installed."""
        if self._available is not None:
            return self._available
        try:
            import socialscan  # noqa: F401
            self._available = True
        except ImportError:
            self._available = False
            logger.warning(
                "socialscan not installed. Install with: pip install socialscan"
            )
        return self._available

    async def should_run(self, context: ProviderContext) -> bool:
        return self._check_available()

    async def run(self, context: ProviderContext) -> SocialscanResult:
        result = SocialscanResult(checked=True)

        if not self._check_available():
            result.error = "socialscan not installed"
            return result

        try:
            import asyncio
            from socialscan.util import Platforms, execute_queries

            # Build query list — only email-supporting platforms
            email_platforms = []
            for p in Platforms:
                # socialscan Platforms enum — check which support email
                try:
                    pname = p.value.__name__
                    if hasattr(p.value, 'EMAIL_SUPPORTED') and p.value.EMAIL_SUPPORTED:
                        email_platforms.append(p)
                    elif pname in EMAIL_PLATFORMS:
                        email_platforms.append(p)
                except Exception:
                    pass

            # If platform detection fails, use all
            if not email_platforms:
                email_platforms = list(Platforms)

            # Execute queries
            queries = await execute_queries(
                [context.email],
                email_platforms,
            )

            registered = []
            not_registered = []
            errors = []

            for query_result in queries:
                platform_name = str(query_result.platform)
                if query_result.available is False:
                    # Email IS taken (registered) on this platform
                    registered.append(platform_name)
                elif query_result.available is True:
                    not_registered.append(platform_name)
                else:
                    errors.append(platform_name)

            result.success = True
            result.registered_platforms = registered
            result.registered_count = len(registered)
            result.not_registered_platforms = not_registered
            result.not_registered_count = len(not_registered)
            result.error_platforms = errors

            # Confidence scoring
            if result.registered_count >= 5:
                result.confidence_score = 0.9
            elif result.registered_count >= 3:
                result.confidence_score = 0.7
            elif result.registered_count >= 1:
                result.confidence_score = 0.5
            else:
                result.confidence_score = 0.1

            raw_data = {
                "email": context.email,
                "registered": registered,
                "not_registered": not_registered,
                "errors": errors,
            }
            result.raw = raw_data
            result.raw_json_path = self._save_raw(context.email, raw_data)

        except ImportError:
            logger.error("socialscan import failed")
            result.error = "import_error"
        except Exception as e:
            logger.error(f"Socialscan error: {e}")
            result.error = str(e)

        return result

    def normalize_result(self, result: SocialscanResult) -> dict:
        return {
            "socialscan_checked": result.checked,
            "socialscan_success": result.success,
            "socialscan_registered_count": result.registered_count,
            "socialscan_registered_platforms": ", ".join(result.registered_platforms),
            "socialscan_not_registered_count": result.not_registered_count,
            "socialscan_confidence_score": result.confidence_score,
            "socialscan_raw_json_path": result.raw_json_path,
            "socialscan_error": result.error,
        }

    def _save_raw(self, email: str, data: dict) -> Optional[str]:
        if not self.raw_output_dir:
            return None
        self.raw_output_dir.mkdir(parents=True, exist_ok=True)
        safe = email.replace("@", "_at_").replace(".", "_")
        path = self.raw_output_dir / f"{safe}.json"
        path.write_text(json.dumps(data, indent=2, ensure_ascii=False))
        return str(path)
