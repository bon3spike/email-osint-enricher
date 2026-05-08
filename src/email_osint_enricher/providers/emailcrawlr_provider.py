"""EmailCrawlr provider — API-based email intelligence.

Source: https://emailcrawlr.com/
Requires EMAILCRAWLR_API_KEY env var. Skips gracefully if no key.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Optional

import httpx

from email_osint_enricher.providers.base import BaseProvider, ProviderContext
from email_osint_enricher.schemas import EmailCrawlrResult

logger = logging.getLogger("enricher")

EMAILCRAWLR_API_URL = "https://api.emailcrawlr.com/v2/email/lookup"


class EmailCrawlrProvider(BaseProvider):
    """API wrapper for EmailCrawlr email intelligence."""

    name = "emailcrawlr"

    def __init__(
        self,
        timeout: int = 60,
        raw_output_dir: Optional[Path] = None,
        api_key: Optional[str] = None,
    ):
        self.timeout = timeout
        self.raw_output_dir = raw_output_dir
        self.api_key = api_key or os.getenv("EMAILCRAWLR_API_KEY", "")

    async def should_run(self, context: ProviderContext) -> bool:
        if not self.api_key:
            logger.debug("EmailCrawlr API key not set — skipping")
            return False
        return True

    async def run(self, context: ProviderContext) -> EmailCrawlrResult:
        result = EmailCrawlrResult(checked=True)

        if not self.api_key:
            result.error = "no_api_key"
            return result

        try:
            headers = {
                "x-api-key": self.api_key,
                "Accept": "application/json",
            }

            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(
                    EMAILCRAWLR_API_URL,
                    params={"email": context.email},
                    headers=headers,
                )

                if resp.status_code == 401:
                    result.error = "invalid_api_key"
                    return result
                if resp.status_code == 429:
                    result.error = "rate_limited"
                    return result
                if resp.status_code != 200:
                    result.error = f"http_{resp.status_code}"
                    return result

                data = resp.json()
                result.success = True

                # Social accounts
                social = data.get("social_accounts", data.get("social", []))
                if isinstance(social, list):
                    result.social_accounts_count = len(social)
                    result.social_accounts_list = [str(s) for s in social[:30]]

                # Deliverability
                result.deliverability = data.get("deliverable", data.get("deliverability", ""))

                # Domain emails
                domain_emails = data.get("domain_emails", [])
                result.domain_emails_count = len(domain_emails) if isinstance(domain_emails, list) else 0

                # Confidence
                conf = 0.3  # base for successful lookup
                if result.social_accounts_count >= 3:
                    conf += 0.4
                elif result.social_accounts_count >= 1:
                    conf += 0.2
                if result.deliverability in ("true", True, "yes"):
                    conf += 0.2
                result.confidence_score = min(conf, 1.0)

                result.raw = data
                result.raw_json_path = self.save_raw(context.email, data)

        except httpx.TimeoutException:
            result.error = "timeout"
        except Exception as e:
            logger.error(f"EmailCrawlr error: {e}")
            result.error = str(e)

        return result

    def normalize_result(self, result: EmailCrawlrResult) -> dict:
        return {
            "emailcrawlr_checked": result.checked,
            "emailcrawlr_success": result.success,
            "emailcrawlr_social_accounts_count": result.social_accounts_count,
            "emailcrawlr_social_accounts_list": ", ".join(result.social_accounts_list),
            "emailcrawlr_deliverability": result.deliverability,
            "emailcrawlr_domain_emails_count": result.domain_emails_count,
            "emailcrawlr_raw_json_path": result.raw_json_path,
            "emailcrawlr_confidence_score": result.confidence_score,
            "emailcrawlr_error": result.error,
        }

