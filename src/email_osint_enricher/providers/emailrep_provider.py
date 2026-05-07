"""EmailRep provider — email reputation and risk scoring.

API: https://emailrep.io/
Supports authenticated (EMAILREP_API_KEY) and unauthenticated modes.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Optional

import httpx

from email_osint_enricher.providers.base import BaseProvider, ProviderContext
from email_osint_enricher.schemas import EmailRepResult

logger = logging.getLogger("enricher")

EMAILREP_API_URL = "https://emailrep.io/{email}"


class EmailRepProvider(BaseProvider):
    """Email reputation lookup via emailrep.io API."""

    name = "emailrep"

    def __init__(
        self,
        timeout: int = 60,
        raw_output_dir: Optional[Path] = None,
        api_key: Optional[str] = None,
    ):
        self.timeout = timeout
        self.raw_output_dir = raw_output_dir
        self.api_key = api_key or os.getenv("EMAILREP_API_KEY", "")

    async def should_run(self, context: ProviderContext) -> bool:
        return True

    async def run(self, context: ProviderContext) -> EmailRepResult:
        result = EmailRepResult(checked=True)
        try:
            headers = {"Accept": "application/json", "User-Agent": "email-osint-enricher/0.2"}
            if self.api_key:
                headers["Key"] = self.api_key

            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(
                    EMAILREP_API_URL.format(email=context.email),
                    headers=headers,
                )

                if resp.status_code == 429:
                    logger.warning("EmailRep rate limited")
                    result.error = "rate_limited"
                    return result

                if resp.status_code != 200:
                    logger.warning(f"EmailRep returned {resp.status_code}")
                    result.error = f"http_{resp.status_code}"
                    return result

                data = resp.json()
                result.success = True
                result.reputation = data.get("reputation", "")
                result.suspicious = data.get("suspicious", False)
                result.references = data.get("references", 0)

                details = data.get("details", {})
                summary_parts = []
                if details.get("profiles"):
                    summary_parts.append(f"profiles: {', '.join(details['profiles'])}")
                if details.get("data_breach"):
                    summary_parts.append("data_breach: yes")
                if details.get("malicious_activity"):
                    summary_parts.append("malicious: yes")
                if details.get("spam"):
                    summary_parts.append("spam: yes")
                if details.get("deliverable"):
                    summary_parts.append("deliverable: yes")
                if details.get("domain_exists"):
                    summary_parts.append("domain_exists: yes")
                result.details_summary = "; ".join(summary_parts)

                # Risk score: higher = riskier
                risk = 0.0
                if result.suspicious:
                    risk += 0.4
                if details.get("malicious_activity"):
                    risk += 0.3
                if details.get("spam"):
                    risk += 0.2
                if details.get("data_breach"):
                    risk += 0.1
                result.risk_score = min(risk, 1.0)

                result.raw = data
                result.raw_json_path = self._save_raw(context.email, data)

        except httpx.TimeoutException:
            logger.warning("EmailRep timed out")
            result.error = "timeout"
        except Exception as e:
            logger.error(f"EmailRep error: {e}")
            result.error = str(e)

        return result

    def normalize_result(self, result: EmailRepResult) -> dict:
        return {
            "emailrep_checked": result.checked,
            "emailrep_success": result.success,
            "emailrep_reputation": result.reputation,
            "emailrep_suspicious": result.suspicious,
            "emailrep_references": result.references,
            "emailrep_details_summary": result.details_summary,
            "emailrep_risk_score": result.risk_score,
            "emailrep_raw_json_path": result.raw_json_path,
            "emailrep_error": result.error,
        }

    def _save_raw(self, email: str, data: dict) -> Optional[str]:
        if not self.raw_output_dir:
            return None
        self.raw_output_dir.mkdir(parents=True, exist_ok=True)
        safe = email.replace("@", "_at_").replace(".", "_")
        path = self.raw_output_dir / f"{safe}.json"
        path.write_text(json.dumps(data, indent=2, ensure_ascii=False))
        return str(path)
