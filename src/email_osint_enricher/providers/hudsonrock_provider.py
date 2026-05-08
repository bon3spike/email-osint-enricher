"""HudsonRock provider — Cybercrime Intelligence (infostealers & breaches).

API: https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email
Free, no API key required.
Returns: infostealer infections, compromised credentials, breach dates, computer info.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Optional

import httpx

from email_osint_enricher.providers.base import BaseProvider, ProviderContext
from email_osint_enricher.schemas import HudsonRockResult

logger = logging.getLogger("enricher")

HUDSONROCK_API_URL = "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email"


class HudsonRockProvider(BaseProvider):
    """Cybercrime intelligence lookup via HudsonRock free API.

    Checks if the email is associated with computers infected by info-stealers.
    Returns compromised credential counts, infection dates, and risk signals.
    """

    name = "hudsonrock"

    def __init__(
        self,
        timeout: int = 30,
        raw_output_dir: Optional[Path] = None,
    ):
        self.timeout = timeout
        self.raw_output_dir = raw_output_dir

    async def should_run(self, context: ProviderContext) -> bool:
        return True

    async def run(self, context: ProviderContext) -> HudsonRockResult:
        result = HudsonRockResult(checked=True)
        try:
            headers = {
                "Accept": "application/json",
                "User-Agent": "email-osint-enricher/0.4",
            }

            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(
                    HUDSONROCK_API_URL,
                    params={"email": context.email},
                    headers=headers,
                )

                if resp.status_code == 429:
                    logger.warning("HudsonRock rate limited")
                    result.error = "rate_limited"
                    return result

                if resp.status_code != 200:
                    logger.warning(f"HudsonRock returned {resp.status_code}")
                    result.error = f"http_{resp.status_code}"
                    return result

                data = resp.json()
                result.success = True
                result.raw = data

                stealers = data.get("stealers", [])
                result.stealers_count = len(stealers)
                result.is_compromised = result.stealers_count > 0

                if stealers:
                    # Aggregate stats from all stealer entries
                    total_corporate = 0
                    total_user = 0
                    dates = []
                    os_list = []

                    for s in stealers:
                        total_corporate += s.get("total_corporate_services", 0)
                        total_user += s.get("total_user_services", 0)
                        date_comp = s.get("date_compromised", "")
                        if date_comp and date_comp != "Not Found":
                            dates.append(date_comp[:10])  # Just the date part
                        os_name = s.get("operating_system", "Not Found")
                        if os_name and os_name != "Not Found":
                            os_list.append(os_name)

                    result.total_corporate_services = total_corporate
                    result.total_user_services = total_user
                    result.compromised_dates = ", ".join(dates[:5])
                    result.operating_systems = ", ".join(set(os_list)[:3])

                    # Latest infection date
                    if dates:
                        result.latest_compromise_date = max(dates)

                    # Confidence: more stealers = more confident the email is real
                    if result.stealers_count >= 3:
                        result.confidence_score = 0.9
                    elif result.stealers_count >= 1:
                        result.confidence_score = 0.7
                else:
                    # No stealers found — doesn't mean email isn't real,
                    # just no cybercrime data
                    result.confidence_score = 0.1

                result.raw_json_path = self._save_raw(context.email, data)

        except httpx.TimeoutException:
            logger.warning("HudsonRock timed out")
            result.error = "timeout"
        except Exception as e:
            logger.error(f"HudsonRock error: {e}")
            result.error = str(e)

        return result

    def normalize_result(self, result: HudsonRockResult) -> dict:
        return {
            "hudsonrock_checked": result.checked,
            "hudsonrock_success": result.success,
            "hudsonrock_is_compromised": result.is_compromised,
            "hudsonrock_stealers_count": result.stealers_count,
            "hudsonrock_total_corporate_services": result.total_corporate_services,
            "hudsonrock_total_user_services": result.total_user_services,
            "hudsonrock_latest_compromise_date": result.latest_compromise_date,
            "hudsonrock_compromised_dates": result.compromised_dates,
            "hudsonrock_operating_systems": result.operating_systems,
            "hudsonrock_confidence_score": result.confidence_score,
            "hudsonrock_raw_json_path": result.raw_json_path,
            "hudsonrock_error": result.error,
        }

    def _save_raw(self, email: str, data: dict) -> Optional[str]:
        if not self.raw_output_dir:
            return None
        self.raw_output_dir.mkdir(parents=True, exist_ok=True)
        safe = email.replace("@", "_at_").replace(".", "_")
        path = self.raw_output_dir / f"{safe}.json"
        path.write_text(json.dumps(data, indent=2, ensure_ascii=False))
        return str(path)
