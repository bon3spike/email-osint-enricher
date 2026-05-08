"""Gravatar provider — profile and avatar lookup via email hash.

API: https://gravatar.com/{md5_hash}.json
Free, no API key required.
Returns: display name, avatar URL, profile bio, location, verified accounts.
"""

from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path
from typing import Optional

import httpx

from email_osint_enricher.providers.base import BaseProvider, ProviderContext
from email_osint_enricher.schemas import GravatarResult

logger = logging.getLogger("enricher")

GRAVATAR_API_URL = "https://gravatar.com/{hash}.json"
GRAVATAR_AVATAR_URL = "https://gravatar.com/avatar/{hash}"


class GravatarProvider(BaseProvider):
    """Profile and avatar lookup via Gravatar.

    Uses MD5 hash of the email to query Gravatar's JSON API.
    Returns display name, avatar, bio, location, and linked accounts.
    """

    name = "gravatar"

    def __init__(
        self,
        timeout: int = 15,
        raw_output_dir: Optional[Path] = None,
    ):
        self.timeout = timeout
        self.raw_output_dir = raw_output_dir

    async def should_run(self, context: ProviderContext) -> bool:
        return True

    async def run(self, context: ProviderContext) -> GravatarResult:
        result = GravatarResult(checked=True)
        email_lower = context.email.strip().lower()
        email_hash = hashlib.md5(email_lower.encode()).hexdigest()

        try:
            headers = {
                "Accept": "application/json",
                "User-Agent": "email-osint-enricher/0.4",
            }

            async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
                resp = await client.get(
                    GRAVATAR_API_URL.format(hash=email_hash),
                    headers=headers,
                )

                if resp.status_code == 404:
                    # No Gravatar profile — email may still be valid
                    result.success = True
                    result.has_profile = False
                    result.confidence_score = 0.0
                    return result

                if resp.status_code == 429:
                    logger.warning("Gravatar rate limited")
                    result.error = "rate_limited"
                    return result

                if resp.status_code != 200:
                    logger.warning(f"Gravatar returned {resp.status_code}")
                    result.error = f"http_{resp.status_code}"
                    return result

                data = resp.json()
                result.success = True
                result.has_profile = True
                result.raw = data

                # Parse profile entries
                entries = data.get("entry", [])
                if entries:
                    entry = entries[0]

                    result.display_name = entry.get("displayName", "")
                    result.avatar_url = GRAVATAR_AVATAR_URL.format(hash=email_hash)

                    name_data = entry.get("name", {})
                    if name_data:
                        formatted = name_data.get("formatted", "")
                        if formatted:
                            result.full_name = formatted

                    result.profile_url = entry.get("profileUrl", "")
                    result.about_me = entry.get("aboutMe", "")

                    # Current location
                    result.location = entry.get("currentLocation", "")

                    # Photos
                    photos = entry.get("photos", [])
                    if photos:
                        result.avatar_url = photos[0].get("value", result.avatar_url)

                    # Linked accounts (very valuable for OSINT)
                    accounts = entry.get("accounts", [])
                    linked = []
                    for acc in accounts:
                        shortname = acc.get("shortname", "")
                        url = acc.get("url", "")
                        display = acc.get("display", "")
                        if url:
                            linked.append(f"{shortname}: {url}")
                        elif display:
                            linked.append(f"{shortname}: {display}")
                    result.linked_accounts = linked
                    result.linked_accounts_count = len(linked)

                    # URLs from profile
                    urls = entry.get("urls", [])
                    result.profile_urls = [u.get("value", "") for u in urls if u.get("value")]

                    # Confidence scoring
                    confidence = 0.3  # Base: profile exists
                    if result.display_name:
                        confidence += 0.1
                    if result.full_name:
                        confidence += 0.15
                    if result.linked_accounts_count > 0:
                        confidence += min(0.25, result.linked_accounts_count * 0.05)
                    if result.about_me:
                        confidence += 0.1
                    if result.location:
                        confidence += 0.1
                    result.confidence_score = min(confidence, 1.0)

                result.raw_json_path = self.save_raw(context.email, data)

        except httpx.TimeoutException:
            logger.warning("Gravatar timed out")
            result.error = "timeout"
        except Exception as e:
            logger.error(f"Gravatar error: {e}")
            result.error = str(e)

        return result

    def normalize_result(self, result: GravatarResult) -> dict:
        return {
            "gravatar_checked": result.checked,
            "gravatar_success": result.success,
            "gravatar_has_profile": result.has_profile,
            "gravatar_display_name": result.display_name,
            "gravatar_full_name": result.full_name,
            "gravatar_avatar_url": result.avatar_url,
            "gravatar_profile_url": result.profile_url,
            "gravatar_about_me": result.about_me,
            "gravatar_location": result.location,
            "gravatar_linked_accounts_count": result.linked_accounts_count,
            "gravatar_linked_accounts": ", ".join(result.linked_accounts),
            "gravatar_confidence_score": result.confidence_score,
            "gravatar_raw_json_path": result.raw_json_path,
            "gravatar_error": result.error,
        }

