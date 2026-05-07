"""GHunt provider wrapper — Google OSINT enrichment.

Strategy:
  A) Try to import ghunt as a Python library and call its async API.
  B) Fallback: invoke `ghunt email <email> --json` via subprocess.
  C) If neither works, return an empty result without crashing.
"""

from __future__ import annotations

import asyncio
import json
import logging
import subprocess
import tempfile
from pathlib import Path
from typing import Optional

from email_osint_enricher.providers.base import BaseProvider, ProviderContext
from email_osint_enricher.schemas import GHuntResult

logger = logging.getLogger("enricher")


class GHuntProvider(BaseProvider):
    """Wrapper around GHunt for email → Google account OSINT."""

    name = "ghunt"

    def __init__(
        self,
        timeout: int = 120,
        raw_output_dir: Optional[Path] = None,
    ):
        self.timeout = timeout
        self.raw_output_dir = raw_output_dir
        self._lib_available: Optional[bool] = None

    async def should_run(self, context: ProviderContext) -> bool:
        """GHunt запускается только для gmail/googlemail/workspace или --force-ghunt."""
        return (
            context.force_ghunt
            or context.is_google_email
            or context.is_google_workspace
        )

    async def run(self, context: ProviderContext) -> GHuntResult:
        """Run GHunt enrichment for a single email."""
        return await self.enrich(context.email)

    def _check_library(self) -> bool:
        """Check if ghunt Python library is importable."""
        if self._lib_available is None:
            try:
                import ghunt  # noqa: F401
                self._lib_available = True
            except ImportError:
                self._lib_available = False
                logger.info("GHunt library not installed; will try CLI fallback")
        return self._lib_available

    async def enrich(self, email: str) -> GHuntResult:
        """Run GHunt enrichment for a single email."""
        result = GHuntResult(checked=True)

        try:
            if self._check_library():
                result = await self._enrich_via_library(email, result)
            else:
                result = await self._enrich_via_cli(email, result)
        except asyncio.TimeoutError:
            logger.warning("GHunt timed out for email")
            result.success = False
        except Exception as e:
            logger.error(f"GHunt error: {e}")
            result.success = False

        # Compute provider confidence
        if result.success:
            conf = 0.0
            if result.display_name:
                conf += 0.4
            if result.gaia_id:
                conf += 0.2
            if result.profile_photo_found:
                conf += 0.15
            if any([result.youtube_found, result.google_maps_reviews_found,
                     result.calendar_public_found, result.drive_public_found]):
                conf += 0.25
            result.confidence_score = min(conf, 1.0)
            result.google_account_found = True

        return result

    async def _enrich_via_library(self, email: str, result: GHuntResult) -> GHuntResult:
        """Attempt to use ghunt as an importable Python library."""
        try:
            from ghunt.apis.peoplepa import PeoplePaHttp
            from ghunt.objects.base import GHuntCreds
            from ghunt.helpers.utils import get_authenticated_gaiaclient

            creds = GHuntCreds()
            if not creds.are_creds_loaded():
                logger.warning("GHunt credentials not found. Run `ghunt login` first.")
                result.success = False
                return result

            as_client = await get_authenticated_gaiaclient(creds)
            people_api = PeoplePaHttp(as_client)

            found, person = await asyncio.wait_for(
                people_api.people_lookup(email, "EMAIL"),
                timeout=self.timeout,
            )

            if found and person:
                result.success = True
                result.display_name = getattr(person, "name", None)
                result.gaia_id = getattr(person, "id", None)

                if hasattr(person, "profile_photos") and person.profile_photos:
                    result.profile_photo_found = True
                    result.profile_photo_url = person.profile_photos[0].url if person.profile_photos else None

                raw_data = {"email": email, "name": result.display_name, "gaia_id": result.gaia_id}
                result.raw = raw_data
                result.raw_json_path = self._save_raw(email, raw_data)
            else:
                result.success = False

        except ImportError as e:
            logger.warning(f"GHunt library import failed: {e}")
            result = await self._enrich_via_cli(email, result)

        return result

    async def _enrich_via_cli(self, email: str, result: GHuntResult) -> GHuntResult:
        """Fallback: call GHunt CLI via subprocess."""
        try:
            with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as tmp:
                tmp_path = tmp.name

            proc = await asyncio.wait_for(
                asyncio.create_subprocess_exec(
                    "ghunt", "email", email, "--json", tmp_path,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                ),
                timeout=self.timeout,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=self.timeout,
            )

            if proc.returncode == 0 and Path(tmp_path).exists():
                raw_data = json.loads(Path(tmp_path).read_text())
                result = self._parse_cli_output(raw_data, result)
                result.raw = raw_data
                result.raw_json_path = self._save_raw(email, raw_data)
            else:
                logger.warning(f"GHunt CLI returned code {proc.returncode}")
                if stderr:
                    logger.debug(f"GHunt stderr: {stderr.decode()[:500]}")
                result.success = False

            Path(tmp_path).unlink(missing_ok=True)

        except FileNotFoundError:
            logger.warning("GHunt CLI not found in PATH. Install with: pip install ghunt")
            result.success = False
        except Exception as e:
            logger.warning(f"GHunt CLI fallback failed: {e}")
            result.success = False

        return result

    def _parse_cli_output(self, data: dict, result: GHuntResult) -> GHuntResult:
        """Parse GHunt JSON output into GHuntResult."""
        result.success = True

        profile = data.get("profile", data)
        result.display_name = (
            profile.get("name") or profile.get("display_name") or data.get("name")
        )
        result.gaia_id = str(
            profile.get("gaia_id") or profile.get("id") or data.get("gaia_id") or ""
        ) or None

        photos = profile.get("profile_photos", profile.get("photos", []))
        if photos:
            result.profile_photo_found = True
            if isinstance(photos[0], dict):
                result.profile_photo_url = photos[0].get("url")
            elif isinstance(photos[0], str):
                result.profile_photo_url = photos[0]

        result.youtube_found = bool(profile.get("youtube") or data.get("youtube"))
        result.google_maps_reviews_found = bool(
            profile.get("maps") or profile.get("google_maps") or data.get("maps_reviews")
        )
        result.calendar_public_found = bool(profile.get("calendar") or data.get("calendar"))
        result.drive_public_found = bool(profile.get("drive") or data.get("drive"))

        return result

    def normalize_result(self, result: GHuntResult) -> dict:
        """Маппинг GHuntResult → поля EnrichmentResult."""
        return {
            "ghunt_checked": result.checked,
            "ghunt_success": result.success,
            "ghunt_display_name": result.display_name,
            "ghunt_gaia_id": result.gaia_id,
            "ghunt_google_account_found": result.google_account_found,
            "ghunt_profile_photo_found": result.profile_photo_found,
            "ghunt_profile_photo_url": result.profile_photo_url,
            "ghunt_google_maps_reviews_found": result.google_maps_reviews_found,
            "ghunt_youtube_found": result.youtube_found,
            "ghunt_calendar_public_found": result.calendar_public_found,
            "ghunt_drive_public_found": result.drive_public_found,
            "ghunt_raw_json_path": result.raw_json_path,
            "ghunt_confidence_score": result.confidence_score,
            "ghunt_error": result.error,
        }

    def _save_raw(self, email: str, data: dict) -> Optional[str]:
        if not self.raw_output_dir:
            return None
        self.raw_output_dir.mkdir(parents=True, exist_ok=True)
        safe_name = email.replace("@", "_at_").replace(".", "_")
        path = self.raw_output_dir / f"{safe_name}.json"
        path.write_text(json.dumps(data, indent=2, ensure_ascii=False))
        return str(path)
