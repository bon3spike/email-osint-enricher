"""User Email Enrichment provider — free reverse email/identity lookup.

Repo: https://github.com/taitems/user-email-enrichment
JS/NPM-based — subprocess wrapper.
"""

from __future__ import annotations

import asyncio
import json
import logging
import shutil
from pathlib import Path
from typing import Optional

from email_osint_enricher.providers.base import BaseProvider, ProviderContext
from email_osint_enricher.schemas import UserEnrichmentResult

logger = logging.getLogger("enricher")


class UserEmailEnrichmentProvider(BaseProvider):
    """Subprocess wrapper for user-email-enrichment NPM tool."""

    name = "user_email_enrichment"

    def __init__(
        self,
        timeout: int = 120,
        raw_output_dir: Optional[Path] = None,
        command: str = "user-email-enrichment",
    ):
        self.timeout = timeout
        self.raw_output_dir = raw_output_dir
        self.command = command

    async def should_run(self, context: ProviderContext) -> bool:
        return True

    async def run(self, context: ProviderContext) -> UserEnrichmentResult:
        result = UserEnrichmentResult(checked=True)

        # Check for npx or direct binary
        cmd = self.command
        if not shutil.which(cmd):
            if shutil.which("npx"):
                cmd = "npx"
            else:
                logger.info(f"'{self.command}' and npx not found — skipping")
                result.error = "binary_not_found"
                return result

        try:
            args = [cmd]
            if cmd == "npx":
                args.extend(["-y", "user-email-enrichment"])
            args.append(context.email)

            proc = await asyncio.wait_for(
                asyncio.create_subprocess_exec(
                    *args,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                ),
                timeout=self.timeout,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=self.timeout,
            )

            if proc.returncode != 0:
                logger.warning(f"user-email-enrichment returned code {proc.returncode}")
                result.error = f"exit_code_{proc.returncode}"
                return result

            output = stdout.decode().strip()
            if not output:
                result.error = "empty_output"
                return result

            data = json.loads(output)
            result.success = True
            result.name = data.get("name") or data.get("displayName", "")
            result.avatar_url = data.get("avatar") or data.get("avatarUrl", "")

            profiles = data.get("profiles", data.get("accounts", []))
            if isinstance(profiles, list):
                result.profiles = ", ".join(
                    p.get("url", str(p)) if isinstance(p, dict) else str(p)
                    for p in profiles[:30]
                )
                result.profiles_count = len(profiles)
            elif isinstance(profiles, dict):
                result.profiles = ", ".join(
                    f"{k}: {v}" for k, v in profiles.items()
                )
                result.profiles_count = len(profiles)

            # Confidence
            conf = 0.0
            if result.name:
                conf += 0.4
            if result.avatar_url:
                conf += 0.2
            if result.profiles_count >= 3:
                conf += 0.4
            elif result.profiles_count >= 1:
                conf += 0.2
            result.confidence_score = min(conf, 1.0)

            result.raw = data
            result.raw_json_path = self._save_raw(context.email, data)

        except asyncio.TimeoutError:
            result.error = "timeout"
        except json.JSONDecodeError:
            result.error = "invalid_json"
        except Exception as e:
            logger.error(f"user-email-enrichment error: {e}")
            result.error = str(e)

        return result

    def normalize_result(self, result: UserEnrichmentResult) -> dict:
        return {
            "user_enrichment_checked": result.checked,
            "user_enrichment_success": result.success,
            "user_enrichment_name": result.name,
            "user_enrichment_avatar_url": result.avatar_url,
            "user_enrichment_profiles": result.profiles,
            "user_enrichment_profiles_count": result.profiles_count,
            "user_enrichment_raw_json_path": result.raw_json_path,
            "user_enrichment_confidence_score": result.confidence_score,
            "user_enrichment_error": result.error,
        }

    def _save_raw(self, email: str, data: dict) -> Optional[str]:
        if not self.raw_output_dir:
            return None
        self.raw_output_dir.mkdir(parents=True, exist_ok=True)
        safe = email.replace("@", "_at_").replace(".", "_")
        path = self.raw_output_dir / f"{safe}.json"
        path.write_text(json.dumps(data, indent=2, ensure_ascii=False, default=str))
        return str(path)
