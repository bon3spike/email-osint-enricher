"""Buster provider — advanced email reconnaissance.

Repo: https://github.com/sham00n/buster
Subprocess wrapper — requires `buster` in PATH.
NO passwords/hashes/private breach details stored.
"""

from __future__ import annotations

import asyncio
import json
import logging
import shutil
from pathlib import Path
from typing import Optional

from email_osint_enricher.providers.base import BaseProvider, ProviderContext
from email_osint_enricher.schemas import BusterResult

logger = logging.getLogger("enricher")

# Fields to strip from raw output (security)
_SENSITIVE_KEYS = {"password", "hash", "passwd", "pwd", "secret", "credential"}


class BusterProvider(BaseProvider):
    """Subprocess wrapper for Buster email reconnaissance."""

    name = "buster"

    def __init__(
        self,
        timeout: int = 180,
        raw_output_dir: Optional[Path] = None,
        command: str = "buster",
    ):
        self.timeout = timeout
        self.raw_output_dir = raw_output_dir
        self.command = command

    async def should_run(self, context: ProviderContext) -> bool:
        return True

    async def run(self, context: ProviderContext) -> BusterResult:
        result = BusterResult(checked=True)

        if not shutil.which(self.command):
            logger.info(f"Buster binary '{self.command}' not found — skipping")
            result.error = "binary_not_found"
            return result

        try:
            proc = await asyncio.wait_for(
                asyncio.create_subprocess_exec(
                    self.command, "-e", context.email,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                ),
                timeout=self.timeout,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=self.timeout,
            )

            if proc.returncode != 0:
                logger.warning(f"Buster returned code {proc.returncode}")
                result.error = f"exit_code_{proc.returncode}"
                return result

            output = stdout.decode()
            if not output.strip():
                result.error = "empty_output"
                return result

            # Try JSON parsing first, fallback to text parsing
            try:
                data = json.loads(output)
                result = self._parse_json(data, result)
            except json.JSONDecodeError:
                result = self._parse_text(output, result)
                data = {"raw_text": output}

            result.success = True
            data = self._sanitize(data)
            result.raw = data
            result.raw_json_path = self._save_raw(context.email, data)

        except asyncio.TimeoutError:
            logger.warning("Buster timed out")
            result.error = "timeout"
        except Exception as e:
            logger.error(f"Buster error: {e}")
            result.error = str(e)

        return result

    def _parse_json(self, data: dict, result: BusterResult) -> BusterResult:
        # Social accounts
        social = data.get("social_accounts", data.get("social", []))
        if isinstance(social, list):
            result.social_accounts_count = len(social)
            result.social_accounts_list = [str(s) for s in social[:50]]

        # Found links
        links = data.get("links", data.get("found_links", []))
        if isinstance(links, list):
            result.found_links_count = len(links)
            result.found_links_list = [str(l) for l in links[:50]]

        # Breaches (count only, no details)
        breaches = data.get("breaches", data.get("breach", []))
        result.breach_count = len(breaches) if isinstance(breaches, list) else (1 if breaches else 0)

        # Reverse whois
        whois = data.get("reverse_whois", data.get("whois_domains", []))
        if isinstance(whois, list):
            result.reverse_whois_domains = ", ".join(str(d) for d in whois[:20])

        # Generated usernames
        usernames = data.get("usernames", data.get("generated_usernames", []))
        if isinstance(usernames, list):
            result.generated_usernames = ", ".join(str(u) for u in usernames[:20])

        # Work email candidates
        work_emails = data.get("work_emails", data.get("related_emails", []))
        if isinstance(work_emails, list):
            result.work_email_candidates = ", ".join(str(e) for e in work_emails[:20])

        return result

    def _parse_text(self, text: str, result: BusterResult) -> BusterResult:
        """Basic text output parsing."""
        lines = text.strip().splitlines()
        links = []
        for line in lines:
            line = line.strip()
            if line.startswith("http"):
                links.append(line)
        result.found_links_count = len(links)
        result.found_links_list = links[:50]
        return result

    def _sanitize(self, data) -> dict:
        """Remove sensitive fields recursively."""
        if isinstance(data, dict):
            return {
                k: self._sanitize(v)
                for k, v in data.items()
                if k.lower() not in _SENSITIVE_KEYS
            }
        if isinstance(data, list):
            return [self._sanitize(item) for item in data]
        return data

    def normalize_result(self, result: BusterResult) -> dict:
        return {
            "buster_checked": result.checked,
            "buster_success": result.success,
            "buster_social_accounts_count": result.social_accounts_count,
            "buster_social_accounts_list": ", ".join(result.social_accounts_list),
            "buster_found_links_count": result.found_links_count,
            "buster_found_links_list": ", ".join(result.found_links_list),
            "buster_breach_count": result.breach_count,
            "buster_reverse_whois_domains": result.reverse_whois_domains,
            "buster_generated_usernames": result.generated_usernames,
            "buster_work_email_candidates": result.work_email_candidates,
            "buster_raw_json_path": result.raw_json_path,
            "buster_confidence_score": result.confidence_score,
            "buster_error": result.error,
        }

    def _save_raw(self, email: str, data: dict) -> Optional[str]:
        if not self.raw_output_dir:
            return None
        self.raw_output_dir.mkdir(parents=True, exist_ok=True)
        safe = email.replace("@", "_at_").replace(".", "_")
        path = self.raw_output_dir / f"{safe}.json"
        path.write_text(json.dumps(data, indent=2, ensure_ascii=False, default=str))
        return str(path)
