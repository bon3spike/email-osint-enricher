"""Mosint provider — Go-based email OSINT tool.

Repo: https://github.com/alpkeskin/mosint
Subprocess wrapper — requires `mosint` binary in PATH.
"""

from __future__ import annotations

import asyncio
import json
import logging
import shutil
from pathlib import Path
from typing import Optional

from email_osint_enricher.providers.base import BaseProvider, ProviderContext
from email_osint_enricher.schemas import MosintResult

logger = logging.getLogger("enricher")


class MosintProvider(BaseProvider):
    """Subprocess wrapper for Mosint email OSINT tool."""

    name = "mosint"

    def __init__(
        self,
        timeout: int = 180,
        raw_output_dir: Optional[Path] = None,
        command: str = "mosint",
    ):
        self.timeout = timeout
        self.raw_output_dir = raw_output_dir
        self.command = command

    async def should_run(self, context: ProviderContext) -> bool:
        return True

    async def run(self, context: ProviderContext) -> MosintResult:
        result = MosintResult(checked=True)

        if not shutil.which(self.command):
            logger.info(f"Mosint binary '{self.command}' not found in PATH — skipping")
            result.error = "binary_not_found"
            return result

        try:
            proc = await asyncio.wait_for(
                asyncio.create_subprocess_exec(
                    self.command, context.email, "-o", "json",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                ),
                timeout=self.timeout,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=self.timeout,
            )

            if proc.returncode != 0:
                logger.warning(f"Mosint returned code {proc.returncode}")
                result.error = f"exit_code_{proc.returncode}"
                if stderr:
                    logger.debug(f"Mosint stderr: {stderr.decode()[:500]}")
                return result

            if not stdout.strip():
                result.error = "empty_output"
                return result

            data = json.loads(stdout.decode())
            result.success = True
            result = self._parse_output(data, result)
            result.raw = data
            result.raw_json_path = self._save_raw(context.email, data)

        except asyncio.TimeoutError:
            logger.warning("Mosint timed out")
            result.error = "timeout"
        except json.JSONDecodeError as e:
            logger.warning(f"Mosint output not valid JSON: {e}")
            result.error = "invalid_json"
        except Exception as e:
            logger.error(f"Mosint error: {e}")
            result.error = str(e)

        return result

    def _parse_output(self, data: dict, result: MosintResult) -> MosintResult:
        services = set()
        findings = 0

        # Social signals
        social = data.get("social", data.get("social_media", []))
        if social:
            result.social_signal = True
            findings += len(social) if isinstance(social, list) else 1
            services.add("social")

        # Breach signals
        breaches = data.get("breaches", data.get("breach", []))
        if breaches:
            result.breach_signal = True
            findings += len(breaches) if isinstance(breaches, list) else 1
            services.add("breach")

        # Domain signals
        domain_info = data.get("domain", data.get("dns", {}))
        if domain_info:
            result.domain_signal = True
            findings += 1
            services.add("domain")

        # Other sections
        for key in ["related_emails", "related_phones", "pastebin", "google_results"]:
            section = data.get(key, [])
            if section:
                findings += len(section) if isinstance(section, list) else 1
                services.add(key)

        result.services_used = ", ".join(sorted(services))
        result.findings_count = findings

        # Confidence
        if findings >= 5:
            result.confidence_score = 0.8
        elif findings >= 2:
            result.confidence_score = 0.5
        elif findings >= 1:
            result.confidence_score = 0.3
        else:
            result.confidence_score = 0.1

        return result

    def normalize_result(self, result: MosintResult) -> dict:
        return {
            "mosint_checked": result.checked,
            "mosint_success": result.success,
            "mosint_services_used": result.services_used,
            "mosint_findings_count": result.findings_count,
            "mosint_social_signal": result.social_signal,
            "mosint_breach_signal": result.breach_signal,
            "mosint_domain_signal": result.domain_signal,
            "mosint_raw_json_path": result.raw_json_path,
            "mosint_confidence_score": result.confidence_score,
            "mosint_error": result.error,
        }

    def _save_raw(self, email: str, data: dict) -> Optional[str]:
        if not self.raw_output_dir:
            return None
        self.raw_output_dir.mkdir(parents=True, exist_ok=True)
        safe = email.replace("@", "_at_").replace(".", "_")
        path = self.raw_output_dir / f"{safe}.json"
        path.write_text(json.dumps(data, indent=2, ensure_ascii=False))
        return str(path)
