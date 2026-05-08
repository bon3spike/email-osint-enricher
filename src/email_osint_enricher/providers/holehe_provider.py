"""Holehe provider wrapper — email-to-registered-accounts OSINT.

Strategy:
  A) Try to import holehe as a Python library and call its async modules.
  B) Fallback: invoke `holehe <email> --only-used` via subprocess.
  C) If neither works, return an empty result without crashing.
"""

from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path
from typing import Optional

from email_osint_enricher.providers.base import BaseProvider, ProviderContext
from email_osint_enricher.schemas import HoleheResult
from email_osint_enricher.scoring import SOCIAL_SERVICES, PROFESSIONAL_SERVICES

logger = logging.getLogger("enricher")


class HoleheProvider(BaseProvider):
    """Wrapper around Holehe for email → registered-accounts OSINT."""

    name = "holehe"

    def __init__(
        self,
        timeout: int = 120,
        raw_output_dir: Optional[Path] = None,
        proxy: Optional[str] = None,
    ):
        self.timeout = timeout
        self.raw_output_dir = raw_output_dir
        self.proxy = proxy
        self._lib_available: Optional[bool] = None

    async def should_run(self, context: ProviderContext) -> bool:
        """Holehe запускается для всех email."""
        return True

    async def run(self, context: ProviderContext) -> HoleheResult:
        """Run Holehe enrichment."""
        self.proxy = self.proxy or context.proxy
        return await self.enrich(context.email)

    def _check_library(self) -> bool:
        if self._lib_available is None:
            try:
                import holehe  # noqa: F401
                self._lib_available = True
            except ImportError:
                self._lib_available = False
                logger.info("Holehe library not installed; will try CLI fallback")
        return self._lib_available

    async def enrich(self, email: str) -> HoleheResult:
        """Run Holehe enrichment for a single email."""
        result = HoleheResult(checked=True)

        try:
            if self._check_library():
                result = await self._enrich_via_library(email, result)
            else:
                result = await self._enrich_via_cli(email, result)
        except asyncio.TimeoutError:
            logger.warning("Holehe timed out")
            result.success = False
        except Exception as e:
            logger.error(f"Holehe error: {e}")
            result.success = False

        if result.success:
            if result.registered_services_count >= 5:
                result.confidence_score = 0.9
            elif result.registered_services_count >= 2:
                result.confidence_score = 0.6
            elif result.registered_services_count >= 1:
                result.confidence_score = 0.3
            else:
                result.confidence_score = 0.1

        return result

    async def _enrich_via_library(self, email: str, result: HoleheResult) -> HoleheResult:
        """Use holehe as Python library."""
        try:
            import httpx
            from holehe import modules
            from holehe.core import import_submodules, launch_module

            module_list = import_submodules(modules)
            out: list[dict] = []

            client_kwargs = {"timeout": self.timeout}
            if self.proxy:
                client_kwargs["proxies"] = self.proxy

            client = httpx.AsyncClient(**client_kwargs)
            try:
                tasks = []
                for module_name in module_list:
                    mod = module_list[module_name]
                    if hasattr(mod, module_name):
                        fn = getattr(mod, module_name)
                        tasks.append(
                            asyncio.wait_for(
                                launch_module(fn, email, client, out),
                                timeout=self.timeout,
                            )
                        )
                results_raw = await asyncio.gather(*tasks, return_exceptions=True)
                for r in results_raw:
                    if isinstance(r, Exception):
                        logger.debug(f"Holehe module failed: {r}")
            finally:
                await client.aclose()

            result = self._parse_modules_output(out, result)
            result.raw = {"email": email, "modules": out}
            result.raw_json_path = self.save_raw(email, result.raw)

        except ImportError as e:
            logger.warning(f"Holehe library import issue: {e}")
            result = await self._enrich_via_cli(email, result)

        return result

    async def _enrich_via_cli(self, email: str, result: HoleheResult) -> HoleheResult:
        """Fallback: call holehe CLI."""
        try:
            cmd = ["holehe", email, "--only-used"]
            if self.proxy:
                cmd.extend(["--proxy", self.proxy])

            proc = await asyncio.wait_for(
                asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                ),
                timeout=self.timeout,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=self.timeout,
            )

            if proc.returncode == 0 and stdout:
                result = self._parse_cli_text(stdout.decode(), result)
                raw_data = {"email": email, "stdout": stdout.decode(), "services": result.registered_services_list}
                result.raw = raw_data
                result.raw_json_path = self.save_raw(email, raw_data)
            else:
                logger.warning(f"Holehe CLI returned code {proc.returncode}")
                if stderr:
                    logger.debug(f"Holehe stderr: {stderr.decode()[:500]}")
                result.success = False

        except FileNotFoundError:
            logger.warning("Holehe CLI not found. Install with: pip install holehe")
            result.success = False
        except Exception as e:
            logger.warning(f"Holehe CLI fallback failed: {e}")
            result.success = False

        return result

    def _parse_modules_output(self, out: list[dict], result: HoleheResult) -> HoleheResult:
        registered = []
        recovery_hints = 0

        for entry in out:
            if not isinstance(entry, dict):
                continue
            if entry.get("exists") is True:
                name = entry.get("name", entry.get("domain", "unknown"))
                registered.append(name)
            if entry.get("phoneNumber") or entry.get("others"):
                recovery_hints += 1

        social = sum(1 for s in registered if s.lower() in SOCIAL_SERVICES)
        professional = sum(1 for s in registered if s.lower() in PROFESSIONAL_SERVICES)

        result.success = True
        result.registered_services_count = len(registered)
        result.registered_services_list = registered
        result.social_services_count = social
        result.professional_services_count = professional
        result.recovery_hints_count = recovery_hints

        return result

    def _parse_cli_text(self, text: str, result: HoleheResult) -> HoleheResult:
        registered = []

        for line in text.splitlines():
            line = line.strip()
            if line.startswith("[+]"):
                parts = line.replace("[+]", "").strip().split()
                if parts:
                    service_name = parts[0].rstrip(":")
                    registered.append(service_name)

        social = sum(1 for s in registered if s.lower() in SOCIAL_SERVICES)
        professional = sum(1 for s in registered if s.lower() in PROFESSIONAL_SERVICES)

        result.success = True
        result.registered_services_count = len(registered)
        result.registered_services_list = registered
        result.social_services_count = social
        result.professional_services_count = professional

        return result

    def normalize_result(self, result: HoleheResult) -> dict:
        return {
            "holehe_checked": result.checked,
            "holehe_success": result.success,
            "holehe_registered_services_count": result.registered_services_count,
            "holehe_registered_services_list": ", ".join(result.registered_services_list),
            "holehe_social_services_count": result.social_services_count,
            "holehe_professional_services_count": result.professional_services_count,
            "holehe_other_services_count": result.other_services_count,
            "holehe_raw_json_path": result.raw_json_path,
            "holehe_confidence_score": result.confidence_score,
            "holehe_error": result.error,
        }

