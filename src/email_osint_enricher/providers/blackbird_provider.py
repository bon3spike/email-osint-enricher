"""Blackbird provider — email + username search across 600+ platforms.

Repo: https://github.com/p1ngul1n0/blackbird

Detection order:
  1) CLI `blackbird` in PATH (system-wide install)
  2) Vendored copy at `vendor/blackbird/blackbird.py` (bundled in repo)
  3) If neither found — skip gracefully.

Blackbird поддерживает:
  - Поиск по email
  - Поиск по username
  - JSON export
  - Использует WhatsMyName community data
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any, Optional

from email_osint_enricher.providers.base import BaseProvider, ProviderContext, ProviderResult
from email_osint_enricher.schemas import BlackbirdResult

logger = logging.getLogger("enricher")

# Locate vendored blackbird
_VENDOR_ROOT = Path(__file__).resolve().parents[3] / "vendor" / "blackbird"
_VENDOR_SCRIPT = _VENDOR_ROOT / "blackbird.py"


class BlackbirdProvider(BaseProvider):
    """Blackbird — поиск профилей по email и username."""

    name = "blackbird"

    def __init__(
        self,
        timeout: int = 180,
        raw_output_dir: Optional[Path] = None,
    ):
        self.timeout = timeout
        self.raw_output_dir = raw_output_dir

    async def should_run(self, context: ProviderContext) -> bool:
        """Blackbird запускается всегда (ищет и по email, и по username)."""
        return True

    async def run(self, context: ProviderContext) -> BlackbirdResult:
        """Запустить Blackbird по email и username candidates."""
        result = BlackbirdResult(checked=True)

        all_profiles: list[str] = []

        # 1. Поиск по email
        try:
            email_profiles = await self._search_email(context.email)
            result.email_profiles_count = len(email_profiles)
            all_profiles.extend(email_profiles)
        except Exception as e:
            logger.warning(f"Blackbird email search error: {e}")
            result.error = str(e)

        # 2. Поиск по username candidates (первые 3)
        for username in context.username_candidates[:3]:
            try:
                username_profiles = await self._search_username(username)
                result.username_profiles_count += len(username_profiles)
                all_profiles.extend(username_profiles)
            except Exception as e:
                logger.debug(f"Blackbird username search error for {username}: {e}")

        # Дедупликация профилей
        seen: set[str] = set()
        unique_profiles: list[str] = []
        for p in all_profiles:
            if p not in seen:
                seen.add(p)
                unique_profiles.append(p)

        result.profiles_list = unique_profiles
        result.success = True  # Даже если 0 профилей — это success (просто нет данных)

        # Confidence
        total = len(unique_profiles)
        if total >= 5:
            result.confidence_score = 0.9
        elif total >= 2:
            result.confidence_score = 0.6
        elif total >= 1:
            result.confidence_score = 0.3
        else:
            result.confidence_score = 0.1

        # Save raw
        raw_data = {
            "email": context.email,
            "email_profiles": result.email_profiles_count,
            "username_profiles": result.username_profiles_count,
            "profiles": unique_profiles,
        }
        result.raw = raw_data
        result.raw_json_path = self.save_raw(context.email, raw_data)

        return result

    async def _search_email(self, email: str) -> list[str]:
        """Поиск по email через Blackbird CLI."""
        return await self._run_blackbird("--email", email)

    async def _search_username(self, username: str) -> list[str]:
        """Поиск по username через Blackbird CLI."""
        return await self._run_blackbird("--username", username)

    def _resolve_cmd(self) -> list[str]:
        """Determine how to invoke Blackbird.

        Priority:
          1) `blackbird` binary in PATH
          2) Vendored `vendor/blackbird/blackbird.py`
        """
        if shutil.which("blackbird"):
            return ["blackbird"]
        if _VENDOR_SCRIPT.exists():
            return [sys.executable, str(_VENDOR_SCRIPT)]
        return []

    async def _run_blackbird(self, flag: str, value: str) -> list[str]:
        """Запустить Blackbird CLI и вернуть найденные URL профилей."""
        profiles: list[str] = []

        cmd = self._resolve_cmd()
        if not cmd:
            logger.info(
                "Blackbird не найден ни в PATH, ни в vendor/blackbird/. "
                "Склонируй submodule: git submodule update --init"
            )
            return profiles

        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                proc = await asyncio.wait_for(
                    asyncio.create_subprocess_exec(
                        *cmd, flag, value,
                        "--json", tmpdir,
                        "--no-update",
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                        cwd=str(_VENDOR_ROOT) if _VENDOR_SCRIPT.exists() and cmd[0] != "blackbird" else None,
                    ),
                    timeout=self.timeout,
                )
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(),
                    timeout=self.timeout,
                )

                if proc.returncode == 0:
                    # Blackbird сохраняет JSON в указанную директорию
                    for json_file in Path(tmpdir).glob("*.json"):
                        try:
                            data = json.loads(json_file.read_text())
                            profiles.extend(self._parse_results(data))
                        except Exception:
                            pass

                    # Также парсим stdout
                    if stdout:
                        profiles.extend(self._parse_stdout(stdout.decode()))
                else:
                    if stderr:
                        logger.debug(f"Blackbird stderr: {stderr.decode()[:500]}")

        except FileNotFoundError:
            logger.info("Blackbird CLI не найден.")
        except asyncio.TimeoutError:
            logger.warning(f"Blackbird timeout для {value}")
        except Exception as e:
            logger.debug(f"Blackbird error: {e}")

        return profiles

    def _parse_results(self, data: Any) -> list[str]:
        """Парсить JSON результат Blackbird."""
        profiles: list[str] = []

        if isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    url = item.get("url") or item.get("link") or ""
                    status = item.get("status", "")
                    # Blackbird маркирует найденные как "FOUND"
                    if url and ("found" in str(status).lower() or item.get("exists")):
                        profiles.append(url)
        elif isinstance(data, dict):
            sites = data.get("sites", data.get("results", []))
            if isinstance(sites, list):
                profiles.extend(self._parse_results(sites))

        return profiles

    def _parse_stdout(self, text: str) -> list[str]:
        """Парсить текстовый stdout Blackbird."""
        profiles: list[str] = []
        for line in text.splitlines():
            line = line.strip()
            # Blackbird выводит [+] Site: URL
            if "[+]" in line or "[FOUND]" in line.upper():
                # Извлечь URL
                urls = re.findall(r'https?://\S+', line)
                profiles.extend(urls)
        return profiles

    def normalize_result(self, result: BlackbirdResult) -> dict:
        """Маппинг BlackbirdResult → поля EnrichmentResult."""
        return {
            "blackbird_checked": result.checked,
            "blackbird_success": result.success,
            "blackbird_email_profiles_count": result.email_profiles_count,
            "blackbird_username_profiles_count": result.username_profiles_count,
            "blackbird_profiles_list": ", ".join(result.profiles_list[:20]),
            "blackbird_report_path": result.report_path,
            "blackbird_raw_json_path": result.raw_json_path,
            "blackbird_confidence_score": result.confidence_score,
            "blackbird_error": result.error,
        }

