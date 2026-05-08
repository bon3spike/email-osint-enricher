"""Maigret provider — deep username OSINT.

Repo: https://github.com/soxoj/maigret

Strategy:
  A) CLI: `maigret <username> --json ndjson --timeout 30`
  B) Если не установлен — пропустить.

Maigret:
  - Собирает dossier по username
  - Проверяет аккаунты на большом количестве сайтов
  - Собирает доступную информацию с веб-страниц
  - No API keys required
  - Используется ПОСЛЕ генерации username candidates
"""

from __future__ import annotations

import asyncio
import json
import logging
import tempfile
from pathlib import Path
from typing import Optional

from email_osint_enricher.providers.base import BaseProvider, ProviderContext, ProviderResult
from email_osint_enricher.schemas import MaigretResult

logger = logging.getLogger("enricher")


class MaigretProvider(BaseProvider):
    """Maigret — глубокий OSINT по username."""

    name = "maigret"

    def __init__(
        self,
        timeout: int = 300,
        raw_output_dir: Optional[Path] = None,
    ):
        self.timeout = timeout
        self.raw_output_dir = raw_output_dir

    async def should_run(self, context: ProviderContext) -> bool:
        """Maigret запускается только если есть username candidates."""
        return len(context.username_candidates) > 0

    async def run(self, context: ProviderContext) -> MaigretResult:
        """Запустить Maigret по username candidates."""
        result = MaigretResult(checked=True)
        result.username_candidates = context.username_candidates[:5]

        all_profiles: list[str] = []

        # Обрабатываем первые 2 username (Maigret медленный)
        for username in context.username_candidates[:2]:
            try:
                profiles = await self._search_username(username, context.email)
                all_profiles.extend(profiles)
            except Exception as e:
                logger.warning(f"Maigret error для {username}: {e}")
                if not result.error:
                    result.error = str(e)

        # Дедупликация
        seen: set[str] = set()
        unique: list[str] = []
        for p in all_profiles:
            if p not in seen:
                seen.add(p)
                unique.append(p)

        result.profiles_list = unique
        result.profiles_count = len(unique)
        result.success = True

        # Confidence
        if result.profiles_count >= 10:
            result.confidence_score = 0.9
        elif result.profiles_count >= 5:
            result.confidence_score = 0.7
        elif result.profiles_count >= 2:
            result.confidence_score = 0.5
        elif result.profiles_count >= 1:
            result.confidence_score = 0.3
        else:
            result.confidence_score = 0.1

        # Save raw
        raw_data = {
            "email": context.email,
            "usernames_checked": result.username_candidates,
            "profiles_count": result.profiles_count,
            "profiles": unique,
        }
        result.raw = raw_data
        result.raw_json_path = self.save_raw(context.email, raw_data)

        return result

    async def _search_username(self, username: str, email: str) -> list[str]:
        """Запустить Maigret CLI для одного username."""
        profiles: list[str] = []

        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                report_path = Path(tmpdir) / "report.json"

                proc = await asyncio.wait_for(
                    asyncio.create_subprocess_exec(
                        "maigret", username,
                        "--json", "ndjson",
                        "--folderoutput", tmpdir,
                        "--timeout", "30",
                        "--no-color",
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    ),
                    timeout=self.timeout,
                )
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(),
                    timeout=self.timeout,
                )

                if proc.returncode == 0 or proc.returncode is None:
                    # Парсим output файлы
                    for json_file in Path(tmpdir).glob("*.json"):
                        try:
                            text = json_file.read_text()
                            # NDJSON формат — одна строка на запись
                            for line in text.splitlines():
                                line = line.strip()
                                if not line:
                                    continue
                                try:
                                    entry = json.loads(line)
                                    url = entry.get("url_user") or entry.get("url") or ""
                                    status = entry.get("status", {})
                                    if isinstance(status, dict):
                                        status_str = status.get("status", "")
                                    else:
                                        status_str = str(status)
                                    if url and "claimed" in status_str.lower():
                                        profiles.append(url)
                                except json.JSONDecodeError:
                                    continue
                        except Exception:
                            pass

                    # Fallback: парсим stdout
                    if not profiles and stdout:
                        profiles.extend(self._parse_stdout(stdout.decode()))

                else:
                    if stderr:
                        logger.debug(f"Maigret stderr: {stderr.decode()[:500]}")

        except FileNotFoundError:
            logger.info("Maigret CLI не найден. Установите: pip install maigret")
        except asyncio.TimeoutError:
            logger.warning(f"Maigret timeout для {username}")
        except Exception as e:
            logger.debug(f"Maigret error: {e}")

        return profiles

    def _parse_stdout(self, text: str) -> list[str]:
        """Парсить текстовый stdout Maigret."""
        import re
        profiles: list[str] = []
        for line in text.splitlines():
            line = line.strip()
            if "[+]" in line or "Claimed" in line:
                urls = re.findall(r'https?://\S+', line)
                profiles.extend(urls)
        return profiles

    def normalize_result(self, result: MaigretResult) -> dict:
        return {
            "maigret_checked": result.checked,
            "maigret_success": result.success,
            "maigret_username_candidates": ", ".join(result.username_candidates),
            "maigret_profiles_count": result.profiles_count,
            "maigret_profiles_list": ", ".join(result.profiles_list[:20]),
            "maigret_report_path": result.report_path,
            "maigret_raw_json_path": result.raw_json_path,
            "maigret_confidence_score": result.confidence_score,
            "maigret_error": result.error,
        }

