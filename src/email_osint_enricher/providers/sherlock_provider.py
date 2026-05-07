"""Sherlock provider — fast username fallback.

Repo: https://github.com/sherlock-project/sherlock

Strategy:
  A) CLI: `sherlock <username> --print-found --json`
  B) Если не установлен — пропустить.

Sherlock:
  - Ищет username на 400+ social networks
  - Быстрее Maigret, но менее глубокий
  - Используется как fallback если Maigret выключен или недоступен
"""

from __future__ import annotations

import asyncio
import json
import logging
import tempfile
from pathlib import Path
from typing import Optional

from email_osint_enricher.providers.base import BaseProvider, ProviderContext, ProviderResult
from email_osint_enricher.schemas import SherlockResult

logger = logging.getLogger("enricher")


class SherlockProvider(BaseProvider):
    """Sherlock — быстрый поиск username на 400+ платформах."""

    name = "sherlock"

    def __init__(
        self,
        timeout: int = 120,
        raw_output_dir: Optional[Path] = None,
    ):
        self.timeout = timeout
        self.raw_output_dir = raw_output_dir

    async def should_run(self, context: ProviderContext) -> bool:
        """Sherlock запускается если есть username candidates."""
        return len(context.username_candidates) > 0

    async def run(self, context: ProviderContext) -> SherlockResult:
        """Запустить Sherlock по username candidates."""
        result = SherlockResult(checked=True)

        all_profiles: list[str] = []

        # Проверяем первые 3 username (Sherlock быстрый)
        for username in context.username_candidates[:3]:
            try:
                profiles = await self._search_username(username)
                all_profiles.extend(profiles)
            except Exception as e:
                logger.debug(f"Sherlock error для {username}: {e}")
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
            result.confidence_score = 0.85
        elif result.profiles_count >= 5:
            result.confidence_score = 0.65
        elif result.profiles_count >= 2:
            result.confidence_score = 0.4
        elif result.profiles_count >= 1:
            result.confidence_score = 0.25
        else:
            result.confidence_score = 0.1

        raw_data = {
            "email": context.email,
            "usernames_checked": context.username_candidates[:3],
            "profiles_count": result.profiles_count,
            "profiles": unique,
        }
        result.raw = raw_data
        result.raw_json_path = self._save_raw(context.email, raw_data)

        return result

    async def _search_username(self, username: str) -> list[str]:
        """Запустить Sherlock CLI для одного username."""
        profiles: list[str] = []

        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                output_file = Path(tmpdir) / f"{username}.json"

                proc = await asyncio.wait_for(
                    asyncio.create_subprocess_exec(
                        "sherlock", username,
                        "--print-found",
                        "--output", str(Path(tmpdir) / username),
                        "--folderoutput", tmpdir,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    ),
                    timeout=self.timeout,
                )
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(),
                    timeout=self.timeout,
                )

                # Парсим JSON output файлы
                for json_file in Path(tmpdir).glob("*.json"):
                    try:
                        data = json.loads(json_file.read_text())
                        if isinstance(data, dict):
                            for site_name, site_data in data.items():
                                if isinstance(site_data, dict):
                                    url = site_data.get("url_user", "")
                                    status = site_data.get("status", {})
                                    if isinstance(status, dict):
                                        status_msg = status.get("message", "")
                                    else:
                                        status_msg = str(status)
                                    if url and "claimed" in status_msg.lower():
                                        profiles.append(url)
                    except Exception:
                        pass

                # Fallback: парсим stdout
                if not profiles and stdout:
                    profiles.extend(self._parse_stdout(stdout.decode()))

        except FileNotFoundError:
            logger.info("Sherlock CLI не найден. Установите: pip install sherlock-project")
        except asyncio.TimeoutError:
            logger.warning(f"Sherlock timeout для {username}")
        except Exception as e:
            logger.debug(f"Sherlock error: {e}")

        return profiles

    def _parse_stdout(self, text: str) -> list[str]:
        """Парсить stdout Sherlock."""
        import re
        profiles: list[str] = []
        for line in text.splitlines():
            line = line.strip()
            if "[+]" in line:
                urls = re.findall(r'https?://\S+', line)
                profiles.extend(urls)
        return profiles

    def normalize_result(self, result: SherlockResult) -> dict:
        return {
            "sherlock_checked": result.checked,
            "sherlock_success": result.success,
            "sherlock_profiles_count": result.profiles_count,
            "sherlock_profiles_list": ", ".join(result.profiles_list[:20]),
            "sherlock_raw_json_path": result.raw_json_path,
            "sherlock_confidence_score": result.confidence_score,
            "sherlock_error": result.error,
        }

    def _save_raw(self, email: str, data: dict) -> Optional[str]:
        if not self.raw_output_dir:
            return None
        self.raw_output_dir.mkdir(parents=True, exist_ok=True)
        safe_name = email.replace("@", "_at_").replace(".", "_")
        path = self.raw_output_dir / f"{safe_name}.json"
        path.write_text(json.dumps(data, indent=2, ensure_ascii=False))
        return str(path)
