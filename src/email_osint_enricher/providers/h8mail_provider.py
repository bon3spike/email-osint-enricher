"""h8mail provider — email breach / exposure / risk signal.

Repo: https://github.com/khast3x/h8mail

Strategy:
  A) CLI: `h8mail -t <email> -j <output.json>`
  B) Если не установлен — пропустить.

ВАЖНО:
  - НЕ сохранять passwords, hashes, sensitive breach contents
  - Сохранять только агрегированные признаки (кол-во упоминаний, источники, risk score)
"""

from __future__ import annotations

import asyncio
import json
import logging
import tempfile
from pathlib import Path
from typing import Optional

from email_osint_enricher.providers.base import BaseProvider, ProviderContext, ProviderResult
from email_osint_enricher.schemas import H8mailResult

logger = logging.getLogger("enricher")

# Поля, которые НЕЛЬЗЯ сохранять в raw output
_SENSITIVE_KEYS = {
    "password", "passwords", "hash", "hashes", "hashtype",
    "plaintext", "leak_data", "credential", "credentials",
}


class H8mailProvider(BaseProvider):
    """h8mail — breach/exposure/risk signal (только агрегированные данные)."""

    name = "h8mail"

    def __init__(
        self,
        timeout: int = 120,
        raw_output_dir: Optional[Path] = None,
    ):
        self.timeout = timeout
        self.raw_output_dir = raw_output_dir

    async def should_run(self, context: ProviderContext) -> bool:
        """h8mail запускается для всех email."""
        return True

    async def run(self, context: ProviderContext) -> H8mailResult:
        """Запустить h8mail для проверки breach/exposure."""
        result = H8mailResult(checked=True)

        try:
            result = await self._run_cli(context.email, result)
        except asyncio.TimeoutError:
            logger.warning("h8mail timeout")
            result.error = "timeout"
        except Exception as e:
            logger.error(f"h8mail error: {e}")
            result.error = str(e)

        return result

    async def _run_cli(self, email: str, result: H8mailResult) -> H8mailResult:
        """Запустить h8mail CLI."""
        try:
            with tempfile.NamedTemporaryFile(
                suffix=".json", delete=False, mode="w"
            ) as tmp:
                tmp_path = tmp.name

            proc = await asyncio.wait_for(
                asyncio.create_subprocess_exec(
                    "h8mail", "-t", email,
                    "-j", tmp_path,
                    "--hide", "auth",  # Скрыть sensitive данные
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
                raw_text = Path(tmp_path).read_text()
                if raw_text.strip():
                    raw_data = json.loads(raw_text)
                    result = self._parse_output(raw_data, result)
                    # Sanitize raw data перед сохранением
                    sanitized = self._sanitize_raw(raw_data)
                    result.raw = sanitized
                    result.raw_json_path = self._save_raw(email, sanitized)
            else:
                if stderr:
                    logger.debug(f"h8mail stderr: {stderr.decode()[:500]}")
                # Пробуем парсить stdout
                if stdout:
                    result = self._parse_stdout(stdout.decode(), result)

            Path(tmp_path).unlink(missing_ok=True)

        except FileNotFoundError:
            logger.info("h8mail CLI не найден. Установите: pip install h8mail")
            result.success = False
        except Exception as e:
            logger.warning(f"h8mail CLI error: {e}")
            result.error = str(e)
            result.success = False

        return result

    def _parse_output(self, data: Any, result: H8mailResult) -> H8mailResult:
        """Парсить JSON output h8mail."""
        result.success = True

        targets = []
        if isinstance(data, list):
            targets = data
        elif isinstance(data, dict):
            targets = data.get("targets", [data])

        breach_count = 0
        sources: set[str] = set()

        for target in targets:
            if not isinstance(target, dict):
                continue

            # h8mail structure: target -> breaches/data
            breaches = target.get("data", target.get("breaches", []))
            if isinstance(breaches, list):
                for breach in breaches:
                    if isinstance(breach, dict):
                        source = breach.get("source", breach.get("title", "unknown"))
                        sources.add(source)
                        breach_count += 1
                    elif isinstance(breach, str):
                        sources.add(breach)
                        breach_count += 1

            # Прямые поля
            if "num_breaches" in target:
                breach_count = max(breach_count, int(target["num_breaches"]))

        result.breach_mentions_count = breach_count
        result.sources_list = list(sources)[:20]  # Ограничить
        result.sources_count = len(sources)

        # Risk score (0-100)
        if breach_count >= 10:
            result.risk_score = 90.0
        elif breach_count >= 5:
            result.risk_score = 70.0
        elif breach_count >= 2:
            result.risk_score = 50.0
        elif breach_count >= 1:
            result.risk_score = 30.0
        else:
            result.risk_score = 0.0

        return result

    def _parse_stdout(self, text: str, result: H8mailResult) -> H8mailResult:
        """Fallback: парсить stdout h8mail."""
        result.success = True
        breach_count = 0
        sources: set[str] = set()

        for line in text.splitlines():
            line = line.strip()
            # h8mail помечает находки [+] или breach/leak mentions
            if any(keyword in line.lower() for keyword in ["breach", "leak", "found", "pwned"]):
                breach_count += 1
                # Попробовать извлечь имя источника
                if ":" in line:
                    source_part = line.split(":")[0].strip()
                    source_part = source_part.lstrip("[+]").strip()
                    if source_part and len(source_part) < 100:
                        sources.add(source_part)

        result.breach_mentions_count = breach_count
        result.sources_list = list(sources)[:20]
        result.sources_count = len(sources)

        if breach_count >= 10:
            result.risk_score = 90.0
        elif breach_count >= 5:
            result.risk_score = 70.0
        elif breach_count >= 2:
            result.risk_score = 50.0
        elif breach_count >= 1:
            result.risk_score = 30.0

        return result

    def _sanitize_raw(self, data: Any) -> dict:
        """Удалить sensitive данные из raw output.

        НИКОГДА не сохраняем passwords, hashes, credentials.
        """
        if isinstance(data, dict):
            return {
                k: self._sanitize_raw(v)
                for k, v in data.items()
                if k.lower() not in _SENSITIVE_KEYS
            }
        elif isinstance(data, list):
            return [self._sanitize_raw(item) for item in data]
        elif isinstance(data, str):
            # Не сохранять строки, похожие на хэши
            if len(data) in (32, 40, 64, 128) and all(c in "0123456789abcdef" for c in data.lower()):
                return "[REDACTED_HASH]"
            return data
        return data

    def normalize_result(self, result: H8mailResult) -> dict:
        return {
            "h8mail_checked": result.checked,
            "h8mail_success": result.success,
            "h8mail_breach_mentions_count": result.breach_mentions_count,
            "h8mail_sources_count": result.sources_count,
            "h8mail_sources_list": ", ".join(result.sources_list),
            "h8mail_risk_score": result.risk_score,
            "h8mail_raw_json_path": result.raw_json_path,
            "h8mail_error": result.error,
        }

    def _save_raw(self, email: str, data: dict) -> Optional[str]:
        if not self.raw_output_dir:
            return None
        self.raw_output_dir.mkdir(parents=True, exist_ok=True)
        safe_name = email.replace("@", "_at_").replace(".", "_")
        path = self.raw_output_dir / f"{safe_name}.json"
        path.write_text(json.dumps(data, indent=2, ensure_ascii=False))
        return str(path)
