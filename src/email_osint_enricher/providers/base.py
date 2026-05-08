"""Base provider interface — единый контракт для всех OSINT-провайдеров."""

from __future__ import annotations

import json
import logging
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Optional

from pydantic import BaseModel, Field

logger = logging.getLogger("enricher")


class ProviderContext(BaseModel):
    """Контекст, передаваемый между провайдерами в pipeline."""

    email: str
    email_normalized: str = ""
    email_domain: str = ""
    email_type: str = ""

    # Из входного CSV
    applicant_name: Optional[str] = None
    applicant_country: Optional[str] = None
    applicant_id: Optional[str] = None

    # Генерированные username-кандидаты
    username_candidates: list[str] = Field(default_factory=list)

    # Накопленные URL профилей от предыдущих провайдеров
    profiles_found: list[str] = Field(default_factory=list)

    # Корпоративный домен (если corporate email)
    corporate_domain: Optional[str] = None

    # Персональные сайты
    personal_website_urls: list[str] = Field(default_factory=list)

    # Флаги

    is_google_email: bool = False
    is_google_workspace: bool = False

    # Proxy
    proxy: Optional[str] = None


class ProviderResult(BaseModel):
    """Базовый результат провайдера."""

    provider_name: str = ""
    checked: bool = False
    success: bool = False
    confidence_score: float = 0.0
    error: Optional[str] = None
    raw_json_path: Optional[str] = None
    raw: dict[str, Any] = Field(default_factory=dict)


class BaseProvider(ABC):
    """Абстрактный базовый класс для OSINT-провайдеров.

    Каждый провайдер реализует:
    - name: уникальное имя
    - should_run(): нужно ли запускать для данного контекста
    - run(): основная логика
    - normalize_result(): маппинг raw → полей EnrichmentResult
    """

    name: str = "base"

    def __init__(
        self,
        timeout: int = 120,
        raw_output_dir: Optional[Path] = None,
        **kwargs: Any,
    ):
        self.timeout = timeout
        self.raw_output_dir = raw_output_dir

    @abstractmethod
    async def should_run(self, context: ProviderContext) -> bool:
        """Определить, нужно ли запускать провайдер для данного email."""
        ...

    @abstractmethod
    async def run(self, context: ProviderContext) -> ProviderResult:
        """Выполнить OSINT-запрос. Возвращает ProviderResult."""
        ...

    def normalize_result(self, result: ProviderResult) -> dict[str, Any]:
        """Преобразовать ProviderResult в dict полей для EnrichmentResult.

        По умолчанию возвращает базовые поля.
        Переопределяется в каждом провайдере.
        """
        prefix = self.name
        return {
            f"{prefix}_checked": result.checked,
            f"{prefix}_success": result.success,
            f"{prefix}_confidence_score": result.confidence_score,
            f"{prefix}_error": result.error,
            f"{prefix}_raw_json_path": result.raw_json_path,
        }

    # ── Shared utilities ─────────────────────────────────────────────────

    def save_raw(self, email: str, data: Any) -> Optional[str]:
        """Save raw JSON data to output directory. Returns path or None."""
        if not self.raw_output_dir:
            return None
        self.raw_output_dir.mkdir(parents=True, exist_ok=True)
        safe_name = email.replace("@", "_at_").replace(".", "_")
        path = self.raw_output_dir / f"{safe_name}.json"

        def _ser(obj: Any) -> Any:
            if isinstance(obj, set):
                return list(obj)
            return str(obj)

        path.write_text(
            json.dumps(data, indent=2, ensure_ascii=False, default=_ser),
            encoding="utf-8",
        )
        return str(path)

    @staticmethod
    def compute_confidence(count: int, thresholds: tuple[int, int, int] = (5, 2, 1)) -> float:
        """Standard confidence scoring by count.

        thresholds = (high, medium, low) — count thresholds.
        Returns 0.9 / 0.6 / 0.3 / 0.1 based on which threshold is met.
        """
        high, medium, low = thresholds
        if count >= high:
            return 0.9
        elif count >= medium:
            return 0.6
        elif count >= low:
            return 0.3
        return 0.1
