"""Base provider interface — единый контракт для всех OSINT-провайдеров."""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
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
    force_ghunt: bool = False
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
