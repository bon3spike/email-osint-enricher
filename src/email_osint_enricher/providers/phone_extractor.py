"""Public Profile Phone Extractor — извлечение телефонов из публичных страниц.

Извлекает телефонные кандидаты из публично доступных URL/профилей,
найденных другими провайдерами (GHunt, Holehe, Blackbird, Maigret, Sherlock).

Правила:
- Не обходить login walls
- Не скрейпить приватные данные
- Не тригерить контактные формы, сброс пароля, SMS, email, уведомления
- Только публичные страницы без авторизации
- Уважать robots.txt
- Rate limits и таймауты
- Сохранять source URL для каждого кандидата
- Извлечённый номер НЕ считается верифицированным
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from pathlib import Path
from typing import Optional
from urllib.parse import urljoin, urlparse

from email_osint_enricher.providers.base import BaseProvider, ProviderContext
from email_osint_enricher.schemas import PhoneCandidate, PhoneExtractorResult

logger = logging.getLogger("enricher")

# ── Regex паттерны для телефонов ─────────────────────────────────────────────

_PHONE_INTL_RE = re.compile(
    r'(?<!\d)'
    r'(\+\d{1,4}'
    r'[\s\-\.()]*'
    r'(?:\d[\s\-\.()]*){6,14}'
    r'\d)'
    r'(?!\d)',
)

_TEL_LINK_RE = re.compile(r'href=["\']tel:([^"\']+)["\']', re.IGNORECASE)

_WHATSAPP_RE = re.compile(
    r'(?:wa\.me/|api\.whatsapp\.com/send\?phone=|whatsapp\.com/send\?phone=)'
    r'(\+?\d{7,15})',
    re.IGNORECASE,
)

_TELEGRAM_RE = re.compile(r't\.me/\+(\d{7,15})', re.IGNORECASE)

_CONTACT_PAGE_RE = re.compile(
    r'href=["\']([^"\']*(?:contact|about|kontakt|связ|контакт|обратн)[^"\']*)["\']',
    re.IGNORECASE,
)

_FALSE_POSITIVE_RE = re.compile(
    r'^\d{4}[-/]\d{2}[-/]\d{2}$'
    r'|^\d{1,5}$'
    r'|^0{4,}'
)


class PhoneExtractorProvider(BaseProvider):
    """Извлекает телефонные кандидаты из публичных URL."""

    name = "phone_extractor"

    def __init__(
        self,
        timeout: int = 30,
        max_pages_per_profile: int = 3,
        rate_delay: float = 1.0,
        raw_output_dir: Optional[Path] = None,
        proxy: Optional[str] = None,
    ):
        self.timeout = timeout
        self.max_pages_per_profile = max_pages_per_profile
        self.rate_delay = rate_delay
        self.raw_output_dir = raw_output_dir
        self.proxy = proxy

    async def should_run(self, context: ProviderContext) -> bool:
        """Запускается если есть URL профилей или корпоративный домен."""
        return bool(
            context.profiles_found
            or context.corporate_domain
            or context.personal_website_urls
        )

    async def run(self, context: ProviderContext) -> PhoneExtractorResult:
        """Извлечь телефонных кандидатов из публичных URL."""
        result = PhoneExtractorResult(checked=True)

        # Собираем все URL для обработки
        all_urls: list[str] = []

        if context.profiles_found:
            all_urls.extend(context.profiles_found)
        if context.personal_website_urls:
            all_urls.extend(context.personal_website_urls)
        if context.corporate_domain:
            for suffix in ["/contact", "/about", "/contacts", "/kontakt", ""]:
                all_urls.append(f"https://{context.corporate_domain}{suffix}")

        # Дедупликация URL
        seen_urls: set[str] = set()
        unique_urls: list[str] = []
        for url in all_urls:
            url = url.strip()
            if not url or url in seen_urls:
                continue
            if not url.startswith(("http://", "https://")):
                url = f"https://{url}"
            seen_urls.add(url)
            unique_urls.append(url)

        if not unique_urls:
            result.success = True
            result.phone_candidates_found = False
            return result

        urls_to_process = unique_urls[:self.max_pages_per_profile * 3]
        logger.info(f"Phone extractor: проверяю {len(urls_to_process)} публичных URL")

        all_candidates: list[PhoneCandidate] = []

        try:
            import httpx

            client_kwargs = {
                "timeout": self.timeout,
                "follow_redirects": True,
                "headers": {
                    "User-Agent": "Mozilla/5.0 (compatible; email-osint-enricher/0.1)",
                    "Accept": "text/html,application/xhtml+xml",
                },
            }
            if self.proxy or context.proxy:
                client_kwargs["proxy"] = self.proxy or context.proxy

            async with httpx.AsyncClient(**client_kwargs) as client:
                for url in urls_to_process:
                    try:
                        candidates = await self._process_url(client, url)
                        all_candidates.extend(candidates)
                    except Exception as e:
                        logger.debug(f"Ошибка при обработке {url}: {e}")
                    if self.rate_delay > 0:
                        await asyncio.sleep(self.rate_delay)

        except ImportError:
            logger.warning("httpx не установлен — phone_extractor пропущен")
            result.success = False
            result.phone_extraction_error = "httpx not installed"
            return result
        except Exception as e:
            logger.error(f"Phone extractor error: {e}")
            result.success = False
            result.phone_extraction_error = str(e)
            return result

        merged = self._deduplicate_candidates(all_candidates, context.applicant_country)

        result.success = True
        result.phone_candidates_list = merged
        result.phone_candidates_count = len(merged)
        result.phone_candidates_found = len(merged) > 0

        if merged:
            best = max(merged, key=lambda c: c.confidence_score)
            if best.confidence_score >= 50:
                result.phone_candidate_best = best.phone_number
                result.phone_candidate_source_url = best.source_url
                result.phone_candidate_source_provider = best.source_provider
                result.phone_candidate_context = best.context_snippet
                result.phone_candidate_confidence_score = best.confidence_score
            else:
                result.phone_candidate_best = None
                result.phone_candidate_confidence_score = best.confidence_score

        self._save_raw(context.email, result)
        return result

    async def _process_url(self, client, url: str) -> list[PhoneCandidate]:
        """Обработать одну публичную страницу."""
        candidates: list[PhoneCandidate] = []

        try:
            if not await self._check_robots(client, url):
                return candidates

            resp = await client.get(url)
            if resp.status_code != 200:
                return candidates

            content_type = resp.headers.get("content-type", "")
            if "text/html" not in content_type and "text/plain" not in content_type:
                return candidates

            html = resp.text[:500_000]

            is_contact_page = bool(re.search(
                r'(?:contact|about|kontakt|связ|контакт)', url.lower()
            ))
            source_provider = self._detect_provider(url)

            # 1. tel: ссылки (+50)
            for match in _TEL_LINK_RE.finditer(html):
                phone = self._clean_phone(match.group(1))
                if phone:
                    candidates.append(PhoneCandidate(
                        phone_number=phone, source_url=url,
                        source_provider=source_provider,
                        extraction_method="tel_link", confidence_score=50,
                        context_snippet=self._extract_context(html, match.start(), match.end()),
                    ))

            # 2. WhatsApp (+45)
            for match in _WHATSAPP_RE.finditer(html):
                phone = self._clean_phone(match.group(1))
                if phone:
                    candidates.append(PhoneCandidate(
                        phone_number=phone, source_url=url,
                        source_provider=source_provider,
                        extraction_method="whatsapp_link", confidence_score=45,
                        context_snippet=self._extract_context(html, match.start(), match.end()),
                    ))

            # 3. Telegram (+40)
            for match in _TELEGRAM_RE.finditer(html):
                phone = self._clean_phone("+" + match.group(1))
                if phone:
                    candidates.append(PhoneCandidate(
                        phone_number=phone, source_url=url,
                        source_provider=source_provider,
                        extraction_method="telegram_link", confidence_score=40,
                        context_snippet=self._extract_context(html, match.start(), match.end()),
                    ))

            # 4. Phone regex (+40 contact page / +20 other)
            base_conf = 40 if is_contact_page else 20
            for match in _PHONE_INTL_RE.finditer(html):
                phone = self._clean_phone(match.group(1))
                if phone and not _FALSE_POSITIVE_RE.match(phone.replace("+", "")):
                    candidates.append(PhoneCandidate(
                        phone_number=phone, source_url=url,
                        source_provider=source_provider,
                        extraction_method="regex_international",
                        confidence_score=base_conf,
                        context_snippet=self._extract_context(html, match.start(), match.end()),
                    ))

            # 5. Подстраницы contact/about (1 уровень)
            if not is_contact_page:
                for sub_url in self._find_contact_links(html, url)[:2]:
                    try:
                        sub = await self._process_url(client, sub_url)
                        candidates.extend(sub)
                        await asyncio.sleep(self.rate_delay)
                    except Exception:
                        pass

        except Exception as e:
            logger.debug(f"Ошибка обработки {url}: {e}")

        return candidates

    async def _check_robots(self, client, url: str) -> bool:
        try:
            parsed = urlparse(url)
            robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
            resp = await client.get(robots_url)
            if resp.status_code == 200:
                text = resp.text.lower()
                path = parsed.path or "/"
                if f"disallow: {path.lower()}" in text and "user-agent: *" in text:
                    return False
            return True
        except Exception:
            return True

    def _detect_provider(self, url: str) -> str:
        domain = urlparse(url).netloc.lower()
        for key, prov in {
            "github.com": "github", "linkedin.com": "linkedin",
            "twitter.com": "twitter", "x.com": "twitter",
            "facebook.com": "facebook", "instagram.com": "instagram",
            "t.me": "telegram", "vk.com": "vk", "youtube.com": "youtube",
        }.items():
            if key in domain:
                return prov
        return "web"

    def _clean_phone(self, raw: str) -> str | None:
        cleaned = re.sub(r'[\s\-\.\(\)]', '', raw.strip())
        if not re.match(r'^[\+\d]', cleaned):
            return None
        digits = re.sub(r'\D', '', cleaned)
        if len(digits) < 7 or len(digits) > 15:
            return None
        try:
            import phonenumbers
            parsed = phonenumbers.parse(cleaned, None)
            if phonenumbers.is_valid_number(parsed):
                return phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
            if not cleaned.startswith("+"):
                parsed = phonenumbers.parse("+" + cleaned, None)
                if phonenumbers.is_valid_number(parsed):
                    return phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
        except Exception:
            pass
        if cleaned.startswith("+") and len(digits) >= 10:
            return cleaned
        return None

    def _extract_context(self, html: str, start: int, end: int, window: int = 100) -> str:
        snippet = html[max(0, start - window):min(len(html), end + window)]
        snippet = re.sub(r'<[^>]+>', ' ', snippet)
        snippet = re.sub(r'\s+', ' ', snippet).strip()
        return snippet[:300]

    def _find_contact_links(self, html: str, base_url: str) -> list[str]:
        links: list[str] = []
        for match in _CONTACT_PAGE_RE.finditer(html):
            href = match.group(1)
            if href.startswith(("http://", "https://")):
                links.append(href)
            elif href.startswith("/"):
                links.append(urljoin(base_url, href))
        return links

    def _deduplicate_candidates(
        self, candidates: list[PhoneCandidate], applicant_country: str | None = None,
    ) -> list[PhoneCandidate]:
        if not candidates:
            return []
        phone_groups: dict[str, list[PhoneCandidate]] = {}
        for c in candidates:
            phone_groups.setdefault(c.phone_number, []).append(c)

        merged: list[PhoneCandidate] = []
        for phone, group in phone_groups.items():
            best = max(group, key=lambda c: c.confidence_score)
            score = best.confidence_score

            unique_urls = set(c.source_url for c in group)
            if len(unique_urls) > 1:
                score += 20

            if applicant_country:
                try:
                    import phonenumbers
                    parsed = phonenumbers.parse(phone, None)
                    cc = phonenumbers.region_code_for_number(parsed)
                    if cc and cc.lower() == applicant_country.lower()[:2]:
                        score += 30
                except Exception:
                    pass

            try:
                import phonenumbers
                parsed = phonenumbers.parse(phone, None)
                if not phonenumbers.is_valid_number(parsed):
                    score -= 30
            except Exception:
                score -= 10

            best.confidence_score = max(0, min(100, score))
            if len(unique_urls) > 1:
                best.context_snippet = (
                    f"[Найден на {len(unique_urls)} страницах] " + (best.context_snippet or "")
                )[:300]
            merged.append(best)

        merged.sort(key=lambda c: c.confidence_score, reverse=True)
        return merged

    def normalize_result(self, result: PhoneExtractorResult) -> dict:
        return {
            "phone_extractor_checked": result.checked,
            "phone_candidates_found": result.phone_candidates_found,
            "phone_candidates_count": result.phone_candidates_count,
            "phone_candidates_list": ", ".join(c.phone_number for c in result.phone_candidates_list[:10]),
            "phone_candidate_best": result.phone_candidate_best,
            "phone_candidate_source_url": result.phone_candidate_source_url,
            "phone_candidate_source_provider": result.phone_candidate_source_provider,
            "phone_candidate_context": result.phone_candidate_context,
            "phone_candidate_confidence_score": result.phone_candidate_confidence_score,
            "phone_extraction_error": result.phone_extraction_error,
        }

    def _save_raw(self, email: str, result: PhoneExtractorResult) -> None:
        if not self.raw_output_dir:
            return
        self.raw_output_dir.mkdir(parents=True, exist_ok=True)
        safe_name = email.replace("@", "_at_").replace(".", "_")
        path = self.raw_output_dir / f"{safe_name}.json"
        data = {
            "email": email,
            "candidates_count": result.phone_candidates_count,
            "best_candidate": result.phone_candidate_best,
            "best_confidence": result.phone_candidate_confidence_score,
            "candidates": [c.model_dump() for c in result.phone_candidates_list],
        }
        path.write_text(json.dumps(data, indent=2, ensure_ascii=False))
