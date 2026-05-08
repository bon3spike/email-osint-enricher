"""Email normalization, classification, masking, DNS/MX checks."""

from __future__ import annotations

import asyncio
import dns.resolver
import logging
import re
from functools import lru_cache
from email_osint_enricher.schemas import EmailType

logger = logging.getLogger("enricher")

# Well-known free providers (lowercase domains)
FREE_PROVIDERS: set[str] = {
    "gmail.com", "googlemail.com",
    "yahoo.com", "yahoo.co.uk", "yahoo.co.jp", "ymail.com",
    "outlook.com", "hotmail.com", "live.com", "msn.com",
    "protonmail.com", "proton.me", "pm.me",
    "icloud.com", "me.com", "mac.com",
    "aol.com",
    "mail.com",
    "zoho.com",
    "yandex.ru", "yandex.com",
    "mail.ru", "inbox.ru", "list.ru", "bk.ru",
    "gmx.com", "gmx.de",
    "tutanota.com", "tuta.io",
    "fastmail.com",
    "hey.com",
}

GOOGLE_DOMAINS: set[str] = {"gmail.com", "googlemail.com"}

# Known Google MX patterns
_GOOGLE_MX_PATTERNS = [
    "google.com",
    "googlemail.com",
    "aspmx.l.google.com",
    "smtp.google.com",
]

_EMAIL_RE = re.compile(r"^[a-zA-Z0-9_.+\-]+@[a-zA-Z0-9\-]+\.[a-zA-Z0-9\-.]+$")

# Cache for MX lookups
_mx_cache: dict[str, list[str]] = {}
_gws_cache: dict[str, bool] = {}


def is_valid_email(email: str) -> bool:
    """Basic email format validation."""
    return bool(_EMAIL_RE.match(email.strip()))


def normalize_email(email: str) -> str:
    """Lowercase + strip. For Gmail: remove dots and +alias from local part."""
    email = email.strip().lower()
    local, _, domain = email.partition("@")
    if not domain:
        return email

    if domain in GOOGLE_DOMAINS:
        # Remove dots and +alias
        local = local.split("+")[0].replace(".", "")

    return f"{local}@{domain}"


def get_domain(email: str) -> str:
    """Extract domain from email."""
    _, _, domain = email.strip().lower().partition("@")
    return domain


def classify_email(email: str) -> EmailType:
    """Classify email into a type. Uses cached MX data if available."""
    domain = get_domain(email)
    if not domain:
        return EmailType.unknown
    if domain in GOOGLE_DOMAINS:
        return EmailType.gmail
    if domain in FREE_PROVIDERS:
        return EmailType.free_provider
    # Check if we already know it's Google Workspace
    if _gws_cache.get(domain, False):
        return EmailType.google_workspace
    return EmailType.corporate


def is_google_email(email: str, force: bool = False) -> bool:
    """Check if email is a Google email (gmail/workspace)."""
    if force:
        return True
    domain = get_domain(email)
    if domain in GOOGLE_DOMAINS:
        return True
    # Check Google Workspace cache
    return _gws_cache.get(domain, False)


def mask_email(email: str) -> str:
    """Mask email for log output: j***@domain.com."""
    local, _, domain = email.partition("@")
    if not domain or len(local) == 0:
        return "***@***"
    return f"{local[0]}***@{domain}"


# ── DNS / MX utilities ──────────────────────────────────────────────────────

def lookup_mx(domain: str, timeout: float = 5.0) -> list[str]:
    """Lookup MX records for a domain. Returns list of MX hostnames (lowercase).
    Results are cached."""
    if domain in _mx_cache:
        return _mx_cache[domain]

    try:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = timeout
        resolver.timeout = timeout
        answers = resolver.resolve(domain, "MX")
        mx_hosts = [str(rdata.exchange).rstrip(".").lower() for rdata in answers]
        _mx_cache[domain] = mx_hosts
        return mx_hosts
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
            dns.resolver.NoNameservers, dns.resolver.Timeout,
            dns.exception.DNSException) as e:
        logger.debug(f"MX lookup failed for {domain}: {e}")
        _mx_cache[domain] = []
        return []


def has_mx_record(domain: str) -> bool:
    """Check if domain has any MX records (email is potentially deliverable)."""
    return len(lookup_mx(domain)) > 0


def is_google_workspace(domain: str) -> bool:
    """Detect Google Workspace by checking MX records for Google patterns.
    Results are cached."""
    if domain in _gws_cache:
        return _gws_cache[domain]

    if domain in GOOGLE_DOMAINS:
        _gws_cache[domain] = True
        return True

    mx_hosts = lookup_mx(domain)
    is_gws = any(
        any(pattern in mx_host for pattern in _GOOGLE_MX_PATTERNS)
        for mx_host in mx_hosts
    )
    _gws_cache[domain] = is_gws

    if is_gws:
        logger.info(f"Detected Google Workspace domain: {domain}")

    return is_gws


async def async_lookup_mx(domain: str, timeout: float = 5.0) -> list[str]:
    """Async wrapper for MX lookup (runs in thread pool)."""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, lookup_mx, domain, timeout)


async def async_is_google_workspace(domain: str) -> bool:
    """Async wrapper for Google Workspace detection."""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, is_google_workspace, domain)


def precheck_domains(emails: list[str]) -> dict[str, dict]:
    """Batch precheck unique domains: MX records + Google Workspace detection.
    Returns dict[domain] -> {has_mx, is_google_workspace, mx_hosts}."""
    domains = set(get_domain(e) for e in emails)
    results = {}

    for domain in domains:
        if not domain:
            continue
        mx = lookup_mx(domain)
        gws = is_google_workspace(domain)
        results[domain] = {
            "has_mx": len(mx) > 0,
            "is_google_workspace": gws,
            "mx_hosts": mx,
        }

    return results


async def precheck_domains_async(emails: list[str]) -> dict[str, dict]:
    """Async parallel domain precheck: MX + Google Workspace detection.

    Runs all DNS lookups concurrently via thread pool — much faster for
    large batches with many unique domains.
    """
    domains = set(get_domain(e) for e in emails)
    domains.discard("")

    loop = asyncio.get_event_loop()

    async def _check_one(domain: str) -> tuple[str, dict]:
        mx = await loop.run_in_executor(None, lookup_mx, domain)
        gws = await loop.run_in_executor(None, is_google_workspace, domain)
        return domain, {
            "has_mx": len(mx) > 0,
            "is_google_workspace": gws,
            "mx_hosts": mx,
        }

    results_list = await asyncio.gather(*[_check_one(d) for d in domains])
    return dict(results_list)
