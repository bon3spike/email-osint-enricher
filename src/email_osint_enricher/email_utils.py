"""Email normalization, classification, and masking helpers."""

from __future__ import annotations

import re
from email_osint_enricher.schemas import EmailType

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

_EMAIL_RE = re.compile(r"^[a-zA-Z0-9_.+\-]+@[a-zA-Z0-9\-]+\.[a-zA-Z0-9\-.]+$")


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
    """Classify email into a type."""
    domain = get_domain(email)
    if not domain:
        return EmailType.unknown
    if domain in GOOGLE_DOMAINS:
        return EmailType.gmail
    if domain in FREE_PROVIDERS:
        return EmailType.free_provider
    # Heuristic: if domain has known TLDs and looks corporate
    # Google Workspace detection would need DNS MX lookup — mark as corporate for now
    return EmailType.corporate


def is_google_email(email: str, force: bool = False) -> bool:
    """Check if email should be processed by GHunt."""
    if force:
        return True
    domain = get_domain(email)
    return domain in GOOGLE_DOMAINS


def mask_email(email: str) -> str:
    """Mask email for log output: j***@domain.com."""
    local, _, domain = email.partition("@")
    if not domain or len(local) == 0:
        return "***@***"
    return f"{local[0]}***@{domain}"
