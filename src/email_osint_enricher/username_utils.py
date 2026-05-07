"""Генерация username-кандидатов из email и applicantName.

Используется для Blackbird, Maigret, Sherlock — провайдеры, которые
ищут аккаунты по username.
"""

from __future__ import annotations

import re
import unicodedata


def _normalize_name_part(s: str) -> str:
    """Убрать акценты, привести к ascii lowercase."""
    nfkd = unicodedata.normalize("NFKD", s)
    ascii_only = nfkd.encode("ascii", "ignore").decode("ascii")
    return ascii_only.lower().strip()


def _split_name(name: str) -> list[str]:
    """Разбить имя на части, убрать пустые."""
    parts = re.split(r"[\s\-_\.]+", name.strip())
    return [_normalize_name_part(p) for p in parts if p]


def generate_username_candidates(
    email: str,
    applicant_name: str | None = None,
    max_candidates: int = 10,
) -> list[str]:
    """Генерировать username-кандидаты из email и/или имени.

    Примеры:
        email="john.doe@corp.com" → ["john.doe", "johndoe", "john_doe", "jdoe"]
        applicantName="John Doe" → ["john.doe", "johndoe", "john_doe", "jdoe", "doejohn"]

    Returns:
        Список уникальных username-кандидатов (до max_candidates).
    """
    candidates: list[str] = []

    # ── Из email local part ──────────────────────────────────────────────
    local = email.split("@")[0].lower().strip() if "@" in email else ""

    if local:
        # Оригинальный local part
        candidates.append(local)

        # Без точек и подчёркиваний
        plain = re.sub(r"[._\-]", "", local)
        if plain != local:
            candidates.append(plain)

        # Заменить точки на подчёркивания и наоборот
        if "." in local:
            candidates.append(local.replace(".", "_"))
        if "_" in local:
            candidates.append(local.replace("_", "."))

        # Убрать +alias для Gmail
        if "+" in local:
            base = local.split("+")[0]
            candidates.append(base)

        # Убрать trailing цифры: johndoe123 → johndoe
        stripped = re.sub(r"\d+$", "", local)
        if stripped and stripped != local and stripped != plain:
            candidates.append(stripped)

        # Первая буква + фамилия: j.doe → jdoe
        parts = re.split(r"[._\-]", local)
        if len(parts) >= 2:
            # jdoe
            candidates.append(parts[0][0] + parts[-1])
            # doej
            candidates.append(parts[-1] + parts[0][0])

    # ── Из applicantName ─────────────────────────────────────────────────
    if applicant_name:
        name_parts = [p for p in _split_name(applicant_name) if p]  # filter empty after ascii norm
        if name_parts:
            # john.doe
            candidates.append(".".join(name_parts))
            # johndoe
            candidates.append("".join(name_parts))
            # john_doe
            candidates.append("_".join(name_parts))

            if len(name_parts) >= 2:
                first = name_parts[0]
                last = name_parts[-1]

                if not first or not last:
                    pass  # skip name combos if ascii normalization emptied parts
                    first = first or "x"
                    last = last or "x"

                # jdoe
                candidates.append(first[0] + last)
                # doej
                candidates.append(last + first[0])
                # doejohn
                candidates.append(last + first)
                # john.d
                candidates.append(first + "." + last[0])
                # j.doe
                candidates.append(first[0] + "." + last)

    # ── Дедупликация + фильтрация ────────────────────────────────────────
    seen: set[str] = set()
    unique: list[str] = []
    for c in candidates:
        c = c.strip()
        if not c or len(c) <= 2 or c in seen:
            continue
        # Убрать если только цифры или слишком короткий
        if c.isdigit():
            continue
        seen.add(c)
        unique.append(c)

    return unique[:max_candidates]
