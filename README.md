# 📧 Email OSINT Enricher

Локальный CLI-инструмент для массового OSINT-обогащения email-списков.
На вход — CSV/XLSX с email-ами, на выход — таблица со всеми найденными данными и скорингом.

**12 OSINT-провайдеров** • **8 метрик скоринга** • **CSV + XLSX + JSONL выход** • **Batch + Resume** • **Без API-ключей в базовой конфигурации**

---

## 🚀 Быстрый старт

```bash
# Клонирование и установка
git clone https://github.com/bon3spike/email-osint-enricher.git
cd email-osint-enricher
pip install -e ".[dev]"

# Один email
email-osint-enricher single -e user@gmail.com

# Пакетная обработка
email-osint-enricher batch -i emails.csv -o output/

# Просмотр всех провайдеров
email-osint-enricher list-providers
```

## 📋 Требования

- Python 3.10+
- pip (или uv)
- Для core-провайдеров: `ghunt`, `holehe`, `blackbird`, `maigret`, `sherlock`, `h8mail` — CLI-инструменты в PATH
- Для опциональных провайдеров: см. таблицу ниже

---

## 🔍 Провайдеры

### Core-провайдеры (включены по умолчанию)

| # | Провайдер | Что делает | Что собирает |
|---|-----------|-----------|--------------|
| 1 | **GHunt** | Google/Gmail OSINT | Имя, Gaia ID, фото, YouTube, Maps отзывы, Calendar, Drive |
| 2 | **Holehe** | Email → сервисы | Зарегистрированные аккаунты, разбивка social/professional |
| 3 | **Blackbird** | Email + username поиск | Профили на 600+ платформах |
| 4 | **Maigret** | Username OSINT (досье) | Глубокий поиск профилей по username-кандидатам |
| 5 | **h8mail** | Breach/утечки | Упоминания в утечках, источники, risk_score |
| 6 | **EmailRep** | Репутация email | reputation, suspicious, references, risk_score |
| 7 | **Phone Extractor** | Извлечение телефонов | Парсит публичные URL-ы от других провайдеров |

### Опциональные провайдеры (выключены по умолчанию)

| # | Провайдер | Требует | Что собирает |
|---|-----------|---------|--------------|
| 8 | **Sherlock** | `sherlock` в PATH | Профили на 400+ сайтах (fallback для Maigret) |
| 9 | **Mosint** | `mosint` Go-бинарник | social_signal, breach_signal, domain_signal |
| 10 | **Buster** | `buster` в PATH | Соц. аккаунты, ссылки, reverse whois, usernames |
| 11 | **User Email Enrichment** | NPM / `npx` | Имя, аватар, социальные профили |
| 12 | **EmailCrawlr** | `EMAILCRAWLR_API_KEY` | Соц. аккаунты, deliverability, domain emails |

### Управление провайдерами

```bash
# Показать все провайдеры и их статус
email-osint-enricher list-providers

# Выбрать конкретные провайдеры
email-osint-enricher single -e user@gmail.com -p ghunt,holehe,emailrep

# Отключить провайдеры
email-osint-enricher batch -i list.csv --disable-providers mosint,buster

# Включить Sherlock (по умолчанию выключен)
email-osint-enricher single -e user@gmail.com -p ghunt,holehe,sherlock
```

---

## 🎯 Скоринг

### 8 метрик (0–100 каждая)

| Метрика | Описание |
|---------|----------|
| `email_footprint_score` | Общий цифровой след |
| `identity_confidence_score` | Уверенность в идентификации личности |
| `social_presence_score` | Присутствие в соцсетях и профессиональных платформах |
| `email_reputation_score` | Репутация email (по EmailRep + breach данным) |
| `deliverability_score` | Доставляемость (MX, тип домена, EmailRep) |
| `provider_consensus_score` | Совпадения между провайдерами (cross-validation) |
| `conflict_risk_score` | Риск конфликта данных (разные имена, слабые профили) |
| `final_enrichment_score` | Итоговый взвешенный балл |

### Формула итогового скора

```
final = 0.25×identity + 0.20×footprint + 0.15×social
      + 0.15×reputation + 0.10×deliverability + 0.10×consensus
      - 0.20×risk - 0.15×conflict
```

### Тиры

| Tier | Порог | Действие |
|------|-------|----------|
| **Strong** | ≥70 | Персонализированный outreach |
| **Medium** | ≥40 | Ручная верификация перед outreach |
| **Weak** | ≥15 | Попробовать дополнительные провайдеры |
| **No Signal** | <15 | Не приоритизировать |

### Provider Consensus

- +10 баллов: один и тот же URL найден 2+ провайдерами
- +15 баллов: одна и та же платформа найдена 2+ провайдерами
- Максимум 100

### Conflict Risk

- +30: имя из enrichment не совпадает с applicantName
- +20: слишком много слабых профилей (≥5)
- +15: разные имена из разных провайдеров
- Максимум 100

---

## 📥 Вход / Выход

### Вход

CSV или XLSX с колонками:
- `email` (обязательно)
- `applicantName` (опционально — для name matching)
- `applicantCountry` (опционально)
- `applicantId`, `externalId`, `claim_value`, `lead_score`, `tier` (опционально — passthrough)

### Выход

```
output/
├── enriched_results.csv
├── enriched_results.xlsx
├── enriched_results.jsonl
├── run_summary.json
├── errors.json          # только ошибки
├── logs/                # логи
└── raw/                 # сырые JSON от каждого провайдера
    ├── ghunt/
    ├── holehe/
    ├── emailrep/
    └── ...
```

Каждая строка выхода содержит:
- Все поля от 12 провайдеров
- 8 скоров + tier + recommended_action
- Объединённый список профилей (merged, deduplicated по URL)

---

## ⌨️ CLI

```bash
# Полная справка
email-osint-enricher --help

# Один email
email-osint-enricher single -e user@gmail.com -o output/

# Пакетная обработка
email-osint-enricher batch -i emails.csv -o output/

# XLSX с выбором листа и колонки
email-osint-enricher batch -i data.xlsx --sheet "Sheet1" --email-column "Email Address"

# Resume после прерывания
email-osint-enricher batch -i emails.csv --resume

# Dry run (проверка без вызова провайдеров)
email-osint-enricher batch -i emails.csv --dry-run

# Force GHunt для non-Gmail
email-osint-enricher single -e user@company.com --force-ghunt

# Через прокси
email-osint-enricher batch -i emails.csv --proxy socks5://127.0.0.1:9050

# Список провайдеров
email-osint-enricher list-providers
```

---

## ⚙️ Конфигурация

Скопируйте `config.yaml.example` → `config.yaml`:

```yaml
providers:
  ghunt:
    enabled: true
    timeout_seconds: 120
  emailrep:
    enabled: true
    timeout_seconds: 60
  mosint:
    enabled: false  # нужен Go-бинарник
  # ...

batch:
  concurrency: 3
  delay_seconds: 1.5
  max_retries: 2

output:
  save_raw_json: true
  write_xlsx: true
  write_csv: true
  write_jsonl: true
```

### Переменные окружения

```bash
# Опционально — для EmailRep (больше лимитов)
export EMAILREP_API_KEY=your_key

# Обязательно для EmailCrawlr
export EMAILCRAWLR_API_KEY=your_key
```

---

## 🛡️ Безопасность

- ⛔ Никаких паролей/хэшей в выходных файлах (автоматическая санитизация)
- 🔒 Email-ы маскируются в логах
- ✅ Подпроцессные провайдеры (Mosint/Buster/UE) не ломают pipeline если не установлены
- 📜 Только публичные данные — lawful OSINT

---

## 🧪 Тесты

```bash
# Запуск всех тестов
pytest tests/ -v

# Или через pip/uv
python -m pytest tests/ -v
```

111 тестов покрывают:
- Все 12 провайдеров в реестре
- Email-утилиты (нормализация, классификация, маскировка)
- Загрузку CSV/XLSX
- Username генерацию (включая Cyrillic)
- Все 8 метрик скоринга
- Profile merging и dedup
- Graceful failure для отсутствующих бинарников
- Мокированный EmailRep (high/suspicious)
- Санитизацию паролей/хэшей (Buster)
- Provider consensus / conflict scoring
- Отключённые провайдеры не влияют на скор

---

## 📂 Структура проекта

```
email_osint_enricher/
├── src/email_osint_enricher/
│   ├── __init__.py, __main__.py
│   ├── cli.py              # CLI (single, batch, list-providers)
│   ├── config.py            # Загрузка config.yaml
│   ├── schemas.py           # Pydantic модели (12 провайдеров, scoring, summary)
│   ├── pipeline.py          # Оркестрация провайдеров
│   ├── scoring.py           # 8 метрик + merge_profiles
│   ├── email_utils.py       # Нормализация, MX, Google Workspace
│   ├── username_utils.py    # Генерация username-кандидатов
│   ├── input_loader.py      # CSV/XLSX загрузка
│   ├── output_writer.py     # CSV/XLSX/JSONL запись
│   ├── logging_utils.py     # Настройка логирования
│   └── providers/
│       ├── base.py          # BaseProvider, ProviderContext
│       ├── ghunt_provider.py
│       ├── holehe_provider.py
│       ├── blackbird_provider.py
│       ├── maigret_provider.py
│       ├── sherlock_provider.py
│       ├── h8mail_provider.py
│       ├── phone_extractor.py
│       ├── emailrep_provider.py
│       ├── mosint_provider.py
│       ├── buster_provider.py
│       ├── user_email_enrichment_provider.py
│       └── emailcrawlr_provider.py
├── tests/                   # 111 тестов
├── config.yaml.example
├── .env.example
└── pyproject.toml
```

## License

MIT
