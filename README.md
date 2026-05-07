# 📧 Email OSINT Enricher

Локальный CLI-инструмент для массового OSINT-обогащения email-списков.
На вход — CSV/XLSX с email-ами, на выход — таблица со всеми найденными данными и скорингом.

**12 OSINT-провайдеров** • **8 метрик скоринга** • **CSV + XLSX + JSONL выход** • **Batch + Resume** • **Всё в одной репе**

---

## 🚀 Установка (всё в одной репе)

### Один скрипт — всё ставит:

```bash
git clone --recursive https://github.com/bon3spike/email-osint-enricher.git
cd email-osint-enricher
bash scripts/setup.sh
```

Скрипт автоматически:
1. Установит системные зависимости (`libcairo2-dev`, `pkg-config`)
2. Скачает Blackbird как git submodule в `vendor/`
3. Установит все Python-зависимости + все OSINT-провайдеры
4. Создаст `config.yaml` и `.env` из шаблонов
5. Проверит что все тулзы доступны
6. Запустит тесты

### Ручная установка (если хочется по шагам):

```bash
# 1. Клонируем с submodules
git clone --recursive https://github.com/bon3spike/email-osint-enricher.git
cd email-osint-enricher

# 2. Системные зависимости (Ubuntu/Debian — для maigret/pycairo)
sudo apt-get install -y libcairo2-dev pkg-config build-essential

# 3. Ставим всё
pip install -e ".[dev]"

# 4. Зависимости Blackbird (из vendor/)
pip install -r vendor/blackbird/requirements.txt

# 5. Конфиг
cp config.yaml.example config.yaml
cp .env.example .env

# 6. Проверка
email-osint-enricher list-providers
pytest tests/ -v
```

### GHunt — одноразовая авторизация:

```bash
ghunt login
# Он попросит Google cookies из браузера (SID, SSID, APISID, SAPISID, HSID)
# Достать: расширение EditThisCookie на accounts.google.com
# Делается один раз, потом работает автоматически
```

---

## 📋 Требования

- Python 3.11+
- pip
- `libcairo2-dev` + `pkg-config` (для maigret — Ubuntu: `apt install`, macOS: `brew install cairo`)
- Git (для submodules)

Все OSINT-тулзы устанавливаются автоматически через pip:
- `ghunt`, `holehe`, `h8mail`, `maigret`, `sherlock-project` — как pip-зависимости
- `blackbird` — как git submodule в `vendor/blackbird/`

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
| 8 | **Sherlock** | ✅ уже установлен | Профили на 400+ сайтах (fallback для Maigret) |
| 9 | **Mosint** | `mosint` Go-бинарник | social_signal, breach_signal, domain_signal |
| 10 | **EmailCrawlr** | `EMAILCRAWLR_API_KEY` | Соц. аккаунты, deliverability, domain emails |

### Управление провайдерами

```bash
# Показать все провайдеры и их статус
email-osint-enricher list-providers

# Выбрать конкретные провайдеры
email-osint-enricher single -e user@gmail.com -p ghunt,holehe,emailrep

# Отключить провайдеры
email-osint-enricher batch -i list.csv --disable-providers mosint

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

---

## 📥 Вход / Выход

### Вход

CSV или XLSX с колонками:
- `email` (обязательно)
- `applicantName` (опционально — для name matching)
- `applicantCountry`, `applicantId`, `externalId`, `claim_value`, `lead_score`, `tier` (опционально)

### Выход

```
output/
├── enriched_results.csv
├── enriched_results.xlsx
├── enriched_results.jsonl
├── run_summary.json
├── errors.json
├── logs/
└── raw/                 # сырые JSON от каждого провайдера
```

---

## ⌨️ CLI

```bash
email-osint-enricher --help                          # справка
email-osint-enricher list-providers                  # все провайдеры
email-osint-enricher single -e user@gmail.com        # один email
email-osint-enricher batch -i emails.csv -o output/  # пакетная обработка
email-osint-enricher batch -i data.xlsx --sheet "Sheet1" --email-column "Email"
email-osint-enricher batch -i emails.csv --resume    # продолжить после прерывания
email-osint-enricher batch -i emails.csv --dry-run   # проверка без запуска
email-osint-enricher single -e user@corp.com --force-ghunt  # GHunt для non-Gmail
email-osint-enricher batch -i emails.csv --disable-providers mosint
```

---

## ⚙️ Конфигурация

`config.yaml` — управление провайдерами, батчингом, выходом:

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
batch:
  concurrency: 3
  delay_seconds: 1.5
output:
  save_raw_json: true
  write_xlsx: true
```

### API-ключи (`.env`):

```bash
EMAILREP_API_KEY=your_key      # опционально — больше лимитов
EMAILCRAWLR_API_KEY=your_key   # обязательно для EmailCrawlr
```

---

## 🛡️ Безопасность

- ⛔ Никаких паролей/хэшей в выходных файлах (автосанитизация)
- 🔒 Email-ы маскируются в логах
- ✅ Провайдеры не ломают pipeline если не установлены
- 📜 Только публичные данные — lawful OSINT

---

## 🧪 Тесты

```bash
pytest tests/ -v
```

111 тестов: все провайдеры, скоринг, merging, утилиты, graceful failures.

---

## 📂 Структура проекта

```
email-osint-enricher/
├── scripts/setup.sh              # ← полная установка одной командой
├── vendor/blackbird/             # ← Blackbird (git submodule)
├── src/email_osint_enricher/
│   ├── cli.py, pipeline.py, scoring.py, schemas.py
│   ├── config.py, email_utils.py, username_utils.py
│   ├── input_loader.py, output_writer.py
│   └── providers/ (12 провайдеров)
├── tests/ (111 тестов)
├── config.yaml.example, .env.example
└── pyproject.toml
```

## License

MIT
