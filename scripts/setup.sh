#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────
# Email OSINT Enricher — полная установка (всё в одной репе)
# Запуск: bash scripts/setup.sh
# ─────────────────────────────────────────────────────────────────────
set -euo pipefail

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

info()  { echo -e "${GREEN}[✓]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
fail()  { echo -e "${RED}[✗]${NC} $*"; }

echo ""
echo "═══════════════════════════════════════════════════"
echo "  Email OSINT Enricher — Setup"
echo "═══════════════════════════════════════════════════"
echo ""

# ── 1. Системные зависимости (для maigret/pycairo) ──────────────────
if command -v apt-get &>/dev/null; then
    info "Установка системных зависимостей (libcairo2-dev, pkg-config)..."
    sudo apt-get update -qq
    sudo apt-get install -y -qq libcairo2-dev pkg-config build-essential 2>/dev/null || \
        warn "Не удалось установить системные пакеты. Maigret может не установиться."
elif command -v brew &>/dev/null; then
    info "macOS: установка cairo через brew..."
    brew install cairo pkg-config 2>/dev/null || \
        warn "Не удалось установить cairo через brew."
else
    warn "Неизвестный менеджер пакетов. Убедись что libcairo2-dev и pkg-config установлены."
fi

# ── 2. Git submodules (Blackbird) ────────────────────────────────────
info "Инициализация git submodules (Blackbird)..."
git submodule update --init --recursive 2>/dev/null || \
    warn "Не удалось обновить submodules. Blackbird будет недоступен."

# Установка зависимостей Blackbird
if [ -f vendor/blackbird/requirements.txt ]; then
    info "Установка зависимостей Blackbird..."
    pip install -r vendor/blackbird/requirements.txt --quiet 2>/dev/null || \
        warn "Не удалось установить зависимости Blackbird."
fi

# ── 3. Основной пакет ───────────────────────────────────────────────
info "Установка email-osint-enricher + все OSINT-провайдеры..."
pip install -e ".[dev]" || {
    fail "Ошибка установки. Попробуй:"
    echo "  pip install -e . --no-deps"
    echo "  pip install ghunt holehe h8mail sherlock-project"
    echo "  pip install maigret  # требует libcairo2-dev"
    exit 1
}

# ── 4. Конфигурация ─────────────────────────────────────────────────
if [ ! -f config.yaml ]; then
    cp config.yaml.example config.yaml
    info "Создан config.yaml из шаблона"
else
    info "config.yaml уже существует"
fi

if [ ! -f .env ]; then
    cp .env.example .env
    info "Создан .env из шаблона (отредактируй если нужны API-ключи)"
else
    info ".env уже существует"
fi

# ── 5. Проверка ─────────────────────────────────────────────────────
echo ""
echo "═══════════════════════════════════════════════════"
echo "  Проверка установки"
echo "═══════════════════════════════════════════════════"
echo ""

check_tool() {
    local name="$1"
    local cmd="$2"
    if command -v "$cmd" &>/dev/null; then
        info "$name — установлен ✓"
    else
        warn "$name — НЕ найден ($cmd)"
    fi
}

check_tool "email-osint-enricher" "email-osint-enricher"
check_tool "GHunt"               "ghunt"
check_tool "Holehe"              "holehe"
check_tool "h8mail"              "h8mail"
check_tool "Maigret"             "maigret"
check_tool "Sherlock"            "sherlock"

if [ -f vendor/blackbird/blackbird.py ]; then
    info "Blackbird — установлен (vendor/) ✓"
else
    warn "Blackbird — НЕ найден в vendor/"
fi

# ── 6. Тесты ────────────────────────────────────────────────────────
echo ""
info "Запуск тестов..."
python -m pytest tests/ -v --tb=short 2>&1 | tail -15

echo ""
echo "═══════════════════════════════════════════════════"
info "Установка завершена!"
echo ""
echo "  Быстрый старт:"
echo "    email-osint-enricher list-providers"
echo "    email-osint-enricher single -e user@gmail.com"
echo "    email-osint-enricher batch -i emails.csv -o output/"
echo ""
echo "  GHunt требует одноразовую авторизацию:"
echo "    ghunt login"
echo "═══════════════════════════════════════════════════"
