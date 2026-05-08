"""Configuration loading from YAML + env vars."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

import yaml

from email_osint_enricher.schemas import AppConfig


_DEFAULT_CONFIG_PATHS = [
    Path("config.yaml"),
    Path("config.yml"),
    Path("config.yaml.example"),
]


def load_config(config_path: Optional[str] = None) -> AppConfig:
    """Load configuration from YAML file and environment overrides."""
    path: Optional[Path] = None

    if config_path:
        path = Path(config_path)
    else:
        env_path = os.getenv("ENRICHER_CONFIG_PATH")
        if env_path:
            path = Path(env_path)
        else:
            for candidate in _DEFAULT_CONFIG_PATHS:
                if candidate.exists():
                    path = candidate
                    break

    if path and path.exists():
        with open(path) as f:
            raw = yaml.safe_load(f) or {}
        cfg = AppConfig(**raw)

        # Merge: ensure providers added in newer versions are present
        # even if the user's config.yaml was copied from an older template
        defaults = AppConfig()
        for pname, pconf in defaults.providers.items():
            if pname not in cfg.providers:
                cfg.providers[pname] = pconf
    else:
        cfg = AppConfig()

    # Environment overrides
    if level := os.getenv("ENRICHER_LOG_LEVEL"):
        cfg.logging.level = level

    return cfg
