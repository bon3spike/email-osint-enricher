"""Logging setup with Rich handler and email masking."""

from __future__ import annotations

import logging
from pathlib import Path

from rich.logging import RichHandler


def setup_logging(level: str = "INFO", log_dir: Path | None = None) -> logging.Logger:
    """Configure root logger with Rich console + optional file handler."""
    log_level = getattr(logging, level.upper(), logging.INFO)

    logger = logging.getLogger("enricher")
    logger.setLevel(log_level)
    logger.handlers.clear()

    # Console via Rich
    console_handler = RichHandler(
        rich_tracebacks=True,
        show_time=True,
        show_path=False,
    )
    console_handler.setLevel(log_level)
    logger.addHandler(console_handler)

    # File handler
    if log_dir:
        log_dir.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_dir / "enricher.log", encoding="utf-8")
        file_handler.setLevel(log_level)
        fmt = logging.Formatter("%(asctime)s | %(levelname)-8s | %(message)s")
        file_handler.setFormatter(fmt)
        logger.addHandler(file_handler)

    return logger
