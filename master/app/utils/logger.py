"""
APEXEYE MASTER - Logging Module

Provides a reusable logger for the Master application.
"""

import logging
import os
from pathlib import Path

from master.app.config import config

_logger_initialized = False


def get_logger(name: str = "apexeye.master") -> logging.Logger:
    """Return a configured logger. Initializes handlers on first call."""
    global _logger_initialized
    logger = logging.getLogger(name)

    if not _logger_initialized:
        log_dir = Path(config.LOG_PATH)
        log_dir.mkdir(parents=True, exist_ok=True)
        log_file = log_dir / "master.log"

        level = getattr(logging, config.LOG_LEVEL.upper(), logging.DEBUG)
        logger.setLevel(level)

        fmt = logging.Formatter(
            "[%(asctime)s] [%(levelname)-8s] %(name)s — %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )

        # File handler
        fh = logging.FileHandler(str(log_file), encoding="utf-8")
        fh.setLevel(level)
        fh.setFormatter(fmt)
        logger.addHandler(fh)

        # Console handler
        ch = logging.StreamHandler()
        ch.setLevel(level)
        ch.setFormatter(fmt)
        logger.addHandler(ch)

        _logger_initialized = True

    return logger
