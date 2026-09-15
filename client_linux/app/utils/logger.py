"""
APEXEYE LINUX CLIENT — Logging Module

Configures console and file logging for the Linux agent.
Logs write to logs/client_linux.log (or configured APEXEYE_CLIENT_LOG_PATH).
"""

import logging
import sys
from pathlib import Path

from client_linux.app.config import config

_loggers: dict[str, logging.Logger] = {}


def get_logger(name: str = "apexeye.linux_client") -> logging.Logger:
    """Return a configured Logger instance."""
    if name in _loggers:
        return _loggers[name]

    logger = logging.getLogger(name)
    level = getattr(logging, config.LOG_LEVEL.upper(), logging.DEBUG)
    logger.setLevel(level)

    # Avoid duplicate handlers if called repeatedly
    if not logger.handlers:
        fmt = logging.Formatter(
            "[%(asctime)s] [%(levelname)-8s] %(name)s \u2014 %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )

        # Console handler
        console = logging.StreamHandler(sys.stdout)
        console.setLevel(level)
        console.setFormatter(fmt)
        logger.addHandler(console)

        # File handler
        try:
            log_dir = Path(config.LOG_PATH)
            log_dir.mkdir(parents=True, exist_ok=True)
            file_handler = logging.FileHandler(
                log_dir / "client_linux.log", encoding="utf-8"
            )
            file_handler.setLevel(level)
            file_handler.setFormatter(fmt)
            logger.addHandler(file_handler)
        except Exception:
            pass  # Fall back to console only

    _loggers[name] = logger
    return logger
