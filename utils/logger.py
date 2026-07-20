"""Logging setup for the SOC Triage Tool.

Provides a centralized logger that writes to both a rotating file log
(``logs/soc_tool.log``) and the console.  All modules should obtain their
logger via ``from utils.logger import get_logger`` and then call
``get_logger(__name__)`` so that the calling module's name appears in the
log records.

Design notes
------------
* The log directory is created lazily on first use so that the tool can
  run on a fresh checkout without manual setup.
* A ``RotatingFileHandler`` is used so that the log file does not grow
  unbounded over time.
* The log format includes a timestamp, log level, the emitting module,
  the thread name (very useful for diagnosing the background enrichment
  threads) and the message itself.
"""

from __future__ import annotations

import logging
import os
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Optional

# Default location for log files, relative to the project root.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_LOG_DIR = PROJECT_ROOT / "logs"
DEFAULT_LOG_FILE = DEFAULT_LOG_DIR / "soc_tool.log"

# Flag used to ensure logging is only initialized once per process.
_LOGGING_INITIALIZED = False


def setup_logging(log_file: Optional[Path] = None,
                  level: int = logging.INFO) -> None:
    """Configure the root logger for the whole application.

    Parameters
    ----------
    log_file:
        Optional path to the log file.  Defaults to ``logs/soc_tool.log``
        under the project root.
    level:
        The minimum log level to emit.  Defaults to ``logging.INFO``.
    """
    global _LOGGING_INITIALIZED
    if _LOGGING_INITIALIZED:
        return

    log_file = Path(log_file) if log_file else DEFAULT_LOG_FILE
    log_file.parent.mkdir(parents=True, exist_ok=True)

    formatter = logging.Formatter(
        fmt="%(asctime)s | %(levelname)-8s | %(name)s | %(threadName)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # File handler with rotation: 5 MB per file, 5 backups.
    file_handler = RotatingFileHandler(
        filename=str(log_file),
        maxBytes=5 * 1024 * 1024,
        backupCount=5,
        encoding="utf-8",
    )
    file_handler.setFormatter(formatter)
    file_handler.setLevel(level)

    # Console handler for live feedback during development.
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    console_handler.setLevel(level)

    root_logger = logging.getLogger()
    root_logger.setLevel(level)
    # Avoid duplicate handlers if setup_logging is called multiple times.
    for handler in list(root_logger.handlers):
        root_logger.removeHandler(handler)
    root_logger.addHandler(file_handler)
    root_logger.addHandler(console_handler)

    _LOGGING_INITIALIZED = True
    logging.info("Logging initialized -> %s", log_file)


def get_logger(name: str) -> logging.Logger:
    """Return a module-level logger.

    Calling :func:`setup_logging` first is recommended but not required;
    if logging has not been set up yet, a sensible default configuration
    is applied automatically.

    Parameters
    ----------
    name:
        Typically ``__name__`` of the calling module.
    """
    if not _LOGGING_INITIALIZED:
        setup_logging()
    return logging.getLogger(name)


__all__ = ["setup_logging", "get_logger"]
