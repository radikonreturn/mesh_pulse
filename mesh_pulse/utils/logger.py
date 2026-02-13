"""Structured logging with Rich console and file output."""

import logging
import sys
from pathlib import Path

from rich.logging import RichHandler

from mesh_pulse.utils.config import LOG_FILE


def get_logger(name: str, level: int = logging.INFO) -> logging.Logger:
    """Create a structured logger with Rich console + file handlers.

    Args:
        name: Logger name (usually __name__).
        level: Logging level.

    Returns:
        Configured logger instance.
    """
    logger = logging.getLogger(name)

    if logger.handlers:
        return logger

    logger.setLevel(level)
    logger.propagate = False

    # ── Rich console handler (stderr so it doesn't pollute TUI) ──
    console_handler = RichHandler(
        level=level,
        rich_tracebacks=True,
        show_path=False,
        markup=True,
        console=None,  # defaults to stderr
    )
    console_handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(console_handler)

    # ── File handler ──
    try:
        log_path = Path(LOG_FILE)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(str(log_path), encoding="utf-8")
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(
            logging.Formatter(
                "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            )
        )
        logger.addHandler(file_handler)
    except OSError:
        logger.warning("Could not create log file at %s", LOG_FILE)

    return logger
