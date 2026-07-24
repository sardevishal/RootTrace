"""
utils/logger.py

Centralized logger for the Vulnerability Intelligence Engine.
Logs key lifecycle events: scan start, client success/failure, completion.
"""

import logging
import sys
from typing import Optional


def get_logger(name: str, level: Optional[int] = None) -> logging.Logger:
    """
    Returns a named logger with a consistent format.

    Args:
        name: Module name (use __name__ when calling).
        level: Optional log level override. Defaults to INFO.

    Returns:
        Configured Logger instance.
    """
    logger = logging.getLogger(name)

    if logger.handlers:
        # Avoid adding duplicate handlers on repeated imports
        return logger

    log_level = level if level is not None else logging.INFO
    logger.setLevel(log_level)

    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(log_level)

    formatter = logging.Formatter(
        fmt="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    return logger
