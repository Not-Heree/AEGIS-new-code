"""
Application Logger
==================
Centralized logging for EASM AEGIS.

Usage:
    from utils.logger import logger

    logger.info("Phase 1 complete: %d subdomains", count)
    logger.error("Nuclei crashed: %s", error, exc_info=True)
    logger.warning("Shodan API key invalid")
    logger.debug("Raw response: %s", data)

Log files are stored in ./logs/ directory.
Console shows INFO and above.
File stores DEBUG and above (everything).
"""

import logging
import os


def setup_logger(name="easm-aegis", log_file="easm_aegis.log"):
    """
    Set up application logger with file and console handlers.

    Returns:
        logging.Logger instance
    """
    _logger = logging.getLogger(name)

    # Prevent duplicate handlers if called multiple times
    if _logger.handlers:
        return _logger

    _logger.setLevel(logging.DEBUG)

    # ── File handler — keeps ALL logs ────────────────────
    os.makedirs("logs", exist_ok=True)
    fh = logging.FileHandler(
        os.path.join("logs", log_file),
        encoding="utf-8"
    )
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter(
        '%(asctime)s [%(levelname)-8s] %(name)s: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    ))
    _logger.addHandler(fh)

    # ── Console handler — shows INFO and above ───────────
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    ch.setFormatter(logging.Formatter(
        '%(asctime)s [%(levelname)-8s] %(message)s',
        datefmt='%H:%M:%S'
    ))
    _logger.addHandler(ch)

    return _logger


# Create singleton logger — import this everywhere
logger = setup_logger()