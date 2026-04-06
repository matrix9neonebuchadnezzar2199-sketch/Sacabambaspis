# -*- coding: utf-8 -*-
"""アプリ全体の logging 初期化（SACABAM_LOG_LEVEL: DEBUG/INFO/WARNING/ERROR）。"""
import logging
import os

_CONFIGURED = False


def configure_logging() -> None:
    global _CONFIGURED
    if _CONFIGURED:
        return
    raw = os.environ.get("SACABAM_LOG_LEVEL", "INFO").strip().upper()
    level = getattr(logging, raw, logging.INFO)
    if not isinstance(level, int):
        level = logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    _CONFIGURED = True


def get_logger(name: str = "sacabambaspis") -> logging.Logger:
    configure_logging()
    return logging.getLogger(name)
