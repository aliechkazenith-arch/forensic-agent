"""Structured Logging & Secret Redaction Configuration.

Standards:
- Zero Credential & Secret Leakage in server logs (AGENTS.md / Phase 11).
- Structured JSON and standard log formatters with ISO-8601 UTC timestamps.
- Global log filter scrubbing passwords, tokens, API keys, and Authorization headers.
"""
from __future__ import annotations

import logging
import os
import sys
from typing import Any, Dict, Optional

from backend.app.core.network_validator import sanitize_credentials


class SecretRedactingFilter(logging.Filter):
    """Logging filter that automatically redacts credentials and secrets from log records."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            if record.args:
                formatted = record.getMessage()
                record.msg = sanitize_credentials(formatted)
                record.args = ()
            elif isinstance(record.msg, str):
                record.msg = sanitize_credentials(record.msg)
        except Exception:
            if isinstance(record.msg, str):
                record.msg = sanitize_credentials(record.msg)
        return True


def setup_structured_logging(
    level: Optional[str] = None,
    json_format: bool = False,
) -> None:
    """Configure structured logging with automatic secret redaction for the entire application."""
    log_level_name = level or os.getenv("FORENSICOPS_LOG_LEVEL", "INFO").upper()
    log_level = getattr(logging, log_level_name, logging.INFO)

    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)

    # Remove existing handlers to avoid duplicates
    for handler in list(root_logger.handlers):
        root_logger.removeHandler(handler)

    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(log_level)

    # Add secret redacting filter
    redacting_filter = SecretRedactingFilter()
    handler.addFilter(redacting_filter)

    if json_format or os.getenv("FORENSICOPS_LOG_FORMAT", "text").lower() == "json":
        formatter = logging.Formatter(
            '{"time":"%(asctime)s","name":"%(name)s","level":"%(levelname)s","message":"%(message)s"}',
            datefmt="%Y-%m-%dT%H:%M:%SZ",
        )
    else:
        formatter = logging.Formatter(
            "[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )

    handler.setFormatter(formatter)
    root_logger.addHandler(handler)

    # Apply redacting filter to uvicorn loggers as well
    for uvi_logger_name in ("uvicorn", "uvicorn.error", "uvicorn.access", "fastapi"):
        uvi_logger = logging.getLogger(uvi_logger_name)
        uvi_logger.addFilter(redacting_filter)
