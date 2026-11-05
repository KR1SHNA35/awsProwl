"""Logging configuration for awsProwl."""

from __future__ import annotations

import sys
from contextlib import AbstractContextManager
from pathlib import Path
from typing import Any

from loguru import logger

from awsprowl.core.config import LoggingConfig, get_config


def setup_logging(config: LoggingConfig | None = None) -> None:
    """Set up loguru logging based on configuration."""
    if config is None:
        config = get_config().logging

    # Remove default handler
    logger.remove()

    # Add console handler
    if config.format == "pretty":
        log_format = (
            "<green>{time:YYYY-MM-DD HH:mm:ss}</green> | "
            "<level>{level: <8}</level> | "
            "<cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - "
            "<level>{message}</level>"
        )
    else:
        log_format = (
            "{{"
            '"time": "{time:YYYY-MM-DD HH:mm:ss}", '
            '"level": "{level}", '
            '"logger": "{{name}}", '
            '"function": "{{function}}", '
            '"line": {{line}}, '
            '"message": "{{message}}"'
            "}}"
        )

    logger.add(
        sys.stderr,
        format=log_format,
        level=config.level,
        colorize=config.colors,
        backtrace=True,
        diagnose=True,
    )

    # Add file handler if configured
    if config.file:
        log_path = Path(config.file)
        log_path.parent.mkdir(parents=True, exist_ok=True)

        logger.add(
            log_path,
            format=log_format if config.format == "pretty" else "{message}",
            level=config.level,
            rotation=config.max_size,
            retention=config.retention,
            compression="gz",
            backtrace=True,
            diagnose=True,
            serialize=(config.format == "json"),
        )


def get_logger(name: str | None = None) -> Any:
    """Get a logger instance with optional name."""
    if name:
        return logger.bind(name=name)
    return logger


class LogContext(AbstractContextManager[None]):
    """Context manager for adding contextual information to logs."""

    def __init__(self, **context: Any) -> None:
        self.context = context
        self._token: Any = None

    def __enter__(self) -> None:
        self._token = logger.contextualize(**self.context)
        self._token.__enter__()
        return

    def __exit__(self, exc_type: type[BaseException] | None, exc_val: BaseException | None, exc_tb: Any) -> None:
        if self._token:
            self._token.__exit__(exc_type, exc_val, exc_tb)


def log_exception(exc: Exception, *, context: dict[str, Any] | None = None) -> None:
    """Log an exception with full context."""
    log = get_logger()
    if context:
        log = log.bind(**context)

    if hasattr(exc, "to_dict"):
        log.error("Exception occurred: {}", exc.to_dict())
    else:
        log.exception("Exception occurred: {}", str(exc))


# Initialize logging on module import
setup_logging()
