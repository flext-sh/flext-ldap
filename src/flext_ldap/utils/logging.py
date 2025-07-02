"""Standardized logging utilities for LDAP projects."""

from __future__ import annotations

import logging
import logging.handlers
import sys
from datetime import datetime
from typing import TYPE_CHECKING, Any, Self

from flext_ldapants import DEFAULT_LARGE_LIMIT, DEFAULT_MAX_ITEMS

from flext_ldap.core.config import LoggingConfig

if TYPE_CHECKING:
    from types import TracebackType

# Constants for magic values
BYTES_PER_KB = 1024

logger = logging.getLogger(__name__)


class StructuredFormatter(logging.Formatter):
    """Structured logging formatter with consistent output.

    Formats log messages with structured data for better analysis
    and monitoring.
    """

    def __init__(self, include_timestamp: bool = True) -> None:
        """Initialize formatter."""
        self.include_timestamp = include_timestamp
        super().__init__()

    def format(self, record: logging.LogRecord) -> str:
        """Format log record with structured output."""
        # Base format
        if self.include_timestamp:
            timestamp = datetime.fromtimestamp(record.created).isoformat()
            base = f"{timestamp} - {record.name} - {record.levelname} - {record.getMessage()}"
        else:
            base = f"{record.name} - {record.levelname} - {record.getMessage()}"

        # Add structured data if available
        if hasattr(record, "extra_data") and record.extra_data:
            extra_parts: list[str] = []
            for key, value in record.extra_data.items():
                extra_parts.append(f"{key}={value}")

            if extra_parts:
                base += f" | {' '.join(extra_parts)}"

        # Add exception info if present
        if record.exc_info:
            base += f"\n{self.formatException(record.exc_info)}"

        return base


class LDAPLogger:
    """LDAP-specific logger with standard configuration and utilities.

    Provides consistent logging setup for LDAP operations with
    performance tracking and structured output.
    """

    def __init__(self, name: str, config: LoggingConfig | None = None) -> None:
        """Initialize LDAP logger."""
        self.name = name
        try:
            self.config: LoggingConfig | Any = config or LoggingConfig()
        except Exception:
            # Fallback to basic config if Pydantic config fails
            from dataclasses import dataclass

            @dataclass
            class BasicLoggingConfig:
                level: str = "INFO"
                format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
                file_path: str | None = None
                max_file_size_mb: int = DEFAULT_MAX_ITEMS
                backup_count: int = 5
                enable_console: bool = True
                mask_sensitive_data: bool = True

            self.config = BasicLoggingConfig()
        self.logger = logging.getLogger(name)
        self._setup_logger()

    def _setup_logger(self) -> None:
        """Setup logger with configuration."""
        # Clear existing handlers
        self.logger.handlers.clear()

        # Set log level
        self.logger.setLevel(getattr(logging, self.config.level))

        # Create formatter
        formatter = StructuredFormatter()

        # Console handler
        if self.config.enable_console:
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setFormatter(formatter)
            self.logger.addHandler(console_handler)

        # File handler
        if self.config.file_path:
            self._setup_file_handler(formatter)

        # Prevent propagation to avoid duplicate messages
        self.logger.propagate = False

    def _setup_file_handler(self, formatter: logging.Formatter) -> None:
        """Setup rotating file handler."""
        try:
            # Handle file path
            if self.config.file_path is None:
                return

            # Convert to Path if it's a string
            from pathlib import Path

            if isinstance(self.config.file_path, str):
                file_path = Path(self.config.file_path)
            else:
                file_path = self.config.file_path

            # Ensure directory exists
            file_path.parent.mkdir(parents=True, exist_ok=True)

            # Create rotating file handler
            file_handler = logging.handlers.RotatingFileHandler(
                str(file_path),
                maxBytes=self.config.max_file_size_mb * BYTES_PER_KB * BYTES_PER_KB,
                backupCount=self.config.backup_count,
            )
            file_handler.setFormatter(formatter)
            self.logger.addHandler(file_handler)

        except Exception as e:
            # Fallback to console logging
            self.logger.exception("Failed to setup file logging: %s", e)

    def debug(self, message: str, *args: Any, **kwargs: Any) -> None:
        """Log debug message with extra data."""
        formatted_message = message % args if args else message
        self._log_with_extra(logging.DEBUG, formatted_message, kwargs)

    def info(self, message: str, *args: Any, **kwargs: Any) -> None:
        """Log info message with extra data."""
        formatted_message = message % args if args else message
        self._log_with_extra(logging.INFO, formatted_message, kwargs)

    def warning(self, message: str, *args: Any, **kwargs: Any) -> None:
        """Log warning message with extra data."""
        formatted_message = message % args if args else message
        self._log_with_extra(logging.WARNING, formatted_message, kwargs)

    def error(self, message: str, *args: Any, **kwargs: Any) -> None:
        """Log error message with extra data."""
        formatted_message = message % args if args else message
        self._log_with_extra(logging.ERROR, formatted_message, kwargs)

    def critical(self, message: str, *args: Any, **kwargs: Any) -> None:
        """Log critical message with extra data."""
        formatted_message = message % args if args else message
        self._log_with_extra(logging.CRITICAL, formatted_message, kwargs)

    def exception(self, message: str, *args: Any, **kwargs: Any) -> None:
        """Log exception message with stack trace."""
        formatted_message = message % args if args else message
        kwargs["exc_info"] = True
        self._log_with_extra(logging.ERROR, formatted_message, kwargs)

    def _log_with_extra(
        self,
        level: int,
        message: str,
        extra_data: dict[str, Any],
    ) -> None:
        """Log message with extra structured data."""
        # Filter sensitive data if configured
        if self.config.mask_sensitive_data:
            extra_data = self._mask_sensitive_data(extra_data)

        # Create log record with extra data
        record = self.logger.makeRecord(
            self.name,
            level,
            __file__,
            0,
            message,
            (),
            None,
        )
        record.extra_data = extra_data

        self.logger.handle(record)

    def _mask_sensitive_data(self, data: dict[str, Any]) -> dict[str, Any]:
        """Mask sensitive data in log output."""
        sensitive_keys = {
            "password",
            "passwd",
            "pwd",
            "secret",
            "token",
            "key",
            "auth",
            "credential",
            "bind_password",
        }

        masked_data: dict[str, Any] = {}
        for key, value in data.items():
            if any(sensitive_key in key.lower() for sensitive_key in sensitive_keys):
                masked_data[key] = "***MASKED***"
            else:
                masked_data[key] = value

        return masked_data

    def log_ldap_operation(
        self,
        operation: str,
        dn: str,
        success: bool,
        duration: float | None = None,
        **kwargs: Any,
    ) -> None:
        """Log LDAP operation with standard format."""
        extra_data = {"operation": operation, "dn": dn, "success": success, **kwargs}

        if duration is not None:
            extra_data["duration_ms"] = round(duration * DEFAULT_LARGE_LIMIT, 2)

        if success:
            self.info(f"LDAP {operation} successful", **extra_data)
        else:
            self.error(f"LDAP {operation} failed", **extra_data)

    def log_performance(
        self,
        operation: str,
        count: int,
        duration: float,
        **kwargs: str | float | bool,
    ) -> None:
        """Log performance metrics."""
        rate = count / duration if duration > 0 else 0

        extra_data = {
            "operation": operation,
            "count": count,
            "duration_s": round(duration, 3),
            "rate_per_second": round(rate, 2),
            **kwargs,
        }

        # Convert extra_data values to compatible types
        converted_extra = {}
        for key, value in extra_data.items():
            if isinstance(value, str | int | float | bool):
                converted_extra[key] = value
            else:
                converted_extra[key] = str(value)

        self.info(f"Performance: {operation}", **converted_extra)

    def log_migration_progress(
        self,
        stage: str,
        processed: int,
        total: int,
        errors: int = 0,
        **kwargs: Any,
    ) -> None:
        """Log migration progress."""
        percentage = (processed / total * DEFAULT_MAX_ITEMS) if total > 0 else 0

        extra_data = {
            "stage": stage,
            "processed": processed,
            "total": total,
            "percentage": round(percentage, 1),
            "errors": errors,
            **kwargs,
        }

        self.info(f"Migration progress: {stage}", **extra_data)


# Global logger registry
_loggers: dict[str, LDAPLogger] = {}


def get_logger(name: str, config: LoggingConfig | None = None) -> LDAPLogger:
    """Get or create LDAP logger instance.

    Args:
        name: Logger name
        config: Optional logging configuration

    Returns:
        LDAPLogger instance
    """
    if name not in _loggers:
        _loggers[name] = LDAPLogger(name, config)

    return _loggers[name]


def setup_logging(config: LoggingConfig, root_logger_name: str = "ldap") -> LDAPLogger:
    """Setup logging with specified configuration.

    Args:
        config: Logging configuration
        root_logger_name: Root logger name

    Returns:
        Configured root logger
    """
    # Clear existing loggers
    _loggers.clear()

    # Create root logger
    return get_logger(root_logger_name, config)


class PerformanceTimer:
    """Context manager for timing operations.

    Provides convenient timing of operations with automatic logging.
    """

    def __init__(
        self,
        logger: LDAPLogger,
        operation: str,
        auto_log: bool = True,
        **extra_data: Any,
    ) -> None:
        """Initialize performance timer."""
        self.logger = logger
        self.operation = operation
        self.auto_log = auto_log
        self.extra_data = extra_data
        self.start_time: datetime | None = None
        self.duration: float | None = None

    def __enter__(self) -> Self:
        """Start timing."""
        self.start_time = datetime.now()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        """Stop timing and optionally log."""
        if self.start_time:
            end_time = datetime.now()
            self.duration = (end_time - self.start_time).total_seconds()

            if self.auto_log:
                self.logger.info(
                    "Operation completed: %s",
                    self.operation,
                    duration_s=round(self.duration, 3),
                    **{
                        k: v
                        for k, v in self.extra_data.items()
                        if isinstance(v, str | int | float | bool)
                    },
                )

    def get_duration(self) -> float | None:
        """Get operation duration in seconds."""
        return self.duration
