"""
Standardized logging utilities for LDAP projects.

Provides consistent logging setup and utilities across
tap-ldap, target-ldap, and flx-ldap projects.
"""
from __future__ import annotations

import logging
import logging.handlers
import sys

from datetime import datetime
from typing import Any

from ldap_core_shared.config.base_config import LoggingConfig


logger = logging.getLogger(__name__)


class StructuredFormatter(logging.Formatter):
    """
    Structured logging formatter with consistent output.

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
            base = f"{record.name} - {record.levelname} - {record.getMessage()}"

        # Add structured data if available
        if hasattr(record, "extra_data") and record.extra_data:
            extra_parts: list = []
            for key, value in record.extra_data.items():
                extra_parts.append(f"{key}={value}")

            if extra_parts:
                base += f" | {' '.join(extra_parts)}"

        # Add exception info if present
        if record.exc_info:
            base += f"\n{self.formatException(record.exc_info)}"

        return base


class LDAPLogger:
    """
    LDAP-specific logger with standard configuration and utilities.

    Provides consistent logging setup for LDAP operations with
    performance tracking and structured output.
    """

    def __init__(self, name: str, config: LoggingConfig | None = None) -> None:
        """Initialize LDAP logger."""
        self.name = name
        self.config = config or LoggingConfig()
        self.logger = logging.getLogger(name)
        self._setup_logger()

    def _setup_logger(self) -> Any:
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

    def _setup_file_handler(self, formatter: logging.Formatter) -> Any:
        """Setup rotating file handler."""
        try:
            # Ensure directory exists
            self.config.file_path.parent.mkdir(parents=True, exist_ok=True)

            # Create rotating file handler
            file_handler = logging.handlers.RotatingFileHandler(
                self.config.file_path,
                maxBytes=self.config.max_file_size_mb * 1024 * 1024,
                backupCount=self.config.backup_count,
            )
            file_handler.setFormatter(formatter)
            self.logger.addHandler(file_handler)

        except Exception as e:
            # Fallback to console logging
            self.logger.exception("Failed to setup file logging: %s", e)

    def debug(self, message: str, **kwargs) -> Any:
        """Log debug message with extra data."""
        self._log_with_extra(logging.DEBUG, message, kwargs)

    def info(self, message: str, **kwargs) -> Any:
        """Log info message with extra data."""
        self._log_with_extra(logging.INFO, message, kwargs)

    def warning(self, message: str, **kwargs) -> Any:
        """Log warning message with extra data."""
        self._log_with_extra(logging.WARNING, message, kwargs)

    def error(self, message: str, **kwargs) -> Any:
        """Log error message with extra data."""
        self._log_with_extra(logging.ERROR, message, kwargs)

    def critical(self, message: str, **kwargs) -> Any:
        """Log critical message with extra data."""
        self._log_with_extra(logging.CRITICAL, message, kwargs)

    def _log_with_extra(
        self, level: int, message: str, extra_data: dict[str, Any]
    ) -> Any:
        """Log message with extra structured data."""
        # Filter sensitive data if configured
        if self.config.mask_sensitive_data:
            extra_data = self._mask_sensitive_data(extra_data)

        # Create log record with extra data
        record = self.logger.makeRecord(
            self.name, level, __file__, 0, message, (), None
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

        masked_data: dict = {}
        for key, value in data.items():
            if any(sensitive_key in key.lower() for sensitive_key in sensitive_keys):
                masked_data[key] = "***MASKED***"
                masked_data[key] = value

        return masked_data

    def log_ldap_operation(
        self,
        operation: str,
        dn: str,
        success: bool,
        duration: float | None = None,
        **kwargs,
    ):
        """Log LDAP operation with standard format."""
        extra_data = {"operation": operation, "dn": dn, "success": success, **kwargs}

        if duration is not None:
            extra_data["duration_ms"] = round(duration * 1000, 2)

        if success:
            self.info(f"LDAP {operation} successful", **extra_data)
            self.error(f"LDAP {operation} failed", **extra_data)

    def log_performance(
        self, operation: str, count: int, duration: float, **kwargs
    ) -> Any:
        """Log performance metrics."""
        rate = count / duration if duration > 0 else 0

        extra_data = {
            "operation": operation,
            "count": count,
            "duration_s": round(duration, 3),
            "rate_per_second": round(rate, 2),
            **kwargs,
        }

        self.info(f"Performance: {operation}", **extra_data)

    def log_migration_progress(
        self, stage: str, processed: int, total: int, errors: int = 0, **kwargs
    ):
        """Log migration progress."""
        percentage = (processed / total * 100) if total > 0 else 0

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
    """
    Get or create LDAP logger instance.

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
    """
    Setup logging with specified configuration.

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
    """
    Context manager for timing operations.

    Provides convenient timing of operations with automatic logging.
    """

    def __init__(
        self, logger: LDAPLogger, operation: str, auto_log: bool = True, **extra_data
    ):
        """Initialize performance timer."""
        self.logger = logger
        self.operation = operation
        self.auto_log = auto_log
        self.extra_data = extra_data
        self.start_time = None
        self.duration = None

    def __enter__(self) -> Any:
        """Start timing."""
        self.start_time = datetime.now()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> Any:
        """Stop timing and optionally log."""
        if self.start_time:
            end_time = datetime.now()
            self.duration = (end_time - self.start_time).total_seconds()

            if self.auto_log:
                self.logger.info(
                    f"Operation completed: {self.operation}",
                    duration_s=round(self.duration, 3),
                    **self.extra_data,
                )

    def get_duration(self) -> float | None:
        """Get operation duration in seconds."""
        return self.duration
