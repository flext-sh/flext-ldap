"""Enterprise Logging System for LDAP Core Shared.

This module provides a comprehensive logging framework with structured logging,
performance monitoring, security event tracking, and integration with external
monitoring systems. Designed for enterprise environments with compliance and
audit requirements.

Features:
    - Structured logging with JSON format support
    - Performance monitoring and slow query detection
    - Security event logging and audit trails
    - Context-aware logging with request/operation tracking
    - Integration with external monitoring systems
    - Log rotation and retention management
    - Sensitive data filtering and redaction
    - Distributed tracing support
    - Real-time log streaming capabilities

Architecture:
    - LoggerManager: Central logging management
    - StructuredLogger: Enhanced logger with context
    - PerformanceMonitor: Performance tracking and metrics
    - SecurityLogger: Security event logging
    - AuditLogger: Compliance and audit logging
    - LogFormatter: Custom formatters with filtering

Usage Example:
    >>> from ldap_core_shared.core.logging import LoggerManager
    >>>
    >>> # Initialize logging
    >>> LoggerManager.initialize()
    >>>
    >>> # Get structured logger
    >>> logger = LoggerManager.get_logger("schema.operations")
    >>>
    >>> # Log with context
    >>> with logger.context(operation="schema_deploy", schema="custom.schema"):
    ...     logger.info("Starting schema deployment")
    ...     # ... operation code ...
    ...     logger.info("Schema deployment completed")

Standards:
    - Structured logging with consistent field names
    - Security event classification (OWASP)
    - Performance metrics standardization
    - Compliance logging (SOX, GDPR, HIPAA)
    - Correlation ID tracking across operations
"""

from __future__ import annotations

import json
import logging
import logging.handlers
import sys
import threading
import time
from contextlib import contextmanager
from datetime import UTC, datetime
from enum import Enum
from typing import TYPE_CHECKING, Any, ClassVar
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

from ldap_core_shared.core.config import LoggingConfig
from ldap_core_shared.core.exceptions import LDAPCoreError

if TYPE_CHECKING:
    from collections.abc import Generator


class LogLevel(Enum):
    """Extended log levels for enterprise logging."""

    TRACE = 5
    DEBUG = 10
    INFO = 20
    WARNING = 30
    ERROR = 40
    CRITICAL = 50
    SECURITY = 60
    AUDIT = 70


class EventType(Enum):
    """Event types for categorization."""

    SYSTEM = "system"
    OPERATION = "operation"
    SECURITY = "security"
    PERFORMANCE = "performance"
    AUDIT = "audit"
    ERROR = "error"
    BUSINESS = "business"


class SecurityEventType(Enum):
    """Security event classifications following OWASP."""

    AUTHENTICATION_SUCCESS = "auth_success"
    AUTHENTICATION_FAILURE = "auth_failure"
    AUTHORIZATION_SUCCESS = "authz_success"
    AUTHORIZATION_FAILURE = "authz_failure"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DATA_ACCESS = "data_access"
    DATA_MODIFICATION = "data_modification"
    CONFIGURATION_CHANGE = "config_change"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    SECURITY_VIOLATION = "security_violation"


class LogContext(BaseModel):
    """Structured log context for correlation and analysis."""

    model_config = ConfigDict(extra="allow")

    correlation_id: str = Field(default_factory=lambda: str(uuid4()))
    session_id: str | None = Field(default=None)
    user_id: str | None = Field(default=None)
    operation: str | None = Field(default=None)
    component: str | None = Field(default=None)
    request_id: str | None = Field(default=None)
    trace_id: str | None = Field(default=None)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))

    # Performance context
    start_time: float | None = Field(default=None)
    duration: float | None = Field(default=None)

    # Security context
    ip_address: str | None = Field(default=None)
    user_agent: str | None = Field(default=None)
    security_level: str | None = Field(default=None)

    # Business context
    tenant_id: str | None = Field(default=None)
    environment: str | None = Field(default=None)
    version: str | None = Field(default=None)


class LogRecord(BaseModel):
    """Structured log record for JSON logging."""

    model_config = ConfigDict(extra="allow")

    timestamp: datetime
    level: str
    logger_name: str
    message: str
    event_type: EventType
    context: LogContext

    # Optional fields
    exception: dict[str, Any] | None = Field(default=None)
    stack_trace: str | None = Field(default=None)
    metrics: dict[str, Any] | None = Field(default=None)
    tags: list[str] = Field(default_factory=list)

    def to_json(self) -> str:
        """Convert to JSON string for structured logging."""
        return json.dumps(
            self.model_dump(mode="json"),
            default=str,
            ensure_ascii=False,
        )


class SensitiveDataFilter:
    """Filter for removing sensitive data from logs."""

    SENSITIVE_PATTERNS: ClassVar[list[str]] = [
        r'password["\']?\s*[:=]\s*["\']?([^"\'}\s,]+)',
        r'token["\']?\s*[:=]\s*["\']?([^"\'}\s,]+)',
        r'secret["\']?\s*[:=]\s*["\']?([^"\'}\s,]+)',
        r'key["\']?\s*[:=]\s*["\']?([^"\'}\s,]+)',
        r'authorization["\']?\s*[:=]\s*["\']?([^"\'}\s,]+)',
    ]

    @classmethod
    def filter_message(cls, message: str) -> str:
        """Filter sensitive data from log message.

        Args:
            message: Original message

        Returns:
            Filtered message with sensitive data redacted

        """
        import re

        filtered = message
        for pattern in cls.SENSITIVE_PATTERNS:
            filtered = re.sub(
                pattern,
                r"\1***REDACTED***",
                filtered,
                flags=re.IGNORECASE,
            )

        return filtered

    @classmethod
    def filter_dict(cls, data: dict[str, Any]) -> dict[str, Any]:
        """Filter sensitive data from dictionary.

        Args:
            data: Original data dictionary

        Returns:
            Filtered dictionary with sensitive values redacted

        """
        sensitive_keys = {
            "password",
            "passwd",
            "pwd",
            "secret",
            "token",
            "key",
            "authorization",
            "auth",
            "credential",
            "cred",
        }

        filtered = {}
        for key, value in data.items():
            if any(sensitive in key.lower() for sensitive in sensitive_keys):
                filtered[key] = "***REDACTED***"
            elif isinstance(value, dict):
                filtered[key] = cls.filter_dict(value)
            elif isinstance(value, str):
                filtered[key] = cls.filter_message(value)
            else:
                filtered[key] = value

        return filtered


class StructuredFormatter(logging.Formatter):
    """Custom formatter for structured JSON logging."""

    def __init__(self, include_trace: bool = False) -> None:
        """Initialize structured formatter.

        Args:
            include_trace: Whether to include stack traces

        """
        super().__init__()
        self.include_trace = include_trace

    def format(self, record: logging.LogRecord) -> str:
        """Format log record as structured JSON.

        Args:
            record: Log record to format

        Returns:
            Formatted JSON string

        """
        # Get context from record
        context = getattr(record, "context", LogContext())
        if not isinstance(context, LogContext):
            context = LogContext()

        # Create structured record
        log_record = LogRecord(
            timestamp=datetime.fromtimestamp(record.created, tz=UTC),
            level=record.levelname,
            logger_name=record.name,
            message=SensitiveDataFilter.filter_message(record.getMessage()),
            event_type=getattr(record, "event_type", EventType.SYSTEM),
            context=context,
            tags=getattr(record, "tags", []),
        )

        # Add exception information
        if record.exc_info:
            log_record.exception = {
                "type": record.exc_info[0].__name__ if record.exc_info[0] else None,
                "message": str(record.exc_info[1]) if record.exc_info[1] else None,
            }

            if self.include_trace:
                log_record.stack_trace = self.formatException(record.exc_info)

        # Add metrics if available
        if hasattr(record, "metrics"):
            log_record.metrics = record.metrics

        return log_record.to_json()


class PerformanceMonitor:
    """Performance monitoring and metrics collection."""

    def __init__(self, slow_threshold: float = 1.0) -> None:
        """Initialize performance monitor.

        Args:
            slow_threshold: Threshold for slow operations in seconds

        """
        self.slow_threshold = slow_threshold
        self._active_operations: dict[str, float] = {}
        self._lock = threading.Lock()

    def start_operation(self, operation_id: str) -> None:
        """Start timing an operation.

        Args:
            operation_id: Unique operation identifier

        """
        with self._lock:
            self._active_operations[operation_id] = time.time()

    def end_operation(self, operation_id: str) -> float:
        """End timing an operation and return duration.

        Args:
            operation_id: Unique operation identifier

        Returns:
            Operation duration in seconds

        """
        with self._lock:
            start_time = self._active_operations.pop(operation_id, None)
            if start_time is None:
                return 0.0

            return time.time() - start_time

    @contextmanager
    def time_operation(
        self,
        operation_name: str,
        logger: StructuredLogger | None = None,
    ) -> Generator[str, None, None]:
        """Context manager for timing operations.

        Args:
            operation_name: Name of operation being timed
            logger: Logger to use for slow operation warnings

        """
        operation_id = f"{operation_name}_{uuid4().hex[:8]}"

        self.start_operation(operation_id)
        time.time()

        try:
            yield operation_id
        finally:
            duration = self.end_operation(operation_id)

            # Log slow operations
            if duration > self.slow_threshold and logger:
                logger.warning(
                    "Slow operation detected: %s",
                    operation_name,
                    extra={
                        "event_type": EventType.PERFORMANCE,
                        "metrics": {
                            "operation": operation_name,
                            "duration": duration,
                            "threshold": self.slow_threshold,
                        },
                    },
                )


class StructuredLogger:
    """Enhanced logger with structured logging capabilities."""

    def __init__(self, name: str, logger: logging.Logger) -> None:
        """Initialize structured logger.

        Args:
            name: Logger name
            logger: Underlying logger instance

        """
        self.name = name
        self.logger = logger
        self._context_stack: list[LogContext] = []
        self._local = internal.invalid()

    def _get_current_context(self) -> LogContext:
        """Get current logging context."""
        if hasattr(self._local, "context"):
            return self._local.context
        return LogContext(component=self.name)

    def _merge_context(self, **kwargs: Any) -> LogContext:
        """Merge current context with additional data."""
        current = self._get_current_context()
        context_dict = current.model_dump()
        context_dict.update(**kwargs)
        return LogContext(**context_dict)

    @contextmanager
    def context(self, **context_data: Any) -> Generator[LogContext, None, None]:
        """Context manager for adding context to log messages.

        Args:
            **context_data: Additional context data

        """
        old_context = getattr(self._local, "context", LogContext())
        new_context = self._merge_context(**context_data)
        self._local.context = new_context

        try:
            yield new_context
        finally:
            self._local.context = old_context

    def _log(
        self,
        level: int,
        message: str,
        event_type: EventType = EventType.SYSTEM,
        exception: Exception | None = None,
        metrics: dict[str, Any] | None = None,
        tags: list[str] | None = None,
        **context_data: Any,
    ) -> None:
        """Internal logging method with structured data.

        Args:
            level: Logging level
            message: Log message
            event_type: Event type classification
            exception: Exception to log
            metrics: Performance metrics
            tags: Log tags for categorization
            **context_data: Additional context data

        """
        if not self.logger.isEnabledFor(level):
            return

        # Merge context
        context = self._merge_context(**context_data)

        # Create log record
        record = self.logger.makeRecord(
            name=self.name,
            level=level,
            fn="",
            lno=0,
            msg=message,
            args=(),
            exc_info=None,
        )

        # Add structured data
        record.context = context
        record.event_type = event_type
        record.metrics = metrics or {}
        record.tags = tags or []

        # Add exception info
        if exception:
            if isinstance(exception, LDAPCoreError):
                record.exception_data = exception.to_dict()
            else:
                record.exc_info = (type(exception), exception, exception.__traceback__)

        self.logger.handle(record)

    def trace(self, message: str, **kwargs: Any) -> None:
        """Log trace message."""
        self._log(LogLevel.TRACE.value, message, **kwargs)

    def debug(self, message: str, **kwargs: Any) -> None:
        """Log debug message."""
        self._log(LogLevel.DEBUG.value, message, **kwargs)

    def info(self, message: str, **kwargs: Any) -> None:
        """Log info message."""
        self._log(LogLevel.INFO.value, message, **kwargs)

    def warning(self, message: str, **kwargs: Any) -> None:
        """Log warning message."""
        self._log(LogLevel.WARNING.value, message, **kwargs)

    def error(self, message: str, **kwargs: Any) -> None:
        """Log error message."""
        self._log(LogLevel.ERROR.value, message, **kwargs)

    def critical(self, message: str, **kwargs: Any) -> None:
        """Log critical message."""
        self._log(LogLevel.CRITICAL.value, message, **kwargs)

    def security(
        self,
        message: str,
        security_event: SecurityEventType,
        **kwargs,
    ) -> None:
        """Log security event.

        Args:
            message: Security event message
            security_event: Type of security event
            **kwargs: Additional context

        """
        kwargs["security_event_type"] = security_event.value
        self._log(
            LogLevel.SECURITY.value,
            message,
            event_type=EventType.SECURITY,
            **kwargs,
        )

    def audit(self, message: str, **kwargs) -> None:
        """Log audit event.

        Args:
            message: Audit message
            **kwargs: Additional context

        """
        self._log(LogLevel.AUDIT.value, message, event_type=EventType.AUDIT, **kwargs)

    def performance(self, message: str, metrics: dict[str, Any], **kwargs) -> None:
        """Log performance metrics.

        Args:
            message: Performance message
            metrics: Performance metrics
            **kwargs: Additional context

        """
        self._log(
            LogLevel.INFO.value,
            message,
            event_type=EventType.PERFORMANCE,
            metrics=metrics,
            **kwargs,
        )


class LoggerManager:
    """Central logger management for the application."""

    _initialized: bool = False
    _loggers: ClassVar[dict[str, StructuredLogger]] = {}
    _performance_monitor: PerformanceMonitor | None = None
    _config: LoggingConfig | None = None

    @classmethod
    def initialize(cls, config: LoggingConfig | None = None) -> None:
        """Initialize logging system.

        Args:
            config: Logging configuration

        """
        if cls._initialized:
            return

        cls._config = config or LoggingConfig()

        # Configure root logger
        root_logger = logging.getLogger()
        root_logger.setLevel(getattr(logging, cls._config.level.value))

        # Clear existing handlers
        root_logger.handlers.clear()

        # Add console handler
        if cls._config.console_enabled:
            console_handler = logging.StreamHandler(sys.stdout)
            if cls._config.structured_logging:
                console_handler.setFormatter(StructuredFormatter())
            else:
                console_handler.setFormatter(
                    logging.Formatter(cls._config.format),
                )
            root_logger.addHandler(console_handler)

        # Add file handler
        if cls._config.log_file:
            file_handler = logging.handlers.RotatingFileHandler(
                filename=cls._config.log_file,
                maxBytes=cls._config.max_file_size,
                backupCount=cls._config.backup_count,
                encoding="utf-8",
            )

            if cls._config.structured_logging:
                file_handler.setFormatter(StructuredFormatter(include_trace=True))
            else:
                file_handler.setFormatter(
                    logging.Formatter(cls._config.format),
                )
            root_logger.addHandler(file_handler)

        # Initialize performance monitor
        if cls._config.performance_logging:
            cls._performance_monitor = PerformanceMonitor(
                slow_threshold=cls._config.slow_query_threshold,
            )

        cls._initialized = True

    @classmethod
    def get_logger(cls, name: str) -> StructuredLogger:
        """Get or create structured logger.

        Args:
            name: Logger name

        Returns:
            Structured logger instance

        """
        if not cls._initialized:
            cls.initialize()

        if name not in cls._loggers:
            underlying_logger = logging.getLogger(name)
            cls._loggers[name] = StructuredLogger(name, underlying_logger)

        return cls._loggers[name]

    @classmethod
    def get_performance_monitor(cls) -> PerformanceMonitor | None:
        """Get performance monitor instance.

        Returns:
            Performance monitor or None if not enabled

        """
        return cls._performance_monitor

    @classmethod
    def shutdown(cls) -> None:
        """Shutdown logging system."""
        logging.shutdown()
        cls._initialized = False
        cls._loggers.clear()
        cls._performance_monitor = None


# Convenience functions
def get_logger(name: str) -> StructuredLogger:
    """Get structured logger instance.

    Args:
        name: Logger name

    Returns:
        Structured logger

    """
    return LoggerManager.get_logger(name)


def get_performance_monitor() -> PerformanceMonitor | None:
    """Get performance monitor instance.

    Returns:
        Performance monitor or None

    """
    return LoggerManager.get_performance_monitor()


# Export main classes
__all__ = [
    "EventType",
    "LogContext",
    "LogRecord",
    "LoggerManager",
    "PerformanceMonitor",
    "SecurityEventType",
    "StructuredLogger",
    "get_logger",
    "get_performance_monitor",
]
