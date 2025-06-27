"""Comprehensive unit tests for LDAP Core Shared logging system.

This module provides extensive testing coverage for the enterprise-grade logging
system, including structured logging, performance monitoring, security event
tracking, context management, and integration patterns.

Test Coverage:
    - Structured logger functionality and context management
    - Performance monitoring and slow operation detection
    - Security event logging and audit trails
    - Log formatting and sensitive data filtering
    - Logger manager initialization and configuration
    - Integration with configuration system
    - Context propagation and correlation IDs
    - Log record serialization and JSON formatting
    - Performance benchmarking for logging operations
    - Security features for sensitive data protection

Test Categories:
    - Unit tests for individual logging components
    - Integration tests for logging system coordination
    - Security tests for sensitive data filtering
    - Performance tests for logging overhead
    - Context management tests for correlation
    - Formatting tests for structured output
"""

import json
import logging
import tempfile
import threading
import time
from datetime import datetime
from pathlib import Path
from unittest.mock import Mock

import pytest

from ldap_core_shared.core.config import LoggingConfig
from ldap_core_shared.core.logging import (
    EventType,
    LogContext,
    LoggerManager,
    LogLevel,
    LogRecord,
    PerformanceMonitor,
    SecurityEventType,
    SensitiveDataFilter,
    StructuredFormatter,
    StructuredLogger,
    get_logger,
    get_performance_monitor,
)


@pytest.mark.unit
@pytest.mark.logging
class TestLogContext:
    """Test cases for log context functionality."""

    def test_default_context_creation(self) -> None:
        """Test creating log context with default values."""
        context = LogContext()

        assert context.correlation_id is not None
        assert len(context.correlation_id) > 0
        assert context.session_id is None
        assert context.user_id is None
        assert context.operation is None
        assert context.component is None
        assert isinstance(context.timestamp, datetime)

    def test_context_with_all_fields(self) -> None:
        """Test creating log context with all fields specified."""
        context = LogContext(
            correlation_id="test-correlation-123",
            session_id="session-456",
            user_id="user-789",
            operation="test_operation",
            component="test_component",
            request_id="request-abc",
            trace_id="trace-def",
            start_time=1234567890.0,
            duration=1.5,
            ip_address="192.168.1.100",
            user_agent="TestAgent/1.0",
            security_level="high",
            tenant_id="tenant-123",
            environment="testing",
            version="1.0.0",
        )

        assert context.correlation_id == "test-correlation-123"
        assert context.session_id == "session-456"
        assert context.user_id == "user-789"
        assert context.operation == "test_operation"
        assert context.component == "test_component"
        assert context.request_id == "request-abc"
        assert context.trace_id == "trace-def"
        assert context.start_time == 1234567890.0
        assert context.duration == 1.5
        assert context.ip_address == "192.168.1.100"
        assert context.user_agent == "TestAgent/1.0"
        assert context.security_level == "high"
        assert context.tenant_id == "tenant-123"
        assert context.environment == "testing"
        assert context.version == "1.0.0"

    def test_context_serialization(self) -> None:
        """Test log context serialization."""
        context = LogContext(
            correlation_id="test-123",
            operation="test_op",
            user_id="user-456",
        )

        context_dict = context.model_dump()

        assert context_dict["correlation_id"] == "test-123"
        assert context_dict["operation"] == "test_op"
        assert context_dict["user_id"] == "user-456"
        assert "timestamp" in context_dict


@pytest.mark.unit
@pytest.mark.logging
class TestLogRecord:
    """Test cases for log record functionality."""

    def test_log_record_creation(self) -> None:
        """Test creating structured log record."""
        context = LogContext(correlation_id="test-123")

        record = LogRecord(
            timestamp=datetime.now(),
            level="INFO",
            logger_name="test.logger",
            message="Test message",
            event_type=EventType.OPERATION,
            context=context,
        )

        assert record.level == "INFO"
        assert record.logger_name == "test.logger"
        assert record.message == "Test message"
        assert record.event_type == EventType.OPERATION
        assert record.context.correlation_id == "test-123"

    def test_log_record_with_optional_fields(self) -> None:
        """Test log record with all optional fields."""
        context = LogContext()
        exception_info = {"type": "ValueError", "message": "Test exception"}
        metrics = {"duration": 1.5, "requests": 10}
        tags = ["test", "operation"]

        record = LogRecord(
            timestamp=datetime.now(),
            level="ERROR",
            logger_name="test.logger",
            message="Error message",
            event_type=EventType.ERROR,
            context=context,
            exception=exception_info,
            stack_trace="Test stack trace",
            metrics=metrics,
            tags=tags,
        )

        assert record.exception == exception_info
        assert record.stack_trace == "Test stack trace"
        assert record.metrics == metrics
        assert record.tags == tags

    def test_log_record_json_serialization(self) -> None:
        """Test log record JSON serialization."""
        context = LogContext(correlation_id="test-123")

        record = LogRecord(
            timestamp=datetime.now(),
            level="INFO",
            logger_name="test.logger",
            message="Test message",
            event_type=EventType.SYSTEM,
            context=context,
            tags=["test"],
        )

        json_str = record.to_json()
        parsed = json.loads(json_str)

        assert parsed["level"] == "INFO"
        assert parsed["logger_name"] == "test.logger"
        assert parsed["message"] == "Test message"
        assert parsed["event_type"] == "system"
        assert parsed["context"]["correlation_id"] == "test-123"
        assert parsed["tags"] == ["test"]


@pytest.mark.unit
@pytest.mark.logging
class TestSensitiveDataFilter:
    """Test cases for sensitive data filtering."""

    def test_filter_message_patterns(self) -> None:
        """Test filtering sensitive patterns from messages."""
        test_cases = [
            ("User login with password=secret123", "password"),
            ("API call with token=abc123token", "token"),
            ("Configuration has secret=mysecret", "secret"),
            ("Authorization key=apikey123", "key"),
            ("Header authorization=Bearer token123", "authorization"),
        ]

        for message, pattern in test_cases:
            filtered = SensitiveDataFilter.filter_message(message)
            # Should contain redacted marker
            assert "***REDACTED***" in filtered or pattern not in filtered

    def test_filter_dict_sensitive_keys(self) -> None:
        """Test filtering sensitive keys from dictionaries."""
        sensitive_data = {
            "password": "secret123",
            "user_password": "secret456",
            "api_token": "token789",
            "secret_key": "key123",
            "authorization": "Bearer abc123",
            "username": "john_doe",  # Not sensitive
            "operation": "login",  # Not sensitive
            "timestamp": "2023-01-01T00:00:00Z",  # Not sensitive
        }

        filtered = SensitiveDataFilter.filter_dict(sensitive_data)

        # Sensitive fields should be redacted
        assert filtered["password"] == "***REDACTED***"
        assert filtered["user_password"] == "***REDACTED***"
        assert filtered["api_token"] == "***REDACTED***"
        assert filtered["secret_key"] == "***REDACTED***"
        assert filtered["authorization"] == "***REDACTED***"

        # Non-sensitive fields should remain
        assert filtered["username"] == "john_doe"
        assert filtered["operation"] == "login"
        assert filtered["timestamp"] == "2023-01-01T00:00:00Z"

    def test_filter_dict_nested_data(self) -> None:
        """Test filtering sensitive data in nested dictionaries."""
        nested_data = {
            "user_info": {
                "username": "john",
                "password": "secret123",
                "profile": {
                    "name": "John Doe",
                    "api_key": "key456",
                },
            },
            "config": {
                "database_url": "postgres://user:pass@host/db",
                "debug": True,
            },
        }

        filtered = SensitiveDataFilter.filter_dict(nested_data)

        # Nested sensitive data should be filtered
        assert filtered["user_info"]["password"] == "***REDACTED***"
        assert filtered["user_info"]["profile"]["api_key"] == "***REDACTED***"

        # Non-sensitive nested data should remain
        assert filtered["user_info"]["username"] == "john"
        assert filtered["user_info"]["profile"]["name"] == "John Doe"
        assert filtered["config"]["debug"] is True

    def test_filter_message_in_strings(self) -> None:
        """Test filtering sensitive patterns within string values."""
        data_with_sensitive_strings = {
            "error_message": "Authentication failed for password=secret123",
            "log_entry": "User token=abc123 expired",
            "safe_message": "Operation completed successfully",
        }

        filtered = SensitiveDataFilter.filter_dict(data_with_sensitive_strings)

        # String values should have sensitive patterns filtered
        error_msg = filtered["error_message"]
        log_entry = filtered["log_entry"]

        # Should not contain raw sensitive data
        assert "secret123" not in error_msg or "***REDACTED***" in error_msg
        assert "abc123" not in log_entry or "***REDACTED***" in log_entry

        # Safe messages should remain unchanged
        assert filtered["safe_message"] == "Operation completed successfully"


@pytest.mark.unit
@pytest.mark.logging
class TestStructuredFormatter:
    """Test cases for structured log formatter."""

    def test_basic_formatting(self) -> None:
        """Test basic log record formatting."""
        formatter = StructuredFormatter()

        # Create a standard logging record
        log_record = logging.LogRecord(
            name="test.logger",
            level=logging.INFO,
            pathname="test.py",
            lineno=10,
            msg="Test message",
            args=(),
            exc_info=None,
        )

        # Add structured data
        context = LogContext(correlation_id="test-123")
        log_record.context = context
        log_record.event_type = EventType.SYSTEM
        log_record.tags = ["test"]

        formatted = formatter.format(log_record)
        parsed = json.loads(formatted)

        assert parsed["level"] == "INFO"
        assert parsed["logger_name"] == "test.logger"
        assert parsed["message"] == "Test message"
        assert parsed["event_type"] == "system"
        assert parsed["context"]["correlation_id"] == "test-123"
        assert parsed["tags"] == ["test"]

    def test_formatting_with_exception(self) -> None:
        """Test formatting log records with exceptions."""
        formatter = StructuredFormatter(include_trace=True)

        try:
            msg = "Test exception"
            raise ValueError(msg)
        except ValueError:
            exc_info = True
        else:
            exc_info = None

        log_record = logging.LogRecord(
            name="test.logger",
            level=logging.ERROR,
            pathname="test.py",
            lineno=10,
            msg="Error occurred",
            args=(),
            exc_info=exc_info,
        )

        formatted = formatter.format(log_record)
        parsed = json.loads(formatted)

        assert parsed["level"] == "ERROR"
        assert parsed["message"] == "Error occurred"
        assert "exception" in parsed
        assert parsed["exception"]["type"] == "ValueError"
        assert parsed["exception"]["message"] == "Test exception"
        assert "stack_trace" in parsed

    def test_formatting_without_context(self) -> None:
        """Test formatting when no context is provided."""
        formatter = StructuredFormatter()

        log_record = logging.LogRecord(
            name="test.logger",
            level=logging.INFO,
            pathname="test.py",
            lineno=10,
            msg="Message without context",
            args=(),
            exc_info=None,
        )

        formatted = formatter.format(log_record)
        parsed = json.loads(formatted)

        assert parsed["message"] == "Message without context"
        assert "context" in parsed
        # Should have default context
        assert "correlation_id" in parsed["context"]

    def test_sensitive_data_filtering_in_formatter(self) -> None:
        """Test that formatter filters sensitive data."""
        formatter = StructuredFormatter()

        log_record = logging.LogRecord(
            name="test.logger",
            level=logging.WARNING,
            pathname="test.py",
            lineno=10,
            msg="User login failed with password=secret123",
            args=(),
            exc_info=None,
        )

        formatted = formatter.format(log_record)
        parsed = json.loads(formatted)

        # Message should have sensitive data filtered
        message = parsed["message"]
        assert "secret123" not in message or "***REDACTED***" in message


@pytest.mark.unit
@pytest.mark.logging
class TestPerformanceMonitor:
    """Test cases for performance monitoring."""

    def test_operation_timing(self) -> None:
        """Test basic operation timing functionality."""
        monitor = PerformanceMonitor(slow_threshold=0.1)

        operation_id = "test_operation_123"

        # Start timing
        monitor.start_operation(operation_id)

        # Simulate work
        time.sleep(0.05)

        # End timing
        duration = monitor.end_operation(operation_id)

        assert duration >= 0.05
        assert duration < 1.0  # Should be reasonable

    def test_slow_operation_detection(self) -> None:
        """Test slow operation detection and logging."""
        mock_logger = Mock(spec=StructuredLogger)
        monitor = PerformanceMonitor(slow_threshold=0.05)

        with monitor.time_operation("slow_test", logger=mock_logger):
            time.sleep(0.1)  # Exceed threshold

        # Should have called warning for slow operation
        mock_logger.warning.assert_called_once()
        call_args = mock_logger.warning.call_args
        assert "Slow operation detected" in call_args[0][0]
        assert call_args[1]["event_type"] == EventType.PERFORMANCE

    def test_fast_operation_no_warning(self) -> None:
        """Test that fast operations don't trigger warnings."""
        mock_logger = Mock(spec=StructuredLogger)
        monitor = PerformanceMonitor(slow_threshold=0.1)

        with monitor.time_operation("fast_test", logger=mock_logger):
            time.sleep(0.01)  # Under threshold

        # Should not have called warning
        mock_logger.warning.assert_not_called()

    def test_concurrent_operations(self) -> None:
        """Test timing multiple concurrent operations."""
        monitor = PerformanceMonitor()

        operation_ids = ["op1", "op2", "op3"]

        # Start all operations
        for op_id in operation_ids:
            monitor.start_operation(op_id)

        time.sleep(0.05)

        # End operations in different order
        durations = []
        for op_id in reversed(operation_ids):
            duration = monitor.end_operation(op_id)
            durations.append(duration)

        # All should have reasonable durations
        for duration in durations:
            assert duration >= 0.05
            assert duration < 1.0

    def test_end_nonexistent_operation(self) -> None:
        """Test ending an operation that was never started."""
        monitor = PerformanceMonitor()

        duration = monitor.end_operation("nonexistent_operation")

        # Should return 0.0 for non-existent operation
        assert duration == 0.0

    def test_context_manager_exception_handling(self) -> None:
        """Test performance monitor context manager with exceptions."""
        mock_logger = Mock(spec=StructuredLogger)
        monitor = PerformanceMonitor(slow_threshold=0.05)

        try:
            with monitor.time_operation("exception_test", logger=mock_logger):
                time.sleep(0.1)  # Exceed threshold
                msg = "Test exception"
                raise ValueError(msg)
        except ValueError:
            pass  # Expected

        # Should still log slow operation despite exception
        mock_logger.warning.assert_called_once()


@pytest.mark.unit
@pytest.mark.logging
class TestStructuredLogger:
    """Test cases for structured logger functionality."""

    def test_structured_logger_creation(self) -> None:
        """Test creating structured logger."""
        underlying_logger = logging.getLogger("test.structured")
        structured_logger = StructuredLogger("test.structured", underlying_logger)

        assert structured_logger.name == "test.structured"
        assert structured_logger.logger == underlying_logger

    def test_context_manager(self) -> None:
        """Test logger context manager functionality."""
        underlying_logger = logging.getLogger("test.context")
        structured_logger = StructuredLogger("test.context", underlying_logger)

        with structured_logger.context(operation="test_op", user_id="123"):
            current_context = structured_logger._get_current_context()
            assert current_context.operation == "test_op"
            assert current_context.user_id == "123"

        # Context should be reset after exiting
        after_context = structured_logger._get_current_context()
        assert after_context.operation is None
        assert after_context.user_id is None

    def test_nested_context_managers(self) -> None:
        """Test nested context managers."""
        underlying_logger = logging.getLogger("test.nested")
        structured_logger = StructuredLogger("test.nested", underlying_logger)

        with structured_logger.context(operation="outer_op"):
            with structured_logger.context(user_id="123"):
                context = structured_logger._get_current_context()
                assert context.operation == "outer_op"
                assert context.user_id == "123"

            # Inner context should be restored
            context = structured_logger._get_current_context()
            assert context.operation == "outer_op"
            assert context.user_id is None

    def test_logging_methods(self) -> None:
        """Test all logging level methods."""
        underlying_logger = Mock(spec=logging.Logger)
        underlying_logger.isEnabledFor.return_value = True
        underlying_logger.makeRecord.return_value = Mock()
        underlying_logger.handle.return_value = None

        structured_logger = StructuredLogger("test.methods", underlying_logger)

        # Test all logging methods
        structured_logger.trace("Trace message")
        structured_logger.debug("Debug message")
        structured_logger.info("Info message")
        structured_logger.warning("Warning message")
        structured_logger.error("Error message")
        structured_logger.critical("Critical message")

        # Should have called handle for each message
        assert underlying_logger.handle.call_count == 6

    def test_security_logging(self) -> None:
        """Test security event logging."""
        underlying_logger = Mock(spec=logging.Logger)
        underlying_logger.isEnabledFor.return_value = True
        underlying_logger.makeRecord.return_value = Mock()
        underlying_logger.handle.return_value = None

        structured_logger = StructuredLogger("test.security", underlying_logger)

        structured_logger.security(
            "Authentication failed",
            security_event=SecurityEventType.AUTHENTICATION_FAILURE,
            user_id="test_user",
        )

        # Should have called handle
        underlying_logger.handle.assert_called_once()

        # Check the record that was created
        call_args = underlying_logger.makeRecord.call_args
        assert call_args[1]["level"] == LogLevel.SECURITY.value

    def test_audit_logging(self) -> None:
        """Test audit event logging."""
        underlying_logger = Mock(spec=logging.Logger)
        underlying_logger.isEnabledFor.return_value = True
        underlying_logger.makeRecord.return_value = Mock()
        underlying_logger.handle.return_value = None

        structured_logger = StructuredLogger("test.audit", underlying_logger)

        structured_logger.audit(
            "User action performed",
            user_id="test_user",
            action="update_profile",
        )

        # Should have called handle
        underlying_logger.handle.assert_called_once()

    def test_performance_logging(self) -> None:
        """Test performance metrics logging."""
        underlying_logger = Mock(spec=logging.Logger)
        underlying_logger.isEnabledFor.return_value = True
        underlying_logger.makeRecord.return_value = Mock()
        underlying_logger.handle.return_value = None

        structured_logger = StructuredLogger("test.performance", underlying_logger)

        metrics = {"duration": 1.5, "requests": 10, "errors": 0}

        structured_logger.performance(
            "Operation completed",
            metrics=metrics,
            operation="data_sync",
        )

        # Should have called handle
        underlying_logger.handle.assert_called_once()

    def test_context_propagation_across_threads(self) -> None:
        """Test context propagation in multi-threaded environment."""
        underlying_logger = logging.getLogger("test.threads")
        structured_logger = StructuredLogger("test.threads", underlying_logger)

        results = {}

        def thread_function(thread_id) -> None:
            with structured_logger.context(thread_id=thread_id):
                context = structured_logger._get_current_context()
                assert context is not None
                results[thread_id] = context.thread_id

        # Start multiple threads with different contexts
        threads = []
        for i in range(3):
            thread = threading.Thread(target=thread_function, args=(f"thread_{i}",))
            threads.append(thread)
            thread.start()

        # Wait for all threads to complete
        for thread in threads:
            thread.join()

        # Each thread should have its own context
        assert results["thread_0"] == "thread_0"
        assert results["thread_1"] == "thread_1"
        assert results["thread_2"] == "thread_2"


@pytest.mark.unit
@pytest.mark.logging
class TestLoggerManager:
    """Test cases for logger manager functionality."""

    def test_logger_manager_initialization(self) -> None:
        """Test logger manager initialization."""
        config = LoggingConfig(
            level=LogLevel.DEBUG,
            console_enabled=True,
            structured_logging=True,
        )

        LoggerManager.initialize(config)

        assert LoggerManager._initialized is True
        assert LoggerManager._config == config

    def test_get_logger_after_initialization(self) -> None:
        """Test getting logger after manager initialization."""
        LoggerManager.initialize()

        logger = LoggerManager.get_logger("test.manager")

        assert isinstance(logger, StructuredLogger)
        assert logger.name == "test.manager"

    def test_get_logger_before_initialization(self) -> None:
        """Test getting logger before explicit initialization."""
        # Reset state
        LoggerManager._initialized = False
        LoggerManager._loggers.clear()

        # Should auto-initialize
        logger = LoggerManager.get_logger("test.auto")

        assert isinstance(logger, StructuredLogger)
        assert LoggerManager._initialized is True

    def test_logger_singleton_behavior(self) -> None:
        """Test that same logger name returns same instance."""
        LoggerManager.initialize()

        logger1 = LoggerManager.get_logger("test.singleton")
        logger2 = LoggerManager.get_logger("test.singleton")

        assert logger1 is logger2

    def test_performance_monitor_initialization(self) -> None:
        """Test performance monitor initialization."""
        config = LoggingConfig(
            performance_logging=True,
            slow_query_threshold=0.5,
        )

        LoggerManager.initialize(config)

        monitor = LoggerManager.get_performance_monitor()

        assert isinstance(monitor, PerformanceMonitor)
        assert monitor.slow_threshold == 0.5

    def test_performance_monitor_disabled(self) -> None:
        """Test when performance monitoring is disabled."""
        config = LoggingConfig(performance_logging=False)

        LoggerManager.initialize(config)

        monitor = LoggerManager.get_performance_monitor()

        assert monitor is None

    def test_file_logging_configuration(self) -> None:
        """Test file logging configuration."""
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            log_file = Path(tmp.name)

        try:
            config = LoggingConfig(
                log_file=log_file,
                max_file_size=1024 * 1024,  # 1MB
                backup_count=3,
                structured_logging=True,
            )

            LoggerManager.initialize(config)

            # Get logger and log a message
            logger = LoggerManager.get_logger("test.file")
            logger.info("Test file logging")

            # Force log flush
            logging.shutdown()

            # Verify log file was created and contains data
            assert log_file.exists()
            assert log_file.stat().st_size > 0

        finally:
            if log_file.exists():
                log_file.unlink()

    def test_logger_manager_shutdown(self) -> None:
        """Test logger manager shutdown."""
        LoggerManager.initialize()
        LoggerManager.get_logger("test.shutdown")

        LoggerManager.shutdown()

        assert LoggerManager._initialized is False
        assert len(LoggerManager._loggers) == 0
        assert LoggerManager._performance_monitor is None


@pytest.mark.integration
@pytest.mark.logging
class TestLoggingIntegration:
    """Integration tests for logging system."""

    def test_end_to_end_structured_logging(self) -> None:
        """Test complete structured logging flow."""
        # Initialize with structured logging
        config = LoggingConfig(
            level=LogLevel.DEBUG,
            structured_logging=True,
            console_enabled=False,  # Disable console for test
        )

        LoggerManager.initialize(config)

        # Get logger and use context
        logger = get_logger("integration.test")

        with logger.context(operation="integration_test", user_id="test_user"):
            logger.info("Starting integration test")
            logger.debug("Debug information", component="test_component")
            logger.warning("Warning message", event_type=EventType.OPERATION)

        # Test should complete without errors
        assert True

    def test_performance_monitoring_integration(self) -> None:
        """Test performance monitoring integration."""
        config = LoggingConfig(
            performance_logging=True,
            slow_query_threshold=0.01,  # Very low threshold for testing
        )

        LoggerManager.initialize(config)

        logger = get_logger("performance.test")
        monitor = get_performance_monitor()

        assert monitor is not None

        # Test slow operation detection
        with monitor.time_operation("slow_integration_test", logger=logger):
            time.sleep(0.02)  # Should trigger slow operation warning

        # Test should complete without errors
        assert True

    def test_security_event_logging_integration(self) -> None:
        """Test security event logging integration."""
        LoggerManager.initialize()

        logger = get_logger("security.test")

        # Log various security events
        logger.security(
            "User authentication failed",
            SecurityEventType.AUTHENTICATION_FAILURE,
            user_id="test_user",
            ip_address="192.168.1.100",
        )

        logger.security(
            "Unauthorized access attempt",
            SecurityEventType.AUTHORIZATION_FAILURE,
            user_id="malicious_user",
            resource="sensitive_data",
        )

        # Test should complete without errors
        assert True

    def test_configuration_integration(self) -> None:
        """Test logging configuration integration."""
        # Test different configuration scenarios
        configs = [
            LoggingConfig(level=LogLevel.INFO, structured_logging=False),
            LoggingConfig(level=LogLevel.DEBUG, structured_logging=True),
            LoggingConfig(level=LogLevel.ERROR, console_enabled=False),
        ]

        for config in configs:
            LoggerManager.shutdown()  # Reset
            LoggerManager.initialize(config)

            logger = get_logger(f"config.test.{config.level.value}")
            logger.info("Configuration test message")

            # Should not raise errors
            assert True


@pytest.mark.performance
@pytest.mark.logging
class TestLoggingPerformance:
    """Performance tests for logging system."""

    def test_logger_creation_performance(self, benchmark) -> None:
        """Benchmark logger creation performance."""
        LoggerManager.initialize()

        def create_logger():
            return get_logger("performance.test")

        result = benchmark(create_logger)
        assert isinstance(result, StructuredLogger)

    def test_structured_logging_performance(self, benchmark) -> None:
        """Benchmark structured logging performance."""
        LoggerManager.initialize()
        logger = get_logger("performance.structured")

        def log_structured_message() -> None:
            with logger.context(operation="benchmark", user_id="test"):
                logger.info("Benchmark message", component="test")

        benchmark(log_structured_message)

    def test_context_management_performance(self, benchmark) -> None:
        """Benchmark context management performance."""
        LoggerManager.initialize()
        logger = get_logger("performance.context")

        def use_context() -> None:
            with logger.context(operation="benchmark"):
                with logger.context(user_id="test"):
                    logger.debug("Nested context message")

        benchmark(use_context)

    def test_sensitive_data_filtering_performance(self, benchmark) -> None:
        """Benchmark sensitive data filtering performance."""
        sensitive_data = {
            "password": "secret123",
            "token": "abc123token",
            "key": "apikey456",
            "normal_field": "normal_value",
            "another_field": "another_value",
        }

        def filter_data():
            return SensitiveDataFilter.filter_dict(sensitive_data)

        result = benchmark(filter_data)
        assert result["password"] == "***REDACTED***"


# Custom test fixtures for logging testing
@pytest.fixture
def sample_logging_config():
    """Create a sample logging configuration for testing."""
    return LoggingConfig(
        level=LogLevel.DEBUG,
        console_enabled=True,
        structured_logging=True,
        performance_logging=True,
        slow_query_threshold=0.1,
    )


@pytest.fixture
def sample_log_context():
    """Create a sample log context for testing."""
    return LogContext(
        correlation_id="test-correlation-123",
        operation="test_operation",
        user_id="test_user",
        component="test_component",
    )


@pytest.fixture
def mock_structured_logger():
    """Create a mock structured logger for testing."""
    mock_logger = Mock(spec=StructuredLogger)
    mock_logger.name = "mock.logger"
    return mock_logger


@pytest.fixture
def temp_log_file():
    """Create a temporary log file for testing."""
    with tempfile.NamedTemporaryFile(suffix=".log", delete=False) as f:
        yield Path(f.name)

    # Cleanup
    Path(f.name).unlink(missing_ok=True)


@pytest.fixture(autouse=True)
def cleanup_logger_manager():
    """Cleanup logger manager state after each test."""
    yield

    # Reset logger manager state
    LoggerManager.shutdown()
    LoggerManager._initialized = False
    LoggerManager._loggers.clear()
    LoggerManager._performance_monitor = None
    LoggerManager._config = None
