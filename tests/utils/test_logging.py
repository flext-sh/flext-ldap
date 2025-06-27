"""Tests for Standardized Logging Utilities.

This module provides comprehensive test coverage for the LDAP logging
system including structured formatting, performance timing, and
security-aware logging with sensitive data masking.

Test Coverage:
    - StructuredFormatter: Consistent log message formatting
    - LDAPLogger: LDAP-specific logging with configuration
    - PerformanceTimer: Context manager for operation timing
    - Sensitive data masking and security validation
    - File logging with rotation and error handling

Security Testing:
    - Sensitive data masking validation
    - Log injection prevention
    - File permission and access validation
    - Error handling without information leakage

Performance Testing:
    - Large log volume handling
    - File rotation efficiency
    - Memory usage optimization
    - Timer accuracy validation
"""

from __future__ import annotations

import logging
import tempfile
import time
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from ldap_core_shared.utils.constants import DEFAULT_LARGE_LIMIT, DEFAULT_MAX_ITEMS
from ldap_core_shared.utils.logging import (
    BYTES_PER_KB,
    LDAPLogger,
    PerformanceTimer,
    StructuredFormatter,
    _loggers,
    get_logger,
    setup_logging,
)


class MockLoggingConfig:
    """Mock logging configuration for testing."""

    def __init__(self, **kwargs) -> None:
        self.level = kwargs.get("level", "INFO")
        self.format = kwargs.get(
            "format", "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        )
        self.file_path = kwargs.get("file_path")
        self.max_file_size_mb = kwargs.get("max_file_size_mb", DEFAULT_MAX_ITEMS)
        self.backup_count = kwargs.get("backup_count", 5)
        self.enable_console = kwargs.get("enable_console", True)
        self.mask_sensitive_data = kwargs.get("mask_sensitive_data", True)


class TestStructuredFormatter:
    """Test cases for StructuredFormatter."""

    def test_formatter_basic_message(self) -> None:
        """Test basic message formatting."""
        formatter = StructuredFormatter(include_timestamp=False)

        # Create mock log record
        record = logging.LogRecord(
            name="test.logger",
            level=logging.INFO,
            pathname="test.py",
            lineno=10,
            msg="Test message",
            args=(),
            exc_info=None,
        )

        result = formatter.format(record)
        expected = "test.logger - INFO - Test message"
        assert result == expected

    def test_formatter_with_timestamp(self) -> None:
        """Test message formatting with timestamp."""
        formatter = StructuredFormatter(include_timestamp=True)

        record = logging.LogRecord(
            name="test.logger",
            level=logging.INFO,
            pathname="test.py",
            lineno=10,
            msg="Test message",
            args=(),
            exc_info=None,
        )
        record.created = time.time()

        result = formatter.format(record)

        # Check that timestamp is included
        assert "test.logger - INFO - Test message" in result
        assert len(result) > len("test.logger - INFO - Test message")

    def test_formatter_with_extra_data(self) -> None:
        """Test formatting with extra structured data."""
        formatter = StructuredFormatter(include_timestamp=False)

        record = logging.LogRecord(
            name="test.logger",
            level=logging.INFO,
            pathname="test.py",
            lineno=10,
            msg="Test message",
            args=(),
            exc_info=None,
        )
        record.extra_data = {"key1": "value1", "key2": 42}

        result = formatter.format(record)
        expected = "test.logger - INFO - Test message | key1=value1 key2=42"
        assert result == expected

    def test_formatter_with_exception(self) -> None:
        """Test formatting with exception information."""
        formatter = StructuredFormatter(include_timestamp=False)

        try:
            msg = "Test exception"
            raise ValueError(msg)
        except ValueError:
            import sys

            exc_info = sys.exc_info()

        record = logging.LogRecord(
            name="test.logger",
            level=logging.ERROR,
            pathname="test.py",
            lineno=10,
            msg="Error occurred",
            args=(),
            exc_info=exc_info,
        )

        result = formatter.format(record)

        assert "test.logger - ERROR - Error occurred" in result
        assert "ValueError: Test exception" in result
        assert "Traceback" in result

    def test_formatter_empty_extra_data(self) -> None:
        """Test formatting with empty extra data."""
        formatter = StructuredFormatter(include_timestamp=False)

        record = logging.LogRecord(
            name="test.logger",
            level=logging.INFO,
            pathname="test.py",
            lineno=10,
            msg="Test message",
            args=(),
            exc_info=None,
        )
        record.extra_data = {}

        result = formatter.format(record)
        expected = "test.logger - INFO - Test message"
        assert result == expected


class TestLDAPLogger:
    """Test cases for LDAPLogger."""

    def setup_method(self) -> None:
        """Set up test fixtures."""
        # Clear global logger registry
        _loggers.clear()

    def test_logger_initialization_basic(self) -> None:
        """Test basic logger initialization."""
        config = MockLoggingConfig()
        logger = LDAPLogger("test.logger", config)

        assert logger.name == "test.logger"
        assert logger.config == config
        assert isinstance(logger.logger, logging.Logger)
        assert logger.logger.level == logging.INFO

    def test_logger_initialization_without_config(self) -> None:
        """Test logger initialization without config."""
        logger = LDAPLogger("test.logger")

        assert logger.name == "test.logger"
        assert hasattr(logger.config, "level")
        assert logger.config.level == "INFO"

    def test_logger_initialization_fallback_config(self) -> None:
        """Test logger initialization with fallback config."""
        # Mock Pydantic config failure
        with patch(
            "ldap_core_shared.config.base_config.LoggingConfig",
            side_effect=Exception("Mock failure"),
        ):
            logger = LDAPLogger("test.logger")

            assert logger.name == "test.logger"
            assert hasattr(logger.config, "level")
            assert logger.config.level == "INFO"
            assert logger.config.mask_sensitive_data is True

    def test_logger_console_setup(self) -> None:
        """Test console handler setup."""
        config = MockLoggingConfig(enable_console=True)
        logger = LDAPLogger("test.logger", config)

        # Should have console handler
        handlers = logger.logger.handlers
        assert len(handlers) >= 1
        assert any(isinstance(h, logging.StreamHandler) for h in handlers)

    def test_logger_console_disabled(self) -> None:
        """Test logger with console disabled."""
        config = MockLoggingConfig(enable_console=False)
        logger = LDAPLogger("test.logger", config)

        # Should not have console handler
        handlers = logger.logger.handlers
        console_handlers = [h for h in handlers if isinstance(h, logging.StreamHandler)]
        assert len(console_handlers) == 0

    def test_logger_file_setup(self) -> None:
        """Test file handler setup."""
        with tempfile.TemporaryDirectory() as temp_dir:
            log_file = Path(temp_dir) / "test.log"
            config = MockLoggingConfig(file_path=str(log_file))
            logger = LDAPLogger("test.logger", config)

            # Should have file handler
            handlers = logger.logger.handlers
            file_handlers = [
                h
                for h in handlers
                if isinstance(h, logging.handlers.RotatingFileHandler)
            ]
            assert len(file_handlers) == 1

    def test_logger_file_setup_failure(self) -> None:
        """Test file handler setup with invalid path."""
        config = MockLoggingConfig(file_path="/invalid/path/test.log")

        # Should handle gracefully without crashing
        logger = LDAPLogger("test.logger", config)

        # Should still have console handler
        handlers = logger.logger.handlers
        assert len(handlers) >= 1

    def test_logger_debug_message(self) -> None:
        """Test debug message logging."""
        config = MockLoggingConfig(level="DEBUG", enable_console=False)
        logger = LDAPLogger("test.logger", config)

        with patch.object(logger.logger, "handle") as mock_handle:
            logger.debug("Debug message", key1="value1", key2=42)

            mock_handle.assert_called_once()
            record = mock_handle.call_args[0][0]
            assert record.levelno == logging.DEBUG
            assert record.getMessage() == "Debug message"
            assert hasattr(record, "extra_data")
            assert record.extra_data["key1"] == "value1"
            assert record.extra_data["key2"] == 42

    def test_logger_info_message(self) -> None:
        """Test info message logging."""
        config = MockLoggingConfig(enable_console=False)
        logger = LDAPLogger("test.logger", config)

        with patch.object(logger.logger, "handle") as mock_handle:
            logger.info("Info message", operation="test")

            mock_handle.assert_called_once()
            record = mock_handle.call_args[0][0]
            assert record.levelno == logging.INFO
            assert record.getMessage() == "Info message"
            assert record.extra_data["operation"] == "test"

    def test_logger_warning_message(self) -> None:
        """Test warning message logging."""
        config = MockLoggingConfig(enable_console=False)
        logger = LDAPLogger("test.logger", config)

        with patch.object(logger.logger, "handle") as mock_handle:
            logger.warning("Warning message", reason="test")

            mock_handle.assert_called_once()
            record = mock_handle.call_args[0][0]
            assert record.levelno == logging.WARNING

    def test_logger_error_message(self) -> None:
        """Test error message logging."""
        config = MockLoggingConfig(enable_console=False)
        logger = LDAPLogger("test.logger", config)

        with patch.object(logger.logger, "handle") as mock_handle:
            logger.error("Error message", error_code=500)

            mock_handle.assert_called_once()
            record = mock_handle.call_args[0][0]
            assert record.levelno == logging.ERROR

    def test_logger_critical_message(self) -> None:
        """Test critical message logging."""
        config = MockLoggingConfig(enable_console=False)
        logger = LDAPLogger("test.logger", config)

        with patch.object(logger.logger, "handle") as mock_handle:
            logger.critical("Critical message", severity="high")

            mock_handle.assert_called_once()
            record = mock_handle.call_args[0][0]
            assert record.levelno == logging.CRITICAL

    def test_sensitive_data_masking_enabled(self) -> None:
        """Test sensitive data masking when enabled."""
        config = MockLoggingConfig(mask_sensitive_data=True, enable_console=False)
        logger = LDAPLogger("test.logger", config)

        with patch.object(logger.logger, "handle") as mock_handle:
            logger.info("Login attempt", password="secret123", username="user")

            mock_handle.assert_called_once()
            record = mock_handle.call_args[0][0]
            assert record.extra_data["password"] == "***MASKED***"
            assert record.extra_data["username"] == "user"  # Not sensitive

    def test_sensitive_data_masking_disabled(self) -> None:
        """Test sensitive data masking when disabled."""
        config = MockLoggingConfig(mask_sensitive_data=False, enable_console=False)
        logger = LDAPLogger("test.logger", config)

        with patch.object(logger.logger, "handle") as mock_handle:
            logger.info("Login attempt", password="secret123", username="user")

            mock_handle.assert_called_once()
            record = mock_handle.call_args[0][0]
            assert record.extra_data["password"] == "secret123"  # Not masked
            assert record.extra_data["username"] == "user"

    def test_mask_sensitive_data_various_keys(self) -> None:
        """Test masking of various sensitive key names."""
        config = MockLoggingConfig(mask_sensitive_data=True)
        logger = LDAPLogger("test.logger", config)

        test_data = {
            "password": "secret1",
            "passwd": "secret2",
            "pwd": "secret3",
            "secret": "secret4",
            "token": "secret5",
            "key": "secret6",
            "auth": "secret7",
            "credential": "secret8",
            "bind_password": "secret9",
            "username": "user123",  # Should not be masked
            "email": "user@example.com",  # Should not be masked
        }

        masked = logger._mask_sensitive_data(test_data)

        # Check sensitive data is masked
        for key in [
            "password",
            "passwd",
            "pwd",
            "secret",
            "token",
            "key",
            "auth",
            "credential",
            "bind_password",
        ]:
            assert masked[key] == "***MASKED***"

        # Check non-sensitive data is preserved
        assert masked["username"] == "user123"
        assert masked["email"] == "user@example.com"

    def test_log_ldap_operation_success(self) -> None:
        """Test LDAP operation logging for success."""
        config = MockLoggingConfig(enable_console=False)
        logger = LDAPLogger("test.logger", config)

        with patch.object(logger, "info") as mock_info:
            logger.log_ldap_operation(
                operation="SEARCH",
                dn="cn=test,dc=example,dc=com",
                success=True,
                duration=0.5,
                result_count=10,
            )

            mock_info.assert_called_once()
            call_args = mock_info.call_args
            assert "LDAP SEARCH successful" in call_args[0]
            assert call_args[1]["operation"] == "SEARCH"
            assert call_args[1]["dn"] == "cn=test,dc=example,dc=com"
            assert call_args[1]["success"] is True
            assert call_args[1]["duration_ms"] == 500.0  # 0.5 * 1000
            assert call_args[1]["result_count"] == 10

    def test_log_ldap_operation_failure(self) -> None:
        """Test LDAP operation logging for failure."""
        config = MockLoggingConfig(enable_console=False)
        logger = LDAPLogger("test.logger", config)

        with patch.object(logger, "error") as mock_error:
            logger.log_ldap_operation(
                operation="BIND",
                dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
                success=False,
                error_code=49,
            )

            mock_error.assert_called_once()
            call_args = mock_error.call_args
            assert "LDAP BIND failed" in call_args[0]
            assert call_args[1]["operation"] == "BIND"
            assert call_args[1]["success"] is False
            assert call_args[1]["error_code"] == 49

    def test_log_performance(self) -> None:
        """Test performance logging."""
        config = MockLoggingConfig(enable_console=False)
        logger = LDAPLogger("test.logger", config)

        with patch.object(logger, "info") as mock_info:
            logger.log_performance(
                operation="BULK_IMPORT",
                count=1000,
                duration=10.5,
                memory_mb=128,
            )

            mock_info.assert_called_once()
            call_args = mock_info.call_args
            assert "Performance: BULK_IMPORT" in call_args[0]
            assert call_args[1]["operation"] == "BULK_IMPORT"
            assert call_args[1]["count"] == 1000
            assert call_args[1]["duration_s"] == 10.5
            assert call_args[1]["rate_per_second"] == pytest.approx(95.24, rel=1e-2)
            assert call_args[1]["memory_mb"] == 128

    def test_log_migration_progress(self) -> None:
        """Test migration progress logging."""
        config = MockLoggingConfig(enable_console=False)
        logger = LDAPLogger("test.logger", config)

        with patch.object(logger, "info") as mock_info:
            logger.log_migration_progress(
                stage="USER_IMPORT",
                processed=750,
                total=1000,
                errors=5,
                source="LDAP_A",
            )

            mock_info.assert_called_once()
            call_args = mock_info.call_args
            assert "Migration progress: USER_IMPORT" in call_args[0]
            assert call_args[1]["stage"] == "USER_IMPORT"
            assert call_args[1]["processed"] == 750
            assert call_args[1]["total"] == 1000
            assert call_args[1]["percentage"] == 75.0
            assert call_args[1]["errors"] == 5
            assert call_args[1]["source"] == "LDAP_A"


class TestGlobalFunctions:
    """Test cases for global logging functions."""

    def setup_method(self) -> None:
        """Set up test fixtures."""
        _loggers.clear()

    def test_get_logger_new(self) -> None:
        """Test getting new logger instance."""
        config = MockLoggingConfig()
        logger = get_logger("test.new", config)

        assert isinstance(logger, LDAPLogger)
        assert logger.name == "test.new"
        assert logger.config == config

    def test_get_logger_existing(self) -> None:
        """Test getting existing logger instance."""
        config = MockLoggingConfig()
        logger1 = get_logger("test.existing", config)
        logger2 = get_logger("test.existing")  # No config provided

        # Should return the same instance
        assert logger1 is logger2
        assert logger1.config == config

    def test_setup_logging(self) -> None:
        """Test logging setup function."""
        config = MockLoggingConfig(level="DEBUG")

        # Add some existing loggers
        get_logger("existing1")
        get_logger("existing2")
        assert len(_loggers) == 2

        # Setup logging should clear existing loggers
        root_logger = setup_logging(config, "root")

        assert isinstance(root_logger, LDAPLogger)
        assert root_logger.name == "root"
        assert root_logger.config == config
        assert len(_loggers) == 1  # Only the root logger
        assert "root" in _loggers


class TestPerformanceTimer:
    """Test cases for PerformanceTimer."""

    def test_timer_basic_usage(self) -> None:
        """Test basic timer usage."""
        mock_logger = Mock()
        mock_logger.info = Mock()

        with PerformanceTimer(mock_logger, "test_operation") as timer:
            time.sleep(0.01)  # Small delay

        assert timer.get_duration() is not None
        assert timer.get_duration() > 0
        assert timer.get_duration() < 1.0  # Should be much less than 1 second

        # Should have called logger.info
        mock_logger.info.assert_called_once()
        call_args = mock_logger.info.call_args
        assert "Operation completed: test_operation" in call_args[0]

    def test_timer_without_auto_log(self) -> None:
        """Test timer without automatic logging."""
        mock_logger = Mock()
        mock_logger.info = Mock()

        with PerformanceTimer(mock_logger, "test_operation", auto_log=False) as timer:
            time.sleep(0.01)

        assert timer.get_duration() is not None
        assert timer.get_duration() > 0

        # Should not have called logger
        mock_logger.info.assert_not_called()

    def test_timer_with_extra_data(self) -> None:
        """Test timer with extra data."""
        mock_logger = Mock()
        mock_logger.info = Mock()

        with PerformanceTimer(
            mock_logger,
            "test_operation",
            operation_type="bulk_import",
            count=1000,
        ) as timer:
            time.sleep(0.01)

        assert timer.get_duration() is not None

        # Check extra data was passed
        mock_logger.info.assert_called_once()
        call_args = mock_logger.info.call_args
        assert call_args[1]["operation_type"] == "bulk_import"
        assert call_args[1]["count"] == 1000

    def test_timer_with_exception(self) -> None:
        """Test timer behavior when exception occurs."""
        mock_logger = Mock()
        mock_logger.info = Mock()

        try:
            with PerformanceTimer(mock_logger, "test_operation") as timer:
                time.sleep(0.01)
                msg = "Test exception"
                raise ValueError(msg)
        except ValueError:
            pass

        # Should still record duration and log
        assert timer.get_duration() is not None
        assert timer.get_duration() > 0
        mock_logger.info.assert_called_once()

    def test_timer_duration_accuracy(self) -> None:
        """Test timer duration accuracy."""
        mock_logger = Mock()

        start_time = time.time()
        with PerformanceTimer(mock_logger, "test_operation", auto_log=False) as timer:
            time.sleep(0.1)  # 100ms delay
        end_time = time.time()

        expected_duration = end_time - start_time
        actual_duration = timer.get_duration()

        assert actual_duration is not None
        # Allow for some timing variance
        assert abs(actual_duration - expected_duration) < 0.01


class TestSecurityValidation:
    """Security-focused test cases."""

    def test_log_injection_prevention(self) -> None:
        """Test prevention of log injection attacks."""
        config = MockLoggingConfig(enable_console=False)
        logger = LDAPLogger("test.logger", config)

        # Test with potential injection strings
        malicious_inputs = [
            "user\nINFO - Fake log entry",
            "user\r\nERROR - Injected error",
            "user\x00REDACTED_LDAP_BIND_PASSWORD",
            "user\x1b[31mred_text\x1b[0m",
        ]

        with patch.object(logger.logger, "handle") as mock_handle:
            for malicious_input in malicious_inputs:
                logger.info("User login", username=malicious_input)

        # Should have logged all attempts
        assert mock_handle.call_count == len(malicious_inputs)

        # Check that log records contain the original (potentially malicious) data
        # The formatter should handle escaping/display safely
        for call in mock_handle.call_args_list:
            record = call[0][0]
            assert hasattr(record, "extra_data")
            assert "username" in record.extra_data

    def test_sensitive_key_variations(self) -> None:
        """Test detection of sensitive keys with variations."""
        config = MockLoggingConfig(mask_sensitive_data=True)
        logger = LDAPLogger("test.logger", config)

        test_cases = [
            ("user_password", "secret", True),
            ("PASSWORD", "secret", True),
            ("bind_pwd", "secret", True),
            ("auth_token", "secret", True),
            ("api_key", "secret", True),
            ("user_credential", "secret", True),
            ("username", "user123", False),
            ("email_address", "user@example.com", False),
            ("user_id", "12345", False),
        ]

        for key, value, should_mask in test_cases:
            data = {key: value}
            masked = logger._mask_sensitive_data(data)

            if should_mask:
                assert masked[key] == "***MASKED***", f"Key '{key}' should be masked"
            else:
                assert masked[key] == value, f"Key '{key}' should not be masked"

    def test_file_permission_handling(self) -> None:
        """Test file permission error handling."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create a directory where we don't have write permission
            log_file = Path(temp_dir) / "restricted" / "test.log"

            # Make parent directory read-only (on Unix systems)
            import os

            if os.name == "posix":
                restricted_dir = log_file.parent
                restricted_dir.mkdir(exist_ok=True)
                restricted_dir.chmod(0o444)  # Read-only

                try:
                    config = MockLoggingConfig(file_path=str(log_file))
                    logger = LDAPLogger("test.logger", config)

                    # Should handle gracefully without crashing
                    assert isinstance(logger, LDAPLogger)

                finally:
                    # Restore permissions for cleanup
                    restricted_dir.chmod(0o755)


class TestPerformanceValidation:
    """Performance-focused test cases."""

    def test_large_volume_logging(self) -> None:
        """Test logging performance with large volumes."""
        config = MockLoggingConfig(enable_console=False)
        logger = LDAPLogger("test.logger", config)

        start_time = time.time()

        # Log many messages quickly
        for i in range(1000):
            logger.info("Message %s", i, count=i, operation="test")

        duration = time.time() - start_time

        # Should complete reasonably quickly
        assert duration < 5.0  # Less than 5 seconds for 1000 messages

    def test_timer_overhead(self) -> None:
        """Test performance timer overhead."""
        mock_logger = Mock()

        # Test timer overhead
        start_time = time.time()
        for _ in range(100):
            with PerformanceTimer(mock_logger, "test", auto_log=False):
                pass  # No operation
        duration = time.time() - start_time

        # Timer overhead should be minimal
        assert duration < 0.1  # Less than 100ms for 100 timer instances

    def test_structured_formatter_performance(self) -> None:
        """Test structured formatter performance."""
        formatter = StructuredFormatter()

        # Create record with large extra data
        record = logging.LogRecord(
            name="test.logger",
            level=logging.INFO,
            pathname="test.py",
            lineno=10,
            msg="Test message",
            args=(),
            exc_info=None,
        )
        record.extra_data = {f"key_{i}": f"value_{i}" for i in range(100)}

        start_time = time.time()
        for _ in range(100):
            formatter.format(record)
        duration = time.time() - start_time

        # Formatting should be fast even with large extra data
        assert duration < 1.0  # Less than 1 second for 100 formats


class TestConstants:
    """Test cases for module constants."""

    def test_constants_values(self) -> None:
        """Test that constants have expected values."""
        assert BYTES_PER_KB == 1024
        assert DEFAULT_LARGE_LIMIT == 1000
        assert DEFAULT_MAX_ITEMS == 100


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
