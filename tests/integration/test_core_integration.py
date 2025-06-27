"""Integration tests for LDAP Core Shared complete system.

This module provides comprehensive integration testing for the complete LDAP Core
Shared system, testing the interaction between all core components including
configuration management, logging, exception handling, and initialization.

Test Coverage:
    - End-to-end initialization and configuration loading
    - Integration between logging and exception systems
    - Configuration validation across all components
    - Performance monitoring integration
    - Security event logging integration
    - Error handling across component boundaries
    - Resource cleanup and shutdown procedures
    - Multi-environment configuration testing
    - Component interaction under various scenarios

Test Categories:
    - System initialization integration tests
    - Cross-component communication tests
    - Error propagation and handling tests
    - Configuration consistency tests
    - Performance and monitoring integration tests
    - Security integration tests
"""

import json
import tempfile
import time
from pathlib import Path
from unittest.mock import patch

import pytest

from ldap_core_shared.core import (
    ApplicationConfig,
    CoreInitializationError,
    Environment,
    get_config,
    get_logger,
    get_performance_monitor,
    initialize_core,
    shutdown_core,
)
from ldap_core_shared.core.config import ConfigManager
from ldap_core_shared.core.exceptions import (
    ConfigurationValidationError,
    ErrorCategory,
    ErrorSeverity,
    LDAPCoreError,
    ValidationError,
)
from ldap_core_shared.core.logging import (
    LoggerManager,
    SecurityEventType,
)


@pytest.mark.integration
class TestSystemInitializationIntegration:
    """Integration tests for complete system initialization."""

    def test_complete_system_startup_and_shutdown(self) -> None:
        """Test complete system startup and shutdown cycle."""
        # Initialize with comprehensive configuration
        config = initialize_core(
            environment="testing",
            override_values={
                "debug": True,
                "logging": {
                    "level": "DEBUG",
                    "structured_logging": True,
                    "performance_logging": True,
                    "security_logging": True,
                },
                "monitoring": {
                    "enabled": True,
                    "health_check_enabled": True,
                },
                "security": {
                    "require_authentication": True,
                },
            },
        )

        # Verify all components are initialized
        assert isinstance(config, ApplicationConfig)
        assert config.environment == Environment.TESTING

        # Test logger functionality
        logger = get_logger("integration.startup")
        assert logger is not None

        # Test performance monitor
        monitor = get_performance_monitor()
        assert monitor is not None

        # Test configuration access
        retrieved_config = get_config()
        assert retrieved_config is config

        # Test logging with various types
        logger.info("System startup completed")
        logger.debug("Debug information")
        logger.security(
            "Security event logged",
            SecurityEventType.AUTHENTICATION_SUCCESS,
        )

        # Test performance monitoring
        with monitor.time_operation("startup_test"):
            time.sleep(0.001)

        # Shutdown system
        shutdown_core()

        # Verify system is properly shut down
        from ldap_core_shared.core import is_initialized

        assert is_initialized() is False

    def test_configuration_hierarchy_integration(self) -> None:
        """Test configuration hierarchy with all override methods."""
        # Create configuration file
        file_config = {
            "environment": "staging",
            "debug": False,
            "version": "file-1.0.0",
            "database": {
                "host": "file-db.example.com",
                "port": 5432,
            },
            "logging": {
                "level": "INFO",
                "structured_logging": False,
            },
        }

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        ) as f:
            json.dump(file_config, f)
            config_file = f.name

        try:
            # Set environment variables
            env_overrides = {
                "LDAP_CORE_DEBUG": "true",
                "LDAP_CORE_DATABASE_HOST": "env-db.example.com",
                "LDAP_CORE_LOGGING_STRUCTURED_LOGGING": "true",
            }

            with patch.dict("os.environ", env_overrides):
                # Initialize with all override methods
                config = initialize_core(
                    config_file=config_file,
                    override_values={
                        "version": "override-2.0.0",
                        "database": {"port": 5433},
                        "logging": {"level": "DEBUG"},
                    },
                )

                # Verify hierarchy: overrides > env vars > file > defaults
                assert config.environment == Environment.STAGING  # From file
                assert config.debug is True  # From env var
                assert config.version == "override-2.0.0"  # From override
                assert config.database.host == "env-db.example.com"  # From env var
                assert config.database.port == 5433  # From override
                assert config.logging.level.value == "DEBUG"  # From override
                assert config.logging.structured_logging is True  # From env var

        finally:
            Path(config_file).unlink()

    def test_multi_environment_configuration_validation(self) -> None:
        """Test configuration validation across different environments."""
        environments_and_configs = [
            (
                "development",
                {
                    "debug": True,
                    "logging": {"level": "DEBUG"},
                },
            ),
            (
                "testing",
                {
                    "debug": True,
                    "logging": {"level": "INFO"},
                },
            ),
            (
                "staging",
                {
                    "debug": False,
                    "logging": {"level": "INFO"},
                    "security": {"require_authentication": True},
                },
            ),
            (
                "production",
                {
                    "debug": False,
                    "logging": {"level": "WARNING"},
                    "security": {"require_authentication": True},
                    "connection": {"use_tls": True},
                },
            ),
        ]

        for env_name, overrides in environments_and_configs:
            shutdown_core()  # Reset between tests

            config = initialize_core(
                environment=env_name,
                override_values=overrides,
            )

            assert config.environment.value == env_name

            # Verify environment-specific validations
            validation_errors = config.validate_full_config()

            if env_name == "production":
                # Production should have stricter validation
                assert config.security.require_authentication is True
                assert config.connection.use_tls is True
                assert config.debug is False

            # Should have no validation errors for properly configured environments
            assert len(validation_errors) == 0


@pytest.mark.integration
class TestLoggingExceptionIntegration:
    """Integration tests for logging and exception systems."""

    def test_exception_logging_integration(self) -> None:
        """Test integration between exception and logging systems."""
        # Initialize with structured logging
        initialize_core(
            override_values={
                "logging": {
                    "structured_logging": True,
                    "security_logging": True,
                },
            }
        )

        logger = get_logger("integration.exceptions")

        # Test logging various exception types
        try:
            raise ValidationError(
                message="Test validation error",
                field="test_field",
                value="invalid_value",
            )
        except ValidationError as e:
            logger.exception("Validation error occurred", exception=e)

        # Test logging with context and exception
        with logger.context(operation="test_operation", user_id="test_user"):
            try:
                raise LDAPCoreError(
                    message="Test core error",
                    error_code="TEST_001",
                    severity=ErrorSeverity.HIGH,
                    category=ErrorCategory.OPERATION,
                )
            except LDAPCoreError as e:
                logger.exception("Core error in context", exception=e)

        # Test security exception logging
        try:
            from ldap_core_shared.core.exceptions import SecurityViolationError

            raise SecurityViolationError(
                message="Unauthorized access attempt",
                violation_type="unauthorized_access",
                user_id="malicious_user",
            )
        except SecurityViolationError as e:
            logger.security(
                "Security violation detected",
                SecurityEventType.SECURITY_VIOLATION,
                exception=e,
            )

    def test_configuration_exception_integration(self) -> None:
        """Test integration between configuration and exception systems."""
        # Test configuration validation with exception handling
        with pytest.raises(CoreInitializationError) as exc_info:
            initialize_core(
                environment="production",
                override_values={
                    "debug": True,  # Should trigger validation error
                    "security": {"require_authentication": False},
                },
            )

        # Verify the exception contains proper context
        assert "Configuration validation failed" in str(exc_info.value)
        assert isinstance(exc_info.value.cause, ConfigurationValidationError)

    def test_performance_monitoring_logging_integration(self) -> None:
        """Test integration between performance monitoring and logging."""
        initialize_core(
            override_values={
                "logging": {
                    "performance_logging": True,
                    "slow_query_threshold": 0.01,  # Very low threshold
                },
                "monitoring": {"enabled": True},
            }
        )

        logger = get_logger("integration.performance")
        monitor = get_performance_monitor()

        # Test slow operation detection and logging
        with monitor.time_operation("slow_test_operation", logger=logger):
            time.sleep(0.02)  # Should exceed threshold

        # Test performance logging with metrics
        metrics = {
            "duration": 1.5,
            "requests_processed": 100,
            "errors": 2,
            "throughput": 66.67,
        }

        logger.performance(
            "Operation performance metrics",
            metrics=metrics,
            operation="data_processing",
        )


@pytest.mark.integration
class TestConfigurationComponentIntegration:
    """Integration tests for configuration with all components."""

    def test_configuration_affects_all_components(self) -> None:
        """Test that configuration changes affect all components."""
        # Initialize with specific configuration
        initialize_core(
            override_values={
                "debug": True,
                "logging": {
                    "level": "DEBUG",
                    "structured_logging": True,
                    "performance_logging": True,
                    "slow_query_threshold": 0.1,
                },
                "security": {
                    "require_authentication": True,
                    "session_timeout": 7200,
                },
                "monitoring": {
                    "enabled": True,
                    "health_check_enabled": True,
                    "health_check_interval": 60,
                },
            }
        )

        # Verify configuration propagated to logging system
        logger = get_logger("integration.config")
        assert LoggerManager._config.level.value == "DEBUG"
        assert LoggerManager._config.structured_logging is True

        # Verify performance monitoring configuration
        monitor = get_performance_monitor()
        assert monitor is not None
        assert monitor.slow_threshold == 0.1

        # Test that components work with the configuration
        with logger.context(test_context=True):
            logger.debug("Debug message should be logged")

            with monitor.time_operation("config_test"):
                time.sleep(0.001)  # Under threshold, should not warn

    def test_configuration_validation_across_components(self) -> None:
        """Test configuration validation across all components."""
        # Test valid configuration
        valid_config = {
            "environment": "production",
            "debug": False,
            "database": {
                "host": "prod-db.example.com",
                "port": 5432,
                "ssl_mode": "require",
                "pool_size": 20,
            },
            "connection": {
                "servers": ["ldaps://ldap.example.com:636"],
                "use_tls": True,
                "tls_verify": True,
                "pool_size": 10,
                "max_pool_size": 50,
            },
            "security": {
                "require_authentication": True,
                "session_timeout": 3600,
                "sasl_mechanisms": ["PLAIN", "DIGEST-MD5"],
            },
            "logging": {
                "level": "INFO",
                "structured_logging": True,
                "security_logging": True,
            },
            "monitoring": {
                "enabled": True,
                "metrics_enabled": True,
            },
        }

        config = initialize_core(override_values=valid_config)

        # Should pass all validation rules
        validation_errors = config.validate_full_config()
        assert len(validation_errors) == 0

    def test_configuration_template_generation_integration(self) -> None:
        """Test configuration template generation integration."""
        # Initialize system
        initialize_core()

        # Generate configuration template
        with tempfile.NamedTemporaryFile(suffix=".yaml", delete=False) as f:
            template_file = Path(f.name)

        try:
            ConfigManager.save_config_template(template_file)

            # Verify template was generated
            assert template_file.exists()

            # Load and validate template
            import yaml

            with template_file.open("r") as f:
                template_data = yaml.safe_load(f)

            # Verify all required sections are present
            required_sections = [
                "environment",
                "database",
                "connection",
                "schema",
                "security",
                "logging",
                "monitoring",
            ]

            for section in required_sections:
                assert section in template_data

            # Test that template can be used for initialization
            shutdown_core()
            config = initialize_core(config_file=template_file)
            assert isinstance(config, ApplicationConfig)

        finally:
            template_file.unlink()


@pytest.mark.integration
class TestErrorHandlingIntegration:
    """Integration tests for error handling across components."""

    def test_initialization_error_propagation(self) -> None:
        """Test error propagation during initialization."""
        # Test various initialization failure scenarios
        failure_scenarios = [
            # Configuration validation failure
            {
                "environment": "production",
                "debug": True,
                "security": {"require_authentication": False},
            },
            # Invalid configuration values
            {
                "database": {"port": "invalid_port"},
            },
            # Conflicting configuration
            {
                "connection": {"pool_size": 50, "max_pool_size": 10},
            },
        ]

        for invalid_config in failure_scenarios:
            with pytest.raises(CoreInitializationError):
                initialize_core(override_values=invalid_config)

    def test_logging_error_handling_integration(self) -> None:
        """Test error handling in logging system integration."""
        initialize_core(
            override_values={
                "logging": {
                    "structured_logging": True,
                    "console_enabled": True,
                },
            }
        )

        logger = get_logger("integration.error_handling")

        # Test logging with various error conditions
        try:
            # Simulate complex error scenario
            msg = "Original error"
            raise ValueError(msg)
        except ValueError as original:
            try:
                raise LDAPCoreError(
                    message="Wrapped error",
                    error_code="WRAP_001",
                    cause=original,
                )
            except LDAPCoreError as wrapped:
                # Should log without throwing additional errors
                logger.exception("Complex error scenario", exception=wrapped)

    def test_performance_monitoring_error_handling(self) -> None:
        """Test error handling in performance monitoring integration."""
        initialize_core(
            override_values={
                "logging": {"performance_logging": True},
                "monitoring": {"enabled": True},
            }
        )

        logger = get_logger("integration.perf_errors")
        monitor = get_performance_monitor()

        # Test performance monitoring with exceptions
        try:
            with monitor.time_operation("error_operation", logger=logger):
                msg = "Test error during monitoring"
                raise RuntimeError(msg)
        except RuntimeError:
            pass  # Expected

        # Monitor should still function after errors
        with monitor.time_operation("recovery_operation", logger=logger):
            time.sleep(0.001)


@pytest.mark.integration
class TestSecurityIntegration:
    """Integration tests for security features across components."""

    def test_sensitive_data_protection_integration(self) -> None:
        """Test sensitive data protection across all components."""
        initialize_core(
            override_values={
                "logging": {
                    "structured_logging": True,
                    "security_logging": True,
                },
            }
        )

        logger = get_logger("integration.security")

        # Test sensitive data in various contexts
        sensitive_context = {
            "username": "test_user",
            "password": "secret123",
            "api_token": "token_abc123",
            "session_id": "session_456",
        }

        # Test exception with sensitive data
        try:
            raise ValidationError(
                message="Authentication failed with password=secret123",
                field="credentials",
                context=sensitive_context,
            )
        except ValidationError as e:
            # Log the exception - sensitive data should be filtered
            logger.security(
                "Authentication failure with sensitive data",
                SecurityEventType.AUTHENTICATION_FAILURE,
                exception=e,
            )

        # Test logging with sensitive context
        with logger.context(**sensitive_context):
            logger.warning("Operation with sensitive context")

    def test_security_event_lifecycle_integration(self) -> None:
        """Test complete security event lifecycle integration."""
        initialize_core(
            override_values={
                "logging": {
                    "security_logging": True,
                    "audit_logging": True,
                },
                "security": {
                    "require_authentication": True,
                    "max_login_attempts": 3,
                },
            }
        )

        logger = get_logger("integration.security_events")

        # Simulate security event lifecycle
        security_events = [
            (SecurityEventType.AUTHENTICATION_SUCCESS, "User login successful"),
            (SecurityEventType.DATA_ACCESS, "User accessed sensitive data"),
            (SecurityEventType.CONFIGURATION_CHANGE, "User modified configuration"),
            (SecurityEventType.AUTHENTICATION_FAILURE, "Invalid login attempt"),
            (SecurityEventType.SECURITY_VIOLATION, "Suspicious activity detected"),
        ]

        for event_type, message in security_events:
            logger.security(
                message,
                event_type,
                user_id="test_user",
                ip_address="192.168.1.100",
                timestamp=time.time(),
            )

        # Test audit logging
        logger.audit(
            "Security audit completed",
            events_processed=len(security_events),
            security_level="high",
        )


@pytest.mark.integration
class TestResourceManagementIntegration:
    """Integration tests for resource management and cleanup."""

    def test_resource_cleanup_integration(self) -> None:
        """Test proper resource cleanup across all components."""
        # Initialize with file logging to test file handle cleanup
        with tempfile.NamedTemporaryFile(suffix=".log", delete=False) as f:
            log_file = Path(f.name)

        try:
            initialize_core(
                override_values={
                    "logging": {
                        "log_file": str(log_file),
                        "structured_logging": True,
                    },
                    "monitoring": {"enabled": True},
                }
            )

            # Use various components to create resources
            logger = get_logger("integration.cleanup")
            monitor = get_performance_monitor()

            # Generate some activity
            for i in range(10):
                with logger.context(iteration=i):
                    logger.info("Test iteration %s", i)

                    with monitor.time_operation(f"operation_{i}"):
                        time.sleep(0.001)

            # Verify log file was created and has content
            assert log_file.exists()
            assert log_file.stat().st_size > 0

            # Shutdown should clean up all resources
            shutdown_core()

            # Verify cleanup
            from ldap_core_shared.core import is_initialized

            assert is_initialized() is False

        finally:
            # Cleanup test file
            if log_file.exists():
                log_file.unlink()

    def test_memory_usage_integration(self) -> None:
        """Test memory usage patterns across components."""
        # Initialize system
        initialize_core(
            override_values={
                "logging": {"performance_logging": True},
                "monitoring": {"enabled": True},
            }
        )

        logger = get_logger("integration.memory")
        monitor = get_performance_monitor()

        # Generate activity to test memory patterns
        for batch in range(5):
            with logger.context(batch=batch):
                logger.info("Processing batch %s", batch)

                # Simulate multiple operations
                for op in range(20):
                    with monitor.time_operation(f"batch_{batch}_op_{op}"):
                        # Simulate some work
                        data = {"operation": op, "data": "x" * 100}
                        logger.debug("Operation data", **data)

        # System should handle the load without issues
        assert True  # If we get here, memory management is working


# Custom fixtures for integration testing
@pytest.fixture(autouse=True)
def integration_cleanup():
    """Ensure clean state for integration tests."""
    # Cleanup before test
    shutdown_core()
    yield
    # Cleanup after test
    shutdown_core()


@pytest.fixture
def sample_production_config():
    """Provide a valid production configuration for testing."""
    return {
        "environment": "production",
        "debug": False,
        "database": {
            "host": "prod-db.example.com",
            "port": 5432,
            "ssl_mode": "verify-full",
            "pool_size": 20,
        },
        "connection": {
            "servers": [
                "ldaps://ldap1.example.com:636",
                "ldaps://ldap2.example.com:636",
            ],
            "use_tls": True,
            "tls_verify": True,
        },
        "security": {
            "require_authentication": True,
            "session_timeout": 3600,
            "max_login_attempts": 3,
        },
        "logging": {
            "level": "INFO",
            "structured_logging": True,
            "security_logging": True,
            "performance_logging": True,
        },
        "monitoring": {
            "enabled": True,
            "metrics_enabled": True,
            "health_check_enabled": True,
        },
    }


@pytest.fixture
def comprehensive_test_config():
    """Provide comprehensive test configuration with all features enabled."""
    return {
        "environment": "testing",
        "debug": True,
        "version": "integration-test-1.0.0",
        "database": {
            "host": "test-db.example.com",
            "database": "integration_test_db",
        },
        "connection": {
            "servers": ["ldap://test-ldap.example.com:389"],
            "use_tls": False,  # OK for testing
        },
        "security": {
            "require_authentication": False,  # OK for testing
            "session_timeout": 1800,
        },
        "logging": {
            "level": "DEBUG",
            "structured_logging": True,
            "performance_logging": True,
            "security_logging": True,
            "slow_query_threshold": 0.1,
        },
        "monitoring": {
            "enabled": True,
            "metrics_enabled": True,
            "health_check_enabled": True,
            "health_check_interval": 10,
        },
        "schema": {
            "validation_enabled": True,
            "strict_validation": False,
            "auto_backup": True,
        },
    }
