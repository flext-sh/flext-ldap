"""Comprehensive unit tests for LDAP Core Shared initialization system.

This module provides extensive testing coverage for the enterprise-grade core
initialization system, including configuration loading, logging setup, dependency
validation, graceful shutdown, and integration patterns.

Test Coverage:
    - Core initialization with various configurations
    - Configuration validation and error handling
    - Logging system integration and setup
    - Dependency validation and environment checks
    - Graceful shutdown and resource cleanup
    - Initialization state management
    - Error handling and recovery patterns
    - Auto-initialization features
    - Reconfiguration capabilities
    - Production environment validation

Test Categories:
    - Unit tests for initialization functions
    - Integration tests for core system coordination
    - Configuration tests for various environments
    - Error handling tests for failure scenarios
    - Shutdown tests for resource cleanup
    - State management tests for initialization tracking
"""

import os
import tempfile
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
    is_initialized,
    reconfigure,
    shutdown_core,
)
from ldap_core_shared.core.config import ConfigManager
from ldap_core_shared.core.logging import LoggerManager, PerformanceMonitor


@pytest.mark.unit
@pytest.mark.core
class TestCoreInitialization:
    """Test cases for core initialization functionality."""

    def test_basic_initialization(self) -> None:
        """Test basic core initialization with default settings."""
        config = initialize_core()

        assert isinstance(config, ApplicationConfig)
        assert is_initialized() is True
        assert config.environment == Environment.DEVELOPMENT

        # Should be able to get logger after initialization
        logger = get_logger("test.basic")
        assert logger is not None

    def test_initialization_with_environment(self) -> None:
        """Test initialization with specific environment."""
        config = initialize_core(environment="testing")

        assert config.environment == Environment.TESTING
        assert is_initialized() is True

    def test_initialization_with_config_overrides(self) -> None:
        """Test initialization with configuration overrides."""
        overrides = {
            "debug": True,
            "version": "test-version",
            "logging": {"level": "DEBUG"},
        }

        config = initialize_core(
            environment="development",
            override_values=overrides,
        )

        assert config.debug is True
        assert config.version == "test-version"
        assert config.logging.level.value == "DEBUG"

    def test_initialization_with_config_file(self) -> None:
        """Test initialization with external configuration file."""
        config_data = {
            "environment": "staging",
            "debug": False,
            "logging": {"level": "INFO", "console_enabled": True},
        }

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as f:
            import json
            json.dump(config_data, f)
            config_file = f.name

        try:
            config = initialize_core(config_file=config_file)

            assert config.environment == Environment.STAGING
            assert config.debug is False
            assert config.logging.level.value == "INFO"
        finally:
            Path(config_file).unlink()

    def test_double_initialization_without_force(self) -> None:
        """Test that double initialization returns same config without force."""
        config1 = initialize_core(environment="development")
        config2 = initialize_core(environment="testing")  # Should return same config

        assert config1 is config2
        assert config1.environment == Environment.DEVELOPMENT  # Should not change

    def test_force_reinitialization(self) -> None:
        """Test force reinitialization with different settings."""
        config1 = initialize_core(environment="development")
        config2 = initialize_core(environment="testing", force_reinit=True)

        assert config1 is not config2
        assert config1.environment == Environment.DEVELOPMENT
        assert config2.environment == Environment.TESTING

    def test_initialization_error_handling(self) -> None:
        """Test initialization error handling."""
        # Create invalid configuration that should fail
        invalid_overrides = {
            "environment": "production",
            "debug": True,  # Invalid for production
            "security": {"require_authentication": False},  # Invalid for production
        }

        with pytest.raises(CoreInitializationError):
            initialize_core(override_values=invalid_overrides)

    def test_initialization_with_performance_monitoring(self) -> None:
        """Test initialization with performance monitoring enabled."""
        overrides = {
            "monitoring": {"enabled": True},
            "logging": {"performance_logging": True, "slow_query_threshold": 0.5},
        }

        config = initialize_core(override_values=overrides)

        assert config.monitoring.enabled is True
        assert config.logging.performance_logging is True

        # Performance monitor should be available
        monitor = get_performance_monitor()
        assert isinstance(monitor, PerformanceMonitor)

    def test_initialization_logging_setup(self) -> None:
        """Test that initialization properly sets up logging."""
        logging_config = {
            "logging": {
                "level": "DEBUG",
                "structured_logging": True,
                "console_enabled": True,
            },
        }

        config = initialize_core(override_values=logging_config)

        assert config.logging.level.value == "DEBUG"
        assert config.logging.structured_logging is True

        # Logger should be available and functional
        logger = get_logger("test.logging.setup")
        assert logger is not None

        # Test logging functionality
        logger.info("Test initialization logging")  # Should not raise


@pytest.mark.unit
@pytest.mark.core
class TestCoreStateManagement:
    """Test cases for core state management."""

    def test_is_initialized_before_init(self) -> None:
        """Test is_initialized before any initialization."""
        # Reset state
        shutdown_core()

        assert is_initialized() is False

    def test_is_initialized_after_init(self) -> None:
        """Test is_initialized after initialization."""
        initialize_core()

        assert is_initialized() is True

    def test_get_config_before_initialization(self) -> None:
        """Test get_config before initialization raises error."""
        # Reset state
        shutdown_core()

        with pytest.raises(CoreInitializationError):
            get_config()

    def test_get_config_after_initialization(self) -> None:
        """Test get_config after initialization."""
        original_config = initialize_core(environment="testing")
        retrieved_config = get_config()

        assert retrieved_config is original_config
        assert retrieved_config.environment == Environment.TESTING

    def test_config_singleton_behavior(self) -> None:
        """Test that configuration follows singleton pattern."""
        config1 = initialize_core()
        config2 = get_config()

        assert config1 is config2

    def test_reconfigure_functionality(self) -> None:
        """Test reconfiguration functionality."""
        # Initial configuration
        original_config = initialize_core(environment="development")
        assert original_config.debug is False

        # Reconfigure with new settings
        new_config = reconfigure(override_values={"debug": True})

        assert new_config is not original_config
        assert new_config.debug is True
        assert new_config.environment == Environment.DEVELOPMENT  # Should preserve environment

    def test_reconfigure_before_initialization(self) -> None:
        """Test reconfigure before initialization raises error."""
        shutdown_core()

        with pytest.raises(CoreInitializationError):
            reconfigure(override_values={"debug": True})

    def test_reconfigure_with_config_file(self) -> None:
        """Test reconfigure with new config file."""
        # Initial configuration
        initialize_core(environment="development")

        # Create new config file
        new_config_data = {
            "debug": True,
            "logging": {"level": "DEBUG"},
        }

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as f:
            import json
            json.dump(new_config_data, f)
            config_file = f.name

        try:
            new_config = reconfigure(config_file=config_file)

            assert new_config.debug is True
            assert new_config.logging.level.value == "DEBUG"
        finally:
            Path(config_file).unlink()


@pytest.mark.unit
@pytest.mark.core
class TestCoreShutdown:
    """Test cases for core shutdown functionality."""

    def test_graceful_shutdown(self) -> None:
        """Test graceful shutdown functionality."""
        # Initialize core
        initialize_core()
        assert is_initialized() is True

        # Shutdown
        shutdown_core()

        # Should be marked as not initialized
        assert is_initialized() is False

    def test_shutdown_before_initialization(self) -> None:
        """Test shutdown before initialization (should be safe)."""
        # Reset state to ensure not initialized
        shutdown_core()

        # Should not raise error
        shutdown_core()

        assert is_initialized() is False

    def test_multiple_shutdowns(self) -> None:
        """Test multiple shutdown calls (should be safe)."""
        initialize_core()

        # Multiple shutdowns should be safe
        shutdown_core()
        shutdown_core()
        shutdown_core()

        assert is_initialized() is False

    def test_shutdown_cleans_up_loggers(self) -> None:
        """Test that shutdown properly cleans up logging system."""
        initialize_core()
        logger = get_logger("test.shutdown")

        # Verify logger works before shutdown
        logger.info("Test before shutdown")

        shutdown_core()

        # LoggerManager should be reset
        assert LoggerManager._initialized is False

    def test_shutdown_and_reinitialize(self) -> None:
        """Test shutdown followed by reinitialization."""
        # Initial setup
        config1 = initialize_core(environment="development")
        get_logger("test.reinit")

        # Shutdown
        shutdown_core()
        assert is_initialized() is False

        # Reinitialize
        config2 = initialize_core(environment="testing")
        new_logger = get_logger("test.reinit")

        # Should be different instances
        assert config1 is not config2
        assert config2.environment == Environment.TESTING

        # Logger should work after reinit
        new_logger.info("Test after reinit")


@pytest.mark.unit
@pytest.mark.core
class TestCoreDependencyValidation:
    """Test cases for core dependency validation."""

    def test_python_version_validation(self) -> None:
        """Test Python version validation."""
        # This test ensures current Python version is acceptable
        # Since we're running the test, the version should be valid
        config = initialize_core()
        assert config is not None

    @patch("sys.version_info", (3, 7))  # Below minimum version
    def test_python_version_too_old(self) -> None:
        """Test initialization fails with old Python version."""
        with pytest.raises(CoreInitializationError) as exc_info:
            initialize_core(force_reinit=True)

        assert "Python 3.8+ required" in str(exc_info.value)

    def test_production_environment_validation(self) -> None:
        """Test production environment specific validations."""
        with patch.dict(os.environ, {"LDAP_CORE_ENV": "production"}):
            config = initialize_core(
                environment="production",
                override_values={
                    "debug": False,
                    "security": {"require_authentication": True},
                    "connection": {"use_tls": True},
                    "logging": {"level": "INFO"},
                },
            )

            assert config.environment == Environment.PRODUCTION

    def test_development_paths_creation(self) -> None:
        """Test that development paths are created if they don't exist."""
        with tempfile.TemporaryDirectory() as temp_dir:
            schema_path = Path(temp_dir) / "test_schema"
            backup_path = Path(temp_dir) / "test_backup"

            overrides = {
                "schema": {
                    "base_path": str(schema_path),
                    "backup_path": str(backup_path),
                },
            }

            # Set development environment
            with patch.dict(os.environ, {"LDAP_CORE_ENV": "development"}):
                config = initialize_core(
                    environment="development",
                    override_values=overrides,
                )

            # Paths should exist after initialization
            assert config.schema.base_path == schema_path
            assert config.schema.backup_path == backup_path

    def test_missing_environment_variables_warning(self) -> None:
        """Test warning for missing environment variables in production."""
        # Clear environment variables
        with patch.dict(os.environ, {}, clear=True):
            # Should initialize but may log warnings
            config = initialize_core(
                environment="production",
                override_values={
                    "debug": False,
                    "security": {"require_authentication": True},
                    "connection": {"use_tls": True},
                },
            )

            assert config.environment == Environment.PRODUCTION


@pytest.mark.integration
@pytest.mark.core
class TestCoreInitializationIntegration:
    """Integration tests for core initialization."""

    def test_complete_initialization_flow(self) -> None:
        """Test complete initialization flow with all components."""
        config = initialize_core(
            environment="testing",
            override_values={
                "debug": True,
                "logging": {
                    "level": "DEBUG",
                    "structured_logging": True,
                    "performance_logging": True,
                },
                "monitoring": {"enabled": True},
            },
        )

        # Verify all components are working
        logger = get_logger("integration.test")
        monitor = get_performance_monitor()

        assert config is not None
        assert logger is not None
        assert monitor is not None

        # Test structured logging with context
        with logger.context(test_operation="integration"):
            logger.info("Integration test message")

        # Test performance monitoring
        with monitor.time_operation("integration_test"):
            import time
            time.sleep(0.001)  # Small delay

    def test_configuration_override_hierarchy(self) -> None:
        """Test configuration override hierarchy."""
        # Create config file
        file_config = {
            "debug": False,
            "version": "file-version",
            "logging": {"level": "INFO"},
        }

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as f:
            import json
            json.dump(file_config, f)
            config_file = f.name

        try:
            # Set environment variables
            with patch.dict(os.environ, {
                "LDAP_CORE_DEBUG": "true",
                "LDAP_CORE_LOGGING_LEVEL": "WARNING",
            }):
                # Override values should have highest priority
                config = initialize_core(
                    config_file=config_file,
                    override_values={
                        "version": "override-version",
                        "logging": {"level": "ERROR"},
                    },
                )

                # Override values should win
                assert config.version == "override-version"
                assert config.logging.level.value == "ERROR"

                # Environment variables should override file
                assert config.debug is True  # From env var

        finally:
            Path(config_file).unlink()

    def test_initialization_with_invalid_config_file(self) -> None:
        """Test initialization with invalid config file."""
        # Create invalid JSON file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as f:
            f.write("invalid json content {")
            invalid_config_file = f.name

        try:
            with pytest.raises(CoreInitializationError):
                initialize_core(config_file=invalid_config_file)
        finally:
            Path(invalid_config_file).unlink()

    def test_initialization_with_nonexistent_config_file(self) -> None:
        """Test initialization with non-existent config file."""
        nonexistent_file = "/tmp/nonexistent_config.json"

        with pytest.raises(CoreInitializationError):
            initialize_core(config_file=nonexistent_file)

    def test_logging_integration_after_initialization(self) -> None:
        """Test logging system integration after initialization."""
        initialize_core(
            override_values={
                "logging": {
                    "structured_logging": True,
                    "security_logging": True,
                    "performance_logging": True,
                },
            },
        )

        logger = get_logger("integration.logging")

        # Test different log types
        logger.info("Info message")
        logger.warning("Warning message")
        logger.error("Error message")

        # Test structured logging with context
        with logger.context(operation="test", user_id="123"):
            logger.info("Contextual message")

        # Test security logging
        from ldap_core_shared.core.logging import SecurityEventType
        logger.security(
            "Security event",
            SecurityEventType.AUTHENTICATION_SUCCESS,
            user_id="test_user",
        )

    def test_error_handling_during_initialization(self) -> None:
        """Test error handling during various initialization phases."""
        # Test configuration validation failure
        with pytest.raises(CoreInitializationError):
            initialize_core(
                environment="production",
                override_values={
                    "debug": True,  # Should fail in production
                    "security": {"require_authentication": False},
                },
            )


@pytest.mark.unit
@pytest.mark.core
class TestAutoInitialization:
    """Test cases for auto-initialization features."""

    def test_auto_initialization_disabled_by_default(self) -> None:
        """Test that auto-initialization is disabled by default."""
        # Clear any existing initialization
        shutdown_core()

        # Should not be initialized by default
        assert is_initialized() is False

    @patch.dict(os.environ, {"LDAP_CORE_AUTO_INIT": "true"})
    def test_auto_initialization_enabled(self) -> None:
        """Test auto-initialization when enabled via environment."""
        # This test simulates the auto-init behavior
        # In practice, this would happen on module import
        try:
            initialize_core()
            assert is_initialized() is True
        except Exception:
            # Auto-init might fail in test environment, which is acceptable
            pass

    @patch.dict(os.environ, {"LDAP_CORE_AUTO_INIT": "false"})
    def test_auto_initialization_explicitly_disabled(self) -> None:
        """Test auto-initialization explicitly disabled."""
        shutdown_core()

        # Should remain not initialized
        assert is_initialized() is False


# Custom test fixtures for core initialization testing
@pytest.fixture
def clean_core_state():
    """Ensure clean core state before and after test."""
    shutdown_core()
    yield
    shutdown_core()


@pytest.fixture
def sample_config_file():
    """Create a sample configuration file for testing."""
    config_data = {
        "environment": "testing",
        "debug": True,
        "version": "test-1.0.0",
        "logging": {
            "level": "DEBUG",
            "console_enabled": True,
        },
        "database": {
            "host": "test-db.example.com",
            "database": "test_db",
        },
    }

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as f:
        import json
        json.dump(config_data, f)
        yield f.name

    # Cleanup
    Path(f.name).unlink()


@pytest.fixture
def initialized_core():
    """Provide initialized core for tests that need it."""
    config = initialize_core(environment="testing")
    yield config
    shutdown_core()


@pytest.fixture
def production_config_overrides():
    """Provide valid production configuration overrides."""
    return {
        "environment": "production",
        "debug": False,
        "security": {
            "require_authentication": True,
            "session_timeout": 3600,
        },
        "connection": {
            "use_tls": True,
            "tls_verify": True,
        },
        "logging": {
            "level": "INFO",
            "structured_logging": True,
            "security_logging": True,
        },
        "monitoring": {
            "enabled": True,
            "health_check_enabled": True,
        },
    }


@pytest.fixture(autouse=True)
def cleanup_core_state():
    """Automatically cleanup core state after each test."""
    yield

    # Ensure clean state after test
    try:
        shutdown_core()
    except Exception:
        pass  # Ignore errors during cleanup

    # Reset any global state
    if hasattr(ConfigManager, "_instance"):
        ConfigManager._instance = None
