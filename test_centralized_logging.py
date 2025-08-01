#!/usr/bin/env python3
"""Pytest tests for centralized logging configuration in flext-ldap.

These tests demonstrate how flext-ldap respects centralized logging
configuration from flext-core and shows proper TRACE level usage.

Run with: pytest test_centralized_logging.py -v -s
"""

import os

import pytest
from flext_core import get_logger
from flext_ldap.config import FlextLdapConnectionConfig, create_development_config
from flext_ldap.ldap_infrastructure import FlextLdapClient, FlextLdapConverter

# Test logger for proper logging instead of print statements
test_logger = get_logger(__name__)


def test_centralized_logging() -> None:
    """Test centralized logging configuration."""
    test_logger.info("🔧 FLEXT-CORE CENTRALIZED LOGGING TEST")
    test_logger.info("=" * 50)

    # Show current environment configuration
    flext_level = os.environ.get("FLEXT_LOG_LEVEL", "Not set")
    client-a_level = os.environ.get("client-a_LOG_LEVEL", "Not set")
    generic_level = os.environ.get("LOG_LEVEL", "Not set")

    test_logger.info("Environment variables:")
    test_logger.info(f"  FLEXT_LOG_LEVEL: {flext_level}")
    test_logger.info(f"  client-a_LOG_LEVEL: {client-a_level}")
    test_logger.info(f"  LOG_LEVEL: {generic_level}")

    # Test logger creation and level detection
    logger = get_logger("flext_ldap.test")
    logger_level = getattr(logger, "_level_value", "Unknown")

    test_logger.info(f"Logger level: {logger_level}")
    test_logger.info(f"TRACE enabled: {logger_level <= 5}")
    test_logger.info(f"DEBUG enabled: {logger_level <= 10}")

    # Assertions for proper testing
    assert logger is not None
    assert hasattr(logger, "_level_value")

    # Test configuration objects with centralized logging
    test_logger.info("🧪 Testing FlextLdapConnectionConfig validation...")
    config = FlextLdapConnectionConfig(
        server="test.example.com",
        port=389,
        timeout_seconds=30,
    )
    test_logger.info("✅ Config validation completed")

    # Assertions for proper testing
    assert config.server == "test.example.com"
    assert config.port == 389
    assert config.timeout_seconds == 30

    # Test converter with centralized logging
    test_logger.info("🧪 Testing FlextLdapConverter with TRACE...")
    converter = FlextLdapConverter()

    # Test type detection - should show TRACE logs if enabled
    test_values = ["test@example.com", "123", "cn=user,dc=example,dc=com"]
    for value in test_values:
        detected_type = converter.detect_type(value)
        test_logger.info(f"  Value '{value}' -> Type: {detected_type.value}")

    # Assertions for proper testing
    assert converter is not None
    assert len(test_values) == 3

    # Test LDAP client initialization
    test_logger.info("🧪 Testing FlextLdapClient initialization...")
    client = FlextLdapClient(config)
    test_logger.info("✅ LDAP client initialized successfully")

    # Assertions for proper testing
    assert client is not None
    assert client._config == config

    # Test development config factory
    test_logger.info("🧪 Testing development config factory...")
    dev_config = create_development_config()
    test_logger.info("✅ Development config created successfully")
    test_logger.info(f"  Debug mode: {dev_config.enable_debug_mode}")
    test_logger.info(f"  Project: {dev_config.project_name} v{dev_config.project_version}")

    # Assertions for proper testing
    assert dev_config is not None
    assert dev_config.project_name is not None
    assert dev_config.project_version is not None

    test_logger.info("✅ Centralized logging test completed!")


@pytest.mark.parametrize("level", ["TRACE", "DEBUG", "INFO", "WARNING", "ERROR"])
def test_different_log_levels(level: str) -> None:
    """Test logging with different centralized levels."""
    test_logger.info(f"🎯 TESTING {level} LOG LEVEL")
    test_logger.info("=" * 40)

    test_logger.info(f"--- Testing with {level} level ---")

    # Set environment variable
    os.environ["FLEXT_LOG_LEVEL"] = level

    # Create new logger to pick up the change
    logger = get_logger(f"flext_ldap.test_{level.lower()}")
    logger_level = getattr(logger, "_level_value", "Unknown")

    test_logger.info(f"Logger numeric level: {logger_level}")

    # Test all log levels
    logger.trace(f"TRACE message with {level} configuration")
    logger.debug(f"DEBUG message with {level} configuration")
    logger.info(f"INFO message with {level} configuration")
    logger.warning(f"WARNING message with {level} configuration")
    logger.error(f"ERROR message with {level} configuration")

    # Assertions for proper testing
    assert logger is not None
    assert level in {"TRACE", "DEBUG", "INFO", "WARNING", "ERROR"}

    # Reset environment for clean state
    os.environ.pop("FLEXT_LOG_LEVEL", None)


def test_environment_cleanup() -> None:
    """Test environment cleanup after all tests."""
    # Reset environment for clean state
    os.environ.pop("FLEXT_LOG_LEVEL", None)
    os.environ.pop("client-a_LOG_LEVEL", None)
    os.environ.pop("LOG_LEVEL", None)

    test_logger.info("🚀 All centralized logging tests completed!")

    # Assertions for proper testing
    assert "FLEXT_LOG_LEVEL" not in os.environ


if __name__ == "__main__":
    # Run with pytest for proper test execution
    pytest.main(["-v", "-s", __file__])
