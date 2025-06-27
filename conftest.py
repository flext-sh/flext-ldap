"""Global pytest configuration and fixtures for LDAP Core Shared tests."""

import sys
import tempfile
from collections.abc import Generator
from pathlib import Path
from typing import Any
from unittest.mock import Mock, patch

import pytest

# Add src to Python path for testing
sys.path.insert(0, str(Path(__file__).parent / "src"))

import contextlib

from ldap_core_shared.core.config import ApplicationConfig, ConfigManager
from ldap_core_shared.core.exceptions import LDAPCoreError
from ldap_core_shared.core.logging import LoggerManager


@pytest.fixture(scope="session", autouse=True)
def setup_test_environment() -> Generator[None, None, None]:
    """Setup global test environment."""
    # Ensure clean state for tests
    yield
    # Cleanup after all tests
    with contextlib.suppress(Exception):
        LoggerManager.shutdown()


@pytest.fixture
def temp_dir() -> Generator[Path, None, None]:
    """Create temporary directory for tests."""
    with tempfile.TemporaryDirectory() as temp_dir:
        yield Path(temp_dir)


@pytest.fixture
def sample_config_data() -> dict[str, Any]:
    """Sample configuration data for testing."""
    return {
        "environment": "testing",
        "debug": True,
        "version": "1.0.0-test",
        "name": "Test Application",
        "database": {
            "host": "localhost",
            "port": 5432,
            "database": "test_db",
            "username": "test_user",
            "password": "test_password",
        },
        "connection": {
            "servers": ["ldap://test.example.com:389"],
            "bind_dn": "cn=test,dc=example,dc=com",
            "use_tls": True,
            "pool_size": 5,
        },
        "schema": {
            "base_path": "/tmp/test/schema",
            "backup_path": "/tmp/test/backup",
            "validation_enabled": True,
        },
        "security": {
            "require_authentication": True,
            "session_timeout": 1800,
            "sasl_mechanisms": ["PLAIN", "DIGEST-MD5"],
        },
        "logging": {
            "level": "DEBUG",
            "structured_logging": True,
            "performance_logging": True,
            "console_enabled": True,
        },
        "monitoring": {
            "enabled": True,
            "metrics_enabled": True,
            "health_check_enabled": True,
        },
    }


@pytest.fixture
def application_config(sample_config_data: dict[str, Any]) -> ApplicationConfig:
    """Create ApplicationConfig instance for testing."""
    return ApplicationConfig(**sample_config_data)


@pytest.fixture
def clean_config_manager() -> Generator[None, None, None]:
    """Ensure ConfigManager starts clean for each test."""
    # Reset ConfigManager state
    ConfigManager._instance = None
    yield
    # Cleanup after test
    ConfigManager._instance = None


@pytest.fixture
def clean_logger_manager() -> Generator[None, None, None]:
    """Ensure LoggerManager starts clean for each test."""
    # Shutdown and reset LoggerManager
    with contextlib.suppress(Exception):
        LoggerManager.shutdown()
    LoggerManager._initialized = False
    LoggerManager._loggers = {}
    LoggerManager._performance_monitor = None
    LoggerManager._config = None
    yield
    # Cleanup after test
    with contextlib.suppress(Exception):
        LoggerManager.shutdown()


@pytest.fixture
def mock_file_system(temp_dir: Path):
    """Mock file system operations for testing."""
    # Create test directories
    schema_dir = temp_dir / "schema"
    backup_dir = temp_dir / "backup"
    schema_dir.mkdir(parents=True, exist_ok=True)
    backup_dir.mkdir(parents=True, exist_ok=True)

    # Create sample files
    sample_schema = schema_dir / "test.schema"
    sample_schema.write_text("""
# Test Schema
attributetype ( 1.2.3.4.5.1
    NAME 'testAttribute'
    DESC 'Test attribute for testing'
    SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )

objectclass ( 1.2.3.4.5.2
    NAME 'testClass'
    DESC 'Test object class'
    SUP top
    STRUCTURAL
    MUST ( cn )
    MAY ( testAttribute ) )
""")

    return {
        "temp_dir": temp_dir,
        "schema_dir": schema_dir,
        "backup_dir": backup_dir,
        "sample_schema": sample_schema,
    }


@pytest.fixture
def sample_exception_context() -> dict[str, Any]:
    """Sample exception context for testing."""
    return {
        "operation": "test_operation",
        "resource": "test_resource",
        "user": "test_user",
        "session_id": "test_session_123",
        "timestamp": "2024-01-01T00:00:00Z",
        "additional_data": {
            "test_key": "test_value",
            "numeric_value": 42,
        },
    }


@pytest.fixture
def mock_ldap_connection():
    """Mock LDAP connection for testing."""
    mock_conn = Mock()
    mock_conn.bind.return_value = True
    mock_conn.search.return_value = Mock(success=True, entries=[])
    mock_conn.add.return_value = Mock(success=True)
    mock_conn.modify.return_value = Mock(success=True)
    mock_conn.delete.return_value = Mock(success=True)
    mock_conn.unbind.return_value = None
    return mock_conn


@pytest.fixture
def environment_variables():
    """Mock environment variables for testing."""
    test_env_vars = {
        "LDAP_CORE_ENV": "testing",
        "LDAP_CORE_DEBUG": "true",
        "LDAP_CORE_LOGGING_LEVEL": "DEBUG",
        "LDAP_CORE_CONNECTION_SERVERS": "ldap://test1.example.com,ldap://test2.example.com",
        "LDAP_CORE_SECURITY_REQUIRE_AUTHENTICATION": "true",
    }

    with patch.dict("os.environ", test_env_vars):
        yield test_env_vars


@pytest.fixture
def config_file_yaml(temp_dir: Path) -> Path:
    """Create YAML configuration file for testing."""
    config_content = """
environment: testing
debug: true
version: "1.0.0-test"

database:
  host: localhost
  port: 5432
  database: test_db
  username: test_user
  password: test_password

connection:
  servers:
    - ldap://test.example.com:389
  bind_dn: cn=test,dc=example,dc=com
  use_tls: true
  pool_size: 5

schema:
  base_path: /tmp/test/schema
  backup_path: /tmp/test/backup
  validation_enabled: true

security:
  require_authentication: true
  session_timeout: 1800

logging:
  level: DEBUG
  structured_logging: true
  performance_logging: true

monitoring:
  enabled: true
  metrics_enabled: true
"""

    config_file = temp_dir / "test_config.yaml"
    config_file.write_text(config_content)
    return config_file


@pytest.fixture
def config_file_json(temp_dir: Path) -> Path:
    """Create JSON configuration file for testing."""
    import json

    config_data = {
        "environment": "testing",
        "debug": True,
        "version": "1.0.0-test",
        "database": {
            "host": "localhost",
            "port": 5432,
            "database": "test_db",
        },
        "logging": {
            "level": "DEBUG",
            "structured_logging": True,
        },
    }

    config_file = temp_dir / "test_config.json"
    config_file.write_text(json.dumps(config_data, indent=2))
    return config_file


@pytest.fixture
def performance_test_setup():
    """Setup for performance testing."""
    import time

    def slow_operation(duration: float = 0.1) -> str:
        """Simulate slow operation."""
        time.sleep(duration)
        return "operation_completed"

    def fast_operation() -> str:
        """Simulate fast operation."""
        return "operation_completed"

    return {
        "slow_operation": slow_operation,
        "fast_operation": fast_operation,
    }


# Pytest hooks for custom behavior
def pytest_configure(config: pytest.Config) -> None:
    """Configure pytest with custom settings."""
    # Add custom markers
    config.addinivalue_line(
        "markers",
        "integration: mark test as integration test",
    )
    config.addinivalue_line(
        "markers",
        "slow: mark test as slow running test",
    )


def pytest_collection_modifyitems(
    config: pytest.Config, items: list[pytest.Item]
) -> None:
    """Modify test collection to add markers automatically."""
    for item in items:
        # Add integration marker to integration tests
        if "integration" in str(item.fspath):
            item.add_marker(pytest.mark.integration)

        # Add slow marker to tests with 'slow' in name
        if "slow" in item.name:
            item.add_marker(pytest.mark.slow)


# Custom assertions for LDAP Core testing
class LDAPCoreAssertions:
    """Custom assertions for LDAP Core testing."""

    @staticmethod
    def assert_valid_exception(exception: LDAPCoreError) -> None:
        """Assert exception has required attributes."""
        assert hasattr(exception, "error_code")
        assert hasattr(exception, "severity")
        assert hasattr(exception, "category")
        assert hasattr(exception, "context")
        assert exception.error_code is not None
        assert exception.severity is not None
        assert exception.category is not None

    @staticmethod
    def assert_config_valid(config: ApplicationConfig) -> None:
        """Assert configuration is valid."""
        assert config.environment is not None
        assert config.name is not None
        assert config.version is not None
        assert config.database is not None
        assert config.connection is not None
        assert config.schema is not None
        assert config.security is not None
        assert config.logging is not None
        assert config.monitoring is not None


@pytest.fixture
def ldap_assertions():
    """Provide custom LDAP Core assertions."""
    return LDAPCoreAssertions()
