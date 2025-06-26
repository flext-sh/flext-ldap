"""Comprehensive unit tests for LDAP Core Shared configuration management.

This module provides extensive testing coverage for the enterprise-grade configuration
management system, including hierarchical loading, validation, environment-specific
configurations, security features, and integration patterns.

Test Coverage:
    - Configuration model validation and type safety
    - Hierarchical configuration loading (files, env vars, overrides)
    - Environment-specific configuration behavior
    - Configuration validation and error handling
    - Security configuration features
    - Database and LDAP connection configuration
    - Schema management configuration
    - Logging and monitoring configuration
    - Configuration file format support (YAML, JSON)
    - Environment variable parsing and conversion
    - Configuration template generation
    - Cross-validation rules and business logic

Test Categories:
    - Unit tests for individual configuration classes
    - Integration tests for ConfigManager functionality
    - Security tests for sensitive data handling
    - Validation tests for configuration rules
    - File format tests for YAML/JSON loading
    - Environment variable tests for parsing
    - Template generation tests
"""

import json
import os
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

from ldap_core_shared.core.config import (
    ApplicationConfig,
    ConfigManager,
    ConnectionStrategy,
    DatabaseConfig,
    Environment,
    LDAPConnectionConfig,
    LoggingConfig,
    LogLevel,
    MonitoringConfig,
    SchemaConfig,
    SecurityConfig,
)
from ldap_core_shared.core.exceptions import ConfigurationValidationError


@pytest.mark.unit
@pytest.mark.config
class TestBaseConfiguration:
    """Test cases for base configuration functionality."""

    def test_default_configuration_creation(self) -> None:
        """Test creating configuration with default values."""
        config = ApplicationConfig()

        assert config.environment == Environment.DEVELOPMENT
        assert config.debug is False
        assert config.version == "1.0.0"
        assert config.name == "LDAP Core Shared"
        assert config.description == "Enterprise LDAP Core Library"

    def test_configuration_model_validation(self) -> None:
        """Test Pydantic model validation for configuration."""
        # Valid configuration should work
        config = ApplicationConfig(
            environment=Environment.PRODUCTION,
            debug=True,
            version="2.0.0",
        )

        assert config.environment == Environment.PRODUCTION
        assert config.debug is True
        assert config.version == "2.0.0"

    def test_configuration_immutability_settings(self) -> None:
        """Test configuration model settings for validation."""
        ApplicationConfig()

        # Test that extra fields are forbidden
        with pytest.raises(ValueError):
            ApplicationConfig(invalid_field="should_fail")

    def test_environment_enum_values(self) -> None:
        """Test Environment enumeration values."""
        assert Environment.DEVELOPMENT.value == "development"
        assert Environment.TESTING.value == "testing"
        assert Environment.STAGING.value == "staging"
        assert Environment.PRODUCTION.value == "production"


@pytest.mark.unit
@pytest.mark.config
class TestDatabaseConfig:
    """Test cases for database configuration."""

    def test_default_database_config(self) -> None:
        """Test default database configuration values."""
        config = DatabaseConfig()

        assert config.host == "localhost"
        assert config.port == 5432
        assert config.database == "ldap_core"
        assert config.username == "ldap_user"
        assert config.ssl_mode == "require"
        assert config.pool_size == 10
        assert config.max_overflow == 20
        assert config.pool_timeout == 30.0

    def test_database_config_validation(self) -> None:
        """Test database configuration validation."""
        # Valid configuration
        config = DatabaseConfig(
            host="db.example.com",
            port=5433,
            database="custom_db",
            username="custom_user",
            ssl_mode="verify-full",
            pool_size=20,
            max_overflow=40,
            pool_timeout=60.0,
        )

        assert config.host == "db.example.com"
        assert config.port == 5433
        assert config.ssl_mode == "verify-full"

    def test_database_port_validation(self) -> None:
        """Test database port range validation."""
        # Valid port
        config = DatabaseConfig(port=5432)
        assert config.port == 5432

        # Invalid ports should raise validation error
        with pytest.raises(ValueError):
            DatabaseConfig(port=0)

        with pytest.raises(ValueError):
            DatabaseConfig(port=65536)

    def test_ssl_mode_validation(self) -> None:
        """Test SSL mode validation."""
        valid_modes = ["disable", "allow", "prefer", "require", "verify-ca", "verify-full"]

        for mode in valid_modes:
            config = DatabaseConfig(ssl_mode=mode)
            assert config.ssl_mode == mode

        # Invalid SSL mode should raise validation error
        with pytest.raises(ValueError):
            DatabaseConfig(ssl_mode="invalid_mode")

    def test_connection_url_generation(self) -> None:
        """Test database connection URL generation."""
        config = DatabaseConfig(
            host="example.com",
            port=5432,
            database="testdb",
            username="testuser",
            ssl_mode="require",
        )

        # Without password
        url = config.get_connection_url(include_password=False)
        expected = "postgresql://testuser@example.com:5432/testdb?sslmode=require"
        assert url == expected

        # With password
        config.password = "testpass"
        url_with_password = config.get_connection_url(include_password=True)
        expected_with_password = "postgresql://testuser:testpass@example.com:5432/testdb?sslmode=require"
        assert url_with_password == expected_with_password

    def test_pool_configuration_validation(self) -> None:
        """Test connection pool configuration validation."""
        # Valid pool configuration
        config = DatabaseConfig(
            pool_size=5,
            max_overflow=10,
            pool_timeout=15.0,
        )

        assert config.pool_size == 5
        assert config.max_overflow == 10
        assert config.pool_timeout == 15.0

        # Test pool size limits
        with pytest.raises(ValueError):
            DatabaseConfig(pool_size=0)

        with pytest.raises(ValueError):
            DatabaseConfig(pool_size=101)


@pytest.mark.unit
@pytest.mark.config
class TestLDAPConnectionConfig:
    """Test cases for LDAP connection configuration."""

    def test_default_ldap_config(self) -> None:
        """Test default LDAP configuration values."""
        config = LDAPConnectionConfig()

        assert config.servers == ["ldap://localhost:389"]
        assert config.bind_dn is None
        assert config.bind_password is None
        assert config.use_tls is False
        assert config.tls_verify is True
        assert config.strategy == ConnectionStrategy.SAFE_SYNC
        assert config.pool_size == 10
        assert config.max_pool_size == 50
        assert config.connection_timeout == 30.0
        assert config.max_retries == 3
        assert config.auto_failover is True

    def test_ldap_server_validation(self) -> None:
        """Test LDAP server URI validation."""
        # Valid server URIs
        valid_servers = [
            "ldap://server1.example.com:389",
            "ldaps://server2.example.com:636",
            "ldapi:///var/run/ldapi",
        ]

        config = LDAPConnectionConfig(servers=valid_servers)
        assert config.servers == valid_servers

        # Invalid server URIs should raise validation error
        with pytest.raises(ValueError):
            LDAPConnectionConfig(servers=["http://invalid.com"])

        with pytest.raises(ValueError):
            LDAPConnectionConfig(servers=["ftp://invalid.com"])

        # Empty server list should raise validation error
        with pytest.raises(ValueError):
            LDAPConnectionConfig(servers=[])

    def test_connection_strategy_enum(self) -> None:
        """Test connection strategy enumeration."""
        assert ConnectionStrategy.SYNC.value == "sync"
        assert ConnectionStrategy.SAFE_SYNC.value == "safe_sync"
        assert ConnectionStrategy.SAFE_RESTARTABLE.value == "safe_restartable"
        assert ConnectionStrategy.ASYNC.value == "async"
        assert ConnectionStrategy.POOLED.value == "pooled"

    def test_pool_size_validation(self) -> None:
        """Test LDAP connection pool size validation."""
        # Valid pool configuration
        config = LDAPConnectionConfig(
            pool_size=5,
            max_pool_size=15,
        )

        assert config.pool_size == 5
        assert config.max_pool_size == 15

        # max_pool_size must be >= pool_size
        with pytest.raises(ValueError):
            LDAPConnectionConfig(pool_size=20, max_pool_size=10)

    def test_timeout_validation(self) -> None:
        """Test timeout configuration validation."""
        config = LDAPConnectionConfig(
            connection_timeout=45.0,
            response_timeout=60.0,
            pool_timeout=30.0,
            failover_timeout=120.0,
        )

        assert config.connection_timeout == 45.0
        assert config.response_timeout == 60.0
        assert config.pool_timeout == 30.0
        assert config.failover_timeout == 120.0

        # Test timeout limits
        with pytest.raises(ValueError):
            LDAPConnectionConfig(connection_timeout=0.5)  # Below minimum


@pytest.mark.unit
@pytest.mark.config
class TestSchemaConfig:
    """Test cases for schema configuration."""

    def test_default_schema_config(self) -> None:
        """Test default schema configuration values."""
        config = SchemaConfig()

        assert config.base_path == Path("/etc/ldap/schema")
        assert config.backup_path == Path("/var/backups/ldap/schemas")
        assert config.temp_path == Path("/tmp/ldap-schemas")
        assert config.validation_enabled is True
        assert config.strict_validation is False
        assert config.check_dependencies is True
        assert config.auto_backup is True
        assert config.supported_formats == [".schema", ".ldif"]
        assert config.default_encoding == "utf-8"

    def test_schema_path_handling(self) -> None:
        """Test schema path validation and creation."""
        with tempfile.TemporaryDirectory() as tmpdir:
            base_path = Path(tmpdir) / "schema"
            backup_path = Path(tmpdir) / "backup"

            config = SchemaConfig(
                base_path=base_path,
                backup_path=backup_path,
            )

            # Paths should be converted to Path objects
            assert isinstance(config.base_path, Path)
            assert isinstance(config.backup_path, Path)

    def test_schema_validation_settings(self) -> None:
        """Test schema validation configuration options."""
        config = SchemaConfig(
            validation_enabled=True,
            strict_validation=True,
            check_dependencies=True,
            check_conflicts=True,
            allow_obsolete=False,
        )

        assert config.validation_enabled is True
        assert config.strict_validation is True
        assert config.check_dependencies is True
        assert config.check_conflicts is True
        assert config.allow_obsolete is False

    def test_schema_operation_settings(self) -> None:
        """Test schema operation configuration."""
        config = SchemaConfig(
            auto_backup=False,
            require_confirmation=False,
            dry_run_default=True,
        )

        assert config.auto_backup is False
        assert config.require_confirmation is False
        assert config.dry_run_default is True


@pytest.mark.unit
@pytest.mark.config
class TestSecurityConfig:
    """Test cases for security configuration."""

    def test_default_security_config(self) -> None:
        """Test default security configuration values."""
        config = SecurityConfig()

        assert config.require_authentication is True
        assert config.session_timeout == 3600
        assert config.max_login_attempts == 3
        assert config.lockout_duration == 300
        assert config.sasl_mechanisms == ["PLAIN", "DIGEST-MD5"]
        assert config.sasl_security_layer is True
        assert config.tls_protocols == ["TLSv1.2", "TLSv1.3"]

    def test_authentication_settings(self) -> None:
        """Test authentication configuration settings."""
        config = SecurityConfig(
            require_authentication=False,
            session_timeout=7200,
            max_login_attempts=5,
            lockout_duration=600,
        )

        assert config.require_authentication is False
        assert config.session_timeout == 7200
        assert config.max_login_attempts == 5
        assert config.lockout_duration == 600

    def test_sasl_mechanism_validation(self) -> None:
        """Test SASL mechanism validation."""
        valid_mechanisms = ["PLAIN", "LOGIN", "DIGEST-MD5", "CRAM-MD5", "EXTERNAL", "GSSAPI"]

        config = SecurityConfig(sasl_mechanisms=valid_mechanisms)
        assert config.sasl_mechanisms == valid_mechanisms

        # Invalid SASL mechanism should raise validation error
        with pytest.raises(ValueError):
            SecurityConfig(sasl_mechanisms=["INVALID_MECHANISM"])

    def test_security_timeout_validation(self) -> None:
        """Test security timeout validation."""
        # Valid timeouts
        config = SecurityConfig(
            session_timeout=1800,  # 30 minutes
            lockout_duration=900,   # 15 minutes
        )

        assert config.session_timeout == 1800
        assert config.lockout_duration == 900

        # Test timeout limits
        with pytest.raises(ValueError):
            SecurityConfig(session_timeout=30)  # Below minimum

        with pytest.raises(ValueError):
            SecurityConfig(session_timeout=86401)  # Above maximum

    def test_tls_configuration(self) -> None:
        """Test TLS configuration settings."""
        config = SecurityConfig(
            tls_protocols=["TLSv1.2", "TLSv1.3"],
            tls_ciphers="HIGH:!aNULL:!MD5",
        )

        assert config.tls_protocols == ["TLSv1.2", "TLSv1.3"]
        assert config.tls_ciphers == "HIGH:!aNULL:!MD5"


@pytest.mark.unit
@pytest.mark.config
class TestLoggingConfig:
    """Test cases for logging configuration."""

    def test_default_logging_config(self) -> None:
        """Test default logging configuration values."""
        config = LoggingConfig()

        assert config.level == LogLevel.INFO
        assert config.format == "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        assert config.log_file is None
        assert config.max_file_size == 10 * 1024 * 1024  # 10MB
        assert config.backup_count == 5
        assert config.console_enabled is True
        assert config.console_color is True
        assert config.structured_logging is False
        assert config.performance_logging is False
        assert config.security_logging is True

    def test_log_level_configuration(self) -> None:
        """Test log level configuration."""
        config = LoggingConfig(level=LogLevel.DEBUG)
        assert config.level == LogLevel.DEBUG

        config = LoggingConfig(level=LogLevel.ERROR)
        assert config.level == LogLevel.ERROR

    def test_file_logging_configuration(self) -> None:
        """Test file logging configuration."""
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            log_file = Path(tmp.name)

        config = LoggingConfig(
            log_file=log_file,
            max_file_size=20 * 1024 * 1024,  # 20MB
            backup_count=10,
        )

        assert config.log_file == log_file
        assert config.max_file_size == 20 * 1024 * 1024
        assert config.backup_count == 10

        # Cleanup
        log_file.unlink()

    def test_structured_logging_options(self) -> None:
        """Test structured logging configuration."""
        config = LoggingConfig(
            structured_logging=True,
            include_caller=True,
            performance_logging=True,
            slow_query_threshold=0.5,
        )

        assert config.structured_logging is True
        assert config.include_caller is True
        assert config.performance_logging is True
        assert config.slow_query_threshold == 0.5

    def test_logging_validation(self) -> None:
        """Test logging configuration validation."""
        # Test file size limits
        with pytest.raises(ValueError):
            LoggingConfig(max_file_size=500)  # Below minimum

        # Test backup count limits
        with pytest.raises(ValueError):
            LoggingConfig(backup_count=0)

        with pytest.raises(ValueError):
            LoggingConfig(backup_count=51)  # Above maximum


@pytest.mark.unit
@pytest.mark.config
class TestMonitoringConfig:
    """Test cases for monitoring configuration."""

    def test_default_monitoring_config(self) -> None:
        """Test default monitoring configuration values."""
        config = MonitoringConfig()

        assert config.enabled is False
        assert config.metrics_enabled is False
        assert config.metrics_port == 9090
        assert config.metrics_path == "/metrics"
        assert config.health_check_enabled is True
        assert config.health_check_interval == 30
        assert config.alerting_enabled is False
        assert config.alert_webhook_url is None

    def test_metrics_configuration(self) -> None:
        """Test metrics configuration."""
        config = MonitoringConfig(
            enabled=True,
            metrics_enabled=True,
            metrics_port=9091,
            metrics_path="/custom/metrics",
        )

        assert config.enabled is True
        assert config.metrics_enabled is True
        assert config.metrics_port == 9091
        assert config.metrics_path == "/custom/metrics"

    def test_health_check_configuration(self) -> None:
        """Test health check configuration."""
        config = MonitoringConfig(
            health_check_enabled=True,
            health_check_interval=60,
        )

        assert config.health_check_enabled is True
        assert config.health_check_interval == 60

    def test_alerting_configuration(self) -> None:
        """Test alerting configuration."""
        webhook_url = "https://hooks.slack.com/webhook"

        config = MonitoringConfig(
            alerting_enabled=True,
            alert_webhook_url=webhook_url,
        )

        assert config.alerting_enabled is True
        assert config.alert_webhook_url == webhook_url

    def test_monitoring_port_validation(self) -> None:
        """Test monitoring port validation."""
        # Valid port
        config = MonitoringConfig(metrics_port=8080)
        assert config.metrics_port == 8080

        # Invalid ports
        with pytest.raises(ValueError):
            MonitoringConfig(metrics_port=1023)  # Below minimum

        with pytest.raises(ValueError):
            MonitoringConfig(metrics_port=65536)  # Above maximum


@pytest.mark.unit
@pytest.mark.config
class TestApplicationConfig:
    """Test cases for main application configuration."""

    def test_default_application_config(self) -> None:
        """Test default application configuration."""
        config = ApplicationConfig()

        assert config.environment == Environment.DEVELOPMENT
        assert config.debug is False
        assert config.version == "1.0.0"
        assert config.name == "LDAP Core Shared"
        assert config.description == "Enterprise LDAP Core Library"

        # Check sub-configurations are properly initialized
        assert isinstance(config.database, DatabaseConfig)
        assert isinstance(config.connection, LDAPConnectionConfig)
        assert isinstance(config.schema, SchemaConfig)
        assert isinstance(config.security, SecurityConfig)
        assert isinstance(config.logging, LoggingConfig)
        assert isinstance(config.monitoring, MonitoringConfig)

    def test_full_configuration_validation(self) -> None:
        """Test full configuration cross-validation."""
        # Production configuration should be strict
        config = ApplicationConfig(
            environment=Environment.PRODUCTION,
            debug=False,
            security=SecurityConfig(require_authentication=True),
            logging=LoggingConfig(level=LogLevel.INFO),
            connection=LDAPConnectionConfig(use_tls=True),
        )

        errors = config.validate_full_config()
        assert len(errors) == 0  # Should be valid

    def test_production_validation_rules(self) -> None:
        """Test production-specific validation rules."""
        # Debug mode in production should trigger warning
        config = ApplicationConfig(
            environment=Environment.PRODUCTION,
            debug=True,
        )

        errors = config.validate_full_config()
        assert any("Debug mode should not be enabled in production" in error for error in errors)

    def test_security_validation_rules(self) -> None:
        """Test security-related validation rules."""
        # Production without authentication should trigger error
        config = ApplicationConfig(
            environment=Environment.PRODUCTION,
            security=SecurityConfig(require_authentication=False),
        )

        errors = config.validate_full_config()
        assert any("Authentication is required in production" in error for error in errors)

    def test_tls_validation_rules(self) -> None:
        """Test TLS validation rules."""
        # Production without TLS should trigger warning
        config = ApplicationConfig(
            environment=Environment.PRODUCTION,
            connection=LDAPConnectionConfig(use_tls=False),
        )

        errors = config.validate_full_config()
        assert any("TLS should be enabled in production" in error for error in errors)

    def test_logging_validation_rules(self) -> None:
        """Test logging validation rules."""
        # Debug logging in production should trigger warning
        config = ApplicationConfig(
            environment=Environment.PRODUCTION,
            logging=LoggingConfig(level=LogLevel.DEBUG),
        )

        errors = config.validate_full_config()
        assert any("Debug logging should not be used in production" in error for error in errors)

    def test_consistency_validation_rules(self) -> None:
        """Test configuration consistency validation."""
        # max_pool_size must be >= pool_size
        config = ApplicationConfig(
            connection=LDAPConnectionConfig(pool_size=20, max_pool_size=10),
        )

        # This should be caught during LDAPConnectionConfig validation
        with pytest.raises(ValueError):
            config.connection


@pytest.mark.integration
@pytest.mark.config
class TestConfigManager:
    """Integration tests for ConfigManager functionality."""

    def test_load_config_basic(self) -> None:
        """Test basic configuration loading."""
        config = ConfigManager.load_config(environment="development")

        assert isinstance(config, ApplicationConfig)
        assert config.environment == Environment.DEVELOPMENT

    def test_load_config_with_overrides(self) -> None:
        """Test configuration loading with overrides."""
        overrides = {
            "debug": True,
            "version": "test-version",
            "logging": {"level": "DEBUG"},
        }

        config = ConfigManager.load_config(
            environment="testing",
            override_values=overrides,
        )

        assert config.environment == Environment.TESTING
        assert config.debug is True
        assert config.version == "test-version"
        assert config.logging.level == LogLevel.DEBUG

    def test_load_config_from_yaml_file(self) -> None:
        """Test loading configuration from YAML file."""
        config_data = {
            "environment": "staging",
            "debug": False,
            "database": {
                "host": "staging-db.example.com",
                "port": 5432,
                "database": "staging_db",
            },
            "connection": {
                "servers": ["ldaps://staging-ldap.example.com:636"],
                "use_tls": True,
            },
        }

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False, encoding="utf-8") as f:
            yaml.dump(config_data, f)
            config_file = f.name

        try:
            config = ConfigManager.load_config(config_file=config_file)

            assert config.environment == Environment.STAGING
            assert config.debug is False
            assert config.database.host == "staging-db.example.com"
            assert config.connection.servers == ["ldaps://staging-ldap.example.com:636"]
            assert config.connection.use_tls is True
        finally:
            Path(config_file).unlink()

    def test_load_config_from_json_file(self) -> None:
        """Test loading configuration from JSON file."""
        config_data = {
            "environment": "production",
            "debug": False,
            "security": {
                "require_authentication": True,
                "session_timeout": 7200,
            },
            "monitoring": {
                "enabled": True,
                "metrics_enabled": True,
            },
        }

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as f:
            json.dump(config_data, f)
            config_file = f.name

        try:
            config = ConfigManager.load_config(config_file=config_file)

            assert config.environment == Environment.PRODUCTION
            assert config.security.require_authentication is True
            assert config.security.session_timeout == 7200
            assert config.monitoring.enabled is True
        finally:
            Path(config_file).unlink()

    @patch.dict(os.environ, {
        "LDAP_CORE_ENV": "testing",
        "LDAP_CORE_DEBUG": "true",
        "LDAP_CORE_DATABASE_HOST": "env-db.example.com",
        "LDAP_CORE_DATABASE_PORT": "5433",
        "LDAP_CORE_CONNECTION_USE_TLS": "true",
        "LDAP_CORE_LOGGING_LEVEL": "DEBUG",
    })
    def test_load_config_from_environment(self) -> None:
        """Test loading configuration from environment variables."""
        config = ConfigManager.load_config()

        assert config.environment == Environment.TESTING
        assert config.debug is True
        assert config.database.host == "env-db.example.com"
        assert config.database.port == 5433
        assert config.connection.use_tls is True
        assert config.logging.level == LogLevel.DEBUG

    def test_environment_variable_type_conversion(self) -> None:
        """Test environment variable type conversion."""
        test_cases = [
            ("true", True),
            ("false", False),
            ("1", True),
            ("0", False),
            ("123", 123),
            ("45.67", 45.67),
            ("server1,server2,server3", ["server1", "server2", "server3"]),
            ("simple_string", "simple_string"),
        ]

        for input_value, expected_output in test_cases:
            result = ConfigManager._convert_env_value(input_value)
            assert result == expected_output

    def test_configuration_validation_error(self) -> None:
        """Test configuration validation error handling."""
        # Create invalid configuration that should fail validation
        override_values = {
            "environment": "production",
            "debug": True,  # Should trigger validation error in production
            "security": {"require_authentication": False},  # Should trigger validation error
        }

        with pytest.raises(ConfigurationValidationError):
            ConfigManager.load_config(override_values=override_values)

    def test_get_config_singleton(self) -> None:
        """Test ConfigManager singleton behavior."""
        # Load initial config
        config1 = ConfigManager.load_config(environment="development")

        # Get config should return the same instance
        config2 = ConfigManager.get_config()

        assert config1 is config2

    def test_get_config_not_loaded(self) -> None:
        """Test get_config when no configuration is loaded."""
        # Reset ConfigManager state
        ConfigManager._instance = None

        with pytest.raises(ConfigurationValidationError):
            ConfigManager.get_config()

    def test_save_config_template_yaml(self) -> None:
        """Test saving configuration template as YAML."""
        with tempfile.NamedTemporaryFile(suffix=".yaml", delete=False) as f:
            template_file = Path(f.name)

        try:
            ConfigManager.save_config_template(template_file)

            # Verify file was created and contains valid YAML
            assert template_file.exists()

            with template_file.open("r") as f:
                loaded_data = yaml.safe_load(f)

            assert "environment" in loaded_data
            assert "database" in loaded_data
            assert "connection" in loaded_data
            assert "security" in loaded_data
        finally:
            template_file.unlink()

    def test_save_config_template_json(self) -> None:
        """Test saving configuration template as JSON."""
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            template_file = Path(f.name)

        try:
            ConfigManager.save_config_template(template_file)

            # Verify file was created and contains valid JSON
            assert template_file.exists()

            with template_file.open("r") as f:
                loaded_data = json.load(f)

            assert "environment" in loaded_data
            assert "database" in loaded_data
            assert "connection" in loaded_data
            assert "security" in loaded_data
        finally:
            template_file.unlink()


# Custom test fixtures for configuration testing
@pytest.fixture
def sample_database_config():
    """Create a sample database configuration for testing."""
    return DatabaseConfig(
        host="test-db.example.com",
        port=5432,
        database="test_db",
        username="test_user",
        ssl_mode="require",
        pool_size=5,
    )


@pytest.fixture
def sample_ldap_config():
    """Create a sample LDAP configuration for testing."""
    return LDAPConnectionConfig(
        servers=["ldaps://test-ldap.example.com:636"],
        use_tls=True,
        tls_verify=True,
        strategy=ConnectionStrategy.SAFE_SYNC,
        pool_size=10,
    )


@pytest.fixture
def sample_application_config():
    """Create a sample application configuration for testing."""
    return ApplicationConfig(
        environment=Environment.TESTING,
        debug=True,
        version="test-1.0.0",
    )


@pytest.fixture
def temp_config_file():
    """Create a temporary configuration file for testing."""
    config_data = {
        "environment": "testing",
        "debug": True,
        "database": {
            "host": "temp-db.example.com",
            "database": "temp_db",
        },
    }

    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False, encoding="utf-8") as f:
        yaml.dump(config_data, f)
        yield f.name

    # Cleanup
    Path(f.name).unlink()
