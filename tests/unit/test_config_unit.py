"""Unit tests for FLEXT LDAP configuration.

Tests all configuration classes with real behavior, no mocks or patches.
Tests use actual validation and configuration patterns from the refactored API.
"""

from __future__ import annotations

import pytest
from flext_core import FlextLogLevel
from pydantic import SecretStr, ValidationError

from flext_ldap.config import (
    FlextLdapAuthConfig,
    FlextLdapConnectionConfig,
    FlextLdapConstants,
    FlextLdapLoggingConfig,
)
from flext_ldap.models import (
    FlextLdapScopeEnum,
    FlextLdapSearchConfig,
    FlextLdapSettings,
    create_development_config,
    create_production_config,
    create_test_config,
)

# Constants
HTTP_OK = 200
EXPECTED_BULK_SIZE = 2
EXPECTED_DATA_COUNT = 3


class TestFlextLdapConstants:
    """Test FlextLdapConstants."""

    def test_constants_values(self) -> None:
        """Test that constants have expected values."""
        assert FlextLdapConstants.DEFAULT_TIMEOUT_SECONDS == 30
        assert FlextLdapConstants.MAX_TIMEOUT_SECONDS == 300
        assert FlextLdapConstants.DEFAULT_POOL_SIZE == 10
        assert FlextLdapConstants.MAX_POOL_SIZE == 100
        assert FlextLdapConstants.DEFAULT_PAGE_SIZE == 1000
        assert FlextLdapConstants.MAX_PAGE_SIZE == 10000


class TestFlextLdapConnectionConfig:
    """Test FlextLdapConnectionConfig functionality."""

    def test_connection_config_defaults(self) -> None:
        """Test FlextLdapConnectionConfig with default values."""
        config = FlextLdapConnectionConfig()
        assert config.server == "localhost"
        assert config.port == 389
        assert config.use_ssl is False
        assert config.timeout == 30
        assert config.pool_size == 10
        assert config.enable_connection_pooling is True

    def test_connection_config_custom(self) -> None:
        """Test FlextLdapConnectionConfig with custom values."""
        config = FlextLdapConnectionConfig(
            server="test.example.com",
            port=636,
            use_ssl=True,
            timeout=60,
            pool_size=20,
            enable_connection_pooling=False,
        )
        assert config.server == "test.example.com"
        assert config.port == 636
        assert config.use_ssl is True
        assert config.timeout == 60
        assert config.pool_size == 20
        assert config.enable_connection_pooling is False

    def test_server_validation_valid(self) -> None:
        """Test server validation with valid values."""
        config = FlextLdapConnectionConfig(server="localhost")
        assert config.server == "localhost"

    def test_server_validation_invalid(self) -> None:
        """Test server validation with invalid values."""
        with pytest.raises(ValueError, match="Host cannot be empty"):
            FlextLdapConnectionConfig(server="")

        with pytest.raises(ValueError, match="Host cannot be empty"):
            FlextLdapConnectionConfig(server="   ")

    def test_port_validation_valid(self) -> None:
        """Test port validation with valid values."""
        config = FlextLdapConnectionConfig(port=636)
        assert config.port == 636

    def test_port_validation_invalid(self) -> None:
        """Test port validation with invalid values."""
        with pytest.raises(ValidationError):
            FlextLdapConnectionConfig(port=0)

        with pytest.raises(ValidationError):
            FlextLdapConnectionConfig(port=65536)

    def test_domain_rules_validation_success(self) -> None:
        """Test domain rules validation with valid config."""
        config = FlextLdapConnectionConfig(
            server="localhost",
            port=389,
            timeout=30,
            pool_size=10,
        )
        # Should not raise
        config.validate_business_rules()


class TestFlextLdapAuthConfig:
    """Test FlextLdapAuthConfig functionality."""

    def test_auth_config_defaults(self) -> None:
        """Test FlextLdapAuthConfig with default values."""
        config = FlextLdapAuthConfig()
        assert config.bind_dn == ""
        assert config.bind_password is not None
        assert config.bind_password.get_secret_value() == ""
        assert config.use_anonymous_bind is False
        assert config.sasl_mechanism is None

    def test_auth_config_custom(self) -> None:
        """Test FlextLdapAuthConfig with custom values."""
        config = FlextLdapAuthConfig(
            bind_dn="cn=admin,dc=example,dc=org",
            bind_password=SecretStr("secret"),
            use_anonymous_bind=True,
            sasl_mechanism="EXTERNAL",
        )
        assert config.bind_dn == "cn=admin,dc=example,dc=org"
        assert config.bind_password is not None
        assert config.bind_password.get_secret_value() == "secret"
        assert config.use_anonymous_bind is True
        assert config.sasl_mechanism == "EXTERNAL"

    def test_bind_dn_validation(self) -> None:
        """Test bind DN validation."""
        config = FlextLdapAuthConfig(bind_dn="  cn=admin,dc=example,dc=org  ")
        expected_dn = "cn=admin,dc=example,dc=org"  # Should be stripped
        assert config.bind_dn == expected_dn

    def test_domain_rules_validation_anonymous_bind(self) -> None:
        """Test domain rules validation for anonymous bind."""
        config = FlextLdapAuthConfig(use_anonymous_bind=True)
        # Should not raise even without bind_dn/password
        config.validate_business_rules()

    def test_domain_rules_validation_bind_dn_required(self) -> None:
        """Test domain rules validation when bind DN is required."""
        config = FlextLdapAuthConfig(use_anonymous_bind=False, bind_dn="")
        result = config.validate_business_rules()
        assert not result.success
        assert result.error is not None
        assert "bind dn" in result.error.lower()

    def test_domain_rules_validation_password_required(self) -> None:
        """Test domain rules validation when password is required."""
        config = FlextLdapAuthConfig(
            use_anonymous_bind=False,
            bind_dn="cn=admin,dc=example,dc=org",
            bind_password=SecretStr(""),
        )
        result = config.validate_business_rules()
        assert not result.success
        assert "Bind password is required" in (result.error or "")


class TestFlextLdapSearchConfig:
    """Test FlextLdapSearchConfig functionality."""

    def test_search_config_defaults(self) -> None:
        """Test FlextLdapSearchConfig with default values."""
        config = FlextLdapSearchConfig()
        assert config.default_scope.value == "subtree"
        assert config.default_size_limit == 1000
        assert config.default_time_limit == 30
        assert config.default_page_size == 1000
        assert config.enable_referral_following is False
        assert config.max_referral_hops == 5

    def test_search_config_custom(self) -> None:
        """Test FlextLdapSearchConfig with custom values."""
        config = FlextLdapSearchConfig(
            default_scope=FlextLdapScopeEnum.ONE,
            default_size_limit=500,
            default_time_limit=60,
            default_page_size=100,
            enable_referral_following=True,
            max_referral_hops=10,
        )
        assert config.default_scope == FlextLdapScopeEnum.ONE
        assert config.default_size_limit == 500
        assert config.default_time_limit == 60
        assert config.default_page_size == 100
        assert config.enable_referral_following is True
        assert config.max_referral_hops == 10


class TestFlextLdapLoggingConfig:
    """Test FlextLdapLoggingConfig functionality."""

    def test_logging_config_defaults(self) -> None:
        """Test FlextLdapLoggingConfig with default values."""
        config = FlextLdapLoggingConfig()
        assert config.log_level == FlextLogLevel.INFO
        assert config.enable_connection_logging is False
        assert config.enable_operation_logging is True
        assert config.log_sensitive_data is False
        assert config.structured_logging is True

    def test_logging_config_custom(self) -> None:
        """Test FlextLdapLoggingConfig with custom values."""
        config = FlextLdapLoggingConfig(
            log_level=FlextLogLevel.DEBUG,
        )
        # Update attributes after creation since they have defaults
        config = config.model_copy(
            update={
                "enable_connection_logging": True,
                "enable_operation_logging": False,
                "log_sensitive_data": True,
                "structured_logging": False,
            },
        )
        assert config.log_level == FlextLogLevel.DEBUG
        assert config.enable_connection_logging is True
        assert config.enable_operation_logging is False
        assert config.log_sensitive_data is True
        assert config.structured_logging is False


class TestFlextLdapSettings:
    """Test FlextLdapSettings functionality."""

    def test_settings_import(self) -> None:
        """Test that FlextLdapSettings can be imported."""
        assert FlextLdapSettings is not None

    def test_settings_instantiation_defaults(self) -> None:
        """Test that FlextLdapSettings can be instantiated with defaults."""
        settings = FlextLdapSettings()
        assert settings is not None
        assert settings.default_connection is None
        assert settings.enable_debug_mode is False
        assert settings.enable_caching is False

    def test_settings_custom_values(self) -> None:
        """Test FlextLdapSettings with custom values."""
        connection_config = FlextLdapConnectionConfig(
            server="custom.ldap.com",
            port=636,
            use_ssl=True,
        )

        settings = FlextLdapSettings()
        # Update other fields using model_copy
        settings = settings.model_copy(
            update={
                "default_connection": connection_config,
                "enable_debug_mode": True,
                "enable_caching": True,
                "cache_ttl": 600,
            },
        )

        assert settings.default_connection is not None
        assert settings.default_connection.server == "custom.ldap.com"
        assert settings.default_connection.port == 636
        assert settings.default_connection.use_ssl is True
        assert settings.enable_debug_mode is True
        assert settings.enable_caching is True
        assert settings.cache_ttl == 600

    def test_get_effective_connection(self) -> None:
        """Test getting effective connection configuration."""
        settings = FlextLdapSettings()

        # Test with no default connection
        effective = settings.get_effective_connection()
        assert effective is not None
        assert isinstance(effective, FlextLdapConnectionConfig)

        # Test with override
        override_config = FlextLdapConnectionConfig(
            server="override.ldap.com",
            port=636,
        )
        effective = settings.get_effective_connection(override=override_config)
        assert effective.server == "override.ldap.com"
        assert effective.port == 636


class TestFlextLdapConfigFactories:
    """Test configuration factory functions."""

    def test_create_development_config(self) -> None:
        """Test development configuration factory."""
        config = create_development_config()
        assert config is not None
        assert isinstance(config, FlextLdapSettings)
        assert config.enable_debug_mode is True

    def test_create_production_config(self) -> None:
        """Test production configuration factory."""
        config = create_production_config("ldap.production.com")
        assert config is not None
        assert isinstance(config, FlextLdapSettings)
        assert config.enable_debug_mode is False
        assert config.default_connection is not None
        assert config.default_connection.server == "ldap.production.com"
        assert config.default_connection.port == 636  # Default SSL port
        assert config.default_connection.use_ssl is True

    def test_create_test_config(self) -> None:
        """Test test configuration factory."""
        config = create_test_config()
        assert config is not None
        assert isinstance(config, FlextLdapSettings)
        assert config.enable_debug_mode is False  # Test config should be quiet
        assert config.enable_test_mode is False  # Default mock disabled

        # Test with mock enabled
        config_with_mock = create_test_config(enable_mock=True)
        assert config_with_mock.enable_test_mode is True

    def test_factory_functions_return_different_instances(self) -> None:
        """Test that factory functions return independent instances."""
        dev_config = create_development_config()
        prod_config = create_production_config("ldap.prod.com")
        test_config = create_test_config()

        # Should be different instances
        assert dev_config is not prod_config
        assert dev_config is not test_config
        assert prod_config is not test_config

        # Should have different debug modes
        assert dev_config.enable_debug_mode is True
        assert prod_config.enable_debug_mode is False
        assert test_config.enable_debug_mode is False  # Test config should be quiet


class TestFlextLdapConfigIntegration:
    """Test configuration integration with real validation behavior."""

    def test_connection_config_full_validation(self) -> None:
        """Test connection configuration with comprehensive validation."""
        # Test complete valid configuration
        config = FlextLdapConnectionConfig(
            server="ldap.example.com",
            port=636,
            use_ssl=True,
            timeout=60,
            pool_size=20,
        )

        # Should validate successfully
        config.validate_domain_rules()

        # Verify all fields
        assert config.server == "ldap.example.com"
        assert config.port == 636
        assert config.use_ssl is True
        assert config.timeout == 60
        assert config.pool_size == 20

    def test_auth_config_full_validation(self) -> None:
        """Test authentication configuration with comprehensive validation."""
        # Test complete valid auth config
        config = FlextLdapAuthConfig(
            bind_dn="cn=admin,dc=example,dc=com",
            bind_password=SecretStr("secure_password"),
            use_anonymous_bind=False,
            sasl_mechanism=None,
        )

        # Should validate successfully
        result = config.validate_business_rules()
        assert result.success

    def test_search_config_limits_validation(self) -> None:
        """Test search configuration with realistic limits."""
        config = FlextLdapSearchConfig(
            default_scope=FlextLdapScopeEnum.SUBTREE,
            default_size_limit=5000,
            default_time_limit=120,
            default_page_size=500,
        )

        # All values should be within reasonable bounds
        assert config.default_scope == FlextLdapScopeEnum.SUBTREE
        assert config.default_size_limit == 5000
        assert config.default_time_limit == 120
        assert config.default_page_size == 500

    def test_integrated_settings_workflow(self) -> None:
        """Test complete settings configuration workflow."""
        # Create connection config
        conn_config = FlextLdapConnectionConfig(
            server="production.ldap.com",
            port=636,
            use_ssl=True,
        )

        # Create auth config
        auth_config = FlextLdapAuthConfig(
            bind_dn="cn=service,dc=company,dc=com",
            bind_password=SecretStr("service_password"),
        )

        # Create logging config
        log_config = FlextLdapLoggingConfig(
            log_level=FlextLogLevel.WARNING,
        )

        # Create complete settings
        settings = FlextLdapSettings()
        settings = settings.model_copy(update={
            "default_connection": conn_config,
            "default_auth": auth_config,
            "logging": log_config,
            "enable_caching": True,
            "cache_ttl": 3600,
        })

        # Verify integrated configuration
        assert settings.default_connection is not None
        assert settings.default_connection.server == "production.ldap.com"
        assert settings.enable_caching is True
        assert settings.cache_ttl == 3600
