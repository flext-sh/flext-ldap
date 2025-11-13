"""Comprehensive unit tests for FlextLdapConfig.

Tests LDAP configuration management with environment variables, validation,
computed fields, and infrastructure protocols.

Test Categories:
- @pytest.mark.unit - Unit tests with real objects
"""

from __future__ import annotations

import pytest
from flext_core import FlextExceptions, FlextResult
from pydantic import SecretStr

from flext_ldap.config import FlextLdapConfig
from flext_ldap.constants import FlextLdapConstants
from flext_ldap.models import FlextLdapModels

# mypy: disable-error-code="arg-type,misc,operator,attr-defined,assignment,index,call-arg,union-attr,return-value,list-item,valid-type"


class TestFlextLdapConfigInitialization:
    """Test FlextLdapConfig initialization with defaults."""

    @pytest.mark.unit
    def test_config_init_with_defaults(self) -> None:
        """Test initialization with default values."""
        config = FlextLdapConfig()
        assert config is not None
        assert config.ldap_server_uri == FlextLdapConstants.Protocol.DEFAULT_SERVER_URI
        assert config.ldap_port == FlextLdapConstants.Protocol.DEFAULT_PORT
        assert config.ldap_use_ssl is True
        assert config.ldap_verify_certificates is True

    @pytest.mark.unit
    def test_config_init_with_custom_values(self) -> None:
        """Test initialization with custom values."""
        config = FlextLdapConfig(
            ldap_server_uri="ldap://example.com",
            ldap_port=3390,
            ldap_use_ssl=False,
            ldap_bind_dn="cn=admin,dc=example,dc=com",
            ldap_bind_password=SecretStr("password123"),
        )
        assert config.ldap_server_uri == "ldap://example.com"
        assert config.ldap_port == 3390
        assert config.ldap_use_ssl is False
        assert config.ldap_bind_dn == "cn=admin,dc=example,dc=com"

    @pytest.mark.unit
    def test_config_stores_parameters(self) -> None:
        """Test that all parameters are properly stored."""
        config = FlextLdapConfig(
            ldap_server_uri="ldap://test.local",
            ldap_port=389,
            ldap_base_dn="dc=test,dc=local",
            ldap_pool_size=10,
        )
        assert config.ldap_server_uri == "ldap://test.local"
        assert config.ldap_port == 389
        assert config.ldap_base_dn == "dc=test,dc=local"
        assert config.ldap_pool_size == 10


class TestFlextLdapConfigValidators:
    """Test field validators."""

    @pytest.mark.unit
    def test_validate_bind_dn_with_valid_dn(self) -> None:
        """Test bind DN validator with valid DN."""
        config = FlextLdapConfig(
            ldap_bind_dn="cn=admin,dc=example,dc=com",
            ldap_bind_password=SecretStr("password123"),
        )
        assert config.ldap_bind_dn == "cn=admin,dc=example,dc=com"

    @pytest.mark.unit
    def test_validate_bind_dn_with_none(self) -> None:
        """Test bind DN validator with None (anonymous bind)."""
        config = FlextLdapConfig(ldap_bind_dn=None)
        assert config.ldap_bind_dn is None

    @pytest.mark.unit
    def test_validate_bind_dn_with_invalid_format(self) -> None:
        """Test bind DN validator rejects DN without = sign."""
        with pytest.raises(Exception) as exc_info:
            FlextLdapConfig(ldap_bind_dn="invalid_dn_no_equals")
        assert "Invalid LDAP bind DN format" in str(exc_info.value)

    @pytest.mark.unit
    def test_validate_bind_dn_with_too_short(self) -> None:
        """Test bind DN validator rejects DN below minimum length."""
        with pytest.raises(Exception) as exc_info:
            FlextLdapConfig(ldap_bind_dn="c=")
        assert "string too short" in str(exc_info.value)


class TestFlextLdapConfigComputedFields:
    """Test computed field generation."""

    @pytest.mark.unit
    def test_connection_info_computed_field(self) -> None:
        """Test connection_info computed field."""
        config = FlextLdapConfig(
            ldap_server_uri="ldap://test.local",
            ldap_port=389,
            ldap_use_ssl=False,
        )
        conn_info = config.connection_info
        assert isinstance(conn_info, FlextLdapModels.ConnectionInfo)
        assert conn_info.server == "ldap://test.local"
        assert conn_info.port == 389
        assert conn_info.use_ssl is False

    @pytest.mark.unit
    def test_authentication_info_computed_field(self) -> None:
        """Test authentication_info computed field."""
        config = FlextLdapConfig(
            ldap_bind_dn="cn=admin,dc=example,dc=com",
            ldap_bind_password=SecretStr("password123"),
        )
        auth_info = config.authentication_info
        assert isinstance(
            auth_info, FlextLdapModels.ConfigRuntimeMetadata.Authentication
        )
        assert auth_info.bind_dn_configured is True
        assert auth_info.bind_password_configured is True
        assert auth_info.anonymous_bind is False

    @pytest.mark.unit
    def test_authentication_info_anonymous_bind(self) -> None:
        """Test authentication_info for anonymous bind."""
        config = FlextLdapConfig(ldap_bind_dn=None)
        auth_info = config.authentication_info
        assert auth_info.bind_dn_configured is False
        assert auth_info.bind_password_configured is False
        assert auth_info.anonymous_bind is True

    @pytest.mark.unit
    def test_pooling_info_computed_field(self) -> None:
        """Test pooling_info computed field."""
        config = FlextLdapConfig(ldap_pool_size=15)
        pool_info = config.pooling_info
        assert isinstance(pool_info, FlextLdapModels.ConfigRuntimeMetadata.Pooling)
        assert pool_info.pool_size == 15

    @pytest.mark.unit
    def test_operation_limits_computed_field(self) -> None:
        """Test operation_limits computed field."""
        config = FlextLdapConfig(
            ldap_operation_timeout=120,
            ldap_size_limit=1000,
            ldap_time_limit=60,
            ldap_connection_timeout=30,
        )
        op_limits = config.operation_limits
        assert isinstance(
            op_limits, FlextLdapModels.ConfigRuntimeMetadata.OperationLimits
        )
        assert op_limits.operation_timeout == 120
        assert op_limits.size_limit == 1000
        assert op_limits.time_limit == 60

    @pytest.mark.unit
    def test_caching_info_computed_field(self) -> None:
        """Test caching_info computed field."""
        config = FlextLdapConfig(enable_caching=True, cache_ttl=3600)
        caching_info = config.caching_info
        assert isinstance(caching_info, FlextLdapModels.ConfigRuntimeMetadata.Caching)
        assert caching_info.caching_enabled is True
        assert caching_info.cache_ttl == 3600

    @pytest.mark.unit
    def test_retry_info_computed_field(self) -> None:
        """Test retry_info computed field."""
        config = FlextLdapConfig(max_retry_attempts=3, retry_delay=5)
        retry_info = config.retry_info
        assert isinstance(retry_info, FlextLdapModels.ConfigRuntimeMetadata.Retry)
        assert retry_info.retry_attempts == 3

    @pytest.mark.unit
    def test_ldap_capabilities_computed_field(self) -> None:
        """Test ldap_capabilities computed field."""
        config = FlextLdapConfig(
            ldap_use_ssl=True,
            ldap_bind_dn="cn=admin,dc=example,dc=com",
            ldap_bind_password=SecretStr("password123"),
        )
        caps = config.ldap_capabilities
        assert isinstance(caps, FlextLdapModels.ConfigCapabilities)
        assert caps.supports_ssl is True
        assert caps.has_authentication is True
        assert caps.is_production_ready is True


class TestFlextLdapConfigModelValidators:
    """Test model validators for cross-field validation."""

    @pytest.mark.unit
    def test_validate_ldap_configuration_consistency_valid(self) -> None:
        """Test valid LDAP configuration consistency."""
        config = FlextLdapConfig(
            ldap_bind_dn="cn=admin,dc=example,dc=com",
            ldap_bind_password=SecretStr("password123"),
        )
        assert config.ldap_bind_dn is not None

    @pytest.mark.unit
    def test_validate_ldap_configuration_consistency_missing_password(self) -> None:
        """Test bind DN without password fails validation."""
        with pytest.raises(Exception) as exc_info:
            FlextLdapConfig(
                ldap_bind_dn="cn=admin,dc=example,dc=com",
                ldap_bind_password=None,
            )
        assert "Bind password is required" in str(exc_info.value)

    @pytest.mark.unit
    def test_validate_ldap_configuration_consistency_caching_no_ttl(self) -> None:
        """Test caching enabled without TTL fails validation."""
        with pytest.raises(Exception) as exc_info:
            FlextLdapConfig(
                enable_caching=True,
                cache_ttl=0,
            )
        assert "Cache TTL must be positive" in str(exc_info.value)

    @pytest.mark.unit
    def test_validate_ldap_configuration_consistency_ldaps_without_ssl(self) -> None:
        """Test ldaps:// URI without SSL enabled fails validation."""
        with pytest.raises(Exception) as exc_info:
            FlextLdapConfig(
                ldap_server_uri="ldaps://example.com",
                ldap_use_ssl=False,
            )
        assert "SSL must be enabled for ldaps://" in str(exc_info.value)


class TestFlextLdapConfigCallMethod:
    """Test __call__ method for dot notation access."""

    @pytest.mark.unit
    def test_call_connection_server(self) -> None:
        """Test accessing connection.server via __call__."""
        config = FlextLdapConfig(ldap_server_uri="ldap://test.local")
        result = config("ldap.connection.server")
        assert result == "ldap://test.local"

    @pytest.mark.unit
    def test_call_connection_port(self) -> None:
        """Test accessing connection.port via __call__."""
        config = FlextLdapConfig(ldap_port=3390)
        result = config("ldap.connection.port")
        assert result == 3390

    @pytest.mark.unit
    def test_call_connection_ssl(self) -> None:
        """Test accessing connection.ssl via __call__."""
        config = FlextLdapConfig(ldap_use_ssl=True)
        result = config("ldap.connection.ssl")
        assert result is True

    @pytest.mark.unit
    def test_call_connection_timeout(self) -> None:
        """Test accessing connection.timeout via __call__."""
        config = FlextLdapConfig(ldap_connection_timeout=30)
        result = config("ldap.connection.timeout")
        assert result == 30

    @pytest.mark.unit
    def test_call_connection_uri(self) -> None:
        """Test accessing connection.uri via __call__."""
        config = FlextLdapConfig(
            ldap_server_uri="ldap://test.local",
            ldap_port=389,
        )
        result = config("ldap.connection.uri")
        assert result == "ldap://test.local:389"

    @pytest.mark.unit
    def test_call_auth_bind_dn(self) -> None:
        """Test accessing auth.bind_dn via __call__."""
        config = FlextLdapConfig(
            ldap_bind_dn="cn=admin,dc=example,dc=com",
            ldap_bind_password=SecretStr("password123"),
        )
        result = config("ldap.auth.bind_dn")
        assert result == "cn=admin,dc=example,dc=com"

    @pytest.mark.unit
    def test_call_auth_bind_password(self) -> None:
        """Test accessing auth.bind_password via __call__."""
        config = FlextLdapConfig(ldap_bind_password=SecretStr("password123"))
        result = config("ldap.auth.bind_password")
        assert result == "password123"

    @pytest.mark.unit
    def test_call_auth_base_dn(self) -> None:
        """Test accessing auth.base_dn via __call__."""
        config = FlextLdapConfig(ldap_base_dn="dc=example,dc=com")
        result = config("ldap.auth.base_dn")
        assert result == "dc=example,dc=com"

    @pytest.mark.unit
    def test_call_pool_size(self) -> None:
        """Test accessing pool.size via __call__."""
        config = FlextLdapConfig(ldap_pool_size=20)
        result = config("ldap.pool.size")
        assert result == 20

    @pytest.mark.unit
    def test_call_pool_timeout(self) -> None:
        """Test accessing pool.timeout via __call__."""
        config = FlextLdapConfig(ldap_pool_timeout=60)
        result = config("ldap.pool.timeout")
        assert result == 60

    @pytest.mark.unit
    def test_call_operation_timeout(self) -> None:
        """Test accessing operation.timeout via __call__."""
        config = FlextLdapConfig(ldap_operation_timeout=120)
        result = config("ldap.operation.timeout")
        assert result == 120

    @pytest.mark.unit
    def test_call_operation_size_limit(self) -> None:
        """Test accessing operation.size_limit via __call__."""
        config = FlextLdapConfig(ldap_size_limit=1000)
        result = config("ldap.operation.size_limit")
        assert result == 1000

    @pytest.mark.unit
    def test_call_operation_time_limit(self) -> None:
        """Test accessing operation.time_limit via __call__."""
        config = FlextLdapConfig(ldap_time_limit=60)
        result = config("ldap.operation.time_limit")
        assert result == 60

    @pytest.mark.unit
    def test_call_cache_enabled(self) -> None:
        """Test accessing cache.enabled via __call__."""
        config = FlextLdapConfig(enable_caching=True)
        result = config("ldap.cache.enabled")
        assert result is True

    @pytest.mark.unit
    def test_call_cache_ttl(self) -> None:
        """Test accessing cache.ttl via __call__."""
        config = FlextLdapConfig(cache_ttl=3600)
        result = config("ldap.cache.ttl")
        assert result == 3600

    @pytest.mark.unit
    def test_call_retry_attempts(self) -> None:
        """Test accessing retry.attempts via __call__."""
        config = FlextLdapConfig(max_retry_attempts=3)
        result = config("ldap.retry.attempts")
        assert result == 3

    @pytest.mark.unit
    def test_call_retry_delay(self) -> None:
        """Test accessing retry.delay via __call__."""
        config = FlextLdapConfig(retry_delay=5)
        result = config("ldap.retry.delay")
        assert result == 5

    @pytest.mark.unit
    def test_call_logging_debug(self) -> None:
        """Test accessing logging.debug via __call__."""
        config = FlextLdapConfig(ldap_enable_debug=True)
        result = config("ldap.logging.debug")
        assert result is True

    @pytest.mark.unit
    def test_call_logging_trace(self) -> None:
        """Test accessing logging.trace via __call__."""
        config = FlextLdapConfig(ldap_enable_trace=True)
        result = config("ldap.logging.trace")
        assert result is True

    @pytest.mark.unit
    def test_call_logging_queries(self) -> None:
        """Test accessing logging.queries via __call__."""
        config = FlextLdapConfig(ldap_log_queries=True)
        result = config("ldap.logging.queries")
        assert result is True

    @pytest.mark.unit
    def test_call_logging_mask_passwords(self) -> None:
        """Test accessing logging.mask_passwords via __call__."""
        config = FlextLdapConfig(ldap_mask_passwords=False)
        result = config("ldap.logging.mask_passwords")
        assert result is False


class TestFlextLdapConfigInfrastructureMethods:
    """Test infrastructure protocol methods."""

    @pytest.mark.unit
    def test_configure_success(self) -> None:
        """Test configure method with valid config."""
        config = FlextLdapConfig()
        result = config.configure({"ldap_server_uri": "ldap://new.local"})
        assert isinstance(result, FlextResult)

    @pytest.mark.unit
    def test_validate_business_rules_returns_success(self) -> None:
        """Test validate_business_rules returns success."""
        config = FlextLdapConfig()
        result = config.validate_business_rules()
        assert isinstance(result, FlextResult)
        assert result.is_success


class TestFlextLdapConfigLdapSpecificMethods:
    """Test LDAP-specific methods."""

    @pytest.mark.unit
    def test_validate_ldap_requirements_success(self) -> None:
        """Test validate_ldap_requirements with valid config."""
        config = FlextLdapConfig(
            ldap_server_uri="ldap://test.local",
            ldap_port=389,
            ldap_connection_timeout=30,
            ldap_operation_timeout=120,
        )
        result = config.validate_ldap_requirements()
        assert isinstance(result, FlextResult)
        assert result.is_success

    @pytest.mark.unit
    def test_validate_ldap_requirements_ldaps_with_ldap_port(self) -> None:
        """Test ldaps:// URI with LDAP port fails validation.

        Note: With Pydantic v2 @model_validator, validation occurs at __init__.
        """
        with pytest.raises(FlextExceptions.ConfigurationError) as exc_info:
            FlextLdapConfig(
                ldap_server_uri="ldaps://test.local",
                ldap_port=389,
                ldap_connection_timeout=30,
                ldap_operation_timeout=120,
            )
        assert "Port 389 is for LDAP, not LDAPS" in str(exc_info.value)
        assert "Use 636" in str(exc_info.value)

    @pytest.mark.unit
    def test_validate_ldap_requirements_ldap_with_ldaps_port(self) -> None:
        """Test ldap:// URI with LDAPS port fails validation.

        Note: With Pydantic v2 @model_validator, validation occurs at __init__.
        """
        with pytest.raises(FlextExceptions.ConfigurationError) as exc_info:
            FlextLdapConfig(
                ldap_server_uri="ldap://test.local",
                ldap_port=636,
                ldap_connection_timeout=30,
                ldap_operation_timeout=120,
            )
        assert "Port 636 is for LDAPS, not LDAP" in str(exc_info.value)
        assert "Use 389" in str(exc_info.value)

    @pytest.mark.unit
    def test_validate_ldap_requirements_operation_timeout_less_than_connection(
        self,
    ) -> None:
        """Test operation timeout must be greater than connection timeout.

        Note: With Pydantic v2 @model_validator, validation occurs at __init__.
        """
        with pytest.raises(FlextExceptions.ConfigurationError) as exc_info:
            FlextLdapConfig(
                ldap_server_uri="ldap://test.local",
                ldap_port=389,
                ldap_connection_timeout=30,
                ldap_operation_timeout=20,
            )
        assert "Operation timeout must be greater than connection timeout" in str(
            exc_info.value
        )

    @pytest.mark.unit
    def test_effective_bind_password_with_password(self) -> None:
        """Test effective_bind_password returns actual password."""
        config = FlextLdapConfig(
            ldap_bind_dn="cn=admin,dc=example,dc=com",
            ldap_bind_password=SecretStr("secret123"),
        )
        password = config.effective_bind_password
        assert password == "secret123"

    @pytest.mark.unit
    def test_effective_bind_password_without_password(self) -> None:
        """Test effective_bind_password returns None when no password."""
        config = FlextLdapConfig(ldap_bind_password=None)
        password = config.effective_bind_password
        assert password is None


class TestFlextLdapConfigDependencyInjection:
    """Test dependency injection methods."""

    @pytest.mark.unit
    def test_get_di_config_provider(self) -> None:
        """Test getting dependency-injector config provider."""
        config = FlextLdapConfig()
        provider = config.get_di_config_provider()
        assert provider is not None

    @pytest.mark.unit
    def test_get_di_config_provider_singleton(self) -> None:
        """Test DI config provider is singleton per class."""
        config1 = FlextLdapConfig()
        provider1 = config1.get_di_config_provider()

        config2 = FlextLdapConfig()
        provider2 = config2.get_di_config_provider()

        assert provider1 is provider2


class TestFlextLdapConfigIntegration:
    """Integration tests for FlextLdapConfig."""

    @pytest.mark.unit
    def test_config_complete_workflow(self) -> None:
        """Test complete configuration workflow."""
        config = FlextLdapConfig(
            ldap_server_uri="ldap://test.local",
            ldap_port=389,
            ldap_bind_dn="cn=admin,dc=test,dc=local",
            ldap_bind_password=SecretStr("admin123"),
            ldap_base_dn="dc=test,dc=local",
            ldap_use_ssl=False,
            enable_caching=True,
            cache_ttl=3600,
        )

        assert config.connection_info is not None
        assert config.authentication_info is not None
        assert config.pooling_info is not None
        assert config.operation_limits is not None
        assert config.caching_info is not None
        assert config.retry_info is not None
        assert config.ldap_capabilities is not None

        result = config.validate_ldap_requirements()
        assert result.is_success

        assert config("ldap.connection.server") == "ldap://test.local"
        assert config("ldap.auth.bind_dn") == "cn=admin,dc=test,dc=local"

    @pytest.mark.unit
    def test_config_all_fields_accessible(self) -> None:
        """Test that all configuration fields are accessible."""
        config = FlextLdapConfig(
            ldap_server_uri="ldap://test",
            ldap_port=389,
            ldap_use_ssl=False,
            ldap_verify_certificates=True,
            ldap_base_dn="dc=test",
            ldap_user_base_dn="ou=users",
            ldap_group_base_dn="ou=groups",
            ldap_pool_size=10,
            ldap_pool_timeout=30,
            ldap_connection_timeout=30,
            ldap_operation_timeout=120,
            ldap_size_limit=1000,
            ldap_time_limit=60,
            ldap_enable_debug=False,
            ldap_enable_trace=False,
            ldap_log_queries=False,
            ldap_mask_passwords=True,
        )

        assert config.ldap_server_uri is not None
        assert config.ldap_port is not None
        assert config.ldap_use_ssl is not None
        assert config.ldap_verify_certificates is not None
        assert config.ldap_base_dn is not None
        assert config.ldap_user_base_dn is not None
        assert config.ldap_group_base_dn is not None
        assert config.ldap_pool_size is not None
        assert config.ldap_pool_timeout is not None
        assert config.ldap_connection_timeout is not None
        assert config.ldap_operation_timeout is not None
        assert config.ldap_size_limit is not None
        assert config.ldap_time_limit is not None
        assert config.ldap_enable_debug is not None
        assert config.ldap_enable_trace is not None
        assert config.ldap_log_queries is not None
        assert config.ldap_mask_passwords is not None


__all__ = [
    "TestFlextLdapConfigCallMethod",
    "TestFlextLdapConfigComputedFields",
    "TestFlextLdapConfigDependencyInjection",
    "TestFlextLdapConfigInfrastructureMethods",
    "TestFlextLdapConfigInitialization",
    "TestFlextLdapConfigIntegration",
    "TestFlextLdapConfigLdapSpecificMethods",
    "TestFlextLdapConfigModelValidators",
    "TestFlextLdapConfigValidators",
]
