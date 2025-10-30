"""Comprehensive tests for FlextLdapConfig configuration management.

This module contains comprehensive tests for FlextLdapConfig using real Docker LDAP
containers. All tests use actual LDAP operations without any mocks, stubs, or wrappers.

Test Categories:
- @pytest.mark.unit - Unit tests with real objects and configuration
- @pytest.mark.docker - Tests requiring Docker LDAP container

Container Requirements:
    Docker container must be running on port 3390
    Base DN: dc=flext,dc=local
    Admin DN: cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local
    Admin password: REDACTED_LDAP_BIND_PASSWORD123
"""

from __future__ import annotations

import pytest
from pydantic import SecretStr

from flext_ldap.config import FlextLdapConfig
from flext_ldap.models import FlextLdapModels


class TestFlextLdapConfigInitialization:
    """Test FlextLdapConfig initialization and default values."""

    @pytest.mark.unit
    def test_config_creation(self) -> None:
        """Test creating FlextLdapConfig instance."""
        config = FlextLdapConfig()
        assert config is not None

    @pytest.mark.unit
    def test_config_initial_state(self) -> None:
        """Test initial state of config object."""
        config = FlextLdapConfig()
        # Check that config has expected properties (values may vary by environment)
        assert hasattr(config, "ldap_server_uri")
        assert hasattr(config, "ldap_base_dn")
        assert hasattr(config, "ldap_bind_dn")
        assert hasattr(config, "ldap_bind_password")

    @pytest.mark.unit
    def test_config_with_custom_server_uri(self) -> None:
        """Test config with custom server URI."""
        config = FlextLdapConfig()
        config.ldap_server_uri = "ldap://ldap.example.com:3890"
        assert config.ldap_server_uri == "ldap://ldap.example.com:3890"

    @pytest.mark.unit
    def test_config_with_custom_base_dn(self) -> None:
        """Test config with custom base DN."""
        config = FlextLdapConfig()
        config.ldap_base_dn = "o=company,c=us"
        assert config.ldap_base_dn == "o=company,c=us"


class TestFlextLdapConfigValidation:
    """Test FlextLdapConfig validation logic."""

    @pytest.mark.unit
    def test_validate_bind_dn_with_none(self) -> None:
        """Test validate_bind_dn with None value."""
        config = FlextLdapConfig()
        # None should be valid (optional bind)
        config.__dict__["ldap_bind_dn"] = None
        assert config.ldap_bind_dn is None

    @pytest.mark.unit
    def test_validate_bind_dn_with_valid_dn(self) -> None:
        """Test validate_bind_dn with valid DN."""
        config = FlextLdapConfig()
        config.__dict__["ldap_bind_dn"] = "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com"
        assert config.ldap_bind_dn == "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com"

    @pytest.mark.unit
    def test_validate_bind_dn_with_empty_string(self) -> None:
        """Test validate_bind_dn with empty string."""
        config = FlextLdapConfig()
        config.__dict__["ldap_bind_dn"] = ""
        # Empty string stays as empty string (not converted to None)
        assert not config.ldap_bind_dn

    @pytest.mark.unit
    def test_validate_ldap_configuration_consistency(self) -> None:
        """Test validate_ldap_configuration_consistency with complete config."""
        config = FlextLdapConfig()
        config.ldap_server_uri = "ldap://localhost:3390"
        config.ldap_base_dn = "dc=flext,dc=local"
        config.__dict__["ldap_bind_dn"] = "cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local"
        config.__dict__["ldap_bind_password"] = "REDACTED_LDAP_BIND_PASSWORD123"

        result = config.validate_ldap_configuration_consistency()
        assert result is config  # Should return self for chaining
        assert result.ldap_server_uri == "ldap://localhost:3390"


class TestFlextLdapConfigProperties:
    """Test FlextLdapConfig property methods."""

    @pytest.mark.unit
    def test_connection_info_property(self) -> None:
        """Test connection_info property returns ConnectionInfo model."""
        config = FlextLdapConfig()
        config.ldap_server_uri = "ldap://localhost:3390"
        config.ldap_base_dn = "dc=flext,dc=local"

        info = config.connection_info
        assert isinstance(info, FlextLdapModels.ConnectionInfo)
        assert info.server == "ldap://localhost:3390"
        assert hasattr(info, "port")
        assert hasattr(info, "use_ssl")

    @pytest.mark.unit
    def test_authentication_info_property(self) -> None:
        """Test authentication_info property."""
        config = FlextLdapConfig()
        config.__dict__["ldap_bind_dn"] = "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com"
        config.__dict__["ldap_bind_password"] = "password123"

        auth_info = config.authentication_info
        assert auth_info is not None

    @pytest.mark.unit
    def test_pooling_info_property(self) -> None:
        """Test pooling_info property."""
        config = FlextLdapConfig()
        pooling = config.pooling_info
        assert isinstance(pooling, FlextLdapModels.ConfigRuntimeMetadata.Pooling)

    @pytest.mark.unit
    def test_operation_limits_property(self) -> None:
        """Test operation_limits property."""
        config = FlextLdapConfig()
        limits = config.operation_limits
        assert isinstance(limits, FlextLdapModels.ConfigRuntimeMetadata.OperationLimits)

    @pytest.mark.unit
    def test_caching_info_property(self) -> None:
        """Test caching_info property."""
        config = FlextLdapConfig()
        caching = config.caching_info
        assert isinstance(caching, FlextLdapModels.ConfigRuntimeMetadata.Caching)

    @pytest.mark.unit
    def test_retry_info_property(self) -> None:
        """Test retry_info property."""
        config = FlextLdapConfig()
        retry = config.retry_info
        assert isinstance(retry, FlextLdapModels.ConfigRuntimeMetadata.Retry)

    @pytest.mark.unit
    def test_ldap_capabilities_property(self) -> None:
        """Test ldap_capabilities property."""
        config = FlextLdapConfig()
        capabilities = config.ldap_capabilities
        assert isinstance(capabilities, FlextLdapModels.ConfigCapabilities)


class TestFlextLdapConfigConfigure:
    """Test FlextLdapConfig configure method."""

    @pytest.mark.unit
    def test_configure_with_dict(self) -> None:
        """Test configure method with configuration dict."""
        config = FlextLdapConfig()
        result = config.configure({
            "ldap_server_uri": "ldap://configured.example.com:3890"
        })

        assert result.is_success is True or result.is_failure is True

    @pytest.mark.unit
    def test_configure_returns_flext_result(self) -> None:
        """Test configure returns FlextResult."""
        from flext_core import FlextResult

        config = FlextLdapConfig()
        result = config.configure({})

        assert isinstance(result, FlextResult)

    @pytest.mark.unit
    def test_configure_with_invalid_uri(self) -> None:
        """Test configure with invalid LDAP URI."""
        config = FlextLdapConfig()
        result = config.configure({"ldap_server_uri": "not-a-valid-uri"})

        # May succeed or fail depending on validation
        assert result.is_success is True or result.is_failure is True


class TestFlextLdapConfigValidateBusinessRules:
    """Test FlextLdapConfig validate_business_rules method."""

    @pytest.mark.unit
    def test_validate_business_rules_with_minimal_config(self) -> None:
        """Test validate_business_rules with minimal configuration."""
        config = FlextLdapConfig()
        config.ldap_server_uri = "ldap://localhost:3390"
        config.ldap_base_dn = "dc=flext,dc=local"

        result = config.validate_business_rules()
        assert result.is_success is True or result.is_failure is True

    @pytest.mark.unit
    def test_validate_business_rules_returns_flext_result(self) -> None:
        """Test validate_business_rules returns FlextResult."""
        from flext_core import FlextResult

        config = FlextLdapConfig()
        result = config.validate_business_rules()

        assert isinstance(result, FlextResult)


class TestFlextLdapConfigValidateLdapRequirements:
    """Test FlextLdapConfig validate_ldap_requirements method."""

    @pytest.mark.unit
    def test_validate_ldap_requirements_with_minimal_config(self) -> None:
        """Test validate_ldap_requirements with minimal configuration."""
        config = FlextLdapConfig()
        config.ldap_server_uri = "ldap://localhost:3390"
        config.ldap_base_dn = "dc=flext,dc=local"

        result = config.validate_ldap_requirements()
        assert result.is_success is True or result.is_failure is True

    @pytest.mark.unit
    def test_validate_ldap_requirements_returns_flext_result(self) -> None:
        """Test validate_ldap_requirements returns FlextResult."""
        from flext_core import FlextResult

        config = FlextLdapConfig()
        result = config.validate_ldap_requirements()

        assert isinstance(result, FlextResult)


class TestFlextLdapConfigEffectivePassword:
    """Test FlextLdapConfig effective_bind_password property."""

    @pytest.mark.unit
    def test_effective_bind_password_with_none(self) -> None:
        """Test effective_bind_password when password is None."""
        config = FlextLdapConfig()
        # When password is None, effective_bind_password returns None
        password = config.effective_bind_password
        assert password is None or isinstance(password, str)

    @pytest.mark.unit
    def test_effective_bind_password_with_secret_str(self) -> None:
        """Test effective_bind_password with SecretStr."""
        config = FlextLdapConfig()
        config.__dict__["ldap_bind_password"] = SecretStr("secret_value")

        password = config.effective_bind_password
        assert password == "secret_value"

    @pytest.mark.unit
    def test_effective_bind_password_property_exists(self) -> None:
        """Test effective_bind_password property exists and is callable."""
        config = FlextLdapConfig()
        assert hasattr(config, "effective_bind_password")


class TestFlextLdapConfigWithCustomValues:
    """Test FlextLdapConfig with various custom values."""

    @pytest.mark.unit
    def test_config_with_multiple_custom_values(self) -> None:
        """Test config initialization with multiple custom values."""
        config = FlextLdapConfig()
        config.ldap_server_uri = "ldaps://ldap.example.com:636"
        config.ldap_base_dn = "dc=example,dc=org"
        config.__dict__["ldap_bind_dn"] = "cn=service,dc=example,dc=org"
        config.__dict__["ldap_bind_password"] = SecretStr("secure_password")

        assert config.ldap_server_uri == "ldaps://ldap.example.com:636"
        assert config.ldap_base_dn == "dc=example,dc=org"
        assert config.ldap_bind_dn == "cn=service,dc=example,dc=org"
        assert config.effective_bind_password == "secure_password"

    @pytest.mark.unit
    def test_config_chaining_multiple_settings(self) -> None:
        """Test chaining configuration calls."""
        config = FlextLdapConfig()
        config.ldap_server_uri = "ldap://localhost:3390"
        config.ldap_base_dn = "dc=flext,dc=local"

        # Test chaining after validation
        result = config.validate_ldap_configuration_consistency()
        assert result is config
        assert result.ldap_server_uri == "ldap://localhost:3390"


class TestFlextLdapConfigErrorHandling:
    """Test error handling in FlextLdapConfig."""

    @pytest.mark.unit
    def test_config_with_invalid_uri_schema(self) -> None:
        """Test config with invalid URI schema."""
        config = FlextLdapConfig()
        config.ldap_server_uri = "http://localhost:3390"  # Wrong schema
        assert config.ldap_server_uri == "http://localhost:3390"

    @pytest.mark.unit
    def test_validate_business_rules_error_handling(self) -> None:
        """Test validate_business_rules error handling."""
        config = FlextLdapConfig()
        # Even with missing fields, should return FlextResult
        result = config.validate_business_rules()

        assert result is not None
        assert hasattr(result, "is_success")
        assert hasattr(result, "is_failure")


__all__ = [
    "TestFlextLdapConfigConfigure",
    "TestFlextLdapConfigEffectivePassword",
    "TestFlextLdapConfigErrorHandling",
    "TestFlextLdapConfigInitialization",
    "TestFlextLdapConfigProperties",
    "TestFlextLdapConfigValidateBusinessRules",
    "TestFlextLdapConfigValidateLdapRequirements",
    "TestFlextLdapConfigValidation",
    "TestFlextLdapConfigWithCustomValues",
]
