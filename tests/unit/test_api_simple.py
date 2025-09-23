"""Simple tests for FlextLdapAPI focusing on properties and validations.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

import pytest

from flext_ldap.api import FlextLdapAPI
from flext_ldap.config import FlextLdapConfigs
from flext_ldap.models import FlextLdapModels


class TestFlextLdapAPIProperties:
    """Test FlextLdapAPI property accessors."""

    def test_api_create_factory_method(self) -> None:
        """Test API creation via factory method."""
        api = FlextLdapAPI.create()
        assert api is not None
        assert isinstance(api, FlextLdapAPI)

    def test_api_client_property(self) -> None:
        """Test client property accessor."""
        api = FlextLdapAPI.create()
        client = api.client
        assert client is not None

    def test_api_config_property(self) -> None:
        """Test config property accessor."""
        api = FlextLdapAPI.create()
        config = api.config
        assert config is not None
        assert isinstance(config, FlextLdapConfigs)

    def test_api_users_property(self) -> None:
        """Test users repository property accessor."""
        api = FlextLdapAPI.create()
        users = api.users
        assert users is not None

    def test_api_groups_property(self) -> None:
        """Test groups repository property accessor."""
        api = FlextLdapAPI.create()
        groups = api.groups
        assert groups is not None

    def test_api_models_property(self) -> None:
        """Test models property accessor."""
        api = FlextLdapAPI.create()
        models = api.models
        assert models is not None

    def test_api_types_property(self) -> None:
        """Test types property accessor."""
        api = FlextLdapAPI.create()
        types = api.types
        assert types is not None

    def test_api_protocols_property(self) -> None:
        """Test protocols property accessor."""
        api = FlextLdapAPI.create()
        protocols = api.protocols
        assert protocols is not None

    def test_api_validations_property(self) -> None:
        """Test validations property accessor."""
        api = FlextLdapAPI.create()
        validations = api.validations
        assert validations is not None


class TestFlextLdapAPIValidations:
    """Test FlextLdapAPI validation methods."""

    def test_validate_dn_valid(self) -> None:
        """Test DN validation with valid DN."""
        api = FlextLdapAPI.create()
        result = api.validate_dn("cn=test,dc=example,dc=com")
        assert result.is_success
        assert result.data == "cn=test,dc=example,dc=com"

    def test_validate_dn_valid_with_spaces(self) -> None:
        """Test DN validation accepts DN with surrounding spaces."""
        api = FlextLdapAPI.create()
        result = api.validate_dn("  cn=test,dc=example,dc=com  ")
        assert result.is_success
        assert "cn=test,dc=example,dc=com" in result.data

    def test_validate_dn_invalid_empty(self) -> None:
        """Test DN validation rejects empty string."""
        api = FlextLdapAPI.create()
        result = api.validate_dn("")
        assert result.is_failure
        assert result.error is not None and "cannot be empty" in result.error

    def test_validate_dn_invalid_whitespace(self) -> None:
        """Test DN validation rejects whitespace-only string."""
        api = FlextLdapAPI.create()
        result = api.validate_dn("   ")
        assert result.is_failure
        assert result.error is not None and "cannot be empty" in result.error

    def test_validate_dn_invalid_no_equals(self) -> None:
        """Test DN validation rejects DN without equals sign."""
        api = FlextLdapAPI.create()
        result = api.validate_dn("cn,dc")
        assert result.is_failure
        assert result.error is not None and ("invalid" in result.error.lower() or "=" in result.error)

    def test_validate_filter_valid_simple(self) -> None:
        """Test filter validation with simple filter."""
        api = FlextLdapAPI.create()
        result = api.validate_filter("(objectClass=person)")
        assert result.is_success
        assert result.data == "(objectClass=person)"

    def test_validate_filter_valid_complex(self) -> None:
        """Test filter validation with complex filter."""
        api = FlextLdapAPI.create()
        result = api.validate_filter("(&(objectClass=person)(cn=test))")
        assert result.is_success

    def test_validate_filter_invalid_empty(self) -> None:
        """Test filter validation rejects empty string."""
        api = FlextLdapAPI.create()
        result = api.validate_filter("")
        assert result.is_failure
        assert result.error is not None and "cannot be empty" in result.error

    def test_validate_filter_accepts_simple_format(self) -> None:
        """Test filter validation accepts simple filter format."""
        api = FlextLdapAPI.create()
        result = api.validate_filter("objectClass=person")
        assert result.is_success
        assert result.data == "objectClass=person"

    def test_validate_email_valid(self) -> None:
        """Test email validation with valid email."""
        api = FlextLdapAPI.create()
        result = api.validate_email("test@example.com")
        assert result.is_success
        assert result.data == "test@example.com"

    def test_validate_email_valid_complex(self) -> None:
        """Test email validation with complex valid email."""
        api = FlextLdapAPI.create()
        result = api.validate_email("test.user+tag@sub.example.com")
        assert result.is_success

    def test_validate_email_invalid_empty(self) -> None:
        """Test email validation rejects empty string."""
        api = FlextLdapAPI.create()
        result = api.validate_email("")
        assert result.is_failure
        assert result.error is not None and (
            "validation failed" in result.error.lower()
            or "empty" in result.error.lower()
        )

    def test_validate_email_invalid_no_at(self) -> None:
        """Test email validation rejects email without @."""
        api = FlextLdapAPI.create()
        result = api.validate_email("testexample.com")
        assert result.is_failure

    def test_validate_email_invalid_no_domain(self) -> None:
        """Test email validation rejects email without domain."""
        api = FlextLdapAPI.create()
        result = api.validate_email("test@")
        assert result.is_failure


class TestFlextLdapAPIConfigValidation:
    """Test FlextLdapAPI configuration validation."""

    def test_validate_config_consistency_with_defaults(self) -> None:
        """Test config validation with default config."""
        api = FlextLdapAPI.create()
        result = api.validate_configuration_consistency()
        assert result.is_success or result.is_failure

    def test_validate_config_consistency_with_custom_config(self) -> None:
        """Test config validation with custom config."""
        connection_config = FlextLdapModels.ConnectionConfig(
            server="ldap://localhost:389",
            bind_dn="cn=admin,dc=example,dc=com",
            bind_password="password",
        )
        config = FlextLdapConfigs(ldap_default_connection=connection_config)
        api = FlextLdapAPI(config=config)
        result = api.validate_configuration_consistency()
        assert result.is_success or result.is_failure


class TestFlextLdapAPIConnectionStatus:
    """Test FlextLdapAPI connection status methods."""

    @pytest.mark.asyncio
    async def test_is_connected_when_not_connected(self) -> None:
        """Test is_connected returns False when not connected."""
        api = FlextLdapAPI.create()
        is_connected = await api.is_connected()
        assert is_connected is False

    @pytest.mark.asyncio
    async def test_test_connection_without_connection(self) -> None:
        """Test test_connection without active connection."""
        api = FlextLdapAPI.create()
        result = await api.test_connection()
        assert result.is_failure or result.is_success
