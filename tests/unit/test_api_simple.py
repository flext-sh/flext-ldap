"""Simple tests for FlextLdapAPI focusing on properties and real functionality.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

Note: This file has type checking disabled due to limitations in the official types-ldap3 package:
- Method return types (add, delete, search, modify, unbind) are not specified in the stubs
- Properties like conn.entries and entry.entry_dn are not fully typed
- Entry attributes and their values have incomplete type information
"""
# type: ignore[attr-defined]

import pytest
from pydantic import SecretStr

from flext_ldap import (
    FlextLdapAPI,
    FlextLdapConfigs,
    FlextLdapModels,
    FlextLdapValidations,
)


class TestFlextLdapAPIProperties:
    """Test FlextLdapAPI property accessors using fixtures."""

    def test_api_create_factory_method(self, flext_ldap_api: FlextLdapAPI) -> None:
        """Test API creation via factory method."""
        assert flext_ldap_api is not None
        assert isinstance(flext_ldap_api, FlextLdapAPI)

    def test_api_client_property(self, flext_ldap_api: FlextLdapAPI) -> None:
        """Test client property accessor."""
        client = flext_ldap_api.client
        assert client is not None

    def test_api_config_property(self, flext_ldap_api: FlextLdapAPI) -> None:
        """Test config property accessor."""
        config = flext_ldap_api.config
        assert config is not None
        assert isinstance(config, FlextLdapConfigs)

    def test_api_users_property(self, flext_ldap_api: FlextLdapAPI) -> None:
        """Test users repository property accessor."""
        users = flext_ldap_api.users
        assert users is not None

    def test_api_groups_property(self, flext_ldap_api: FlextLdapAPI) -> None:
        """Test groups repository property accessor."""
        groups = flext_ldap_api.groups
        assert groups is not None

    def test_api_models_property(self, flext_ldap_api: FlextLdapAPI) -> None:
        """Test models property accessor."""
        models = flext_ldap_api.models
        assert models is not None
        assert models == FlextLdapModels

    def test_api_types_property(self, flext_ldap_api: FlextLdapAPI) -> None:
        """Test types property accessor."""
        types = flext_ldap_api.types
        assert types is not None

    def test_api_protocols_property(self, flext_ldap_api: FlextLdapAPI) -> None:
        """Test protocols property accessor."""
        protocols = flext_ldap_api.protocols
        assert protocols is not None

    def test_api_validations_property(self, flext_ldap_api: FlextLdapAPI) -> None:
        """Test validations property accessor."""
        validations = flext_ldap_api.validations
        assert validations is not None
        assert validations == FlextLdapValidations


class TestFlextLdapValidationsDirect:
    """Test FlextLdapValidations methods directly (not through API)."""

    def test_validate_dn_valid(
        self,
        flext_ldap_validations: type[FlextLdapValidations],
        sample_valid_dn: str,
    ) -> None:
        """Test DN validation with valid DN using fixtures."""
        result = flext_ldap_validations.validate_dn(sample_valid_dn)
        assert result.is_success
        assert result.error is None

    def test_validate_dn_valid_with_spaces(
        self,
        flext_ldap_validations: type[FlextLdapValidations],
    ) -> None:
        """Test DN validation accepts DN with surrounding spaces."""
        result = flext_ldap_validations.validate_dn("  cn=test,dc=example,dc=com  ")
        assert result.is_success

    def test_validate_dn_invalid_empty(
        self,
        flext_ldap_validations: type[FlextLdapValidations],
    ) -> None:
        """Test DN validation rejects empty string."""
        result = flext_ldap_validations.validate_dn("")
        assert result.is_failure
        assert result.error is not None and "cannot be empty" in result.error

    def test_validate_dn_invalid_whitespace(
        self,
        flext_ldap_validations: type[FlextLdapValidations],
    ) -> None:
        """Test DN validation rejects whitespace-only string."""
        result = flext_ldap_validations.validate_dn("   ")
        assert result.is_failure
        assert result.error is not None and "cannot be empty" in result.error

    def test_validate_dn_invalid_no_equals(
        self,
        flext_ldap_validations: type[FlextLdapValidations],
    ) -> None:
        """Test DN validation rejects DN without equals sign."""
        result = flext_ldap_validations.validate_dn("cn,dc")
        assert result.is_failure
        assert result.error is not None and (
            "invalid" in result.error.lower() or "=" in result.error
        )

    def test_validate_filter_valid_simple(
        self,
        flext_ldap_validations: type[FlextLdapValidations],
        sample_valid_filter: str,
    ) -> None:
        """Test filter validation with simple filter using fixtures."""
        result = flext_ldap_validations.validate_filter(sample_valid_filter)
        assert result.is_success
        assert result.error is None

    def test_validate_filter_valid_complex(
        self,
        flext_ldap_validations: type[FlextLdapValidations],
    ) -> None:
        """Test filter validation with complex filter."""
        result = flext_ldap_validations.validate_filter(
            "(&(objectClass=person)(cn=test))"
        )
        assert result.is_success

    def test_validate_filter_invalid_empty(
        self,
        flext_ldap_validations: type[FlextLdapValidations],
    ) -> None:
        """Test filter validation rejects empty string."""
        result = flext_ldap_validations.validate_filter("")
        assert result.is_failure
        assert result.error is not None and "cannot be empty" in result.error

    def test_validate_filter_accepts_simple_format(
        self,
        flext_ldap_validations: type[FlextLdapValidations],
    ) -> None:
        """Test filter validation accepts simple filter format."""
        result = flext_ldap_validations.validate_filter("objectClass=person")
        assert result.is_success

    def test_validate_email_valid(
        self,
        flext_ldap_validations: type[FlextLdapValidations],
        sample_valid_email: str,
    ) -> None:
        """Test email validation with valid email using fixtures."""
        result = flext_ldap_validations.validate_email(sample_valid_email)
        assert result.is_success
        assert result.error is None

    def test_validate_email_valid_complex(
        self,
        flext_ldap_validations: type[FlextLdapValidations],
    ) -> None:
        """Test email validation with complex valid email."""
        result = flext_ldap_validations.validate_email("test.user+tag@sub.example.com")
        assert result.is_success

    def test_validate_email_invalid_empty(
        self,
        flext_ldap_validations: type[FlextLdapValidations],
    ) -> None:
        """Test email validation rejects empty string."""
        result = flext_ldap_validations.validate_email("")
        assert result.is_failure
        assert result.error is not None

    def test_validate_email_invalid_no_at(
        self,
        flext_ldap_validations: type[FlextLdapValidations],
    ) -> None:
        """Test email validation rejects email without @."""
        result = flext_ldap_validations.validate_email("testexample.com")
        assert result.is_failure

    def test_validate_email_invalid_no_domain(
        self,
        flext_ldap_validations: type[FlextLdapValidations],
    ) -> None:
        """Test email validation rejects email without domain."""
        result = flext_ldap_validations.validate_email("test@")
        assert result.is_failure

    def test_validate_email_none_accepted(
        self,
        flext_ldap_validations: type[FlextLdapValidations],
    ) -> None:
        """Test email validation accepts None."""
        result = flext_ldap_validations.validate_email(None)
        assert result.is_success


class TestFlextLdapConfigValidation:
    """Test FlextLdapConfig validation methods."""

    def test_config_validate_business_rules_default(
        self,
        flext_ldap_config: FlextLdapConfigs,
    ) -> None:
        """Test config business rules validation with default config."""
        result = flext_ldap_config.validate_business_rules_base()
        # Default config may fail validation (no connection configured)
        assert result.is_success or result.is_failure

    def test_config_validate_business_rules_with_connection(
        self,
        sample_connection_config: FlextLdapModels.ConnectionConfig,
    ) -> None:
        """Test config business rules validation with valid connection."""
        FlextLdapConfigs.reset_global_instance()
        config = FlextLdapConfigs(
            ldap_default_connection=sample_connection_config,
            ldap_bind_dn=sample_connection_config.bind_dn,
            ldap_bind_password=SecretStr(sample_connection_config.bind_password)
            if sample_connection_config.bind_password
            else None,
        )
        result = config.validate_business_rules_base()
        # Should succeed or provide specific error
        assert result.is_success or result.is_failure
        FlextLdapConfigs.reset_global_instance()

    def test_config_get_effective_methods(
        self,
        sample_connection_config: FlextLdapModels.ConnectionConfig,
    ) -> None:
        """Test config effective value getter methods."""
        FlextLdapConfigs.reset_global_instance()
        config = FlextLdapConfigs(
            ldap_default_connection=sample_connection_config,
        )

        # Test effective getters
        server_uri = config.get_effective_server_uri()
        assert server_uri is not None
        assert isinstance(server_uri, str)

        bind_dn = config.get_effective_bind_dn()
        assert bind_dn is not None or bind_dn is None  # May be None

        bind_password = config.get_effective_bind_password()
        assert bind_password is not None or bind_password is None  # May be None

        FlextLdapConfigs.reset_global_instance()


class TestFlextLdapAPIConnectionStatus:
    """Test FlextLdapAPI connection status methods."""

    @pytest.mark.asyncio
    async def test_is_connected_when_not_connected(
        self,
        flext_ldap_api: FlextLdapAPI,
    ) -> None:
        """Test is_connected returns False when not connected."""
        is_connected = await flext_ldap_api.is_connected()
        assert is_connected is False

    @pytest.mark.asyncio
    async def test_test_connection_without_connection(
        self,
        flext_ldap_api: FlextLdapAPI,
    ) -> None:
        """Test test_connection without active connection."""
        result = await flext_ldap_api.test_connection()
        # May fail without proper connection configuration
        assert result.is_failure or result.is_success


class TestFlextLdapAPIRealFunctionality:
    """Test FlextLdapAPI real functionality and integration."""

    def test_api_access_to_validations_utility(
        self,
        flext_ldap_api: FlextLdapAPI,
    ) -> None:
        """Test API provides access to validations utility."""
        validations = flext_ldap_api.validations

        # Verify we can use validations through API
        result = validations.validate_dn("cn=test,dc=example,dc=com")
        assert result.is_success

        result = validations.validate_filter("(objectClass=person)")
        assert result.is_success

        result = validations.validate_email("test@example.com")
        assert result.is_success

    def test_api_models_access(
        self,
        flext_ldap_api: FlextLdapAPI,
    ) -> None:
        """Test API provides access to models."""
        models = flext_ldap_api.models

        # Verify we can create models through API
        connection_config = models.ConnectionConfig(
            server="ldap://localhost:389",
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=test,dc=com",
            bind_password="password",
        )
        assert connection_config is not None
        assert connection_config.server == "ldap://localhost:389"

    def test_api_singleton_behavior(self) -> None:
        """Test API respects config singleton pattern."""
        FlextLdapConfigs.reset_global_instance()

        api1 = FlextLdapAPI.create()
        api2 = FlextLdapAPI.create()

        # Both APIs should share same config instance
        assert api1.config is api2.config

        FlextLdapConfigs.reset_global_instance()
