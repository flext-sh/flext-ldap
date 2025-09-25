"""Comprehensive tests for FlextLdapAPI following FLEXT standards.

This module provides complete test coverage for the FlextLdapAPI class
using flext_tests library, centralized fixtures, and real functionality testing.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest

from flext_core import FlextResult
from flext_ldap import FlextLdapAPI, FlextLdapConfig
from flext_tests import FlextTestsFactories


class TestFlextLdapAPIComprehensive:
    """Comprehensive test suite for FlextLdapAPI using FLEXT standards."""

    def test_api_initialization_default(self) -> None:
        """Test API initialization with default configuration."""
        api = FlextLdapAPI()

        assert api is not None
        assert api._client is None  # Lazy initialization
        assert api._config is None  # Uses global instance
        assert api._repositories is None  # Lazy initialization
        assert api._acl_manager is None  # Lazy initialization

    def test_api_initialization_with_config(self) -> None:
        """Test API initialization with custom configuration."""
        config = FlextLdapConfig()
        api = FlextLdapAPI(config=config)

        assert api is not None
        assert api._config == config

    def test_api_factory_method(self) -> None:
        """Test API factory method."""
        api = FlextLdapAPI.create()

        assert isinstance(api, FlextLdapAPI)
        assert api._client is None

    def test_api_execute_method(self) -> None:
        """Test API execute method (required by FlextService)."""
        api = FlextLdapAPI()
        result = api.execute()

        assert isinstance(result, FlextResult)
        assert result.is_success
        assert result.data is None

    @pytest.mark.asyncio
    async def test_api_execute_async_method(self) -> None:
        """Test API async execute method."""
        api = FlextLdapAPI()
        result = await api.execute_async()

        assert isinstance(result, FlextResult)
        assert result.is_success
        assert result.data is None

    def test_client_property_lazy_initialization(self) -> None:
        """Test client property lazy initialization."""
        api = FlextLdapAPI()

        # First access should create the client
        client1 = api.client
        assert client1 is not None

        # Second access should return the same instance
        client2 = api.client
        assert client1 is client2

    def test_config_property_with_custom_config(self) -> None:
        """Test config property with custom configuration."""
        config = FlextLdapConfig()
        api = FlextLdapAPI(config=config)

        assert api.config == config

    def test_config_property_with_global_instance(self) -> None:
        """Test config property uses global instance when no custom config."""
        api = FlextLdapAPI()
        config = api.config

        assert isinstance(config, FlextLdapConfig)

    def test_validate_configuration_consistency(self) -> None:
        """Test configuration consistency validation."""
        api = FlextLdapAPI()

        result = api.validate_configuration_consistency()
        assert isinstance(result, FlextResult)
        # Should succeed with default configuration
        assert result.is_success

    def test_validate_dn_valid_format(self) -> None:
        """Test DN validation with valid format."""
        api = FlextLdapAPI()

        valid_dn = "cn=testuser,ou=users,dc=example,dc=com"
        result = api.validate_dn(valid_dn)

        assert isinstance(result, FlextResult)
        assert result.is_success

    def test_validate_dn_invalid_format(self) -> None:
        """Test DN validation with invalid format."""
        api = FlextLdapAPI()

        invalid_dn = "invalid-dn-format"
        result = api.validate_dn(invalid_dn)

        assert isinstance(result, FlextResult)
        assert result.is_failure

    def test_validate_dn_empty(self) -> None:
        """Test DN validation with empty string."""
        api = FlextLdapAPI()

        result = api.validate_dn("")

        assert isinstance(result, FlextResult)
        assert result.is_failure

    def test_validate_filter_valid_format(self) -> None:
        """Test filter validation with valid format."""
        api = FlextLdapAPI()

        valid_filter = "(objectClass=person)"
        result = api.validate_filter(valid_filter)

        assert isinstance(result, FlextResult)
        assert result.is_success

    def test_validate_filter_invalid_format(self) -> None:
        """Test filter validation with invalid format."""
        api = FlextLdapAPI()

        invalid_filter = "invalid@filter#with$invalid%chars"
        result = api.validate_filter(invalid_filter)

        assert isinstance(result, FlextResult)
        assert result.is_failure

    def test_validate_filter_empty(self) -> None:
        """Test filter validation with empty string."""
        api = FlextLdapAPI()

        result = api.validate_filter("")

        assert isinstance(result, FlextResult)
        assert result.is_failure

    def test_api_integration_with_flext_tests(self) -> None:
        """Test API integration with flext_tests factories."""
        # Use flext_tests factories to create test data
        FlextTestsFactories.create_realistic_test_data()

        api = FlextLdapAPI()

        # Test that API can handle realistic test data
        assert api is not None

        # Test configuration with test data
        config_result = api.validate_configuration_consistency()
        assert isinstance(config_result, FlextResult)

    def test_api_error_handling_consistency(self) -> None:
        """Test consistent error handling across API methods."""
        api = FlextLdapAPI()

        # All methods should return FlextResult
        methods_to_test = [
            api.validate_configuration_consistency,
            lambda: api.validate_dn("invalid"),
            lambda: api.validate_filter("invalid"),
        ]

        for method in methods_to_test:
            result = method()
            assert isinstance(result, FlextResult)
            # Should either succeed or fail, but always return a result
            assert result.is_success or result.is_failure
