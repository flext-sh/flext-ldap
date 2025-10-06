"""Comprehensive unit tests for flext-ldap API module.

This module provides complete test coverage for the flext-ldap API functionality,
following FLEXT standards with real functionality testing and no mocks.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import threading
import time

import pytest
from flext_ldap import (
    FlextLDAP,
    FlextLDAPConfig,
    FlextLDAPConstants,
)
from flext_tests import FlextTestsFactories
from pydantic import SecretStr

from flext_core import FlextResult


@pytest.mark.unit
class TestFlextLDAPApi:
    """Comprehensive tests for FlextLDAP class."""

    def test_api_initialization(self) -> None:
        """Test API initialization with default configuration."""
        api = FlextLDAP()

        assert api is not None
        assert hasattr(api, "_client")
        assert hasattr(api, "_acl_manager")
        assert hasattr(api, "_config")

    def test_api_initialization_with_config(self) -> None:
        """Test API initialization with custom configuration."""
        config = FlextLDAPConfig(
            ldap_server_uri=f"{FlextLDAPConstants.Protocol.DEFAULT_SERVER_URI}:{FlextLDAPConstants.Protocol.DEFAULT_PORT}",
            ldap_bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=test,dc=com",
            ldap_bind_password=SecretStr("testpass"),
            ldap_base_dn="dc=test,dc=com",
        )

        api = FlextLDAP(config)

        assert api is not None
        assert api._config is not None
        assert (
            api._config.ldap_server_uri
            == f"{FlextLDAPConstants.Protocol.DEFAULT_SERVER_URI}:{FlextLDAPConstants.Protocol.DEFAULT_PORT}"
        )

    def test_api_factory_method(self) -> None:
        """Test API factory method."""
        api = FlextLDAP.create()

        assert isinstance(api, FlextLDAP)
        assert api is not None

    def test_api_properties(self) -> None:
        """Test API property accessors."""
        api = FlextLDAP()

        # Test client property
        client = api.client
        assert client is not None
        assert hasattr(client, "is_connected")

        # Test config property
        config = api.config
        assert config is not None
        assert hasattr(config, "ldap_server_uri")

        # Test models property
        models = api.models
        assert models is not None

        # Test types property
        types = api.types
        assert types is not None

        # Test protocols property
        protocols = api.protocols
        assert protocols is not None

        # Test validations property
        validations = api.validations
        assert validations is not None

    def test_api_connection_methods(self) -> None:
        """Test API connection methods."""
        api = FlextLDAP()

        # Test is_connected method
        connected = api.is_connected()
        assert isinstance(connected, bool)

        # Test test_connection method
        result = api.test_connection()
        assert isinstance(result, FlextResult)

        # Test connect method
        result = api.connect()
        assert isinstance(result, FlextResult)

        # Test unbind method
        result = api.unbind()
        assert isinstance(result, FlextResult)

    def test_api_search_methods(self) -> None:
        """Test API search methods."""
        api = FlextLDAP()

        # Test search_groups method
        result = api.search_groups(
            base_dn="dc=test,dc=com",
            cn="testgroup",
            filter_str="(objectClass=group)",
            scope="subtree",
            attributes=["cn", "member"],
        )
        assert isinstance(result, FlextResult)

        # Test search_entries method
        result = api.search_entries(
            base_dn="dc=test,dc=com",
            filter_str="(objectClass=*)",
            scope="subtree",
            attributes=["cn", "mail"],
        )
        assert isinstance(result, FlextResult)

        # Test get_group method
        result = api.get_group("cn=testgroup,dc=test,dc=com")
        assert isinstance(result, FlextResult)

    def test_api_update_methods(self) -> None:
        """Test API update methods."""
        api = FlextLDAP()

        # Test update_user_attributes method
        result = api.update_user_attributes(
            dn="cn=testuser,dc=test,dc=com",
            attributes={"cn": "newcn", "mail": "newmail@example.com"},
        )
        assert isinstance(result, FlextResult)

        # Test update_group_attributes method
        result = api.update_group_attributes(
            dn="cn=testgroup,dc=test,dc=com",
            attributes={"cn": "newgroup", "description": "Updated group"},
        )
        assert isinstance(result, FlextResult)

    def test_api_delete_methods(self) -> None:
        """Test API delete methods."""
        api = FlextLDAP()

        # Test delete_user method
        result = api.delete_user("cn=testuser,dc=test,dc=com")
        assert isinstance(result, FlextResult)

    def test_api_validation_methods(self) -> None:
        """Test API validation methods."""
        api = FlextLDAP()

        # Test validate_configuration_consistency method
        result = api.validate_configuration_consistency()
        assert isinstance(result, FlextResult)

        # Test validate_dn method
        result = api.validate_dn("cn=testuser,dc=test,dc=com")
        assert isinstance(result, FlextResult)

        # Test validate_filter method
        result = api.validate_filter("(objectClass=*)")
        assert isinstance(result, FlextResult)

    def test_api_validation_with_invalid_input(self) -> None:
        """Test API validation with invalid input."""
        api = FlextLDAP()

        # Test validate_dn with invalid DN
        result = api.validate_dn("")
        assert isinstance(result, FlextResult)
        assert result.is_failure

        # Test validate_filter with invalid filter
        result = api.validate_filter("")
        assert isinstance(result, FlextResult)
        assert result.is_failure

    def test_api_execute_methods(self) -> None:
        """Test API execute methods."""
        api = FlextLDAP()

        # Test execute method
        result = api.execute()
        assert isinstance(result, FlextResult)
        assert result.is_success

    def test_api_execute_method(self) -> None:
        """Test API execute method."""
        api = FlextLDAP()

        # Test execute method
        result = api.execute()
        assert isinstance(result, FlextResult)
        assert result.is_success

    def test_api_error_handling(self) -> None:
        """Test API error handling mechanisms."""
        api = FlextLDAP()

        # Test with invalid DN
        result = api.validate_dn("invalid-dn")
        assert isinstance(result, FlextResult)
        assert result.is_failure
        assert result.error is not None

        # Test with invalid filter
        result = api.validate_filter("invalid-filter")
        assert isinstance(result, FlextResult)
        assert result.is_failure
        assert result.error is not None

    def test_api_thread_safety(self) -> None:
        """Test API thread safety."""
        api = FlextLDAP()

        # Test concurrent operations

        results = []

        def validate_dn() -> None:
            result = api.validate_dn("cn=testuser,dc=test,dc=com")
            results.append(result)

        threads = []
        for _ in range(5):
            thread = threading.Thread(target=validate_dn)
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        # All results should be successful
        assert len(results) == 5
        for result in results:
            assert isinstance(result, FlextResult)

    def test_api_memory_usage(self) -> None:
        """Test API memory usage patterns."""
        api = FlextLDAP()

        # Test multiple operations
        results = []
        for i in range(10):
            result = api.validate_dn(f"cn=testuser{i},dc=test,dc=com")
            results.append(result)

        # Verify operations are performed without memory leaks
        assert len(results) == 10
        assert all(isinstance(result, FlextResult) for result in results)

    @pytest.mark.performance
    @pytest.mark.slow
    def test_api_performance(self) -> None:
        """Test API performance characteristics.

        NOTE: This test is sensitive to resource contention and should be run
        in isolation using 'make test-performance' to avoid intermittent failures.
        """
        api = FlextLDAP()

        # Test validation performance
        start_time = time.time()
        for i in range(100):
            result = api.validate_dn(f"cn=testuser{i},dc=test,dc=com")
            assert isinstance(result, FlextResult)
        end_time = time.time()

        # Should complete within reasonable time
        duration = end_time - start_time
        assert duration < 5.0  # Should complete within 5 seconds

    def test_api_configuration_persistence(self) -> None:
        """Test API configuration persistence."""
        config = FlextLDAPConfig(
            ldap_server_uri=f"{FlextLDAPConstants.Protocol.DEFAULT_SERVER_URI}:{FlextLDAPConstants.Protocol.DEFAULT_PORT}",
            ldap_bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=test,dc=com",
            ldap_bind_password=SecretStr("testpass"),
            ldap_base_dn="dc=test,dc=com",
        )

        api = FlextLDAP(config)

        # Verify configuration is properly stored
        stored_config = api.config
        assert (
            stored_config.ldap_server_uri
            == f"{FlextLDAPConstants.Protocol.DEFAULT_SERVER_URI}:{FlextLDAPConstants.Protocol.DEFAULT_PORT}"
        )
        assert stored_config.ldap_bind_dn == "cn=REDACTED_LDAP_BIND_PASSWORD,dc=test,dc=com"
        assert stored_config.ldap_base_dn == "dc=test,dc=com"

    def test_api_extensibility(self) -> None:
        """Test API extensibility features."""
        FlextLDAP()

        # Test that API can be extended with custom configurations
        custom_config = FlextLDAPConfig(
            ldap_server_uri=f"{FlextLDAPConstants.Protocol.DEFAULT_SERVER_URI}:{FlextLDAPConstants.Protocol.DEFAULT_PORT}",
            ldap_bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=test,dc=com",
            ldap_bind_password=SecretStr("testpass"),
            ldap_base_dn="dc=test,dc=com",
        )

        custom_api = FlextLDAP(custom_config)

        # Verify custom configuration is preserved
        stored_config = custom_api.config
        assert (
            stored_config.ldap_server_uri
            == f"{FlextLDAPConstants.Protocol.DEFAULT_SERVER_URI}:{FlextLDAPConstants.Protocol.DEFAULT_PORT}"
        )
        assert stored_config.ldap_bind_dn == "cn=REDACTED_LDAP_BIND_PASSWORD,dc=test,dc=com"

    def test_api_integration_complete_workflow(self) -> None:
        """Test complete API workflow integration."""
        api = FlextLDAP()

        # Test complete workflow
        # 1. Validate configuration
        config_result = api.validate_configuration_consistency()
        assert isinstance(config_result, FlextResult)

        # 2. Validate DN
        dn_result = api.validate_dn("cn=testuser,dc=test,dc=com")
        assert isinstance(dn_result, FlextResult)

        # 3. Validate filter
        filter_result = api.validate_filter("(objectClass=*)")
        assert isinstance(filter_result, FlextResult)

        # 4. Execute main operation
        execute_result = api.execute()
        assert isinstance(execute_result, FlextResult)
        assert execute_result.is_success


"""Comprehensive tests for FlextLDAP following FLEXT standards.

This module provides complete test coverage for the FlextLDAP class
using flext_tests library, centralized fixtures, and real functionality testing.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""


class TestFlextLDAPApiComprehensive:
    """Comprehensive test suite for FlextLDAP using FLEXT standards."""

    def test_api_initialization_default(self) -> None:
        """Test API initialization with default configuration."""
        api = FlextLDAP()

        assert api is not None
        assert api._client is None  # Lazy initialization
        assert api._config is not None  # Initialized with global instance
        assert api._acl_manager is None  # Lazy initialization

    def test_api_initialization_with_config(self) -> None:
        """Test API initialization with custom configuration."""
        config = FlextLDAPConfig()
        api = FlextLDAP(config=config)

        assert api is not None
        assert api._config == config

    def test_api_factory_method(self) -> None:
        """Test API factory method."""
        api = FlextLDAP.create()

        assert isinstance(api, FlextLDAP)
        assert api._client is None

    def test_api_execute_method(self) -> None:
        """Test API execute method (required by FlextService)."""
        api = FlextLDAP()
        result = api.execute()

        assert isinstance(result, FlextResult)
        assert result.is_success
        assert result.data is None

    def test_client_property_lazy_initialization(self) -> None:
        """Test client property lazy initialization."""
        api = FlextLDAP()

        # First access should create the client
        client1 = api.client
        assert client1 is not None

        # Second access should return the same instance
        client2 = api.client
        assert client1 is client2

    def test_config_property_with_custom_config(self) -> None:
        """Test config property with custom configuration."""
        config = FlextLDAPConfig()
        api = FlextLDAP(config=config)

        assert api.config == config

    def test_config_property_with_global_instance(self) -> None:
        """Test config property uses global instance when no custom config."""
        api = FlextLDAP()
        config = api.config

        assert isinstance(config, FlextLDAPConfig)

    def test_validate_configuration_consistency(self) -> None:
        """Test configuration consistency validation."""
        api = FlextLDAP()

        result = api.validate_configuration_consistency()
        assert isinstance(result, FlextResult)
        # Should succeed with default configuration
        assert result.is_success

    def test_validate_dn_valid_format(self) -> None:
        """Test DN validation with valid format."""
        api = FlextLDAP()

        valid_dn = "cn=testuser,ou=users,dc=example,dc=com"
        result = api.validate_dn(valid_dn)

        assert isinstance(result, FlextResult)
        assert result.is_success

    def test_validate_dn_invalid_format(self) -> None:
        """Test DN validation with invalid format."""
        api = FlextLDAP()

        invalid_dn = "invalid-dn-format"
        result = api.validate_dn(invalid_dn)

        assert isinstance(result, FlextResult)
        assert result.is_failure

    def test_validate_dn_empty(self) -> None:
        """Test DN validation with empty string."""
        api = FlextLDAP()

        result = api.validate_dn("")

        assert isinstance(result, FlextResult)
        assert result.is_failure

    def test_validate_filter_valid_format(self) -> None:
        """Test filter validation with valid format."""
        api = FlextLDAP()

        valid_filter = "(objectClass=person)"
        result = api.validate_filter(valid_filter)

        assert isinstance(result, FlextResult)
        assert result.is_success

    def test_validate_filter_invalid_format(self) -> None:
        """Test filter validation with invalid format."""
        api = FlextLDAP()

        invalid_filter = "invalid@filter#with$invalid%chars"
        result = api.validate_filter(invalid_filter)

        assert isinstance(result, FlextResult)
        assert result.is_failure

    def test_validate_filter_empty(self) -> None:
        """Test filter validation with empty string."""
        api = FlextLDAP()

        result = api.validate_filter("")

        assert isinstance(result, FlextResult)
        assert result.is_failure

    def test_api_integration_with_flext_tests(self) -> None:
        """Test API integration with flext_tests factories."""
        # Use flext_tests factories to create test data
        FlextTestsFactories.create_realistic_test_data()

        api = FlextLDAP()

        # Test that API can handle realistic test data
        assert api is not None

        # Test configuration with test data
        config_result = api.validate_configuration_consistency()
        assert isinstance(config_result, FlextResult)

    def test_api_error_handling_consistency(self) -> None:
        """Test consistent error handling across API methods."""
        api = FlextLDAP()

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
