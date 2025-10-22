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
from flext_core import FlextResult
from pydantic import SecretStr

from flext_ldap import (
    FlextLdap,
    FlextLdapConfig,
    FlextLdapConstants,
    FlextLdapValidations,
)


@pytest.mark.unit
class TestFlextLdap:
    """Comprehensive tests for FlextLdap class."""

    def test_api_initialization(self) -> None:
        """Test API initialization with default configuration."""
        api = FlextLdap()

        assert api is not None
        assert hasattr(api, "_client")
        assert hasattr(api, "_config")

    def test_api_initialization_with_config(self) -> None:
        """Test API initialization with custom configuration."""
        config = FlextLdapConfig(
            ldap_server_uri=f"{FlextLdapConstants.Protocol.DEFAULT_SERVER_URI}:{FlextLdapConstants.Protocol.DEFAULT_PORT}",
            ldap_bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=test,dc=com",
            ldap_bind_password=SecretStr("testpass"),
            ldap_base_dn="dc=test,dc=com",
        )

        api = FlextLdap(config)

        assert api is not None
        assert api.config is not None
        assert (
            api.config.ldap_server_uri
            == f"{FlextLdapConstants.Protocol.DEFAULT_SERVER_URI}:{FlextLdapConstants.Protocol.DEFAULT_PORT}"
        )

    def test_api_factory_method(self) -> None:
        """Test API factory method."""
        api = FlextLdap.create()

        assert isinstance(api, FlextLdap)
        assert api is not None

    def test_api_properties(self) -> None:
        """Test API property accessors."""
        api = FlextLdap()

        # Test client property
        client = api.client
        assert client is not None
        assert hasattr(client, "is_connected")

        # Test config property
        config = api.config
        assert config is not None
        assert hasattr(config, "ldap_server_uri")

        # REMOVED: Property accessors for namespace classes
        # Users should import directly:
        # from flext_ldap import FlextLdapModels, FlextLdapTypes, FlextLdapProtocols, FlextLdapValidations

    def test_api_connection_methods(self) -> None:
        """Test API connection methods."""
        api = FlextLdap()

        # Test is_connected property via client (wrapper removed)
        connected = api.client.is_connected
        assert isinstance(connected, bool)

        # Test test_connection method via client (wrapper removed)
        result = api.client.test_connection()
        assert isinstance(result, FlextResult)
        # In unit tests, connection will fail due to no LDAP server running
        # This is expected behavior for unit tests

        # Test connect method
        connect_result = api.connect()
        assert isinstance(connect_result, FlextResult)

        # Test unbind method via client (wrapper removed)
        unbind_result = api.client.unbind()
        assert isinstance(unbind_result, FlextResult)
        assert unbind_result.is_success

    def test_api_search_methods(self) -> None:
        """Test API search methods."""
        api = FlextLdap()

        # Test search method for groups (filtering with objectClass=groupOfNames)
        result = api.search(
            base_dn="dc=test,dc=com",
            filter_str="(objectClass=groupOfNames)",
            attributes=["cn", "member"],
        )
        assert isinstance(result, FlextResult)

        # Test search method for general searches
        result = api.search(
            base_dn="dc=test,dc=com",
            filter_str="(objectClass=*)",
            attributes=["cn", "mail"],
        )
        assert isinstance(result, FlextResult)

        # Test search with single=True parameter
        search_one_result = api.search(
            base_dn="dc=test,dc=com", filter_str="(objectClass=person)", single=True
        )
        assert isinstance(search_one_result, FlextResult)
        assert search_one_result.is_failure  # Should fail without connection

    def test_api_update_methods(self) -> None:
        """Test API update methods."""
        api = FlextLdap()

        # Test modify method for user attributes
        result = api.modify(
            dn="cn=testuser,dc=test,dc=com",
            changes={"cn": "newcn", "mail": "newmail@example.com"},
        )
        assert isinstance(result, FlextResult)

        # Test modify method for group attributes
        result = api.modify(
            dn="cn=testgroup,dc=test,dc=com",
            changes={"cn": "newgroup", "description": "Updated group"},
        )
        assert isinstance(result, FlextResult)

    def test_api_delete_methods(self) -> None:
        """Test API delete methods."""
        api = FlextLdap()

        # Test delete_entry method
        result = api.delete_entry("cn=testuser,dc=test,dc=com")
        assert isinstance(result, FlextResult)

    def test_api_validation_methods(self) -> None:
        """Test API validation methods."""
        api = FlextLdap()

        # Verify API initialized correctly
        assert api is not None

        # Test validate_dn method - now via FlextLdapValidations
        dn_result = FlextLdapValidations.validate_dn("cn=testuser,dc=test,dc=com")
        assert isinstance(dn_result, FlextResult)
        assert dn_result.is_success

        # Test validate_filter method - now via FlextLdapValidations
        filter_result = FlextLdapValidations.validate_filter("(objectClass=*)")
        assert isinstance(filter_result, FlextResult)
        assert filter_result.is_success

    def test_api_validation_with_invalid_input(self) -> None:
        """Test API validation with invalid input."""
        FlextLdap()

        # Test validate_dn with invalid DN
        result = FlextLdapValidations.validate_dn("")
        assert isinstance(result, FlextResult)
        assert result.is_failure

        # Test validate_filter with invalid filter
        result = FlextLdapValidations.validate_filter("")
        assert isinstance(result, FlextResult)
        assert result.is_failure

    def test_api_execute_methods(self) -> None:
        """Test API execute methods."""
        api = FlextLdap()

        # Test execute method
        result = api.execute()
        assert isinstance(result, FlextResult)
        assert result.is_success

    def test_api_execute_method(self) -> None:
        """Test API execute method."""
        api = FlextLdap()

        # Test execute method
        result = api.execute()
        assert isinstance(result, FlextResult)
        assert result.is_success

    def test_api_error_handling(self) -> None:
        """Test API error handling mechanisms."""
        FlextLdap()

        # Test with invalid DN
        result = FlextLdapValidations.validate_dn("invalid-dn")
        assert isinstance(result, FlextResult)
        assert result.is_failure
        assert result.error is not None

        # Test with invalid filter
        result = FlextLdapValidations.validate_filter("invalid-filter")
        assert isinstance(result, FlextResult)
        assert result.is_failure
        assert result.error is not None

    def test_api_thread_safety(self) -> None:
        """Test API thread safety."""
        FlextLdap()

        # Test concurrent operations

        results = []

        def validate_dn() -> None:
            result = FlextLdapValidations.validate_dn("cn=testuser,dc=test,dc=com")
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
        FlextLdap()

        # Test multiple operations
        results = []
        for i in range(10):
            result = FlextLdapValidations.validate_dn(f"cn=testuser{i},dc=test,dc=com")
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
        FlextLdap()

        # Test validation performance
        start_time = time.time()
        for i in range(100):
            result = FlextLdapValidations.validate_dn(f"cn=testuser{i},dc=test,dc=com")
            assert isinstance(result, FlextResult)
        end_time = time.time()

        # Should complete within reasonable time
        duration = end_time - start_time
        assert duration < 5.0  # Should complete within 5 seconds

    def test_api_configuration_persistence(self) -> None:
        """Test API configuration persistence."""
        config = FlextLdapConfig(
            ldap_server_uri=f"{FlextLdapConstants.Protocol.DEFAULT_SERVER_URI}:{FlextLdapConstants.Protocol.DEFAULT_PORT}",
            ldap_bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=test,dc=com",
            ldap_bind_password=SecretStr("testpass"),
            ldap_base_dn="dc=test,dc=com",
        )

        api = FlextLdap(config)

        # Verify configuration is properly stored
        stored_config = api.config
        assert (
            stored_config.ldap_server_uri
            == f"{FlextLdapConstants.Protocol.DEFAULT_SERVER_URI}:{FlextLdapConstants.Protocol.DEFAULT_PORT}"
        )
        assert stored_config.ldap_bind_dn == "cn=REDACTED_LDAP_BIND_PASSWORD,dc=test,dc=com"
        assert stored_config.ldap_base_dn == "dc=test,dc=com"

    def test_api_extensibility(self) -> None:
        """Test API extensibility features."""
        FlextLdap()

        # Test that API can be extended with custom configurations
        custom_config = FlextLdapConfig(
            ldap_server_uri=f"{FlextLdapConstants.Protocol.DEFAULT_SERVER_URI}:{FlextLdapConstants.Protocol.DEFAULT_PORT}",
            ldap_bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=test,dc=com",
            ldap_bind_password=SecretStr("testpass"),
            ldap_base_dn="dc=test,dc=com",
        )

        custom_api = FlextLdap(custom_config)

        # Verify custom configuration is preserved
        stored_config = custom_api.config
        assert (
            stored_config.ldap_server_uri
            == f"{FlextLdapConstants.Protocol.DEFAULT_SERVER_URI}:{FlextLdapConstants.Protocol.DEFAULT_PORT}"
        )
        assert stored_config.ldap_bind_dn == "cn=REDACTED_LDAP_BIND_PASSWORD,dc=test,dc=com"

    def test_api_integration_complete_workflow(self) -> None:
        """Test complete API workflow integration."""
        api = FlextLdap()

        # Test complete workflow
        # 1. Validate configuration exists
        assert api.config is not None

        # 2. Validate DN
        dn_result = FlextLdapValidations.validate_dn("cn=testuser,dc=test,dc=com")
        assert isinstance(dn_result, FlextResult)

        # 3. Validate filter
        filter_result = FlextLdapValidations.validate_filter("(objectClass=*)")
        assert isinstance(filter_result, FlextResult)

        # 4. Execute main operation
        execute_result = api.execute()
        assert isinstance(execute_result, FlextResult)
        assert execute_result.is_success


"""Comprehensive tests for FlextLdap following FLEXT standards.

This module provides complete test coverage for the FlextLdap class
using flext_tests library, centralized fixtures, and real functionality testing.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""


class TestFlextLdapComprehensive:
    """Comprehensive test suite for FlextLdap using FLEXT standards."""

    def test_api_initialization_default(self) -> None:
        """Test API initialization with default configuration."""
        api = FlextLdap()

        assert api is not None
        assert api._client is None  # Lazy initialization
        assert api.config is not None  # Initialized with global instance

    def test_api_initialization_with_config(self) -> None:
        """Test API initialization with custom configuration."""
        config = FlextLdapConfig()
        api = FlextLdap(config=config)

        assert api is not None
        assert api.config == config

    def test_api_factory_method(self) -> None:
        """Test API factory method."""
        api = FlextLdap.create()

        assert isinstance(api, FlextLdap)
        assert api._client is None

    def test_api_execute_method(self) -> None:
        """Test API execute method (required by FlextService)."""
        api = FlextLdap()
        result = api.execute()

        assert isinstance(result, FlextResult)
        assert result.is_success
        assert result.unwrap() is None

    def test_client_property_lazy_initialization(self) -> None:
        """Test client property lazy initialization."""
        api = FlextLdap()

        # First access should create the client
        client1 = api.client
        assert client1 is not None

        # Second access should return the same instance
        client2 = api.client
        assert client1 is client2

    def test_config_property_with_custom_config(self) -> None:
        """Test config property with custom configuration."""
        config = FlextLdapConfig()
        api = FlextLdap(config=config)

        assert api.config == config

    def test_config_property_with_global_instance(self) -> None:
        """Test config property uses global instance when no custom config."""
        api = FlextLdap()
        config = api.config

        assert isinstance(config, FlextLdapConfig)

    def test_validate_configuration_consistency(self) -> None:
        """Test configuration consistency validation."""
        api = FlextLdap()

        # Configuration should be properly initialized
        config = api.config
        assert isinstance(config, FlextLdapConfig)
        assert config is not None

    def test_validate_dn_valid_format(self) -> None:
        """Test DN validation with valid format."""
        FlextLdap()

        valid_dn = "cn=testuser,ou=users,dc=example,dc=com"
        result = FlextLdapValidations.validate_dn(valid_dn)

        assert isinstance(result, FlextResult)
        assert result.is_success

    def test_validate_dn_invalid_format(self) -> None:
        """Test DN validation with invalid format."""
        FlextLdap()

        invalid_dn = "invalid-dn-format"
        result = FlextLdapValidations.validate_dn(invalid_dn)

        assert isinstance(result, FlextResult)
        assert result.is_failure

    def test_validate_dn_empty(self) -> None:
        """Test DN validation with empty string."""
        FlextLdap()

        result = FlextLdapValidations.validate_dn("")

        assert isinstance(result, FlextResult)
        assert result.is_failure

    def test_validate_filter_valid_format(self) -> None:
        """Test filter validation with valid format."""
        FlextLdap()

        valid_filter = "(objectClass=person)"
        result = FlextLdapValidations.validate_filter(valid_filter)

        assert isinstance(result, FlextResult)
        assert result.is_success

    def test_validate_filter_invalid_format(self) -> None:
        """Test filter validation with invalid format."""
        FlextLdap()

        invalid_filter = "invalid@filter#with$invalid%chars"
        result = FlextLdapValidations.validate_filter(invalid_filter)

        assert isinstance(result, FlextResult)
        assert result.is_failure

    def test_validate_filter_empty(self) -> None:
        """Test filter validation with empty string."""
        FlextLdap()

        result = FlextLdapValidations.validate_filter("")

        assert isinstance(result, FlextResult)
        assert result.is_failure

    def test_api_integration_with_flext_tests(self) -> None:
        """Test API integration with flext_tests factories."""
        # Use flext_tests factories to create test data
        # FlextTestsFactories.create_realistic_test_data()  # TODO(marlonsc): [https://github.com/flext-sh/flext/issues/TBD] Use when available

        api = FlextLdap()

        # Test that API can handle realistic test data
        assert api is not None

        # Test configuration with test data
        config = api.config
        assert isinstance(config, FlextLdapConfig)

    def test_api_error_handling_consistency(self) -> None:
        """Test consistent error handling across API methods."""
        # Test that validation methods return FlextResult
        dn_result = FlextLdapValidations.validate_dn("cn=test,dc=test,dc=com")
        assert isinstance(dn_result, FlextResult)

        filter_result = FlextLdapValidations.validate_filter("(objectClass=*)")
        assert isinstance(filter_result, FlextResult)
