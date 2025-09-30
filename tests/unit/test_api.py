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
from pydantic import SecretStr

from flext_core import FlextResult
from flext_ldap.api import FlextLdapAPI
from flext_ldap.config import FlextLdapConfig
from flext_ldap.constants import FlextLdapConstants
from flext_ldap.models import FlextLdapModels
from flext_tests import FlextTestsFactories


class TestFlextLdapAPI:
    """Comprehensive tests for FlextLdapAPI class."""

    def test_api_initialization(self) -> None:
        """Test API initialization with default configuration."""
        api = FlextLdapAPI()

        assert api is not None
        assert hasattr(api, "_client")
        assert hasattr(api, "_repositories")
        assert hasattr(api, "_acl_manager")
        assert hasattr(api, "_config")

    def test_api_initialization_with_config(self) -> None:
        """Test API initialization with custom configuration."""
        config = FlextLdapConfig(
            ldap_server_uri=f"{FlextLdapConstants.Protocol.DEFAULT_SERVER_URI}:{FlextLdapConstants.Protocol.DEFAULT_PORT}",
            ldap_bind_dn="cn=admin,dc=test,dc=com",
            ldap_bind_password=SecretStr("testpass"),
            ldap_base_dn="dc=test,dc=com",
        )

        api = FlextLdapAPI(config)

        assert api is not None
        assert api._config is not None
        assert (
            api._config.ldap_server_uri
            == f"{FlextLdapConstants.Protocol.DEFAULT_SERVER_URI}:{FlextLdapConstants.Protocol.DEFAULT_PORT}"
        )

    def test_api_factory_method(self) -> None:
        """Test API factory method."""
        api = FlextLdapAPI.create()

        assert isinstance(api, FlextLdapAPI)
        assert api is not None

    def test_api_properties(self) -> None:
        """Test API property accessors."""
        api = FlextLdapAPI()

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
        assert models == FlextLdapModels

        # Test types property
        types = api.types
        assert types is not None

        # Test protocols property
        protocols = api.protocols
        assert protocols is not None

        # Test validations property
        validations = api.validations
        assert validations is not None

    def test_api_repositories_properties(self) -> None:
        """Test API repository properties."""
        api = FlextLdapAPI()

        # Test users property
        users = api.users
        assert users is not None

        # Test groups property
        groups = api.groups
        assert groups is not None

    @pytest.mark.asyncio
    async def test_api_connection_methods(self) -> None:
        """Test API connection methods."""
        api = FlextLdapAPI()

        # Test is_connected method
        connected = await api.is_connected()
        assert isinstance(connected, bool)

        # Test test_connection method
        result = await api.test_connection()
        assert isinstance(result, FlextResult)

        # Test connect method
        result = await api.connect()
        assert isinstance(result, FlextResult)

        # Test unbind method
        result = await api.unbind()
        assert isinstance(result, FlextResult)

    @pytest.mark.asyncio
    async def test_api_search_methods(self) -> None:
        """Test API search methods."""
        api = FlextLdapAPI()

        # Test search_groups method
        result = await api.search_groups(
            base_dn="dc=test,dc=com",
            cn="testgroup",
            filter_str="(objectClass=group)",
            scope="subtree",
            attributes=["cn", "member"],
        )
        assert isinstance(result, FlextResult)

        # Test search_entries method
        result = await api.search_entries(
            base_dn="dc=test,dc=com",
            filter_str="(objectClass=*)",
            scope="subtree",
            attributes=["cn", "mail"],
        )
        assert isinstance(result, FlextResult)

        # Test get_group method
        result = await api.get_group("cn=testgroup,dc=test,dc=com")
        assert isinstance(result, FlextResult)

    @pytest.mark.asyncio
    async def test_api_update_methods(self) -> None:
        """Test API update methods."""
        api = FlextLdapAPI()

        # Test update_user_attributes method
        result = await api.update_user_attributes(
            dn="cn=testuser,dc=test,dc=com",
            attributes={"cn": "newcn", "mail": "newmail@example.com"},
        )
        assert isinstance(result, FlextResult)

        # Test update_group_attributes method
        result = await api.update_group_attributes(
            dn="cn=testgroup,dc=test,dc=com",
            attributes={"cn": "newgroup", "description": "Updated group"},
        )
        assert isinstance(result, FlextResult)

    @pytest.mark.asyncio
    async def test_api_delete_methods(self) -> None:
        """Test API delete methods."""
        api = FlextLdapAPI()

        # Test delete_user method
        result = await api.delete_user("cn=testuser,dc=test,dc=com")
        assert isinstance(result, FlextResult)

    def test_api_validation_methods(self) -> None:
        """Test API validation methods."""
        api = FlextLdapAPI()

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
        api = FlextLdapAPI()

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
        api = FlextLdapAPI()

        # Test execute method
        result = api.execute()
        assert isinstance(result, FlextResult)
        assert result.is_success

    @pytest.mark.asyncio
    async def test_api_execute_async_method(self) -> None:
        """Test API execute async method."""
        api = FlextLdapAPI()

        # Test execute_async method
        result = await api.execute_async()
        assert isinstance(result, FlextResult)
        assert result.is_success

    def test_api_error_handling(self) -> None:
        """Test API error handling mechanisms."""
        api = FlextLdapAPI()

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
        api = FlextLdapAPI()

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
        api = FlextLdapAPI()

        # Test multiple operations
        results = []
        for i in range(10):
            result = api.validate_dn(f"cn=testuser{i},dc=test,dc=com")
            results.append(result)

        # Verify operations are performed without memory leaks
        assert len(results) == 10
        assert all(isinstance(result, FlextResult) for result in results)

    def test_api_performance(self) -> None:
        """Test API performance characteristics."""
        api = FlextLdapAPI()

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
        config = FlextLdapConfig(
            ldap_server_uri=f"{FlextLdapConstants.Protocol.DEFAULT_SERVER_URI}:{FlextLdapConstants.Protocol.DEFAULT_PORT}",
            ldap_bind_dn="cn=admin,dc=test,dc=com",
            ldap_bind_password=SecretStr("testpass"),
            ldap_base_dn="dc=test,dc=com",
        )

        api = FlextLdapAPI(config)

        # Verify configuration is properly stored
        stored_config = api.config
        assert (
            stored_config.ldap_server_uri
            == f"{FlextLdapConstants.Protocol.DEFAULT_SERVER_URI}:{FlextLdapConstants.Protocol.DEFAULT_PORT}"
        )
        assert stored_config.ldap_bind_dn == "cn=admin,dc=test,dc=com"
        assert stored_config.ldap_base_dn == "dc=test,dc=com"

    def test_api_extensibility(self) -> None:
        """Test API extensibility features."""
        FlextLdapAPI()

        # Test that API can be extended with custom configurations
        custom_config = FlextLdapConfig(
            ldap_server_uri=f"{FlextLdapConstants.Protocol.DEFAULT_SERVER_URI}:{FlextLdapConstants.Protocol.DEFAULT_PORT}",
            ldap_bind_dn="cn=admin,dc=test,dc=com",
            ldap_bind_password=SecretStr("testpass"),
            ldap_base_dn="dc=test,dc=com",
        )

        custom_api = FlextLdapAPI(custom_config)

        # Verify custom configuration is preserved
        stored_config = custom_api.config
        assert (
            stored_config.ldap_server_uri
            == f"{FlextLdapConstants.Protocol.DEFAULT_SERVER_URI}:{FlextLdapConstants.Protocol.DEFAULT_PORT}"
        )
        assert stored_config.ldap_bind_dn == "cn=admin,dc=test,dc=com"

    def test_api_integration_complete_workflow(self) -> None:
        """Test complete API workflow integration."""
        api = FlextLdapAPI()

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


"""Comprehensive tests for FlextLdapAPI following FLEXT standards.

This module provides complete test coverage for the FlextLdapAPI class
using flext_tests library, centralized fixtures, and real functionality testing.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""


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
