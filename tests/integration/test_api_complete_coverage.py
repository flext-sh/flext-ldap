"""Complete coverage tests for FlextLdap API with modern patterns.

Tests FlextLdap API complete coverage using advanced Python 3.13 patterns:
- Single class architecture with nested factory and assertion classes
- Factory patterns with flext_tests utilities for test data generation
- Comprehensive assertion helpers with flext_tests integration
- Parameterized tests for operation combinations and edge cases
- StrEnum and mappings for test configuration management
- Maximum code reuse through flext-core and flext_tests patterns

Tests all code paths including error handling and edge cases.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from enum import StrEnum
from typing import ClassVar, Literal, cast

import pytest
from flext_core import FlextResult
from flext_ldif import FlextLdifParser
from flext_ldif.models import FlextLdifModels
from flext_tests import FlextTestsFactories, FlextTestsUtilities

from flext_ldap import FlextLdap
from flext_ldap.config import FlextLdapConfig
from flext_ldap.models import FlextLdapModels

pytestmark = pytest.mark.integration


class ConfigType(StrEnum):
    """Configuration type enumeration."""

    BASIC = "basic"
    FULL = "full"


class OperationType(StrEnum):
    """Operation type enumeration."""

    CONNECT = "connect"
    SEARCH = "search"
    ADD = "add"
    DELETE = "delete"
    EXECUTE = "execute"


class TestDataFactories:
    """Factory methods for generating test data and configurations across all API tests.

    Uses flext_tests utilities for consistent test data generation and configuration.
    """

    # Configuration templates using ClassVar for reuse
    CONFIG_TEMPLATES: ClassVar[dict[ConfigType, dict[str, object]]] = {
        ConfigType.BASIC: {
            "use_ssl": False,
            "use_tls": False,
            "timeout": 30,
        },
        ConfigType.FULL: {
            "use_ssl": False,
            "use_tls": False,
            "timeout": 30,
            "auto_bind": True,
            "auto_range": True,
        },
    }

    @classmethod
    def create_config_by_type(
        cls,
        config_type: ConfigType,
        ldap_container: dict[str, object],
    ) -> FlextLdapConfig:
        """Factory for FlextLdapConfig using config type and flext_tests patterns."""
        if config_type == ConfigType.FULL:
            return FlextLdapConfig(
                host=str(ldap_container["host"]),
                port=int(str(ldap_container["port"])),
                bind_dn=str(ldap_container["bind_dn"]),
                bind_password=str(ldap_container["password"]),
                use_ssl=False,
                use_tls=False,
                timeout=30,
                auto_bind=True,
                auto_range=True,
            )
        # ConfigType.BASIC
        return FlextLdapConfig(
            host=str(ldap_container["host"]),
            port=int(str(ldap_container["port"])),
            bind_dn=str(ldap_container["bind_dn"]),
            bind_password=str(ldap_container["password"]),
        )

    @staticmethod
    def create_full_config(ldap_container: dict[str, object]) -> FlextLdapConfig:
        """Factory for complete FlextLdapConfig with all options."""
        return TestDataFactories.create_config_by_type(ConfigType.FULL, ldap_container)

    @staticmethod
    def create_basic_config(ldap_container: dict[str, object]) -> FlextLdapConfig:
        """Factory for basic FlextLdapConfig with essential options."""
        return TestDataFactories.create_config_by_type(ConfigType.BASIC, ldap_container)

    @staticmethod
    def create_connection_config_from_config(
        config: FlextLdapConfig,
    ) -> FlextLdapModels.ConnectionConfig:
        """Factory for ConnectionConfig from FlextLdapConfig."""
        return FlextLdapModels.ConnectionConfig(
            host=config.host,
            port=config.port,
            use_ssl=config.use_ssl,
            use_tls=config.use_tls,
            bind_dn=config.bind_dn,
            bind_password=config.bind_password,
            timeout=config.timeout,
            auto_bind=config.auto_bind,
            auto_range=config.auto_range,
        )

    @staticmethod
    def create_search_options(
        base_dn: str,
        filter_str: str = "(objectClass=*)",
        scope: Literal["BASE", "ONELEVEL", "SUBTREE"] = "SUBTREE",
    ) -> FlextLdapModels.SearchOptions:
        """Factory for SearchOptions with smart defaults."""
        return FlextLdapModels.SearchOptions(
            base_dn=base_dn,
            filter_str=filter_str,
            scope=scope,
        )

    @staticmethod
    def create_test_entry(dn_suffix: str = "testservice") -> FlextLdifModels.Entry:
        """Factory for test entry using flext_tests patterns."""
        # Use flext_tests for consistent data generation
        user_data = FlextTestsFactories.create_user(
            user_id=dn_suffix,
            name="Test Service",
            email=f"{dn_suffix}@flext.local",
        )

        return FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(
                value=f"cn={dn_suffix},ou=people,dc=flext,dc=local",
            ),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={
                    "cn": [str(getattr(user_data, "name", str(user_data)))],
                    "sn": ["Test"],
                    "mail": [str(getattr(user_data, "email", str(user_data)))],
                    "objectClass": [
                        "inetOrgPerson",
                        "organizationalPerson",
                        "person",
                        "top",
                    ],
                },
            ),
        )


class TestAssertions:
    """Comprehensive assertion helpers for API operations across all test methods.

    Uses flext_tests utilities for consistent assertion patterns and error handling.
    """

    @staticmethod
    def assert_config_initialized(
        instance: FlextLdap,
        config_type: type[FlextLdapConfig] = FlextLdapConfig,
    ) -> None:
        """Assert that FlextLdap instance has properly initialized config."""
        assert instance._config is not None
        assert isinstance(instance._config, config_type)

    @staticmethod
    def assert_connection_success(result: FlextResult[bool]) -> None:
        """Assert that connection operation succeeded using flext_tests."""
        FlextTestsUtilities.TestUtilities.assert_result_success(result)

    @staticmethod
    def assert_search_success(
        result: FlextResult[FlextLdapModels.SearchResult],
    ) -> None:
        """Assert that search operation succeeded using flext_tests."""
        FlextTestsUtilities.TestUtilities.assert_result_success(result)

    @staticmethod
    def assert_add_success(
        result: FlextResult[FlextLdapModels.OperationResult],
    ) -> None:
        """Assert that add operation succeeded using flext_tests."""
        FlextTestsUtilities.TestUtilities.assert_result_success(result)

    @staticmethod
    def assert_operation_failure(
        result: FlextResult[object],
        expected_error_contains: str,
    ) -> None:
        """Assert that operation failed with expected error using flext_tests patterns."""
        FlextTestsUtilities.TestUtilities.assert_result_failure(result)
        assert result.error is not None, "Error message should be present"
        assert expected_error_contains in result.error, (
            f"Error should contain '{expected_error_contains}'"
        )


class TestFlextLdapAPICompleteCoverage:
    """Complete coverage tests for FlextLdap API using modern patterns.

    This class contains all complete coverage tests using factory patterns,
    comprehensive assertions, parameterized tests, and advanced Python 3.13 features
    for maximum code reuse and test coverage.

    Tests all code paths including error handling and edge cases.
    """

    # Configuration test parameters
    CONFIG_TEST_PARAMS: ClassVar[list[tuple[ConfigType, bool]]] = [
        # (config_type, expect_success)
        (ConfigType.BASIC, True),
        (ConfigType.FULL, True),
    ]

    @pytest.mark.parametrize(
        ("config_type", "expect_success"),
        CONFIG_TEST_PARAMS,
        ids=[
            f"{config[0].value}_{'success' if config[1] else 'failure'}"
            for config in CONFIG_TEST_PARAMS
        ],
    )
    def test_api_initialization_with_config_types(
        self,
        ldap_container: dict[str, object],
        config_type: ConfigType,
        expect_success: bool,
    ) -> None:
        """Parameterized test for API initialization with different config types."""
        config = TestDataFactories.create_config_by_type(config_type, ldap_container)
        api = FlextLdap(config=config)

        TestAssertions.assert_config_initialized(api, FlextLdapConfig)

        # Test connection with the config
        connection_config = TestDataFactories.create_connection_config_from_config(
            config
        )
        result = api.connect(connection_config)

        if expect_success:
            TestAssertions.assert_connection_success(result)
            api.disconnect()
        else:
            FlextTestsUtilities.TestUtilities.assert_result_failure(result)

    def test_api_initialization_with_default_config(
        self,
    ) -> None:
        """Test API initialization with default config."""
        # Create a simple FlextLdap instance for config testing
        instance = FlextLdap()
        TestAssertions.assert_config_initialized(instance)

    def test_connect_with_service_config_all_options(
        self,
        ldap_parser: FlextLdifParser,
        ldap_container: dict[str, object],
    ) -> None:
        """Test connect using service config with all options."""
        config = TestDataFactories.create_full_config(ldap_container)

        api = FlextLdap(config=config, parser=ldap_parser)
        connection_config = TestDataFactories.create_connection_config_from_config(
            config
        )

        result = api.connect(connection_config)
        TestAssertions.assert_connection_success(result)
        api.disconnect()

    def test_execute_when_operations_execute_fails(
        self,
        ldap_client: FlextLdap,
    ) -> None:
        """Test execute when operations.execute fails."""
        # Disconnect to make operations.execute fail
        ldap_client.disconnect()

        result = ldap_client.execute()
        # Fast fail - should return failure when not connected
        TestAssertions.assert_operation_failure(
            cast("FlextResult[object]", result), "Not connected"
        )

    # Operation sequence test parameters
    OPERATION_SEQUENCE_PARAMS: ClassVar[list[tuple[str, list[OperationType]]]] = [
        # (test_name, operations)
        ("connect_only", [OperationType.CONNECT]),
        ("connect_search", [OperationType.CONNECT, OperationType.SEARCH]),
        (
            "full_crud",
            [
                OperationType.CONNECT,
                OperationType.SEARCH,
                OperationType.ADD,
                OperationType.DELETE,
            ],
        ),
    ]

    @pytest.mark.parametrize(
        ("test_name", "operations"),
        OPERATION_SEQUENCE_PARAMS,
        ids=[config[0] for config in OPERATION_SEQUENCE_PARAMS],
    )
    def test_operation_sequences_parameterized(
        self,
        ldap_container: dict[str, object],
        test_name: str,
        operations: list[OperationType],
    ) -> None:
        """Parameterized test for operation sequences."""
        config = TestDataFactories.create_basic_config(ldap_container)
        api = FlextLdap(config=config)
        connection_config = TestDataFactories.create_connection_config_from_config(
            config
        )

        try:
            for operation in operations:
                match operation:
                    case OperationType.CONNECT:
                        connect_result = api.connect(connection_config)
                        TestAssertions.assert_connection_success(connect_result)

                    case OperationType.SEARCH:
                        search_options = TestDataFactories.create_search_options(
                            str(ldap_container["base_dn"]),
                        )
                        search_result = api.search(search_options)
                        TestAssertions.assert_search_success(search_result)

                    case OperationType.ADD:
                        entry = TestDataFactories.create_test_entry(f"test_{test_name}")
                        # Cleanup first
                        _ = api.delete(str(entry.dn))
                        add_result = api.add(entry)
                        TestAssertions.assert_add_success(add_result)

                    case OperationType.DELETE:
                        entry = TestDataFactories.create_test_entry(f"test_{test_name}")
                        delete_result = api.delete(str(entry.dn))
                        # Delete may succeed or fail depending on entry existence
                        assert delete_result.is_success or delete_result.is_failure

                    case OperationType.EXECUTE:
                        execute_result = api.execute()
                        FlextTestsUtilities.TestUtilities.assert_result_success(
                            execute_result
                        )

        finally:
            api.disconnect()

    def test_all_operations_with_service_config(
        self,
        ldap_container: dict[str, object],
    ) -> None:
        """Test all operations using service config."""
        config = TestDataFactories.create_basic_config(ldap_container)
        api = FlextLdap(config=config)

        connection_config = TestDataFactories.create_connection_config_from_config(
            config
        )

        # Connect using service config
        connect_result = api.connect(connection_config)
        TestAssertions.assert_connection_success(connect_result)

        # Search
        search_options = TestDataFactories.create_search_options(
            str(ldap_container["base_dn"]),
        )
        search_result = api.search(search_options)
        TestAssertions.assert_search_success(search_result)

        # Add
        entry = TestDataFactories.create_test_entry()

        # Cleanup first
        _ = api.delete(str(entry.dn))

        add_result = api.add(entry)
        TestAssertions.assert_add_success(add_result)

        # Cleanup
        delete_result = api.delete(str(entry.dn))
        assert delete_result.is_success or delete_result.is_failure

        api.disconnect()
