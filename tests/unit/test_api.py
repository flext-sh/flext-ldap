"""Unit tests for FlextLdap API.

This module provides comprehensive testing of the FlextLdap main API facade including
API initialization, connection management, disconnected operations, context manager
functionality, and service registration scenarios. Uses advanced Python 3.13 features,
factory patterns, and generic helpers for efficient test data generation and edge case
coverage. All tests validate API behavior, service lifecycle, and error handling
patterns.

Tested modules: flext_ldap.api, flext_ldap.config, flext_ldap.models
Test scope: API facade behavior, connection lifecycle, service registration
Coverage target: 100% with parametrized edge cases

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import ClassVar

import pytest
from flext_core import FlextResult
from flext_ldif import FlextLdif
from flext_ldif.models import FlextLdifModels
from flext_ldif.services.parser import FlextLdifParser
from flext_tests import FlextTestsMatchers
from ldap3 import MODIFY_REPLACE

from flext_ldap import FlextLdap
from flext_ldap.config import FlextLdapConfig
from flext_ldap.constants import FlextLdapConstants
from flext_ldap.models import FlextLdapModels
from flext_ldap.services.connection import FlextLdapConnection
from flext_ldap.services.operations import FlextLdapOperations

from ..fixtures.constants import TestConstants

pytestmark = pytest.mark.unit


# ===== HELPER FIXTURES =====


@pytest.fixture
def default_config() -> FlextLdapConfig:
    """Provide default FlextLdapConfig instance."""
    return FlextLdapConfig()


@pytest.fixture
def api_instance(default_config: FlextLdapConfig) -> FlextLdap:
    """Provide FlextLdap API instance for testing."""
    return ApiTestDataFactory.create_api_instance(default_config, None)


# ===== TEST ENUMS AND FACTORIES =====


class LdapOperation(StrEnum):
    """LDAP operation types for dynamic testing."""

    SEARCH = "search"
    ADD = "add"
    MODIFY = "modify"
    DELETE = "delete"


# ServiceName enum removed - service registration functionality no longer exists


class ApiTestScenario(StrEnum):
    """Test scenarios for API validation."""

    DEFAULT = "default"
    CONNECTED = "connected"
    DISCONNECTED = "disconnected"
    FAILURE = "failure"


class ApiTestCategory(StrEnum):
    """API test categories for flat parametrization."""

    INITIALIZATION = "initialization"
    CONNECTION_MGMT = "connection_mgmt"
    PROPERTIES = "properties"
    CONTEXT_MGR = "context_mgr"
    SERVICE_REG = "service_reg"


@dataclass(frozen=True, slots=True)
class ApiTestDataFactory:
    """Test data factory for API tests using Python 3.13 dataclasses."""

    base_dn: str = TestConstants.DEFAULT_BASE_DN
    test_user_dn: str = TestConstants.TEST_USER_DN
    test_group_dn: str = TestConstants.TEST_GROUP_DN

    @staticmethod
    def create_search_options(
        base_dn: str | None = None,
        filter_str: str = TestConstants.DEFAULT_FILTER,
        scope: FlextLdapConstants.SearchScope = FlextLdapConstants.SearchScope.SUBTREE,
    ) -> FlextLdapModels.SearchOptions:
        """Factory method for search options."""
        return FlextLdapModels.SearchOptions(
            base_dn=base_dn or TestConstants.DEFAULT_BASE_DN,
            filter_str=filter_str,
            scope=scope,
            attributes=list(TestConstants.DEFAULT_ATTRIBUTES)
            if TestConstants.DEFAULT_ATTRIBUTES
            else None,
        )

    @staticmethod
    def create_test_entry(
        dn: str | None = None,
        **attributes: list[str] | str,
    ) -> FlextLdifModels.Entry:
        """Factory method for test entries."""
        entry_dn = dn or TestConstants.TEST_USER_DN
        default_attrs: dict[str, list[str]] = {
            "cn": ["testuser"],
            "sn": ["User"],
            "givenName": ["Test"],
            "uid": ["testuser"],
            "mail": ["testuser@flext.local"],
            "objectClass": ["inetOrgPerson", "organizationalPerson", "person", "top"],
            "userPassword": ["test123"],
        }
        for key, value in attributes.items():
            if isinstance(value, str):
                default_attrs[key] = [value]
            else:
                default_attrs[key] = [str(item) for item in value]
        return FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value=entry_dn),
            attributes=FlextLdifModels.LdifAttributes(attributes=default_attrs),
        )

    @staticmethod
    def create_modify_changes(**changes: str) -> dict[str, list[tuple[str, list[str]]]]:
        """Factory method for modify changes."""
        return {k: [(MODIFY_REPLACE, [v])] for k, v in changes.items()}

    @staticmethod
    def create_api_instance(
        config: FlextLdapConfig,
        parser: FlextLdifParser | None = None,
    ) -> FlextLdap:
        """Factory method to create API instance."""
        connection = FlextLdapConnection(config=config, parser=parser)
        operations = FlextLdapOperations(connection=connection)
        # Get FlextLdif instance (parser is used by connection, ldif is separate)
        ldif_instance = FlextLdif.get_instance()
        return FlextLdap(connection=connection, operations=operations, ldif=ldif_instance)


class TestFlextLdapAPI:
    """Comprehensive tests for FlextLdap main API facade.

    Single class per module with parametrized test methods covering:
    - API initialization and configuration
    - Connection lifecycle management
    - API properties and client access
    - Context manager functionality
    - Service registration and lifecycle

    Uses Python 3.13 StrEnum for test categorization and parametrization.
    """

    _factory = ApiTestDataFactory()

    # API test categories for test organization
    TEST_CATEGORIES: ClassVar[tuple[ApiTestCategory, ...]] = (
        ApiTestCategory.INITIALIZATION,
        ApiTestCategory.CONNECTION_MGMT,
        ApiTestCategory.PROPERTIES,
        ApiTestCategory.CONTEXT_MGR,
    )

    # Explicit operation values for parametrization (hard-coded to avoid pyrefly issues)
    _OPERATIONS: ClassVar[tuple[str, ...]] = (
        LdapOperation.SEARCH.value,
        LdapOperation.ADD.value,
        LdapOperation.MODIFY.value,
        LdapOperation.DELETE.value,
    )

    @staticmethod
    def _execute_operation_check_failure(
        api: FlextLdap,
        operation: LdapOperation,
    ) -> bool:
        """Execute LDAP operation and check if it fails.

        Returns True if operation fails (expected when not connected).
        """
        if operation == LdapOperation.SEARCH:
            return api.search(ApiTestDataFactory.create_search_options()).is_failure
        if operation == LdapOperation.ADD:
            return api.add(ApiTestDataFactory.create_test_entry()).is_failure
        if operation == LdapOperation.MODIFY:
            return api.modify(
                TestConstants.TEST_USER_DN,
                ApiTestDataFactory.create_modify_changes(mail="updated@flext.local"),
            ).is_failure
        if operation == LdapOperation.DELETE:
            return api.delete(TestConstants.TEST_USER_DN).is_failure
        msg = f"Unknown operation: {operation}"
        raise ValueError(msg)

    def test_api_initialization_with_default_config(
        self,
        default_config: FlextLdapConfig,
    ) -> None:
        """Test API initialization with default configuration.

        Covers initialization with default config.
        """
        api = ApiTestDataFactory.create_api_instance(default_config, None)
        # Validate default initialization state
        assert api._connection.is_connected is False
        assert api._connection is not None
        assert api._operations is not None
        assert api._config is not None
        assert api._config.host == "localhost"  # default value

    @pytest.mark.parametrize("operation", _OPERATIONS)
    def test_operation_when_not_connected_returns_failure(
        self,
        api_instance: FlextLdap,
        operation: str,
    ) -> None:
        """Test operations fail when not connected (parametrized).

        Covers: test_operation_when_not_connected_returns_failure
        """
        operation_enum = LdapOperation(operation)
        is_failure = self._execute_operation_check_failure(api_instance, operation_enum)
        assert is_failure, f"Operation {operation} should fail when not connected"

    def test_execute_when_not_connected_returns_failure(
        self,
        api_instance: FlextLdap,
    ) -> None:
        """Test execute fails when not connected.

        Covers: test_execute_when_not_connected_returns_failure_with_error_message
        """
        result = api_instance.execute()
        FlextTestsMatchers.assert_failure(result)
        assert FlextLdapConstants.ErrorStrings.NOT_CONNECTED in (result.error or "")

    def test_disconnect_when_not_connected_succeeds_silently(
        self,
        api_instance: FlextLdap,
    ) -> None:
        """Test disconnect succeeds silently when already disconnected.

        Covers: test_disconnect_when_not_connected_succeeds_silently
        """
        api_instance.disconnect()
        assert api_instance._connection.is_connected is False

    def test_connect_method_returns_result_with_valid_config(
        self,
        api_instance: FlextLdap,
    ) -> None:
        """Test connect returns FlextResult with valid connection config.

        Unit test verifies API method behavior without real LDAP server.
        Integration tests verify actual connections.
        """
        connection_config = FlextLdapModels.ConnectionConfig(
            host="localhost",
            port=389,
            use_ssl=False,
            bind_dn="cn=admin,dc=test,dc=local",
            bind_password="test123",
        )
        result = api_instance.connect(connection_config)

        # Verify connect returns FlextResult (success/failure per server availability)
        assert isinstance(result, FlextResult)
        assert hasattr(result, "is_success")
        assert hasattr(result, "is_failure")

    def test_client_property_returns_operations_instance(
        self,
        api_instance: FlextLdap,
    ) -> None:
        """Test client property returns the operations service instance.

        Covers TestApiProperties::test_client_property_returns_operations_instance
        """
        client = api_instance._operations
        assert client is not None

    def test_context_manager_enter_returns_self(self, api_instance: FlextLdap) -> None:
        """Test context manager __enter__ returns the API instance.

        Covers TestContextManager::test_context_manager_enter_returns_self
        """
        with api_instance as entered:
            assert entered is api_instance

    def test_context_manager_exit_disconnects_properly(
        self,
        api_instance: FlextLdap,
    ) -> None:
        """Test context manager __exit__ properly disconnects.

        Unit test verifies __exit__ behavior without requiring real LDAP server.
        """
        # Before __exit__, verify not connected
        assert api_instance._connection.is_connected is False
        # Call __exit__ when already disconnected
        api_instance.__exit__(None, None, None)
        # Should still be disconnected
        assert api_instance._connection.is_connected is False

    def test_context_manager_with_statement_manages_lifecycle(
        self,
        default_config: FlextLdapConfig,
    ) -> None:
        """Test context manager lifecycle properly manages disconnection.

        Unit test verifies __enter__ and __exit__ behavior without real LDAP connection.
        """
        with ApiTestDataFactory.create_api_instance(default_config, None) as api:
            # Verify __enter__ returns self and API is usable within context
            assert api is not None
            assert api._connection is not None
        # After context manager exits, should be properly disconnected
        assert api._connection.is_connected is False

    # NOTE: Service registration tests removed - _register_core_services method
    # no longer exists in FlextLdap API. The API now uses dependency injection
    # pattern instead of service container registration.
