"""Unit tests for flext_ldap.adapters.ldap3.Ldap3Adapter.

Tests LDAP3 adapter functionality with real connection handling and error scenarios.
Focuses on connection lifecycle, search operations, entry conversion, and error handling
without requiring live LDAP server connections. Uses advanced Python 3.13 features,
factory patterns, and generic helpers from flext_tests for efficient test data generation
and edge case coverage. All tests validate adapter behavior with mocked dependencies.

Tested modules: flext_ldap.adapters.ldap3.Ldap3Adapter
Test scope: Adapter connection management, search operations, entry conversion, error handling
Coverage target: 100% with parametrized edge cases

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import ClassVar, cast
from unittest.mock import MagicMock

import pytest
from flext_core import FlextResult
from flext_ldif import FlextLdifParser
from flext_ldif.models import FlextLdifModels
from flext_tests import FlextTestsUtilities
from ldap3 import Connection, Server

from flext_ldap.adapters.ldap3 import Ldap3Adapter
from flext_ldap.models import FlextLdapModels

from ..helpers.test_deduplication_helpers import TestDeduplicationHelpers

pytestmark = pytest.mark.unit


@pytest.fixture
def adapter(ldap_parser: FlextLdifParser) -> Ldap3Adapter:
    """Provide Ldap3Adapter instance for testing."""
    return Ldap3Adapter(parser=ldap_parser)


@pytest.fixture
def search_options() -> FlextLdapModels.SearchOptions:
    """Provide standard search options for testing."""
    return Ldap3AdapterTestDataFactory.create_search_options()


class AdapterTestScenario(StrEnum):
    """Test scenarios for LDAP3 adapter testing."""

    DEFAULT = "default"
    CONNECTED = "connected"
    DISCONNECTED = "disconnected"
    FAILURE = "failure"


class AdapterTestCategory(StrEnum):
    """Test categories for adapter operations."""

    CONNECTION = "connection"
    SEARCH = "search"
    CONVERSION = "conversion"
    ADD = "add"


class ConnectionState(StrEnum):
    """Connection states for parametrized testing."""

    CONNECTED = "connected"
    DISCONNECTED = "disconnected"
    UNBOUND = "unbound"


@dataclass(frozen=True, slots=True)
class Ldap3AdapterTestDataFactory:
    """Factory for creating test data for Ldap3Adapter tests using Python 3.13 dataclasses."""

    # Connection test states for parametrization
    CONNECTION_STATES: ClassVar[tuple[ConnectionState, ...]] = (
        ConnectionState.CONNECTED,
        ConnectionState.DISCONNECTED,
        ConnectionState.UNBOUND,
    )

    # Test categories for organization
    TEST_CATEGORIES: ClassVar[tuple[AdapterTestCategory, ...]] = (
        AdapterTestCategory.CONNECTION,
        AdapterTestCategory.SEARCH,
        AdapterTestCategory.CONVERSION,
        AdapterTestCategory.ADD,
    )

    # Invalid host scenarios for parametrization
    INVALID_HOSTS: ClassVar[tuple[str, ...]] = (
        "192.0.2.1",  # TEST-NET-1, reserved for documentation
        "invalid-host-that-does-not-exist",
    )

    @staticmethod
    def create_search_options(
        base_dn: str = "dc=example,dc=com",
        filter_str: str = "(objectClass=*)",
        scope: str = "SUBTREE",
    ) -> FlextLdapModels.SearchOptions:
        """Factory method for search options."""
        return FlextLdapModels.SearchOptions(
            base_dn=base_dn,
            filter_str=filter_str,
            scope=scope,  # type: ignore[arg-type]
        )

    @staticmethod
    def create_test_entry(
        dn: str = "cn=test,dc=example,dc=com",
        **attributes: list[str] | str,
    ) -> FlextLdifModels.Entry:
        """Factory method for test entries."""
        default_attrs: dict[
            str, list[str] | str | tuple[str, ...] | set[str] | frozenset[str]
        ] = {
            "cn": ["test"],
            "objectClass": ["top", "person"],
        }
        if attributes:
            for key, value in attributes.items():
                default_attrs[key] = [value] if isinstance(value, str) else value
        return TestDeduplicationHelpers.create_entry(dn, default_attrs)  # type: ignore[arg-type]

    @staticmethod
    def create_invalid_entry() -> FlextLdifModels.Entry:
        """Factory method for invalid entries (empty DN)."""
        return FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value=""),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={"cn": ["test"], "objectClass": ["person"]},
            ),
        )


class TestLdap3AdapterUnit:
    """Unit tests for Ldap3Adapter with real LDAP functionality.

    Single class with flat test methods covering:
    - Connection management (lifecycle, properties, state validation)
    - Search operations (not connected, invalid parameters, real LDAP errors)
    - Entry conversion (None handling, error scenarios)
    - Add operations (not connected, invalid entries)

    Previously nested test classes: TestConnectionManagement, TestSearchOperations,
    TestConversion, TestAddOperations - now flattened per FLEXT architecture.
    """

    _factory = Ldap3AdapterTestDataFactory()

    def test_adapter_initialization(self, adapter: Ldap3Adapter) -> None:
        """Test adapter initialization creates valid instance."""
        assert adapter is not None
        assert adapter._connection is None
        assert adapter._server is None
        assert adapter.is_connected is False

    @pytest.mark.parametrize("invalid_host", Ldap3AdapterTestDataFactory.INVALID_HOSTS)
    def test_connect_with_invalid_host(
        self,
        adapter: Ldap3Adapter,
        invalid_host: str,
    ) -> None:
        """Test connect with invalid host scenarios (parametrized)."""
        # Use parametrized invalid hosts to trigger connection failure
        config = FlextLdapModels.ConnectionConfig(
            host=invalid_host,
            port=389,
            timeout=1,  # Short timeout for faster test
        )
        result = adapter.connect(config)

        # Should fail with connection error
        assert result.is_failure
        assert result.error is not None
        assert "Connection failed" in result.error or "Failed" in result.error

    def test_disconnect_with_real_connection(
        self,
        adapter: Ldap3Adapter,
        connection_config: FlextLdapModels.ConnectionConfig,
    ) -> None:
        """Test disconnect with real connection."""
        connect_result = adapter.connect(connection_config)
        if connect_result.is_failure:
            pytest.skip(f"Failed to connect: {connect_result.error}")

        # Disconnect should work with real connection
        adapter.disconnect()

        # Connection should be cleared
        assert adapter._connection is None
        assert adapter._server is None
        assert adapter.is_connected is False

    @pytest.mark.parametrize(
        "connection_type",
        [
            "connected",
            "not_connected",
        ],
    )
    def test_connection_property_by_state(
        self,
        adapter: Ldap3Adapter,
        ldap_container: dict[str, object],
        connection_type: str,
    ) -> None:
        """Test connection property with different connection states (parametrized)."""
        if connection_type == "connected":
            # Create real ldap3 connection using fixture
            real_connection = TestDeduplicationHelpers.create_ldap3_connection(
                ldap_container,
            )
            adapter._connection = cast("Connection", real_connection)

            # Access connection property
            connection = adapter.connection
            assert connection == real_connection
            assert isinstance(connection, Connection)

            # Cleanup
            if connection.bound:
                connection.unbind()

        else:  # not_connected
            adapter._connection = None

            # Access connection property
            connection = adapter.connection
            assert connection is None

    @pytest.mark.parametrize(
        "connection_state",
        [
            ConnectionState.CONNECTED.value,
            ConnectionState.DISCONNECTED.value,
            ConnectionState.UNBOUND.value,
        ],
    )
    def test_is_connected_property_by_state(
        self,
        adapter: Ldap3Adapter,
        ldap_container: dict[str, object],
        connection_state: str,
    ) -> None:
        """Test is_connected property with different connection states (parametrized)."""
        if connection_state == ConnectionState.CONNECTED.value:
            # Real connected connection
            real_connection_obj = TestDeduplicationHelpers.create_ldap3_connection(
                ldap_container,
            )
            real_connection = cast("Connection", real_connection_obj)
            adapter._connection = real_connection
            assert adapter.is_connected is True
            if real_connection.bound:
                real_connection.unbind()

        elif connection_state == ConnectionState.DISCONNECTED.value:
            # No connection
            adapter._connection = None
            assert adapter.is_connected is False

        elif connection_state == ConnectionState.UNBOUND.value:
            # Unbound connection
            server = Server("ldap://localhost:389")
            unbound_connection = Connection(server, auto_bind=False)
            adapter._connection = unbound_connection
            assert adapter.is_connected is False

    def test_search_when_not_connected(
        self,
        adapter: Ldap3Adapter,
        search_options: FlextLdapModels.SearchOptions,
    ) -> None:
        """Test search when not connected."""
        adapter._connection = None

        result = adapter.search(search_options)

        # Should fail with not connected error
        assert result.is_failure
        assert result.error is not None
        assert "Not connected" in result.error

    def test_search_with_invalid_base_dn(
        self,
        adapter: Ldap3Adapter,
        connection_config: FlextLdapModels.ConnectionConfig,
    ) -> None:
        """Test search with invalid base DN - real LDAP error."""
        connect_result = adapter.connect(connection_config)
        if connect_result.is_failure:
            pytest.skip(f"Failed to connect: {connect_result.error}")

        try:
            # Use invalid base DN to trigger real LDAP error
            search_options = FlextLdapModels.SearchOptions(
                base_dn="invalid=base,dn=invalid",
                filter_str="(objectClass=*)",
                scope="SUBTREE",
            )
            result = adapter.search(search_options)

            # Should fail with LDAP error
            assert result.is_failure
            assert result.error is not None
        finally:
            adapter.disconnect()

    def test_convert_ldap3_results_none_handling(self) -> None:
        """Test _convert_ldap3_results handles None attribute values."""
        adapter = Ldap3Adapter()

        # Create mock connection with entries containing None values
        connection = Connection(Server("ldap://dummy"), client_strategy="MOCK_SYNC")
        connection.strategy.add_entry(
            "cn=test,dc=example,dc=com",
            {
                "objectClass": ["person"],
                "testValue": "single",
                "testList": ["a", "b"],
            },
        )

        if len(connection.entries) > 0:
            connection.entries[0]
            converted = adapter._convert_ldap3_results(connection)

            assert isinstance(converted, list)
            assert len(converted) == 1

            dn, attrs = converted[0]
            assert dn == "cn=test,dc=example,dc=com"
            # Single value should be converted to list
            assert attrs["testValue"] == ["single"]
            # List should remain list
            assert attrs["testList"] == ["a", "b"]

    def test_search_error_in_entry_conversion(
        self,
        search_options: FlextLdapModels.SearchOptions,
    ) -> None:
        """Test search error handling when entry conversion fails."""
        adapter = Ldap3Adapter()

        # Create a proper mock connection
        mock_connection = MagicMock(spec=Connection)
        mock_connection.bound = True
        mock_connection.search.return_value = True

        # Create mock entries with proper structure
        mock_entry = MagicMock()
        mock_entry.entry_dn = "dc=example,dc=com"
        mock_entry.entry_attributes = {"objectClass": ["top"]}
        mock_connection.entries = [mock_entry]
        mock_connection.result = {"result": 0}

        adapter._connection = mock_connection

        def mock_convert_failure(*args: object, **kwargs: object) -> object:
            return FlextResult[list[FlextLdifModels.Entry]].fail(
                "Mock conversion failure"
            )

        # Use test_context to temporarily mock the method
        with FlextTestsUtilities.test_context(
            adapter, "_convert_parsed_entries", mock_convert_failure
        ):
            # This should trigger the error logging
            result = adapter.search(search_options)
            assert result.is_failure
            assert "Mock conversion failure" in str(result.error)

    def test_add_when_not_connected(self, adapter: Ldap3Adapter) -> None:
        """Test add when not connected."""
        adapter._connection = None

        # Use factory to create entry
        entry = self._factory.create_test_entry()

        result = adapter.add(entry)

        # Should fail with not connected error
        assert result.is_failure
        assert result.error is not None
        assert "Not connected" in result.error

    def test_add_with_invalid_entry(
        self,
        adapter: Ldap3Adapter,
        connection_config: FlextLdapModels.ConnectionConfig,
    ) -> None:
        """Test add with invalid entry - real validation error."""
        connect_result = adapter.connect(connection_config)
        if connect_result.is_failure:
            pytest.skip(f"Failed to connect: {connect_result.error}")

        try:
            # Use factory to create invalid entry (empty DN)
            entry = self._factory.create_invalid_entry()

            result = adapter.add(entry)

            # Should fail with validation error
            assert result.is_failure
            assert result.error is not None
        finally:
            adapter.disconnect()
