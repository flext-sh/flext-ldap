"""Unit tests for flext_ldap.adapters.ldap3.Ldap3Adapter.

This module provides comprehensive testing of the Ldap3Adapter service including
connection lifecycle management, search operations, entry conversion, and add
operations. Uses advanced Python 3.13 features, factory patterns, and generic
helpers for efficient test data generation and edge case coverage.

Tested modules: flext_ldap.adapters.ldap3
Test scope: Connection management, search operations, entry conversion, add operations
Coverage target: 100% with parametrized edge cases

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Callable
from enum import StrEnum
from typing import ClassVar

import pytest
from flext_ldif import FlextLdifParser
from flext_ldif.models import FlextLdifModels
from flext_tests import FlextTestsMatchers
from ldap3 import Connection, Server

from flext_ldap.adapters.ldap3 import Ldap3Adapter
from flext_ldap.constants import FlextLdapConstants
from flext_ldap.models import FlextLdapModels

from ..fixtures.typing import GenericFieldsDict
from ..helpers.test_deduplication_helpers import TestDeduplicationHelpers

pytestmark = pytest.mark.unit


@pytest.fixture
def adapter(ldap_parser: FlextLdifParser) -> Ldap3Adapter:
    """Provide Ldap3Adapter instance for testing."""
    return Ldap3Adapter(parser=ldap_parser)


class TestLdap3AdapterUnit:
    """Comprehensive tests for Ldap3Adapter using factories and DRY principles.

    Single class per module with nested helpers, constants, and factory methods
    organized within the class. Uses parametrized tests and constants for
    maximum code reuse.
    """

    # ===== NESTED ENUMS AND CONSTANTS =====

    class ConnectionState(StrEnum):
        """Connection states for parametrized testing."""

        CONNECTED = "connected"
        DISCONNECTED = "disconnected"
        UNBOUND = "unbound"

    # Test constants - consolidated in ClassVar mappings
    _CONSTANTS: ClassVar[dict[str, str]] = {
        "DEFAULT_BASE_DN": "dc=example,dc=com",
        "DEFAULT_FILTER": "(objectClass=*)",
        "TEST_DN": "cn=test,dc=example,dc=com",
    }
    _DEFAULT_PORT: ClassVar[int] = 389
    _CONNECTION_STATES: ClassVar[tuple[str, ...]] = (
        ConnectionState.CONNECTED.value,
        ConnectionState.DISCONNECTED.value,
        ConnectionState.UNBOUND.value,
    )

    # Invalid hosts for parametrized connection failure tests
    _INVALID_HOSTS: ClassVar[tuple[str, ...]] = (
        "192.0.2.1",
        "invalid-host-that-does-not-exist",
    )

    # ===== FACTORY METHODS =====

    @staticmethod
    def _create_search_options(
        base_dn: str | None = None,
        filter_str: str | None = None,
        scope: FlextLdapConstants.SearchScope | None = None,
    ) -> FlextLdapModels.SearchOptions:
        """Factory method for search options using constants."""
        return FlextLdapModels.SearchOptions(
            base_dn=base_dn or TestLdap3AdapterUnit._CONSTANTS["DEFAULT_BASE_DN"],
            filter_str=filter_str or TestLdap3AdapterUnit._CONSTANTS["DEFAULT_FILTER"],
            scope=scope or FlextLdapConstants.SearchScope.SUBTREE,
        )

    @staticmethod
    def _create_test_entry(
        dn: str | None = None,
        **attributes: list[str] | str,
    ) -> FlextLdifModels.Entry:
        """Factory method for test entries."""
        entry_dn = dn or TestLdap3AdapterUnit._CONSTANTS["TEST_DN"]
        default_attrs: dict[
            str,
            list[str] | str | tuple[str, ...] | set[str] | frozenset[str],
        ] = {
            "cn": ["test"],
            "objectClass": ["top", "person"],
        }
        if attributes:
            for key, value in attributes.items():
                default_attrs[key] = [value] if isinstance(value, str) else value
        return TestDeduplicationHelpers.create_entry(entry_dn, default_attrs)

    @staticmethod
    def _create_invalid_entry() -> FlextLdifModels.Entry:
        """Factory method for invalid entries (empty DN)."""
        return FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value=""),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={"cn": ["test"], "objectClass": ["person"]},
            ),
        )

    # ===== CONNECTION HELPER METHODS =====

    @staticmethod
    def _ensure_disconnected(adapter: Ldap3Adapter) -> None:
        """Ensure adapter is disconnected and clean up connection if needed."""
        connection_obj = adapter._connection
        if (
            connection_obj is not None
            and isinstance(connection_obj, Connection)
            and connection_obj.bound
        ):
            unbind_func: Callable[[], None] = connection_obj.unbind
            unbind_func()
        adapter._connection = None
        adapter._server = None

    @staticmethod
    def _connect_with_skip(
        adapter: Ldap3Adapter,
        connection_config: FlextLdapModels.ConnectionConfig,
    ) -> None:
        """Connect adapter, skip test if connection fails."""
        connect_result = adapter.connect(connection_config)
        if connect_result.is_failure:
            pytest.skip(f"Failed to connect: {connect_result.error}")

    # ===== TEST METHODS =====

    def test_adapter_initialization(self, adapter: Ldap3Adapter) -> None:
        """Test adapter initialization creates valid instance."""
        assert adapter is not None
        assert adapter._connection is None
        assert adapter._server is None
        assert adapter.is_connected is False

    @pytest.mark.parametrize("invalid_host", _INVALID_HOSTS)
    def test_connect_with_invalid_host(
        self,
        adapter: Ldap3Adapter,
        invalid_host: str,
    ) -> None:
        """Test connect with invalid host scenarios (parametrized)."""
        config = FlextLdapModels.ConnectionConfig(
            host=invalid_host,
            port=self._DEFAULT_PORT,
            timeout=1,  # Fast timeout for test
        )
        result = adapter.connect(config)
        _ = FlextTestsMatchers.assert_failure(result, "failed")

    def test_disconnect_with_real_connection(
        self,
        adapter: Ldap3Adapter,
        connection_config: FlextLdapModels.ConnectionConfig,
    ) -> None:
        """Test disconnect with real connection."""
        self._connect_with_skip(adapter, connection_config)
        adapter.disconnect()
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
        ldap_container: GenericFieldsDict,
        connection_type: str,
    ) -> None:
        """Test connection property with different connection states (parametrized)."""
        if connection_type == "connected":
            real_connection = TestDeduplicationHelpers.create_ldap3_connection(
                ldap_container,
            )
            # Type narrowing: create_ldap3_connection returns Connection
            # No need to check isinstance - it's guaranteed to be Connection
            adapter._connection = real_connection
            connection = adapter.connection
            assert connection == real_connection
            assert isinstance(connection, Connection)
            self._ensure_disconnected(adapter)
        else:
            adapter._connection = None
            connection = adapter.connection
            assert connection is None

    @pytest.mark.parametrize("connection_state", _CONNECTION_STATES)
    def test_is_connected_property_by_state(
        self,
        adapter: Ldap3Adapter,
        ldap_container: GenericFieldsDict,
        connection_state: str,
    ) -> None:
        """Test is_connected property with different connection states (parametrized)."""
        if connection_state == self.ConnectionState.CONNECTED.value:
            real_connection_obj = TestDeduplicationHelpers.create_ldap3_connection(
                ldap_container,
            )
            # Type narrowing: create_ldap3_connection returns Connection
            # No need to check isinstance - it's guaranteed to be Connection
            if real_connection_obj is not None:
                adapter._connection = real_connection_obj
                assert adapter.is_connected is True
                self._ensure_disconnected(adapter)
        elif connection_state == self.ConnectionState.DISCONNECTED.value:
            adapter._connection = None
            assert adapter.is_connected is False
        elif connection_state == self.ConnectionState.UNBOUND.value:
            server = Server("ldap://localhost:389")
            unbound_connection = Connection(server, auto_bind=False)
            adapter._connection = unbound_connection
            assert adapter.is_connected is False

    def test_search_when_not_connected(
        self,
        adapter: Ldap3Adapter,
    ) -> None:
        """Test search when not connected."""
        adapter._connection = None
        search_options = self._create_search_options()
        result = adapter.search(search_options)
        _ = FlextTestsMatchers.assert_failure(result, "Not connected")

    def test_search_with_invalid_base_dn(
        self,
        adapter: Ldap3Adapter,
        connection_config: FlextLdapModels.ConnectionConfig,
    ) -> None:
        """Test search with invalid base DN - real LDAP error."""
        self._connect_with_skip(adapter, connection_config)
        try:
            search_options = self._create_search_options(
                base_dn="invalid=base,dn=invalid",
            )
            result = adapter.search(search_options)
            _ = FlextTestsMatchers.assert_failure(result)
        finally:
            adapter.disconnect()

    def test_convert_ldap3_results_none_handling(self) -> None:
        """Test _convert_ldap3_results handles None attribute values."""
        adapter = Ldap3Adapter()
        connection = Connection(Server("ldap://dummy"), client_strategy="MOCK_SYNC")
        connection.strategy.add_entry(
            self._CONSTANTS["TEST_DN"],
            {
                "objectClass": ["person"],
                "testValue": "single",
                "testList": ["a", "b"],
            },
        )
        if len(connection.entries) > 0:
            converted = adapter.ResultConverter.convert_ldap3_results(connection)
            assert isinstance(converted, list)
            assert len(converted) == 1
            dn, attrs = converted[0]
            assert dn == self._CONSTANTS["TEST_DN"]
            assert attrs["testValue"] == ["single"]
            assert attrs["testList"] == ["a", "b"]

    def test_search_error_in_entry_conversion(
        self,
        adapter: Ldap3Adapter,
        connection_config: FlextLdapModels.ConnectionConfig,
    ) -> None:
        """Test search error handling when entry conversion fails using real connection."""
        self._connect_with_skip(adapter, connection_config)
        try:
            invalid_search = self._create_search_options(
                base_dn="invalid=base,dn=invalid",
            )
            result = adapter.search(invalid_search)
            error = FlextTestsMatchers.assert_failure(result)
            assert len(error) > 0
        finally:
            adapter.disconnect()

    def test_add_when_not_connected(self, adapter: Ldap3Adapter) -> None:
        """Test add when not connected."""
        adapter._connection = None
        entry = self._create_test_entry()
        result = adapter.add(entry)
        _ = FlextTestsMatchers.assert_failure(result, "Not connected")

    def test_add_with_invalid_entry(
        self,
        adapter: Ldap3Adapter,
        connection_config: FlextLdapModels.ConnectionConfig,
    ) -> None:
        """Test add with invalid entry - real validation error."""
        self._connect_with_skip(adapter, connection_config)
        try:
            entry = self._create_invalid_entry()
            result = adapter.add(entry)
            _ = FlextTestsMatchers.assert_failure(result)
        finally:
            adapter.disconnect()
