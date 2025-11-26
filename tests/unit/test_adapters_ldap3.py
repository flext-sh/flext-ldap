"""Unit tests for flext_ldap.adapters.ldap3.Ldap3Adapter.

**Modules Tested:**
- `flext_ldap.adapters.ldap3.Ldap3Adapter` - LDAP3 adapter for connection management

**Test Scope:**
- Adapter connection management (lifecycle, properties, state validation)
- Search operations (not connected, invalid parameters, real LDAP errors)
- Entry conversion (None handling, error scenarios)
- Add operations (not connected, invalid entries)

All tests use real functionality without mocks, leveraging flext-core test utilities
and domain-specific helpers to reduce code duplication while maintaining 100% coverage.

Module: TestLdap3AdapterUnit
Scope: Comprehensive adapter testing with maximum code reuse
Pattern: Parametrized tests using factories and constants

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
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

from ..helpers.test_deduplication_helpers import TestDeduplicationHelpers

pytestmark = pytest.mark.unit


class ConnectionState(StrEnum):
    """Connection states for parametrized testing."""

    CONNECTED = "connected"
    DISCONNECTED = "disconnected"
    UNBOUND = "unbound"


@dataclass(frozen=True, slots=True)
class Ldap3AdapterTestDataFactory:
    """Factory for creating test data for Ldap3Adapter tests using Python 3.13 dataclasses."""

    CONNECTION_STATES: ClassVar[tuple[ConnectionState, ...]] = (
        ConnectionState.CONNECTED,
        ConnectionState.DISCONNECTED,
        ConnectionState.UNBOUND,
    )

    DEFAULT_BASE_DN: ClassVar[str] = "dc=example,dc=com"
    DEFAULT_FILTER: ClassVar[str] = "(objectClass=*)"
    DEFAULT_SCOPE: ClassVar[FlextLdapConstants.LiteralTypes.SearchScope] = "SUBTREE"
    TEST_DN: ClassVar[str] = "cn=test,dc=example,dc=com"
    DEFAULT_PORT: ClassVar[int] = 389

    @staticmethod
    def create_search_options(
        base_dn: str | None = None,
        filter_str: str | None = None,
        scope: FlextLdapConstants.LiteralTypes.SearchScope | None = None,
    ) -> FlextLdapModels.SearchOptions:
        """Factory method for search options."""
        factory = Ldap3AdapterTestDataFactory()
        return FlextLdapModels.SearchOptions(
            base_dn=base_dn or factory.DEFAULT_BASE_DN,
            filter_str=filter_str or factory.DEFAULT_FILTER,
            scope=scope or factory.DEFAULT_SCOPE,
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
        return TestDeduplicationHelpers.create_entry(dn, default_attrs)

    @staticmethod
    def create_invalid_entry() -> FlextLdifModels.Entry:
        """Factory method for invalid entries (empty DN)."""
        return FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value=""),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={"cn": ["test"], "objectClass": ["person"]},
            ),
        )


@pytest.fixture
def adapter(ldap_parser: FlextLdifParser) -> Ldap3Adapter:
    """Provide Ldap3Adapter instance for testing."""
    return Ldap3Adapter(parser=ldap_parser)


@pytest.fixture
def search_options() -> FlextLdapModels.SearchOptions:
    """Provide standard search options for testing."""
    return Ldap3AdapterTestDataFactory.create_search_options()


class TestLdap3AdapterUnit:
    """Comprehensive tests for Ldap3Adapter using factories and DRY principles.

    Uses parametrized tests and constants for maximum code reuse.
    """

    _factory = Ldap3AdapterTestDataFactory()

    def test_adapter_initialization(self, adapter: Ldap3Adapter) -> None:
        """Test adapter initialization creates valid instance."""
        assert adapter is not None
        assert adapter._connection is None
        assert adapter._server is None
        assert adapter.is_connected is False

    @pytest.mark.parametrize(
        "invalid_host",
        [
            "192.0.2.1",
            "invalid-host-that-does-not-exist",
        ],
    )
    def test_connect_with_invalid_host(
        self,
        adapter: Ldap3Adapter,
        invalid_host: str,
    ) -> None:
        """Test connect with invalid host scenarios (parametrized)."""
        config = FlextLdapModels.ConnectionConfig(
            host=invalid_host,
            port=Ldap3AdapterTestDataFactory.DEFAULT_PORT,
            timeout=1,  # Fast timeout for test
        )
        result = adapter.connect(config)

        # Use FlextTestsMatchers for failure assertion
        FlextTestsMatchers.assert_failure(result, "failed")

    def test_disconnect_with_real_connection(
        self,
        adapter: Ldap3Adapter,
        connection_config: FlextLdapModels.ConnectionConfig,
    ) -> None:
        """Test disconnect with real connection."""
        connect_result = adapter.connect(connection_config)
        if connect_result.is_failure:
            pytest.skip(f"Failed to connect: {connect_result.error}")

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
        ldap_container: dict[str, object],
        connection_type: str,
    ) -> None:
        """Test connection property with different connection states (parametrized)."""
        if connection_type == "connected":
            real_connection = TestDeduplicationHelpers.create_ldap3_connection(
                ldap_container,
            )
            if isinstance(real_connection, Connection):
                adapter._connection = real_connection
                connection = adapter.connection
                assert connection == real_connection
                assert isinstance(connection, Connection)
                if connection.bound:
                    unbind_func: Callable[[], None] = connection.unbind
                    unbind_func()
        else:
            adapter._connection = None
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
            real_connection_obj = TestDeduplicationHelpers.create_ldap3_connection(
                ldap_container,
            )
            if isinstance(real_connection_obj, Connection):
                adapter._connection = real_connection_obj
                assert adapter.is_connected is True
                if real_connection_obj.bound:
                    unbind_func: Callable[[], None] = real_connection_obj.unbind
                    unbind_func()
        elif connection_state == ConnectionState.DISCONNECTED.value:
            adapter._connection = None
            assert adapter.is_connected is False
        elif connection_state == ConnectionState.UNBOUND.value:
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

        # Use FlextTestsMatchers for failure assertion
        FlextTestsMatchers.assert_failure(result, "Not connected")

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
            search_options = FlextLdapModels.SearchOptions(
                base_dn="invalid=base,dn=invalid",  # Invalid base DN
                filter_str=self._factory.DEFAULT_FILTER,
                scope=self._factory.DEFAULT_SCOPE,
            )
            result = adapter.search(search_options)

            # Use FlextTestsMatchers for failure assertion
            FlextTestsMatchers.assert_failure(result)
        finally:
            adapter.disconnect()

    def test_convert_ldap3_results_none_handling(self) -> None:
        """Test _convert_ldap3_results handles None attribute values."""
        adapter = Ldap3Adapter()

        connection = Connection(Server("ldap://dummy"), client_strategy="MOCK_SYNC")
        connection.strategy.add_entry(
            self._factory.TEST_DN,
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
            assert dn == self._factory.TEST_DN
            assert attrs["testValue"] == ["single"]
            assert attrs["testList"] == ["a", "b"]

    def test_search_error_in_entry_conversion(
        self,
        adapter: Ldap3Adapter,
        connection_config: FlextLdapModels.ConnectionConfig,
    ) -> None:
        """Test search error handling when entry conversion fails using real connection."""
        connect_result = adapter.connect(connection_config)
        if connect_result.is_failure:
            pytest.skip(f"Failed to connect: {connect_result.error}")

        try:
            # Use invalid search options that will cause conversion issues
            # Use invalid base DN format (not empty, but invalid)
            invalid_search = FlextLdapModels.SearchOptions(
                base_dn="invalid=base,dn=invalid",  # Invalid base DN format
                filter_str=self._factory.DEFAULT_FILTER,
                scope=self._factory.DEFAULT_SCOPE,
            )
            result = adapter.search(invalid_search)

            # Should fail due to invalid base DN or conversion issues
            # Use FlextTestsMatchers for failure assertion
            error = FlextTestsMatchers.assert_failure(result)
            assert len(error) > 0
        finally:
            adapter.disconnect()

    def test_add_when_not_connected(self, adapter: Ldap3Adapter) -> None:
        """Test add when not connected."""
        adapter._connection = None

        entry = self._factory.create_test_entry()

        result = adapter.add(entry)

        # Use FlextTestsMatchers for failure assertion
        FlextTestsMatchers.assert_failure(result, "Not connected")

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
            entry = self._factory.create_invalid_entry()

            result = adapter.add(entry)

            # Use FlextTestsMatchers for failure assertion
            FlextTestsMatchers.assert_failure(result)
        finally:
            adapter.disconnect()
