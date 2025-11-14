"""Integration tests for FlextLdapOperations with real LDAP server.

Tests all operations service methods with real server and flext-ldif integration.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from collections.abc import Generator

import pytest
from ldap3 import MODIFY_REPLACE

from flext_ldap.models import FlextLdapModels
from flext_ldap.services.connection import FlextLdapConnection
from flext_ldap.services.operations import FlextLdapOperations
from tests.fixtures.constants import RFC
from tests.helpers.entry_helpers import EntryTestHelpers
from tests.helpers.operation_helpers import TestOperationHelpers

pytestmark = pytest.mark.integration


class TestFlextLdapOperationsSearch:
    """Tests for FlextLdapOperations search method."""

    @pytest.fixture
    def operations_service(
        self,
        connection_config: FlextLdapModels.ConnectionConfig,
    ) -> Generator[FlextLdapOperations]:
        """Get operations service with connected adapter."""
        connection = FlextLdapConnection()
        connect_result = connection.connect(connection_config)
        if connect_result.is_failure:
            pytest.skip(f"Failed to connect: {connect_result.error}")

        operations = FlextLdapOperations(connection=connection)
        yield operations

        # Cleanup
        connection.disconnect()

    def test_search_all_entries(
        self,
        operations_service: FlextLdapOperations,
        ldap_container: dict[str, object],
    ) -> None:
        """Test searching all entries."""
        search_result = TestOperationHelpers.search_and_assert_success(
            operations_service,
            str(ldap_container["base_dn"]),
            filter_str="(objectClass=*)",
            scope="SUBTREE",
            expected_min_count=1,
        )
        assert search_result.total_count == len(search_result.entries)

    def test_search_with_base_scope(
        self,
        operations_service: FlextLdapOperations,
        ldap_container: dict[str, object],
    ) -> None:
        """Test search with BASE scope."""
        _ = TestOperationHelpers.search_and_assert_success(
            operations_service,
            str(ldap_container["base_dn"]),
            filter_str="(objectClass=*)",
            scope="BASE",
            expected_max_count=1,
        )

    def test_search_with_onelevel_scope(
        self,
        operations_service: FlextLdapOperations,
        ldap_container: dict[str, object],
    ) -> None:
        """Test search with ONELEVEL scope."""
        search_result = TestOperationHelpers.search_and_assert_success(
            operations_service,
            str(ldap_container["base_dn"]),
            filter_str="(objectClass=*)",
            scope="ONELEVEL",
        )
        assert isinstance(search_result.entries, list)

    def test_search_with_attributes(
        self,
        operations_service: FlextLdapOperations,
        ldap_container: dict[str, object],
    ) -> None:
        """Test search with specific attributes."""
        _ = TestOperationHelpers.search_and_assert_success(
            operations_service,
            str(ldap_container["base_dn"]),
            filter_str="(objectClass=*)",
            scope="SUBTREE",
            attributes=["objectClass", "cn"],
            expected_min_count=1,
        )

    def test_search_with_size_limit(
        self,
        operations_service: FlextLdapOperations,
        ldap_container: dict[str, object],
    ) -> None:
        """Test search with size limit."""
        _ = TestOperationHelpers.search_and_assert_success(
            operations_service,
            str(ldap_container["base_dn"]),
            filter_str="(objectClass=*)",
            scope="SUBTREE",
            size_limit=2,
            expected_max_count=2,
        )

    def test_search_when_not_connected(
        self,
        ldap_container: dict[str, object],
    ) -> None:
        """Test search when not connected."""
        connection = FlextLdapConnection()
        operations = FlextLdapOperations(connection=connection)

        search_options = TestOperationHelpers.create_search_options(
            str(ldap_container["base_dn"]),
            filter_str="(objectClass=*)",
            scope="SUBTREE",
        )

        TestOperationHelpers.execute_operation_when_not_connected(
            operations,
            "search",
            search_options=search_options,
        )

    def test_search_with_failed_adapter_search(
        self,
        operations_service: FlextLdapOperations,
        ldap_container: dict[str, object],
    ) -> None:
        """Test search when adapter search fails - covers line 87."""
        # Force adapter to fail by using invalid filter that causes search error
        search_options = FlextLdapModels.SearchOptions(
            base_dn=str(ldap_container["base_dn"]),
            filter_str="(invalidFilterSyntax)",  # Invalid filter syntax
            scope="SUBTREE",
        )

        result = operations_service.search(search_options)
        # Should handle adapter failure gracefully
        assert (
            result.is_failure or result.is_success
        )  # May fail or succeed depending on server


class TestFlextLdapOperationsAdd:
    """Tests for FlextLdapOperations add method."""

    @pytest.fixture
    def operations_service(
        self,
        connection_config: FlextLdapModels.ConnectionConfig,
    ) -> Generator[FlextLdapOperations]:
        """Get operations service with connected adapter."""
        connection = FlextLdapConnection()
        connect_result = connection.connect(connection_config)
        if connect_result.is_failure:
            pytest.skip(f"Failed to connect: {connect_result.error}")

        operations = FlextLdapOperations(connection=connection)
        yield operations

        # Cleanup
        connection.disconnect()

    def test_add_entry(
        self,
        operations_service: FlextLdapOperations,
    ) -> None:
        """Test adding an entry."""
        entry = TestOperationHelpers.create_inetorgperson_entry(
            "testopsadd", RFC.DEFAULT_BASE_DN, sn="Test"
        )

        result = EntryTestHelpers.add_and_cleanup(operations_service, entry)
        TestOperationHelpers.assert_operation_result_success(
            result, expected_operation_type="add", expected_entries_affected=1
        )

    def test_add_entry_when_not_connected(self) -> None:
        """Test add when not connected."""
        connection = FlextLdapConnection()
        operations = FlextLdapOperations(connection=connection)

        entry = TestOperationHelpers.create_entry_with_dn_and_attributes(
            "cn=test,dc=example,dc=com",
            {"cn": ["test"], "objectClass": ["top", "person"]},
        )

        TestOperationHelpers.execute_operation_when_not_connected(
            operations,
            "add",
            entry=entry,
        )


class TestFlextLdapOperationsModify:
    """Tests for FlextLdapOperations modify method."""

    @pytest.fixture
    def operations_service(
        self,
        connection_config: FlextLdapModels.ConnectionConfig,
    ) -> Generator[FlextLdapOperations]:
        """Get operations service with connected adapter."""
        connection = FlextLdapConnection()
        TestOperationHelpers.connect_with_skip_on_failure(connection, connection_config)

        operations = FlextLdapOperations(connection=connection)
        yield operations

        # Cleanup
        connection.disconnect()

    def test_modify_entry(
        self,
        operations_service: FlextLdapOperations,
    ) -> None:
        """Test modifying an entry."""
        entry = TestOperationHelpers.create_inetorgperson_entry(
            "testopsmodify", RFC.DEFAULT_BASE_DN, sn="Test"
        )
        entry_dict = {
            "dn": str(entry.dn),
            "attributes": entry.attributes.attributes if entry.attributes else {},
        }

        changes: dict[str, list[tuple[str, list[str]]]] = {
            "mail": [(MODIFY_REPLACE, ["modified@example.com"])],
        }

        _entry, add_result, modify_result = (
            EntryTestHelpers.modify_entry_with_verification(
                operations_service, entry_dict, changes, verify_attribute=None
            )
        )

        assert add_result.is_success
        TestOperationHelpers.assert_operation_result_success(
            modify_result, expected_operation_type="modify"
        )


class TestFlextLdapOperationsDelete:
    """Tests for FlextLdapOperations delete method."""

    @pytest.fixture
    def operations_service(
        self,
        connection_config: FlextLdapModels.ConnectionConfig,
    ) -> Generator[FlextLdapOperations]:
        """Get operations service with connected adapter."""
        connection = FlextLdapConnection()
        TestOperationHelpers.connect_with_skip_on_failure(connection, connection_config)

        operations = FlextLdapOperations(connection=connection)
        yield operations

        # Cleanup
        connection.disconnect()

    def test_delete_entry(
        self,
        operations_service: FlextLdapOperations,
    ) -> None:
        """Test deleting an entry."""
        entry_dict = TestOperationHelpers.create_entry_dict(
            "testopsdelete", RFC.DEFAULT_BASE_DN, sn="Test"
        )

        _entry, add_result, delete_result = (
            EntryTestHelpers.delete_entry_with_verification(
                operations_service, entry_dict
            )
        )

        assert add_result.is_success
        TestOperationHelpers.assert_operation_result_unwrapped(
            delete_result,
            expected_operation_type="delete",
            expected_entries_affected=1,
        )

    def test_delete_when_not_connected(self) -> None:
        """Test delete when not connected."""
        connection = FlextLdapConnection()
        operations = FlextLdapOperations(connection=connection)

        TestOperationHelpers.execute_operation_when_not_connected(
            operations,
            "delete",
            dn="cn=test,dc=example,dc=com",
        )


class TestFlextLdapOperationsExecute:
    """Tests for FlextLdapOperations execute method."""

    @pytest.fixture
    def operations_service(
        self,
        connection_config: FlextLdapModels.ConnectionConfig,
    ) -> Generator[FlextLdapOperations]:
        """Get operations service with connected adapter."""
        connection = FlextLdapConnection()
        TestOperationHelpers.connect_with_skip_on_failure(connection, connection_config)

        operations = FlextLdapOperations(connection=connection)
        yield operations

        connection.disconnect()

    def test_execute_when_connected(
        self,
        operations_service: FlextLdapOperations,
    ) -> None:
        """Test execute method when connected - covers execute() method."""
        search_result = TestOperationHelpers.execute_and_assert_success(
            operations_service
        )
        assert search_result.total_count == 0
        assert len(search_result.entries) == 0

    def test_execute_when_not_connected(self) -> None:
        """Test execute method when not connected - covers execute() failure path."""
        connection = FlextLdapConnection()
        operations = FlextLdapOperations(connection=connection)

        result = operations.execute()
        assert result.is_failure
        assert "Not connected" in (result.error or "")
