"""Integration tests for FlextLdapOperations with real LDAP server.

Tests all operations service methods with real server and flext-ldif integration.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from collections.abc import Generator

import pytest
from flext_ldif.models import FlextLdifModels
from ldap3 import MODIFY_REPLACE

from flext_ldap.models import FlextLdapModels
from flext_ldap.services.connection import FlextLdapConnection
from flext_ldap.services.operations import FlextLdapOperations

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
        search_options = FlextLdapModels.SearchOptions(
            base_dn=str(ldap_container["base_dn"]),
            filter_str="(objectClass=*)",
            scope="SUBTREE",
        )

        result = operations_service.search(search_options)
        assert result.is_success, f"Search failed: {result.error}"
        search_result = result.unwrap()
        assert len(search_result.entries) > 0
        assert search_result.total_count == len(search_result.entries)

    def test_search_with_base_scope(
        self,
        operations_service: FlextLdapOperations,
        ldap_container: dict[str, object],
    ) -> None:
        """Test search with BASE scope."""
        search_options = FlextLdapModels.SearchOptions(
            base_dn=str(ldap_container["base_dn"]),
            filter_str="(objectClass=*)",
            scope="BASE",
        )

        result = operations_service.search(search_options)
        assert result.is_success
        search_result = result.unwrap()
        assert len(search_result.entries) <= 1

    def test_search_with_onelevel_scope(
        self,
        operations_service: FlextLdapOperations,
        ldap_container: dict[str, object],
    ) -> None:
        """Test search with ONELEVEL scope."""
        search_options = FlextLdapModels.SearchOptions(
            base_dn=str(ldap_container["base_dn"]),
            filter_str="(objectClass=*)",
            scope="ONELEVEL",
        )

        result = operations_service.search(search_options)
        assert result.is_success
        search_result = result.unwrap()
        assert isinstance(search_result.entries, list)

    def test_search_with_attributes(
        self,
        operations_service: FlextLdapOperations,
        ldap_container: dict[str, object],
    ) -> None:
        """Test search with specific attributes."""
        # Note: "dn" is not a searchable attribute, it's part of entry structure
        search_options = FlextLdapModels.SearchOptions(
            base_dn=str(ldap_container["base_dn"]),
            filter_str="(objectClass=*)",
            scope="SUBTREE",
            attributes=["objectClass", "cn"],  # Removed "dn", added "cn"
        )

        result = operations_service.search(search_options)
        assert result.is_success
        search_result = result.unwrap()
        assert len(search_result.entries) > 0

    def test_search_with_size_limit(
        self,
        operations_service: FlextLdapOperations,
        ldap_container: dict[str, object],
    ) -> None:
        """Test search with size limit."""
        search_options = FlextLdapModels.SearchOptions(
            base_dn=str(ldap_container["base_dn"]),
            filter_str="(objectClass=*)",
            scope="SUBTREE",
            size_limit=2,
        )

        result = operations_service.search(search_options)
        assert result.is_success
        search_result = result.unwrap()
        assert len(search_result.entries) <= 2

    def test_search_when_not_connected(
        self,
        ldap_container: dict[str, object],
    ) -> None:
        """Test search when not connected."""
        connection = FlextLdapConnection()
        operations = FlextLdapOperations(connection=connection)

        search_options = FlextLdapModels.SearchOptions(
            base_dn=str(ldap_container["base_dn"]),
            filter_str="(objectClass=*)",
            scope="SUBTREE",
        )

        result = operations.search(search_options)
        assert result.is_failure
        assert "Not connected" in (result.error or "")


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
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(
                value="cn=testopsadd,ou=people,dc=flext,dc=local"
            ),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={
                    "cn": ["testopsadd"],
                    "sn": ["Test"],
                    "objectClass": [
                        "inetOrgPerson",
                        "organizationalPerson",
                        "person",
                        "top",
                    ],
                }
            ),
        )

        # Cleanup first
        _ = operations_service.delete(str(entry.dn))

        result = operations_service.add(entry)
        assert result.is_success, f"Add failed: {result.error}"
        operation_result = result.unwrap()
        assert operation_result.success is True
        assert operation_result.entries_affected == 1

        # Cleanup
        delete_result = operations_service.delete(str(entry.dn))
        assert delete_result.is_success or delete_result.is_failure

    def test_add_entry_when_not_connected(self) -> None:
        """Test add when not connected."""
        connection = FlextLdapConnection()
        operations = FlextLdapOperations(connection=connection)

        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=test,dc=example,dc=com"),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={"cn": ["test"], "objectClass": ["top", "person"]}
            ),
        )

        result = operations.add(entry)
        assert result.is_failure
        assert "Not connected" in (result.error or "")


class TestFlextLdapOperationsModify:
    """Tests for FlextLdapOperations modify method."""

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

    def test_modify_entry(
        self,
        operations_service: FlextLdapOperations,
    ) -> None:
        """Test modifying an entry."""
        # First add an entry
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(
                value="cn=testopsmodify,ou=people,dc=flext,dc=local"
            ),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={
                    "cn": ["testopsmodify"],
                    "sn": ["Test"],
                    "objectClass": [
                        "inetOrgPerson",
                        "organizationalPerson",
                        "person",
                        "top",
                    ],
                }
            ),
        )

        # Cleanup first
        _ = operations_service.delete(str(entry.dn))

        add_result = operations_service.add(entry)
        assert add_result.is_success

        # Modify entry
        changes: dict[str, list[tuple[str, list[str]]]] = {
            "mail": [(MODIFY_REPLACE, ["modified@example.com"])],
        }

        modify_result = operations_service.modify(str(entry.dn), changes)
        assert modify_result.is_success, f"Modify failed: {modify_result.error}"
        operation_result = modify_result.unwrap()
        assert operation_result.success is True

        # Cleanup
        delete_result = operations_service.delete(str(entry.dn))
        assert delete_result.is_success or delete_result.is_failure


class TestFlextLdapOperationsDelete:
    """Tests for FlextLdapOperations delete method."""

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

    def test_delete_entry(
        self,
        operations_service: FlextLdapOperations,
    ) -> None:
        """Test deleting an entry."""
        # First add an entry
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(
                value="cn=testopsdelete,ou=people,dc=flext,dc=local"
            ),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={
                    "cn": ["testopsdelete"],
                    "sn": ["Test"],
                    "objectClass": [
                        "inetOrgPerson",
                        "organizationalPerson",
                        "person",
                        "top",
                    ],
                }
            ),
        )

        # Cleanup first
        _ = operations_service.delete(str(entry.dn))

        add_result = operations_service.add(entry)
        assert add_result.is_success

        # Delete entry
        delete_result = operations_service.delete(str(entry.dn))
        assert delete_result.is_success, f"Delete failed: {delete_result.error}"
        operation_result = delete_result.unwrap()
        assert operation_result.success is True
        assert operation_result.entries_affected == 1

    def test_delete_when_not_connected(self) -> None:
        """Test delete when not connected."""
        connection = FlextLdapConnection()
        operations = FlextLdapOperations(connection=connection)

        result = operations.delete("cn=test,dc=example,dc=com")
        assert result.is_failure
        assert "Not connected" in (result.error or "")
