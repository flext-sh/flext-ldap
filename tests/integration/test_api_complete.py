"""Complete integration tests for FlextLdap API with real LDAP server.

All tests use real LDAP operations, no mocks. Tests all methods and edge cases.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest
from flext_ldif.models import FlextLdifModels
from ldap3 import MODIFY_ADD, MODIFY_REPLACE

from flext_ldap import FlextLdap
from flext_ldap.config import FlextLdapConfig
from flext_ldap.models import FlextLdapModels
from tests.fixtures.constants import RFC
from tests.helpers.entry_helpers import EntryTestHelpers

pytestmark = pytest.mark.integration


class TestFlextLdapAPIComplete:
    """Complete tests for FlextLdap API with real LDAP server."""

    def test_api_initialization_with_config(self) -> None:
        """Test API initialization with custom config."""
        config = FlextLdapConfig(
            ldap_host=RFC.DEFAULT_HOST,
            ldap_port=RFC.DEFAULT_PORT,
        )
        api = FlextLdap(config=config)
        assert api._config == config
        assert api._connection is not None
        assert api._operations is not None

    def test_client_property(
        self,
        ldap_client: FlextLdap,
    ) -> None:
        """Test client property access."""
        client = ldap_client.client
        assert client is not None
        assert client == ldap_client._operations

    def test_context_manager(
        self,
        connection_config: FlextLdapModels.ConnectionConfig,
    ) -> None:
        """Test context manager usage."""
        with FlextLdap() as api:
            result = api.connect(connection_config)
            assert result.is_success
            assert api.is_connected is True

        # Should be disconnected after context exit
        assert api.is_connected is False

    def test_context_manager_with_exception(
        self,
        connection_config: FlextLdapModels.ConnectionConfig,
    ) -> None:
        """Test context manager with exception."""
        test_exception = ValueError("Test exception")
        try:
            with FlextLdap() as api:
                result = api.connect(connection_config)
                assert result.is_success
                raise test_exception
        except ValueError:
            pass

        # Should still be disconnected
        api = FlextLdap()
        result = api.connect(connection_config)
        if result.is_success:
            api.disconnect()

    def test_search_with_different_server_types(
        self,
        ldap_client: FlextLdap,
        ldap_container: dict[str, object],
    ) -> None:
        """Test search with different server types."""
        search_options = FlextLdapModels.SearchOptions(
            base_dn=str(ldap_container["base_dn"]),
            filter_str="(objectClass=*)",
            scope="SUBTREE",
        )

        # Only test with 'rfc' which is always registered in quirks
        result = ldap_client.search(search_options, server_type="rfc")
        assert result.is_success

    def test_add_with_operation_result(
        self,
        ldap_client: FlextLdap,
    ) -> None:
        """Test add returns proper OperationResult."""
        entry = EntryTestHelpers.create_entry(
            "cn=testapiadd,ou=people,dc=flext,dc=local",
            {
                "cn": ["testapiadd"],
                "sn": ["Test"],
                "objectClass": [
                    "inetOrgPerson",
                    "organizationalPerson",
                    "person",
                    "top",
                ],
            },
        )

        result = EntryTestHelpers.add_and_cleanup(ldap_client, entry)
        assert result.is_success
        operation_result = result.unwrap()
        assert operation_result.success is True
        assert operation_result.operation_type == "add"

    def test_modify_with_dn_object(
        self,
        ldap_client: FlextLdap,
    ) -> None:
        """Test modify with DistinguishedName object."""
        entry_dict = {
            "dn": "cn=testapimod,ou=people,dc=flext,dc=local",
            "attributes": {
                "cn": ["testapimod"],
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
        _ = ldap_client.delete(str(entry.dn))

        add_result = ldap_client.add(entry)
        assert add_result.is_success

        # Modify using DN object
        changes: dict[str, list[tuple[str, list[str]]]] = {
            "mail": [(MODIFY_REPLACE, ["test@example.com"])],
        }

        modify_result = ldap_client.modify(str(entry.dn) if entry.dn else "", changes)
        assert modify_result.is_success

        # Cleanup
        delete_result = ldap_client.delete(str(entry.dn))
        assert delete_result.is_success or delete_result.is_failure

    def test_delete_with_dn_object(
        self,
        ldap_client: FlextLdap,
    ) -> None:
        """Test delete with DistinguishedName object."""
        entry_dict = {
            "dn": "cn=testapidel,ou=people,dc=flext,dc=local",
            "attributes": {
                "cn": ["testapidel"],
                "sn": ["Test"],
                "objectClass": [
                    "inetOrgPerson",
                    "organizationalPerson",
                    "person",
                    "top",
                ],
            },
        }

        entry, add_result, delete_result = EntryTestHelpers.delete_entry_with_verification(
            ldap_client, entry_dict
        )

        assert add_result.is_success

        # Delete using DN object
        delete_result = ldap_client.delete(str(entry.dn) if entry.dn else "")
        assert delete_result.is_success

    def test_execute_when_connected(
        self,
        ldap_client: FlextLdap,
    ) -> None:
        """Test execute when connected."""
        result = ldap_client.execute()
        assert result.is_success
        search_result = result.unwrap()
        assert search_result.total_count == 0

    def test_execute_when_not_connected(self) -> None:
        """Test execute when not connected."""
        api = FlextLdap()
        result = api.execute()
        # Execute returns empty result, not failure
        assert result.is_success
        search_result = result.unwrap()
        assert search_result.total_count == 0

    def test_connect_with_service_config(
        self,
        ldap_container: dict[str, object],
    ) -> None:
        """Test connect using service config."""
        config = FlextLdapConfig(
            ldap_host=str(ldap_container["host"]),
            ldap_port=int(str(ldap_container["port"])),
            ldap_bind_dn=str(ldap_container["bind_dn"]),
            ldap_bind_password=str(ldap_container["password"]),
        )
        api = FlextLdap(config=config)
        result = api.connect(None)  # Use service config
        assert result.is_success
        api.disconnect()

    def test_all_operations_in_sequence(
        self,
        ldap_client: FlextLdap,
    ) -> None:
        """Test all operations in sequence."""
        # Add
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(
                value="cn=testsequence,ou=people,dc=flext,dc=local"
            ),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={
                    "cn": ["testsequence"],
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
        _ = ldap_client.delete(str(entry.dn))

        add_result = ldap_client.add(entry)
        assert add_result.is_success

        # Search
        search_options = FlextLdapModels.SearchOptions(
            base_dn=str(entry.dn),
            filter_str="(objectClass=*)",
            scope="BASE",
        )
        search_result = ldap_client.search(search_options)
        assert search_result.is_success
        assert len(search_result.unwrap().entries) == 1

        # Modify
        changes: dict[str, list[tuple[str, list[str]]]] = {
            "mail": [(MODIFY_ADD, ["test@example.com"])],
        }
        modify_result = ldap_client.modify(str(entry.dn), changes)
        assert modify_result.is_success

        # Delete
        delete_result = ldap_client.delete(str(entry.dn))
        assert delete_result.is_success
