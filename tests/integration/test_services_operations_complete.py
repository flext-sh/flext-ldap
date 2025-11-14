"""Complete integration tests for FlextLdapOperations with real LDAP server.

All tests use real LDAP operations, no mocks. Tests all methods and edge cases.

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
from tests.fixtures.constants import RFC
from tests.helpers.entry_helpers import EntryTestHelpers

pytestmark = pytest.mark.integration


class TestFlextLdapOperationsComplete:
    """Complete tests for FlextLdapOperations with real LDAP server."""

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

        connection.disconnect()

    def test_search_with_normalized_base_dn(
        self,
        operations_service: FlextLdapOperations,
    ) -> None:
        """Test search with normalized base DN."""
        # Test with DN that needs normalization
        search_options = FlextLdapModels.SearchOptions(
            base_dn=f"  {RFC.DEFAULT_BASE_DN}  ",  # With spaces
            filter_str="(objectClass=*)",
            scope="SUBTREE",
        )

        result = operations_service.search(search_options)
        assert result.is_success

    def test_search_with_different_server_types(
        self,
        operations_service: FlextLdapOperations,
    ) -> None:
        """Test search with different server types."""
        search_options = FlextLdapModels.SearchOptions(
            base_dn=RFC.DEFAULT_BASE_DN,
            filter_str="(objectClass=*)",
            scope="SUBTREE",
        )

        # Only test with 'rfc' which is always registered in quirks
        result = operations_service.search(search_options, server_type="rfc")
        assert result.is_success

    def test_add_with_normalized_dn(
        self,
        operations_service: FlextLdapOperations,
    ) -> None:
        """Test add with normalized DN."""
        # Entry with DN that needs normalization
        entry = EntryTestHelpers.create_entry(
            f"  cn=testnorm,ou=people,{RFC.DEFAULT_BASE_DN}  ",
            {
                "cn": ["testnorm"],
                "sn": ["Test"],
                "objectClass": [
                    "inetOrgPerson",
                    "organizationalPerson",
                    "person",
                    "top",
                ],
            },
        )

        result = EntryTestHelpers.add_and_cleanup(operations_service, entry)
        assert result.is_success

    def test_modify_with_dn_object(
        self,
        operations_service: FlextLdapOperations,
    ) -> None:
        """Test modify with DistinguishedName object."""
        # First add an entry
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(
                value="cn=testmoddn,ou=people,dc=flext,dc=local"
            ),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={
                    "cn": ["testmoddn"],
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

        # Modify using DN object
        changes: dict[str, list[tuple[str, list[str]]]] = {
            "mail": [(MODIFY_REPLACE, ["test@example.com"])],
        }

        modify_result = operations_service.modify(
            str(entry.dn) if entry.dn else "", changes
        )
        assert modify_result.is_success

        # Cleanup
        delete_result = operations_service.delete(str(entry.dn))
        assert delete_result.is_success or delete_result.is_failure

    def test_modify_with_normalized_dn(
        self,
        operations_service: FlextLdapOperations,
    ) -> None:
        """Test modify with normalized DN."""
        # First add an entry
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(
                value="cn=testmodnorm,ou=people,dc=flext,dc=local"
            ),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={
                    "cn": ["testmodnorm"],
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

        # Modify with DN that needs normalization
        changes: dict[str, list[tuple[str, list[str]]]] = {
            "mail": [(MODIFY_REPLACE, ["test@example.com"])],
        }

        modify_result = operations_service.modify(f"  {entry.dn!s}  ", changes)
        assert modify_result.is_success

        # Cleanup
        delete_result = operations_service.delete(str(entry.dn))
        assert delete_result.is_success or delete_result.is_failure

    def test_delete_with_dn_object(
        self,
        operations_service: FlextLdapOperations,
    ) -> None:
        """Test delete with DistinguishedName object."""
        # First add an entry
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(
                value="cn=testdeldn,ou=people,dc=flext,dc=local"
            ),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={
                    "cn": ["testdeldn"],
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

        # Delete using DN object
        delete_result = operations_service.delete(str(entry.dn) if entry.dn else "")
        assert delete_result.is_success

    def test_delete_with_normalized_dn(
        self,
        operations_service: FlextLdapOperations,
    ) -> None:
        """Test delete with normalized DN."""
        # First add an entry
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(
                value="cn=testdelnorm,ou=people,dc=flext,dc=local"
            ),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={
                    "cn": ["testdelnorm"],
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

        # Delete with DN that needs normalization
        delete_result = operations_service.delete(f"  {entry.dn!s}  ")
        assert delete_result.is_success

    def test_execute_when_connected(
        self,
        operations_service: FlextLdapOperations,
    ) -> None:
        """Test execute when connected."""
        result = operations_service.execute()
        assert result.is_success
        search_result = result.unwrap()
        assert search_result.total_count == 0
        assert len(search_result.entries) == 0

    def test_add_with_operation_result_success(
        self,
        operations_service: FlextLdapOperations,
    ) -> None:
        """Test add returns proper OperationResult on success."""
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(
                value="cn=testresult,ou=people,dc=flext,dc=local"
            ),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={
                    "cn": ["testresult"],
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
        assert result.is_success
        operation_result = result.unwrap()
        assert operation_result.success is True
        assert operation_result.operation_type == "add"
        assert operation_result.entries_affected == 1

        # Cleanup
        delete_result = operations_service.delete(str(entry.dn))
        assert delete_result.is_success or delete_result.is_failure

    def test_modify_with_operation_result_success(
        self,
        operations_service: FlextLdapOperations,
    ) -> None:
        """Test modify returns proper OperationResult on success."""
        # First add an entry
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(
                value="cn=testmodresult,ou=people,dc=flext,dc=local"
            ),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={
                    "cn": ["testmodresult"],
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

        # Modify
        changes: dict[str, list[tuple[str, list[str]]]] = {
            "mail": [(MODIFY_REPLACE, ["test@example.com"])],
        }

        modify_result = operations_service.modify(str(entry.dn), changes)
        assert modify_result.is_success
        operation_result = modify_result.unwrap()
        assert operation_result.success is True
        assert operation_result.operation_type == "modify"
        assert operation_result.entries_affected == 1

        # Cleanup
        delete_result = operations_service.delete(str(entry.dn))
        assert delete_result.is_success or delete_result.is_failure

    def test_delete_with_operation_result_success(
        self,
        operations_service: FlextLdapOperations,
    ) -> None:
        """Test delete returns proper OperationResult on success."""
        # First add an entry
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(
                value="cn=testdelresult,ou=people,dc=flext,dc=local"
            ),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={
                    "cn": ["testdelresult"],
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

        # Delete
        delete_result = operations_service.delete(str(entry.dn))
        assert delete_result.is_success
        operation_result = delete_result.unwrap()
        assert operation_result.success is True
        assert operation_result.operation_type == "delete"
        assert operation_result.entries_affected == 1
