"""Complete coverage tests for FlextLdapOperations with real LDAP server.

Tests all code paths including error handling and edge cases.

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

pytestmark = pytest.mark.integration


class TestFlextLdapOperationsCompleteCoverage:
    """Complete coverage tests for FlextLdapOperations."""

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

    def test_search_with_normalized_base_dn_whitespace(
        self,
        operations_service: FlextLdapOperations,
    ) -> None:
        """Test search with base DN that needs normalization."""
        search_options = FlextLdapModels.SearchOptions(
            base_dn=f"  {RFC.DEFAULT_BASE_DN}  ",
            filter_str="(objectClass=*)",
            scope="SUBTREE",
        )

        result = operations_service.search(search_options)
        assert result.is_success

    def test_search_error_handling(
        self,
        operations_service: FlextLdapOperations,
    ) -> None:
        """Test search error handling path."""
        # This tests the error path when adapter.search fails
        search_options = FlextLdapModels.SearchOptions(
            base_dn=RFC.DEFAULT_BASE_DN,
            filter_str="(objectClass=*)",
            scope="SUBTREE",
        )

        # Disconnect to trigger error
        operations_service._connection.disconnect()

        result = operations_service.search(search_options)
        assert result.is_failure
        assert "Not connected" in (result.error or "")

    def test_add_with_normalized_dn_whitespace(
        self,
        operations_service: FlextLdapOperations,
    ) -> None:
        """Test add with DN that needs normalization."""
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(
                value=f"  cn=testnorm2,ou=people,{RFC.DEFAULT_BASE_DN}  "
            ),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={
                    "cn": ["testnorm2"],
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
        _ = operations_service.delete(str(entry.dn).strip())

        result = operations_service.add(entry)
        assert result.is_success

        # Verify DN was normalized
        assert str(entry.dn).strip() == str(entry.dn)

        # Cleanup
        delete_result = operations_service.delete(str(entry.dn).strip())
        assert delete_result.is_success or delete_result.is_failure

    def test_add_error_handling(
        self,
        operations_service: FlextLdapOperations,
    ) -> None:
        """Test add error handling path."""
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(
                value="cn=testerror,ou=people,dc=flext,dc=local"
            ),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={
                    "cn": ["testerror"],
                    "objectClass": [
                        "inetOrgPerson",
                        "organizationalPerson",
                        "person",
                        "top",
                    ],
                }
            ),
        )

        # Disconnect to trigger error
        operations_service._connection.disconnect()

        result = operations_service.add(entry)
        assert result.is_failure
        assert "Not connected" in (result.error or "")

    def test_add_with_adapter_failure(
        self,
        operations_service: FlextLdapOperations,
    ) -> None:
        """Test add when adapter.add fails."""
        # Entry that will fail to add (invalid DN format)
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="invalid-dn"),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={
                    "cn": ["test"],
                    "objectClass": ["top", "person"],
                }
            ),
        )

        result = operations_service.add(entry)
        # Should fail and return OperationResult with success=False
        assert result.is_failure

    def test_modify_with_normalized_dn_whitespace(
        self,
        operations_service: FlextLdapOperations,
    ) -> None:
        """Test modify with DN that needs normalization."""
        # First add an entry
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(
                value="cn=testmodnorm2,ou=people,dc=flext,dc=local"
            ),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={
                    "cn": ["testmodnorm2"],
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

    def test_modify_error_handling(
        self,
        operations_service: FlextLdapOperations,
    ) -> None:
        """Test modify error handling path."""
        changes: dict[str, list[tuple[str, list[str]]]] = {
            "mail": [(MODIFY_REPLACE, ["test@example.com"])],
        }

        # Disconnect to trigger error
        operations_service._connection.disconnect()

        result = operations_service.modify("cn=test,dc=flext,dc=local", changes)
        assert result.is_failure
        assert "Not connected" in (result.error or "")

    def test_delete_with_normalized_dn_whitespace(
        self,
        operations_service: FlextLdapOperations,
    ) -> None:
        """Test delete with DN that needs normalization."""
        # First add an entry
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(
                value="cn=testdelnorm2,ou=people,dc=flext,dc=local"
            ),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={
                    "cn": ["testdelnorm2"],
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

    def test_delete_error_handling(
        self,
        operations_service: FlextLdapOperations,
    ) -> None:
        """Test delete error handling path."""
        # Disconnect to trigger error
        operations_service._connection.disconnect()

        result = operations_service.delete("cn=test,dc=flext,dc=local")
        assert result.is_failure
        assert "Not connected" in (result.error or "")

    def test_execute_error_handling(self) -> None:
        """Test execute error handling path."""
        connection = FlextLdapConnection()
        operations = FlextLdapOperations(connection=connection)

        result = operations.execute()
        assert result.is_failure
        assert "Not connected" in (result.error or "")
