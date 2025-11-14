"""Unit tests for FlextLdapOperations.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from flext_ldif.models import FlextLdifModels
from ldap3 import MODIFY_REPLACE

from flext_ldap.models import FlextLdapModels
from flext_ldap.services.connection import FlextLdapConnection
from flext_ldap.services.operations import FlextLdapOperations


class TestFlextLdapOperations:
    """Tests for FlextLdapOperations service."""

    def test_operations_initialization(self) -> None:
        """Test operations service initialization."""
        connection = FlextLdapConnection()
        operations = FlextLdapOperations(connection=connection)
        assert operations is not None
        assert operations._connection == connection

    def test_search_when_not_connected(self) -> None:
        """Test search when not connected."""
        connection = FlextLdapConnection()
        operations = FlextLdapOperations(connection=connection)

        search_options = FlextLdapModels.SearchOptions(
            base_dn="dc=example,dc=com",
            filter_str="(objectClass=*)",
            scope="SUBTREE",
        )

        result = operations.search(search_options)
        assert result.is_failure
        assert "Not connected" in (result.error or "")

    def test_add_when_not_connected(self) -> None:
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

    def test_modify_when_not_connected(self) -> None:
        """Test modify when not connected."""
        connection = FlextLdapConnection()
        operations = FlextLdapOperations(connection=connection)

        changes: dict[str, list[tuple[str, list[str]]]] = {
            "mail": [(MODIFY_REPLACE, ["test@example.com"])],
        }

        result = operations.modify("cn=test,dc=example,dc=com", changes)
        assert result.is_failure
        assert "Not connected" in (result.error or "")

    def test_delete_when_not_connected(self) -> None:
        """Test delete when not connected."""
        connection = FlextLdapConnection()
        operations = FlextLdapOperations(connection=connection)

        result = operations.delete("cn=test,dc=example,dc=com")
        assert result.is_failure
        assert "Not connected" in (result.error or "")

    def test_execute_when_not_connected(self) -> None:
        """Test execute when not connected."""
        connection = FlextLdapConnection()
        operations = FlextLdapOperations(connection=connection)

        result = operations.execute()
        assert result.is_failure
        assert "Not connected" in (result.error or "")
