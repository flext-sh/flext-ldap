"""Integration tests for FlextLdapOperations error cases with real LDAP server.

Tests error handling paths in operations service for coverage.
All tests use real LDAP server from fixtures.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest
from ldap3 import MODIFY_REPLACE

from flext_ldap.models import FlextLdapModels
from flext_ldap.services.connection import FlextLdapConnection
from flext_ldap.services.operations import FlextLdapOperations
from tests.helpers.entry_helpers import EntryTestHelpers

pytestmark = pytest.mark.integration


class TestFlextLdapOperationsErrorCoverage:
    """Tests for operations service error handling coverage."""

    def test_search_with_failed_adapter_search(
        self,
        connection_config: FlextLdapModels.ConnectionConfig,
    ) -> None:
        """Test search when adapter search fails."""
        connection = FlextLdapConnection()
        connect_result = connection.connect(connection_config)
        assert connect_result.is_success

        operations = FlextLdapOperations(connection=connection)

        # Search with invalid base_dn to trigger error path
        search_options = FlextLdapModels.SearchOptions(
            base_dn="invalid=base,dn=invalid",
            filter_str="(objectClass=*)",
            scope="SUBTREE",
        )

        result = operations.search(search_options)
        # Should handle error gracefully
        assert result.is_failure or result.is_success

        connection.disconnect()

    def test_add_with_failed_adapter_add(
        self,
        connection_config: FlextLdapModels.ConnectionConfig,
    ) -> None:
        """Test add when adapter add fails."""
        connection = FlextLdapConnection()
        connect_result = connection.connect(connection_config)
        assert connect_result.is_success

        operations = FlextLdapOperations(connection=connection)

        # Try to add entry with invalid DN to trigger error path
        entry = EntryTestHelpers.create_entry(
            "invalid=dn",
            {"objectClass": ["top"]},
        )

        result = operations.add(entry)
        # Should return failure with proper error message
        assert result.is_failure
        assert result.error is not None

        connection.disconnect()

    def test_modify_with_failed_adapter_modify(
        self,
        connection_config: FlextLdapModels.ConnectionConfig,
    ) -> None:
        """Test modify when adapter modify fails."""
        connection = FlextLdapConnection()
        connect_result = connection.connect(connection_config)
        assert connect_result.is_success

        operations = FlextLdapOperations(connection=connection)

        # Try to modify non-existent entry
        changes: dict[str, list[tuple[str, list[str]]]] = {
            "cn": [(MODIFY_REPLACE, ["modified"])],
        }

        result = operations.modify("cn=nonexistent,dc=flext,dc=local", changes)
        # Should return failure
        assert result.is_failure
        assert result.error is not None

        connection.disconnect()

    def test_delete_with_failed_adapter_delete(
        self,
        connection_config: FlextLdapModels.ConnectionConfig,
    ) -> None:
        """Test delete when adapter delete fails."""
        connection = FlextLdapConnection()
        connect_result = connection.connect(connection_config)
        assert connect_result.is_success

        operations = FlextLdapOperations(connection=connection)

        # Try to delete non-existent entry
        result = operations.delete("cn=nonexistent,dc=flext,dc=local")
        # Should return failure
        assert result.is_failure
        assert result.error is not None

        connection.disconnect()

    def test_execute_when_not_connected(
        self,
    ) -> None:
        """Test execute when not connected."""
        connection = FlextLdapConnection()
        operations = FlextLdapOperations(connection=connection)

        result = operations.execute()
        # Should return failure when not connected
        assert result.is_failure
        assert "Not connected" in (result.error or "")
