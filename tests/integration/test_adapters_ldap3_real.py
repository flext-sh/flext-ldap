"""Integration tests for Ldap3Adapter with real LDAP server.

Tests Ldap3Adapter with real LDAP operations, no mocks.
All tests use real LDAP server and fixtures.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Generator
from typing import cast

import pytest
from ldap3 import MODIFY_REPLACE

from flext_ldap.adapters.ldap3 import Ldap3Adapter
from flext_ldap.constants import FlextLdapConstants
from flext_ldap.models import FlextLdapModels
from flext_ldap.protocols import FlextLdapProtocols

from ..fixtures.constants import RFC
from ..fixtures.typing import GenericFieldsDict, LdapContainerDict
from ..helpers.entry_helpers import EntryTestHelpers
from ..helpers.operation_helpers import TestOperationHelpers

pytestmark = pytest.mark.integration


class TestLdap3AdapterReal:
    """Tests for Ldap3Adapter with real LDAP server."""

    @pytest.fixture
    def connected_adapter(
        self,
        connection_config: FlextLdapModels.ConnectionConfig,
    ) -> Generator[Ldap3Adapter]:
        """Get connected adapter for testing."""
        adapter = Ldap3Adapter()
        connect_result = adapter.connect(connection_config)
        if connect_result.is_failure:
            pytest.skip(f"Failed to connect: {connect_result.error}")
        yield adapter
        adapter.disconnect()

    @pytest.mark.timeout(30)
    def test_connect_with_real_server(
        self,
        connection_config: FlextLdapModels.ConnectionConfig,
    ) -> None:
        """Test connection with real LDAP server."""
        adapter = Ldap3Adapter()
        result = adapter.connect(connection_config)
        TestOperationHelpers.assert_result_success(result)
        # Validate actual content: adapter should be connected
        assert adapter.is_connected is True
        adapter.disconnect()

    @pytest.mark.timeout(30)
    def test_search_with_real_server(
        self,
        connected_adapter: Ldap3Adapter,
        ldap_container: LdapContainerDict,
    ) -> None:
        """Test search with real LDAP server."""
        search_options = FlextLdapModels.SearchOptions(
            base_dn=RFC.DEFAULT_BASE_DN,
            filter_str="(objectClass=*)",
            scope=FlextLdapConstants.SearchScope.SUBTREE,
        )
        result = connected_adapter.search(search_options)
        search_result = TestOperationHelpers.assert_result_success_and_unwrap(
            result,
            error_message="Search",
        )
        assert len(search_result.entries) > 0

    @pytest.mark.timeout(30)
    def test_add_entry_with_real_server(
        self,
        connected_adapter: Ldap3Adapter,
    ) -> None:
        """Test adding entry with real LDAP server."""
        entry = TestOperationHelpers.create_inetorgperson_entry(
            "testldap3add",
            RFC.DEFAULT_BASE_DN,
            sn="Test",
        )

        result = connected_adapter.add(entry)
        TestOperationHelpers.assert_result_success(result)
        operation_result = result.unwrap()
        # Validate actual content: add() returns OperationResult with operation_type field
        assert operation_result.operation_type == FlextLdapConstants.OperationType.ADD
        assert operation_result.success is True
        assert operation_result.entries_affected == 1

        # Cleanup
        delete_result = connected_adapter.delete(str(entry.dn))
        if delete_result.is_success:
            delete_op_result = delete_result.unwrap()
            assert delete_op_result.success is True
            assert delete_op_result.entries_affected == 1
        else:
            # If delete fails, validate error message
            error_msg = TestOperationHelpers.get_error_message(delete_result)
            assert len(error_msg) > 0

    @pytest.mark.timeout(30)
    def test_modify_entry_with_real_server(
        self,
        connected_adapter: Ldap3Adapter,
    ) -> None:
        """Test modifying entry with real LDAP server."""
        entry = TestOperationHelpers.create_inetorgperson_entry(
            "testldap3modify",
            RFC.DEFAULT_BASE_DN,
            sn="Test",
        )

        add_result = connected_adapter.add(entry)
        TestOperationHelpers.assert_result_success(add_result)
        add_op_result = add_result.unwrap()
        assert add_op_result.operation == "added"
        assert add_op_result.success is True

        changes: dict[str, list[tuple[str, list[str]]]] = {
            "mail": [(MODIFY_REPLACE, ["testldap3modify@example.com"])],
        }

        modify_result = connected_adapter.modify(str(entry.dn), changes)
        TestOperationHelpers.assert_result_success(modify_result)
        modify_op_result = modify_result.unwrap()
        # Validate actual content: modify should succeed
        assert modify_op_result.operation == "modified"
        assert modify_op_result.success is True
        assert modify_op_result.entries_affected == 1

        # Cleanup
        delete_result = connected_adapter.delete(str(entry.dn))
        if delete_result.is_success:
            delete_op_result = delete_result.unwrap()
            assert delete_op_result.success is True
            assert delete_op_result.entries_affected == 1
        else:
            error_msg = TestOperationHelpers.get_error_message(delete_result)
            assert len(error_msg) > 0

    @pytest.mark.timeout(30)
    def test_delete_entry_with_real_server(
        self,
        connected_adapter: Ldap3Adapter,
    ) -> None:
        """Test deleting entry with real LDAP server."""
        entry_dict: GenericFieldsDict = {
            "dn": "cn=testldap3delete,ou=people,dc=flext,dc=local",
            "attributes": {
                "cn": ["testldap3delete"],
                "sn": ["Test"],
                "objectClass": [
                    "inetOrgPerson",
                    "organizationalPerson",
                    "person",
                    "top",
                ],
            },
        }

        # Ldap3Adapter implements FlextLdapProtocols.LdapService.LdapClientProtocol implicitly via duck typing
        # Type ignore needed because mypy doesn't recognize structural subtyping

        _entry, add_result, delete_result = (
            EntryTestHelpers.delete_entry_with_verification(
                cast(
                    "FlextLdapProtocols.LdapService.LdapClientProtocol",
                    connected_adapter,
                ),
                entry_dict,
            )
        )

        TestOperationHelpers.assert_result_success(add_result)
        add_op_result = add_result.unwrap()
        assert add_op_result.operation == "added"
        assert add_op_result.success is True

        TestOperationHelpers.assert_result_success(delete_result)
        delete_op_result = delete_result.unwrap()
        # Validate actual content: delete should succeed
        assert delete_op_result.operation == "deleted"
        assert delete_op_result.success is True
        assert delete_op_result.entries_affected == 1

    @pytest.mark.timeout(30)
    def test_search_when_not_connected(
        self,
        ldap_container: LdapContainerDict,
    ) -> None:
        """Test search when not connected."""
        adapter = Ldap3Adapter()
        search_options = FlextLdapModels.SearchOptions(
            base_dn=RFC.DEFAULT_BASE_DN,
            filter_str="(objectClass=*)",
            scope=FlextLdapConstants.SearchScope.SUBTREE,
        )
        result = adapter.search(search_options)
        TestOperationHelpers.assert_result_failure(result)
        error_msg = TestOperationHelpers.get_error_message(result)
        # Validate error message content: should indicate not connected
        assert "Not connected" in error_msg or "not connected" in error_msg.lower()

    @pytest.mark.timeout(30)
    def test_disconnect_when_not_connected(self) -> None:
        """Test disconnect when not connected."""
        adapter = Ldap3Adapter()
        adapter.disconnect()
        assert adapter.is_connected is False
