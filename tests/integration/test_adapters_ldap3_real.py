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
from flext_ldif import FlextLdifParser
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
        ldap_parser: FlextLdifParser,
        connection_config: FlextLdapModels.ConnectionConfig,
    ) -> Generator[Ldap3Adapter]:
        """Get connected adapter for testing."""
        adapter = Ldap3Adapter(parser=ldap_parser)
        connect_result = adapter.connect(connection_config)
        if connect_result.is_failure:
            pytest.skip(f"Failed to connect: {connect_result.error}")
        yield adapter
        adapter.disconnect()

    @pytest.mark.timeout(30)
    def test_connect_with_real_server(
        self,
        ldap_parser: FlextLdifParser,
        connection_config: FlextLdapModels.ConnectionConfig,
    ) -> None:
        """Test connection with real LDAP server."""
        adapter = Ldap3Adapter(parser=ldap_parser)
        result = adapter.connect(connection_config)
        assert result.is_success, f"Connect failed: {result.error}"
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
        assert result.is_success, f"Add failed: {result.error}"

        # Cleanup
        delete_result = connected_adapter.delete(str(entry.dn))
        assert delete_result.is_success or delete_result.is_failure

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
        assert add_result.is_success, f"Add failed: {add_result.error}"

        changes: dict[str, list[tuple[str, list[str]]]] = {
            "mail": [(MODIFY_REPLACE, ["testldap3modify@example.com"])],
        }

        modify_result = connected_adapter.modify(str(entry.dn), changes)
        assert modify_result.is_success, f"Modify failed: {modify_result.error}"

        # Cleanup
        delete_result = connected_adapter.delete(str(entry.dn))
        assert delete_result.is_success or delete_result.is_failure

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

        assert add_result.is_success
        assert delete_result.is_success, f"Delete failed: {delete_result.error}"

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
        assert result.is_failure
        # No fallback - FlextResult guarantees error exists when is_failure is True
        assert result.error is not None
        assert "Not connected" in result.error

    @pytest.mark.timeout(30)
    def test_disconnect_when_not_connected(self) -> None:
        """Test disconnect when not connected."""
        adapter = Ldap3Adapter()
        adapter.disconnect()
        assert adapter.is_connected is False
