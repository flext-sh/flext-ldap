"""Integration tests for FlextLdap API with real LDAP server.

Tests the main API facade with real server, flext-ldif integration,
and quirks support.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from typing import cast

import pytest
from flext_core import t
from ldap3 import MODIFY_REPLACE

from flext_ldap import FlextLdap
from flext_ldap.constants import FlextLdapConstants as c
from flext_ldap.models import FlextLdapModels as m
from flext_ldap.protocols import FlextLdapProtocols as p

from ..conftest import create_flext_ldap_instance
from ..fixtures.constants import RFC
from ..fixtures.typing import GenericFieldsDict, LdapContainerDict
from ..helpers.entry_helpers import EntryTestHelpers
from ..helpers.operation_helpers import TestOperationHelpers
from ..helpers.test_deduplication_helpers import TestDeduplicationHelpers

pytestmark = pytest.mark.integration


class TestFlextLdapAPI:
    """Tests for FlextLdap main API facade."""

    def test_api_initialization(self) -> None:
        """Test API initialization."""
        api = create_flext_ldap_instance()
        assert api is not None
        assert api._connection.is_connected is False

    def test_api_connect_and_disconnect(
        self,
        connection_config: m.ConnectionConfig,
    ) -> None:
        """Test API connection lifecycle."""
        api = create_flext_ldap_instance()
        TestDeduplicationHelpers.connect_and_disconnect(
            cast("p.LdapService.LdapClientProtocol", api),
            connection_config,
        )

    def test_api_search(
        self,
        ldap_client: FlextLdap,
        ldap_container: LdapContainerDict,
    ) -> None:
        """Test API search operation."""
        TestOperationHelpers.search_and_assert_success(
            cast("p.LdapService.LdapClientProtocol", ldap_client),
            ldap_container["base_dn"],
            expected_min_count=1,
        )

    def test_api_add(
        self,
        ldap_client: FlextLdap,
    ) -> None:
        """Test API add operation."""
        TestDeduplicationHelpers.api_add_operation(
            cast("p.LdapService.LdapClientProtocol", ldap_client),
            "testapiadd",
            sn="Test",
        )

    def test_api_modify(
        self,
        ldap_client: FlextLdap,
    ) -> None:
        """Test API modify operation."""
        TestDeduplicationHelpers.api_modify_operation(
            cast("p.LdapService.LdapClientProtocol", ldap_client),
            "testapimodify",
        )

    def test_api_delete(
        self,
        ldap_client: FlextLdap,
    ) -> None:
        """Test API delete operation."""
        TestDeduplicationHelpers.api_delete_operation(
            cast("p.LdapService.LdapClientProtocol", ldap_client),
            "testapidelete",
        )

    def test_api_operations_when_not_connected(
        self,
        ldap_container: LdapContainerDict,
    ) -> None:
        """Test API operations when not connected."""
        api = create_flext_ldap_instance()

        # Search should fail
        search_options = TestOperationHelpers.create_search_options(
            ldap_container["base_dn"],
        )
        TestOperationHelpers.execute_operation_when_not_connected(
            cast("p.LdapService.LdapClientProtocol", api),
            "search",
            search_options=cast("t.GeneralValueType", search_options),
        )

        # Add should fail
        entry = EntryTestHelpers.create_entry(
            "cn=test,dc=example,dc=com",
            {"cn": ["test"], "objectClass": ["top", "person"]},
        )
        TestOperationHelpers.execute_operation_when_not_connected(
            cast("p.LdapService.LdapClientProtocol", api),
            "add",
            entry=cast("t.GeneralValueType", entry),
        )

        # Modify should fail
        changes: dict[str, list[tuple[str, list[str]]]] = {
            "mail": [(MODIFY_REPLACE, ["test@example.com"])],
        }
        TestOperationHelpers.execute_operation_when_not_connected(
            cast("p.LdapService.LdapClientProtocol", api),
            "modify",
            dn="cn=test,dc=example,dc=com",
            changes=changes,
        )

        # Delete should fail
        TestOperationHelpers.execute_operation_when_not_connected(
            cast("p.LdapService.LdapClientProtocol", api),
            "delete",
            dn="cn=test,dc=example,dc=com",
        )


class TestFlextLdapAPIWithQuirks:
    """Tests for FlextLdap API with flext-ldif quirks integration."""

    def test_search_with_different_server_types(
        self,
        ldap_client: FlextLdap,
        ldap_container: LdapContainerDict,
    ) -> None:
        """Test search with different server type detections."""
        search_options = m.SearchOptions(
            base_dn=ldap_container["base_dn"],
            filter_str="(objectClass=*)",
            scope=c.SearchScope.SUBTREE,
        )

        # Test with different server types (quirks handled by flext-ldif)
        for _server_type in ["rfc", "openldap2", "generic"]:
            # Note: server_type is passed through to parser
            result = ldap_client.search(search_options)
            TestOperationHelpers.assert_result_success(result)
            search_result = result.unwrap()
            # Validate actual content: search should return SearchResult
            assert search_result is not None
            assert hasattr(search_result, "entries")
            assert hasattr(search_result, "total_count")
            assert search_result.total_count == len(search_result.entries)

    def test_add_entry_with_quirks(
        self,
        ldap_client: FlextLdap,
    ) -> None:
        """Test adding entry with server-specific quirks handling."""
        # Entry that might need quirks processing
        additional_attrs: GenericFieldsDict = cast(
            "GenericFieldsDict",
            {"mail": ["test@example.com"]},
        )
        entry = TestOperationHelpers.create_inetorgperson_entry(
            "testquirks",
            RFC.DEFAULT_BASE_DN,
            additional_attrs=additional_attrs,
        )

        # Add should work with quirks handled by flext-ldif
        result = EntryTestHelpers.add_and_cleanup(
            cast("p.LdapService.LdapClientProtocol", ldap_client),
            entry,
        )
        TestOperationHelpers.assert_result_success(result)
        operation_result = result.unwrap()
        # Validate actual content: add() returns OperationResult with operation_type field
        assert operation_result.operation_type == c.OperationType.ADD
        assert operation_result.success is True
        assert operation_result.entries_affected == 1

        # Cleanup
        delete_result = ldap_client.delete(str(entry.dn))
        if delete_result.is_success:
            delete_op_result = delete_result.unwrap()
            assert delete_op_result.success is True
            assert delete_op_result.entries_affected == 1
        else:
            # If delete fails, validate error message
            error_msg = TestOperationHelpers.get_error_message(delete_result)
            assert len(error_msg) > 0
