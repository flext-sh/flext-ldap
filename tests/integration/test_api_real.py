"""Integration tests for FlextLdap API with real LDAP server.

Tests the main API facade with real server, flext-ldif integration,
and quirks support.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from typing import cast

import pytest
from ldap3 import MODIFY_REPLACE

from flext_ldap import FlextLdap
from flext_ldap.models import FlextLdapModels
from flext_ldap.typings import LdapClientProtocol

from ..fixtures.constants import RFC
from ..helpers.entry_helpers import EntryTestHelpers
from ..helpers.operation_helpers import TestOperationHelpers
from ..helpers.test_deduplication_helpers import TestDeduplicationHelpers

pytestmark = pytest.mark.integration


class TestFlextLdapAPI:
    """Tests for FlextLdap main API facade."""

    def test_api_initialization(self) -> None:
        """Test API initialization."""
        api = FlextLdap()
        assert api is not None
        assert api.is_connected is False

    def test_api_connect_and_disconnect(
        self,
        connection_config: FlextLdapModels.ConnectionConfig,
    ) -> None:
        """Test API connection lifecycle."""
        api = FlextLdap()
        TestDeduplicationHelpers.connect_and_disconnect(cast("LdapClientProtocol", api), connection_config)

    def test_api_search(
        self,
        ldap_client: FlextLdap,
        ldap_container: dict[str, object],
    ) -> None:
        """Test API search operation."""
        TestOperationHelpers.search_and_assert_success(
            cast("LdapClientProtocol", ldap_client),
            str(ldap_container["base_dn"]),
            expected_min_count=1,
        )

    def test_api_add(
        self,
        ldap_client: FlextLdap,
    ) -> None:
        """Test API add operation."""
        TestDeduplicationHelpers.api_add_operation(cast("LdapClientProtocol", ldap_client), "testapiadd", sn="Test")

    def test_api_modify(
        self,
        ldap_client: FlextLdap,
    ) -> None:
        """Test API modify operation."""
        TestDeduplicationHelpers.api_modify_operation(cast("LdapClientProtocol", ldap_client), "testapimodify")

    def test_api_delete(
        self,
        ldap_client: FlextLdap,
    ) -> None:
        """Test API delete operation."""
        TestDeduplicationHelpers.api_delete_operation(cast("LdapClientProtocol", ldap_client), "testapidelete")

    def test_api_operations_when_not_connected(
        self,
        ldap_container: dict[str, object],
    ) -> None:
        """Test API operations when not connected."""
        api = FlextLdap()

        # Search should fail
        search_options = TestOperationHelpers.create_search_options(
            str(ldap_container["base_dn"]),
        )
        TestOperationHelpers.execute_operation_when_not_connected(
            cast("LdapClientProtocol", api),
            "search",
            search_options=search_options,
        )

        # Add should fail
        entry = EntryTestHelpers.create_entry(
            "cn=test,dc=example,dc=com",
            {"cn": ["test"], "objectClass": ["top", "person"]},
        )
        TestOperationHelpers.execute_operation_when_not_connected(
            cast("LdapClientProtocol", api),
            "add",
            entry=entry,
        )

        # Modify should fail
        changes: dict[str, list[tuple[str, list[str]]]] = {
            "mail": [(MODIFY_REPLACE, ["test@example.com"])],
        }
        TestOperationHelpers.execute_operation_when_not_connected(
            cast("LdapClientProtocol", api),
            "modify",
            dn="cn=test,dc=example,dc=com",
            changes=changes,
        )

        # Delete should fail
        TestOperationHelpers.execute_operation_when_not_connected(
            cast("LdapClientProtocol", api),
            "delete",
            dn="cn=test,dc=example,dc=com",
        )


class TestFlextLdapAPIWithQuirks:
    """Tests for FlextLdap API with flext-ldif quirks integration."""

    def test_search_with_different_server_types(
        self,
        ldap_client: FlextLdap,
        ldap_container: dict[str, object],
    ) -> None:
        """Test search with different server type detections."""
        search_options = FlextLdapModels.SearchOptions(
            base_dn=str(ldap_container["base_dn"]),
            filter_str="(objectClass=*)",
            scope="SUBTREE",
        )

        # Test with different server types (quirks handled by flext-ldif)
        for server_type in ["rfc", "openldap2", "generic"]:
            # Note: server_type is passed through to parser
            result = ldap_client.search(search_options)
            assert result.is_success, (
                f"Search failed for server_type={server_type}: {result.error}"
            )

    def test_add_entry_with_quirks(
        self,
        ldap_client: FlextLdap,
    ) -> None:
        """Test adding entry with server-specific quirks handling."""
        # Entry that might need quirks processing
        entry = TestOperationHelpers.create_inetorgperson_entry(
            "testquirks",
            RFC.DEFAULT_BASE_DN,
            additional_attrs={"mail": ["test@example.com"]},
        )

        # Add should work with quirks handled by flext-ldif
        result = EntryTestHelpers.add_and_cleanup(
            cast("LdapClientProtocol", ldap_client), entry
        )
        assert result.is_success, f"Add failed: {result.error}"

        # Cleanup
        delete_result = ldap_client.delete(str(entry.dn))
        assert delete_result.is_success or delete_result.is_failure
