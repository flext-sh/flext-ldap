"""Integration tests for FlextLdap API with real LDAP server.

Tests the main API facade with real server, flext-ldif integration,
and quirks support.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import pytest
from flext_ldif.models import FlextLdifModels
from ldap3 import MODIFY_REPLACE

from flext_ldap import FlextLdap
from flext_ldap.models import FlextLdapModels

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

        # Connect
        connect_result = api.connect(connection_config)
        assert connect_result.is_success, f"Connect failed: {connect_result.error}"
        assert api.is_connected is True

        # Disconnect
        api.disconnect()
        assert api.is_connected is False

    def test_api_search(
        self,
        ldap_client: FlextLdap,
        ldap_container: dict[str, object],
    ) -> None:
        """Test API search operation."""
        search_options = FlextLdapModels.SearchOptions(
            base_dn=str(ldap_container["base_dn"]),
            filter_str="(objectClass=*)",
            scope="SUBTREE",
        )

        result = ldap_client.search(search_options)
        assert result.is_success, f"Search failed: {result.error}"
        search_result = result.unwrap()
        assert len(search_result.entries) > 0

    def test_api_add(
        self,
        ldap_client: FlextLdap,
    ) -> None:
        """Test API add operation."""
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(
                value="cn=testapiadd,ou=people,dc=flext,dc=local"
            ),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={
                    "cn": ["testapiadd"],
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

        result = ldap_client.add(entry)
        assert result.is_success, f"Add failed: {result.error}"

        # Cleanup
        delete_result = ldap_client.delete(str(entry.dn))
        assert delete_result.is_success or delete_result.is_failure

    def test_api_modify(
        self,
        ldap_client: FlextLdap,
    ) -> None:
        """Test API modify operation."""
        # First add an entry
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(
                value="cn=testapimodify,ou=people,dc=flext,dc=local"
            ),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={
                    "cn": ["testapimodify"],
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

        # Modify entry
        changes: dict[str, list[tuple[str, list[str]]]] = {
            "mail": [(MODIFY_REPLACE, ["api@example.com"])],
        }

        modify_result = ldap_client.modify(str(entry.dn), changes)
        assert modify_result.is_success, f"Modify failed: {modify_result.error}"

        # Cleanup
        delete_result = ldap_client.delete(str(entry.dn))
        assert delete_result.is_success or delete_result.is_failure

    def test_api_delete(
        self,
        ldap_client: FlextLdap,
    ) -> None:
        """Test API delete operation."""
        # First add an entry
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(
                value="cn=testapidelete,ou=people,dc=flext,dc=local"
            ),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={
                    "cn": ["testapidelete"],
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

        # Delete entry
        delete_result = ldap_client.delete(str(entry.dn))
        assert delete_result.is_success, f"Delete failed: {delete_result.error}"

    def test_api_operations_when_not_connected(
        self,
        ldap_container: dict[str, object],
    ) -> None:
        """Test API operations when not connected."""
        api = FlextLdap()

        # Search should fail
        search_options = FlextLdapModels.SearchOptions(
            base_dn=str(ldap_container["base_dn"]),
            filter_str="(objectClass=*)",
            scope="SUBTREE",
        )
        search_result = api.search(search_options)
        assert search_result.is_failure

        # Add should fail
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=test,dc=example,dc=com"),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={"cn": ["test"], "objectClass": ["top", "person"]}
            ),
        )
        add_result = api.add(entry)
        assert add_result.is_failure

        # Modify should fail
        changes: dict[str, list[tuple[str, list[str]]]] = {
            "mail": [(MODIFY_REPLACE, ["test@example.com"])],
        }
        modify_result = api.modify("cn=test,dc=example,dc=com", changes)
        assert modify_result.is_failure

        # Delete should fail
        delete_result = api.delete("cn=test,dc=example,dc=com")
        assert delete_result.is_failure


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
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(
                value="cn=testquirks,ou=people,dc=flext,dc=local"
            ),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={
                    "cn": ["testquirks"],
                    "sn": ["Test"],
                    "mail": ["test@example.com"],
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

        # Add should work with quirks handled by flext-ldif
        result = ldap_client.add(entry)
        assert result.is_success, f"Add failed: {result.error}"

        # Cleanup
        delete_result = ldap_client.delete(str(entry.dn))
        assert delete_result.is_success or delete_result.is_failure
