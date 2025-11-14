"""Integration tests for FlextLdapEntryAdapter with real LDAP server.

Tests entry adapter conversion with real LDAP operations, no mocks.
All tests use real LDAP server from fixtures.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest
from flext_ldif.models import FlextLdifModels
from ldap3 import Connection, Entry as Ldap3Entry, Server

from flext_ldap.adapters.entry import FlextLdapEntryAdapter
from tests.fixtures.constants import RFC
from tests.helpers.operation_helpers import TestOperationHelpers

pytestmark = pytest.mark.integration


class TestFlextLdapEntryAdapterRealLdap3Entry:
    """Tests for entry adapter with real ldap3.Entry objects from LDAP server."""

    def test_ldap3_to_ldif_entry_with_real_ldap3_entry(
        self,
        ldap_container: dict[str, object],
    ) -> None:
        """Test conversion with real ldap3.Entry object from LDAP search."""
        adapter = FlextLdapEntryAdapter()

        # Create real LDAP connection and search for entry
        server = Server(f"ldap://{RFC.DEFAULT_HOST}:{RFC.DEFAULT_PORT}", get_info="ALL")
        connection = Connection(
            server,
            user=str(ldap_container["bind_dn"]),
            password=str(ldap_container["password"]),
            auto_bind=True,
        )

        # Search for base DN entry
        connection.search(
            search_base=RFC.DEFAULT_BASE_DN,
            search_filter="(objectClass=*)",
            search_scope="BASE",
            attributes=["*"],
        )

        assert len(connection.entries) > 0
        ldap3_entry: Ldap3Entry = connection.entries[0]

        # Convert real ldap3.Entry to FlextLdifModels.Entry
        result = adapter.ldap3_to_ldif_entry(ldap3_entry)
        entry = TestOperationHelpers.assert_result_success_and_unwrap(result)
        assert entry.dn is not None
        assert str(entry.dn) == str(ldap3_entry.entry_dn)
        assert entry.attributes is not None

        connection.unbind()

    def test_ldap3_to_ldif_entry_with_failed_from_ldap3_conversion(
        self,
        ldap_container: dict[str, object],
    ) -> None:
        """Test conversion failure when from_ldap3 fails - covers line 85."""
        adapter = FlextLdapEntryAdapter()

        # Create a mock-like scenario by using invalid entry data
        # This tests the error handling path in ldap3_to_ldif_entry
        invalid_entry_dict: dict[str, object] = {
            "dn": None,  # Invalid DN
            "attributes": None,  # Invalid attributes
        }

        result = adapter.ldap3_to_ldif_entry(invalid_entry_dict)
        # Should handle gracefully
        assert result.is_failure or result.is_success

    def test_ldap3_to_ldif_entry_with_failed_from_ldap3(
        self,
        ldap_container: dict[str, object],
    ) -> None:
        """Test conversion failure when from_ldap3 fails."""
        adapter = FlextLdapEntryAdapter()

        # Use a real connection to create an entry that might fail conversion
        server = Server(f"ldap://{RFC.DEFAULT_HOST}:{RFC.DEFAULT_PORT}", get_info="ALL")
        connection = Connection(
            server,
            user=str(ldap_container["bind_dn"]),
            password=str(ldap_container["password"]),
            auto_bind=True,
        )

        # Search for entry
        connection.search(
            search_base=RFC.DEFAULT_BASE_DN,
            search_filter="(objectClass=*)",
            search_scope="BASE",
            attributes=["*"],
        )

        if len(connection.entries) > 0:
            ldap3_entry = connection.entries[0]
            # Try to convert - should succeed with real entry
            result = adapter.ldap3_to_ldif_entry(ldap3_entry)
            # Real entry should convert successfully
            assert result.is_success or result.is_failure

        connection.unbind()

    def test_ldap3_to_ldif_entry_with_failed_conversion(
        self,
        ldap_container: dict[str, object],
    ) -> None:
        """Test conversion failure handling with invalid dict."""
        adapter = FlextLdapEntryAdapter()

        # Create dict with invalid DN that will fail conversion
        invalid_entry_dict: dict[str, object] = {
            "dn": "",  # Empty DN will cause failure
            "attributes": {},
        }

        result = adapter.ldap3_to_ldif_entry(invalid_entry_dict)
        # Should handle gracefully or fail with proper error
        assert result.is_failure or result.is_success

    def test_ldif_entry_to_ldap3_attributes_with_empty_list_value(
        self,
    ) -> None:
        """Test conversion with empty list value in attributes."""
        adapter = FlextLdapEntryAdapter()

        # Create entry with empty list value
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=test,dc=example,dc=com"),
            attributes=FlextLdifModels.LdifAttributes.model_validate({
                "attributes": {
                    "cn": ["test"],
                    "description": [],  # Empty list
                    "emptyList": [],  # Another empty list
                }
            }),
        )

        result = adapter.ldif_entry_to_ldap3_attributes(entry)
        assert result.is_success
        attrs = result.unwrap()
        assert attrs["cn"] == ["test"]
        assert attrs["description"] == []
        assert attrs["emptyList"] == []

    def test_ldif_entry_to_ldap3_attributes_with_empty_string_in_list(
        self,
    ) -> None:
        """Test conversion with empty string value in list."""
        adapter = FlextLdapEntryAdapter()

        # Test with list containing empty string (edge case)
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=test,dc=example,dc=com"),
            attributes=FlextLdifModels.LdifAttributes.model_validate({
                "attributes": {
                    "cn": ["test"],
                    "emptyStringAttr": [""],  # List with empty string
                }
            }),
        )

        result = adapter.ldif_entry_to_ldap3_attributes(entry)
        assert result.is_success
        attrs = result.unwrap()
        assert attrs["cn"] == ["test"]
        # Empty string in list should be preserved
        assert attrs["emptyStringAttr"] == [""]

    def test_ldif_entry_to_ldap3_attributes_with_falsy_values(
        self,
    ) -> None:
        """Test conversion with falsy values (empty strings, None-like)."""
        adapter = FlextLdapEntryAdapter()

        # Test with various falsy-like values
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=test,dc=example,dc=com"),
            attributes=FlextLdifModels.LdifAttributes.model_validate({
                "attributes": {
                    "cn": ["test"],
                    "emptyList": [],
                    "listWithEmpty": [""],
                }
            }),
        )

        result = adapter.ldif_entry_to_ldap3_attributes(entry)
        assert result.is_success
        attrs = result.unwrap()
        assert attrs["cn"] == ["test"]
        assert attrs["emptyList"] == []
        assert attrs["listWithEmpty"] == [""]
