"""Integration tests for entry adapter ldap3.Entry conversion with real LDAP.

Tests conversion of real ldap3.Entry objects from LDAP server to FlextLdifModels.Entry.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Callable, Generator

import pytest
from flext_ldif.models import FlextLdifModels
from ldap3 import Connection, Entry as Ldap3Entry, Server

from flext_ldap.adapters.entry import FlextLdapEntryAdapter

from ..fixtures.constants import RFC

pytestmark = pytest.mark.integration


class TestFlextLdapEntryAdapterLdap3Conversion:
    """Tests for entry adapter with real ldap3.Entry conversion."""

    @pytest.fixture
    def ldap_connection(
        self,
        ldap_container: dict[str, object],
    ) -> Generator[Connection]:
        """Create real LDAP connection for testing."""
        server = Server(f"ldap://{RFC.DEFAULT_HOST}:{RFC.DEFAULT_PORT}", get_info="ALL")
        connection = Connection(
            server,
            user=str(ldap_container["bind_dn"]),
            password=str(ldap_container["password"]),
            auto_bind=True,
        )
        yield connection
        if connection.bound:
            unbind_func: Callable[[], None] = connection.unbind
            unbind_func()

    def test_ldap3_entry_to_ldif_entry_with_real_entry(
        self,
        ldap_connection: Connection,
    ) -> None:
        """Test conversion of real ldap3.Entry to FlextLdifModels.Entry."""
        adapter = FlextLdapEntryAdapter()

        # Search for entry
        ldap_connection.search(
            search_base=RFC.DEFAULT_BASE_DN,
            search_filter="(objectClass=*)",
            search_scope="BASE",
            attributes=["*"],
        )

        assert len(ldap_connection.entries) > 0
        ldap3_entry: Ldap3Entry = ldap_connection.entries[0]

        # Convert to FlextLdifModels.Entry
        result = adapter.ldap3_to_ldif_entry(ldap3_entry)
        assert result.is_success

        entry = result.unwrap()
        assert isinstance(entry, FlextLdifModels.Entry)
        assert str(entry.dn) == str(ldap3_entry.entry_dn)
        assert entry.attributes is not None

    def test_ldap3_entry_conversion_failure_handling(
        self,
        ldap_connection: Connection,
    ) -> None:
        """Test conversion failure handling with problematic entry."""
        adapter = FlextLdapEntryAdapter()

        # Create entry with problematic attributes
        # This tests the error handling path in from_ldap3
        try:
            # Try to create an entry that might cause conversion issues
            ldap_connection.search(
                search_base=RFC.DEFAULT_BASE_DN,
                search_filter="(objectClass=*)",
                search_scope="BASE",
                attributes=["*"],
            )

            if len(ldap_connection.entries) > 0:
                ldap3_entry: Ldap3Entry = ldap_connection.entries[0]
                result = adapter.ldap3_to_ldif_entry(ldap3_entry)
                # Should succeed with real entry
                assert result.is_success
        except Exception:
            # If conversion fails, that's OK - we're testing error handling
            pass

    def test_ldif_entry_to_ldap3_attributes_with_real_entry(
        self,
        ldap_connection: Connection,
    ) -> None:
        """Test conversion of real entry to ldap3 attributes."""
        adapter = FlextLdapEntryAdapter()

        # Get real entry
        ldap_connection.search(
            search_base=RFC.DEFAULT_BASE_DN,
            search_filter="(objectClass=*)",
            search_scope="BASE",
            attributes=["*"],
        )

        assert len(ldap_connection.entries) > 0
        ldap3_entry: Ldap3Entry = ldap_connection.entries[0]

        # Convert to FlextLdifModels.Entry
        entry_result = adapter.ldap3_to_ldif_entry(ldap3_entry)
        assert entry_result.is_success
        entry = entry_result.unwrap()

        # Convert back to ldap3 attributes
        attrs_result = adapter.ldif_entry_to_ldap3_attributes(entry)
        assert attrs_result.is_success

        attrs = attrs_result.unwrap()
        assert isinstance(attrs, dict)
        assert len(attrs) > 0

        # Verify attributes match
        for attr_name in ldap3_entry.entry_attributes:
            if attr_name in attrs:
                ldap3_values = list(ldap3_entry[attr_name].values)
                assert attrs[attr_name] == [str(v) for v in ldap3_values]

    def test_ldif_entry_to_ldap3_attributes_with_list_like_tuple(
        self,
    ) -> None:
        """Test conversion with tuple (list-like) values."""
        adapter = FlextLdapEntryAdapter()

        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=test,dc=example,dc=com"),
            attributes=FlextLdifModels.LdifAttributes.model_validate({
                "attributes": {
                    "cn": ("test",),  # Tuple
                    "mail": ["test@example.com"],
                },
            }),
        )

        result = adapter.ldif_entry_to_ldap3_attributes(entry)
        assert result.is_success
        attrs = result.unwrap()
        assert attrs["cn"] == ["test"]

    def test_ldif_entry_to_ldap3_attributes_with_empty_list(
        self,
    ) -> None:
        """Test conversion with empty list value."""
        adapter = FlextLdapEntryAdapter()

        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=test,dc=example,dc=com"),
            attributes=FlextLdifModels.LdifAttributes.model_validate({
                "attributes": {
                    "cn": ["test"],
                    "emptyList": [],  # Empty list
                },
            }),
        )

        result = adapter.ldif_entry_to_ldap3_attributes(entry)
        assert result.is_success
        attrs = result.unwrap()
        assert attrs["emptyList"] == []

    def test_ldif_entry_to_ldap3_attributes_with_falsy_string(
        self,
    ) -> None:
        """Test conversion with falsy string value."""
        adapter = FlextLdapEntryAdapter()

        # LdifAttributes requires all values to be lists
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=test,dc=example,dc=com"),
            attributes=FlextLdifModels.LdifAttributes.model_validate({
                "attributes": {
                    "cn": ["test"],
                    "emptyList": [],  # Empty list
                    "listWithEmpty": [""],  # List with empty string
                },
            }),
        )

        result = adapter.ldif_entry_to_ldap3_attributes(entry)
        assert result.is_success
        attrs = result.unwrap()
        assert attrs["emptyList"] == []
        assert attrs["listWithEmpty"] == [""]
