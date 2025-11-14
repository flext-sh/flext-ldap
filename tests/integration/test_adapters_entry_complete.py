"""Complete integration tests for FlextLdapEntryAdapter with real LDAP server.

All tests use real LDAP operations, no mocks. Tests all methods and edge cases.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Generator
from typing import cast

import pytest
from flext_ldif.models import FlextLdifModels
from ldap3 import Connection, Entry as Ldap3Entry, Server

from flext_ldap.adapters.entry import FlextLdapEntryAdapter
from tests.fixtures.constants import RFC

pytestmark = pytest.mark.integration


class TestFlextLdapEntryAdapterComplete:
    """Complete tests for FlextLdapEntryAdapter with real LDAP server."""

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
            connection.unbind()

    def test_ldap3_to_ldif_entry_with_real_ldap3_entry(
        self,
        ldap_connection: Connection,
    ) -> None:
        """Test conversion with real ldap3.Entry from LDAP search."""
        adapter = FlextLdapEntryAdapter()

        # Search for base DN entry
        ldap_connection.search(
            search_base=RFC.DEFAULT_BASE_DN,
            search_filter="(objectClass=*)",
            search_scope="BASE",
            attributes=["*"],
        )

        assert len(ldap_connection.entries) > 0
        ldap3_entry: Ldap3Entry = ldap_connection.entries[0]

        # Convert real ldap3.Entry to FlextLdifModels.Entry
        result = adapter.ldap3_to_ldif_entry(ldap3_entry)
        assert result.is_success

        entry = result.unwrap()
        assert entry.dn is not None
        assert str(entry.dn) == str(ldap3_entry.entry_dn)
        assert entry.attributes is not None

    def test_ldap3_to_ldif_entry_with_dict_from_real_search(
        self,
        ldap_connection: Connection,
    ) -> None:
        """Test conversion with dict format from real LDAP search."""
        adapter = FlextLdapEntryAdapter()

        # Search for entries
        ldap_connection.search(
            search_base=RFC.DEFAULT_BASE_DN,
            search_filter="(objectClass=*)",
            search_scope="BASE",
            attributes=["*"],
        )

        assert len(ldap_connection.entries) > 0
        ldap3_entry: Ldap3Entry = ldap_connection.entries[0]

        # Convert to dict format
        entry_dict: dict[str, object] = {
            "dn": str(ldap3_entry.entry_dn),
            "attributes": cast(
                "object",
                {
                    attr: list(ldap3_entry[attr].values)
                    for attr in ldap3_entry.entry_attributes
                },
            ),
        }

        result = adapter.ldap3_to_ldif_entry(entry_dict)
        assert result.is_success

        entry = result.unwrap()
        assert str(entry.dn) == entry_dict["dn"]
        assert entry.attributes is not None

    def test_ldif_entry_to_ldap3_attributes_with_real_entry(
        self,
        ldap_connection: Connection,
    ) -> None:
        """Test conversion with entry from real LDAP search."""
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
        entry_result = adapter.ldap3_to_ldif_entry(ldap3_entry)
        assert entry_result.is_success
        entry = entry_result.unwrap()

        # Convert back to ldap3 attributes
        attrs_result = adapter.ldif_entry_to_ldap3_attributes(entry)
        assert attrs_result.is_success

        attrs = attrs_result.unwrap()
        assert isinstance(attrs, dict)
        assert len(attrs) > 0

    def test_ldif_entry_to_ldap3_attributes_with_list_like_values(self) -> None:
        """Test conversion with list-like values."""
        adapter = FlextLdapEntryAdapter()

        # Create entry with tuple (list-like)
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=test,dc=example,dc=com"),
            attributes=FlextLdifModels.LdifAttributes.model_validate({
                "attributes": {
                    "cn": ("test",),  # Tuple (list-like)
                    "mail": ["test@example.com", "test2@example.com"],
                    "objectClass": ["top", "person"],
                }
            }),
        )

        result = adapter.ldif_entry_to_ldap3_attributes(entry)
        assert result.is_success
        attrs = result.unwrap()
        assert attrs["cn"] == ["test"]
        assert len(attrs["mail"]) == 2

    def test_ldif_entry_to_ldap3_attributes_with_empty_string_value(self) -> None:
        """Test conversion with empty string value."""
        adapter = FlextLdapEntryAdapter()

        # LdifAttributes requires all values to be lists
        # Empty string must be represented as empty list or list with empty string
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=test,dc=example,dc=com"),
            attributes=FlextLdifModels.LdifAttributes.model_validate({
                "attributes": {
                    "cn": ["test"],
                    "emptyList": [],  # Empty list stays empty list
                    "listWithEmpty": [""],  # List with empty string
                }
            }),
        )

        result = adapter.ldif_entry_to_ldap3_attributes(entry)
        assert result.is_success
        attrs = result.unwrap()
        assert attrs["cn"] == ["test"]
        assert attrs["emptyList"] == []  # Empty list stays empty
        assert attrs["listWithEmpty"] == [""]  # List with empty string

    def test_normalize_entry_for_server_with_real_entry(
        self,
        ldap_connection: Connection,
    ) -> None:
        """Test normalization with entry from real LDAP."""
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

        entry_result = adapter.ldap3_to_ldif_entry(ldap3_entry)
        assert entry_result.is_success
        entry = entry_result.unwrap()

        # Test normalization for different server types
        for server_type in ["rfc", "openldap2", "generic"]:
            result = adapter.normalize_entry_for_server(entry, server_type)
            assert result.is_success
            normalized = result.unwrap()
            assert normalized is not None

    def test_validate_entry_for_server_with_real_entry(
        self,
        ldap_connection: Connection,
    ) -> None:
        """Test validation with entry from real LDAP."""
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

        entry_result = adapter.ldap3_to_ldif_entry(ldap3_entry)
        assert entry_result.is_success
        entry = entry_result.unwrap()

        # Validate for different server types
        for server_type in ["rfc", "openldap2", "generic"]:
            result = adapter.validate_entry_for_server(entry, server_type)
            assert result.is_success
            assert result.unwrap() is True

    def test_ldap3_to_ldif_entry_with_already_ldif_entry(
        self,
        ldap_connection: Connection,
    ) -> None:
        """Test conversion when entry is already FlextLdifModels.Entry."""
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

        # Pass same entry back (should return as-is)
        result = adapter.ldap3_to_ldif_entry(entry)
        assert result.is_success
        assert result.unwrap() == entry

    def test_ldap3_to_ldif_entry_with_none(self) -> None:
        """Test conversion with None entry."""
        adapter = FlextLdapEntryAdapter()
        result = adapter.ldap3_to_ldif_entry(None)
        assert result.is_failure
        assert "cannot be None" in (result.error or "")

    def test_ldif_entry_to_ldap3_attributes_with_none_attributes(self) -> None:
        """Test conversion with entry having no attributes."""
        adapter = FlextLdapEntryAdapter()
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=test,dc=example,dc=com"),
            attributes=None,
        )
        result = adapter.ldif_entry_to_ldap3_attributes(entry)
        assert result.is_failure
        assert "no attributes" in (result.error or "").lower()

    def test_validate_entry_for_server_with_empty_dn(self) -> None:
        """Test validation with empty DN."""
        adapter = FlextLdapEntryAdapter()
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value=""),
            attributes=FlextLdifModels.LdifAttributes(attributes={"cn": ["test"]}),
        )
        result = adapter.validate_entry_for_server(entry, "rfc")
        assert result.is_failure
        assert "DN cannot be empty" in (result.error or "")

    def test_validate_entry_for_server_with_no_attributes(self) -> None:
        """Test validation with no attributes."""
        adapter = FlextLdapEntryAdapter()
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=test,dc=example,dc=com"),
            attributes=None,
        )
        result = adapter.validate_entry_for_server(entry, "rfc")
        assert result.is_failure
        assert "must have attributes" in (result.error or "").lower()

    def test_validate_entry_for_server_with_empty_attributes(self) -> None:
        """Test validation with empty attributes dict."""
        adapter = FlextLdapEntryAdapter()
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=test,dc=example,dc=com"),
            attributes=FlextLdifModels.LdifAttributes(attributes={}),
        )
        result = adapter.validate_entry_for_server(entry, "rfc")
        assert result.is_failure
        assert "must have attributes" in (result.error or "").lower()

    def test_execute_method(self) -> None:
        """Test execute method required by FlextService."""
        adapter = FlextLdapEntryAdapter()
        result = adapter.execute()
        assert result.is_success
        assert result.unwrap() is None
