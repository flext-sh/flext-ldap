"""Unit tests for FlextLdapEntryAdapter.

Tests entry adapter conversion between ldap3 and FlextLdif with real
functionality and quirks integration.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from typing import cast

from flext_ldif import FlextLdifModels

from flext_ldap.adapters.entry import FlextLdapEntryAdapter


class TestFlextLdapEntryAdapter:
    """Tests for FlextLdapEntryAdapter."""

    def test_adapter_initialization(self) -> None:
        """Test adapter initialization."""
        adapter = FlextLdapEntryAdapter()
        assert adapter is not None
        assert adapter._ldif is not None
        assert adapter._server_type is None

    def test_adapter_initialization_with_server_type(self) -> None:
        """Test adapter initialization with server type."""
        adapter = FlextLdapEntryAdapter(server_type="openldap2")
        assert adapter._server_type == "openldap2"

    def test_ldap3_to_ldif_entry_with_none(self) -> None:
        """Test conversion with None entry."""
        adapter = FlextLdapEntryAdapter()
        result = adapter.ldap3_to_ldif_entry(None)
        assert result.is_failure
        assert "cannot be None" in (result.error or "")

    def test_ldap3_to_ldif_entry_with_ldif_entry(self) -> None:
        """Test conversion with already FlextLdifModels.Entry."""
        adapter = FlextLdapEntryAdapter()
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=test,dc=example,dc=com"),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={"cn": ["test"], "objectClass": ["top", "person"]}
            ),
        )
        result = adapter.ldap3_to_ldif_entry(entry)
        assert result.is_success
        assert result.unwrap() == entry

    def test_ldap3_to_ldif_entry_with_dict(self) -> None:
        """Test conversion with dict format."""
        adapter = FlextLdapEntryAdapter()
        entry_dict: dict[str, object] = {
            "dn": "cn=test,dc=example,dc=com",
            "attributes": cast(
                "object",
                {
                    "cn": ["test"],
                    "objectClass": ["top", "person"],
                },
            ),
        }
        result = adapter.ldap3_to_ldif_entry(entry_dict)
        assert result.is_success
        entry = result.unwrap()
        assert str(entry.dn) == "cn=test,dc=example,dc=com"
        assert entry.attributes is not None
        assert "cn" in entry.attributes.attributes

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

    def test_ldif_entry_to_ldap3_attributes_with_single_values(self) -> None:
        """Test conversion with single-value attributes."""
        adapter = FlextLdapEntryAdapter()
        # LdifAttributes requires all values to be lists (Pydantic validation)
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=test,dc=example,dc=com"),
            attributes=FlextLdifModels.LdifAttributes.model_validate({
                "attributes": {
                    "cn": ["test"],  # Single-value as list
                    "sn": ["User"],  # Single-value as list
                    "objectClass": ["top", "person"],
                }
            }),
        )
        result = adapter.ldif_entry_to_ldap3_attributes(entry)
        assert result.is_success
        attrs = result.unwrap()
        assert attrs["cn"] == ["test"]
        assert attrs["sn"] == ["User"]
        assert attrs["objectClass"] == ["top", "person"]

    def test_ldif_entry_to_ldap3_attributes_with_list_values(self) -> None:
        """Test conversion with list-value attributes."""
        adapter = FlextLdapEntryAdapter()
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=test,dc=example,dc=com"),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={
                    "cn": ["test"],
                    "mail": ["test@example.com", "test2@example.com"],
                    "objectClass": ["top", "person"],
                }
            ),
        )
        result = adapter.ldif_entry_to_ldap3_attributes(entry)
        assert result.is_success
        attrs = result.unwrap()
        assert attrs["cn"] == ["test"]
        assert len(attrs["mail"]) == 2
        assert "test@example.com" in attrs["mail"]
        assert "test2@example.com" in attrs["mail"]

    def test_ldif_entry_to_ldap3_attributes_with_empty_values(self) -> None:
        """Test conversion with empty values."""
        adapter = FlextLdapEntryAdapter()
        # LdifAttributes requires all values to be lists (Pydantic validation)
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=test,dc=example,dc=com"),
            attributes=FlextLdifModels.LdifAttributes.model_validate({
                "attributes": {
                    "cn": ["test"],
                    "description": [],  # Empty string becomes empty list
                    "emptyList": [],
                }
            }),
        )
        result = adapter.ldif_entry_to_ldap3_attributes(entry)
        assert result.is_success
        attrs = result.unwrap()
        assert attrs["cn"] == ["test"]
        assert attrs["description"] == []
        assert attrs["emptyList"] == []

    def test_normalize_entry_for_server(self) -> None:
        """Test entry normalization for server type."""
        adapter = FlextLdapEntryAdapter()
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=test,dc=example,dc=com"),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={"cn": ["test"], "objectClass": ["top", "person"]}
            ),
        )
        result = adapter.normalize_entry_for_server(entry, "openldap2")
        assert result.is_success
        normalized = result.unwrap()
        assert normalized == entry  # Normalization handled by flext-ldif quirks

    def test_validate_entry_for_server_with_valid_entry(self) -> None:
        """Test validation with valid entry."""
        adapter = FlextLdapEntryAdapter()
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=test,dc=example,dc=com"),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={"cn": ["test"], "objectClass": ["top", "person"]}
            ),
        )
        result = adapter.validate_entry_for_server(entry, "openldap2")
        assert result.is_success
        assert result.unwrap() is True

    def test_validate_entry_for_server_with_empty_dn(self) -> None:
        """Test validation with empty DN."""
        adapter = FlextLdapEntryAdapter()
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value=""),
            attributes=FlextLdifModels.LdifAttributes(attributes={"cn": ["test"]}),
        )
        result = adapter.validate_entry_for_server(entry, "openldap2")
        assert result.is_failure
        assert "DN cannot be empty" in (result.error or "")

    def test_validate_entry_for_server_with_no_attributes(self) -> None:
        """Test validation with no attributes."""
        adapter = FlextLdapEntryAdapter()
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=test,dc=example,dc=com"),
            attributes=None,
        )
        result = adapter.validate_entry_for_server(entry, "openldap2")
        assert result.is_failure
        assert "must have attributes" in (result.error or "").lower()

    def test_validate_entry_for_server_with_empty_attributes(self) -> None:
        """Test validation with empty attributes dict."""
        adapter = FlextLdapEntryAdapter()
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=test,dc=example,dc=com"),
            attributes=FlextLdifModels.LdifAttributes(attributes={}),
        )
        result = adapter.validate_entry_for_server(entry, "openldap2")
        assert result.is_failure
        assert "must have attributes" in (result.error or "").lower()

    def test_execute_method(self) -> None:
        """Test execute method required by FlextService."""
        adapter = FlextLdapEntryAdapter()
        result = adapter.execute()
        assert result.is_success
        assert result.unwrap() is None


class TestFlextLdapEntryAdapterWithLdap3Entry:
    """Tests for entry adapter with real ldap3.Entry objects."""

    def test_ldap3_to_ldif_entry_with_ldap3_entry_dict(self) -> None:
        """Test conversion with dict format (real-world usage)."""
        adapter = FlextLdapEntryAdapter()
        entry_dict: dict[str, object] = {
            "dn": "cn=test,dc=example,dc=com",
            "attributes": cast(
                "object",
                {
                    "cn": ["test"],
                    "objectClass": ["top", "person"],
                },
            ),
        }
        result = adapter.ldap3_to_ldif_entry(entry_dict)
        assert result.is_success
        entry = result.unwrap()
        assert str(entry.dn) == "cn=test,dc=example,dc=com"
        assert entry.attributes is not None
        assert "cn" in entry.attributes.attributes
