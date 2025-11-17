"""Unit tests for FlextLdapEntryAdapter.

Tests entry adapter conversion between ldap3 and FlextLdif with real
functionality and quirks integration.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from flext_ldap.adapters.entry import FlextLdapEntryAdapter
from tests.helpers.operation_helpers import TestOperationHelpers


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
        TestOperationHelpers.assert_result_failure(
            result,
            expected_error="cannot be None",
        )

    def test_ldif_entry_to_ldap3_attributes_with_none_attributes(self) -> None:
        """Test conversion with entry having no attributes."""
        adapter = FlextLdapEntryAdapter()
        entry = TestOperationHelpers.create_entry_simple(
            "cn=test,dc=example,dc=com",
            {},
        )
        entry.attributes = None
        result = adapter.ldif_entry_to_ldap3_attributes(entry)
        TestOperationHelpers.assert_result_failure(
            result,
            expected_error="no attributes",
        )

    def test_ldif_entry_to_ldap3_attributes_with_single_values(self) -> None:
        """Test conversion with single-value attributes."""
        adapter = FlextLdapEntryAdapter()
        entry = TestOperationHelpers.create_entry_simple(
            "cn=test,dc=example,dc=com",
            {
                "cn": ["test"],
                "sn": ["User"],
                "objectClass": ["top", "person"],
            },
        )
        result = adapter.ldif_entry_to_ldap3_attributes(entry)
        attrs = TestOperationHelpers.assert_result_success_and_unwrap(result)
        assert attrs["cn"] == ["test"]
        assert attrs["sn"] == ["User"]
        assert attrs["objectClass"] == ["top", "person"]

    def test_ldif_entry_to_ldap3_attributes_with_list_values(self) -> None:
        """Test conversion with list-value attributes."""
        adapter = FlextLdapEntryAdapter()
        entry = TestOperationHelpers.create_entry_simple(
            "cn=test,dc=example,dc=com",
            {
                "cn": ["test"],
                "mail": ["test@example.com", "test2@example.com"],
                "objectClass": ["top", "person"],
            },
        )
        result = adapter.ldif_entry_to_ldap3_attributes(entry)
        attrs = TestOperationHelpers.assert_result_success_and_unwrap(result)
        assert attrs["cn"] == ["test"]
        assert len(attrs["mail"]) == 2
        assert "test@example.com" in attrs["mail"]
        assert "test2@example.com" in attrs["mail"]

    def test_ldif_entry_to_ldap3_attributes_with_empty_values(self) -> None:
        """Test conversion with empty values."""
        adapter = FlextLdapEntryAdapter()
        entry = TestOperationHelpers.create_entry_simple(
            "cn=test,dc=example,dc=com",
            {
                "cn": ["test"],
                "description": [],
                "emptyList": [],
            },
        )
        result = adapter.ldif_entry_to_ldap3_attributes(entry)
        attrs = TestOperationHelpers.assert_result_success_and_unwrap(result)
        assert attrs["cn"] == ["test"]
        assert attrs["description"] == []
        assert attrs["emptyList"] == []

    def test_ldif_entry_to_ldap3_attributes_with_single_string_value(self) -> None:
        """Test conversion with single string value (covers lines 139-144)."""
        adapter = FlextLdapEntryAdapter()
        # Create entry with attributes that have single string values (not list-like)
        entry = TestOperationHelpers.create_entry_simple(
            "cn=test,dc=example,dc=com",
            {
                "cn": ["test"],
                "objectClass": ["top", "person"],
            },
        )
        # Manually set attributes to have single string values for testing
        # This tests the path where value is not list-like and not falsy (lines 139-144)
        if entry.attributes:
            # Override to test single value path (lines 139-144)
            entry.attributes.attributes["singleValue"] = "single_string"  # type: ignore[assignment]
            entry.attributes.attributes["emptyString"] = ""  # type: ignore[assignment]

        result = adapter.ldif_entry_to_ldap3_attributes(entry)
        attrs = TestOperationHelpers.assert_result_success_and_unwrap(result)

        # Single string values should become lists with one element (covers line 144)
        assert attrs["cn"] == ["test"]  # Already a list
        assert isinstance(
            attrs.get("singleValue"),
            list,
        )  # Single value converted to list
        assert (
            attrs.get("emptyString") == []
        )  # Empty string becomes empty list (line 141)

    def test_normalize_entry_for_server(self) -> None:
        """Test entry normalization for server type."""
        adapter = FlextLdapEntryAdapter()
        entry = TestOperationHelpers.create_entry_simple(
            "cn=test,dc=example,dc=com",
            {"cn": ["test"], "objectClass": ["top", "person"]},
        )
        result = adapter.normalize_entry_for_server(entry, "openldap2")
        normalized = TestOperationHelpers.assert_result_success_and_unwrap(result)
        assert normalized == entry  # Normalization handled by flext-ldif quirks

    def test_validate_entry_for_server_with_valid_entry(self) -> None:
        """Test validation with valid entry."""
        adapter = FlextLdapEntryAdapter()
        entry = TestOperationHelpers.create_entry_simple(
            "cn=test,dc=example,dc=com",
            {"cn": ["test"], "objectClass": ["top", "person"]},
        )
        result = adapter.validate_entry_for_server(entry, "openldap2")
        assert TestOperationHelpers.assert_result_success_and_unwrap(result) is True

    def test_validate_entry_for_server_with_empty_dn(self) -> None:
        """Test validation with empty DN."""
        adapter = FlextLdapEntryAdapter()
        entry = TestOperationHelpers.create_entry_simple(
            "",
            {"cn": ["test"]},
        )
        result = adapter.validate_entry_for_server(entry, "openldap2")
        TestOperationHelpers.assert_result_failure(
            result,
            expected_error="DN cannot be empty",
        )

    def test_validate_entry_for_server_with_no_attributes(self) -> None:
        """Test validation with no attributes."""
        adapter = FlextLdapEntryAdapter()
        entry = TestOperationHelpers.create_entry_simple(
            "cn=test,dc=example,dc=com",
            {},
        )
        entry.attributes = None
        result = adapter.validate_entry_for_server(entry, "openldap2")
        TestOperationHelpers.assert_result_failure(
            result,
            expected_error="must have attributes",
        )

    def test_validate_entry_for_server_with_empty_attributes(self) -> None:
        """Test validation with empty attributes dict."""
        adapter = FlextLdapEntryAdapter()
        entry = TestOperationHelpers.create_entry_simple(
            "cn=test,dc=example,dc=com",
            {},
        )
        result = adapter.validate_entry_for_server(entry, "openldap2")
        TestOperationHelpers.assert_result_failure(
            result,
            expected_error="must have attributes",
        )

    def test_execute_method(self) -> None:
        """Test execute method required by FlextService."""
        adapter = FlextLdapEntryAdapter()
        result = adapter.execute()
        assert TestOperationHelpers.assert_result_success_and_unwrap(result) is True
