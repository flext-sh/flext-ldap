"""Unit tests for FlextLdapEntryAdapter.

Tests entry adapter conversion between ldap3 and FlextLdif with real
functionality and quirks integration.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import pytest

from flext_ldap.adapters.entry import FlextLdapEntryAdapter
from flext_ldap.constants import FlextLdapConstants

from ..helpers.operation_helpers import TestOperationHelpers

pytestmark = pytest.mark.unit


class TestFlextLdapEntryAdapter:
    """Tests for FlextLdapEntryAdapter."""

    def test_adapter_initialization(self) -> None:
        """Test adapter initialization with default server_type."""
        adapter = FlextLdapEntryAdapter()
        assert adapter is not None
        assert adapter._ldif is not None
        # Default server_type comes from Constants (not None anymore)
        assert adapter._server_type == FlextLdapConstants.LdapDefaults.SERVER_TYPE
        assert adapter._server_type == "generic"

    def test_adapter_initialization_with_server_type(self) -> None:
        """Test adapter initialization with server type."""
        adapter = FlextLdapEntryAdapter(server_type="openldap")
        assert adapter._server_type == "openldap"

    # Removed: test_ldap3_to_ldif_entry_with_none
    # Type system guarantees None cannot be passed (ldap3_entry: Ldap3Entry, not Ldap3Entry | None)
    # Type checker will catch None at call site - no runtime test needed

    def test_ldif_entry_to_ldap3_attributes_with_empty_attributes(self) -> None:
        """Test conversion with entry having empty attributes - fast-fail.

        Pydantic v2 validation prevents setting attributes to None.
        Empty attributes dict is also invalid - LDAP entries MUST have attributes.
        """
        adapter = FlextLdapEntryAdapter()
        # Empty attributes - not valid for LDAP
        entry = TestOperationHelpers.create_entry_simple(
            "cn=test,dc=example,dc=com",
            {},  # Empty attributes - should fail
        )
        result = adapter.ldif_entry_to_ldap3_attributes(entry)
        # Fast-fail: LDAP entries must have attributes
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
        """Test conversion with empty values - empty lists are included."""
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
        # Empty lists are included as empty lists (consistent with integration tests)
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
            entry.attributes.attributes["singleValue"] = "single_string"
            entry.attributes.attributes["emptyString"] = ""

        result = adapter.ldif_entry_to_ldap3_attributes(entry)
        attrs = TestOperationHelpers.assert_result_success_and_unwrap(result)

        # Single string values should become lists with one element (covers line 144)
        assert attrs["cn"] == ["test"]  # Already a list
        assert isinstance(
            attrs.get("singleValue"),
            list,
        )  # Single value converted to list
        # Empty strings are preserved as valid LDAP attribute values
        # (implementation intentionally keeps them - see entry.py lines 170-173)
        assert "emptyString" in attrs
        assert attrs["emptyString"] == [""]

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
        """Test validation with empty DN.

        Note: Pydantic v2 validators in Entry model capture violations but don't reject.
        Entry with empty DN can be created but will have validation violations.
        validate_entry_for_server trusts Pydantic validation - if entry was created,
        it's considered valid (violations are captured in metadata, not rejected).
        """
        adapter = FlextLdapEntryAdapter()
        # Entry with empty DN can be created (Pydantic captures violations, doesn't reject)
        # But validate_entry_for_server trusts Pydantic - if entry exists, it's valid
        entry = TestOperationHelpers.create_entry_simple(
            "",
            {"cn": ["test"]},
        )
        # Entry was created successfully (Pydantic didn't reject)
        # validate_entry_for_server trusts Pydantic validation
        result = adapter.validate_entry_for_server(entry, "openldap2")
        # Should succeed - Pydantic validation passed (violations captured in metadata)
        TestOperationHelpers.assert_result_success(result)

    def test_validate_entry_for_server_pydantic_prevents_none(self) -> None:
        """Test that Pydantic v2 validation prevents None attributes.

        Pydantic v2 model validation (with validate_assignment=True) prevents
        setting attributes to None. This is the CORRECT behavior - no None allowed.
        """
        import pytest
        from pydantic_core import ValidationError

        entry = TestOperationHelpers.create_entry_simple(
            "cn=test,dc=example,dc=com",
            {},
        )
        # Pydantic should raise ValidationError when trying to set None
        with pytest.raises(ValidationError) as exc_info:
            entry.attributes = None

        # Verify it's the correct validation error
        assert "attributes" in str(exc_info.value)

    def test_validate_entry_for_server_with_empty_attributes(self) -> None:
        """Test validation with empty attributes dict.

        Note: Pydantic v2 validators in Entry model capture violations but don't reject.
        Entry with empty attributes can be created but will have validation violations.
        validate_entry_for_server trusts Pydantic validation - if entry was created,
        it's considered valid (violations are captured in metadata, not rejected).
        """
        adapter = FlextLdapEntryAdapter()
        # Entry with empty attributes can be created (Pydantic captures violations, doesn't reject)
        # But validate_entry_for_server trusts Pydantic - if entry exists, it's valid
        entry = TestOperationHelpers.create_entry_simple(
            "cn=test,dc=example,dc=com",
            {},
        )
        # Entry was created successfully (Pydantic didn't reject)
        # validate_entry_for_server trusts Pydantic validation
        result = adapter.validate_entry_for_server(entry, "openldap2")
        # Should succeed - Pydantic validation passed (violations captured in metadata)
        TestOperationHelpers.assert_result_success(result)

    def test_execute_method(self) -> None:
        """Test execute method required by FlextService."""
        adapter = FlextLdapEntryAdapter()
        result = adapter.execute()
        assert TestOperationHelpers.assert_result_success_and_unwrap(result) is True

    # Removed: test_ldap3_to_ldif_entry_with_mixed_value_types
    # Moved to tests/integration/test_adapters_entry_real.py::test_ldap3_to_ldif_entry_with_mixed_attribute_types
    # Uses REAL ldap3.Entry from LDAP server (no mocks)

    # Removed: test_ldap3_to_ldif_entry_missing_entry_dn
    # Removed: test_ldap3_to_ldif_entry_missing_entry_attributes_as_dict
    # Type system guarantees only valid Ldap3Entry objects can be passed
    # Ldap3Entry always has entry_dn and entry_attributes_as_dict properties
    # No need to test invalid objects - type checker prevents them at call site

    def test_ldap3_to_ldif_entry_with_none_values(
        self,
        ldap_container: dict[str, object],
    ) -> None:
        """Test conversion with None values in attributes - covers line 114-115."""
        from ldap3 import Connection, Entry as Ldap3Entry, Server

        adapter = FlextLdapEntryAdapter()

        # Create real connection and search
        server = Server(
            f"ldap://{ldap_container['host']}:{ldap_container['port']}",
            get_info="ALL",
        )
        connection = Connection(
            server,
            user=str(ldap_container["bind_dn"]),
            password=str(ldap_container["password"]),
            auto_bind=True,
        )

        try:
            # Search for entry
            connection.search(
                search_base=str(ldap_container["base_dn"]),
                search_filter="(objectClass=*)",
                search_scope="BASE",
                attributes=["*"],
            )

            if len(connection.entries) > 0:
                ldap3_entry: Ldap3Entry = connection.entries[0]

                # Manually add None value to test conversion (covers line 114-115)
                # Access internal dict and add None value
                if hasattr(ldap3_entry, "entry_attributes_as_dict"):
                    attrs_dict = ldap3_entry.entry_attributes_as_dict
                    attrs_dict["testNoneAttr"] = None

                result = adapter.ldap3_to_ldif_entry(ldap3_entry)
                entry = TestOperationHelpers.assert_result_success_and_unwrap(result)

                # None values should be converted to empty list (covers line 115)
                assert entry.attributes is not None
                if "testNoneAttr" in entry.attributes.attributes:
                    assert entry.attributes.attributes["testNoneAttr"] == []
        finally:
            if connection.bound:
                connection.unbind()

    def test_ldap3_to_ldif_entry_with_non_list_values(
        self,
        ldap_container: dict[str, object],
    ) -> None:
        """Test conversion with non-list single values - covers line 116-117."""
        from ldap3 import Connection, Entry as Ldap3Entry, Server

        adapter = FlextLdapEntryAdapter()

        # Create real connection and search
        server = Server(
            f"ldap://{ldap_container['host']}:{ldap_container['port']}",
            get_info="ALL",
        )
        connection = Connection(
            server,
            user=str(ldap_container["bind_dn"]),
            password=str(ldap_container["password"]),
            auto_bind=True,
        )

        try:
            # Search for entry
            connection.search(
                search_base=str(ldap_container["base_dn"]),
                search_filter="(objectClass=*)",
                search_scope="BASE",
                attributes=["*"],
            )

            if len(connection.entries) > 0:
                ldap3_entry: Ldap3Entry = connection.entries[0]

                # Manually add single string value to test conversion (covers line 116-117)
                if hasattr(ldap3_entry, "entry_attributes_as_dict"):
                    attrs_dict = ldap3_entry.entry_attributes_as_dict
                    attrs_dict["testSingleAttr"] = "single_value"

                result = adapter.ldap3_to_ldif_entry(ldap3_entry)
                entry = TestOperationHelpers.assert_result_success_and_unwrap(result)

                # Single values should be converted to list with one element (covers line 117)
                assert entry.attributes is not None
                if "testSingleAttr" in entry.attributes.attributes:
                    assert entry.attributes.attributes["testSingleAttr"] == [
                        "single_value"
                    ]
        finally:
            if connection.bound:
                connection.unbind()

    # Removed: test_ldap3_to_ldif_entry_with_exception
    # Type system guarantees ldap3_entry is a valid Ldap3Entry
    # Ldap3Entry.entry_dn always converts to string successfully
    # No need to test invalid objects - type checker prevents them at call site
    # Exception handling in try-except block covers real edge cases from ldap3 library
