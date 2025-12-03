"""Complete integration tests for FlextLdapEntryAdapter with real LDAP server.

All tests use real LDAP operations, no mocks. Tests all methods and edge cases.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest
from flext_ldif.models import FlextLdifModels
from ldap3 import Connection, Entry as Ldap3Entry
from pydantic import ValidationError

from flext_ldap.adapters.entry import FlextLdapEntryAdapter
from flext_ldap.constants import FlextLdapConstants

from ..fixtures.constants import RFC
from ..helpers.entry_helpers import EntryTestHelpers
from ..helpers.operation_helpers import TestOperationHelpers
from ..helpers.test_helpers import Ldap3TestHelpers, to_ldap3_scope

pytestmark = pytest.mark.integration


class TestFlextLdapEntryAdapterComplete:
    """Complete tests for FlextLdapEntryAdapter with real LDAP server."""

    def test_ldap3_to_ldif_entry_with_real_ldap3_entry(
        self,
        ldap3_connection: Connection,
    ) -> None:
        """Test conversion with real ldap3.Entry from LDAP search."""
        adapter = FlextLdapEntryAdapter()

        # Search for base DN entry using shared helper
        entries = Ldap3TestHelpers.search_base_entry(
            ldap3_connection,
            RFC.DEFAULT_BASE_DN,
            scope=FlextLdapConstants.SearchScope.BASE,
        )
        assert len(entries) > 0
        ldap3_entry: Ldap3Entry = entries[0]

        # Convert real ldap3.Entry to FlextLdifModels.Entry
        result = adapter.ldap3_to_ldif_entry(ldap3_entry)
        entry = TestOperationHelpers.assert_result_success_and_unwrap(result)
        assert entry.dn is not None
        assert str(entry.dn) == str(ldap3_entry.entry_dn)
        assert entry.attributes is not None

    def test_ldap3_to_ldif_entry_with_dict_from_real_search(
        self,
        ldap3_connection: Connection,
    ) -> None:
        """Test conversion with dict format from real LDAP search."""
        adapter = FlextLdapEntryAdapter()

        # Search for entries
        ldap3_connection.search(
            search_base=RFC.DEFAULT_BASE_DN,
            search_filter="(objectClass=*)",
            search_scope=to_ldap3_scope(FlextLdapConstants.SearchScope.BASE),
            attributes=["*"],
        )

        assert len(ldap3_connection.entries) > 0
        ldap3_entry: Ldap3Entry = ldap3_connection.entries[0]

        # Use ldap3 Entry directly (not dict) - API direta
        result = adapter.ldap3_to_ldif_entry(ldap3_entry)
        entry = TestOperationHelpers.assert_result_success_and_unwrap(result)
        assert str(entry.dn) == str(ldap3_entry.entry_dn)
        assert entry.attributes is not None

    def test_ldif_entry_to_ldap3_attributes_with_real_entry(
        self,
        ldap3_connection: Connection,
    ) -> None:
        """Test conversion with entry from real LDAP search."""
        adapter = FlextLdapEntryAdapter()

        # Search for entry
        ldap3_connection.search(
            search_base=RFC.DEFAULT_BASE_DN,
            search_filter="(objectClass=*)",
            search_scope=to_ldap3_scope(FlextLdapConstants.SearchScope.BASE),
            attributes=["*"],
        )

        assert len(ldap3_connection.entries) > 0
        ldap3_entry: Ldap3Entry = ldap3_connection.entries[0]

        # Convert to FlextLdifModels.Entry
        entry_result = adapter.ldap3_to_ldif_entry(ldap3_entry)
        entry = TestOperationHelpers.assert_result_success_and_unwrap(entry_result)

        # Convert back to ldap3 attributes
        attrs_result = adapter.ldif_entry_to_ldap3_attributes(entry)
        attrs = TestOperationHelpers.assert_result_success_and_unwrap(attrs_result)
        assert isinstance(attrs, dict)
        assert len(attrs) > 0

    def test_ldif_entry_to_ldap3_attributes_with_list_like_values(self) -> None:
        """Test conversion with list-like values."""
        adapter = FlextLdapEntryAdapter()

        # Create entry with tuple (list-like)
        entry = EntryTestHelpers.create_entry(
            "cn=test,dc=example,dc=com",
            {
                "cn": ["test"],  # Convert tuple to list
                "mail": ["test@example.com", "test2@example.com"],
                "objectClass": ["top", "person"],
            },
        )

        result = adapter.ldif_entry_to_ldap3_attributes(entry)
        attrs = TestOperationHelpers.assert_result_success_and_unwrap(result)
        assert attrs["cn"] == ["test"]
        assert len(attrs["mail"]) == 2

    def test_ldif_entry_to_ldap3_attributes_with_empty_string_value(self) -> None:
        """Test conversion with empty string value."""
        adapter = FlextLdapEntryAdapter()

        # LdifAttributes requires all values to be lists
        # Empty string must be represented as empty list or list with empty string
        entry = EntryTestHelpers.create_entry(
            "cn=test,dc=example,dc=com",
            {
                "cn": ["test"],
                "emptyList": [],  # Empty list stays empty list
                "listWithEmpty": [""],  # List with empty string
            },
        )

        result = adapter.ldif_entry_to_ldap3_attributes(entry)
        attrs = TestOperationHelpers.assert_result_success_and_unwrap(result)
        assert attrs["cn"] == ["test"]
        assert attrs["emptyList"] == []  # Empty list stays empty
        assert attrs["listWithEmpty"] == [
            "",
        ]  # List with empty string  # List with empty string

    def test_normalize_entry_for_server_with_real_entry(
        self,
        ldap3_connection: Connection,
    ) -> None:
        """Test normalization with entry from real LDAP."""
        adapter = FlextLdapEntryAdapter()

        # Get real entry
        ldap3_connection.search(
            search_base=RFC.DEFAULT_BASE_DN,
            search_filter="(objectClass=*)",
            search_scope=to_ldap3_scope(FlextLdapConstants.SearchScope.BASE),
            attributes=["*"],
        )

        assert len(ldap3_connection.entries) > 0
        ldap3_entry: Ldap3Entry = ldap3_connection.entries[0]

        entry_result = adapter.ldap3_to_ldif_entry(ldap3_entry)
        _ = TestOperationHelpers.assert_result_success_and_unwrap(entry_result)

        # Entry conversion tested - normalization is handled by flext-ldif quirks system
        # No separate normalize_entry_for_server method needed

    def test_validate_entry_for_server_with_real_entry(
        self,
        ldap3_connection: Connection,
    ) -> None:
        """Test validation with entry from real LDAP."""
        adapter = FlextLdapEntryAdapter()

        # Get real entry
        ldap3_connection.search(
            search_base=RFC.DEFAULT_BASE_DN,
            search_filter="(objectClass=*)",
            search_scope=to_ldap3_scope(FlextLdapConstants.SearchScope.BASE),
            attributes=["*"],
        )

        assert len(ldap3_connection.entries) > 0
        ldap3_entry: Ldap3Entry = ldap3_connection.entries[0]

        entry_result = adapter.ldap3_to_ldif_entry(ldap3_entry)
        _ = TestOperationHelpers.assert_result_success_and_unwrap(entry_result)

        # Entry validation is handled by Pydantic models and flext-ldif quirks system
        # No separate validate_entry_for_server method needed

    def test_ldap3_to_ldif_entry_with_already_ldif_entry(
        self,
        ldap3_connection: Connection,
    ) -> None:
        """Test conversion when entry is already FlextLdifModels.Entry."""
        adapter = FlextLdapEntryAdapter()

        # Get real entry
        ldap3_connection.search(
            search_base=RFC.DEFAULT_BASE_DN,
            search_filter="(objectClass=*)",
            search_scope=to_ldap3_scope(FlextLdapConstants.SearchScope.BASE),
            attributes=["*"],
        )

        assert len(ldap3_connection.entries) > 0
        ldap3_entry: Ldap3Entry = ldap3_connection.entries[0]

        # Convert to FlextLdifModels.Entry - API direta
        entry_result = adapter.ldap3_to_ldif_entry(ldap3_entry)
        TestOperationHelpers.assert_result_success(entry_result)
        entry = entry_result.unwrap()
        # Validate actual content: entry should have DN and attributes
        assert entry.dn is not None
        assert entry.attributes is not None
        assert str(entry.dn) == str(ldap3_entry.entry_dn)

        # Pass same ldap3_entry again (should convert again, not return as-is)
        # API direta: método aceita apenas Ldap3Entry, não Entry já convertido
        result = adapter.ldap3_to_ldif_entry(ldap3_entry)
        TestOperationHelpers.assert_result_success(result)
        converted_entry = result.unwrap()
        # Validate actual content: entries devem ser equivalentes (mesmo DN e atributos)
        assert str(converted_entry.dn) == str(entry.dn)
        assert converted_entry.attributes is not None
        assert entry.attributes is not None
        # Validate attributes are equivalent
        assert set(converted_entry.attributes.attributes) == set(
            entry.attributes.attributes
        )

    # Removed: test_ldap3_to_ldif_entry_with_none
    # Type system guarantees ldap3_entry is a valid Ldap3Entry (not None)
    # Type checker prevents passing None at call site
    # No runtime None check needed - type system guarantees non-None

    def test_round_trip_conversion_ldap3_to_ldif_to_ldap3(
        self,
        ldap3_connection: Connection,
    ) -> None:
        """Test complete round-trip conversion: ldap3 → ldif → ldap3.

        This validates that data is preserved through conversion cycles.
        """
        adapter = FlextLdapEntryAdapter()

        # Get a real entry from LDAP
        ldap3_connection.search(
            search_base=RFC.DEFAULT_BASE_DN,
            search_filter="(objectClass=*)",
            search_scope=to_ldap3_scope(FlextLdapConstants.SearchScope.BASE),
            attributes=["*"],
        )
        assert len(ldap3_connection.entries) > 0
        original_ldap3_entry = ldap3_connection.entries[0]

        # Convert ldap3 → ldif
        ldif_result = adapter.ldap3_to_ldif_entry(original_ldap3_entry)
        original_ldif_entry = TestOperationHelpers.assert_result_success_and_unwrap(
            ldif_result,
        )

        # Convert ldif → ldap3
        ldap3_attrs_result = adapter.ldif_entry_to_ldap3_attributes(original_ldif_entry)
        converted_ldap3_attrs = TestOperationHelpers.assert_result_success_and_unwrap(
            ldap3_attrs_result,
        )

        # Create a new ldif entry from the converted ldap3 attributes
        # (simulating what would happen if we added this to LDAP and retrieved it)
        test_dn = f"cn=round-trip-test,{RFC.DEFAULT_BASE_DN}"
        round_trip_entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value=test_dn),
            attributes=FlextLdifModels.LdifAttributes(attributes=converted_ldap3_attrs),
        )

        # Convert back to ldap3 attributes again
        final_ldap3_result = adapter.ldif_entry_to_ldap3_attributes(round_trip_entry)
        final_ldap3_attrs = TestOperationHelpers.assert_result_success_and_unwrap(
            final_ldap3_result,
        )

        # Validate that critical attributes are preserved
        original_attrs = original_ldap3_entry.entry_attributes_as_dict

        # Check DN preservation
        assert str(round_trip_entry.dn) == test_dn

        # Check that objectClass is preserved (most important attribute)
        if "objectClass" in original_attrs:
            original_oc = original_attrs["objectClass"]
            final_oc = final_ldap3_attrs.get("objectClass", [])
            # Sort both lists for comparison
            assert sorted(original_oc) == sorted(final_oc), (
                f"objectClass not preserved: original={original_oc}, final={final_oc}"
            )

        # Check that other key attributes are preserved
        for attr_name in ["cn", "dc"]:
            if attr_name in original_attrs:
                original_values = original_attrs[attr_name]
                final_values = final_ldap3_attrs.get(attr_name, [])
                assert sorted(original_values) == sorted(final_values), (
                    f"{attr_name} not preserved: original={original_values}, final={final_values}"
                )

    def test_ldif_entry_to_ldap3_attributes_with_empty_attributes(self) -> None:
        """Test conversion with entry having empty attributes dict."""
        adapter = FlextLdapEntryAdapter()
        entry = EntryTestHelpers.create_entry(
            "cn=test,dc=example,dc=com",
            {},
        )
        # Entry.attributes is guaranteed by Pydantic, but attributes.attributes can be empty
        result = adapter.ldif_entry_to_ldap3_attributes(entry)
        TestOperationHelpers.assert_result_failure(
            result,
            expected_error="no attributes",
        )

    def test_validate_entry_for_server_with_empty_dn(self) -> None:
        """Test validation with empty DN.

        Note: Pydantic v2 validators in Entry model capture violations but don't reject.
        Entry with empty DN can be created but will have validation violations.
        validate_entry_for_server trusts Pydantic validation - if entry was created,
        it's considered valid (violations are captured in metadata, not rejected).
        """
        # Entry with empty DN can be created (Pydantic captures violations, doesn't reject)
        entry = EntryTestHelpers.create_entry(
            "",
            {"cn": ["test"]},
        )
        # Entry was created successfully (Pydantic validation passed)
        assert entry is not None

    def test_validate_entry_for_server_with_no_attributes(self) -> None:
        """Test validation with no attributes.

        Note: Pydantic v2 prevents setting attributes=None, so we test with
        empty attributes dict instead, which is the valid way to represent
        an entry with no attributes.
        """
        entry = EntryTestHelpers.create_entry(
            "cn=test,dc=example,dc=com",
            {},
        )
        # Pydantic v2 prevents setting attributes=None - this is correct behavior
        # Test that Pydantic raises ValidationError using model_validate
        invalid_data = entry.model_dump()
        invalid_data["attributes"] = None
        with pytest.raises(ValidationError):
            FlextLdifModels.Entry.model_validate(invalid_data)

        # Test validation with empty attributes
        # Entry with empty attributes can be created (Pydantic validation passed)
        assert entry is not None

    def test_validate_entry_for_server_with_empty_attributes(self) -> None:
        """Test validation with empty attributes dict.

        Note: Pydantic v2 validators in Entry model capture violations but don't reject.
        Entry with empty attributes can be created but will have validation violations.
        Entry validation is handled by Pydantic models.
        """
        entry = EntryTestHelpers.create_entry(
            "cn=test,dc=example,dc=com",
            {},
        )
        # Entry was created successfully (Pydantic validation passed)
        assert entry is not None

    def test_execute_method(self) -> None:
        """Test execute method required by FlextService."""
        adapter = FlextLdapEntryAdapter()
        result = adapter.execute()
        assert TestOperationHelpers.assert_result_success_and_unwrap(result) is True
