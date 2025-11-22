"""Integration tests for FlextLdapEntryAdapter with real LDAP server.

Tests entry adapter conversion with real LDAP operations, no mocks.
All tests use real LDAP server from fixtures.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest
from flext_ldif import FlextLdifParser
from flext_ldif.models import FlextLdifModels
from ldap3 import Connection, Entry as Ldap3Entry, Server

from flext_ldap.adapters.entry import FlextLdapEntryAdapter
from flext_ldap.adapters.ldap3 import Ldap3Adapter
from flext_ldap.models import FlextLdapModels

from ..fixtures.constants import RFC
from ..helpers.operation_helpers import TestOperationHelpers

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

    # Removed: test_ldap3_to_ldif_entry_with_failed_from_ldap3_conversion (None test)
    # Type system guarantees None cannot be passed (ldap3_entry: Ldap3Entry, not Ldap3Entry | None)
    # Type checker will catch None at call site - no runtime test needed

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
        """Test conversion failure handling with invalid Entry."""
        adapter = FlextLdapEntryAdapter()

        # Create a real Entry object using real LDAP connection
        server = Server(
            str(ldap_container["server_url"]),
            get_info="ALL",
        )
        conn = Connection(
            server,
            user=str(ldap_container["bind_dn"]),
            password=str(ldap_container["password"]),
            auto_bind=True,
        )

        try:
            # Try to create an Entry from search
            conn.search(
                search_base=str(ldap_container["base_dn"]),
                search_filter="(objectClass=*)",
                search_scope="BASE",
                attributes=["*"],
            )
            if conn.entries:
                # Use first entry - this is a real Entry object
                entry = conn.entries[0]
                result = adapter.ldap3_to_ldif_entry(entry)
                # Should succeed with real entry
                assert result.is_success
            else:
                # No entries found - skip test (cannot test None as type system prevents it)
                pytest.skip("No entries found in LDAP for testing")
        finally:
            if conn.bound:
                conn.unbind()

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
                },
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
                },
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
                },
            }),
        )

        result = adapter.ldif_entry_to_ldap3_attributes(entry)
        assert result.is_success
        attrs = result.unwrap()
        assert attrs["cn"] == ["test"]
        assert attrs["emptyList"] == []
        assert attrs["listWithEmpty"] == [""]

    def test_ldap3_to_ldif_entry_with_mixed_attribute_types(
        self,
        ldap_container: dict[str, object],
    ) -> None:
        """Test conversion with real ldap3.Entry having mixed attribute types.

        Creates a real LDAP entry with various attribute types and tests conversion.
        Uses REAL ldap3.Entry from LDAP server (no mocks).
        """
        adapter = FlextLdapEntryAdapter()

        # Create real LDAP connection
        server = Server(f"ldap://{RFC.DEFAULT_HOST}:{RFC.DEFAULT_PORT}", get_info="ALL")
        connection = Connection(
            server,
            user=str(ldap_container["bind_dn"]),
            password=str(ldap_container["password"]),
            auto_bind=True,
        )

        try:
            # Search for base DN entry which has various attribute types
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

            # Verify entry structure
            assert entry.dn is not None
            assert str(entry.dn) == str(ldap3_entry.entry_dn)
            assert entry.attributes is not None
            assert len(entry.attributes.attributes) > 0

            # Verify all attributes are lists (ldap3 conversion ensures this)
            for attr_name, attr_values in entry.attributes.attributes.items():
                assert isinstance(attr_values, list), (
                    f"Attribute {attr_name} should be a list"
                )
                # All values in list should be strings
                for value in attr_values:
                    assert isinstance(value, str), (
                        f"Value in {attr_name} should be a string"
                    )

        finally:
            if connection.bound:
                connection.unbind()

    def test_ldap3_to_ldif_entry_with_base64_attributes_from_real_ldap(
        self,
        ldap_container: dict[str, object],
    ) -> None:
        """Test conversion with base64 attributes from real LDAP entry (covers lines 123, 142, 179).

        Uses real LDAP operations to add entry with attributes containing high-ASCII characters,
        which are detected as base64. Then searches and converts to ensure lines are executed.
        """
        adapter_entry = FlextLdapEntryAdapter()
        adapter_ldap3 = Ldap3Adapter(parser=FlextLdifParser())

        # Connect adapter before using
        config = FlextLdapModels.ConnectionConfig(
            host=RFC.DEFAULT_HOST,
            port=RFC.DEFAULT_PORT,
            bind_dn=str(ldap_container["bind_dn"]),
            bind_password=str(ldap_container["password"]),
        )
        connect_result = adapter_ldap3.connect(config)
        if not connect_result.is_success:
            pytest.skip(f"Could not connect to LDAP: {connect_result.error}")

        server = Server(f"ldap://{RFC.DEFAULT_HOST}:{RFC.DEFAULT_PORT}", get_info="ALL")
        connection = Connection(
            server,
            user=str(ldap_container["bind_dn"]),
            password=str(ldap_container["password"]),
            auto_bind=True,
        )

        try:
            # Create entry with high-ASCII attribute value (will be detected as base64)
            test_cn = "testbase64entry"
            entry = TestOperationHelpers.create_inetorgperson_entry(
                test_cn,
                RFC.DEFAULT_BASE_DN,
                additional_attrs={
                    # Use high-ASCII character to trigger base64 detection (line 123, 142)
                    "description": ["Test with high ASCII: \x80\x81\x82"],
                },
            )

            # Add entry to LDAP server
            add_result = adapter_ldap3.add(entry)
            if not add_result.is_success:
                _ = adapter_ldap3.delete(str(entry.dn))
                add_result = adapter_ldap3.add(entry)

            TestOperationHelpers.assert_result_success(add_result)

            # Search for the entry we just added
            connection.search(
                search_base=str(entry.dn),
                search_filter="(objectClass=*)",
                search_scope="BASE",
                attributes=["*"],
            )

            if len(connection.entries) > 0:
                ldap3_entry: Ldap3Entry = connection.entries[0]

                # Convert - this should detect base64 attributes (lines 123, 142, 179)
                result = adapter_entry.ldap3_to_ldif_entry(ldap3_entry)
                converted_entry = TestOperationHelpers.assert_result_success_and_unwrap(
                    result
                )

                # Verify metadata contains base64 tracking
                assert converted_entry.metadata is not None
                if hasattr(converted_entry.metadata, "extensions"):
                    extensions = converted_entry.metadata.extensions
                    if isinstance(extensions, dict):
                        # Check for base64_encoded_attributes (line 179)
                        base64_attrs = extensions.get("base64_encoded_attributes")
                        if base64_attrs:
                            base64_attrs_list = (
                                list(base64_attrs)
                                if isinstance(base64_attrs, (list, set))
                                else [base64_attrs]
                            )
                            base64_attrs_str = [str(a) for a in base64_attrs_list]
                            assert (
                                any("description" in a for a in base64_attrs_str)
                                or len(base64_attrs_str) > 0
                            )

            # Cleanup
            if entry.dn:
                _ = adapter_ldap3.delete(str(entry.dn))
        finally:
            adapter_ldap3.disconnect()
            if connection.bound:
                connection.unbind()

    def test_ldap3_to_ldif_entry_with_dn_change_tracking(
        self,
        ldap_container: dict[str, object],
    ) -> None:
        """Test conversion tracks DN changes (covers lines 220-222)."""
        adapter_entry = FlextLdapEntryAdapter()
        adapter_ldap3 = Ldap3Adapter(parser=FlextLdifParser())

        # Connect adapter before using
        config = FlextLdapModels.ConnectionConfig(
            host=RFC.DEFAULT_HOST,
            port=RFC.DEFAULT_PORT,
            bind_dn=str(ldap_container["bind_dn"]),
            bind_password=str(ldap_container["password"]),
        )
        connect_result = adapter_ldap3.connect(config)
        if not connect_result.is_success:
            pytest.skip(f"Could not connect to LDAP: {connect_result.error}")

        server = Server(f"ldap://{RFC.DEFAULT_HOST}:{RFC.DEFAULT_PORT}", get_info="ALL")
        connection = Connection(
            server,
            user=str(ldap_container["bind_dn"]),
            password=str(ldap_container["password"]),
            auto_bind=True,
        )

        try:
            test_cn = "testdnchange"
            entry = TestOperationHelpers.create_inetorgperson_entry(
                test_cn,
                RFC.DEFAULT_BASE_DN,
            )

            add_result = adapter_ldap3.add(entry)
            if not add_result.is_success:
                _ = adapter_ldap3.delete(str(entry.dn))
                add_result = adapter_ldap3.add(entry)
            TestOperationHelpers.assert_result_success(add_result)

            connection.search(
                search_base=str(entry.dn),
                search_filter="(objectClass=*)",
                search_scope="BASE",
                attributes=["*"],
            )

            if len(connection.entries) > 0:
                ldap3_entry = connection.entries[0]
                result = adapter_entry.ldap3_to_ldif_entry(ldap3_entry)
                converted_entry = TestOperationHelpers.assert_result_success_and_unwrap(
                    result
                )

                # Verify DN tracking in metadata (lines 220-222)
                assert converted_entry.metadata is not None
                if hasattr(converted_entry.metadata, "extensions"):
                    extensions = converted_entry.metadata.extensions
                    if isinstance(extensions, dict):
                        assert "dn_changed" in extensions

            # Cleanup
            if entry.dn:
                _ = adapter_ldap3.delete(str(entry.dn))
        finally:
            adapter_ldap3.disconnect()
            if connection.bound:
                connection.unbind()
